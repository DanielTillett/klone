#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Release and workflow checks (doc/RELEASES).

  - every workflow in .github/workflows: pinned actions (a full commit SHA
    and a version comment), "permissions: {}" at the top and explicit
    permissions on each job, checkouts without persisted credentials, no
    pull_request_target, and no event or input values expanded inside a
    run script; Dependabot covers the actions;
  - build/release.py: two runs give the same bytes, the tarball holds the
    commit's tracked files and the pinned LibU (owners, times and modes
    fixed), the SBOM and SHA256SUMS agree with the files;
  - the tarball builds offline with CMake alone and its unit tests pass.

With --dist, the files in DIR (e.g. the release workflow's) are checked
too, and must equal a fresh build/release.py run for --ref.

    python3 test/run_release_checks.py [--dist DIR] [--ref REF] [--no-build]

Needs PyYAML (python3-yaml).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(command, **kwargs):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kwargs)
    return result.returncode, result.stdout


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", "-c", "core.autocrlf=false", *args], cwd=cwd, text=True).strip()


PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"uses:\s*\S+\s+#\s*v\d+(\.\d+)*\s*$")
# values an outside contributor controls, unsafe to expand into a script
UNTRUSTED = re.compile(r"\$\{\{[^}]*\b(github\.event|github\.head_ref|inputs\.|github\.ref_name)")


def check_workflow(name, text):
    doc = yaml.safe_load(text)
    triggers = doc.get("on", doc.get(True))  # YAML 1.1 reads "on" as true
    check(triggers is not None, f"{name}: no triggers")
    check("pull_request_target" not in (triggers if isinstance(triggers, (dict, list)) else [triggers]),
          f"{name}: pull_request_target runs untrusted code with a write token")
    check(doc.get("permissions") == {}, f"{name}: top-level permissions must be {{}}")
    for job_name, job in doc["jobs"].items():
        check(isinstance(job.get("permissions"), dict) and job["permissions"],
              f"{name}: job {job_name} has no explicit permissions")
        for permission, level in job["permissions"].items():
            check(level in ("read", "write"), f"{name}: {job_name}: {permission}: {level}")
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses:
                check(PINNED.match(uses), f"{name}: {job_name}: {uses} is not pinned to a commit SHA")
                if uses.startswith("actions/checkout@"):
                    check(str(step.get("with", {}).get("persist-credentials")).lower() == "false",
                          f"{name}: {job_name}: checkout keeps credentials")
            script = step.get("run", "")
            check(not UNTRUSTED.search(script),
                  f"{name}: {job_name}: run script expands an untrusted value; pass it in env")
    for line in text.splitlines():
        if re.match(r"\s*-?\s*uses:", line):
            check(VERSION_COMMENT.search(line), f"{name}: no version comment: {line.strip()}")


GOOD = ("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: x\n    permissions:\n      contents: read\n"
        "    steps:\n      - uses: actions/checkout@" + "a" * 40 + " # v4.4.0\n"
        "        with:\n          persist-credentials: false\n")
# mistakes the check must refuse
BAD = {
    "unpinned": GOOD.replace("@" + "a" * 40, "@v4"),
    "short SHA": GOOD.replace("a" * 40, "a" * 12),
    "no version comment": GOOD.replace(" # v4.4.0", ""),
    "top-level write-all": GOOD.replace("permissions: {}", "permissions: write-all"),
    "no top-level permissions": GOOD.replace("permissions: {}\n", ""),
    "no job permissions": GOOD.replace("    permissions:\n      contents: read\n", ""),
    "persisted credentials": GOOD.replace("persist-credentials: false", "persist-credentials: true"),
    "pull_request_target": GOOD.replace("on: push", "on: [pull_request_target]"),
    "event injection": GOOD + '      - run: echo "${{ github.event.pull_request.title }}"\n',
    "input injection": GOOD + "      - run: git tag ${{ inputs.tag }}\n",
}


def check_workflows():
    check_workflow("sample", GOOD)
    for what, text in BAD.items():
        try:
            check_workflow(what, text)
        except AssertionError:
            continue
        check(False, f"the workflow check accepted a workflow with: {what}")
    files = sorted((ROOT / ".github/workflows").glob("*.yml"))
    check(files, "no workflows found")
    for path in files:
        check_workflow(path.name, path.read_text())

    dependabot = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    ecosystems = {u["package-ecosystem"]: u["directory"] for u in dependabot["updates"]}
    check(ecosystems.get("github-actions") == "/", "Dependabot does not cover the workflows")
    check(ecosystems.get("docker") == "/.clusterfuzzlite", "Dependabot does not cover the fuzzing image")
    check((ROOT / "SECURITY.md").is_file(), "no SECURITY.md")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def release(ref, out):
    rc, output = run([sys.executable, str(ROOT / "build/release.py"), "--ref", ref, "--out", str(out)])
    check(rc == 0, f"build/release.py failed:\n{output[-3000:]}")


def check_release(dist, ref, commit, version, lock):
    tarball = dist / f"klin-{version}.tar.gz"
    spdx = dist / f"klin-{version}.spdx.json"
    check(tarball.is_file() and spdx.is_file(), f"missing release files in {dist}")

    # SHA256SUMS lists both files, with their digests
    sums = (dist / "SHA256SUMS").read_text().splitlines()
    check(sums == [f"{sha256(tarball)}  {tarball.name}", f"{sha256(spdx)}  {spdx.name}"],
          f"SHA256SUMS does not match the files: {sums}")

    # the tarball: the commit's tracked files plus the pinned dependencies
    prefix = f"klin-{version}/"
    expected = {prefix + p for p in git("ls-tree", "-r", "--name-only", commit).splitlines()}
    with tarfile.open(tarball) as tar:
        members = tar.getmembers()
    files = {m.name for m in members if not m.isdir()}
    check(expected <= files, f"tracked files missing from the tarball: {sorted(expected - files)[:10]}")
    for name, spec in lock.items():
        tracked = {f"{prefix}{name}/{p}" for p in
                   git("ls-tree", "-r", "--name-only", spec["commit"], cwd=ROOT / name).splitlines()}
        check(tracked and tracked <= files, f"{name} is not in the tarball")
    extra = {f for f in files - expected if not any(f.startswith(f"{prefix}{n}/") for n in lock)}
    check(not extra, f"files in the tarball that the commit does not track: {sorted(extra)[:10]}")
    check(all(m.name.startswith(prefix) or m.name == prefix.rstrip("/") for m in members),
          "a member outside the top directory")
    names = [m.name for m in members]
    check(len(names) == len(set(names)), "duplicate members")
    check(not any("/.git/" in m.name or m.name.endswith("/.git") for m in members), ".git in the tarball")
    check(len({m.mtime for m in members}) == 1, "member times are not fixed")
    check(all(m.uid == 0 and m.gid == 0 and not m.uname and not m.gname for m in members),
          "member owners are not fixed")
    check(all(m.mode in (0o644, 0o755) for m in members if m.isfile()), "unexpected file modes")
    check(sorted(m.name for m in members) == [m.name for m in members], "members are not sorted")

    # the SBOM: SPDX 2.3 describing this tarball and its dependencies
    doc = json.loads(spdx.read_text())
    check(doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0", "not an SPDX 2.3 document")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc["creationInfo"]["created"]),
          f"SPDX created is not UTC: {doc['creationInfo']['created']}")
    check(commit in doc["documentNamespace"], "documentNamespace does not name the commit")
    ids = [p["SPDXID"] for p in doc["packages"]]
    check(len(ids) == len(set(ids)), "duplicate SPDXIDs")
    known = set(ids) | {"SPDXRef-DOCUMENT"}
    check(all(r["spdxElementId"] in known and r["relatedSpdxElement"] in known for r in doc["relationships"]),
          "a relationship names an unknown element")
    packages = {p["name"]: p for p in doc["packages"]}
    klin = packages["klin"]
    check(klin["versionInfo"] == version, "SBOM: wrong Klin version")
    check(klin["checksums"] == [{"algorithm": "SHA256", "checksumValue": sha256(tarball)}],
          "SBOM: the tarball's checksum does not match")
    check(klin["downloadLocation"].endswith(f"@{commit}"), "SBOM: Klin's commit is wrong")
    check({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
           "relatedSpdxElement": klin["SPDXID"]} in doc["relationships"], "SBOM: does not describe Klin")
    for name, spec in lock.items():
        check(name in packages and packages[name]["downloadLocation"] == f"git+{spec['url']}@{spec['commit']}",
              f"SBOM: {name} does not match build/dependencies.json")
        check({"spdxElementId": klin["SPDXID"], "relationshipType": "CONTAINS",
               "relatedSpdxElement": packages[name]["SPDXID"]} in doc["relationships"],
              f"SBOM: Klin does not contain {name}")
    for name in ("openssl", "zlib"):
        check(name in packages and {"spdxElementId": klin["SPDXID"], "relationshipType": "DEPENDS_ON",
                                    "relatedSpdxElement": packages[name]["SPDXID"]} in doc["relationships"],
              f"SBOM: no dependency on {name}")


def check_build(tarball, version, temp):
    """The tarball alone (no git, no network) builds, and its tests pass."""
    with tarfile.open(tarball) as tar:
        tar.extractall(temp / "src", filter="data")
    source = temp / "src" / f"klin-{version}"
    out = temp / "out"
    generator = ["-G", "Ninja"] if shutil.which("ninja") else []
    env = {**os.environ, "GIT_DIR": str(temp / "no-git")}  # no repository to fall back on
    rc, output = run(["cmake", "-S", str(source), "-B", str(out), *generator, "-DKLIN_BUILD_TESTS=ON",
                      "-DCMAKE_BUILD_TYPE=Release"], env=env)
    if rc == 0:
        rc, more = run(["cmake", "--build", str(out), "--parallel"], env=env)
        output += more
    check(rc == 0, f"the tarball does not build on its own:\n{output[-4000:]}")
    rc, output = run([str(out / "bin/klin"), "-V"])
    check(version in output, f"klin -V from the tarball: {output!r}")
    rc, output = run(["ctest", "--test-dir", str(out), "--output-on-failure"])
    check(rc == 0 and "100% tests passed" in output, f"unit tests from the tarball failed:\n{output[-4000:]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dist", type=Path, help="release files to check (e.g. the workflow's)")
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--no-build", action="store_true", help="skip building the tarball")
    args = parser.parse_args()

    check_workflows()
    workflow_checks = checks

    commit = git("rev-parse", "--verify", f"{args.ref}^{{commit}}")
    version = git("show", f"{commit}:VERSION")
    lock = json.loads(git("show", f"{commit}:build/dependencies.json"))
    with tempfile.TemporaryDirectory(prefix="klin-release-checks-") as directory:
        temp = Path(directory)
        first, second = temp / "first", temp / "second"
        release(args.ref, first)
        release(args.ref, second)
        for name in sorted(os.listdir(first)):
            check((first / name).read_bytes() == (second / name).read_bytes(), f"{name} is not reproducible")
        check_release(first, args.ref, commit, version, lock)
        if args.dist:
            for name in sorted(os.listdir(first)):
                check(sha256(args.dist / name) == sha256(first / name),
                      f"{args.dist / name} differs from a fresh build/release.py run")
        if not args.no_build:
            check_build(first / f"klin-{version}.tar.gz", version, temp)

    print(f"{checks} release checks passed ({workflow_checks} on the workflows; klin {version}, {commit[:12]})")


if __name__ == "__main__":
    main()
