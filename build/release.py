#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Klin source release files (doc/RELEASES).

Writes into --out (default .build/dist):

    klin-<version>.tar.gz        the commit's tracked files and the pinned
                                 LibU (build/dependencies.json) under
                                 klin-<version>/libu, so the tarball
                                 builds with CMake alone, offline
    klin-<version>.spdx.json     SPDX 2.3 SBOM: Klin, LibU (contained),
                                 OpenSSL and zlib (system libraries)
    SHA256SUMS                   both files

The files depend only on the commit and the pinned dependencies: two runs
give the same bytes (with the same zlib). Nothing is signed or uploaded
here; the release workflow (.github/workflows/release.yml) does that.

    python3 build/release.py [--ref REF] [--tag vX.Y.Z] [--out DIR]
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # noqa: E402  (build/build.py: the pinned dependencies)

ROOT = build.ROOT
DEFAULT_REPO = "DanielTillett/klin"

# Libraries Klin links from the system: in the SBOM, not in the tarball
SYSTEM_LIBRARIES = [
    {"name": "openssl", "version": "3.0 or later", "license": "Apache-2.0",
     "home": "https://www.openssl.org/", "purl": "pkg:generic/openssl"},
    {"name": "zlib", "version": "any", "license": "Zlib",
     "home": "https://zlib.net/", "purl": "pkg:generic/zlib"},
]


def git(*args, cwd=ROOT, binary=False):
    output = subprocess.check_output(["git", "-c", "core.autocrlf=false", *args], cwd=cwd)
    return output if binary else output.decode().strip()


def archive_members(cwd, commit, prefix):
    """The tracked files of commit, as (TarInfo, data) under prefix."""
    data = git("archive", "--format=tar", f"--prefix={prefix}", commit, cwd=cwd, binary=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            payload = tar.extractfile(member).read() if member.isfile() else None
            yield member, payload


def write_tarball(path, members, mtime):
    """A gzip'd tar of members with the owners, times and order fixed."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for member, payload in sorted(members, key=lambda m: m[0].name):
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = mtime
            member.pax_headers = {}
            if member.isdir():
                member.mode = 0o755
            elif member.isfile():
                member.mode = 0o755 if member.mode & 0o111 else 0o644
            tar.addfile(member, io.BytesIO(payload) if payload is not None else None)
    with open(path, "wb") as out, gzip.GzipFile(filename="", mode="wb", fileobj=out,
                                                compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sbom(version, commit, created, repo, tarball, dependencies):
    """SPDX 2.3 (JSON) for the source tarball."""
    klin = {
        "SPDXID": "SPDXRef-Package-klin",
        "name": "klin",
        "versionInfo": version,
        "packageFileName": tarball.name,
        "supplier": "Person: Daniel Tillett",
        "originator": "Organization: KoanLogic srl (KLone)",
        "downloadLocation": f"git+https://github.com/{repo}.git@{commit}",
        "homepage": f"https://github.com/{repo}",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(tarball)}],
        "licenseConcluded": "BSD-3-Clause",
        "licenseDeclared": "BSD-3-Clause",
        "copyrightText": "Copyright (c) 2005-2012 KoanLogic srl; Copyright (c) 2026 Daniel Tillett",
        "primaryPackagePurpose": "SOURCE",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": f"pkg:github/{repo}@v{version}"}],
    }
    packages = [klin]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": klin["SPDXID"]}]
    for name, spec in dependencies.items():
        directory = ROOT / name
        url = spec["url"]
        upstream = url.removesuffix(".git").split("github.com/")[-1]
        packages.append({
            "SPDXID": f"SPDXRef-Package-{name}",
            "name": name,
            "versionInfo": f"{(directory / 'VERSION').read_text().strip()} ({spec['commit']})",
            "supplier": "Organization: KoanLogic srl",
            "downloadLocation": f"git+{url}@{spec['commit']}",
            "homepage": url.removesuffix(".git"),
            "filesAnalyzed": False,
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "copyrightText": "Copyright (c) 2005-2012 KoanLogic srl",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": f"pkg:github/{upstream}@{spec['commit']}"}],
            "comment": f"pinned in build/dependencies.json; in the tarball under {name}/",
        })
        relationships.append({"spdxElementId": klin["SPDXID"], "relationshipType": "CONTAINS",
                              "relatedSpdxElement": f"SPDXRef-Package-{name}"})
    for library in SYSTEM_LIBRARIES:
        packages.append({
            "SPDXID": f"SPDXRef-Package-{library['name']}",
            "name": library["name"],
            "versionInfo": library["version"],
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "homepage": library["home"],
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": library["license"],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": library["purl"]}],
            "comment": "not in the tarball: linked from the system the build runs on",
        })
        relationships.append({"spdxElementId": klin["SPDXID"], "relationshipType": "DEPENDS_ON",
                              "relatedSpdxElement": f"SPDXRef-Package-{library['name']}"})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": tarball.name,
        "documentNamespace": f"https://github.com/{repo}/releases/v{version}/{commit}",
        "creationInfo": {"created": created, "creators": ["Tool: klin-build-release.py"]},
        "packages": packages,
        "relationships": relationships,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", default="HEAD", help="commit to release (default HEAD)")
    parser.add_argument("--tag", help="release tag; must be v<VERSION> and name --ref's commit")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"GitHub owner/name (default {DEFAULT_REPO})")
    parser.add_argument("--out", type=Path, default=ROOT / ".build/dist")
    args = parser.parse_args()

    commit = git("rev-parse", "--verify", f"{args.ref}^{{commit}}")
    version = git("show", f"{commit}:VERSION")
    if args.tag:
        if args.tag != f"v{version}":
            raise SystemExit(f"tag {args.tag} does not match VERSION {version}")
        tagged = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{args.tag}^{{commit}}"],
                                cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if tagged != commit:
            raise SystemExit(f"tag {args.tag} does not name {commit}")
    # the commit's own pins, which the checkout must have
    lock = json.loads(git("show", f"{commit}:build/dependencies.json"))
    if lock != build.dependencies(False):
        raise SystemExit("build/dependencies.json differs between the checkout and the commit")

    prefix = f"klin-{version}/"
    members = list(archive_members(ROOT, commit, prefix))
    for name, spec in lock.items():
        members += archive_members(ROOT / name, spec["commit"], f"{prefix}{name}/")
    timestamp = int(git("show", "-s", "--format=%ct", commit))
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))

    args.out.mkdir(parents=True, exist_ok=True)
    tarball = args.out / f"klin-{version}.tar.gz"
    write_tarball(tarball, members, timestamp)
    document = sbom(version, commit, created, args.repo, tarball, lock)
    spdx = args.out / f"klin-{version}.spdx.json"
    spdx.write_text(json.dumps(document, indent=2) + "\n")
    sums = "".join(f"{sha256(p)}  {p.name}\n" for p in (tarball, spdx))
    (args.out / "SHA256SUMS").write_text(sums)
    print(f"klin {version} ({commit[:12]}) in {args.out}:\n{sums}", end="")


if __name__ == "__main__":
    main()
