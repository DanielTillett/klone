#!/usr/bin/env python3
"""Pinned Linux build; on Windows run this script through WSL Python."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def dependencies(offline):
    lock = json.loads((ROOT / "build/dependencies.json").read_text())
    for name, spec in lock.items():
        directory = ROOT / name
        if not directory.exists():
            if offline:
                raise RuntimeError(f"Missing {name}; run once without --offline")
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--no-checkout",
                            spec["url"], str(directory)], check=True)
            subprocess.run(["git", "checkout", "--detach", spec["commit"]], cwd=directory, check=True)
        if git("rev-parse", "HEAD", cwd=directory) != spec["commit"]:
            raise RuntimeError(f"{name} does not match build/dependencies.json; refusing to overwrite it")
        if git("diff", "--ignore-cr-at-eol", "HEAD", "--", cwd=directory):
            raise RuntimeError(f"{name} has local changes; refusing to use an unpinned dependency")
    return lock


def copy_sources(source, destination, tracked_only=False):
    options = ["--cached"] if tracked_only else ["--cached", "--others", "--exclude-standard"]
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", *options], cwd=source
    ).decode().split("\0")
    manifest = []
    for relative in paths:
        if not relative or relative.split("/")[0] in {"makl", "libu", ".build"}:
            continue
        src = source / relative
        if not src.is_file():
            continue
        dst = destination / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        if b"\0" not in data:
            data = data.replace(b"\r\n", b"\n")
        manifest.append((relative, hashlib.sha256(data).hexdigest()))
        if not dst.exists() or dst.read_bytes() != data:
            dst.write_bytes(data)
        # Windows checkouts lose executable bits; source utilities use shebangs.
        dst.chmod(0o755 if data.startswith(b"#!") else 0o644)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="require cached pinned dependencies")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--test", action="store_true", help="run core and full HTTP/TLS/session tests")
    parser.add_argument("--incremental", action="store_true", help="reuse generated build files during development")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Use Linux or WSL: wsl -- python3 build/build.py")
    import fcntl
    lock = dependencies(args.offline)
    output = ROOT / ".build" / ("sanitize" if args.sanitize else "release")
    output.mkdir(parents=True, exist_ok=True)
    build_lock = (output / "build.lock").open("a")
    try:
        fcntl.flock(build_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error(f"Another build is using {output}; wait for it to finish")
    source = output / "source"
    # Only the generated source tree inside this repository's .build is replaced.
    if source.resolve().parent.parent != (ROOT / ".build").resolve():
        raise RuntimeError("Unsafe build output directory")
    if source.exists() and not args.incremental:
        shutil.rmtree(source)
    source.mkdir(parents=True, exist_ok=True)
    manifest = copy_sources(ROOT, source)
    for name in lock:
        entries = copy_sources(ROOT / name, source / name, tracked_only=True)
        manifest.extend((name + "/" + path, digest) for path, digest in entries)
    fingerprint = hashlib.sha256(json.dumps(sorted(manifest)).encode()).hexdigest()
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(source / "build/makl-modern.patch")],
                   cwd=source, check=True)
    env = os.environ.copy()
    flags = "-std=gnu99 -fgnu89-inline -g"
    if args.sanitize:
        flags += " -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
        env["LDFLAGS"] = "-fsanitize=address,undefined"
    env["CFLAGS"] = flags
    env["CXXFLAGS"] = flags.replace("-std=gnu99 -fgnu89-inline", "-std=gnu++11")
    env["LC_ALL"] = "C"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = git("show", "-s", "--format=%ct", "HEAD")
    env["MAKEFLAGS"] = "-I" + str(source / "makl/mk")
    env["MAKL_DIR"] = str(source / "makl")
    commands = [
        ["sh", "configure", "--enable_sup_fs", "--disable_cxx", "--enable_debug"],
        ["make", "-C", "build/libu"],
        ["make", "-C", "site", "register.c"],
        ["make", "depend"],
        ["make", f"-j{args.jobs}"],
    ]
    if args.incremental and (source / "Makefile.conf").exists():
        commands = commands[-1:]
    with (output / "build.log").open("w") as log:
        for command in commands:
            print("Running", " ".join(command), flush=True)
            result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
            log.flush()
            if result.returncode:
                print("\n".join((output / "build.log").read_text(errors="replace").splitlines()[-60:]))
                raise SystemExit(result.returncode)
    if "#define SSL_OPENSSL 1" not in (source / "klone_conf.h").read_text():
        raise RuntimeError("This build requires OpenSSL 3; TLS must not be silently disabled")
    metadata = {"dependencies": lock, "source_sha256": fingerprint, "klone_commit": git("rev-parse", "HEAD"),
                "compiler": subprocess.check_output(["cc", "--version"], text=True),
                "openssl": subprocess.check_output(["openssl", "version"], text=True), "cflags": flags}
    (output / "build-info.json").write_text(json.dumps(metadata, indent=2))
    print(f"Server: {source / 'src/kloned/kloned'}\nBuild log: {output / 'build.log'}")
    if args.test:
        subprocess.run([sys.executable, str(ROOT / "test/run_regressions.py"), "--sanitize"], check=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "test/run_server_tests.py"),
                        "--source", str(source)], check=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "test/run_server_tests.py"),
                        "--source", str(source), "--prefork"], check=True, env=env)


if __name__ == "__main__":
    main()
