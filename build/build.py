#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Pinned, reproducible Klin build and test runner (CMake).

Runs on Linux (on Windows, through WSL Python) and other POSIX systems with
CMake 3.24+, a C compiler, OpenSSL 3 and zlib. GNU make is not required: the
default generator is Ninja, and --generator "Unix Makefiles" with
--make-program works with BSD make (bmake) or GNU make.
"""
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
    """Fetch and verify the pinned dependencies (LibU)."""
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
        if not relative or relative.split("/")[0] in {"libu", ".build", ".vera"}:
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


def run_logged(commands, cwd, env, log_path):
    """Run commands in order, appending to log_path; show its tail on failure."""
    with log_path.open("w") as log:
        for command in commands:
            print("Running", " ".join(command), flush=True)
            result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
            log.flush()
            if result.returncode:
                print("\n".join(log_path.read_text(errors="replace").splitlines()[-60:]))
                raise SystemExit(result.returncode)


def default_generator():
    return "Ninja" if shutil.which("ninja") else "Unix Makefiles"


def cmake_build(args, source, output, env, flags):
    """Configure and build the staged sources with CMake; return the build dir."""
    build = output / "cmake"
    if build.exists() and not args.incremental:
        shutil.rmtree(build)
    configure = ["cmake", "-S", str(source), "-B", str(build), "-G", args.generator,
                 "-DCMAKE_BUILD_TYPE=Debug" if args.sanitize else "-DCMAKE_BUILD_TYPE=Release",
                 f"-DCMAKE_C_FLAGS={flags}",
                 "-DKLIN_DEBUG=ON", "-DKLIN_ENABLE_SUP_FS=ON", "-DKLIN_SITE_DIR=",
                 "-DKLIN_BUILD_TESTS=ON"]
    if args.sanitize:
        configure.append("-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined")
    if args.make_program:
        configure.append(f"-DCMAKE_MAKE_PROGRAM={args.make_program}")
    # Configure always runs, so changed options (or a changed generator,
    # which CMake rejects for an existing tree) are never silently ignored.
    commands = [configure, ["cmake", "--build", str(build), "--parallel", str(args.jobs)]]
    run_logged(commands, source, env, output / "build.log")
    return build


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="require cached pinned dependencies")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--test", action="store_true", help="run core and full HTTP/TLS/session tests")
    parser.add_argument("--incremental", action="store_true", help="reuse generated build files during development")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--generator", default=default_generator(),
                        help="CMake generator (default: Ninja if installed, else Unix Makefiles)")
    parser.add_argument("--make-program", help="build tool for the generator, e.g. bmake")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Use Linux, WSL or another POSIX system: wsl -- python3 build/build.py")
    import fcntl
    lock = dependencies(args.offline)
    mode = "sanitize" if args.sanitize else "release"
    output = ROOT / ".build" / mode
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
    env = os.environ.copy()
    flags = "-g"
    if args.sanitize:
        flags += " -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
    env["LC_ALL"] = "C"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = git("show", "-s", "--format=%ct", "HEAD")

    build = cmake_build(args, source, output, env, flags)
    conf, daemon = build / "include/klin_conf.h", build / "bin/klind"
    if "#define SSL_OPENSSL 1" not in conf.read_text():
        raise RuntimeError("This build requires OpenSSL 3; TLS must not be silently disabled")

    metadata = {"dependencies": lock, "source_sha256": fingerprint, "klin_commit": git("rev-parse", "HEAD"),
                "compiler": subprocess.check_output(["cc", "--version"], text=True),
                "openssl": subprocess.check_output(["openssl", "version"], text=True), "cflags": flags,
                "cmake": subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0],
                "generator": args.generator, "make_program": args.make_program}
    (output / "build-info.json").write_text(json.dumps(metadata, indent=2))
    print(f"Server: {daemon}\nBuild log: {output / 'build.log'}")
    if args.test:
        # unit tests against the real libraries (CTest), then the extracted-
        # function regressions and the full-server tests
        subprocess.run(["ctest", "--test-dir", str(build), "-L", "unit", "--output-on-failure"],
                       check=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "test/run_regressions.py"), "--sanitize"], check=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "test/run_server_tests.py"), "--build", str(build)],
                       check=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "test/run_server_tests.py"), "--build", str(build),
                        "--prefork"], check=True, env=env)


if __name__ == "__main__":
    main()
