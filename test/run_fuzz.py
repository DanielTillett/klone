#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Build every fuzz target in fuzz/ (clang, libFuzzer, ASan and UBSan) and
run each one briefly from its seeds (doc/FUZZING):

    python3 test/run_fuzz.py [--runs N] [--target NAME ...]

The build goes to .build/fuzz; a crash is left there as crash-*."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SANITIZERS = "-fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=undefined"


def targets():
    lines = (line.strip() for line in (ROOT / "fuzz/targets.txt").read_text().splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10000, help="inputs per target")
    parser.add_argument("--target", action="append", help="only this target (repeatable)")
    parser.add_argument("--build", type=Path, help=argparse.SUPPRESS)  # older callers
    args = parser.parse_args()
    out = ROOT / ".build/fuzz"
    log = out.parent / "fuzz.log"
    out.mkdir(parents=True, exist_ok=True)
    flags = f"-g -O1 -fno-omit-frame-pointer {SANITIZERS}"
    # the targets link with the C++ driver (libFuzzer is C++)
    env = dict(os.environ, CC="clang", CXX="clang++", CFLAGS=flags, CXXFLAGS=flags)
    with log.open("w") as lf:
        if not (out / "CMakeCache.txt").exists():
            generator = ["-G", "Ninja"] if shutil.which("ninja") else []
            subprocess.run(["cmake", "-S", str(ROOT), "-B", str(out), *generator,
                            "-DKLIN_FUZZ=ON", "-DKLIN_HARDENING=OFF", "-DCMAKE_BUILD_TYPE=Debug"],
                           env=env, stdout=lf, stderr=subprocess.STDOUT, check=True)
        names = args.target or targets()
        subprocess.run(["cmake", "--build", str(out), "--target", *[f"fuzz_{t}" for t in names]],
                       env=env, stdout=lf, stderr=subprocess.STDOUT, check=True)
    failed = []
    for name in names:
        corpus = out / "corpus" / name
        corpus.mkdir(parents=True, exist_ok=True)
        seeds = ROOT / "fuzz/seeds" / name
        command = [str(out / "fuzz" / f"fuzz_{name}"), f"-runs={args.runs}", "-max_len=8192",
                   "-timeout=10", f"-artifact_prefix={out}/{name}-", str(corpus)]
        if seeds.is_dir():
            command.append(str(seeds))
        dictionary = ROOT / "fuzz" / f"fuzz_{name}.dict"
        if dictionary.exists():
            command.insert(1, f"-dict={dictionary}")
        with log.open("a") as lf:
            lf.write(f"\n=== {name}\n")
            lf.flush()
            result = subprocess.run(command, stdout=lf, stderr=subprocess.STDOUT)
        if result.returncode:
            failed.append(name)
    if failed:
        raise SystemExit(f"Fuzz targets failed: {', '.join(failed)}; see {log}\n" +
                         log.read_text()[-6000:])
    print(f"Fuzz smoke test passed: {len(names)} targets, {args.runs} runs each; log: {log}")


if __name__ == "__main__":
    main()
