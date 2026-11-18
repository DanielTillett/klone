#!/usr/bin/env python3
"""Run a bounded libFuzzer smoke test against actual parser/utility libraries."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="CMake build directory")
    parser.add_argument("--runs", type=int, default=10000)
    args = parser.parse_args()
    tree = args.build.resolve()
    if not tree.is_relative_to(ROOT / ".build"):
        parser.error("Use a generated build inside .build")
    output = tree.parent
    executable = output / "fuzz-parsers"
    # Compile the relevant complete translation units with fuzzer coverage.
    # Remaining collaborators come from the corresponding full build archives.
    sources = ["src/libpage/header.c", "src/libpage/field.c", "src/libutils/utils.c"]
    source = Path(next(line.split("=", 1)[1]
                       for line in (tree / "CMakeCache.txt").read_text().splitlines()
                       if line.startswith("KLone_SOURCE_DIR:")))
    libraries = sorted((tree / "lib").glob("*.a"))
    includes = [tree / "include", tree / "libu/include", source]
    command = ["clang", "-std=gnu99", "-fgnu89-inline", "-g", "-O1", "-DHAVE_CONF_H",
               "-fsanitize=fuzzer,address,undefined", "-fno-omit-frame-pointer",
               *[f"-I{path}" for path in includes],
               str(ROOT / "test/fuzz_parsers.c")]
    command += [str(source / name) for name in sources]
    command += ["-Wl,--start-group", *map(str, libraries), "-Wl,--end-group",
                "-lssl", "-lcrypto", "-lz", "-o", str(executable)]
    subprocess.run(command, check=True)
    corpus = output / "fuzz-corpus"
    corpus.mkdir(exist_ok=True)
    seeds = [b"Host: localhost\r\n\r\n", b"Content-Length: -1\r\n\r\n",
             b"%", b"%4", b"%GG", b"&amp;", b"X: a\r\n folded\r\n\r\n"]
    for i, seed in enumerate(seeds):
        (corpus / f"seed-{i}").write_bytes(seed)
    with (output / "fuzz.log").open("w") as log:
        result = subprocess.run([str(executable), f"-runs={args.runs}", "-max_len=8192",
                                 f"-artifact_prefix={output}/", str(corpus)],
                                env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError((output / "fuzz.log").read_text()[-6000:])
    print(f"Parser fuzz smoke test passed ({args.runs} runs); log: {output / 'fuzz.log'}")


if __name__ == "__main__":
    main()
