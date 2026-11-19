#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Compile selected production functions without the legacy MaKL/LibU build.

The C harness provides only the external types/macros and I/O test doubles.
Function bodies are copied verbatim on every run, never reimplemented.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = {
    "src/libutils/utils.c": [
        "u_strnstr", "htoi", "u_urlncpy_encode", "u_urlncpy_decode", "u_urlncpy",
        "u_tochex", "u_hex2ch", "u_hexncpy_decode", "u_hexncpy_encode", "u_hexncpy",
        "u_tohex", "u_md5io",
        "u_stristr", "u_htmlncpy_encode", "u_htmlncpy_decode", "u_htmlncpy",
        "u_sqlncpy_encode", "u_sqlncpy_decode", "u_sqlncpy",
        "u_urlncpy_s", "u_hexncpy_s", "u_htmlncpy_s", "u_sqlncpy_s",
    ],
    "src/libutils/path.c": ["u_uri_normalize"],
    "src/libpage/request.c": ["request_set_content_length"],
    "src/libpage/header.c": ["header_load_ex"],
    "src/libio/iomem.c": ["io_mem_seek"],
    "src/libhttp/sup_fs.c": ["fs_serve"],
}


def extract(source, name):
    # In these sources function definitions and their final braces start in
    # column zero. Fail explicitly if that convention changes.
    pattern = rf"^[\w *]+\b{re.escape(name)}\([^;]*?\)\n\{{\n.*?^\}}"
    matches = re.findall(pattern, source, re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise ValueError(f"Expected one definition of {name}, found {len(matches)}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="klin-regressions-") as directory:
        temp = Path(directory)
        utility_source = (ROOT / "src/libutils/utils.c").read_text(encoding="utf-8")
        entities = re.search(r"static struct html_entities_s\n\{.*?^\};",
                             utility_source, re.MULTILINE | re.DOTALL)
        if entities is None:
            raise ValueError("HTML entity table not found")
        bodies = [entities.group()]
        for filename, names in FUNCTIONS.items():
            source = (ROOT / filename).read_text(encoding="utf-8")
            bodies.extend(extract(source, name) for name in names)
        (temp / "regression_functions.inc").write_text("\n\n".join(bodies), encoding="utf-8")
        executable = temp / ("regressions.exe" if os.name == "nt" else "regressions")
        command = shlex.split(args.cc, posix=os.name != "nt") + [
            "-std=c99", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT), "-I", str(temp),
            str(ROOT / "test/regressions.c"), str(ROOT / "src/libutils/md5.c"),
            "-o", str(executable),
        ]
        if args.sanitize:
            command += ["-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"]
        subprocess.run(command, check=True)
        env = os.environ.copy()
        if args.sanitize and os.name == "nt":
            compiler = shlex.split(args.cc, posix=False)
            runtime = subprocess.check_output(
                compiler + ["--print-runtime-dir"], text=True
            ).strip()
            # Some LLVM Windows packages report the target directory while
            # shipping the dynamic runtime in its sibling "windows" folder.
            runtime_paths = [runtime, str(Path(runtime).parent / "windows")]
            env["PATH"] = os.pathsep.join(runtime_paths + [env.get("PATH", "")])
        subprocess.run([str(executable)], check=True, timeout=30, env=env)


if __name__ == "__main__":
    main()
