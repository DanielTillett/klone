#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of KLone; see the LICENSE file.
"""Build-system checks: awkward site file names, page includes, escaped
compiler flags, import options, incremental rebuilds and the install tree.

Builds in a temporary directory (nothing is written to the checkout):

    python3 test/run_build_checks.py [--generator G] [--make-program P]
"""
import argparse
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

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


def build(build_dir, args, *defines):
    command = ["cmake", "-S", str(ROOT), "-B", str(build_dir), "-G", args.generator, *defines]
    if args.make_program:
        command.append(f"-DCMAKE_MAKE_PROGRAM={args.make_program}")
    rc, out = run(command)
    if rc == 0:
        rc, more = run(["cmake", "--build", str(build_dir)])
        out += more
    return rc, out


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fetch_all(daemon, temp, paths):
    port = free_port()
    config = temp / "kloned.conf"
    config.write_text(f"server_list h\nallow_root yes\nh\n{{\n type http\n addr tcp4://127.0.0.1:{port}\n"
                      " dir_root /www\n}\n")
    process = subprocess.Popen([str(daemon), "-F", "-d", "-f", str(config)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        results = {}
        for path in paths:
            url = f"http://127.0.0.1:{port}/" + urllib.parse.quote(path)
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    results[path] = response.read().decode()
            except urllib.error.HTTPError as error:
                results[path] = error.code
        return results
    finally:
        process.terminate()
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generator", default="Ninja" if shutil.which("ninja") else "Unix Makefiles")
    parser.add_argument("--make-program", help="build tool for the generator, e.g. bmake")
    args = parser.parse_args()
    program = args.make_program or ""
    # any Ninja-based generator (e.g. "CodeBlocks - Ninja"), or a GNU make
    gnu_or_ninja = "Ninja" in args.generator or "GNU Make" in run([program or "make", "--version"])[1]

    with tempfile.TemporaryDirectory(prefix="klone-build-checks-") as directory:
        temp = Path(directory)
        site = temp / "site"
        www = site / "www"
        www.mkdir(parents=True)
        # page include whose name needs escaping in make-style depfiles
        (www / "part#1.inc").write_text("<% io_printf(out, \"part-one\\n\"); %>\n")
        (www / "index.kl1").write_text('<%@ include "part#1.inc" %>\n'
                                       '<% io_printf(out, "flag=%s\\n", KLONE_CHECK_STR); %>\n')
        names = {"trailing]": "t\n", "x]==]y.txt": "b\n", "hash#name.txt": "h\n", "skip.bak": "s\n",
                 "secret.txt": "encrypted at rest\n"}
        if gnu_or_ninja:
            names["dir with space/file with space.txt"] = "s\n"
        for name, body in names.items():
            (www / name).parent.mkdir(parents=True, exist_ok=True)
            (www / name).write_text(body)

        # key file whose path ends in ']' (encrypts secret.txt)
        key = temp / "key]"
        key.write_bytes(b"k" * 32)

        # 1. build with escaped compiler flags, exclusion and encryption
        #    patterns and the optional CGI and file-system suppliers
        b = temp / "build"
        rc, out = build(b, args, f"-DKLONE_SITE_DIR={site}",
                        f"-DKLONE_IMPORT_ARGS=-x;*.bak;-e;*secret*;-k;{key}",
                        "-DKLONE_ENABLE_SUP_CGI=ON", "-DKLONE_ENABLE_SUP_FS=ON",
                        '-DCMAKE_C_FLAGS_RELEASE=-O2 -DKLONE_CHECK_STR=\\"escaped\\"')
        check(rc == 0, f"site build failed:\n{out[-4000:]}")
        served = fetch_all(b / "bin/kloned", temp, ["index.kl1", *names])
        check("part-one" in str(served["index.kl1"]), f"page include not served: {served['index.kl1']!r}")
        check("flag=escaped" in str(served["index.kl1"]), f"escaped flag lost: {served['index.kl1']!r}")
        site_library = (b / "lib").glob("*site*")
        for name, body in names.items():
            if name.endswith(".bak"):
                check(served[name] == 404, f"excluded file was embedded: {name}")
            elif name == "secret.txt":
                # encrypted pages need a per-session key: 430 "key needed",
                # and the plain text must not be in the embedded site
                check(served[name] == 430, f"encrypted page served without a key: {served[name]!r}")
                check(not any(body.encode() in p.read_bytes() for p in site_library),
                      "encrypted page stored in plain text")
            else:
                check(served[name] == body, f"wrong content for {name!r}: {served[name]!r}")

        # 2. editing the included file retranslates the including page
        time.sleep(1.1)  # make-based builds compare timestamps
        (www / "part#1.inc").write_text("<% io_printf(out, \"part-two\\n\"); %>\n")
        rc, out = run(["cmake", "--build", str(b)])
        check(rc == 0, f"incremental build failed:\n{out[-4000:]}")
        served = fetch_all(b / "bin/kloned", temp, ["index.kl1"])
        check("part-two" in str(served["index.kl1"]), "include change did not rebuild the page")

        # 3. spaces with a make that cannot handle them fail clearly
        if not gnu_or_ninja:
            spaced = temp / "spaced site"
            (spaced / "www").mkdir(parents=True)
            (spaced / "www/a.txt").write_text("a\n")
            rc, out = build(temp / "build-spaced", args, f"-DKLONE_SITE_DIR={spaced}")
            # CMake wraps long messages, so compare with whitespace collapsed
            check(rc != 0 and "paths containing spaces need Ninja or GNU make" in " ".join(out.split()),
                  f"no clear error for spaces with {program}:\n{out[-2000:]}")

        # 4. the install tree is enough to compile and link against KLone
        prefix = temp / "prefix"
        rc, out = run(["cmake", "--install", str(b), "--prefix", str(prefix)])
        check(rc == 0, f"install failed:\n{out[-2000:]}")
        program_c = temp / "uses_klone.c"
        program_c.write_text("#include <klone/klone.h>\n#include <klone/vhost.h>\n#include <klone/hook.h>\n"
                             "#include <klone/version.h>\n#include <stdio.h>\n"
                             "int main(void) { return puts(klone_version()) < 0; }\n")
        lib = next(p for p in (prefix / "lib", prefix / "lib64") if p.exists())
        # KLone's public headers include OpenSSL's, which a consumer supplies
        # itself (on macOS, Homebrew's OpenSSL is not on the default path)
        cache = (b / "CMakeCache.txt").read_text().splitlines()
        openssl = [line.split("=", 1)[1] for line in cache if line.startswith("OPENSSL_INCLUDE_DIR:")]
        command = ["cc", "-I", str(prefix / "include"), *[f"-I{d}" for d in openssl if d],
                   str(program_c), "-o", str(temp / "uses_klone"), "-L", str(lib), "-lutils", "-lu"]
        rc, out = run(command)
        check(rc == 0, f"compile/link against the install prefix failed:\n{out[-3000:]}")
        rc, out = run([str(temp / "uses_klone")])
        check(rc == 0 and out.strip() == (ROOT / "VERSION").read_text().strip(), f"wrong version: {out!r}")

    print(f"{checks} build-system checks passed ({args.generator}{' ' + program if program else ''})")


if __name__ == "__main__":
    main()
