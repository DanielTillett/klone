#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Build-system checks: awkward site file names, page includes, escaped
compiler flags, import options, incremental rebuilds and the install tree.

Builds in a temporary directory (nothing is written to the checkout):

    python3 test/run_build_checks.py [--generator G] [--make-program P]
"""
import argparse
import os
import re
import platform
from pathlib import Path
import shutil
import socket
import subprocess
import sys
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


def build(build_dir, args, *defines, source=ROOT):
    command = ["cmake", "-S", str(source), "-B", str(build_dir), "-G", args.generator, *defines]
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


def site_config(port):
    return (f"server_list h\nallow_root yes\nh\n{{\n type http\n addr tcp4://127.0.0.1:{port}\n"
            " dir_root /www\n}\n")


def fetch_all(daemon, temp, paths, embedded_port=None):
    """Serve 'paths' with a -f configuration, or, given embedded_port, with
    the configuration embedded in the site (listening on that port)."""
    port = embedded_port or free_port()
    command = [str(daemon), "-F", "-d"]
    if not embedded_port:
        config = temp / "klind.conf"
        config.write_text(site_config(port))
        command += ["-f", str(config)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


# the only sources that may call OpenSSL: the crypto backend and the TLS
# layer (doc/CRYPTO); everything else goes through klin/crypto.h and tls.h
OPENSSL_ALLOWED = {"src/libutils/crypto.c", "src/libtls/tls.c", "src/libtls/tls_glue.c",
                   "src/libtls/keyproxy.c", "src/libio/iossl.c", "klin/tlsprv.h"}


def check_openssl_confined():
    found = set()
    for top in ("src", "klin", "webapp"):
        for path in (ROOT / top).rglob("*.[ch]"):
            text = path.read_text(errors="replace")
            if "#include <openssl/" in text:
                found.add(path.relative_to(ROOT).as_posix())
    check(found <= OPENSSL_ALLOWED,
          f"OpenSSL used outside the crypto backend and TLS layer: {sorted(found - OPENSSL_ALLOWED)}")


def check_hardening(daemon):
    """The protections of KLIN_HARDENING are really in the program
    (doc/HARDENING): read the ELF headers of klind (Linux, readelf)."""
    if not sys.platform.startswith("linux") or shutil.which("readelf") is None:
        return
    rc, out = run(["readelf", "-W", "-h", "-l", "-d", "-n", "--dyn-syms", str(daemon)])
    check(rc == 0, f"readelf failed: {out[-1000:]}")
    stack = [line for line in out.splitlines() if "GNU_STACK" in line]
    for name, ok in [
            ("position independent (PIE)", re.search(r"Type:\s+DYN", out) is not None),
            ("read-only relocations (RELRO)", "GNU_RELRO" in out),
            ("immediate binding (BIND_NOW)", "BIND_NOW" in out or re.search(r"FLAGS_1.*\bNOW\b", out)),
            ("non-executable stack", stack and " RWE " not in stack[0] and " RW " in stack[0]),
            ("stack protector", "__stack_chk_fail" in out),
            ("_FORTIFY_SOURCE", re.search(r"__\w+_chk\b", out.replace("__stack_chk_fail", "")))]:
        check(ok, f"klind is not hardened: no {name}")
    if platform.machine() in ("x86_64", "AMD64"):
        check("IBT" in out and "SHSTK" in out,
              "klind is not hardened: no control-flow protection (IBT, SHSTK)")


def check_cgi(daemon, temp):
    cgi_dir = temp / "cgi-bin"
    cgi_dir.mkdir()
    scripts = {
        "echo.sh": "printf 'Content-Type: text/plain\\r\\nX-Cgi: yes\\r\\n\\r\\n'\n"
                   "printf 'cgi %s\\n' \"$REQUEST_METHOD\"\ncat\n",
        "status.sh": "printf 'Status: 404 Nope\\r\\nContent-Type: text/plain\\r\\n\\r\\n'\n"
                     "echo missing\n",
    }
    for name, body in scripts.items():
        (cgi_dir / name).write_text("#!/bin/sh\n" + body)
        (cgi_dir / name).chmod(0o755)
    port = free_port()
    config = temp / "cgi.conf"
    config.write_text(f"server_list h\nallow_root yes\nh\n{{\n type http\n addr tcp4://127.0.0.1:{port}\n"
                      f" dir_root /www\n cgi\n {{\n  script_alias /cgi-bin {cgi_dir}\n }}\n}}\n")
    process = subprocess.Popen([str(daemon), "-F", "-d", "-f", str(config)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}/cgi-bin/"
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        with urllib.request.urlopen(base + "echo.sh", timeout=5) as response:
            check(response.headers.get("X-Cgi") == "yes" and response.read() == b"cgi GET\n",
                  "CGI GET failed")
        with urllib.request.urlopen(base + "echo.sh", data=b"posted body", timeout=5) as response:
            check(response.read() == b"cgi POST\nposted body", "CGI POST body not passed through")
        try:
            urllib.request.urlopen(base + "status.sh", timeout=5)
            check(False, "CGI Status: 404 ignored")
        except urllib.error.HTTPError as error:
            check(error.code == 404 and error.read() == b"missing\n", f"CGI Status: {error.code}")
    finally:
        process.terminate()
        process.wait()


def main():
    check_openssl_confined()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generator", default="Ninja" if shutil.which("ninja") else "Unix Makefiles")
    parser.add_argument("--make-program", help="build tool for the generator, e.g. bmake")
    args = parser.parse_args()
    program = args.make_program or ""
    # any Ninja-based generator (e.g. "CodeBlocks - Ninja"), or a GNU make
    gnu_or_ninja = "Ninja" in args.generator or "GNU Make" in run([program or "make", "--version"])[1]

    with tempfile.TemporaryDirectory(prefix="klin-build-checks-") as directory:
        temp = Path(directory)
        site = temp / "site"
        www = site / "www"
        www.mkdir(parents=True)
        # page include whose name needs escaping in make-style depfiles
        (www / "part#1.inc").write_text("<% io_printf(out, \"part-one\\n\"); %>\n")
        (www / "index.kl1").write_text('<%@ include "part#1.inc" %>\n'
                                       '<% io_printf(out, "flag=%s\\n", KLIN_CHECK_STR); %>\n')
        # a page written for KLone (renamed Klin): old header and names, a
        # page with the old .klone extension, and the configuration
        # embedded under its old name, /etc/kloned.conf
        (www / "old.kl1").write_text('<%! #include <klone/utils.h> %>\n'
                                     '<% io_printf(out, "old=%s\\n", KLONE_VERSION); %>\n')
        (www / "legacy.klone").write_text('<% io_printf(out, "legacy-%s\\n", "page"); %>\n')
        embedded_port = free_port()
        (site / "etc").mkdir()
        (site / "etc/kloned.conf").write_text(site_config(embedded_port))
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
        #    patterns and the optional CGI and file-system suppliers; the
        #    site is given with its name from before KLone was renamed Klin
        b = temp / "build"
        rc, out = build(b, args, f"-DKLONE_SITE_DIR={site}",
                        f"-DKLIN_IMPORT_ARGS=-x;*.bak;-e;*secret*;-k;{key}",
                        "-DKLIN_ENABLE_SUP_CGI=ON", "-DKLIN_ENABLE_SUP_FS=ON",
                        '-DCMAKE_C_FLAGS_RELEASE=-O2 -DKLIN_CHECK_STR=\\"escaped\\"')
        check(rc == 0, f"site build failed:\n{out[-4000:]}")
        check("KLONE_SITE_DIR is now KLIN_SITE_DIR" in " ".join(out.split()),
              "no deprecation warning for KLONE_SITE_DIR")
        version = (ROOT / "VERSION").read_text().strip()
        check_hardening(b / "bin/klind")
        served = fetch_all(b / "bin/klind", temp, ["index.kl1", "old.kl1", "legacy.klone", *names])
        check("part-one" in str(served["index.kl1"]), f"page include not served: {served['index.kl1']!r}")
        check("flag=escaped" in str(served["index.kl1"]), f"escaped flag lost: {served['index.kl1']!r}")
        check(f"old={version}" in str(served["old.kl1"]), f"KLone-era page failed: {served['old.kl1']!r}")
        # run as a page: its output, not its source (the page's last
        # newline is HTML and is sent too)
        check(str(served["legacy.klone"]).strip() == "legacy-page",
              f".klone page not run as a page: {served['legacy.klone']!r}")
        embedded = fetch_all(b / "bin/klind", temp, ["old.kl1"], embedded_port)
        check(f"old={version}" in str(embedded["old.kl1"]),
              f"embedded /etc/kloned.conf not used: {embedded['old.kl1']!r}")

        # CGI scripts (the build has the CGI supplier): GET, a POST body on
        # the script's stdin, and a Status line setting the response code
        if os.name != "nt":
            check_cgi(b / "bin/klind", temp)

        # a second configure keeps the site given as KLONE_SITE_DIR (moved
        # to KLIN_SITE_DIR in the cache, the old entry removed)
        rc, out = run(["cmake", "-S", str(ROOT), "-B", str(b)])
        cache = (b / "CMakeCache.txt").read_text()
        check(rc == 0 and f"KLIN_SITE_DIR:PATH={site}" in cache and "\nKLONE_SITE_DIR:" not in cache,
              f"KLONE_SITE_DIR lost on reconfigure:\n{out[-2000:]}")

        # page URIs are written into the generated C as escaped string
        # literals: quotes, backslashes, trigraphs and control characters
        # must not break it (given with -u here: CMake's own file globbing
        # refuses such names inside a site)
        includes = [f"-I{b / 'include'}", f"-I{b / 'libu/include'}", f"-I{ROOT}"]
        includes += [f"-I{line.split('=', 1)[1]}" for line in cache.splitlines()
                     if line.startswith("OPENSSL_INCLUDE_DIR:") and line.split("=", 1)[1]]
        for source in [www / "old.kl1", www / "trailing]"]:
            generated = temp / (source.name + ".c")
            uri = '/d"ir\\x??=/p\x01"a\\ge' + source.suffix
            # -u drops its first character (an MSYS workaround): the site
            # build passes "/${uri}" too
            rc, out = run([str(b / "bin/klin"), "-c", "translate", "-i", str(source),
                           "-o", str(generated), "-u", "/" + uri])
            check(rc == 0, f"translate failed for {source.name}:\n{out[-2000:]}")
            rc, out = run(["cc", "-fsyntax-only", "-DHAVE_CONF_H", *includes, str(generated)])
            check(rc == 0, f"generated C for an awkward URI does not compile:\n{out[-3000:]}")
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
        served = fetch_all(b / "bin/klind", temp, ["index.kl1"])
        check("part-two" in str(served["index.kl1"]), "include change did not rebuild the page")

        # 3. spaces with a make that cannot handle them fail clearly
        if not gnu_or_ninja:
            spaced = temp / "spaced site"
            (spaced / "www").mkdir(parents=True)
            (spaced / "www/a.txt").write_text("a\n")
            rc, out = build(temp / "build-spaced", args, f"-DKLIN_SITE_DIR={spaced}")
            # CMake wraps long messages, so compare with whitespace collapsed
            check(rc != 0 and "paths containing spaces need Ninja or GNU make" in " ".join(out.split()),
                  f"no clear error for spaces with {program}:\n{out[-2000:]}")

        # 4. the install tree is enough to compile and link against Klin
        prefix = temp / "prefix"
        rc, out = run(["cmake", "--install", str(b), "--prefix", str(prefix)])
        check(rc == 0, f"install failed:\n{out[-2000:]}")
        program_c = temp / "uses_klin.c"
        program_c.write_text("#include <klin/klin.h>\n#include <klin/vhost.h>\n#include <klin/hook.h>\n"
                             "#include <klin/version.h>\n#include <stdio.h>\n"
                             "int main(void) { return puts(klin_version()) < 0; }\n")
        lib = next(p for p in (prefix / "lib", prefix / "lib64") if p.exists())
        # Klin's public headers include OpenSSL's, which a consumer supplies
        # itself (on macOS, Homebrew's OpenSSL is not on the default path)
        cache = (b / "CMakeCache.txt").read_text().splitlines()
        openssl = [line.split("=", 1)[1] for line in cache if line.startswith("OPENSSL_INCLUDE_DIR:")]
        command = ["cc", "-I", str(prefix / "include"), *[f"-I{d}" for d in openssl if d],
                   str(program_c), "-o", str(temp / "uses_klin"), "-L", str(lib), "-lutils", "-lu"]
        rc, out = run(command)
        check(rc == 0, f"compile/link against the install prefix failed:\n{out[-3000:]}")
        rc, out = run([str(temp / "uses_klin")])
        check(rc == 0 and out.strip() == version, f"wrong version: {out!r}")

        # 4b. ... through the CMake package (find_package(Klin), Klin::klin)
        #     and through pkg-config, without listing libraries by hand
        consumer = temp / "consumer"
        consumer.mkdir()
        (consumer / "main.c").write_text(program_c.read_text())
        (consumer / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.24)\nproject(consumer C)\n"
            "find_package(Klin 4 REQUIRED)\nadd_executable(consumer main.c)\n"
            "target_link_libraries(consumer PRIVATE Klin::klin)\n")
        openssl_root = [line.split("=", 1)[1] for line in cache if line.startswith("OPENSSL_ROOT_DIR:")]
        rc, out = build(temp / "consumer-build", args, f"-DCMAKE_PREFIX_PATH={prefix}",
                        *[f"-DOPENSSL_ROOT_DIR={d}" for d in openssl_root if d],
                        source=consumer)
        check(rc == 0, f"find_package(Klin) consumer failed:\n{out[-3000:]}")
        rc, out = run([str(temp / "consumer-build/consumer")])
        check(rc == 0 and out.strip() == version, f"Klin::klin consumer: wrong version: {out!r}")
        if shutil.which("pkg-config"):
            env = {**os.environ, "PKG_CONFIG_PATH": str(lib / "pkgconfig")}
            rc, flags = run(["pkg-config", "--cflags", "--libs", "klin"], env=env)
            check(rc == 0, f"pkg-config klin failed:\n{flags}")
            rc, out = run(["cc", str(program_c), "-o", str(temp / "uses_klin_pc"), *flags.split()])
            check(rc == 0, f"compile/link with pkg-config klin failed:\n{out[-3000:]}")
            rc, out = run([str(temp / "uses_klin_pc")])
            check(rc == 0 and out.strip() == version, f"pkg-config consumer: wrong version: {out!r}")

        # 5. ... and so is code written for KLone (renamed Klin) for one
        #    release: old headers and names, and the old command names
        old_c = temp / "uses_klone.c"
        old_c.write_text("#include <klone/klone.h>\n#include <klone/version.h>\n#include <klone_conf.h>\n"
                         "#include <stdio.h>\n#include <string.h>\n"
                         "int main(void) { klone_die_if(strcmp(klone_version(), KLONE_VERSION), \"bad\");\n"
                         " return puts(klone_version()) < 0; }\n")
        command[command.index(str(program_c))] = str(old_c)
        command[command.index(str(temp / "uses_klin"))] = str(temp / "uses_klone")
        rc, out = run(command)
        check(rc == 0, f"KLone-era code did not compile against the install prefix:\n{out[-3000:]}")
        rc, out = run([str(temp / "uses_klone")])
        check(rc == 0 and out.strip() == version, f"wrong version from KLone-era code: {out!r}")
        if os.name != "nt":
            for old, new in [("bin/klone", "klin"), ("sbin/kloned", "klind")]:
                link = prefix / old
                check(link.is_symlink() and os.readlink(link) == new, f"{old} is not a link to {new}")

            # the links follow an absolute install directory, under DESTDIR
            tools = temp / "tools-bin"
            rc, out = run(["cmake", "-S", str(ROOT), "-B", str(b), f"-DCMAKE_INSTALL_BINDIR={tools}"])
            check(rc == 0, f"reconfigure with an absolute bindir failed:\n{out[-2000:]}")
            stage = temp / "stage"
            rc, out = run(["cmake", "--install", str(b), "--prefix", "/opt/klin"],
                          env={**os.environ, "DESTDIR": str(stage)})
            link = Path(str(stage) + str(tools)) / "klone"
            check(rc == 0 and link.is_symlink() and os.readlink(link) == "klin"
                  and (link.parent / "klin").exists(),
                  f"klone link not next to klin in an absolute bindir:\n{out[-2000:]}")

    print(f"{checks} build-system checks passed ({args.generator}{' ' + program if program else ''})")


if __name__ == "__main__":
    main()
