#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Native Windows smoke test: start klind.exe (single-process model) with
an HTTP and an HTTPS server and fetch a dynamic page, a static file and a
missing one over each. The full server tests need fork(2) and /proc."""
import argparse
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fetch(port, path, tls=False):
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # ephemeral test certificate
        raw = context.wrap_socket(raw, server_hostname="localhost")
    with raw:
        raw.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        data = b""
        while chunk := raw.recv(65536):
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split(b"\r\n")[0].split()[1]), body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    args = parser.parse_args()
    failures = 0
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                        str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        plain, secure = free_port(), free_port()
        config = temp / "klind.conf"
        config.write_text(
            f"server_list plain secure\nallow_root yes\n"
            f"log\n{{\ntype file\nfile.basename {(temp / 'klog').as_posix()}\n"
            f"file.limit 1000000\nfile.splits 2\n}}\n"
            f"plain\n{{\ntype http\naddr tcp4://127.0.0.1:{plain}\ndir_root /www\n}}\n"
            f"secure\n{{\ntype https\naddr tcp4://127.0.0.1:{secure}\ndir_root /www\n"
            f"cert_file {cert.as_posix()}\nkey_file {key.as_posix()}\n}}\n")
        log = (temp / "klind.log").open("w")
        process = subprocess.Popen([str(args.daemon), "-F", "-d", "-f", str(config)],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError("klind exited: " + (temp / "klind.log").read_text())
                try:
                    socket.create_connection(("127.0.0.1", plain), timeout=0.5).close()
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.2)
            for port, tls in [(plain, False), (secure, True)]:
                for path, status, needle in [(b"/index.kl1", 200, b"Welcome to Klin"),
                                             (b"/kl.css", 200, b"{"),
                                             (b"/missing.txt", 404, b"")]:
                    try:
                        got, body = fetch(port, path, tls)
                    except OSError as e:
                        got, body = repr(e), b""
                    ok = got == status and needle in body
                    failures += not ok
                    print(f"{'ok  ' if ok else 'FAIL'} {'https' if tls else 'http '} {path.decode()}: {got}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            log.close()
            if failures:
                for f in sorted(temp.glob("klind.log")) + sorted(temp.glob("klog*")):
                    print(f"--- {f.name} ---")
                    print(f.read_text(errors="replace")[-8000:])
    if failures:
        sys.exit(f"{failures} Windows smoke checks failed")
    print("Windows smoke test passed")


if __name__ == "__main__":
    main()
