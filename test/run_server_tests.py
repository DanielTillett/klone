#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of KLone; see the LICENSE file.
"""Build a test-only embedded page and exercise the real HTTP/TLS daemon."""
import argparse
from http.cookies import SimpleCookie
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exchange(port, data, context=None, half_close=False, close=True):
    """Send one request and read until the server closes the connection.

    With close, "Connection: close" is added so a persistent (keep-alive)
    connection is not held open by the server after the response."""
    if close and b"\r\n" in data:
        line, rest = data.split(b"\r\n", 1)
        data = line + b"\r\nConnection: close\r\n" + rest
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        connection = context.wrap_socket(raw, server_hostname="localhost") if context else raw
        with connection:
            connection.sendall(data)
            if half_close:
                connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                try:
                    chunk = connection.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)


class Connection:
    """A client connection that reads responses by their HTTP framing, so
    several requests can be sent on it (keep-alive, pipelining)."""

    def __init__(self, port, context=None):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock = context.wrap_socket(raw, server_hostname="localhost") if context else raw
        self.buf = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.sock.close()

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("connection closed")
        self.buf += chunk

    def _line(self):
        while b"\r\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _take(self, size):
        while len(self.buf) < size:
            self._fill()
        data, self.buf = self.buf[:size], self.buf[size:]
        return data

    def response(self, head=False):
        """Read one response: (status line, {lowercase name: value}, body)."""
        status = self._line().decode()
        headers = {}
        while line := self._line():
            name, _, value = line.decode().partition(":")
            headers[name.strip().lower()] = value.strip()
        code = int(status.split()[1])
        if head or code in (204, 304) or 100 <= code < 200:
            body = b""
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while size := int(self._line().split(b";")[0], 16):
                body += self._take(size)
                if self._take(2) != b"\r\n":
                    raise ValueError("chunk not followed by CRLF")
            while self._line():
                pass  # trailer fields
        elif "content-length" in headers:
            body = self._take(int(headers["content-length"]))
        else:
            body = self.buf
            while True:
                try:
                    chunk = self.sock.recv(65536)
                except (ConnectionResetError, ssl.SSLError):
                    break
                if not chunk:
                    break
                body += chunk
            self.buf = b""
        return status, headers, body

    def closed(self):
        """True if the server closes the connection (nothing else is sent)."""
        if self.buf:
            return False
        try:
            return self.sock.recv(1) == b""
        except socket.timeout:
            return False
        except (ConnectionResetError, ssl.SSLError):
            return True


def client_context(version):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # ephemeral local test certificate
    context.minimum_version = version
    context.maximum_version = version
    return context


def run_build_steps(commands, env, log_path):
    with log_path.open("a") as log:
        for command, cwd in commands:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                log.flush()
                raise RuntimeError(log_path.read_text()[-6000:])


def cmake_cache_value(build, name):
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        if line.startswith(name + ":"):
            return line.split("=", 1)[1]
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="CMake build directory")
    parser.add_argument("--prefork", action="store_true", help="exercise the normal multiprocess server model")
    args = parser.parse_args()
    tree = args.build.resolve()
    if not tree.is_relative_to(ROOT / ".build"):
        parser.error("Tests modify only generated builds inside this repository's .build")
    env = os.environ.copy()
    output = tree.parent
    log_path = output / "test-build.log"
    log_path.write_text("")
    restore = None
    try:
        # Embed the test site (with no import options) for this run only.
        # The original settings are restored afterwards, even if the
        # fixture fails to build, so the test page never stays in kloned.
        settings = {name: cmake_cache_value(tree, name)
                    for name in ("KLONE_SITE_DIR", "KLONE_IMPORT_ARGS")}
        rebuild = ["cmake", "--build", str(tree), "--target", "kloned"]
        # 'cmake -D... <existing build dir>' reconfigures with the cached source
        restore = [(["cmake", *[f"-D{k}={v}" for k, v in settings.items()], str(tree)], tree),
                   (rebuild, tree)]
        run_build_steps([(["cmake", f"-DKLONE_SITE_DIR={ROOT / 'test/site'}",
                           "-DKLONE_IMPORT_ARGS=", str(tree)], tree),
                         (rebuild, tree)], env, log_path)
        daemon = tree / "bin" / cmake_cache_value(tree, "KLONE_DAEMON_NAME")
        run_server_checks(args, env, output, daemon)
    finally:
        if restore:
            run_build_steps(restore, env, log_path)


def run_keep_alive_checks(args, check, plain, secure, request):
    """Persistent connections: several requests per connection, pipelining,
    response framing (Content-Length, chunked, bodyless) and closing."""
    hello = b"klone integration test\n"

    def big_page(body):
        lines = body.strip().split(b"\n")
        return (len(lines) == 2000 and lines[0] == b"line 0000 of a long dynamic page"
                and lines[-1] == b"line 1999 of a long dynamic page")

    def get(path, method=b"GET", extra=b""):
        return method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n" + extra + b"\r\n"

    if not args.prefork:
        # the iterative server (-d) would be blocked by an idle client
        with Connection(plain) as conn:
            conn.send(request)
            status, headers, body = conn.response()
            check(body == hello and headers.get("connection") == "close" and conn.closed(),
                  f"Iterative server kept the connection open: {status} {headers}")
        return

    with Connection(plain) as conn:
        for _ in range(2):
            conn.send(request)
            status, headers, body = conn.response()
            check(status.startswith("HTTP/1.1 200") and body == hello and "connection" not in headers,
                  f"Keep-alive GET failed: {status} {headers} {body[:80]!r}")

        # pipelined requests, each response delimited differently
        conn.send(get(b"/static/hello.txt") + get(b"/session.kl1") + get(b"/big.kl1") +
                  get(b"/embedded.txt", b"HEAD") + get(b"/nocontent.kl1") + get(b"/missing.txt") +
                  get(b"/embedded.txt"))
        status, headers, body = conn.response()
        check(body == hello, f"Pipelined static file: {status} {body[:80]!r}")
        status, headers, body = conn.response()
        check(b"new" in body and headers.get("content-length") == str(len(body)),
              f"Dynamic page without Content-Length: {status} {headers}")
        status, headers, body = conn.response()
        check(headers.get("transfer-encoding") == "chunked" and big_page(body),
              f"Chunked dynamic page: {status} {headers} {len(body)}")
        status, headers, body = conn.response(head=True)
        check(status.startswith("HTTP/1.1 200") and headers.get("content-length") == "21",
              f"Embedded static HEAD: {status} {headers}")
        status, headers, body = conn.response()
        check(status.startswith("HTTP/1.1 204") and "content-length" not in headers and
              "transfer-encoding" not in headers, f"204 response: {status} {headers}")
        status, headers, body = conn.response()
        check(status.startswith("HTTP/1.1 404") and headers.get("content-length") == str(len(body)),
              f"Error page framing: {status} {headers}")
        status, headers, body = conn.response()
        check(body == b"embedded static file\n", f"Response after 204/404: {status} {body!r}")

        # an unread request body is skipped before the next request
        conn.send(b"POST /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n"
                  b"Content-Type: application/octet-stream\r\nContent-Length: 5000\r\n\r\n" +
                  b"x" * 5000 + request)
        conn.response()
        status, headers, body = conn.response()
        check(body == hello, f"Request after an unread body: {status} {body[:80]!r}")

        # the client closes
        conn.send(get(b"/static/hello.txt", extra=b"Connection: close\r\n"))
        status, headers, body = conn.response()
        check(body == hello and headers.get("connection") == "close" and conn.closed(),
              f"Connection: close not honoured: {headers}")

    # HTTP/1.0: closed unless the client asks for keep-alive
    with Connection(plain) as conn:
        conn.send(b"GET /static/hello.txt HTTP/1.0\r\n\r\n")
        status, headers, body = conn.response()
        check(status.startswith("HTTP/1.0 200") and body == hello and conn.closed(),
              f"HTTP/1.0 connection not closed: {status} {headers}")
    with Connection(plain) as conn:
        for _ in range(2):
            conn.send(b"GET /static/hello.txt HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
            status, headers, body = conn.response()
            check(body == hello and headers.get("connection") == "keep-alive",
                  f"HTTP/1.0 keep-alive: {status} {headers}")
        conn.send(b"GET /big.kl1 HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        status, headers, body = conn.response()
        check(big_page(body) and "transfer-encoding" not in headers and conn.closed(),
              f"HTTP/1.0 body of unknown length must end with the close: {headers}")

    # an idle connection is closed after keep_alive_timeout (1 s)
    with Connection(plain) as conn:
        conn.send(request)
        conn.response()
        time.sleep(2)
        check(conn.closed(), "Idle keep-alive connection not closed")

    # TLS: several requests on one connection, then close_notify
    with Connection(secure, client_context(ssl.TLSVersion.TLSv1_3)) as conn:
        for path in [b"/static/hello.txt", b"/big.kl1", b"/static/hello.txt"]:
            conn.send(get(path))
            status, headers, body = conn.response()
            check(status.startswith("HTTP/1.1 200") and body, f"TLS keep-alive {path!r}: {status}")
        conn.send(get(b"/static/hello.txt", extra=b"Connection: close\r\n"))
        conn.response()
        check(conn.closed(), "TLS connection not closed")


def run_server_checks(args, env, output, daemon):
    checks = 0

    def check(condition, message):
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(message)

    with tempfile.TemporaryDirectory(prefix="klone-server-test-") as directory:
        temp = Path(directory)
        (temp / "hello.txt").write_text("klone integration test\n")
        (temp / "a+b.txt").write_text("literal plus\n")
        (temp / "a?b.txt").write_text("encoded question\n")
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plain, client, secure = free_port(), free_port(), free_port()
        config = temp / "kloned.conf"
        blocks = []
        for name, port, tls, session in [("plain", plain, False, "memory"),
                                         ("client", client, False, "client"),
                                         ("secure", secure, True, "client")]:
            blocks.append(f"""{name}
{{
    type {'https' if tls else 'http'}
    addr tcp4://127.0.0.1:{port}
    dir_root /www
    dir_alias /static {temp}
    idle_timeout 2
    keep_alive_timeout 1
    prefork.start_child 1
    prefork.max_child 2
    session
    {{
        type {session}
    }}
    {f'cert_file {cert}' if tls else ''}
    {f'key_file {key}' if tls else ''}
}}
""")
        config.write_text("server_list plain client secure\nallow_root yes\n" + "\n".join(blocks))
        log_path = output / ("server-prefork-test.log" if args.prefork else "server-test.log")
        with log_path.open("w") as log:
            command = [str(daemon), "-F", "-f", str(config)]
            if not args.prefork:
                command.append("-d")
            process = subprocess.Popen(command,
                                       env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text()[-6000:])
                    try:
                        with socket.create_connection(("127.0.0.1", plain), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise TimeoutError(log_path.read_text()[-6000:])
                        time.sleep(0.1)
                request = b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
                response = exchange(plain, request)
                check(b"200 OK" in response and response.endswith(b"klone integration test\n"), "GET failed")
                head = exchange(plain, request.replace(b"GET", b"HEAD", 1))
                check(b"200 OK" in head and head.endswith(b"\r\n\r\n"), "HEAD returned a body")
                for path, body in [(b"a+b.txt", b"literal plus\n"), (b"a%3Fb.txt", b"encoded question\n")]:
                    result = exchange(plain, request.replace(b"hello.txt", path))
                    check(result.endswith(body), f"URI decoding failed: {path!r}")
                malformed = [
                    b"Content-Length: -1\r\n", b"Content-Length: 1x\r\n",
                    b"Content-Length: 9999999999999999999999999999\r\n",
                    b"Content-Length: 0\r\nContent-Length: 0\r\n",
                    b"Transfer-Encoding: chunked\r\n",
                    b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
                    b"Bad Header: value\r\n", b"X: a\r\n folded\r\n",
                    b"X: " + b"x" * 8192 + b"\r\n",
                    b"X: a\r\n" * 257,
                    (b"X: " + b"x" * 1000 + b"\r\n") * 70,
                ]
                for header in malformed:
                    reply = exchange(plain, b"GET /static/hello.txt HTTP/1.1\r\n" + header + b"\r\n")
                    check(b"200 OK" not in reply, f"Accepted malformed headers: {header[:80]!r}")
                for path in [b"hello.txt%00suffix", b"%", b"%4", b"%GG"]:
                    reply = exchange(plain, request.replace(b"hello.txt", path))
                    check(b"200 OK" not in reply, f"Accepted bad URI: {path!r}")
                incomplete = exchange(plain, b"GET /static/hello.txt HTTP/1.1\r\nHost: x\r\n", half_close=True)
                check(b"200 OK" not in incomplete, "Accepted incomplete headers")
                for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
                    reply = exchange(secure, request, client_context(version))
                    check(b"200 OK" in reply, f"TLS failed: {version.name}")
                for version in [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1]:
                    context = client_context(version)
                    context.set_ciphers("ALL:@SECLEVEL=0")
                    try:
                        exchange(secure, request, context)
                    except (ssl.SSLError, OSError):
                        check(True, "")
                    else:
                        check(False, f"Accepted obsolete TLS: {version.name}")
                for port, context in [(plain, None), (client, None),
                                      (secure, client_context(ssl.TLSVersion.TLSv1_3))]:
                    cookies = {}
                    for expected in [b"new", b"persisted"]:
                        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()
                        reply = exchange(port, b"GET /session.kl1 HTTP/1.1\r\nHost: localhost\r\nCookie: " +
                                         cookie_header + b"\r\n\r\n", context)
                        header, _, body = reply.partition(b"\r\n\r\n")
                        check(b"200 OK" in header and expected in body, f"Session round-trip failed: {reply[:400]!r}")
                        for line in header.decode().split("\r\n"):
                            if line.lower().startswith("set-cookie:"):
                                check("HttpOnly" in line and "SameSite=Lax" in line and "Path=/" in line,
                                      f"Missing cookie attributes: {line}")
                                check(("; Secure" in line) == (context is not None), "Wrong Secure attribute")
                                parsed = SimpleCookie(line.split(":", 1)[1].strip())
                                cookies.update({k: v.value for k, v in parsed.items()})
                    check(len(cookies.get("klone_sid", "")) == 32, "Wrong session ID length")
                    if "KL1_CLISES_HMAC" in cookies:
                        tag = cookies["KL1_CLISES_HMAC"]
                        cookies["KL1_CLISES_HMAC"] = ("0" if tag[0] != "0" else "1") + tag[1:]
                        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()
                        reply = exchange(port, b"GET /session.kl1 HTTP/1.1\r\nHost: localhost\r\nCookie: " +
                                         cookie_header + b"\r\n\r\n", context)
                        check(b"persisted" not in reply.partition(b"\r\n\r\n")[2],
                              "Accepted a forged client-session MAC")
                run_keep_alive_checks(args, check, plain, secure, request)
                check(b"200 OK" in exchange(plain, request), "Server failed after malformed requests")
            finally:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        log_text = log_path.read_text(errors="replace")
        check("ERROR: AddressSanitizer" not in log_text and "ERROR: LeakSanitizer" not in log_text
              and "AddressSanitizer:DEADLYSIGNAL" not in log_text and "runtime error:" not in log_text,
              "Sanitizer errors in server-test.log")
    print(f"{checks} full-server checks passed; log: {log_path}")


if __name__ == "__main__":
    main()
