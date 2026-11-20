#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Build a test-only embedded page and exercise the real HTTP/TLS daemon."""
import argparse
import base64
import hashlib
import json
from http.cookies import SimpleCookie
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import zlib

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
    # BSD make compares whole-second file times: what is rebuilt in the
    # second the previous build ended (the library, klind) would look no
    # newer than it, and the old site would stay linked in
    time.sleep(1.1)
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
        # fixture fails to build, so the test page never stays in klind.
        settings = {name: cmake_cache_value(tree, name)
                    for name in ("KLIN_SITE_DIR", "KLIN_IMPORT_ARGS")}
        rebuild = ["cmake", "--build", str(tree), "--target", "klind"]
        # 'cmake -D... <existing build dir>' reconfigures with the cached source
        restore = [(["cmake", *[f"-D{k}={v}" for k, v in settings.items()], str(tree)], tree),
                   (rebuild, tree)]
        run_build_steps([(["cmake", f"-DKLIN_SITE_DIR={ROOT / 'test/site'}",
                           "-DKLIN_IMPORT_ARGS=-Z;*range-z.txt", str(tree)], tree),
                         (rebuild, tree)], env, log_path)
        daemon = tree / "bin" / cmake_cache_value(tree, "KLIN_DAEMON_NAME")
        run_server_checks(args, env, output, daemon)
    finally:
        if restore:
            run_build_steps(restore, env, log_path)


def run_keep_alive_checks(args, check, plain, secure, request):
    """Persistent connections: several requests per connection, pipelining,
    response framing (Content-Length, chunked, bodyless) and closing."""
    hello = b"klin integration test\n"

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

    # bodies larger than the connection's write buffer skip it (passthru),
    # still within the announced Content-Length
    large = bytes(ord("a") + i % 26 for i in range(150000))
    for port, context in [(plain, None), (secure, client_context(ssl.TLSVersion.TLSv1_3))]:
        with Connection(port, context) as conn:
            for _ in range(2):
                conn.send(get(b"/large.kl1") + get(b"/static/hello.txt"))
                status, headers, body = conn.response()
                check(headers.get("content-length") == "150000" and body == large,
                      f"Large body on port {port}: {status} {headers} {len(body)}")
                status, headers, body = conn.response()
                check(body == hello, f"Request after a large body on port {port}: {status}")
        with Connection(port, context) as conn:
            conn.send(get(b"/large.kl1?m=long"))
            status, headers, body = conn.response()
            check(headers.get("content-length") == "149990" and body == large[:149990] and
                  conn.closed(),
                  f"Large body longer than Content-Length on port {port}: {headers} {len(body)}")
        with Connection(port, context) as conn:
            conn.send(get(b"/large.kl1?m=short"))
            try:
                status, headers, body = conn.response()
                short = False
            except EOFError:
                short = len(conn.buf) == 150000
            check(short, f"Large body shorter than Content-Length not ended by a close on port {port}")

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

    # a connection kept open for more than a second, but busy only for short
    # requests, must not make the worker ask for a replacement and exit
    pids, dropped = set(), False
    with Connection(plain) as conn:
        try:
            for _ in range(7):
                conn.send(get(b"/pid.kl1"))
                status, headers, body = conn.response()
                pids.add(body.strip())
                time.sleep(0.4)
        except EOFError:
            dropped = True
    check(not dropped, "Kept-alive connection dropped after a second (prefork watchdog)")
    worker = pids.pop().decode() if len(pids) == 1 else ""
    time.sleep(1)
    state = subprocess.run(["ps", "-o", "stat=", "-p", worker or "0"],
                           stdout=subprocess.PIPE, text=True).stdout.strip()
    check(worker.isdigit() and state and not state.startswith("Z"),
          f"Worker retired after an idle keep-alive connection: pid {worker} state {state!r}")

    # a client waiting while every worker holds a kept-alive connection gets a
    # new worker after about a second, not when that connection ends
    stop, held_errors, waited, spare = threading.Event(), [], None, ""

    def keep_using(conn):
        try:
            while not stop.is_set():
                conn.send(request)
                conn.response()
                time.sleep(0.3)
        except (OSError, EOFError) as e:
            held_errors.append(e)

    with Connection(plain) as held, Connection(plain) as waiting:
        held.send(request)
        held.response()
        user = threading.Thread(target=keep_using, args=(held,))
        user.start()
        try:
            start = time.time()
            waiting.send(get(b"/pid.kl1"))
            status, headers, body = waiting.response()
            if body.strip().isdigit():
                waited, spare = time.time() - start, body.strip().decode()
        except (OSError, EOFError):
            pass
        finally:
            stop.set()
            user.join()
    check(waited is not None and waited < 3,
          f"Client not served while another kept a connection in use (waited {waited})")
    check(not held_errors, f"Kept-alive connection dropped for a waiting client: {held_errors}")

    # the worker started for the waiting client is a spare: it exits after
    # prefork.idle_timeout (1 s) without a client, so the pool shrinks back
    time.sleep(3)
    state = subprocess.run(["ps", "-o", "stat=", "-p", spare or "0"],
                           stdout=subprocess.PIPE, text=True).stdout.strip()
    check(spare and (not state or state.startswith("Z")),
          f"Idle spare worker {spare} still running: state {state!r}")

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

    # TLS: a request that stops halfway is closed after idle_timeout (2 s),
    # although OpenSSL waits for the rest of it (the socket is non-blocking)
    with Connection(secure, client_context(ssl.TLSVersion.TLSv1_3)) as conn:
        conn.send(b"GET /static/hello.txt HTTP/1.1\r\nHost: loc")
        time.sleep(3)
        check(conn.closed(), "Stalled TLS request not closed")

    # TLS: a client that never starts the handshake is dropped after 10 s
    with socket.create_connection(("127.0.0.1", secure), timeout=15) as raw:
        start = time.time()
        try:
            dropped = raw.recv(1) == b""
        except (ConnectionResetError, socket.timeout):
            dropped = False
        check(dropped and 8 < time.time() - start < 14,
              f"Stalled TLS handshake not dropped in time ({time.time() - start:.1f} s)")


PRIVATE, OLD = "Private Area", "Old Clients"


def auth_users(klin, temp):
    """The "user" blocks of the auth configuration, made by klin -c passwd
    (a few PBKDF2 iterations: the tests check the format, not the cost)."""
    def user(name, password, roles, *realms, md5=False):
        command = [str(klin), "-c", "passwd", "-n", "1000"]
        for realm in realms:
            command += ["-r", realm]
        if md5:
            command.append("-m")
        block = subprocess.run(command + [name], input=password + "\n", text=True,
                               capture_output=True, check=True).stdout
        return block.replace("    roles\n", f"    roles {roles}\n")

    inline = (user("alice", "wonder land", "admin staff", PRIVATE, OLD, md5=True) +
              user("bob", "builder", "staff", PRIVATE))
    users_file = temp / "users.conf"
    users_file.write_text(user("carol", "c4rol!", "admin", PRIVATE))
    return inline, users_file


def auth_config(inline, users_file):
    return f"""auth
    {{
        nonce_lifetime 3
        users_file {users_file}
{inline}
        realm
        {{
            name {PRIVATE}
            path /static/secret*
            path /whoami.kl1
            scheme any
            roles admin
        }}
        realm
        {{
            name {OLD}
            path /static/old*
            md5 yes
        }}
    }}"""


def digest_header(challenge, user, password, uri, realm=PRIVATE, alg="SHA-256",
                  method="GET", nc="00000001", cnonce="0a4f113b"):
    nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
    h = (lambda s: hashlib.sha256(s.encode()).hexdigest()) if alg == "SHA-256" else \
        (lambda s: hashlib.md5(s.encode()).hexdigest())
    ha1, ha2 = h(f"{user}:{realm}:{password}"), h(f"{method}:{uri}")
    response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
    return (f'Authorization: Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", algorithm={alg}, response="{response}", qop=auth, nc={nc}, '
            f'cnonce="{cnonce}"\r\n').encode()


def run_auth_checks(check, plain, secure):
    """HTTP authentication (doc/AUTH): Digest and Basic, realms, roles."""
    tls = client_context(ssl.TLSVersion.TLSv1_3)

    def get(port, path, extra=b"", context=None):
        reply = exchange(port, b"GET " + path.encode() + b" HTTP/1.1\r\nHost: localhost\r\n" +
                         extra + b"\r\n", context)
        head, _, body = reply.partition(b"\r\n\r\n")
        head = head.decode("latin-1")
        challenges = [line.split(":", 1)[1].strip() for line in head.split("\r\n")
                      if line.lower().startswith("www-authenticate:")]
        return head.split("\r\n")[0], challenges, body

    status, challenges, _ = get(plain, "/static/hello.txt")
    check(" 200 " in status and not challenges, "Unprotected page asked for credentials")

    # plain HTTP: Digest SHA-256 only (Basic would send the password)
    status, challenges, _ = get(plain, "/static/secret.txt")
    check(" 401 " in status and len(challenges) == 1 and
          challenges[0].startswith(f'Digest realm="{PRIVATE}"') and
          "algorithm=SHA-256" in challenges[0] and 'qop="auth"' in challenges[0],
          f"Wrong challenge: {status} {challenges}")
    first = challenges[0]
    status, _, body = get(plain, "/static/secret.txt",
                          digest_header(first, "alice", "wonder land", "/static/secret.txt"))
    check(" 200 " in status and body == b"top secret\n", f"Digest login failed: {status}")
    for user, password, uri, want in [
            ("alice", "wonder lanD", "/static/secret.txt", " 401 "),    # wrong password
            ("nobody", "wonder land", "/static/secret.txt", " 401 "),   # unknown user
            ("alice", "wonder land", "/static/hello.txt", " 401 "),     # digest of another URI
            ("bob", "builder", "/static/secret.txt", " 403 "),          # no admin role
            ("carol", "c4rol!", "/static/secret.txt", " 200 ")]:        # from users_file
        status, _, _ = get(plain, "/static/secret.txt", digest_header(first, user, password, uri))
        check(want in status, f"Digest {user} {uri}: {status}, expected {want.strip()}")
    status, _, _ = get(plain, "/static/secret.txt",
                       digest_header(first, "alice", "wonder land", "/static/secret.txt",
                                     alg="MD5"))
    check(" 401 " in status, "MD5 Digest accepted in a realm without md5")
    forged = first.replace('nonce="', 'nonce="0', 1).replace('0', '1', 1)
    status, _, _ = get(plain, "/static/secret.txt",
                       digest_header(forged, "alice", "wonder land", "/static/secret.txt"))
    check(" 401 " in status, "Forged nonce accepted")
    basic = b"Authorization: Basic " + base64.b64encode(b"alice:wonder land") + b"\r\n"
    status, _, _ = get(plain, "/static/secret.txt", basic)
    check(" 401 " in status, "Basic accepted over plain HTTP")

    # the page sees the user
    status, challenges, _ = get(plain, "/whoami.kl1")
    status, _, body = get(plain, "/whoami.kl1",
                          digest_header(challenges[0], "carol", "c4rol!", "/whoami.kl1"))
    check(" 200 " in status and body.strip() == b"user=carol", f"Page did not see the user: {body!r}")

    # a realm that also offers MD5, and requires no role
    status, challenges, _ = get(plain, "/static/old.txt")
    check(" 401 " in status and [c.split("algorithm=")[1].split(",")[0] for c in challenges] ==
          ["SHA-256", "MD5"], f"Wrong MD5 realm challenges: {challenges}")
    status, _, body = get(plain, "/static/old.txt",
                          digest_header(challenges[1], "alice", "wonder land", "/static/old.txt",
                                        realm=OLD, alg="MD5"))
    check(" 200 " in status and body == b"old client\n", f"MD5 Digest failed: {status}")

    # TLS: Basic too
    status, challenges, _ = get(secure, "/static/secret.txt", context=tls)
    check(" 401 " in status and challenges[-1] == f'Basic realm="{PRIVATE}", charset="UTF-8"',
          f"No Basic challenge over TLS: {challenges}")
    status, _, body = get(secure, "/static/secret.txt", basic, tls)
    check(" 200 " in status and body == b"top secret\n", f"Basic login failed: {status}")
    for credentials, want in [(b"alice:wrong", " 401 "), (b"bob:builder", " 403 "),
                              (b"alice", " 401 "), (b"carol:c4rol!", " 200 ")]:
        status, _, _ = get(secure, "/static/secret.txt",
                           b"Authorization: Basic " + base64.b64encode(credentials) + b"\r\n", tls)
        check(want in status, f"Basic {credentials!r}: {status}, expected {want.strip()}")
    # the verified-credentials cache keeps no wrong password
    status, _, _ = get(secure, "/static/secret.txt", basic, tls)
    status2, _, _ = get(secure, "/static/secret.txt",
                        b"Authorization: Basic " + base64.b64encode(b"alice:wonder lanD") + b"\r\n", tls)
    check(" 200 " in status and " 401 " in status2, "Cached Basic credentials accepted a wrong password")

    # an expired nonce: stale=true, so the client retries without asking
    time.sleep(4)
    status, challenges, _ = get(plain, "/static/secret.txt",
                                digest_header(first, "alice", "wonder land", "/static/secret.txt"))
    check(" 401 " in status and "stale=true" in challenges[0], f"Expired nonce not stale: {challenges}")


SECURITY_HEADERS = """security_headers
    {
        x_frame_options DENY
        referrer_policy no
        content_security_policy default-src 'self'; frame-ancestors 'none'
    }"""


def run_header_checks(check, plain, client, secure):
    """Security headers (doc/HEADERS): the defaults, a vhost's own values,
    HSTS over HTTPS only, and on error pages too."""
    def fields(port, path, context=None):
        reply = exchange(port, b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n", context)
        head = reply.partition(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        found = {}
        for line in head[1:]:
            name, _, value = line.partition(":")
            found.setdefault(name.strip().lower(), []).append(value.strip())
        return head[0], found

    defaults = {"x-content-type-options": ["nosniff"], "x-frame-options": ["SAMEORIGIN"],
                "referrer-policy": ["strict-origin-when-cross-origin"]}
    for path in [b"/static/hello.txt", b"/pid.kl1", b"/missing.txt"]:
        status, found = fields(plain, path)
        check(all(found.get(k) == v for k, v in defaults.items()),
              f"Default security headers missing on {path!r} ({status}): {found}")
        check("strict-transport-security" not in found and "content-security-policy" not in found,
              f"HSTS or CSP sent by default over HTTP: {found}")

    status, found = fields(secure, b"/static/hello.txt", client_context(ssl.TLSVersion.TLSv1_3))
    check(found.get("strict-transport-security") == ["max-age=31536000"] and
          found.get("x-content-type-options") == ["nosniff"], f"No HSTS over HTTPS: {found}")

    for path in [b"/static/hello.txt", b"/missing.txt"]:
        status, found = fields(client, path)
        check(found.get("x-frame-options") == ["DENY"] and "referrer-policy" not in found and
              found.get("content-security-policy") == ["default-src 'self'; frame-ancestors 'none'"]
              and found.get("x-content-type-options") == ["nosniff"],
              f"Configured security headers not sent on {path!r}: {found}")


def run_conditional_checks(check, plain, files):
    """ETag, If-None-Match and Range on embedded files (one stored as is,
    one compressed at import: ranges are cut after it is uncompressed)."""
    def get(path, extra=b"", method=b"GET"):
        reply = exchange(plain, method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n" +
                         extra + b"\r\n")
        head, _, body = reply.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        fields = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            fields[name.strip().lower()] = value.strip()
        return int(lines[0].split()[1]), fields, body

    for name in ["range.txt", "range-z.txt"]:
        path = b"/" + name.encode()
        data = (ROOT / "test/site/www" / name).read_bytes()
        size = len(data)
        status, fields, body = get(path)
        etag = fields.get("etag", "")
        check(status == 200 and body == data and fields.get("accept-ranges") == "bytes" and
              re.fullmatch(r'"[0-9a-f]{32}"', etag), f"{name}: no ETag: {status} {fields}")
        check(etag == f'"{hashlib.md5(data).hexdigest()}"', f"{name}: ETag is not the content's")

        for inm in [etag, f"W/{etag}", f'"nope", {etag}', "*"]:
            status, fields, body = get(path, f"If-None-Match: {inm}\r\n".encode())
            check(status == 304 and body == b"" and fields.get("etag") == etag,
                  f"{name}: If-None-Match {inm}: {status}")
        status, _, body = get(path, b'If-None-Match: "other"\r\n')
        check(status == 200 and body == data, f"{name}: a different ETag got {status}")
        # If-None-Match decides over If-Modified-Since
        status, _, _ = get(path, b'If-None-Match: "other"\r\n'
                           b"If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT\r\n")
        check(status == 200, f"{name}: If-Modified-Since won over If-None-Match ({status})")

        for spec, first, last in [("0-99", 0, 99), ("100-", 100, size - 1), ("-50", size - 50, size - 1),
                                  (f"{size - 10}-{size + 500}", size - 10, size - 1),
                                  ("5000-5000", 5000, 5000), (f"-{size + 9}", 0, size - 1)]:
            status, fields, body = get(path, f"Range: bytes={spec}\r\n".encode())
            check(status == 206 and body == data[first:last + 1] and
                  fields.get("content-range") == f"bytes {first}-{last}/{size}" and
                  fields.get("content-length") == str(last - first + 1),
                  f"{name}: Range {spec}: {status} {fields.get('content-range')} {len(body)}")
        for spec in [f"{size}-", f"{size + 5}-{size + 9}", "-0"]:
            status, fields, body = get(path, f"Range: bytes={spec}\r\n".encode())
            check(status == 416 and body == b"" and fields.get("content-range") == f"bytes */{size}",
                  f"{name}: unsatisfiable Range {spec}: {status} {fields}")
        for spec in ["bytes=0-1,5-6", "bytes=5-2", "items=0-1", "bytes=x-1", "bytes=-"]:
            status, _, body = get(path, f"Range: {spec}\r\n".encode())
            check(status == 200 and body == data, f"{name}: Range {spec} not ignored: {status}")
        status, _, body = get(path, f"Range: bytes=0-9\r\nIf-Range: {etag}\r\n".encode())
        check(status == 206 and body == data[:10], f"{name}: If-Range with the ETag: {status}")
        status, _, body = get(path, b'Range: bytes=0-9\r\nIf-Range: "changed"\r\n')
        check(status == 200 and body == data, f"{name}: If-Range with another ETag: {status}")
        status, fields, body = get(path, b"Range: bytes=0-9\r\n", b"HEAD")
        check(body == b"", f"{name}: HEAD with Range sent a body")

    # pages have no ETag (their output changes)
    status, fields, _ = get(b"/pid.kl1")
    check("etag" not in fields and "accept-ranges" not in fields, "A page got an ETag")

    # sent as stored (send_enc_deflate): another representation, another
    # ETag, and no ranges of the compressed bytes
    data = (ROOT / "test/site/www/range-z.txt").read_bytes()
    deflate = b"Accept-Encoding: deflate\r\n"
    reply = exchange(files, b"GET /range-z.txt HTTP/1.1\r\nHost: localhost\r\n" + deflate +
                     b"Range: bytes=0-9\r\n\r\n")
    head, _, body = reply.partition(b"\r\n\r\n")
    tag = re.search(rb'(?im)^etag: *("[0-9a-f]{32}-deflate")', head)
    check(b" 200 " in head.split(b"\r\n")[0] and b"content-encoding: deflate" in head.lower() and
          tag and b"accept-ranges" not in head.lower() and
          zlib.decompress(body) == data,      # zlib format, as HTTP defines it
          f"Deflated representation: {head!r}")
    if tag:
        reply = exchange(files, b"GET /range-z.txt HTTP/1.1\r\nHost: localhost\r\n" + deflate +
                         b"If-None-Match: " + tag.group(1) + b"\r\n\r\n")
        check(b" 304 " in reply.split(b"\r\n")[0], "If-None-Match of the deflated ETag")


class EventStream:
    """An SSE client: reads the header, then events as they arrive, noting
    when each one came (chunked or, on HTTP/1.0, until the close)."""

    def __init__(self, port, path, extra=b"", context=None, version=b"HTTP/1.1"):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock = context.wrap_socket(raw, server_hostname="localhost") if context else raw
        self.sock.sendall(b"GET " + path + b" " + version + b"\r\nHost: localhost\r\n" +
                          b"Accept: text/event-stream\r\n" + extra + b"\r\n")
        self.buf, self.text, self.ended = b"", "", False
        while b"\r\n\r\n" not in self.buf:
            self._recv()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        self.status = lines[0]
        self.fields = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            self.fields[name.strip().lower()] = value.strip()
        self.chunked = self.fields.get("transfer-encoding") == "chunked"

    def _recv(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError
        self.buf += data

    def _decode(self):
        if not self.chunked:
            self.text += self.buf.decode()
            self.buf = b""
            return
        while b"\r\n" in self.buf:
            size_line, rest = self.buf.split(b"\r\n", 1)
            size = int(size_line.split(b";")[0], 16)
            if len(rest) < size + 2:
                return
            if size == 0:
                self.ended = True
            self.text += rest[:size].decode()
            self.buf = rest[size + 2:]

    def event(self):
        """The next event as {field: value} (data lines joined), or None at
        the end of the stream."""
        while True:
            self._decode()
            if "\n\n" in self.text:
                block, self.text = self.text.split("\n\n", 1)
                event = {}
                for line in block.split("\n"):
                    name, _, value = line.partition(":")
                    value = value[1:] if value.startswith(" ") else value
                    event[name] = event[name] + "\n" + value if name in event else value
                return event
            if self.ended:
                return None
            try:
                self._recv()
            except EOFError:
                return None

    def close(self):
        self.sock.close()


def run_sse_checks(args, check, plain, secure, temp):
    """Server-Sent Events (doc/SSE): header, events sent as written,
    reconnecting with Last-Event-ID, HTTP/1.0, TLS, and a page that sees
    the client go away."""
    stream = EventStream(plain, b"/sse.kl1")
    check(" 200 " in stream.status and stream.fields.get("content-type") == "text/event-stream" and
          stream.chunked and stream.fields.get("cache-control") == "no-store",
          f"SSE header: {stream.status} {stream.fields}")
    start = time.monotonic()
    first = stream.event()
    times, events, blocks = [], [], []
    while (event := stream.event()) is not None:
        blocks.append(event)
        if "id" in event:
            events.append(event)
            times.append(time.monotonic() - start)
    stream.close()
    check(first == {"": "klin"}, f"No opening comment: {first}")
    check(blocks and blocks[0] == {"retry": "1500"}, f"No retry field: {blocks[:1]}")
    ticks = [e for e in events if e.get("event") == "tick"]
    check([e["id"] for e in ticks] == ["1", "2", "3"] and
          ticks[0]["data"] == "event 1\nsecond line", f"SSE events: {events}")
    # sent as written: 300 ms apart, not all at the end
    check(len(times) == 3 and times[0] < 0.25 and times[2] - times[0] > 0.45,
          f"Events not streamed: {times}")

    stream = EventStream(plain, b"/sse.kl1?n=2", b"Last-Event-ID: 41\r\n")
    ids = []
    while (event := stream.event()) is not None:
        if "id" in event:
            ids.append(event["id"])
    stream.close()
    check(ids == ["42", "43"], f"Last-Event-ID not used: {ids}")

    # the stream ends, the connection stays usable (HTTP/1.1; the
    # iterative server closes every connection)
    with Connection(plain) as conn:
        conn.send(b"GET /sse.kl1?n=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, headers, body = conn.response()
        check(" 200 " in status and b"id: 1\ndata: event 1\ndata: second line\n\n" in body,
              f"SSE over keep-alive: {status} {body!r}")
        if args.prefork:
            conn.send(b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            status, _, body = conn.response()
            check(" 200 " in status and body == b"klin integration test\n",
                  "Connection not reusable after an event stream")

    # HTTP/1.0: no chunking, the end of the stream closes the connection
    stream = EventStream(plain, b"/sse.kl1?n=2", version=b"HTTP/1.0")
    ids = []
    while (event := stream.event()) is not None:
        if "id" in event:
            ids.append(event["id"])
    stream.close()
    check(not stream.chunked and ids == ["1", "2"], f"SSE over HTTP/1.0: {ids}")

    stream = EventStream(secure, b"/sse.kl1?n=2", context=client_context(ssl.TLSVersion.TLSv1_3))
    ids = []
    while (event := stream.event()) is not None:
        if "id" in event:
            ids.append(event["id"])
    stream.close()
    check(ids == ["1", "2"], f"SSE over TLS: {ids}")

    # the page waits in sse_wait(); closing the connection ends it at once
    mark = temp / "sse-closed"
    stream = EventStream(plain, b"/sse.kl1?n=1&mark=" + str(mark).encode())
    while (event := stream.event()) is not None and event.get("id") != "1":
        pass
    ping = stream.event()
    stream.close()
    deadline = time.monotonic() + 3
    while not mark.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    check(ping == {"": "ping"} and mark.exists() and mark.read_text() == "closed\n",
          f"Page did not see the client go away: {ping} {mark.exists()}")


class WebSocket:
    """A WebSocket client (RFC 6455) that can also send what a correct
    client would not."""
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, port, path=b"/ws.kl1", extra=b"", context=None, origin=True,
                 key=None, version=b"13"):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock = context.wrap_socket(raw, server_hostname="localhost") if context else raw
        self.key = key if key is not None else base64.b64encode(os.urandom(16))
        host = b"127.0.0.1:" + str(port).encode()
        request = (b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n"
                   b"Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
                   b"Sec-WebSocket-Version: " + version + b"\r\n")
        if self.key:
            request += b"Sec-WebSocket-Key: " + self.key + b"\r\n"
        if origin is True:
            request += b"Origin: http" + (b"s" if context else b"") + b"://" + host + b"\r\n"
        elif origin:
            request += b"Origin: " + origin + b"\r\n"
        self.sock.sendall(request + extra + b"\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            self._recv()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        self.status = int(lines[0].split()[1])
        self.fields = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            self.fields[name.strip().lower()] = value.strip()

    def accepted(self):
        want = base64.b64encode(hashlib.sha1(self.key + self.GUID.encode()).digest()).decode()
        return (self.status == 101 and self.fields.get("upgrade", "").lower() == "websocket" and
                self.fields.get("sec-websocket-accept") == want)

    def _recv(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError
        self.buf += data

    def _take(self, n):
        while len(self.buf) < n:
            self._recv()
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send_frame(self, op, payload=b"", fin=True, mask=True, rsv=0):
        head = bytes([(0x80 if fin else 0) | rsv | op])
        n = len(payload)
        bit = 0x80 if mask else 0
        if n < 126:
            head += bytes([bit | n])
        elif n < 65536:
            head += bytes([bit | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([bit | 127]) + n.to_bytes(8, "big")
        if mask:
            key = os.urandom(4)
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            head += key
        self.sock.sendall(head + payload)

    def send(self, data):
        self.send_frame(1 if isinstance(data, str) else 2,
                        data.encode() if isinstance(data, str) else data)

    def frame(self):
        """(opcode, payload) of the next frame from the server, None at EOF."""
        try:
            b0, b1 = self._take(2)
            if b1 & 0x80:
                return ("masked", b"")       # a server must not mask
            n = b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._take(2), "big")
            elif n == 127:
                n = int.from_bytes(self._take(8), "big")
            return (b0 & 0x0F, self._take(n))
        except (EOFError, ConnectionResetError, socket.timeout, ssl.SSLError):
            return None

    def close_code(self):
        """The code of the close frame the server sends next (skipping data)."""
        while (frame := self.frame()) is not None:
            if frame[0] == 8:
                return int.from_bytes(frame[1][:2], "big") if len(frame[1]) >= 2 else 1005
        return None

    def close(self):
        self.sock.close()


def run_websocket_checks(check, plain, secure):
    """WebSockets (doc/WEBSOCKET): handshake, echo of every frame form,
    control frames, protocol errors and limits, refused handshakes, TLS."""
    ws = WebSocket(plain, extra=b"Sec-WebSocket-Protocol: echo, chat\r\n")
    check(ws.accepted() and ws.fields.get("sec-websocket-protocol") == "chat",
          f"WebSocket handshake: {ws.status} {ws.fields}")
    for message in ["hello", "héllo ☃ \U0001F600", "x" * 125, "y" * 126, "z" * 70000]:
        ws.send(message)
        check(ws.frame() == (1, message.encode()), f"Text echo of {len(message)} chars")
    ws.send(bytes(range(256)) * 300)
    check(ws.frame() == (2, bytes(range(256)) * 300), "Binary echo")
    ws.send("")
    check(ws.frame() == (1, b""), "Empty message echo")
    # a fragmented message with a ping between its parts
    ws.send_frame(1, b"frag", fin=False)
    ws.send_frame(9, b"are you there")
    check(ws.frame() == (10, b"are you there"), "Ping not answered with its payload")
    ws.send_frame(0, b"men", fin=False)
    ws.send_frame(0, b"ted")
    check(ws.frame() == (1, b"fragmented"), "Fragmented message")
    ws.send_frame(10, b"unsolicited pong")    # ignored
    ws.send("protocol")
    check(ws.frame() == (1, b"chat"), "Chosen subprotocol not seen by the page")
    # the client closes: the server answers with the same code
    ws.send_frame(8, (4001).to_bytes(2, "big") + b"client done")
    check(ws.close_code() == 4001, "Close not echoed")
    check(ws.frame() is None, "Connection not closed after the close handshake")
    ws.close()

    # the page closes
    ws = WebSocket(plain)
    ws.send("bye")
    code = ws.close_code()
    ws.send_frame(8, (1000).to_bytes(2, "big"))
    check(code == 1000 and ws.frame() is None, f"Page close: {code}")
    ws.close()

    # protocol errors: the server closes with the right code
    for name, send, want in [
            ("unmasked frame", lambda w: w.send_frame(1, b"x", mask=False), 1002),
            ("RSV bit", lambda w: w.send_frame(1, b"x", rsv=0x40), 1002),
            ("unknown opcode", lambda w: w.send_frame(3, b"x"), 1002),
            ("fragmented ping", lambda w: w.send_frame(9, b"x", fin=False), 1002),
            ("long ping", lambda w: w.send_frame(9, b"x" * 126), 1002),
            ("stray continuation", lambda w: w.send_frame(0, b"x"), 1002),
            ("new message inside a message",
             lambda w: (w.send_frame(1, b"a", fin=False), w.send_frame(1, b"b")), 1002),
            ("invalid UTF-8", lambda w: w.send_frame(1, b"\xc3\x28"), 1007),
            ("surrogate in UTF-8", lambda w: w.send_frame(1, b"\xed\xa0\x80"), 1007),
            ("overlong UTF-8", lambda w: w.send_frame(1, b"\xc0\xaf"), 1007),
            ("UTF-8 cut short", lambda w: w.send_frame(1, b"ok \xe2\x82"), 1007)]:
        ws = WebSocket(plain)
        send(ws)
        code = ws.close_code()
        ws.close()
        check(code == want, f"{name}: close code {code}, expected {want}")
    ws = WebSocket(plain, b"/ws.kl1?max=1000")
    ws.send("a" * 1000)
    ok = ws.frame() == (1, b"a" * 1000)
    ws.send_frame(1, b"b" * 600, fin=False)
    ws.send_frame(0, b"c" * 600)
    code = ws.close_code()
    ws.close()
    check(ok and code == 1009, f"Message limit: {ok} {code}")

    # refused handshakes
    for name, kwargs, want in [
            ("another site's page", {"origin": b"http://evil.example"}, 403),
            ("version 8", {"version": b"8"}, 426),
            ("no key", {"key": b""}, 400),
            ("short key", {"key": base64.b64encode(b"x" * 10)}, 400)]:
        ws = WebSocket(plain, **kwargs)
        ws.close()
        check(ws.status == want and not ws.accepted(), f"Handshake with {name}: {ws.status}")
    ws = WebSocket(plain, origin=False)
    check(ws.accepted(), "Handshake without Origin (not a browser) refused")
    ws.close()
    reply = exchange(plain, b"GET /ws.kl1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    check(b" 400 " in reply.split(b"\r\n")[0], "A plain GET of a WebSocket page was not refused")

    # TLS
    ws = WebSocket(secure, context=client_context(ssl.TLSVersion.TLSv1_3))
    ws.send("over tls")
    ok = ws.accepted() and ws.frame() == (1, b"over tls")
    ws.send("z" * 70000)
    ok = ok and ws.frame() == (1, b"z" * 70000)
    ws.close()
    check(ok, "WebSocket over TLS")


VALIDATION_ROUTES = """
        route
        {
            path /v/{id}
            page /echo.kl1
        }
        route
        {
            path /d
            page /echo.kl1
        }
        route
        {
            path /r
            page /echo.kl1
        }
        route
        {
            path /h
            page /echo.kl1
        }"""


ROUTES = """routes
    {
        route
        {
            method GET
            path /api/items/{id}
            page /api.kl1
        }
        route
        {
            method PUT, PATCH DELETE
            path /api/items/{id}
            page /api.kl1
        }
        route
        {
            method POST
            path /api/items
            page /api.kl1
        }
        route
        {
            path /api/files/{path*}
            page /api.kl1
        }""" + VALIDATION_ROUTES + """
    }"""


def run_route_checks(args, check, plain):
    """REST routes and JSON (doc/ROUTES, doc/JSON): methods, parameters,
    405 with Allow, JSON bodies and their errors."""
    def call(method, path, body=None, ctype=b"application/json"):
        extra = b""
        if body is not None:
            extra = b"Content-Type: " + ctype + b"\r\nContent-Length: " + \
                str(len(body)).encode() + b"\r\n"
        reply = exchange(plain, method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n" +
                         extra + b"\r\n" + (body or b""))
        head, _, data = reply.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        fields = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            fields[name.strip().lower()] = value.strip()
        try:
            doc = json.loads(data) if data else None
        except ValueError:
            doc = data
        return int(lines[0].split()[1]), fields, doc

    status, fields, doc = call(b"GET", b"/api/items/42")
    check(status == 200 and fields.get("content-type") == "application/json" and
          doc == {"method": "GET", "id": "42"}, f"GET route: {status} {doc}")
    status, fields, doc = call(b"HEAD", b"/api/items/42")
    check(status == 200 and doc is None, f"HEAD on a GET route: {status}")
    for method in [b"PUT", b"PATCH"]:
        status, _, doc = call(method, b"/api/items/7", b'{"name": "x", "tags": [1, 2]}')
        check(status == 200 and doc == {"method": method.decode(), "id": "7",
                                        "body": {"name": "x", "tags": [1, 2]}},
              f"{method!r} with a JSON body: {status} {doc}")
    status, _, doc = call(b"DELETE", b"/api/items/7")
    check(status == 200 and doc == {"method": "DELETE", "id": "7"}, f"DELETE: {doc}")
    status, _, doc = call(b"POST", b"/api/items", b'{"new": true}')
    check(status == 200 and doc == {"method": "POST", "body": {"new": True}}, f"POST: {doc}")

    # the path has routes, not for this method: 405 and what it takes
    status, fields, _ = call(b"POST", b"/api/items/42", b"{}")
    check(status == 405 and fields.get("allow") == "GET, HEAD, PUT, DELETE, PATCH",
          f"405: {status} {fields.get('allow')}")
    status, fields, _ = call(b"GET", b"/api/items")
    check(status == 405 and fields.get("allow") == "POST", f"405 on /api/items: {status}")

    for path in [b"/api/items/42/more", b"/api/items/", b"/api/itemsx/1"]:
        status, _, _ = call(b"GET", path)
        check(status == 404, f"Unrouted {path!r}: {status}")

    # parameters are URL-decoded, and written back escaped
    status, _, doc = call(b"GET", b"/api/items/a%20b%3Cc")
    check(doc == {"method": "GET", "id": "a b<c"}, f"Decoded parameter: {doc}")
    reply = exchange(plain, b"GET /api/items/%3Cx%3E HTTP/1.1\r\nHost: localhost\r\n\r\n")
    check(b'"id":"\\u003cx\\u003e"' in reply, "Route parameter not escaped in JSON output")
    status, _, doc = call(b"GET", b"/api/files/a/b/c.txt")
    check(doc == {"method": "GET", "path": "a/b/c.txt"}, f"Catch-all parameter: {doc}")
    status, _, doc = call(b"GET", b"/api/files/")
    check(doc == {"method": "GET", "path": ""}, f"Empty catch-all: {doc}")

    # JSON body errors
    for body, ctype, want in [(b"{}", b"text/plain", 415), (b'{"a":1,}', b"application/json", 400),
                              (b'{"a":1,"a":2}', b"application/json", 400),
                              (b"[" + b"1," * 600 + b"1]", b"application/json", 413),
                              (b'{"x":1}', b"application/vnd.api+json; charset=utf-8", 200)]:
        status, _, doc = call(b"PUT", b"/api/items/1", body, ctype)
        check(status == want, f"JSON body {body[:20]!r} {ctype!r}: {status}, expected {want}")

    # a request body read by the page leaves the connection usable
    if args.prefork:
        with Connection(plain) as conn:
            body = b'{"k": "v"}'
            conn.send(b"PUT /api/items/9 HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
                      b"application/json\r\nContent-Length: " + str(len(body)).encode() +
                      b"\r\n\r\n" + body)
            status, _, data = conn.response()
            conn.send(b"GET /api/items/10 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            status2, _, data2 = conn.response()
            check(" 200 " in status and json.loads(data)["body"] == {"k": "v"} and
                  json.loads(data2) == {"method": "GET", "id": "10"},
                  "Keep-alive after a JSON PUT")


ACCESS = """access
    {
        rule
        {
            path /static/private*
            allow 10.0.0.0/8, 2001:db8::/32
            deny all
        }
        rule
        {
            path /static/local*
            allow 127.0.0.0/8 ::1
            deny all
        }
        rule
        {
            path /pid.kl1
            deny 127.0.0.1/32
        }
        rule
        {
            deny 192.0.2.0/24
        }
    }"""

BLOCKED = """access
    {
        rule
        {
            allow 10.0.0.0/8
            deny 127.0.0.1
        }
    }"""


def run_access_checks(check, client, blocked, temp):
    """IP access control (doc/ACCESS): rules per path, the first matching
    rule decides, networks, and clients dropped at connection time."""
    (temp / "private.txt").write_text("private\n")
    (temp / "local.txt").write_text("local\n")

    def status(path):
        reply = exchange(client, b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
        return int(reply.split(b"\r\n")[0].split()[1]), reply.partition(b"\r\n\r\n")[2]

    for path, want, body in [(b"/static/private.txt", 403, None),
                             (b"/static/local.txt", 200, b"local\n"),
                             (b"/pid.kl1", 403, None),
                             (b"/static/hello.txt", 200, b"klin integration test\n")]:
        code, data = status(path)
        check(code == want and (body is None or data == body),
              f"Access to {path!r}: {code}, expected {want}")

    # the all-paths rule of 'blocked' refuses 127.0.0.1: no HTTP at all
    with socket.create_connection(("127.0.0.1", blocked), timeout=3) as raw:
        try:
            raw.sendall(b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            dropped = raw.recv(100) == b""
        except (ConnectionResetError, BrokenPipeError):
            dropped = True
    check(dropped, "A denied client was not dropped at connection time")


VALIDATION = """validators
    {
        validator
        {
            name id
            regex [0-9]{1,6}
        }
        validator
        {
            name page
            int 1 100
        }
        validator
        {
            name word
            length 1 8
        }
        validator
        {
            name order
            enum asc desc
        }
        validator
        {
            name token
            regex [a-f0-9]{8}
        }
    }
    params
    {
        path /echo.kl1
        param
        {
            name page
            validator page
            required yes
        }
        param
        {
            name order
            validator order
        }
        param
        {
            name q
            validator word
            source query
        }
    }
    params
    {
        path /v/*
        param
        {
            name id
            source route
            validator id
            required yes
        }
    }
    params
    {
        path /d
        on_invalid drop
        unknown allow
        param
        {
            name page
            validator page
        }
    }
    params
    {
        path /r
        unknown reject
        param
        {
            name page
            validator page
        }
    }
    params
    {
        path /h
        method GET
        param
        {
            name X-Token
            source header
            validator token
            required yes
        }
    }"""

def run_validation_checks(check, plain):
    """Declarative validation (doc/VALIDATE): sources, validator types,
    required, repeated values, NUL smuggling, drop/reject, unknown."""
    def get(path, extra=b"", body=None):
        method = b"POST" if body is not None else b"GET"
        if body is not None:
            extra += b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + \
                str(len(body)).encode() + b"\r\n"
        reply = exchange(plain, method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n" +
                         extra + b"\r\n" + (body or b""))
        head, _, data = reply.partition(b"\r\n\r\n")
        return int(head.split(b"\r\n")[0].split()[1]), sorted(data.decode().split())

    for path, want, seen in [
            (b"/echo.kl1?page=5&order=asc&q=abc", 200, ["order=asc", "page=5", "q=abc"]),
            (b"/echo.kl1?page=100", 200, ["page=100"]),
            (b"/echo.kl1?page=5&extra=1&x=y", 200, ["page=5"]),     # unknown: dropped
            (b"/echo.kl1?page=0", 400, None),
            (b"/echo.kl1?page=101", 400, None),
            (b"/echo.kl1?page=abc", 400, None),
            (b"/echo.kl1?page=+5", 400, None),
            (b"/echo.kl1?page=5%00x", 400, None),                    # a NUL hiding the rest
            (b"/echo.kl1?order=asc", 400, None),                     # required page missing
            (b"/echo.kl1?page=5&order=up", 400, None),
            (b"/echo.kl1?page=5&q=", 400, None),                     # length 1-8
            (b"/echo.kl1?page=5&q=ninechars", 400, None),
            (b"/echo.kl1?page=5&page=500", 400, None),               # each value checked
            (b"/v/123456", 200, ["route:id=123456"]),
            (b"/v/1234567", 400, None),
            (b"/v/12a", 400, None),
            (b"/d?page=0&keep=1", 200, ["keep=1"]),                  # drop mode, unknown allowed
            (b"/d?page=7", 200, ["page=7"]),
            (b"/r?page=1", 200, ["page=1"]),
            (b"/r?page=1&zzz=1", 400, None)]:                        # unknown rejected
        status, body = get(path)
        check(status == want and (seen is None or body == seen),
              f"Validation of {path!r}: {status} {body}, expected {want} {seen}")

    # the source counts: q is a query parameter, a form q is unknown
    status, body = get(b"/echo.kl1?page=5", body=b"q=abc&order=desc")
    check(status == 200 and body == ["order=desc", "page=5"],
          f"Form/query sources: {status} {body}")
    status, body = get(b"/echo.kl1", body=b"page=7")
    check(status == 200 and body == ["page=7"], f"Form value: {status} {body}")

    for token, want in [(b"deadbeef", 200), (b"DEADBEEF", 400), (b"dead", 400), (None, 400)]:
        extra = b"X-Token: " + token + b"\r\n" if token else b""
        status, _ = get(b"/h", extra)
        check(status == want, f"Header validation {token!r}: {status}, expected {want}")

    # pages without params rules are not affected
    status, _ = get(b"/pid.kl1?anything=at%00all")
    check(status == 200, f"A page without rules was validated: {status}")


def key_needles(key):
    """Byte strings that only a copy of the private key contains: a line of
    its PEM text, and part of a prime in both byte orders (OpenSSL keeps
    big numbers as little-endian words)."""
    text = subprocess.run(["openssl", "pkey", "-in", str(key), "-text", "-noout"],
                          capture_output=True, text=True, check=True).stdout
    prime = re.search(r"prime1:\n((?:\s+[0-9a-f:]+\n)+)", text).group(1)
    p = bytes.fromhex(re.sub(r"[\s:]", "", prime)).lstrip(b"\0")
    pem = [line for line in key.read_text().splitlines() if not line.startswith("-----")]
    return [pem[len(pem) // 2].encode(), p[8:40], p[::-1][8:40]]


def process_has(pid, needles):
    """Does the memory of process pid hold any of the needles? Read in
    chunks that overlap by the longest needle."""
    chunk, overlap = 1 << 22, max(len(n) for n in needles)
    with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for line in maps:
            addr, perms = line.split()[:2]
            if "r" not in perms or "[vvar]" in line or "[vsyscall]" in line:
                continue
            start, end = (int(x, 16) for x in addr.split("-"))
            tail = b""
            for at in range(start, end, chunk):
                try:
                    mem.seek(at)
                    data = tail + mem.read(min(chunk, end - at))
                except (OSError, OverflowError, ValueError):
                    break
                if any(n in data for n in needles):
                    return True
                tail = data[-overlap:]
    return False


def run_keymgr_checks(check, root_pid, key, sanitized):
    """The TLS key manager (doc/KEYMGR): after TLS requests, only the key
    manager's memory holds the private key, not klind's or any worker's."""
    if not Path("/proc/self/mem").exists() or sanitized:
        # no /proc (macOS); or a sanitizer build, whose terabytes of shadow
        # and allocator mappings make a scan meaningless (release checks it)
        return
    needles = key_needles(key)
    procs = {root_pid}
    for _ in range(3):  # klind, its workers and key manager, their children
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    ppid = int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
                except (OSError, ValueError, IndexError):
                    continue
                if ppid in procs:
                    procs.add(int(entry.name))
    holders = set()
    for pid in sorted(procs):
        try:
            if process_has(pid, needles):
                holders.add(pid)
        except PermissionError:
            check(False, f"Cannot read the memory of klind process {pid}")
    # the key manager keeps only its control socket (and /dev/null)
    managers = {pid for pid in procs if pid != root_pid and
                len(list(Path(f"/proc/{pid}/fd").iterdir())) <= 4}
    check(len(managers) == 1 and holders == managers,
          f"Private key found in {sorted(holders)}; key manager {sorted(managers)}, "
          f"processes {sorted(procs)}")


def klind_processes(root_pid):
    """klind and the processes it started (and theirs)."""
    procs = {root_pid}
    for _ in range(3):
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    ppid = int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
                except (OSError, ValueError, IndexError):
                    continue
                if ppid in procs:
                    procs.add(int(entry.name))
    return procs


def seccomp_mode(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Seccomp:"):
            return int(line.split()[1])
    return -1


def run_sandbox_checks(args, check, root_pid, plain, unsandboxed):
    """Sandboxes (doc/SANDBOX, Linux seccomp): workers and the key manager
    are filtered, a call outside the list fails with EPERM, one the
    sandbox kills for ends the worker; 'sandbox no' turns it off."""
    if not Path("/proc/self/status").exists():
        return
    procs = klind_processes(root_pid)
    check(seccomp_mode(root_pid) == 0, "klind itself (not a worker) is sandboxed")
    managers = {pid for pid in procs if pid != root_pid and
                len(list(Path(f"/proc/{pid}/fd").iterdir())) <= 4}
    check(managers and all(seccomp_mode(pid) == 2 for pid in managers),
          f"Key manager not sandboxed: {[(p, seccomp_mode(p)) for p in managers]}")
    if not args.prefork:
        return  # the single-process server has no workers

    def get(port, query):
        reply = exchange(port, b"GET /sandbox.kl1?" + query + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
        return reply.partition(b"\r\n\r\n")[2].strip()

    check(get(plain, b"try=link") == b"EPERM", "A call outside the list did not fail with EPERM")
    check(get(unsandboxed, b"try=link") == b"ENOENT", "sandbox no did not turn the sandbox off")
    workers = {pid for pid in klind_processes(root_pid) if pid != root_pid and pid not in managers}
    modes = {seccomp_mode(pid) for pid in workers}
    check(modes == {0, 2}, f"Workers' seccomp modes {modes}: expected filtered and unfiltered")
    try:
        killed = get(plain, b"try=unshare") == b""
    except (ConnectionResetError, OSError):
        killed = True
    check(killed, "unshare(2) did not kill the sandboxed worker")
    check(get(unsandboxed, b"try=unshare") == b"survived", "unshare killed an unsandboxed worker")
    reply = exchange(plain, b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
    check(reply.endswith(b"klin integration test\n"), "Server not serving after a worker was killed")


def run_bad_auth_checks(check, daemon, env, temp):
    """Unsafe or broken auth (and route) configurations stop klind at
    startup, instead of serving the realm unprotected (the reason goes to
    the log)."""
    port = free_port()
    hashed = auth_users(daemon.parent / "klin", temp)[0]

    def starts(auth, block="auth"):
        config = temp / "auth-start.conf"
        config.write_text(f"server_list one\nallow_root yes\none\n{{\ntype http\n"
                          f"addr tcp4://127.0.0.1:{port}\ndir_root /www\n"
                          f"{block}\n{{\n{auth}\n}}\n}}\n")
        process = subprocess.Popen([str(daemon), "-F", "-d", "-f", str(config)], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=2)
            return False
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return True

    realm = "realm\n{\nname R\npath /x*\n%s}\n"
    check(starts(hashed + realm % ""), "A valid auth configuration was refused")
    for name, auth in [
            ("plaintext password", "user\n{\nname eve\npassword hunter2\n}\n" + realm % ""),
            ("Basic over HTTP", hashed + realm % "scheme basic\n"),
            ("realm without path", hashed + "realm\n{\nname R\n}\n"),
            ("unknown scheme", hashed + realm % "scheme ntlm\n"),
            ("quote in realm", hashed + realm.replace("name R", 'name R"') % ""),
            ("missing users_file", hashed + "users_file /nonexistent/users\n" + realm % "")]:
        check(not starts(auth), f"klind started with an unsafe auth configuration ({name})")

    route = "route\n{\n%s\n}\n"
    check(starts(route % "path /a/{id}/{rest*}\npage /p.kl1\nmethod GET, post", "routes"),
          "A valid route was refused")
    for name, body in [("relative path", "path a/{id}\npage /p.kl1"),
                       ("bad parameter name", "path /a/{i-d}\npage /p.kl1"),
                       ("catch-all not last", "path /a/{rest*}/b\npage /p.kl1"),
                       ("unbalanced brace", "path /a/{id\npage /p.kl1"),
                       ("no page", "path /a/{id}"),
                       ("relative page", "path /a\npage p.kl1"),
                       ("unknown method", "path /a\npage /p.kl1\nmethod GET FETCH")]:
        check(not starts(route % body, "routes"), f"klind started with a bad route ({name})")

    check(starts(route % "allow 10.0.0.0/8, ::1 fe80::/10\ndeny all", "access"),
          "A valid access rule was refused")
    for name, body in [("prefix too long", "allow 10.0.0.0/33"),
                       ("IPv6 prefix too long", "allow ::1/129"),
                       ("short address", "allow 10.1.2"),
                       ("host name", "allow localhost"),
                       ("unknown key", "permit 10.0.0.0/8"),
                       ("no allow or deny", "path /x")]:
        check(not starts(route.replace("route", "rule") % body, "access"),
              f"klind started with a bad access rule ({name})")

    def validated(validators, params):
        return starts(validators + "\n}\nparams\n{\n" + params, "validators")
    good = "validator\n{\nname n\nint 1 9\n}"
    check(validated(good, "path /x\nparam\n{\nname a\nvalidator n\n}"),
          "A valid validation configuration was refused")
    for name, validators, params in [
            ("no type", "validator\n{\nname n\n}", "path /x"),
            ("bad regex", "validator\n{\nname n\nregex [a-\n}", "path /x"),
            ("int range reversed", "validator\n{\nname n\nint 9 1\n}", "path /x"),
            ("negative length", "validator\n{\nname n\nlength -1 5\n}", "path /x"),
            ("defined twice", good + "\n" + good, "path /x"),
            ("unknown validator", good, "path /x\nparam\n{\nname a\nvalidator m\n}"),
            ("bad source", good, "path /x\nparam\n{\nname a\nsource cookie\n}"),
            ("bad unknown", good, "path /x\nunknown ignore"),
            ("no path", good, "param\n{\nname a\n}")]:
        check(not validated(validators, params), f"klind started with bad validation ({name})")


def run_root_checks(check, daemon, env, temp):
    """klind will not keep root credentials: started as root it must drop
    to a configured uid and gid, or be told 'allow_root yes' (a chroot alone
    is not enough, root can leave one). Run as root only (WSL, CI with sudo)."""
    if not hasattr(os, "geteuid"):
        return
    port = free_port()

    def started(settings):
        """The pid of a klind that came up with 'settings', or None."""
        config = temp / "root-start.conf"
        config.write_text(f"server_list one\n{settings}\none\n{{\ntype http\n"
                          f"addr tcp4://127.0.0.1:{port}\ndir_root /www\n}}\n")
        process = subprocess.Popen([str(daemon), "-F", "-d", "-f", str(config)], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while process.poll() is None and time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return process
            except OSError:
                time.sleep(0.1)
        if process.poll() is None:
            process.kill()
        process.wait()
        return None

    def stop(process):
        uids = Path(f"/proc/{process.pid}/status").read_text().split("Uid:")[1].split()[:4]
        gids = Path(f"/proc/{process.pid}/status").read_text().split("Gid:")[1].split()[:4]
        process.kill()
        process.wait()
        return uids, gids

    if os.geteuid() != 0:
        process = started("")
        check(process is not None, "klind did not start as an ordinary user")
        stop(process)
        return
    check(started("") is None, "klind kept root credentials without allow_root")
    check(started(f"chroot {temp}") is None, "klind kept root credentials in a chroot")
    check(started("uid 65534") is None, "klind kept group root (uid without gid)")
    process = started("uid 65534\ngid 65534")
    check(process is not None, "klind did not start with uid and gid configured")
    if process is not None:
        uids, gids = stop(process)
        check(uids == ["65534"] * 4 and gids == ["65534"] * 4,
              f"klind did not drop every user and group id: {uids} {gids}")
    process = started("allow_root yes")
    check(process is not None, "allow_root yes did not let klind run as root")
    if process is not None:
        stop(process)


def run_server_checks(args, env, output, daemon):
    checks = 0

    def check(condition, message):
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(message)

    with tempfile.TemporaryDirectory(prefix="klin-server-test-") as directory:
        temp = Path(directory)
        (temp / "hello.txt").write_text("klin integration test\n")
        (temp / "a+b.txt").write_text("literal plus\n")
        (temp / "a?b.txt").write_text("encoded question\n")
        (temp / "secret.txt").write_text("top secret\n")
        (temp / "old.txt").write_text("old client\n")
        auth = auth_config(*auth_users(daemon.parent / "klin", temp))
        run_bad_auth_checks(check, daemon, env, temp)
        run_root_checks(check, daemon, env, temp)
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plain, client, secure, files, memlog, blocked = (free_port() for _ in range(6))
        sessions = temp / "sessions"
        sessions.mkdir()
        config = temp / "klind.conf"
        blocks = []
        # memlog: a log on this server only (none at the top level), kept in
        # memory, which pages read back with server_foreach_memlog_line()
        for name, port, tls, session, extra in [
                ("plain", plain, False, "memory",
                 auth + "\n    " + ROUTES + "\n    " + VALIDATION),
                ("client", client, False, "client", SECURITY_HEADERS + "\n    " + ACCESS),
                ("secure", secure, True, "client", auth),
                ("files", files, False, f"file\n        file.path {sessions}",
                 "index missing.kl1 pid.kl1\n    send_enc_deflate yes"),
                ("memlog", memlog, False, "memory",
                 "log\n    {\n        type memory\n    }\n    sandbox no"),
                ("blocked", blocked, False, "memory", BLOCKED)]:
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
    prefork.idle_timeout 1
    session
    {{
        type {session}
    }}
    {f'cert_file {cert}' if tls else ''}
    {f'key_file {key}' if tls else ''}
    {extra}
}}
""")
        # blanks of every kind between the names: all servers must start (a
        # doubled or leading blank used to drop the ones after it)
        config.write_text("server_list  plain client\tsecure  files memlog blocked\nallow_root yes\n" +
                          "\n".join(blocks))
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
                check(b"200 OK" in response and response.endswith(b"klin integration test\n"), "GET failed")
                check(b"\r\nServer: klin/" in response, f"Wrong Server header: {response[:300]!r}")
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
                for port, context in [(plain, None), (client, None), (files, None),
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
                    check(len(cookies.get("klin_sid", "")) == 32, "Wrong session ID length")
                    if port == plain:
                        # the cookie's name before KLone was renamed Klin is
                        # still read, so an upgrade keeps users logged in
                        old = f"klone_sid={cookies['klin_sid']}".encode()
                        reply = exchange(port, b"GET /session.kl1 HTTP/1.1\r\nHost: localhost\r\nCookie: " +
                                         old + b"\r\n\r\n", context)
                        check(b"persisted" in reply.partition(b"\r\n\r\n")[2],
                              f"Old klone_sid cookie not accepted: {reply[:400]!r}")
                    if port == files:
                        # a session file saved before the rename (klone_sess_)
                        # is taken over under the new name
                        sid = cookies["klin_sid"]
                        saved = list(sessions.glob(f"klin_sess_{sid}_*"))
                        check(len(saved) == 1, f"no session file: {list(sessions.iterdir())}")
                        old_file = saved[0].with_name(saved[0].name.replace("klin_sess_", "klone_sess_", 1))
                        saved[0].rename(old_file)
                        reply = exchange(port, b"GET /session.kl1 HTTP/1.1\r\nHost: localhost\r\nCookie: klone_sid=" +
                                         sid.encode() + b"\r\n\r\n", context)
                        check(b"persisted" in reply.partition(b"\r\n\r\n")[2],
                              f"Old session file not loaded: {reply[:400]!r}")
                        check(saved[0].exists() and not old_file.exists(),
                              f"Old session file not renamed: {list(sessions.iterdir())}")
                    if "KL1_CLISES_HMAC" in cookies:
                        tag = cookies["KL1_CLISES_HMAC"]
                        cookies["KL1_CLISES_HMAC"] = ("0" if tag[0] != "0" else "1") + tag[1:]
                        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()
                        reply = exchange(port, b"GET /session.kl1 HTTP/1.1\r\nHost: localhost\r\nCookie: " +
                                         cookie_header + b"\r\n\r\n", context)
                        check(b"persisted" not in reply.partition(b"\r\n\r\n")[2],
                              "Accepted a forged client-session MAC")
                # a multipart/form-data POST: a field and an uploaded file
                body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\n"
                        b"value 1\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; "
                        b"filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile body\r\n"
                        b"--XyZ--\r\n")
                reply = exchange(plain, b"POST /upload.kl1 HTTP/1.1\r\nHost: localhost\r\n"
                                 b"Content-Type: multipart/form-data; boundary=XyZ\r\n"
                                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                page = reply.partition(b"\r\n\r\n")[2]
                check(b"200 OK" in reply and b"field=value 1\n" in page and
                      b"file=a.txt text/plain 9 [file body]\n" in page,
                      f"multipart upload: {reply[:600]!r}")
                # a configured index list: the first page that exists is served
                reply = exchange(files, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                body = reply.partition(b"\r\n\r\n")[2].strip()
                check(b"200 OK" in reply and body.isdigit(), f"index pid.kl1 not served: {reply[:400]!r}")
                if args.prefork:
                    # a worker logs to the server's own memory log (there is
                    # no top-level log) and reads it back through the parent:
                    # the worker used to crash on the missing top-level log,
                    # and lines came back cut to 7 characters
                    reply = exchange(memlog, b"GET /memlog.kl1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    check(b"200 OK" in reply and
                          b"memlog probe line 0123456789" in reply.partition(b"\r\n\r\n")[2],
                          f"memory log not read back whole: {reply[:600]!r}")
                run_auth_checks(check, plain, secure)
                run_header_checks(check, plain, client, secure)
                run_conditional_checks(check, plain, files)
                run_sse_checks(args, check, plain, secure, temp)
                run_websocket_checks(check, plain, secure)
                run_route_checks(args, check, plain)
                run_access_checks(check, client, blocked, temp)
                run_validation_checks(check, plain)
                run_sandbox_checks(args, check, process.pid, plain, memlog)
                run_keymgr_checks(check, process.pid, key,
                                  "-fsanitize" in cmake_cache_value(daemon.parent.parent,
                                                                    "CMAKE_C_FLAGS"))
                run_keep_alive_checks(args, check, plain, secure, request)
                check(b"200 OK" in exchange(plain, request), "Server failed after malformed requests")
            finally:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                    stopped = True
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    stopped = False
            # SIGTERM stops the server by itself (the handler only sets the
            # stop flag; the main loop logs it and shuts down the children)
            check(stopped, "SIGTERM did not stop the server within 5 s")
        log_text = log_path.read_text(errors="replace")
        check("ERROR: AddressSanitizer" not in log_text and "ERROR: LeakSanitizer" not in log_text
              and "AddressSanitizer:DEADLYSIGNAL" not in log_text and "runtime error:" not in log_text,
              "Sanitizer errors in server-test.log")
        if args.prefork:
            # a negative count is refused at startup (it used to be written
            # as an int into a size_t, i.e. a huge number of children)
            bad = temp / "negative.conf"
            bad.write_text(f"server_list b\nallow_root yes\nb\n{{\n type http\n"
                           f" addr tcp4://127.0.0.1:{free_port()}\n dir_root /www\n"
                           " model prefork\n prefork.max_child -1\n}\n")
            try:
                result = subprocess.run([str(daemon), "-F", "-f", str(bad)], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
                refused = result.returncode != 0
            except subprocess.TimeoutExpired:
                refused = False     # it started and kept running
            check(refused, "prefork.max_child -1 was accepted")
    print(f"{checks} full-server checks passed; log: {log_path}")


if __name__ == "__main__":
    main()
