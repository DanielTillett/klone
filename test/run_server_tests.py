#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Build a test-only embedded page and exercise the real HTTP/TLS daemon."""
import argparse
import base64
import hashlib
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
                           "-DKLIN_IMPORT_ARGS=", str(tree)], tree),
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


def run_bad_auth_checks(check, daemon, env, temp):
    """Unsafe or broken auth configurations stop klind at startup, instead
    of serving the realm unprotected (the reason goes to the log)."""
    port = free_port()
    hashed = auth_users(daemon.parent / "klin", temp)[0]

    def starts(auth):
        config = temp / "auth-start.conf"
        config.write_text(f"server_list one\nallow_root yes\none\n{{\ntype http\n"
                          f"addr tcp4://127.0.0.1:{port}\ndir_root /www\n"
                          f"auth\n{{\n{auth}\n}}\n}}\n")
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
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plain, client, secure, files, memlog = (free_port() for _ in range(5))
        sessions = temp / "sessions"
        sessions.mkdir()
        config = temp / "klind.conf"
        blocks = []
        # memlog: a log on this server only (none at the top level), kept in
        # memory, which pages read back with server_foreach_memlog_line()
        for name, port, tls, session, extra in [
                ("plain", plain, False, "memory", auth),
                ("client", client, False, "client", SECURITY_HEADERS),
                ("secure", secure, True, "client", auth),
                ("files", files, False, f"file\n        file.path {sessions}",
                 "index missing.kl1 pid.kl1"),
                ("memlog", memlog, False, "memory", "log\n    {\n        type memory\n    }")]:
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
        config.write_text("server_list  plain client\tsecure  files memlog\nallow_root yes\n" +
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
