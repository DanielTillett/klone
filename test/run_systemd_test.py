#!/usr/bin/env python3
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
"""Run klind under the hardened unit in contrib/systemd/klind.service.

Needs root and a running systemd (WSL with systemd, or CI with sudo);
otherwise it says so and passes. It creates /opt/klin-test-PID (/run may
be noexec; /home and /tmp are hidden by the unit) and a unit under
/run/systemd/system, and removes both afterwards:

    sudo python3 test/run_systemd_test.py --build .build/release/cmake
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "contrib/systemd/klind.service"
NOBODY = "65534"


def run(*command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return result.returncode, result.stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ids(pid, field):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return line.split()[1:]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="CMake build directory")
    args = parser.parse_args()

    if not sys.platform.startswith("linux") or os.geteuid() != 0 or shutil.which("systemctl") is None \
            or run("systemctl", "is-system-running")[1].strip() not in ("running", "degraded"):
        print("systemd test skipped: needs root and a running systemd")
        return
    daemon = args.build / "bin/klind"
    name = f"klin-test-{os.getpid()}"
    home = Path("/opt") / name
    unit = Path("/run/systemd/system") / f"{name}.service"
    port = free_port()
    checks = 0

    def check(condition, message):
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(message)

    try:
        # outside /home and /tmp (hidden by the unit), with only system libraries
        home.mkdir(mode=0o755)
        shutil.copy2(daemon, home / "klind")
        (home / "klind.conf").write_text(
            f"server_list h\nuid {NOBODY}\ngid {NOBODY}\nh\n{{\n type http\n"
            f" addr tcp4://127.0.0.1:{port}\n dir_root /www\n}}\n")
        text = UNIT.read_text()
        text = re.sub(r"(?m)^ExecStart=.*$",
                      f"ExecStart={home}/klind -F -f {home}/klind.conf", text)
        text = re.sub(r"(?m)^(RuntimeDirectory|StateDirectory|LogsDirectory)=klin$",
                      rf"\1={name}-\1", text)
        unit.write_text(text)
        run("systemctl", "daemon-reload")
        rc, out = run("systemd-analyze", "verify", "--man=no", str(unit))
        check(rc == 0, f"systemd-analyze verify failed:\n{out}")
        rc, out = run("systemctl", "start", f"{name}.service")
        check(rc == 0, f"the unit did not start:\n{out}")

        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    reply = sock.recv(200)
                break
            except OSError:
                if time.monotonic() > deadline:
                    reply = b""
                    break
                time.sleep(0.2)
        check(reply.startswith(b"HTTP/1."), "klind did not answer under the unit: " +
              run("journalctl", "-u", f"{name}.service", "-n", "60", "--no-pager")[1])

        pid = run("systemctl", "show", "-p", "MainPID", "--value", f"{name}.service")[1].strip()
        check(pid not in ("", "0"), "the unit has no main process")
        check(ids(pid, "Uid") == [NOBODY] * 4 and ids(pid, "Gid") == [NOBODY] * 4,
              f"klind did not drop to {NOBODY}: {ids(pid, 'Uid')} {ids(pid, 'Gid')}")
        check(ids(pid, "CapEff") == ["0000000000000000"],
              f"klind kept capabilities: {ids(pid, 'CapEff')}")
        check(ids(pid, "CapBnd") != ["000001ffffffffff"], "the capability bounding set is not reduced")
        check(ids(pid, "NoNewPrivs") == ["1"], "NoNewPrivileges is not set")
        check(ids(pid, "Seccomp") == ["2"], "no system call filter")

        rc, out = run("systemd-analyze", "security", "--no-pager", f"{name}.service")
        score = re.search(r"Overall exposure level for \S+: (\d+\.\d+)", out)
        check(score is not None and float(score.group(1)) <= 3.0,
              f"systemd-analyze security rates the unit too exposed:\n{out[-2500:]}")
        print(f"systemd exposure {score.group(1)}")
    finally:
        run("systemctl", "stop", f"{name}.service")
        unit.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        run("systemctl", "reset-failed", f"{name}.service")
        shutil.rmtree(home, ignore_errors=True)
    print(f"{checks} systemd checks passed")


if __name__ == "__main__":
    main()
