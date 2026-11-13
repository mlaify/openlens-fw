#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy a small printable UTF-8 text file to /tmp on the old camera's open root shell.

Usage: python3 scripts/camera-copy-text.py scripts/bench-probe.sh --host HOST
Requires the temporary root console described in docs/ROOT-CONSOLE.md.
This is a text-only Telnet/heredoc transfer, not a binary firmware uploader.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets


MAX_BYTES = 8192


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local printable text file")
    parser.add_argument("--host", default=os.environ.get("CAM_HOST"), required="CAM_HOST" not in os.environ,
                        help="old camera private IPv4 address (default: $CAM_HOST)")
    args = parser.parse_args()

    source = args.source.read_bytes()
    name = args.source.name
    if name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        parser.error("source basename must contain only letters, digits, dot, underscore, or hyphen")
    if not source or len(source) > MAX_BYTES or not source.endswith(b"\n"):
        parser.error(f"source must be 1-{MAX_BYTES} bytes and end with a newline")
    try:
        decoded = source.decode("utf-8")
    except UnicodeDecodeError:
        parser.error("source must be UTF-8 text")
    if any(character != "\n" and not character.isprintable() for character in decoded):
        parser.error("source must contain printable UTF-8 characters and newlines only")

    helper_path = Path(__file__).with_name("camera-root-console.py")
    spec = importlib.util.spec_from_file_location("camera_root_console", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load root-console helper")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    address = helper.ipaddress.ip_address(args.host)
    if address.version != 4 or not address.is_private:
        parser.error("host must be a private IPv4 address")
    host = str(address)

    target = f"/tmp/{name}"
    marker = f"CODEX_TEXT_END_{secrets.token_hex(16)}".encode("ascii")
    assert marker not in source
    expected = hashlib.sha256(source).hexdigest()
    sock, _ = helper.verified_shell(host)
    try:
        payload = (b"cat > " + target.encode("ascii") + b" <<'" + marker + b"'\r\n"
                   + source.replace(b"\n", b"\r\n") + marker + b"\r\n")
        sock.sendall(payload)
        response = helper.read_until(sock, (b"/opt/ch # ",), 15)
        if b"/opt/ch # " not in response:
            raise RuntimeError("camera did not return to the shell prompt after transfer")
        sock.sendall(f"chmod 700 {target}; sha256sum {target}; wc -c {target}\r\n".encode("ascii"))
        result = helper.read_until(sock, (b"/opt/ch # ",), 8).decode("ascii", "replace")
        digest_line = re.search(rf"(?m)^{expected}  {re.escape(target)}\r?$", result)
        byte_line = re.search(rf"(?m)^{len(source)} {re.escape(target)}\r?$", result)
        if digest_line is None or byte_line is None:
            raise RuntimeError("camera copy failed SHA-256 or byte-count verification")
    finally:
        sock.close()

    print(f"Verified: {target} ({len(source)} bytes, SHA-256 {expected})")


if __name__ == "__main__":
    main()
