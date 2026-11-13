#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a fixed list of READ-ONLY commands on cam #1's already-open root shell (owner opened it).

  python3 scripts/cam-ro-probe.py scripts/probes/<list>.txt bench-logs/<out>.txt

Run it from the owner's terminal: the assistant's sandbox can't connect to the camera. Lists in
scripts/probes/ hold read-only commands only (one per line, # comments); keep it that way.
Output goes to gitignored bench-logs/ (it may contain the serial/MAC; never commit it).

Uses camera-root-console.py's verified_shell (Telnet on :23, root identity check). Each command
is followed by an end marker so output is captured completely. Output goes to one local file.
"""
import importlib.util, re, socket, sys, time

import os
HOST = os.environ.get("CAM_HOST", "")               # the camera's IPv4 address (required)
spec = importlib.util.spec_from_file_location("rc", os.path.join(os.path.dirname(os.path.abspath(__file__)), "camera-root-console.py"))
rc = importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)

def run(sock, cmd, i, seconds=20):
    marker = f"__RO_END_{i}__"
    sock.sendall(f"{cmd}; echo {marker} $?\r\n".encode())
    data = bytearray(); deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(rc.strip_telnet(chunk, sock))
        if re.search(rf"{marker} \d+".encode(), data):
            break
    return data.decode("utf-8", "replace")

def main():
    if not HOST:
        sys.exit("set CAM_HOST to the camera's IPv4 address")
    cmds = [l.rstrip("\n") for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
    out = open(sys.argv[2], "w")
    sock, _ = rc.verified_shell(HOST)
    try:
        sock.sendall(b"\r\n"); time.sleep(0.3); sock.recv(65536)
        for i, c in enumerate(cmds):
            out.write(f"\n===== $ {c}\n{run(sock, c, i)}"); out.flush()
    finally:
        sock.close()
    print("wrote", sys.argv[2], len(cmds), "commands")

main()
