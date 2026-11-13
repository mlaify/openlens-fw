#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live test of src/rtspd on cam #1 (issue #29). Runs from the owner's terminal.

  1. Build: docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
  2. The owner opens the root console:  python3 scripts/camera-root-console.py open --host HOST --user USER --keep-open
  3. python3 scripts/cam-run-rtspd.py [--minutes 10] [--args "-T 50"] [--keep-vendor] [--no-reboot]
  4. While it runs, play on the Mac:  ffplay -rtsp_transport tcp rtsp://HOST:8554/
     (or VLC: Media > Open Network Stream; VLC falls back to RTP over TCP by itself)

What it does, over the already-open root shell (helpers from cam-run-mi-probe.py):
  - uploads build/arm/rtspd to /tmp and checks its SHA-256
  - stops the vendor userland and feeds /dev/watchdog with the stock BusyBox watchdog applet
    (cam-run-mi-probe.stop_vendor; --keep-vendor only kills media_server, and then the vendor
    userland resets the camera ~40 s later)
  - starts rtspd in the background and streams, every 2 s, the camera uptime, rtspd's VmRSS, new
    kernel messages (K:) and new rtspd log lines (R:) into bench-logs/, so if the camera dies the
    last lines before it are saved on the Mac (the first live run rebooted the camera, cause unknown)
  - optional baseline (--baseline N s): vendor stopped, rtspd NOT started
  - phase 1 (--idle, 90 s): rtspd running, no viewer, so a failure there isn't the client's; then it says when to
    start ffplay and keeps streaming for --minutes
  - Ctrl-C stops early; then rtspd gets SIGTERM and its full log is saved
  - reboots the camera to restore stock (unless --no-reboot)
It never writes flash: only RAM-backed /tmp. rtspd has no authentication yet (Gate 3): it serves
the camera's video to anyone on that VLAN while it runs.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("mp", os.path.join(HERE, "cam-run-mi-probe.py"))
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)
run, upload, rc, HOST = mp.run, mp.upload, mp.rc, mp.HOST


# Every 2 s for `seconds` of camera uptime: uptime, the watchdog's time left (if sysfs has it),
# mainctrl's state and wait channel (it feeds the watchdog), rtspd's VmRSS, new kernel lines
# (dmesg -c; the boot log is saved first) and new rtspd log lines. This BusyBox has no cut or
# tail, so it uses sed. Stops early if rtspd exits.
def monitor_cmd(seconds, with_rtspd):
    # Ends on elapsed time, not a round count: a round is sleep 2 plus the commands, which took
    # ~2.1 s and turned a 480-minute run into 8 h 15 min.
    wd = "/sys/class/watchdog/watchdog0"
    cmd = f"M=`pidof mainctrl`; L=0; E=$((`sed 's/\\..*//' /proc/uptime` + {int(seconds)})); "
    if with_rtspd:
        cmd += "P=`cat /tmp/rtspd.pid`; "
    cmd += ("while [ `sed 's/\\..*//' /proc/uptime` -lt $E ]; do sleep 2; "
            f"echo \"@ `sed 's/ .*//' /proc/uptime` wd `cat {wd}/timeleft 2>/dev/null`/"
            f"`cat {wd}/timeout 2>/dev/null` feeder `pidof watchdog` mainctrl "
            f"`sed 's/^[^)]*) //;s/ .*//' /proc/$M/stat 2>/dev/null` `cat /proc/$M/wchan 2>/dev/null`")
    if with_rtspd:
        cmd += " `grep VmRSS /proc/$P/status`"
    cmd += "\"; dmesg -c | sed 's/^/K: /'; "
    if with_rtspd:
        cmd += ("N=`wc -l < /tmp/rtspd.log`; "
                "[ $N -gt $L ] && sed -n \"$((L+1)),${N}p\" /tmp/rtspd.log | sed 's/^/R: /'; L=$N; "
                "kill -0 $P 2>/dev/null || { echo rtspd exited; break; }; ")
    return cmd + "done"


def stream(sock, cmd, seconds):
    # `seconds` is only a backstop for a silent console: a 2 s round takes longer on this box
    """Run cmd and print its output as it arrives: "done", "stopped" (Ctrl-C) or "lost"."""
    mp._seq += 1
    marker = f"__MON_END_{mp._seq}__"
    done = re.compile(rf"{marker} \d+")      # the echoed command shows "$?", the real end a number
    sock.sendall(f"{cmd}; echo {marker} $?\r\n".encode())
    buf = b""
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            sock.settimeout(5)
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionResetError("closed")
            buf += rc.strip_telnet(chunk, sock)
            *lines, buf = buf.split(b"\n")
            for line in lines:
                text = line.decode("utf-8", "replace").rstrip("\r")
                if done.search(text):
                    return "done"
                if text.startswith(("@ ", "K: ", "R: ", "rtspd exited")):
                    print(text)
    except KeyboardInterrupt:
        print("== stopped early")
        sock.sendall(b"\x03\r\n")
        time.sleep(1)
        return "stopped"
    except OSError as e:
        print(f"== connection lost at {time.strftime('%H:%M:%S')} ({e}): camera rebooted or hung")
        return "lost"
    return "done"


def main():
    if not HOST:
        sys.exit("set CAM_HOST to the camera's IPv4 address")
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--idle", type=int, default=90, help="seconds with no viewer first")
    ap.add_argument("--baseline", type=int, default=0,
                    help="seconds with media_server killed and NO rtspd, before starting it (0 = skip)")
    ap.add_argument("--args", default="", help="extra rtspd options, e.g. \"-T 90 -b 4096\"")
    ap.add_argument("--port", type=int, default=8554)
    ap.add_argument("--iq-profile", help="iq-dump file taken under stock; uploaded and passed as -Q")
    ap.add_argument("--auth", help="htdigest file from scripts/rtsp-passwd.py; uploaded and passed "
                    "as -a (play with rtsp://USER:PASS@...). Without it rtspd runs with -N (no auth)")
    ap.add_argument("--no-reboot", action="store_true")
    ap.add_argument("--keep-vendor", action="store_true",
                    help="only kill media_server; the vendor userland then resets the camera after "
                         "~40 s (default: stop it all and feed /dev/watchdog with BusyBox watchdog)")
    args = ap.parse_args()

    binary = os.path.join(REPO, "build", "arm", "rtspd")
    want = open(binary + ".sha256").read().split()[0]
    have = hashlib.sha256(open(binary, "rb").read()).hexdigest()
    if want != have:
        sys.exit(f"local rtspd hash {have} != {want}; rebuild first")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(REPO, "bench-logs", f"rtspd-run-{stamp}")
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(outdir, "session.txt"), "w")
    real_print = print

    def tee(*a, **k):
        real_print(*a, **k)
        real_print(*a, **{**k, "file": log, "flush": True})
    mp.print = tee
    globals()["print"] = tee

    sock, _ = rc.verified_shell(HOST)
    try:
        sock.sendall(b"\r\n")
        time.sleep(0.3)
        sock.recv(65536)
        run(sock, "free; ps")
        print("== upload")
        upload(sock, binary)
        out, _ = run(sock, "sha256sum /tmp/rtspd")
        if want not in out:
            raise RuntimeError("on-camera SHA-256 mismatch; aborting before running anything")
        if args.auth:
            print("== upload Digest credentials (HA1 hashes only)")
            upload(sock, args.auth)
            args.args += f" -a /tmp/{os.path.basename(args.auth)}"
        else:
            args.args += " -N"
        if args.iq_profile:
            print("== upload IQ profile")
            upload(sock, args.iq_profile)
            args.args += f" -Q /tmp/{os.path.basename(args.iq_profile)}"

        mp.stop_vendor(sock, args.keep_vendor)
        run(sock, f"netstat -ltn 2>/dev/null | grep ':{args.port} ' || echo port {args.port} free")

        run(sock, "dmesg > /tmp/dmesg-boot.txt; dmesg -c > /dev/null; uptime; "
                  "ls /sys/class/watchdog/ 2>&1; ls -l /proc/`pidof mainctrl`/fd | grep -i watchdog")
        if args.baseline:
            print(f"\n>>> baseline: {args.baseline} s with media_server killed and NO rtspd\n")
            state = stream(sock, monitor_cmd(args.baseline, False), args.baseline + 120)
            if state == "lost":
                print("== the camera died with none of our code running: the vendor userland reboots it")
                args.no_reboot = True
                return
            if state == "stopped":
                return
        print("== start rtspd")
        run(sock, f"cd /tmp; ./rtspd -p {args.port} {args.args} > /tmp/rtspd.log 2>&1 & "
                  f"echo $! > /tmp/rtspd.pid; cd /opt/ch; sleep 4")
        run(sock, "kill -0 `cat /tmp/rtspd.pid` && echo rtspd running")
        print(f"\n>>> phase 1: {args.idle} s with NO viewer - don't start ffplay yet\n")
        state = stream(sock, monitor_cmd(args.idle, True), args.idle + 120)
        if state == "done":
            cred = "USER:PASS@" if args.auth else ""
            print(f"\n>>> phase 2: play it now on the Mac:  ffplay -rtsp_transport tcp rtsp://{cred}{HOST}:{args.port}/")
            print(f">>> sub-stream (640x360 H.264):        ffplay -rtsp_transport tcp rtsp://{cred}{HOST}:{args.port}/sub")
            print(f">>> streaming for {args.minutes:g} min; Ctrl-C stops early\n")
            state = stream(sock, monitor_cmd(args.minutes * 60, True), args.minutes * 60 + 120)
        if state == "lost":
            print("== the camera dropped the console: nothing more to collect (logs above are all we have)")
            args.no_reboot = True
            return

        print("== stop rtspd")
        run(sock, "kill `cat /tmp/rtspd.pid`; sleep 2; kill -0 `cat /tmp/rtspd.pid` 2>/dev/null "
                  "&& echo still running || echo stopped", seconds=20)
        run(sock, "grep -v '^  MI_\\|VENC nr' /tmp/rtspd.log | sed -e :a -e '$q;N;201,$D;ba'", seconds=60)
        run(sock, "dmesg | sed -e :a -e '$q;N;41,$D;ba'", seconds=30)
    finally:
        if not args.no_reboot:
            print("== reboot to restore stock")
            try:
                sock.sendall(b"/sbin/reboot -f\r\n")
                time.sleep(5)
            except OSError:
                pass
        sock.close()
        log.close()
    real_print(f"\nsaved: {outdir}")


if __name__ == "__main__":
    main()
