#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live test of tools/mi-probe on cam #1 (issue #28). Runs from the owner's terminal.

  1. The owner opens the root console:  python3 scripts/camera-root-console.py open --host HOST --user USER --keep-open
  2. python3 scripts/cam-run-mi-probe.py [--iq-profile bench-logs/iq-run-*/iq-stock.bin]
     [--no-reboot] [--skip-full] [--keep-vendor]

What it does, over the already-open root shell (camera-root-console.py verified_shell):
  - uploads build/arm/mi-probe to /tmp (base64 tar.gz; this BusyBox can't gzip -d but
    tar -xz works) and checks its SHA-256 against build/arm/mi-probe.sha256
  - stops the vendor userland (media_server owns the MI pipeline; mainctrl and friends reset the
    camera ~40 s after it is gone) and feeds /dev/watchdog with BusyBox watchdog (--keep-vendor:
    only kill media_server)
  - runs mi-probe 8 s each: a 720p baseline, one 720p variant per --iq-profile (-Q), then
    (unless --skip-full) 2560x1440 HW_RING; stops at the first kernel Oops,
    reading /proc/mi_modules mid-run
  - saves the logs, /proc/mi_modules state, dmesg tail and the .h265 files to bench-logs/
  - reboots the camera to restore stock (unless --no-reboot)
It never writes flash: only RAM-backed /tmp.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import os
import re
import socket
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HOST = os.environ.get("CAM_HOST", "")  # the camera's IPv4 address; scripts that import this may set it
spec = importlib.util.spec_from_file_location("rc", os.path.join(HERE, "camera-root-console.py"))
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

_seq = 0


def run(sock, cmd, seconds=30, quiet=False):
    """Run one shell command; return its output (between the echoed command and the marker)."""
    global _seq
    _seq += 1
    marker = f"__MP_END_{_seq}__"
    sock.sendall(f"{cmd}; echo {marker} $?\r\n".encode())
    data = bytearray()
    deadline = time.monotonic() + seconds
    pat = re.compile(rf"{marker} (\d+)".encode())
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(rc.strip_telnet(chunk, sock))
        m = pat.search(data)
        if m:
            text = data[:m.start()].decode("utf-8", "replace")
            text = text.split("\n", 1)[1] if "\n" in text else ""   # drop the echoed command
            if not quiet:
                print(f"$ {cmd[:120]}\n{text.rstrip()}\n[rc {m.group(1).decode()}]")
            return text, int(m.group(1))
    raise RuntimeError(f"timeout waiting for: {cmd[:80]}")


def _drain(sock, seconds=0.0):
    """Read and discard what the camera sends (the tty echo of an upload)."""
    deadline = time.monotonic() + seconds
    saved = sock.gettimeout()
    try:
        while True:
            sock.settimeout(max(0.0, deadline - time.monotonic()) or 0.001)
            try:
                chunk = sock.recv(262144)
            except (socket.timeout, BlockingIOError):
                return
            if not chunk:
                return
            rc.strip_telnet(chunk, sock)
    finally:
        sock.settimeout(saved)          # a 1 ms timeout left behind makes sendall() time out


def _remote_size(sock, path):
    out, code = run(sock, f"ls -l {path}", quiet=True)
    m = re.search(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s", out)
    return int(m.group(1)) if code == 0 and m else -1


def upload(sock, path, remote_dir="/tmp"):
    """Copy a file to the camera over the open root shell and unpack it in remote_dir.

    Fast path: one `base64 -d` reads the whole file from the tty (76-char lines, Ctrl-D at the
    end), so there is no round trip per chunk; the size is checked afterwards. If that fails, the
    old way: 600-char `echo -n >> file` commands (slow: ~10 min for 2 MB)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(path, arcname=os.path.basename(path))
    data = buf.getvalue()
    tgz = f"{remote_dir}/mp.tgz"
    run(sock, f"rm -f {remote_dir}/mp.b64 {tgz}", quiet=True)
    sock.settimeout(30)                 # run() leaves its last short timeout on the socket
    try:
        sock.sendall(f"stty -echo 2>/dev/null; base64 -d > {tgz}\r\n".encode())
        _drain(sock, 1.0)                       # let the shell start base64 before the data
        lines = base64.encodebytes(data).decode().splitlines()
        step = 400                              # ~30 KB per send, echo drained in between
        for i in range(0, len(lines), step):
            sock.sendall(("\r\n".join(lines[i:i + step]) + "\r\n").encode())
            _drain(sock)
            if (i // step) % 10 == 0:
                print(f"  upload {i * 100 // len(lines)}%", flush=True)
        sock.sendall(b"\x04")                   # EOF (line start, canonical mode)
        _drain(sock, 1.0)
        run(sock, "stty echo 2>/dev/null; true", quiet=True)
        ok = _remote_size(sock, tgz) == len(data)
    except (OSError, RuntimeError) as exc:
        print(f"  fast upload failed ({exc})", flush=True)
        ok = False
    if not ok:
        print("  fast upload didn't arrive intact; falling back to the slow way", flush=True)
        sock.settimeout(30)
        sock.sendall(b"\x04\x03\r\n")         # end any half-fed base64
        _drain(sock, 1.0)
        run(sock, f"stty echo 2>/dev/null; rm -f {remote_dir}/mp.b64 {tgz}", quiet=True)
        b64 = base64.b64encode(data).decode()
        step = 600          # BusyBox ash line editing caps a command near 1024 chars
        for i in range(0, len(b64), step):
            run(sock, f"echo -n '{b64[i:i + step]}' >> {remote_dir}/mp.b64", quiet=True)
            if (i // step) % 50 == 0:
                print(f"  upload {i * 100 // len(b64)}%", flush=True)
        run(sock, f"base64 -d {remote_dir}/mp.b64 > {tgz}", quiet=True)
    run(sock, f"cd {remote_dir} && tar -xzf mp.tgz && rm -f mp.b64 mp.tgz && cd /opt/ch")


def stop_vendor(sock, keep_vendor=False):
    """Stop what owns the MI pipeline. The vendor userland resets the camera ~40 s after
    media_server is gone (baseline 2026-10-22), so by default stop all of /opt/ch (mainctrl holds
    /dev/watchdog; udhcpc, telnetd and the shells stay) and feed the watchdog with the stock BusyBox
    applet. It daemonizes before opening the device, so success is checked with pidof."""
    if keep_vendor:
        print("== stop procman, kill media_server (vendor userland stays: camera resets in ~40 s)")
        run(sock, "killall procman; killall -9 media_server; i=0; "
                  "while pidof media_server >/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i+1)); done; "
                  "ps | grep -E 'procman|media_server|mainctrl' | grep -v grep", seconds=40)
        return
    print("== stop the vendor userland, feed /dev/watchdog with BusyBox watchdog")
    out, _ = run(sock, "killall procman; killall -9 media_server mainctrl hik_server record_server "
                       "comm_server dbg_server web_server h5live_server ex_server p2p_server; "
                       "for i in 1 2 3 4 5 6 7 8 9 10; do pidof watchdog >/dev/null && break; "
                       "watchdog -T 30 -t 5 /dev/watchdog; usleep 300000; done; "
                       "pidof watchdog && echo feeder running || echo NO FEEDER", seconds=30)
    if "feeder running" not in out:
        raise RuntimeError("watchdog feeder did not start; the camera will reset")
    run(sock, "ps | grep -v ' \\[' ; free")


def download(sock, remote, local):
    out, code = run(sock, f"ls -l {remote}", quiet=True)
    if code:
        print(f"  {remote} missing")
        return False
    print(f"  {out.strip()}")
    text, code = run(sock, f"base64 {remote}", seconds=240, quiet=True)
    if code:
        print(f"  download of {remote} failed")
        return False
    # keep only pure base64 lines (drops any wrapped echo of the command)
    lines = [l.strip() for l in text.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]+", l.strip())]
    data = base64.b64decode("".join(lines))
    with open(local, "wb") as f:
        f.write(data)
    print(f"  saved {local} ({len(data)} bytes)")
    return True


def main():
    if not HOST:
        sys.exit("set CAM_HOST to the camera's IPv4 address")
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-reboot", action="store_true")
    ap.add_argument("--skip-full", action="store_true")
    ap.add_argument("--iq-profile", action="append", default=[],
                    help="IQ profile (iq-dump format, e.g. a stock dump or one made with "
                         "scripts/iq-make.py); repeatable, one 720p variant per profile (-Q)")
    ap.add_argument("--variant", action="append", default=[], metavar="NAME=OPTS",
                    help="run exactly these variants (720p -A -T 50 base + OPTS; uploaded profiles "
                         "are at /tmp/<basename>), instead of the default list")
    ap.add_argument("--keep-vendor", action="store_true",
                    help="only kill media_server (the camera then resets after ~40 s)")
    args = ap.parse_args()

    binary = os.path.join(REPO, "build", "arm", "mi-probe")   # src/build.sh
    want = open(binary + ".sha256").read().split()[0]
    have = hashlib.sha256(open(binary, "rb").read()).hexdigest()
    if want != have:
        sys.exit(f"local mi-probe hash {have} != {want}; rebuild first")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(REPO, "bench-logs", f"mi-probe-run-{stamp}")
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(outdir, "session.txt"), "w")
    real_print = print

    def tee(*a, **k):
        real_print(*a, **k)
        real_print(*a, **{**k, "file": log, "flush": True})
    globals()["print"] = tee

    sock, _ = rc.verified_shell(HOST)
    try:
        sock.sendall(b"\r\n")
        time.sleep(0.3)
        sock.recv(65536)
        run(sock, "free; df /tmp; ps")
        print("== upload")
        upload(sock, binary)
        out, _ = run(sock, "sha256sum /tmp/mi-probe")
        if want not in out:
            raise RuntimeError("on-camera SHA-256 mismatch; aborting before running anything")
        profiles = []
        for path in args.iq_profile:
            print(f"== upload IQ profile {os.path.basename(path)}")
            upload(sock, path)
            profiles.append("/tmp/" + os.path.basename(path))

        # SIGTERM alone left media_server alive in run 1 (its MMA heap stayed allocated and SCL
        # couldn't get buffers), so it is killed with -9.
        stop_vendor(sock, args.keep_vendor)
        run(sock, "ls /proc/mi_modules/mi_sys_mma; cat /proc/mi_modules/mi_sys_mma/* 2>&1 | head -60")

        # Image-quality A/B (#36). The AE-field A/B changed nothing; the iq-diff showed our ISP
        # running the kernel IQ file with black level, CCM, saturation and gamma disabled, while
        # stock's are enabled and tuned. Same AE; without and with stock's IQ applied (-Q).
        # Does an IQ API set reach the picture at all? Stock's IQ applied with -Q and CUS3A 1:1:1
        # both changed nothing, so try extreme profiles (ColorToGray, gamma bypass, max manual
        # saturation, made with scripts/iq-make.py): one 720p variant each, against a baseline.
        base = "-w 1280 -h 720 -b 2048 -A -T 50"
        runs = [("720p-base", base)]
        for prof in profiles:
            stem = os.path.splitext(os.path.basename(prof))[0]
            runs.append((f"720p-{stem}", f"{base} -Q {prof}"))
        if not args.skip_full:
            runs.append(("full-ring-base", "-r -A -T 50"))
        if args.variant:
            runs = [(v.split("=", 1)[0], f"{base} {v.split('=', 1)[1]}") for v in args.variant]
        for name, opts in runs:
            print(f"== mi-probe {name}")
            # run in the background so the live pipeline state can be read mid-run
            run(sock, f"cd /tmp; ./mi-probe -v -t 8 {opts} -o /tmp/mp-{name}.h265 > /tmp/mp-{name}.log 2>&1 & "
                      f"MPPID=$!; cd /opt/ch; sleep 3")
            for m in ("mi_vif/mi_vif0", "mi_isp/mi_isp0", "mi_scl/mi_scl0", "mi_venc/mi_venc0"):
                run(sock, f"cat /proc/mi_modules/{m} 2>&1 | head -80")
            run(sock, "cat /proc/mi_modules/mi_sys_mma/* 2>&1 | head -40")
            run(sock, "wait $MPPID; echo exit=$?", seconds=60)
            run(sock, f"cat /tmp/mp-{name}.log | grep -v 'VENC nr' | head -80", seconds=30)
            run(sock, f"grep -c '^frame' /tmp/mp-{name}.log; grep '^done' /tmp/mp-{name}.log")
            run(sock, f"grep -E 'IQ profile|SetIQApiData failed|CUS3A' /tmp/mp-{name}.log | sed -n '1,40p'")
            run(sock, "dmesg | grep -E 'Cus3a:|nFlagCus3A|InitIspAttr' | sed -e :a -e '$q;N;6,$D;ba'")
            # this BusyBox has no tail; the sed keeps the last 40 lines
            run(sock, f"grep -E '^(AE|AWB|3A|MI run env|cus3a|isp_fe|open /dev|IQ profile)|^  [0-9a-f]{{2}} ' "
                      f"/tmp/mp-{name}.log | sed -e :a -e '$q;N;41,$D;ba'", seconds=30)
            run(sock, "dmesg | grep -iE 'fail|error|err ' | sed -e :a -e '$q;N;21,$D;ba'", seconds=30)
            download(sock, f"/tmp/mp-{name}.h265", os.path.join(outdir, f"mp-{name}.h265"))
            oops, _ = run(sock, "dmesg | grep -c 'Internal error: Oops'", quiet=True)
            if oops.strip() not in ("", "0"):
                print("== kernel Oops after this variant: stopping (the MI state is no longer trustworthy)")
                break
        run(sock, "dmesg | sed -e :a -e '$q;N;81,$D;ba'", seconds=30)
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
