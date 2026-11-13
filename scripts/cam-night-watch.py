#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Watch what the STOCK firmware does in the dark (owner 2026-10-23, #30/#36). Read-only.

  1. Build: src/build.sh (makes build/arm/ae-watch)
  2. Open the camera's root console: python3 scripts/camera-root-console.py open --host HOST \
         --user WEBUSER --keep-open
  3. python3 scripts/cam-night-watch.py --host HOST [--seconds 120]   (or CAM_HOST=HOST)

Over the open root shell, with the vendor userland left running:
  - IR state: IR LED PWM4 and white LED PWM0 (enable/period/duty), the IR-cut night flag
    /tmp/ircut_night_mode, the product type; nothing is written or exported
  - uploads build/arm/ae-watch to /tmp (SHA-256 checked) and runs it: stock's shutter, sensor and
    ISP gain, mean Y and AWB gains once a second (MI_ISP GetIQApiData only)
  - removes /tmp/ae-watch again
Output: bench-logs/night-watch-<host>-<time>.txt (gitignored). Nothing is flashed, nothing stopped.
"""
import argparse
import hashlib
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("mp", os.path.join(HERE, "cam-run-mi-probe.py"))
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)

IR_STATE = ("date; cat /tmp/product_type.txt 2>/dev/null; ls -la /tmp/ircut_night_mode 2>&1; "
            "for c in 4 0; do d=/sys/class/pwm/pwmchip$c/pwm0; "
            "echo pwmchip$c: enable `cat $d/enable 2>&1` period `cat $d/period 2>&1` "
            "duty `cat $d/duty_cycle 2>&1`; done")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("CAM_HOST"), required="CAM_HOST" not in os.environ,
                    help="camera IPv4 address (default: $CAM_HOST)")
    ap.add_argument("--seconds", type=int, default=120)
    args = ap.parse_args()
    exe = os.path.join(REPO, "build", "arm", "ae-watch")
    if not os.path.exists(exe):
        sys.exit("build/arm/ae-watch missing: run src/build.sh first")
    digest = hashlib.sha256(open(exe, "rb").read()).hexdigest()
    os.makedirs(os.path.join(REPO, "bench-logs"), exist_ok=True)
    path = os.path.join(REPO, "bench-logs",
                        time.strftime(f"night-watch-{args.host}-%Y%m%d-%H%M%S.txt"))
    log = open(path, "w")
    real_print = print

    def tee(*a, **k):
        real_print(*a, **k)
        real_print(*a, **{**k, "file": log, "flush": True})
    mp.print = tee

    sock, _ = mp.rc.verified_shell(args.host)
    try:
        sock.sendall(b"\r\n")
        time.sleep(0.3)
        sock.recv(65536)
        tee("== IR / day-night state (stock running)")
        mp.run(sock, IR_STATE)
        mp.run(sock, "ps | grep -E 'media_server|mainctrl' | grep -v grep")
        tee(f"== upload ae-watch (sha256 {digest[:16]})")
        mp.upload(sock, exe)
        out, _ = mp.run(sock, "sha256sum /tmp/ae-watch", quiet=True)
        if digest not in out:
            raise RuntimeError("on-camera SHA-256 mismatch; aborting")
        tee(f"== stock exposure for {args.seconds} s (read-only)")
        mp.run(sock, f"/tmp/ae-watch {args.seconds} 2>&1", seconds=args.seconds + 30)
        tee("== IR / day-night state again")
        mp.run(sock, IR_STATE)
    finally:
        try:
            mp.run(sock, "rm -f /tmp/ae-watch", quiet=True)
        finally:
            sock.close()
    real_print("wrote", path)


main()
