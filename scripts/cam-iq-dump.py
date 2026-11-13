#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dump the ISP's IQ parameters under stock and under our pipeline on cam #1 (issue #36).

  1. Build: docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
  2. The owner opens the root console (--keep-open), then: python3 scripts/cam-iq-dump.py
     [--iq-profile bench-logs/iq-profile-stock.bin]   (apply it, then dump ours: did it land?)
  3. python3 -I scripts/iq-diff.py <isp_api.xml> bench-logs/iq-run-*/iq-stock.bin bench-logs/iq-run-*/iq-ours.bin

What it does, over the open root shell (helpers from cam-run-mi-probe.py):
  - uploads build/arm/iq-dump and build/arm/mi-probe to /tmp and checks their SHA-256
  - runs iq-dump while the stock media_server streams (read-only IQ API gets) -> iq-stock.bin
  - stops the vendor userland and feeds the watchdog (stop_vendor), runs mi-probe 720p -A -T 50
    for 25 s and, 12 s in, iq-dump -> iq-ours.bin
  - downloads both dumps, the logs and the clip to bench-logs/iq-run-<time>/, then reboots
It never writes flash and never sets an IQ parameter.
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


def checked(name):
    path = os.path.join(REPO, "build", "arm", name)
    want = open(path + ".sha256").read().split()[0]
    if hashlib.sha256(open(path, "rb").read()).hexdigest() != want:
        sys.exit(f"local {name} hash mismatch; rebuild first")
    return path, want


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-reboot", action="store_true")
    ap.add_argument("--iq-profile", help="also apply this iq-dump (mi-probe -Q) before dumping ours, "
                    "to check that the profile's values really land in the ISP")
    args = ap.parse_args()
    bins = [checked("iq-dump"), checked("mi-probe")]

    outdir = os.path.join(REPO, "bench-logs", time.strftime("iq-run-%Y%m%d-%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(outdir, "session.txt"), "w")
    real_print = print

    def tee(*a, **k):
        real_print(*a, **k)
        real_print(*a, **{**k, "file": log, "flush": True})
    mp.print = tee
    run = mp.run

    sock, _ = mp.rc.verified_shell(mp.HOST)
    try:
        sock.sendall(b"\r\n")
        time.sleep(0.3)
        sock.recv(65536)
        for path, want in bins:
            tee(f"== upload {os.path.basename(path)}")
            mp.upload(sock, path)
            out, _ = run(sock, f"sha256sum /tmp/{os.path.basename(path)}")
            if want not in out:
                raise RuntimeError("on-camera SHA-256 mismatch; aborting")

        q = ""
        if args.iq_profile:
            if os.path.basename(args.iq_profile) in ("iq-stock.bin", "iq-ours.bin"):
                raise RuntimeError("copy the profile to another name first: this run writes "
                                   "/tmp/iq-stock.bin and /tmp/iq-ours.bin")
            tee("== upload IQ profile")
            mp.upload(sock, args.iq_profile)
            q = f" -Q /tmp/{os.path.basename(args.iq_profile)}"
        tee("== IQ dump under stock (media_server running; read-only)")
        run(sock, "cd /tmp; ./iq-dump /tmp/iq-stock.bin 2>&1 | sed -n '1,80p'; cd /opt/ch", seconds=60)
        mp.download(sock, "/tmp/iq-stock.bin", os.path.join(outdir, "iq-stock.bin"))

        mp.stop_vendor(sock)
        tee("== our pipeline: mi-probe 720p -A -T 50, IQ dump 12 s in")
        run(sock, f"cd /tmp; ./mi-probe -t 25 -w 1280 -h 720 -b 2048 -A -T 50{q} -o /tmp/mp-iq.h265 "
                  "> /tmp/mp-iq.log 2>&1 & MPPID=$!; sleep 12; ./iq-dump /tmp/iq-ours.bin 2>&1 | "
                  "sed -n '1,80p'; wait $MPPID; echo exit=$?; cd /opt/ch", seconds=90)
        run(sock, "grep -E '^(AE|AWB|3A|MI run|done|IQ profile)|SetIQApiData failed' /tmp/mp-iq.log | "
                  "sed -n '1,60p'")
        mp.download(sock, "/tmp/iq-ours.bin", os.path.join(outdir, "iq-ours.bin"))
        mp.download(sock, "/tmp/mp-iq.h265", os.path.join(outdir, "mp-iq.h265"))
        run(sock, "dmesg | grep -iE 'oops|fail|error' | sed -e :a -e '$q;N;21,$D;ba'", seconds=30)
    finally:
        if not args.no_reboot:
            tee("== reboot to restore stock")
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
