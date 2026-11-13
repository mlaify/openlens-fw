#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Chroot test of the #31 rootfs on cam #1, in RAM (the issue's "done when"). Owner's terminal.

  1. Build: src/build.sh, then scripts/build-rootfs.sh (see its header for the docker command)
  2. Open the root console (--keep-open), then: python3 scripts/cam-chroot-test.py [--minutes 10]
  3. When it says so, play: ffplay -rtsp_transport tcp rtsp://USER:PASS@HOST/ (and /sub)

What it does, over the open root shell (helpers from cam-run-mi-probe.py):
  - uploads build/rootfs/chroot-test.tgz (our files only: BusyBox, rcS/inittab, rtspd, credentials,
    IQ profile) and unpacks it into /tmp/newroot (tmpfs)
  - stops the vendor userland and feeds the watchdog (stop_vendor); the stock kernel modules stay
    loaded, so the image's module loading isn't exercised here (it is at the first real boot)
  - bind-mounts the live /config, /dev, /proc, /sys into it, checks the image (BusyBox runs,
    rcS/inittab syntax, files and modes), runs cam-config on a tmpfs stand-in for DATA (no flash
    writes), starts our syslogd and /usr/sbin/rtspd-run inside the chroot, lists the listening
    sockets and samples the log while you play the stream
  - takes a JPEG snapshot through rtspd's control socket and saves it to the run folder (#75)
  - restarts rtspd once (camcfg ctl restart) and shows whether the pipeline comes back
  - polls NTP once (ntpc -1, #78)
  - starts sshd-run (Dropbear, keys only, #76) and camhttpd-run (ONVIF + /snapshot.jpg, #74/#75)
    and tells you to log in with your key
  - with --daynight-check (#30): forces night, then day, then auto, printing the IR LED PWM
  - with --image-check (#73): checks the control socket, steps each image setting low/high/back to
    50 (10 s each, watch the stream), and checks a user change reaches rtspd (auth-reload)
  - with --overnight (tuning runs): each minute also the day/night state and score, the IR LED,
    the shutter limits, the AE (ae.*: mean Y, target, shutter, sensor and ISP gain) and motion
    cells/peak; every 15 minutes a snapshot (snap-HHMM.jpg), so the night picture can be judged
    afterwards (scripts/test_cam_chroot_test.py checks the sampler's command)
  - with --conf FILE: before rtspd starts, each `key=value` line of FILE is set with camcfg (which
    validates it), so a camera's tuning survives from run to run (e.g. bench-conf/cam2.conf,
    gitignored; camcfg's keys as in src/README.md; # comments and blank lines skipped)
  - saves everything to bench-logs/chroot-run-<time>/ and reboots (unless --no-reboot)
It never writes flash.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import shlex
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("mp", os.path.join(HERE, "cam-run-mi-probe.py"))
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)
run = mp.run
NR = "/tmp/newroot"


CHROOT_SH = f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c"
# --overnight, each minute: the day/night and exposure settings and the AE now (ae.*: mean Y, its
# target, shutter, sensor and ISP gain), on one line each from `camcfg ctl get` and `ctl motion`
OVERNIGHT_GET_GREP = "^daynight|^image.irled|^image.shutter|^time.tz|^ae\\."
OVERNIGHT_SAMPLE = (f"{CHROOT_SH} \"camcfg ctl get | grep -E '{OVERNIGHT_GET_GREP}' | tr '\\\\n' ' '; echo; "
                    f"camcfg ctl motion | grep -E 'state|cells|peak|need' | tr '\\\\n' ' '; echo\"")


def snapshot_ok(out):
    """rtspd answered `snapshot` with "ok SIZE": a line of its own, whatever camcfg's exit status
    (camcfg before the 2026-10-24 fix exited 1 on it, so the exit status can't decide)."""
    return any(re.fullmatch(r"ok \d+", line.strip()) for line in out.splitlines())


IMAGE_STEPS = [("saturation", 20, "much less colour"), ("saturation", 80, "much more colour"),
               ("brightness", 25, "darker"), ("brightness", 75, "brighter"),
               ("contrast", 25, "flatter"), ("contrast", 75, "punchier"),
               ("sharpness", 10, "softer"), ("sharpness", 90, "sharper"),
               ("exposure", 30, "darker (AE target down)"), ("exposure", 70, "brighter (AE target up)")]


def image_check(sock):
    """#73 live: socket present and root-only, each setting applied live, user change reloaded."""
    tee = mp.print
    cc = f"chroot {NR} /usr/sbin/camcfg"
    tee("== #73 image settings over the control socket (watch the stream)")
    run(sock, f"ls -la {NR}/run/camd.sock; {cc} ctl get")
    for key, val, what in IMAGE_STEPS:
        tee(f">>> image.{key} = {val}: expect {what}")
        run(sock, f"{cc} set image.{key} {val} && echo applied")
        time.sleep(10)
        if val > 50:
            run(sock, f"{cc} unset image.{key} && echo back to 50")
            time.sleep(4)
    run(sock, f"{cc} set image.bogus 5; {cc} set image.contrast 101; {cc} ctl get; {cc} list")
    tee("== #73 user change -> htdigest regenerated -> rtspd auth-reload (throwaway user, tmpfs)")
    run(sock, f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c \"head -c 12 /dev/urandom | md5sum | cut -c1-24 | "
              f"camcfg user add tmpcheck viewer; grep -c . /run/cam/rtspd.htdigest; "
              f"camcfg user del tmpcheck; grep -c . /run/cam/rtspd.htdigest; "
              f"logread | grep -E 'control:' | tail -n 14\"")


def daynight_check(sock):
    """#30 live: forced night (IR-cut out, IR LEDs on, B/W), forced day, then auto."""
    tee = mp.print
    cc = f"chroot {NR} /usr/sbin/camcfg"
    pwm = "cat /sys/class/pwm/pwmchip4/pwm0/duty_cycle /sys/class/pwm/pwmchip4/pwm0/enable"
    tee("== #30 day/night (watch the stream; a click is the IR-cut moving)")
    run(sock, f"{cc} ctl get | grep daynight; {pwm}")
    tee(">>> forced NIGHT for 20 s: expect a click, black and white, IR LEDs glowing dim red")
    run(sock, f"{cc} set daynight.mode night; sleep 3; {pwm}", seconds=20)
    time.sleep(17)
    tee(">>> forced DAY for 15 s: expect a click, colour, IR LEDs off")
    run(sock, f"{cc} set daynight.mode day; sleep 3; {pwm}", seconds=20)
    time.sleep(12)
    tee(">>> back to AUTO (light sensor, 5 s debounce)")
    run(sock, f"{cc} unset daynight.mode; sleep 7; {cc} ctl get | grep daynight; {pwm}", seconds=20)


CONF_KEY = re.compile(r"[a-z0-9._-]{1,64}")


def read_conf(path):
    """FILE's key=value lines (# comments and blank lines skipped). Keys as camcfg's; values one
    line of printable ASCII. camcfg on the camera validates each value; this only keeps the shell
    command sane. Exits on a malformed line."""
    out = []
    for n, line in enumerate(open(path, encoding="ascii", errors="strict"), 1):
        line = line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        k, sep, v = line.partition("=")
        k = k.strip()
        if not sep or not CONF_KEY.fullmatch(k) or not all(0x20 <= ord(c) < 0x7f for c in v) or len(v) > 300:
            sys.exit(f"{path}:{n}: not a key=value line camcfg could take: {line!r}")
        out.append((k, v))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--no-reboot", action="store_true")
    ap.add_argument("--host", default=mp.HOST or None, required=not mp.HOST,
                    help="camera IPv4 address (default: $CAM_HOST)")
    ap.add_argument("--daynight-check", action="store_true",
                    help="#30: force night, then day, then back to auto while you watch")
    ap.add_argument("--conf", metavar="FILE",
                    help="key=value settings applied with camcfg before rtspd starts (e.g. bench-conf/cam2.conf)")
    ap.add_argument("--overnight", action="store_true",
                    help="tuning run: day/night score, exposure limits and motion each minute, a snapshot every 15 min")
    ap.add_argument("--image-check", action="store_true",
                    help="#73: step each image setting through the control socket while you watch")
    args = ap.parse_args()
    mp.HOST = args.host
    conf = read_conf(args.conf) if args.conf else []

    tgz = os.path.join(REPO, "build", "rootfs", "chroot-test.tgz")
    if not os.path.exists(tgz):
        sys.exit("build/rootfs/chroot-test.tgz missing: run scripts/build-rootfs.sh first")
    digest = hashlib.sha256(open(tgz, "rb").read()).hexdigest()

    outdir = os.path.join(REPO, "bench-logs", time.strftime("chroot-run-%Y%m%d-%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(outdir, "session.txt"), "w")
    real_print = print

    def tee(*a, **k):
        real_print(*a, **k)
        real_print(*a, **{**k, "file": log, "flush": True})
    mp.print = tee

    sock, _ = mp.rc.verified_shell(mp.HOST)
    try:
        sock.sendall(b"\r\n")
        time.sleep(0.3)
        sock.recv(65536)
        tee(f"== upload chroot-test.tgz ({os.path.getsize(tgz)} bytes, sha256 {digest[:16]})")
        mp.upload(sock, tgz)
        out, _ = run(sock, "sha256sum /tmp/chroot-test.tgz")
        if digest not in out:
            raise RuntimeError("on-camera SHA-256 mismatch; aborting")
        run(sock, f"rm -rf {NR}; mkdir -p {NR} && tar -xzf /tmp/chroot-test.tgz -C {NR} && "
                  f"rm /tmp/chroot-test.tgz && du -s {NR}", seconds=60)

        mp.stop_vendor(sock)
        tee("== mount the live /config, /dev, /proc, /sys into the image")
        # the kernel modules open /config/... relative to the caller's root, so the chroot needs
        # the live /config (run 1 failed: no mountpoint -> no IQ file, VENC CreateChn failed)
        run(sock, f"mkdir -p {NR}/proc {NR}/sys {NR}/dev {NR}/tmp {NR}/run {NR}/config && "
                  f"mount -t proc proc {NR}/proc && mount -o bind /sys {NR}/sys && "
                  f"mount -o bind /dev {NR}/dev && mount -t tmpfs -o size=4m tmpfs {NR}/tmp && "
                  f"mount -t tmpfs tmpfs {NR}/run && mount -o bind,ro /config {NR}/config && echo mounted")

        tee("== image checks (inside the chroot)")
        run(sock, f"chroot {NR} /bin/busybox | sed -n 1p; chroot {NR} /bin/sh -n /etc/init.d/rcS && "
                  f"echo rcS syntax ok; chroot {NR} /bin/sh -n /usr/sbin/rtspd-run && echo rtspd-run syntax ok")
        run(sock, f"chroot {NR} /bin/ls -la /linuxrc /etc/inittab /etc/shadow /etc/cam "
                  f"/usr/sbin/rtspd /config/iqfile/iqfile0.bin")
        run(sock, f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c 'cat /etc/inittab; ls /bin | wc -l; ls /sbin /usr/bin /usr/sbin | wc -l'")

        tee("== config on a tmpfs DATA stand-in (no flash writes): cam-config + camcfg")
        run(sock, f"chroot {NR} /sbin/syslogd -C64; "
                  f"mkdir -p {NR}/mnt/nand && mount -t tmpfs -o size=256k tmpfs {NR}/mnt/nand && "
                  f"chroot {NR} /etc/init.d/cam-config; chroot {NR} /usr/sbin/camcfg user list; "
                  f"chroot {NR} /bin/ls -la /mnt/nand/cam /run/cam")
        if conf:
            tee(f"== settings from {args.conf} ({len(conf)}), each through camcfg")
            for k, v in conf:
                run(sock, f"chroot {NR} /usr/sbin/camcfg set {shlex.quote(k)} {shlex.quote(v)}")
        tee("== start rtspd-run inside the chroot")
        # respawn it like init would: ONVIF SetVideoEncoderConfiguration restarts rtspd
        run(sock, f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c "
                  f"'while :; do /usr/sbin/rtspd-run; sleep 1; done' > /dev/null 2>&1 & "
                  f"echo $! > /tmp/rtspd-run.pid; sleep 6; chroot {NR} /sbin/logread | "
                  f"grep -v '^.*rtspd:   MI_' | sed -n '1,40p'", seconds=40)
        tee("== snapshot (#75): JPEG channel -> /run/cam/snapshot.jpg -> bench-logs")
        out, code = run(sock, f"chroot {NR} /usr/sbin/camcfg ctl snapshot; ls -l {NR}/run/cam/snapshot.jpg")
        if code == 0 and "ok " in out:
            mp.download(sock, f"{NR}/run/cam/snapshot.jpg", os.path.join(outdir, "snapshot.jpg"))
        tee("== rtspd restart in the same boot (ONVIF stream changes restart it)")
        run(sock, f"chroot {NR} /usr/sbin/camcfg ctl restart; sleep 15; chroot {NR} /usr/bin/env "
                  f"PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c \"logread | grep rtspd | "
                  f"grep -E 'rtspd: main|failed|error|frame 250|restart' | tail -n 12\"", seconds=40)
        tee("== start sshd-run inside the chroot (#76)")
        run(sock, f"mount -o bind /dev/pts {NR}/dev/pts; chroot {NR} /bin/ls -la /root/.ssh/ /etc/shadow; "
                  # respawn it like init would (the vendor's BusyBox has no tail/tr/od: pipes run in
                  # the chroot)
                  f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c 'while :; do /usr/sbin/sshd-run; sleep 2; done' "
                  f"> /dev/null 2>&1 & sleep 10; "
                  f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c \"logread | grep -E 'sshd|dropbear' | tail -n 8\"", seconds=40)
        tee("== start camhttpd-run inside the chroot (#74 ONVIF, #75 /snapshot.jpg)")
        run(sock, f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c "
                  f"'while :; do /usr/sbin/camhttpd-run; sleep 2; done' > /dev/null 2>&1 & sleep 3; "
                  f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c "
                  f"\"logread | grep camhttpd | tail -n 6\"", seconds=20)
        run(sock, "netstat -ltnp 2>/dev/null || netstat -ltn; netstat -lunp 2>/dev/null | grep 3702")
        tee("== NTP (#78): one poll of time.ntp (default time.cloudflare.com) with the stock DNS")
        run(sock, f"cp /etc/resolv.conf {NR}/tmp/resolv.conf 2>/dev/null; date; "
                  f"chroot {NR} /usr/sbin/ntpc -c /mnt/nand/cam/cam.conf -1 -v; echo ntpc=$?; date", seconds=20)
        tee(f"\n>>> ssh now: ssh root@{mp.HOST}   (compare the host key fingerprint with the sshd lines above;")
        tee(">>>   then try: id; ps; logread | tail; exit) and a password-only login must fail:")
        tee(f">>>   ssh -o PubkeyAuthentication=no root@{mp.HOST}")
        tee(f">>> ONVIF: add http://{mp.HOST}/onvif/device_service in Surveillance Station (ONVIF, port 80),")
        tee(f">>>   snapshot: curl --digest -u USER:PASS -o snap.jpg http://{mp.HOST}/snapshot.jpg")
        tee(f"\n>>> play now: ffplay -rtsp_transport tcp rtsp://USER:PASS@{mp.HOST}/   (and /sub)")
        if args.image_check:
            image_check(sock)
        if args.daynight_check:
            daynight_check(sock)
        tee(f">>> sampling every 60 s for {args.minutes:g} min; Ctrl-C stops early\n")
        end = time.time() + args.minutes * 60
        n = 0
        try:
            while time.time() < end:
                time.sleep(min(60, max(1, end - time.time())))
                tee(f"== sample {time.strftime('%H:%M:%S')}")
                if args.overnight:
                    run(sock, OVERNIGHT_SAMPLE, quiet=False)
                    if n % 15 == 0:
                        out, _ = run(sock, f"chroot {NR} /usr/sbin/camcfg ctl snapshot", quiet=True)
                        if snapshot_ok(out):
                            mp.download(sock, f"{NR}/run/cam/snapshot.jpg",
                                        os.path.join(outdir, time.strftime("snap-%H%M.jpg")))
                    n += 1
                run(sock, f"chroot {NR} /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c \"logread | grep -E 'stats:|client|failed|dropped|sshd|dropbear' | "
                          f"tail -n 8; camcfg ctl get | grep daynight.state; camcfg ctl motion | grep -E 'state|seq'\"; grep VmRSS /proc/`pidof rtspd`/status; free | sed -n 2p")
        except KeyboardInterrupt:
            tee("== stopped early")
        run(sock, f"chroot {NR} /sbin/logread > /tmp/chroot-logread.txt; wc -l /tmp/chroot-logread.txt")
        mp.download(sock, "/tmp/chroot-logread.txt", os.path.join(outdir, "logread.txt"))
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
