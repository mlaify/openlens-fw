#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""First install of our firmware on a STOCK camera over the network (owner's terminal).

  1. Build a RELEASE image (src/build.sh, scripts/build-rootfs.sh WITHOUT --bench) and sign it:
     scripts/make-update.sh ~/.ssh/<your resident key>      -> build/update/<version>.camfw
  2. Open the stock root console: python3 scripts/camera-root-console.py open --host HOST --keep-open
  3. python3 scripts/cam-first-install.py --host HOST --package build/update/<version>.camfw
     (add --check-only for a dry run: everything up to camupdate --check, then the camera reboots
     back to stock)

What it does, over the open root shell (helpers from cam-run-mi-probe.py), all in RAM until the
final step:
  - read-only preflight: /proc/mtd must show mtd2 "rootfs" of 0xCB0000 bytes; free memory and /tmp
  - uploads build/rootfs/chroot-test.tgz (the release build: BusyBox, camupdate, the owner's update
    keys in /etc/cam/update-keys, /etc/cam/device) and the signed package, both SHA-256 checked
  - stops the vendor userland and feeds the watchdog (stop_vendor), mounts /proc /sys /dev and a
    tmpfs /tmp into the chroot
  - runs camupdate --check in the chroot: signature against the owner's keys, device, squashfs,
    size, no bench trailer. The stock camera has no version of ours installed, so the chroot's
    in-RAM /etc/cam/version is set to 20000101.0 first (the package is always newer than that)
  - asks you to type FLASH <host>, then runs camupdate detached (setsid: a dropped console can't
    hang it up): it copies itself to tmpfs, stops every other process (the console freezes here),
    takes over the watchdog, erases and writes mtd2 only, reads it back and compares, reboots
  - waits for the camera to come back and answer on port 80 with our /setup (unclaimed), or, once
    its HTTPS (camtls) is on, with our redirect to https://, whose /setup it then checks

Then claim it within 30 minutes of that boot: python3 scripts/cam-claim.py HOST (or the new DHCP
address; --http while the camera's HTTPS is off). If it doesn't come back, the CH341A restore of mtd2 (Gate 1) brings stock back:
scripts/flash-write-region.sh rootfs <golden>. Only mtd2 is ever written; never cam #2 without
--allow-cam2.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("mp", os.path.join(HERE, "cam-run-mi-probe.py"))
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)
run = mp.run
NR = "/tmp/newroot"
CAM2 = os.environ.get("CAM2_HOST")    # optional: a camera to refuse unless --allow-cam2
MTD2_SIZE = 0xCB0000


def mtd2_ok(proc_mtd):
    """/proc/mtd text: True if mtd2 is the 0xCB0000-byte "rootfs" partition."""
    m = re.search(r'(?m)^mtd2:\s+([0-9a-f]+)\s+[0-9a-f]+\s+"([^"]*)"', proc_mtd)
    return bool(m) and int(m.group(1), 16) == MTD2_SIZE and m.group(2) == "rootfs"


def build_info_release(path):
    try:
        return re.search(r"(?m)^image:\s*release\b", open(path).read()) is not None
    except OSError:
        return False


def install_failed(console):
    """Console text after the detached launch: True if camupdate gave up before the erase. Once it
    says "installing" it may be erasing: never call that a failure (a reboot then could brick),
    unless it said it couldn't take the watchdog, which it checks before the erase (nothing written)."""
    if "can't take the watchdog" in console and "nothing written" in console:
        return True
    if "camupdate: installing" in console:
        return False
    return any(m in console for m in ("REFUSED", "can't read the package", "can't copy to",
                                      "camupdate: exec", 'no mtd "rootfs"', "No such file", "not found"))


REDIRECTS = (301, 302, 303, 307, 308)
HTTPS_UP = "ours, HTTPS on (port 80 sends browsers to https://)"


def classify(code, location, host, tls=False):
    """What an answer to GET / says (tls: it came over HTTPS). Our camhttpd, unclaimed, redirects to
    /setup; with camtls ready, port 80 redirects every page to https://<host>/ first."""
    loc = location or ""
    if code in REDIRECTS and "/setup" in loc:
        return "ours, unclaimed (/setup" + (" over HTTPS)" if tls or loc.startswith("https://") else ")")
    if not tls and code in REDIRECTS and loc.startswith(f"https://{host}/"):
        return HTTPS_UP
    if code == 401:
        return "ours or stock asking for a login (claimed already?)"
    return f"answers HTTP {code}" + (" over HTTPS" if tls else "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def https_answer(host):
    """GET https://host/ without following redirects: (status, Location) or None. The camera's
    certificate is its own CA's, unknown here: not checked (this only asks whether /setup is up)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        r = opener.open(f"https://{host}/", timeout=5)
        return r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location")
    except OSError:
        return None


def wait_for_ours(host, minutes):
    """Poll http://host/ until our camhttpd answers (unclaimed: a redirect to /setup, or with HTTPS
    on, to https://, where / redirects to /setup)."""
    end = time.time() + minutes * 60
    seen_down = False
    opener = urllib.request.build_opener(NoRedirect)
    while time.time() < end:
        try:
            with socket.create_connection((host, 80), timeout=3):
                pass
        except OSError:
            seen_down = True
            time.sleep(5)
            continue
        if not seen_down:
            time.sleep(5)
            continue
        try:
            opener.open(f"http://{host}/", timeout=5)
        except urllib.error.HTTPError as e:
            got = classify(e.code, e.headers.get("Location"), host)
            if got == HTTPS_UP:
                ans = https_answer(host)
                if ans:
                    sub = classify(*ans, host, tls=True)
                    return sub if sub.startswith("ours, unclaimed") else f"{got}; https://{host}/ {sub}"
            return got
        except OSError:
            time.sleep(5)
            continue
        return "answers on port 80 (not our /setup redirect: stock again?)"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=mp.HOST or None, required=not mp.HOST,
                    help="camera IPv4 address (default: $CAM_HOST)")
    ap.add_argument("--package", required=True, help="signed .camfw from scripts/make-update.sh")
    ap.add_argument("--check-only", action="store_true", help="stop after camupdate --check (no write)")
    ap.add_argument("--allow-cam2", action="store_true", help="cam #2 is out of scope unless you say so")
    args = ap.parse_args()
    if CAM2 and args.host == CAM2 and not args.allow_cam2:
        sys.exit("cam #2 is out of scope for a first install (flash cam #1 first; --allow-cam2 overrides)")
    mp.HOST = args.host

    tgz = os.path.join(REPO, "build", "rootfs", "chroot-test.tgz")
    info = os.path.join(REPO, "build", "rootfs", "BUILD-INFO.txt")
    for p in (tgz, args.package):
        if not os.path.exists(p):
            sys.exit(f"{p} missing (build a release image, then scripts/make-update.sh)")
    if not build_info_release(info):
        sys.exit(f"{info} doesn't say 'image: release': build without --bench (a bench chroot is fine for "
                 "tests, but this must be the release build whose rootfs.sqfs you signed)")
    tgz_sha = hashlib.sha256(open(tgz, "rb").read()).hexdigest()
    pkg_sha = hashlib.sha256(open(args.package, "rb").read()).hexdigest()
    pkg_name = os.path.basename(args.package)
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.camfw", pkg_name):
        sys.exit(f"unexpected package name {pkg_name!r}")

    outdir = os.path.join(REPO, "bench-logs", time.strftime("first-install-%Y%m%d-%H%M%S"))
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
        tee("== read-only preflight")
        out, _ = run(sock, "cat /proc/mtd; free; df /tmp; cat /tmp/product_type.txt 2>/dev/null; uname -r")
        if not mtd2_ok(out):
            raise RuntimeError("/proc/mtd doesn't show mtd2 = 0xcb0000 \"rootfs\": not the expected camera, stopping")

        tee(f"== upload chroot-test.tgz (sha256 {tgz_sha[:16]})")
        mp.upload(sock, tgz)
        out, _ = run(sock, "sha256sum /tmp/chroot-test.tgz")
        if tgz_sha not in out:
            raise RuntimeError("chroot-test.tgz SHA-256 mismatch on the camera; stopping")
        run(sock, f"rm -rf {NR}; mkdir -p {NR} && tar -xzf /tmp/chroot-test.tgz -C {NR} && "
                  f"rm /tmp/chroot-test.tgz && du -s {NR}", seconds=60)
        tee(f"== upload {pkg_name} (sha256 {pkg_sha[:16]})")
        mp.upload(sock, args.package, remote_dir=NR)
        out, _ = run(sock, f"sha256sum {NR}/{pkg_name}")
        if pkg_sha not in out:
            raise RuntimeError("package SHA-256 mismatch on the camera; stopping")

        mp.stop_vendor(sock)
        run(sock, f"mkdir -p {NR}/proc {NR}/sys {NR}/dev {NR}/tmp && mount -t proc proc {NR}/proc && "
                  f"mount -o bind /sys {NR}/sys && mount -o bind /dev {NR}/dev && "
                  f"mount -t tmpfs -o size=8m tmpfs {NR}/tmp && echo mounted")
        # no version of ours is installed on a stock camera: let the package count as newer
        run(sock, f"echo 20000101.0 > {NR}/etc/cam/version; cat {NR}/etc/cam/device {NR}/etc/cam/update-keys | "
                  f"cut -c1-60")
        tee("== camupdate --check (signature, device, squashfs, size; nothing written)")
        out, code = run(sock, f"chroot {NR} /usr/sbin/camupdate --check /{pkg_name}", seconds=120)
        if code or "camupdate: OK" not in out:
            raise RuntimeError("camupdate --check refused the package; nothing was written")
        out, code = run(sock, f"chroot {NR} /bin/busybox setsid true && echo setsid ok")
        if code or "setsid ok" not in out:
            raise RuntimeError("the image's BusyBox has no setsid; nothing was written")
        if args.check_only:
            tee("== --check-only: done, nothing written; rebooting back to stock")
            sock.sendall(b"/sbin/reboot -f\r\n")
            time.sleep(3)
            return

        tee(f"\n>>> camupdate accepted the package. The next step ERASES and rewrites mtd2 on {mp.HOST}.")
        tee(">>> The console freezes while it writes; then the camera reboots into our firmware.")
        ans = input(f">>> Type FLASH {mp.HOST} to go ahead: ").strip()
        if ans != f"FLASH {mp.HOST}":
            tee("aborted: nothing written; rebooting back to stock")
            sock.sendall(b"/sbin/reboot -f\r\n")
            time.sleep(3)
            return
        tee("== camupdate install, detached (setsid); its log goes to the chroot's /tmp")
        sock.sendall(f"chroot {NR} /bin/busybox setsid /bin/busybox sh -c "
                     f"'/usr/sbin/camupdate /{pkg_name} > /tmp/camupdate.log 2>&1' &\r\n".encode())
        # camupdate stops every other process once it starts writing, this shell too (it isn't an
        # ancestor after setsid), so a silent console now is the expected sign of progress
        time.sleep(3)
        sock.sendall(f"cat {NR}/tmp/camupdate.log\r\n".encode())
        said = ""
        try:
            sock.settimeout(5)
            said = sock.recv(4096).decode(errors="replace")
        except OSError:
            pass
        tee(said or "(console silent: camupdate has taken over)")
        if install_failed(said):
            raise RuntimeError("camupdate stopped before writing (log above); mtd2 is unchanged. "
                               "Reboot the camera to go back to stock")
    finally:
        sock.close()
    tee("== waiting for the camera to reboot into our firmware (up to 10 minutes)")
    got = wait_for_ours(mp.HOST, 10)
    if got:
        tee(f"== {mp.HOST} {got}")
        tee(f">>> claim it now (30 minutes from its boot): python3 scripts/cam-claim.py {mp.HOST}"
            + ("" if "HTTPS" in got else " --http   (its HTTPS is off)"))
        tee(">>> if it took a new DHCP address, look in your router's leases (same MAC)")
    else:
        tee(f"== {mp.HOST} didn't come back on port 80 within 10 minutes. It may have a new DHCP "
            "address (check the router); if it doesn't boot at all, restore mtd2 with the CH341A "
            "(scripts/flash-write-region.sh rootfs <golden>).")
    real_print(f"\nsaved: {outdir}")


if __name__ == "__main__":
    main()
