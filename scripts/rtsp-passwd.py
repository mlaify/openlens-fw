#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create or update the builder's bench credentials (outside the repo, mode 600):

  python3 scripts/rtsp-passwd.py [USER] [--role admin|operator|viewer] [--file PATH]

Prompts for the password (not echoed) and writes, in ~/.config/cam-firmware-dev/:
  rtspd.htdigest  "user:camera:HA1" (MD5(user:realm:password)): rtspd -a for bench runs next to the
                  stock userland (scripts/cam-run-rtspd.py --auth)
  users.seed      "user:role:password": the accounts a bench image (scripts/build-rootfs.sh --bench)
                  seeds for the RAM chroot test. It holds the password itself, because ONVIF
                  WS-UsernameToken needs it (owner decision 2026-10-23), so keep the folder
                  private. A release image embeds neither file: each camera is claimed at first
                  boot (#128, docs/CLAIM.md).

The password rules are camcfg's (src/camcfg/camcfg.c), implemented again here because this runs on
the host, not the camera: 8..64 characters, never shortened (a longer one is refused); printable
ASCII only (space to '~'); no space at the start or end; not the user name in any case.
"""
import argparse
import getpass
import hashlib
import os

REALM = "camera"


def password_problem(user, pw):
    """None if camcfg takes the password for user, else its reason (camcfg's pw_check, same order)."""
    if any(not 0x20 <= ord(c) <= 0x7E for c in pw):
        return "password: letters, digits, symbols and spaces only (ASCII)"
    if pw and (pw[0] == " " or pw[-1] == " "):
        return "password must not start or end with a space"
    if len(pw) < 8:
        return "password must be at least 8 characters"
    if len(pw) > 64:
        return "password must be at most 64 characters (a longer one is never shortened)"
    if pw.lower() == user.lower():
        return "password must not be the user name"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user", nargs="?", default="admin")
    ap.add_argument("--role", default="admin", choices=["admin", "operator", "viewer"])
    ap.add_argument("--file", default=os.path.expanduser("~/.config/cam-firmware-dev/rtspd.htdigest"))
    args = ap.parse_args()
    if ":" in args.user:
        raise SystemExit("user name may not contain ':'")
    pw = getpass.getpass(f"password for {args.user}: ")
    if pw != getpass.getpass("again: "):
        raise SystemExit("passwords differ")
    why = password_problem(args.user, pw)
    if why:
        raise SystemExit(why)
    ha1 = hashlib.md5(f"{args.user}:{REALM}:{pw}".encode()).hexdigest()
    os.makedirs(os.path.dirname(args.file), exist_ok=True)
    lines = []
    if os.path.exists(args.file):
        lines = [l for l in open(args.file).read().splitlines() if not l.startswith(args.user + ":")]
    lines.append(f"{args.user}:{REALM}:{ha1}")
    fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(args.file, 0o600)
    print(f"wrote {args.file} ({len(lines)} user(s), realm {REALM})")
    seed = os.path.join(os.path.dirname(args.file), "users.seed")
    rows = []
    if os.path.exists(seed):
        rows = [l for l in open(seed).read().splitlines() if not l.startswith(args.user + ":")]
    rows.append(f"{args.user}:{args.role}:{pw}")
    fd = os.open(seed, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(rows) + "\n")
    os.chmod(seed, 0o600)
    print(f"wrote {seed} ({len(rows)} user(s), bench accounts for build-rootfs.sh --bench only)")


if __name__ == "__main__":
    main()
