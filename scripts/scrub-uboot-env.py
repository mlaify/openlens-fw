#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 M&L AI LLC
"""Replace the camera's MAC address in a saved U-Boot environment and fix the env's CRC.

The stock BOOT partition (mtd0, 256 KiB) ends with U-Boot's saved environment: 4 KiB at
0x3F000, a little-endian CRC32 followed by NUL-separated name=value pairs. It holds
`ethaddr=`, the camera's real MAC address. Run this on a copy of mtd0 before you share or
commit it.

    python3 -I scripts/scrub-uboot-env.py vendor-blobs/boot/mtd0-BOOT.bin           # scrub in place
    python3 -I scripts/scrub-uboot-env.py --check vendor-blobs/boot/mtd0-BOOT.bin   # exit 1 if not scrubbed

The placeholder 02:00:00:00:00:00 is a locally administered address. A camera flashed with a
scrubbed BOOT image needs its own MAC set again (U-Boot: `setenv ethaddr <mac>; saveenv`), and
the firmware's settings backup ties its device ID to that address.
"""
import argparse
import re
import struct
import sys
import zlib

ENV_OFF = 0x3F000
ENV_SIZE = 0x1000
PLACEHOLDER = "02:00:00:00:00:00"
MAC_RE = re.compile(rb"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def env_vars(env):
    """Yield (offset, name, value) for each NUL-terminated pair in the env data."""
    off = 0
    while off < len(env) and env[off] != 0:
        end = env.index(b"\0", off)
        name, _, value = env[off:end].partition(b"=")
        yield off, name, value
        off = end + 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image", help="a BOOT partition image (mtd0, 256 KiB)")
    ap.add_argument("--mac", default=PLACEHOLDER, help="replacement MAC (default %(default)s)")
    ap.add_argument("--check", action="store_true", help="only check; exit 1 unless scrubbed")
    a = ap.parse_args()

    if not MAC_RE.match(a.mac.encode()):
        sys.exit(f"--mac: not a MAC address: {a.mac}")
    with open(a.image, "rb") as f:
        img = bytearray(f.read())
    if len(img) != 0x40000:
        sys.exit(f"{a.image}: {len(img)} bytes, expected 262144 (a 256 KiB BOOT partition)")

    data = img[ENV_OFF + 4:ENV_OFF + ENV_SIZE]
    (crc,) = struct.unpack_from("<I", img, ENV_OFF)
    if zlib.crc32(data) != crc:
        sys.exit(f"{a.image}: no valid U-Boot env at 0x{ENV_OFF:X} (CRC mismatch); nothing changed")

    macs = [(o, n, v) for o, n, v in env_vars(data) if n in (b"ethaddr", b"eth1addr")]
    if not macs:
        print(f"{a.image}: env has no ethaddr; nothing to do")
        return 0

    if a.check:
        bad = [n.decode() for _, n, v in macs if v.decode().lower() != a.mac.lower()]
        if bad:
            print(f"{a.image}: NOT scrubbed: a real address is still in {', '.join(bad)}")
            return 1
        print(f"{a.image}: scrubbed ({', '.join(n.decode() for _, n, _ in macs)} = {a.mac})")
        return 0

    for off, name, value in macs:
        if not MAC_RE.match(value):
            sys.exit(f"{a.image}: {name.decode()} isn't a MAC address; nothing changed")
        start = ENV_OFF + 4 + off + len(name) + 1
        img[start:start + len(value)] = a.mac.encode()   # same length: 17 characters
    struct.pack_into("<I", img, ENV_OFF, zlib.crc32(img[ENV_OFF + 4:ENV_OFF + ENV_SIZE]))
    with open(a.image, "r+b") as f:
        f.write(img)
    print(f"{a.image}: {', '.join(n.decode() for _, n, _ in macs)} set to {a.mac}, env CRC updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
