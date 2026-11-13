#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 M&L AI LLC
"""Host test for scripts/scrub-uboot-env.py on a synthetic 256 KiB BOOT image."""
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "scrub-uboot-env.py")
REAL = "12:34:56:AB:CD:EF"


def make_image(path, pairs, crc_ok=True):
    env = b"".join(p + b"\0" for p in pairs) + b"\0"
    env = env.ljust(0x1000 - 4, b"\0")
    img = bytearray(b"\xff" * 0x3F000)
    crc = zlib.crc32(env) if crc_ok else 0xDEADBEEF
    img += struct.pack("<I", crc) + env
    with open(path, "wb") as f:
        f.write(img)


def run(*args):
    return subprocess.run([sys.executable, "-I", TOOL, *args], capture_output=True, text=True)


def env_of(path):
    with open(path, "rb") as f:
        img = f.read()
    (crc,) = struct.unpack_from("<I", img, 0x3F000)
    data = img[0x3F004:0x40000]
    return crc == zlib.crc32(data), data


fails = 0


def check(cond, what):
    global fails
    print(("PASS " if cond else "FAIL ") + what)
    fails += 0 if cond else 1


with tempfile.TemporaryDirectory() as t:
    p = os.path.join(t, "boot.bin")
    pairs = [b"bootdelay=0", b"ethact=sstar_emac", b"ethaddr=" + REAL.encode(), b"ipaddr=192.0.2.7"]
    make_image(p, pairs)
    with open(p, "rb") as f:
        before = f.read()

    check(run("--check", p).returncode == 1, "--check flags a real MAC")
    r = run(p)
    check(r.returncode == 0, "scrub succeeds")
    ok, data = env_of(p)
    check(ok, "env CRC is valid after scrub")
    check(REAL.encode() not in data and b"ethaddr=02:00:00:00:00:00\0" in data, "MAC replaced by the placeholder")
    check(b"ipaddr=192.0.2.7\0" in data and b"ethact=sstar_emac\0" in data, "other variables untouched")
    with open(p, "rb") as f:
        after = f.read()
    check(after[:0x3F000] == before[:0x3F000] and len(after) == len(before), "bytes before the env untouched")
    check(run("--check", p).returncode == 0, "--check passes after scrub")
    check(run(p).returncode == 0 and env_of(p)[0], "a second scrub is harmless")

    bad = os.path.join(t, "bad.bin")
    make_image(bad, pairs, crc_ok=False)
    with open(bad, "rb") as f:
        b0 = f.read()
    check(run(bad).returncode != 0, "bad CRC refused")
    with open(bad, "rb") as f:
        check(f.read() == b0, "bad-CRC image left unchanged")

    short = os.path.join(t, "short.bin")
    with open(short, "wb") as f:
        f.write(b"\0" * 1000)
    check(run(short).returncode != 0, "wrong-size image refused")

    check(run("--mac", "nope", p).returncode != 0, "invalid --mac refused")

print(f"{fails} failed")
sys.exit(1 if fails else 0)
