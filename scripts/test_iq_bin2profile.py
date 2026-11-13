#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for scripts/iq-bin2profile.py with synthetic IQ bins (no vendor file needed):

  python3 -I scripts/test_iq_bin2profile.py

A valid day/night pair gives exactly the image groups that differ (ColorToGray, Brightness, NR3D),
night and day versions in the night bin's order, and skips AE (AETarget, AdaptiveGamma on the AE
page), info, Dummy, Day/Night Mode and night-only (Temperature) groups, an equal group (Contrast) and
a multi-buffer AE group (EVComp, nbuf 2). Refused with nothing written: a bad checksum, magic,
version, payload length or header key; a record with a bad key or type, truncated, with bad buffer
offsets, or an id twice; nbuf != 1 or a size other than iq_groups.h's for a group it would take; a
SHA-256 other than the pinned one; no differing group.
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CONV = os.path.join(HERE, "iq-bin2profile.py")
GROUPS = os.path.join(HERE, "..", "tools", "iq-dump", "iq_groups.h")
fails = 0


def check(what, cond):
    global fails
    print(("ok: " if cond else "FAIL ") + what)
    if not cond:
        fails += 1


def rec(gid, data, nbuf=1, key=1234, typ=5, offs=None, cut=0):
    if offs is None:
        step = len(data) // nbuf
        offs = [i * step for i in range(nbuf)]
    body = struct.pack("<HH", gid, nbuf) + struct.pack(f"<{nbuf}I", *offs) + data
    return struct.pack("<III", key, typ, len(body) + cut) + body


def binfile(recs, magic=0x6D65032C, minor=0, major=1, key=1234, csum_delta=0, plen_delta=0, flag=1):
    payload = b"".join(recs)
    hdr = struct.pack("<IHHIIIIII", magic, minor, major, len(payload) + plen_delta,
                      (sum(payload) + csum_delta) & 0xFFFFFFFF, key, 0, flag, 0)
    return hdr + payload


def pattern(n, seed):
    return bytes((i * 7 + seed) & 0xFF for i in range(n))


def day_night():
    """(day records, night records) as {name: record bytes}, the night ones differing where noted"""
    day = {
        "ctg": rec(4100, struct.pack("<I", 0)),
        "bri": rec(4102, pattern(76, 1)),
        "con": rec(4101, pattern(76, 2)),
        "nr3d": rec(4110, pattern(2632, 3)),
        "aetarget": rec(5127, pattern(132, 4)),
        "evcomp": rec(5123, pattern(8, 5), nbuf=2),
        "adaptgamma": rec(4150, pattern(1028, 6)),
        "dummy": rec(4147, pattern(26192, 7)),
        "ccminfo": rec(4140, pattern(28, 8)),
        "dndetect": rec(4154, pattern(12, 9)),
    }
    night = dict(day)
    night.update({
        "ctg": rec(4100, struct.pack("<I", 1)),
        "bri": rec(4102, pattern(76, 11)),
        "nr3d": rec(4110, pattern(2632, 13)),
        "aetarget": rec(5127, pattern(132, 14)),
        "evcomp": rec(5123, pattern(8, 15), nbuf=2),
        "adaptgamma": rec(4150, pattern(1028, 16)),
        "dummy": rec(4147, pattern(26192, 17)),
        "ccminfo": rec(4140, pattern(28, 18)),
        "dndetect": rec(4154, pattern(12, 19)),
        "temp": rec(4152, pattern(264, 20)),
    })
    return day, night


def read_profile(path):
    b = open(path, "rb").read()
    out, off = [], 0
    while off < len(b):
        gid, size, ret = struct.unpack_from("<IIi", b, off)
        out.append((gid, size, ret, b[off + 12:off + 12 + size]))
        off += 12 + size
    return out, off == len(b)


def run(tmp, day_bytes, night_bytes, sha_day=None, sha_night=None):
    dp, np_, no, do = (os.path.join(tmp, n) for n in ("day.bin", "night.bin", "iq-night.bin", "iq-day.bin"))
    for p in (no, do):
        if os.path.exists(p):
            os.unlink(p)
    open(dp, "wb").write(day_bytes)
    open(np_, "wb").write(night_bytes)
    args = [sys.executable, "-I", CONV, dp, np_, GROUPS, no, do,
            "--sha256-day", sha_day or hashlib.sha256(day_bytes).hexdigest(),
            "--sha256-night", sha_night or hashlib.sha256(night_bytes).hexdigest()]
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr, no, do


def main():
    with tempfile.TemporaryDirectory() as tmp:
        day, night = day_night()
        order = list(night)                       # the night bin's order
        db = binfile([day[k] for k in day])
        nb = binfile([night[k] for k in order])
        rc, out, no, do = run(tmp, db, nb)
        check("valid pair: exit 0", rc == 0)
        n, n_whole = read_profile(no)
        d, d_whole = read_profile(do)
        check("both outputs whole iq-dump records", n_whole and d_whole)
        check("taken: ColorToGray, Brightness, NR3D, in the night order",
              [r[0] for r in n] == [4100, 4102, 4110] and [r[0] for r in d] == [4100, 4102, 4110])
        check("... sizes as iq_groups.h, ret 0", [(r[1], r[2]) for r in n] == [(4, 0), (76, 0), (2632, 0)] and
              [(r[1], r[2]) for r in d] == [(4, 0), (76, 0), (2632, 0)])
        check("... night data in iq-night.bin", n[0][3] == struct.pack("<I", 1) and n[1][3] == pattern(76, 11) and
              n[2][3] == pattern(2632, 13))
        check("... day data in iq-day-switch.bin", d[0][3] == struct.pack("<I", 0) and d[1][3] == pattern(76, 1) and
              d[2][3] == pattern(2632, 3))
        check("skipped: AE (5127, 4150, 5123), Dummy, CCMInfo, DayNightDetection, Temperature, equal Contrast",
              not {5127, 4150, 5123, 4147, 4140, 4154, 4152, 4101} & {r[0] for r in n})
        check("... and it says what it took", "3 groups" in out and "4110" in out)

        def refused(what, day_bytes, night_bytes, reason, **kw):
            rc, out, no, do = run(tmp, day_bytes, night_bytes, **kw)
            check(f"{what}: refused ({reason}), nothing written",
                  rc == 1 and reason in out and not os.path.exists(no) and not os.path.exists(do))

        refused("bad checksum", binfile([day[k] for k in day], csum_delta=1), nb, "checksum")
        refused("bad magic", db, binfile([night[k] for k in order], magic=0x12345678), "magic")
        refused("bad version", db, binfile([night[k] for k in order], major=2), "version")
        refused("bad payload length", db, binfile([night[k] for k in order], plen_delta=4), "payload length")
        refused("bad header key", db, binfile([night[k] for k in order], key=1235), "header key")
        refused("checksum flag off", db, binfile([night[k] for k in order], flag=0), "header key")
        bad = dict(night, bri=rec(4102, pattern(76, 11), key=4321))
        refused("bad record key", db, binfile([bad[k] for k in order]), "key 4321")
        bad = dict(night, bri=rec(4102, pattern(76, 11), typ=6))
        refused("bad record type", db, binfile([bad[k] for k in order]), "type 6")
        refused("truncated record", db, binfile([night[k] for k in order] + [rec(4105, pattern(64, 1), cut=9)]),
                "bytes left")
        refused("truncated header", db, binfile([night[k] for k in order] + [b"\xd2\x04\x00\x00\x05"]), "truncated")
        bad = dict(night, evcomp=rec(5123, pattern(8, 15), nbuf=2, offs=[0, 9]))
        refused("buffer offset past the data", db, binfile([bad[k] for k in order]), "buffer offsets")
        refused("an id twice", db, binfile([night[k] for k in order] + [night["ctg"]]), "id 4100 twice")
        bad = dict(night, bri=rec(4102, pattern(76, 11), nbuf=2, offs=[0, 4]))
        refused("nbuf 2 for a group it takes", db, binfile([bad[k] for k in order]), "2 buffers")
        bad = dict(day, nr3d=rec(4110, pattern(2631, 3)))
        refused("a size other than iq_groups.h's (day bin)", binfile([bad[k] for k in day]), nb, "expected 1 of 2632")
        refused("SHA-256 not the pinned one", db, nb, "SHA-256", sha_night="0" * 64)
        refused("no group differs", db, db, "no image group differs")
        check("default pins: the stock bins' hashes", "f221c7b55bbd74c14fbedd1507f256f852b725775d81132f09b86de0ca7f227d"
              in open(CONV).read() and "631beab1d1d17e99e5d87ed0726713dd54de06eb455cfd175d53c1898aaf538e" in open(CONV).read())
        p = subprocess.run([sys.executable, "-I", CONV, "x"], capture_output=True, text=True)
        check("usage: exit 2", p.returncode == 2)
    print("ALL OK" if not fails else f"{fails} FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
