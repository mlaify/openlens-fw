#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""iq-bin2profile: derive the stock night tuning (rtspd image.night_tuning) from stock's IQ bins.

  python3 -I scripts/iq-bin2profile.py DAY.bin NIGHT.bin iq_groups.h NIGHT_OUT DAY_OUT \\
      [--sha256-day HEX] [--sha256-night HEX]

DAY.bin / NIGHT.bin are stock's /config/iqfile/gc4023_day.bin and gc4023_night.bin from the owner's
dump (vendor files: read at build time, never committed). Both must match their pinned SHA-256
(the defaults below; the options exist for the host test's synthetic bins) and pass every check
below, else nothing is written. Output, in the iq-dump record format rtspd's -q reads
({u32 id, u32 size, s32 ret 0, u8 data[size]}, little-endian; tools/iq-dump/iq-dump.c):
  NIGHT_OUT  the night versions of the groups taken (below) that differ from day,
  DAY_OUT    the day versions of exactly those ids, in the same order, to switch back to day
             without relying on whatever the ISP holds.
A group is taken if iq_groups.h lists it, it is in the image-pipeline range rtspd applies from an IQ
profile (Ids 4098..4999 and 10243, not the Dummy groups 4147/4148: src/mi/mi.c iq_profile_wanted),
and it is not on an AE, AEParam, AEInfo, AWB, AWBInfo, AWBCTCali, AF or AFHW page (our own AE/AWB
runs and these would fight it), not a read-only "...Info" group, not Temperature (night-only, no day
version) and not Day/Night Mode (the kernel's own day/night detection; rtspd decides). A taken group
present in both bins must have one buffer (nbuf 1) of exactly the size iq_groups.h gives.

Bin format (docs/STOCK-IMAGE-TUNING.md section 4; stock's parser trusts the lengths, this one
doesn't): a 32-byte header {u32 magic 0x6d65032c; u16 minor 0; u16 major 1; u32 payload length =
file size - 32; u32 checksum = byte sum of the payload; u32 key 1234; u32 0; u32 1 (checksum on);
u32 0}, then records {u32 key 1234; u32 type 5; u32 len; u16 api_id; u16 nbuf; u32 off[nbuf];
data}, len counting from api_id to the end of data, so data is len - 4 - 4 x nbuf bytes.
Exit 0 written, 1 an input refused (nothing written), 2 usage.
"""
import hashlib
import os
import re
import struct
import sys

DAY_SHA256 = "631beab1d1d17e99e5d87ed0726713dd54de06eb455cfd175d53c1898aaf538e"
NIGHT_SHA256 = "f221c7b55bbd74c14fbedd1507f256f852b725775d81132f09b86de0ca7f227d"
MAGIC, KEY, TYPE = 0x6D65032C, 1234, 5
SKIP_PAGES = {"AE", "AEParam", "AEInfo", "AWB", "AWBInfo", "AWBCTCali", "AF", "AFHW", "APIVer", "Dummy",
              "Temperature", "Day/Night Mode"}
MAX_FILE = 1 << 20


class Refused(Exception):
    pass


def load_groups(path):
    """iq_groups.h: {id: (size, "Page/Name")}"""
    groups = {}
    with open(path, encoding="ascii") as f:
        for m in re.finditer(r'\{ (\d+), (\d+), "([^"]*)" \}', f.read()):
            groups[int(m[1])] = (int(m[2]), m[3])
    if not groups:
        raise Refused(f"{path}: no groups")
    return groups


def taken(gid, groups):
    if gid not in groups:
        return False
    if not (4097 < gid < 5000 or gid == 10243) or gid in (4147, 4148):
        return False
    page, _, name = groups[gid][1].rpartition("/")
    return page not in SKIP_PAGES and not name.endswith("Info")


def parse_bin(path, want_sha):
    """The records of a stock IQ bin, {api_id: (nbuf, data)} in file order; Refused if anything is off."""
    with open(path, "rb") as f:
        b = f.read(MAX_FILE + 1)
    name = os.path.basename(path)
    if len(b) > MAX_FILE:
        raise Refused(f"{name}: larger than {MAX_FILE} bytes")
    sha = hashlib.sha256(b).hexdigest()
    if sha != want_sha:
        raise Refused(f"{name}: SHA-256 {sha}, expected {want_sha}")
    if len(b) < 32:
        raise Refused(f"{name}: shorter than its header")
    magic, minor, major, plen, csum, key, r0, cflag, r1 = struct.unpack_from("<IHHIIIIII", b, 0)
    if magic != MAGIC:
        raise Refused(f"{name}: magic {magic:#x}")
    if (major, minor) != (1, 0):
        raise Refused(f"{name}: version {major}.{minor}")
    if plen != len(b) - 32:
        raise Refused(f"{name}: payload length {plen}, file has {len(b) - 32}")
    if key != KEY or r0 or r1 or cflag != 1:
        raise Refused(f"{name}: header key {key} / words {r0} {cflag} {r1}")
    if sum(b[32:]) & 0xFFFFFFFF != csum:
        raise Refused(f"{name}: checksum {sum(b[32:]) & 0xFFFFFFFF:#x}, header {csum:#x}")
    recs, off = {}, 32
    while off < len(b):
        if off + 16 > len(b):
            raise Refused(f"{name}: record at {off} truncated")
        rkey, rtype, rlen, gid, nbuf = struct.unpack_from("<IIIHH", b, off)
        if rkey != KEY or rtype != TYPE:
            raise Refused(f"{name}: record at {off}: key {rkey} type {rtype}")
        end = off + 12 + rlen
        head = 4 + 4 * nbuf
        if nbuf < 1 or rlen < head or end > len(b):
            raise Refused(f"{name}: record at {off} (id {gid}): length {rlen}, {nbuf} buffers, "
                          f"{len(b) - off - 12} bytes left")
        offs = struct.unpack_from(f"<{nbuf}I", b, off + 16)
        size = rlen - head
        if offs[0] != 0 or any(a >= c for a, c in zip(offs, offs[1:])) or (size and offs[-1] >= size):
            raise Refused(f"{name}: record at {off} (id {gid}): buffer offsets {offs} of {size} bytes")
        if gid in recs:
            raise Refused(f"{name}: id {gid} twice")
        recs[gid] = (nbuf, b[off + 12 + head:end])
        off = end
    return recs


def select(day, night, groups):
    """[(id, night data, day data)] of the taken groups that differ, in the night bin's order"""
    out = []
    for gid, (nbuf, ndata) in night.items():
        if not taken(gid, groups) or gid not in day:
            continue
        size = groups[gid][0]
        for which, (nb, data) in (("day", day[gid]), ("night", (nbuf, ndata))):
            if nb != 1 or len(data) != size:
                raise Refused(f"{which} bin: id {gid} ({groups[gid][1]}): {nb} buffers of {len(data)} "
                              f"bytes, expected 1 of {size}")
        if ndata != day[gid][1]:
            out.append((gid, ndata, day[gid][1]))
    return out


def write_profile(path, recs):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        for gid, data in recs:
            f.write(struct.pack("<IIi", gid, len(data), 0) + data)
    os.replace(tmp, path)


def main(argv):
    args, opts = [], {"--sha256-day": DAY_SHA256, "--sha256-night": NIGHT_SHA256}
    it = iter(argv[1:])
    for a in it:
        if a in opts:
            opts[a] = next(it, "")
        else:
            args.append(a)
    if len(args) != 5:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    day_bin, night_bin, groups_h, night_out, day_out = args
    try:
        groups = load_groups(groups_h)
        day = parse_bin(day_bin, opts["--sha256-day"])
        night = parse_bin(night_bin, opts["--sha256-night"])
        sel = select(day, night, groups)
    except (Refused, OSError) as e:
        print(f"iq-bin2profile: {e}; nothing written", file=sys.stderr)
        return 1
    if not sel:
        print("iq-bin2profile: no image group differs between day and night; nothing written", file=sys.stderr)
        return 1
    write_profile(night_out, [(g, n) for g, n, _ in sel])
    write_profile(day_out, [(g, d) for g, _, d in sel])
    print(f"iq-bin2profile: {len(sel)} groups (night records {len(night)}, day {len(day)}): " +
          " ".join(f"{g}" for g, _, _ in sel))
    for g, n, _ in sel:
        print(f"  {g:5} {groups[g][1]:40} {len(n):6} B")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
