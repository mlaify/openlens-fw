#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a small IQ profile (iq-dump record format, for mi-probe/rtspd -Q) from an iq-dump file
with some fields changed. Only the groups you touch are written.

  python3 -I scripts/iq-make.py <isp_api.xml> in.bin out.bin "ColorToGray/IQ_ColorToGray.bEnable=1" ...
  python3 -I scripts/iq-make.py <isp_api.xml> - out.bin raw:10243=1,14   (raw record: id = u32 list)

A field is "<group name>/<item name>=<value>" (value applies to every element of an array item).
"raw:<id>=<u32>,<u32>,..." writes a record with exactly those words, for commands whose kernel
size differs from the XML (stock sets BypassItem 10243 as 8 bytes {value, item}).
"""
import struct
import sys
import xml.etree.ElementTree as ET

FMT = {"U8": "B", "S8": "b", "U16": "H", "S16": "h", "U32": "I", "S32": "i"}


def main():
    xml, src, dst, *edits = sys.argv[1:]
    data, recs, o = (b"" if src == "-" else open(src, "rb").read()), {}, 0
    while o + 12 <= len(data):
        gid, size, ret = struct.unpack_from("<IIi", data, o)
        recs[gid] = bytearray(data[o + 12:o + 12 + size])
        o += 12 + size
    groups = {g.get("Name"): g for g in ET.parse(xml).getroot().iter("GROUP")}
    touched = []
    for e in edits:
        if e.startswith("raw:"):
            gid, words = e[4:].split("=")
            gid = int(gid)
            recs[gid] = bytearray(struct.pack(f"<{len(words.split(','))}I",
                                              *(int(w, 0) for w in words.split(","))))
            touched.append(gid)
            print(f"raw {gid}: {words}")
            continue
        path, value = e.split("=")
        gname, iname = path.split("/", 1)
        g = groups[gname]
        gid = int(g.get("Id"))
        off = 0
        for it in g.iter("ITEM"):
            f = FMT[it.get("Type")]
            n = int(it.get("M", "1")) * int(it.get("N", "1"))
            if it.get("Name") == iname:
                for k in range(n):
                    struct.pack_into("<" + f, recs[gid], off + k * struct.calcsize(f), int(value, 0))
                break
            off += struct.calcsize(f) * n
        else:
            sys.exit(f"no item {iname} in {gname}")
        if gid not in touched:
            touched.append(gid)
        print(f"{gname} ({gid}) {iname} = {value} at +{off}")
    with open(dst, "wb") as f:
        for gid in touched:
            f.write(struct.pack("<IIi", gid, len(recs[gid]), 0) + bytes(recs[gid]))
    print(f"wrote {dst}: {len(touched)} groups")


if __name__ == "__main__":
    main()
