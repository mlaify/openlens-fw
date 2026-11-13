#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode two iq-dump files with the camera's isp_api.xml and print the fields that differ
(issue #36: stock media_server's ISP parameters vs our pipeline's).

  python3 -I scripts/iq-diff.py <isp_api.xml> iq-stock.bin iq-ours.bin [--all]
"""
import struct
import sys
import xml.etree.ElementTree as ET

FMT = {"U8": "B", "S8": "b", "U16": "H", "S16": "h", "U32": "I", "S32": "i"}


def load(path):
    recs, data = {}, open(path, "rb").read()
    o = 0
    while o + 12 <= len(data):
        gid, size, ret = struct.unpack_from("<IIi", data, o)
        recs[gid] = (ret, data[o + 12:o + 12 + size])
        o += 12 + size
    return recs


def fields(group, blob):
    """Yield (item name, list of values) in XML order."""
    o = 0
    for it in group.iter("ITEM"):
        f = FMT[it.get("Type")]
        n = int(it.get("M", "1")) * int(it.get("N", "1"))
        size = struct.calcsize("<" + f) * n
        vals = list(struct.unpack_from(f"<{n}{f}", blob, o)) if o + size <= len(blob) else None
        yield it.get("Name"), vals
        o += size


def short(v, k=8):
    return str(v if len(v) <= k else v[:k] + ["..."]) if v is not None else "?"


def main():
    xml, a_path, b_path = sys.argv[1:4]
    show_all = "--all" in sys.argv
    a, b = load(a_path), load(b_path)
    root = ET.parse(xml).getroot()
    for page in root.iter("PAGE"):
        for g in page.iter("GROUP"):
            gid = int(g.get("Id"))
            if gid not in a or gid not in b:
                continue
            (ra, da), (rb, db) = a[gid], b[gid]
            title = f"== {gid} {page.get('Name')}/{g.get('Name')}"
            if ra or rb:
                print(f"{title}: get failed (stock ret {ra}, ours ret {rb})")
                continue
            if da == db and not show_all:
                continue
            print(title)
            for (name, va), (_, vb) in zip(fields(g, da), fields(g, db)):
                if va != vb or show_all:
                    diff = "" if va is None or vb is None else \
                        f" ({sum(x != y for x, y in zip(va, vb))}/{len(va)} differ)" if len(va) > 1 else ""
                    print(f"   {name}: stock {short(va)}  ours {short(vb)}{diff}")


if __name__ == "__main__":
    main()
