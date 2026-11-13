#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Annotate Ghidra-decompiled media_server C with the Ifado MI API table and resolved strings.

Each `FUN_<addr>(` that is a known /dev/mi_* ioctl wrapper gets a comment with module, nr, struct
size, direction and the table's proposed name. Each `DAT_<addr>` that points to a C string gets
the string appended. Static only.

  scripts/annotate-mi-calls.py <elf> <analysis/ifado-mi-api-table.tsv> <inventory.tsv> \
      <devmap.tsv> <in.c> [<in.c> ...] > annotated.c

inventory.tsv / devmap.tsv are the IoctlInventory / IoctlDeviceMap outputs for the same <elf>,
so wrappers whose (nr,size,dir) repeat under several addresses are all labelled.
"""
import csv
import re
import struct
import sys


def elf_reader(path):
    b = open(path, "rb").read()
    phoff, = struct.unpack_from("<I", b, 0x1C)
    phes, phn = struct.unpack_from("<HH", b, 0x2A)
    loads = []
    for i in range(phn):
        t, off, va, _pa, fs, _ms, _fl, _al = struct.unpack_from("<8I", b, phoff + i * phes)
        if t == 1:
            loads.append((va, off, fs))

    def rd(va, n):
        for lv, lo, lf in loads:
            if lv <= va < lv + lf:
                return b[va - lv + lo:va - lv + lo + n]
        return None

    def cstr(va):
        d = rd(va, 160)
        if not d:
            return None
        s = d.split(b"\0")[0]
        return s.decode("latin1") if len(s) > 1 and all(32 <= c < 127 for c in s) else None

    return rd, cstr


def main() -> int:
    if len(sys.argv) < 6:
        print(__doc__)
        return 2
    elf, table, inv, devmap = sys.argv[1:5]
    rd, cstr = elf_reader(elf)
    names = {}
    for r in csv.DictReader((l for l in open(table) if not l.startswith("#")), delimiter="\t"):
        names[(r["module"], r["nr"], r["size"], r["dir"])] = r["name"]
    dev = {r["caller"]: r["path"] for r in csv.DictReader(open(devmap), delimiter="\t")}
    label = {}
    for r in csv.DictReader(open(inv), delimiter="\t"):
        if not r["request"].startswith("0x"):
            continue
        mod = dev.get(r["entry"], "")
        mod = mod[8:] if mod.startswith("/dev/mi_") else mod or "?"
        nm = names.get((mod, r["nr"], r["size"], r["dir"]), "")
        label.setdefault(r["entry"], []).append(f"{mod}:nr{r['nr']}/{r['size']}B/d{r['dir']} {nm}".strip())

    def fun(m):
        a = m.group(1)
        return f"FUN_{a}/*MI {'; '.join(label[a])}*/(" if a in label else m.group(0)

    def dat(m):
        w = rd(int(m.group(1), 16), 4)
        if not w:
            return m.group(0)
        s = cstr(struct.unpack("<I", w)[0])
        return f'{m.group(0)}/*"{s}"*/' if s else m.group(0)

    for path in sys.argv[5:]:
        src = open(path).read()
        src = re.sub(r"FUN_([0-9a-f]{8})\(", fun, src)
        src = re.sub(r"DAT_([0-9a-f]{8})", dat, src)
        sys.stdout.write(f"\n/* ===== {path} ===== */\n{src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
