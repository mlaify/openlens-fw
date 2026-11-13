#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve Ghidra `DAT_xxxxxxxx` literals in a decompiled .c file to the strings they point to.

Stripped ARM binaries load string pointers from literal pools, so log messages show up in
Ghidra's output as `DebugPrint(..., DAT_000212e4, ...)`. This reads each DAT_ word from the ELF
and prints the C string it points to. That labels stages like "InitVenc" without touching the
binary. Static only.

  scripts/resolve-dat-strings.py <elf> <decompiled.c> [--so]

Ghidra keeps ET_EXEC addresses as-is; for shared objects (ET_DYN) it adds 0x10000, which
--so (or auto-detection of ET_DYN) subtracts.
"""
import re
import struct
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    elf, src = sys.argv[1], sys.argv[2]
    b = open(elf, "rb").read()
    e_type = struct.unpack_from("<H", b, 0x10)[0]
    bias = 0x10000 if ("--so" in sys.argv or e_type == 3) else 0
    phoff, = struct.unpack_from("<I", b, 0x1C)
    phes, phn = struct.unpack_from("<HH", b, 0x2A)
    loads = []
    for i in range(phn):
        t, off, va, _pa, fs, _ms, _fl, _al = struct.unpack_from("<8I", b, phoff + i * phes)
        if t == 1:
            loads.append((va, off, fs))

    def rd(va: int, n: int):
        for lv, lo, lf in loads:
            if lv <= va < lv + lf:
                return b[va - lv + lo:va - lv + lo + n]
        return None

    def cstr(va: int):
        d = rd(va, 256)
        if not d:
            return None
        s = d.split(b"\0")[0]
        return s.decode("latin1") if s and all(32 <= c < 127 or c in (9, 10) for c in s) else None

    for m in sorted(set(re.findall(r"DAT_([0-9a-f]{8})", open(src).read()))):
        w = rd(int(m, 16) - bias, 4)
        if not w:
            continue
        p, = struct.unpack("<I", w)
        s = cstr(p - bias)
        print(f"DAT_{m} -> {p:#x} : {s!r}" if s else f"DAT_{m} -> {p:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
