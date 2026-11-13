#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""extract-kernel-dtb.py — unpack the stock kernel partition (mtd1) for board analysis.

Reproduces the extraction behind docs/BOARD.md:
  * parses the legacy uImage header (and reports that the "LZMA" payload is really XZ),
  * XZ-decompresses the kernel payload to the raw ARM Image,
  * finds every structurally valid flattened device tree (D0 0D FE ED) in the kernel,
  * finds and decompresses any extra XZ streams stored after the kernel in the partition,
  * optionally decompiles the DTB(s) to .dts with `dtc` if it is installed.

Static analysis only. Outputs are vendor-derived — keep them out of git (write them under
vendor-blobs/ or $TMPDIR, both ignored/ephemeral).

  python3 scripts/extract-kernel-dtb.py vendor-blobs/kernel/mtd1-kernel.bin "$TMPDIR/boardmap"
"""
import lzma
import os
import shutil
import struct
import subprocess
import sys

UIMAGE_MAGIC = 0x27051956
XZ_MAGIC = b"\xfd7zXZ\x00"
DTB_MAGIC = b"\xd0\x0d\xfe\xed"
COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def xz_decompress(buf):
    """Decompress one XZ stream; tolerate trailing padding after the stream."""
    d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    return d.decompress(buf), len(buf) - len(d.unused_data)


def find_dtbs(buf):
    out, i = [], buf.find(DTB_MAGIC)
    while i != -1:
        if i + 28 <= len(buf):
            total, off_struct, off_strings, _, version, _ = struct.unpack(">6I", buf[i + 4:i + 28])
            if (0x200 < total < 0x80000 and version in (16, 17) and off_struct < total
                    and off_strings < total and i + total <= len(buf)):
                out.append((i, total, version))
        i = buf.find(DTB_MAGIC, i + 1)
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    raw = open(src, "rb").read()

    magic, _hcrc, _t, size, load, entry = struct.unpack(">6I", raw[:24])
    if magic != UIMAGE_MAGIC:
        sys.exit(f"not a legacy uImage (magic 0x{magic:08x})")
    arch, itype, comp = raw[29], raw[30], raw[31]
    payload = raw[64:64 + size]
    real = "XZ" if payload.startswith(XZ_MAGIC) else "other"
    print(f"uImage: size={size} load=0x{load:08x} entry=0x{entry:08x} arch={arch} type={itype} "
          f"header-comp={COMP.get(comp, comp)} actual-payload={real}")
    if comp == 3 and real == "XZ":
        print("  NOTE: header says LZMA but payload is XZ — package new kernels the same way")

    kernel, _ = xz_decompress(payload)
    kpath = os.path.join(outdir, "kernel.bin")
    open(kpath, "wb").write(kernel)
    banner = kernel.find(b"Linux version")
    if banner != -1:
        print("  " + kernel[banner:banner + 120].split(b"\0")[0].decode("latin1", "replace"))
    print(f"kernel Image: {len(kernel)} bytes -> {kpath}")

    dtbs = find_dtbs(kernel)
    for n, (off, total, ver) in enumerate(dtbs):
        dpath = os.path.join(outdir, f"board{n}.dtb")
        open(dpath, "wb").write(kernel[off:off + total])
        print(f"DTB @ kernel+0x{off:x}: {total} bytes, v{ver} -> {dpath}")
        if shutil.which("dtc"):
            dts = dpath[:-4] + ".dts"
            subprocess.run(["dtc", "-I", "dtb", "-O", "dts", "-o", dts, dpath],
                           stderr=subprocess.DEVNULL, check=False)
            if os.path.exists(dts):
                model = next((l.strip() for l in open(dts) if l.strip().startswith("model =")), "")
                print(f"  -> {dts}  {model}")
    if not dtbs:
        print("no structurally valid DTB found inside the kernel")

    # extra XZ streams after the kernel payload (stock mtd1 carries two)
    pos, n = 64 + size, 0
    while True:
        i = raw.find(XZ_MAGIC, pos)
        if i == -1:
            break
        try:
            data, used = xz_decompress(raw[i:])
        except lzma.LZMAError:
            pos = i + 1
            continue
        bpath = os.path.join(outdir, f"trailing{n}.bin")
        open(bpath, "wb").write(data)
        tag = data[:4].decode("latin1", "replace") if data[:4].isascii() else data[:4].hex()
        print(f"trailing XZ @ mtd1+0x{i:x}: {used} B -> {len(data)} B, head '{tag}' -> {bpath}")
        pos, n = i + used, n + 1
    first_blob = raw.find(XZ_MAGIC, 64 + size)
    if first_blob != -1:
        budget = first_blob & ~0xFFFF  # stay below the 64 KiB erase block holding the first blob
        print(f"kernel budget that preserves trailing blobs: <= 0x{budget:x} bytes")


if __name__ == "__main__":
    main()
