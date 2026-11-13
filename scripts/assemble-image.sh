#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# assemble-image.sh — build a full 16 MiB flash image from parts, for CH341A / region write.
# Layout matches stock mtdparts. BOOT and DATA are taken from your GOLDEN full-chip read
# (keeps stock U-Boot + per-unit MAC/cal); kernel and rootfs are new images.
#   ./assemble-image.sh <golden-fullchip.bin> <kernel.bin|-> <rootfs.bin> <out.bin>
# Kernel "-" keeps the golden's (stock) kernel: our route (#31) replaces only mtd2. Write the
# result with flash-write-region.sh rootfs <out.bin>, which touches nothing else.
set -euo pipefail
G="${1:?golden full-chip .bin}"; K="${2:?kernel uImage}"; R="${3:?rootfs}"; OUT="${4:?output}"
# KMAX = 0x1C0000: only the first 1.75 MiB of mtd1 is replaced; the trailing 256 KiB
# (three XZ blobs, one possibly the PM RTOS) is kept from the golden image. See docs/BOARD.md.
CHIP=$((0x1000000)); BOOT=$((0x40000)); KOFF=$((0x40000)); KMAX=$((0x1C0000))
ROFF=$((0x240000)); RMAX=$((0xCB0000)); DOFF=$((0xEF0000)); DLEN=$((0x100000))
gsz=$(stat -f%z "$G" 2>/dev/null || stat -c%s "$G")
[ "$gsz" = "$CHIP" ] || { echo "ERROR: golden must be a full 16 MiB chip image ($gsz != $CHIP)"; exit 1; }
if [ "$K" != "-" ]; then
	ksz=$(stat -f%z "$K" 2>/dev/null || stat -c%s "$K"); [ "$ksz" -le "$KMAX" ] || { echo "kernel too big"; exit 1; }
fi
# our rootfs must be a squashfs ("hsqs"); flash a release build only (BUILD-INFO.txt "image: release", #128)
head -c 4 "$R" | grep -q hsqs || { echo "ERROR: $R is not a squashfs image"; exit 1; }
rsz=$(stat -f%z "$R" 2>/dev/null || stat -c%s "$R"); [ "$rsz" -le "$RMAX" ] || { echo "rootfs too big"; exit 1; }
# start from the golden image (preserves BOOT + DATA + reserved), then overwrite kernel+rootfs regions
cp "$G" "$OUT"
# erase (0xFF) then write kernel region
python3 - "$OUT" "$K" "$R" <<'PY'
import sys
out,k,r=sys.argv[1],sys.argv[2],sys.argv[3]
KOFF,KMAX,ROFF,RMAX=0x40000,0x1C0000,0x240000,0xCB0000   # kernel region stops before mtd1's trailing blobs
b=bytearray(open(out,'rb').read())
rd=open(r,'rb').read()
if k != '-':
    kd=open(k,'rb').read()
    b[KOFF:KOFF+KMAX]=b'\xff'*KMAX; b[KOFF:KOFF+len(kd)]=kd
b[ROFF:ROFF+RMAX]=b'\xff'*RMAX; b[ROFF:ROFF+len(rd)]=rd
open(out,'wb').write(b)
print((f"kernel {len(kd)}B @0x{KOFF:x}, " if k != '-' else "kernel kept from golden, ") +
      f"rootfs {len(rd)}B @0x{ROFF:x}; BOOT+DATA preserved from golden")
PY
echo "wrote $OUT ($(stat -f%z "$OUT" 2>/dev/null || stat -c%s "$OUT") bytes)  sha256 $(shasum -a256 "$OUT"|awk '{print $1}')"
if [ "$K" = "-" ]; then
	echo "Flash with: scripts/flash-write-region.sh rootfs $OUT   (writes mtd2 only)"
else
	echo "Flash with: scripts/flash-write-region.sh kernel,rootfs $OUT"
fi
