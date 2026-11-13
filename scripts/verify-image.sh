#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# verify-image.sh — pre-flash sanity check for an OpenIPC kernel uImage + rootfs.
# Confirms the uImage header matches what the STOCK U-Boot expects (bootm by_header)
# and that both images fit the stock partitions. Does NOT write anything.
#   ./verify-image.sh openipc-kernel.bin openipc-rootfs.bin
set -euo pipefail
K="${1:?usage: verify-image.sh <kernel-uImage> <rootfs-squashfs>}"
R="${2:?missing rootfs image}"
# Kernel budget is 0x1C0000, not the full 2 MiB mtd1: the last 256 KiB of mtd1 holds three
# XZ blobs (one may be the PM RTOS) that must not be erased. See docs/BOARD.md.
KMAX=$((0x1C0000)); RMAX=$((0xCB0000))
WANT_LOAD="0x20008000"; WANT_EP="0x20008000"
fail=0

echo "== kernel: $K =="
ksz=$(stat -f%z "$K" 2>/dev/null || stat -c%s "$K")
# parse uImage header with python (big-endian)
read -r magic size load ep arch typ comp <<<"$(python3 - "$K" <<'PY'
import struct,sys
d=open(sys.argv[1],'rb').read(32)
m,h,t,sz,ld,ep,dc=struct.unpack('>7I',d[:28]); os,ar,ty,co=d[28],d[29],d[30],d[31]
print(f"0x{m:08x} {sz} 0x{ld:08x} 0x{ep:08x} {ar} {ty} {co}")
PY
)"
echo "  magic=$magic size=$size load=$load entry=$ep arch=$arch type=$typ comp=$comp"
[ "$magic" = "0x27051956" ] || { echo "  !! not a legacy uImage (need mkimage-wrapped)"; fail=1; }
[ "$load" = "$WANT_LOAD" ]  || { echo "  !! load addr $load != stock $WANT_LOAD"; fail=1; }
[ "$ep" = "$WANT_EP" ]      || { echo "  !! entry $ep != stock $WANT_EP"; fail=1; }
[ "$arch" = "2" ]           || { echo "  !! arch=$arch (want 2=ARM)"; fail=1; }
[ "$typ" = "2" ]            || { echo "  !! type=$typ (want 2=kernel)"; fail=1; }
# Payload type: stock = header comp 3 (lzma) carrying an XZ stream; fallback = comp 0 + zImage.
pmagic=$(dd if="$K" bs=1 skip=64 count=6 2>/dev/null | xxd -p)
zmagic=$(dd if="$K" bs=1 skip=$((64+0x24)) count=4 2>/dev/null | xxd -p)
if [ "$comp" = "3" ]; then
  [ "$pmagic" = "fd377a585a00" ] && echo "  payload: XZ under lzma label (matches stock)" \
    || { echo "  !! comp=3 but payload is not XZ (got $pmagic) — stock bootloader expects XZ"; fail=1; }
elif [ "$comp" = "0" ]; then
  [ "$zmagic" = "18286f01" ] && echo "  payload: uncompressed zImage (fallback option B)" \
    || echo "  ~ comp=none but no zImage magic at +0x24 (got $zmagic) — confirm payload"
else
  echo "  ~ comp=$comp (stock is 3 with XZ payload; untested with this bootloader)"
fi
[ "$ksz" -le "$KMAX" ]      || { echo "  !! file $ksz > kernel budget $KMAX (1.75 MiB; protects trailing mtd1 blobs)"; fail=1; }
echo "  file size $ksz / $KMAX bytes"

echo "== rootfs: $R =="
rsz=$(stat -f%z "$R" 2>/dev/null || stat -c%s "$R")
magicR=$(head -c4 "$R" | xxd -p)
[ "$magicR" = "68737173" ] || echo "  ~ not 'hsqs' squashfs magic (got $magicR) — confirm fs type"
[ "$rsz" -le "$RMAX" ]     || { echo "  !! file $rsz > mtd2 $RMAX (13 MiB)"; fail=1; }
echo "  file size $rsz / $RMAX bytes"

# These are format and size checks only. They don't prove the image boots on this camera, suits
# its SoC (docs/IFADO-PLATFORM.md), or that a tested restore exists (RESUME.md section 3).
echo; [ "$fail" = 0 ] && echo "PASS (format and size only): not a boot, SoC-compatibility or recovery check." || { echo "FAIL — fix the above before flashing."; exit 1; }
