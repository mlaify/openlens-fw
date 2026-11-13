#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# flash-write-region.sh — write ONLY selected region(s), preserving the rest.
# Preserves BOOT (IPL+U-Boot) and DATA (per-unit MAC/cal) while swapping kernel/rootfs.
# The <image> must be a FULL 16 MiB image whose selected region holds your new content
# (build it from the golden + your new kernel/rootfs at the right offsets).
#
#   ./flash-write-region.sh kernel  new-fullchip.bin
#   ./flash-write-region.sh rootfs  new-fullchip.bin
#   ./flash-write-region.sh kernel,rootfs new-fullchip.bin
# NEVER write BOOT or DATA unless you deliberately mean to.
set -euo pipefail
PROG="${PROG:-ch341a_spi}"
REGIONS="${1:?usage: flash-write-region.sh <region[,region...]> <full-chip.bin>}"
IMG="${2:?missing full-chip image}"
LAYOUT="$(dirname "$0")/flash-layout.txt"
[ -f "$IMG" ] || { echo "ERROR: $IMG not found"; exit 1; }
[ -f "$LAYOUT" ] || { echo "ERROR: flash-layout.txt not found next to this script"; exit 1; }
case "$REGIONS" in *BOOT*|*DATA*) echo "REFUSING: writing BOOT or DATA is high-risk; do it manually if you truly mean to."; exit 3;; esac

IFLAGS=(); IFS=',' read -ra R <<< "$REGIONS"; for r in "${R[@]}"; do IFLAGS+=(-i "$r"); done
echo ">> Probing ..."; flashrom -p "$PROG" --flash-name
echo ">> Writing region(s): $REGIONS  from $IMG"
read -r -p "Proceed? type YES: " ans; [ "$ans" = "YES" ] || { echo aborted; exit 1; }
flashrom -p "$PROG" -l "$LAYOUT" "${IFLAGS[@]}" -w "$IMG"
echo ">> Region write complete and verified."
