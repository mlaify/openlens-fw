#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# flash-restore.sh — recovery: write a known-good FULL-CHIP golden image back.
# Use to un-brick. flashrom verifies after write by default.
set -euo pipefail
PROG="${PROG:-ch341a_spi}"
IMG="${1:?usage: flash-restore.sh <GOLDEN-full-chip.bin>}"
[ -f "$IMG" ] || { echo "ERROR: $IMG not found"; exit 1; }
command -v flashrom >/dev/null || { echo "ERROR: flashrom not installed"; exit 1; }

sz=$(stat -f%z "$IMG" 2>/dev/null || stat -c%s "$IMG")
echo "Image: $IMG ($sz bytes, sha256 $(shasum -a 256 "$IMG" | awk '{print $1}'))"
[ "$sz" = "16777216" ] || echo "WARNING: not 16 MiB — make sure this is a FULL-CHIP image, not a mapped-MTD dump."
echo ">> Probing ..."; flashrom -p "$PROG" --flash-name
read -r -p "Write this image to the chip (erases it)? type YES: " ans
[ "$ans" = "YES" ] || { echo "aborted"; exit 1; }
flashrom -p "$PROG" -w "$IMG"      # flashrom re-reads & verifies automatically
echo ">> Restore complete and verified."
