#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# flash-backup.sh — Gate 1: take a verified full-chip golden backup via CH341A.
# Reads the whole 16 MiB SPI-NOR TWICE and compares; identical reads => trustworthy
# golden image. Run on the OWNER's expendable spare at the bench. Never writes.
#
# HARDWARE: CH341A + SOIC-8 clip on the PUYA P25Q128. **3.3 V** — confirm before clipping.
# Power the board OFF (clip provides power) OR follow your clip's in-circuit notes.
set -euo pipefail

PROG="${PROG:-ch341a_spi}"           # flashrom programmer
OUT="${1:-golden}"                    # output basename
STAMP="$(date +%Y%m%d-%H%M%S)"
DIR="golden/${OUT}-${STAMP}"
mkdir -p "$DIR"

command -v flashrom >/dev/null || { echo "ERROR: flashrom not installed (brew install flashrom)"; exit 1; }

echo ">> Probing chip on programmer '$PROG' ..."
flashrom -p "$PROG" --flash-name || { echo "ERROR: chip not detected. Check clip seating, orientation (pin 1), 3.3V."; exit 1; }

echo ">> Read #1 ..."; flashrom -p "$PROG" -r "$DIR/read1.bin"
echo ">> Read #2 ..."; flashrom -p "$PROG" -r "$DIR/read2.bin"

h1=$(shasum -a 256 "$DIR/read1.bin" | awk '{print $1}')
h2=$(shasum -a 256 "$DIR/read2.bin" | awk '{print $1}')
echo "read1 $h1"
echo "read2 $h2"
if [ "$h1" != "$h2" ]; then
  echo "!! MISMATCH — reads differ. Do NOT trust this backup. Reseat the clip and retry."
  exit 2
fi
cp "$DIR/read1.bin" "$DIR/GOLDEN-${OUT}-${STAMP}.bin"
sz=$(stat -f%z "$DIR/GOLDEN-${OUT}-${STAMP}.bin" 2>/dev/null || stat -c%s "$DIR/GOLDEN-${OUT}-${STAMP}.bin")
echo ">> GOLDEN OK: $DIR/GOLDEN-${OUT}-${STAMP}.bin  ($sz bytes, sha256 $h1)"
echo "   Expect 16777216 bytes (16 MiB) for a full-chip P25Q128 read."
echo "   COPY THIS FILE TO YOUR OFFLINE ENCRYPTED DRIVE before doing anything else."
