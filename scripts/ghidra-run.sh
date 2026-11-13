#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ghidra-run.sh — run one of tools/ghidra/*.java headlessly against a binary.
# Handles the Claude Code / macOS sandbox requirements (Java temp dir + IPv4) and uses a
# throwaway project under $TMPDIR. Static analysis only — nothing is executed.
#
#   scripts/ghidra-run.sh <binary> <Script.java> [script args...]
#   e.g. scripts/ghidra-run.sh rootfs/opt/ch/libtools.so DecompileByName.java "$TMPDIR/out.c" SetIrcut gpio_init
set -euo pipefail
BIN="${1:?usage: ghidra-run.sh <binary> <Script.java> [args...]}"; SCRIPT="${2:?missing script}"; shift 2
HERE="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA="${GHIDRA_HEADLESS:-/usr/local/bin/analyzeHeadless}"
TMP="${TMPDIR:-/tmp}"
[ -x "$GHIDRA" ] || { echo "ERROR: analyzeHeadless not found (set GHIDRA_HEADLESS)"; exit 1; }
[ -f "$BIN" ] || { echo "ERROR: binary not found: $BIN"; exit 1; }
[ -f "$HERE/tools/ghidra/$SCRIPT" ] || { echo "ERROR: no such script tools/ghidra/$SCRIPT"; exit 1; }

export JAVA_TOOL_OPTIONS="-Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=$TMP"
PROJ="$(mktemp -d "$TMP/ghidra-proj.XXXXXX")"
LOG="$PROJ.log"
echo ">> $SCRIPT on $(basename "$BIN") (log: $LOG)"
"$GHIDRA" "$PROJ" p -import "$BIN" -processor ARM:LE:32:v8 \
  -scriptPath "$HERE/tools/ghidra" -postScript "$SCRIPT" "$@" -deleteProject > "$LOG" 2>&1 || {
  echo "ERROR: Ghidra failed — tail of log:"; tail -20 "$LOG"; exit 1; }
grep -E 'Wrote|SCRIPT ERROR' "$LOG" | tail -3 || true
rmdir "$PROJ" 2>/dev/null || true
