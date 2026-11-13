#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# backup-projects.sh: one verified archive of the camera projects (owner's Mac).
#
#   scripts/backup-projects.sh DEST_DIR SRC_DIR [SRC_DIR ...]
#   (for example: this repository and your research-notes folder)
#
# Writes DEST_DIR/camera-projects-<UTC stamp>.tar.zst and a .sha256 beside it.
#   - everything in the source folders: ignored files, bench logs, builds, worktrees, .git
#   - backup-meta/: a git bundle (--all) of every source that is a git repo, a SHA-256 of
#     every file, and RESTORE.txt
# The archive is NOT encrypted (owner's decision: it goes on encrypted drives). It holds firmware
# dumps and the unreported vulnerability report: store it only on encrypted media.
# Then it reads the archive back and checks it holds every file.
#
# Not included: the CH341A golden flash images on your offline disk. Keep those too.
set -euo pipefail
DEST=${1:?usage: backup-projects.sh DEST_DIR SRC_DIR [SRC_DIR ...]}
shift
SRCS=("$@")
[ ${#SRCS[@]} -gt 0 ] || { echo "usage: backup-projects.sh DEST_DIR SRC_DIR [SRC_DIR ...]"; exit 1; }
for t in zstd tar git shasum; do command -v "$t" >/dev/null || { echo "missing: $t"; exit 1; }; done
[ -d "$DEST" ] || { echo "$DEST is not a folder"; exit 1; }
DEST=$(cd "$DEST" && pwd -P)
for s in "${SRCS[@]}"; do
	[ -d "$s" ] || { echo "$s is not a folder"; exit 1; }
	s=$(cd "$s" && pwd -P)
	case "$DEST/" in "$s"/*) echo "DEST is inside $s: pick a folder outside it"; exit 1;; esac
done

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$DEST/camera-projects-$STAMP.tar.zst"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/backup.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
META="$STAGE/backup-meta"
mkdir -p "$META"

need=$(du -sk "${SRCS[@]}" | awk '{s += $1} END {print s}')
have=$(df -k "$DEST" | awk 'NR == 2 {print $4}')
[ "$have" -gt "$need" ] || { echo "not enough space in $DEST (${need} KiB of sources, ${have} KiB free)"; exit 1; }

for s in "${SRCS[@]}"; do
	name=$(basename "$s")
	if git -C "$s" rev-parse --verify -q HEAD >/dev/null 2>&1; then
		echo "== git bundle of $name (all branches and tags)"
		git -C "$s" bundle create "$META/$name.bundle" --all
		git -C "$s" bundle verify "$META/$name.bundle" >/dev/null
		git -C "$s" status --short > "$META/$name.git-status.txt"
		git -C "$s" worktree list > "$META/$name.worktrees.txt"
	fi
	echo "== SHA-256 of every file in $name"
	(cd "$(dirname "$s")" && find "$name" -type f -print0 | sort -z | xargs -0 shasum -a 256) \
		> "$META/$name.sha256"
done
cat > "$META/RESTORE.txt" <<EOF
Backup of: ${SRCS[*]}
Made: $STAMP (UTC) on $(hostname -s)

Restore:
  zstd -d -c camera-projects-$STAMP.tar.zst | tar -xf - -C /some/empty/folder
Check the files against the manifest (from inside that folder):
  shasum -a 256 -c backup-meta/<name>.sha256 | grep -v ': OK$'
A git repo can also be rebuilt from its bundle alone:
  git clone backup-meta/<name>.bundle <name>
EOF

export COPYFILE_DISABLE=1   # no macOS ._ metadata entries in the tar
echo "== archive and compress"
parents=()
for s in "${SRCS[@]}"; do parents+=(-C "$(dirname "$s")" "$(basename "$s")"); done
tar -cf - "${parents[@]}" -C "$STAGE" backup-meta | zstd -T0 -15 -q -o "$OUT"
(cd "$DEST" && shasum -a 256 "$(basename "$OUT")" > "$(basename "$OUT").sha256")

echo "== verify: read the archive back"
# regular files in the archive must be every file in the sources plus backup-meta's own files.
# tar -tv marks a file "-", or "h" when it is a hard link to a file stored earlier (stock rootfs
# trees have some: zoneinfo)
want=$(( $(cat "$META"/*.sha256 | wc -l) + $(find "$META" -type f | wc -l) ))
got=$(zstd -d -q -c "$OUT" | tar -tvf - | grep -c '^[-h]' || true)
if [ "$got" -ne "$want" ]; then
	echo "VERIFY FAILED: the archive holds $got files, expected $want. Don't rely on it."
	exit 1
fi
echo
echo "OK: $OUT"
echo "    $(du -h "$OUT" | cut -f1), $want files, $(cat "$OUT.sha256")"
echo "Copy the .tar.zst and .sha256 to each drive, and check each copy with: shasum -a 256 -c *.sha256"
