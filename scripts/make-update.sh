#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# make-update.sh: package and sign build/rootfs/rootfs.sqfs for camupdate (#104, docs/UPDATE-PATH.md).
# Owner's Mac; the signing key is one of the YubiKey resident keys (PIN + touch):
#
#   scripts/make-update.sh ~/.ssh/<your-key>            [--allow-downgrade]
#
# Output: build/update/<version>.camfw (header + SSH signature of the header + squashfs).
#
# A bench image (build-rootfs.sh --bench: the builder's credentials inside, #128) is refused before
# anything is signed: /etc/cam/bench in build/rootfs/root, "image: BENCH" in BUILD-INFO.txt, or
# any bytes after the squashfs's 4 KiB-padded end (where a bench rootfs.sqfs has its trailer).
# camupdate refuses the last on the camera too. Host test: src/camupdate/test.sh.
set -euo pipefail
KEY=${1:?usage: make-update.sh SIGNING-KEY [--allow-downgrade]}
DOWN=0
[ "${2:-}" = "--allow-downgrade" ] && DOWN=1
cd "$(dirname "$0")/.."
RD=build/rootfs
IMG=$RD/rootfs.sqfs
refuse() { echo "REFUSED: $1. A bench image carries the builder's credentials and is never flashed (#128): build a release image (scripts/build-rootfs.sh without --bench)."; exit 1; }
[ ! -e "$RD/root/etc/cam/bench" ] || refuse "$RD is a bench image (/etc/cam/bench)"
! grep -q '^image: BENCH' "$RD/BUILD-INFO.txt" 2>/dev/null || refuse "$RD/BUILD-INFO.txt says it is a bench image"
VER=$(cat "$RD/root/etc/cam/version")
DEV=$(cat "$RD/root/etc/cam/device")
[[ "$VER" =~ ^[0-9]{8}\.[0-9]{1,6}$ ]] || { echo "bad version in the image: $VER"; exit 1; }
[ "$(head -c 4 "$IMG")" = hsqs ] || { echo "$IMG is not a squashfs"; exit 1; }
SHA=$(shasum -a 256 "$IMG" | cut -d' ' -f1)
SIZE=$(wc -c < "$IMG" | tr -d ' ')
# the squashfs ends at its superblock's bytes_used (u64 LE at 40), padded to 4 KiB by mksquashfs
USED=$(od -An -t u8 -j 40 -N 8 "$IMG" | tr -d ' ')
[[ "$USED" =~ ^[0-9]+$ ]] && [ "$USED" -ge 96 ] && [ "$USED" -le "$SIZE" ] ||
	{ echo "$IMG: bad squashfs bytes_used ($USED)"; exit 1; }
PAD=$(( (USED + 4095) / 4096 * 4096 ))
if [ "$SIZE" -gt "$PAD" ]; then
	if tail -c +$((PAD + 1)) "$IMG" | LC_ALL=C grep -ac 'BENCH IMAGE' > /dev/null; then
		refuse "$IMG has the bench trailer"
	fi
	echo "$IMG has $((SIZE - PAD)) bytes after the squashfs: refused"; exit 1
fi
O=build/update && mkdir -p "$O"
H="$O/$VER.hdr"
printf '%s\n' magic=camfw1 "device=$DEV" part=rootfs "version=$VER" "size=$SIZE" "sha256=$SHA" \
	"allow-downgrade=$DOWN" > "$H"
printf '\n' >> "$H"
rm -f "$H.sig"
echo "signing $VER ($SIZE bytes) with $KEY: enter the PIN and touch the key"
ssh-keygen -Y sign -f "$KEY" -n cam-firmware "$H"
cat "$H" "$H.sig" "$IMG" > "$O/$VER.camfw"
rm -f "$H" "$H.sig"
echo "wrote $O/$VER.camfw"
echo "install: ssh root@CAMERA camupdate --check < $O/$VER.camfw && ssh root@CAMERA camupdate < $O/$VER.camfw"
