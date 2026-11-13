#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build-dropbear.sh: static Dropbear SSH server for the camera (#76), ARMv7 Cortex-A7 hard-float,
# from a Debian or Ubuntu signed source package (apt verifies the archive signature and the .dsc
# hashes). Server + dropbearkey only, options in rootfs/dropbear/localoptions.h. Owner's terminal:
#
#   docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-dropbear.sh
#
# The container picks the Dropbear version. Gate 3 needs 2025.87 or later: a post-quantum hybrid key
# exchange (mlkem768x25519-sha256, sntrup761x25519-sha512) and upstream strict kex (Terrapin).
# Ubuntu 24.04 ships 2022.83 (Terrapin backported, no post-quantum kex): the option check below
# stops it. If the container's version is too old, try a newer one (debian:testing, ubuntu:25.10).
#
# Output (gitignored): build/arm/dropbearmulti (+ .sha256) and build/arm/dropbear-VERSION.txt.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
SRC=$PWD
# deb-src for every suite in the image's sources (incl. -security), Debian or Ubuntu deb822 files
for f in /etc/apt/sources.list.d/*.sources; do sed -i 's/^Types: deb$/Types: deb deb-src/' "$f"; done
apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
	binutils-arm-linux-gnueabihf make dpkg-dev file >/dev/null
W=/tmp/dropbear && rm -rf "$W" && mkdir -p "$W" && cd "$W"
apt-get source -qq dropbear
D=$(find "$W" -maxdepth 1 -type d -name 'dropbear-*' | head -1)
[ -n "$D" ] || { echo "ERROR: dropbear source not unpacked"; exit 1; }
cd "$D"
VER=$(dpkg-parsechangelog -S Version)
echo "dropbear source package $VER"
UP=${VER#*:}; UP=${UP%%-*}
# Terrapin (CVE-2023-48795): strict key exchange, upstream since 2024.84 (or a distro backport)
dpkg --compare-versions "$UP" ge 2024.84 || grep -q 'CVE-2023-48795' debian/changelog ||
	{ echo "ERROR: $VER has no CVE-2023-48795 (Terrapin) fix"; exit 1; }
# post-quantum kex (Gate 3): localoptions.h turns on DROPBEAR_MLKEM768 and DROPBEAR_SNTRUP761, so
# the option check below refuses an older Dropbear; say why first
dpkg --compare-versions "$UP" ge 2025.87 ||
	{ echo "ERROR: Dropbear $UP has no mlkem768x25519 key exchange (2025.87+): use a newer container"; exit 1; }

# Dropbear 2024.84+ keeps its sources in src/; older trees at the top. localoptions.h goes next to
# default_options.h (options.h includes it from there), and at the top for older build files.
DEF=$(find . -maxdepth 2 -name default_options.h | head -1)
[ -n "$DEF" ] || { echo "ERROR: no default_options.h in $D"; exit 1; }
cp "$SRC/rootfs/dropbear/localoptions.h" "$(dirname "$DEF")/localoptions.h"
[ "$(dirname "$DEF")" = . ] || cp "$SRC/rootfs/dropbear/localoptions.h" localoptions.h
bad=$(grep -oE '^#define [A-Z0-9_]+' localoptions.h | cut -d' ' -f2 | while read -r n; do
	grep -qE "^#define $n\b" "$DEF" || echo "$n"; done)
[ -z "$bad" ] || { echo "ERROR: not options in this Dropbear version: $bad"; exit 1; }

./configure -q --host=arm-linux-gnueabihf --enable-static --enable-bundled-libtom \
	--disable-zlib --disable-pam --disable-lastlog --disable-utmp --disable-utmpx \
	--disable-wtmp --disable-wtmpx --disable-loginfunc --disable-pututline --disable-pututxline \
	CC=arm-linux-gnueabihf-gcc \
	CFLAGS="-O2 -mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard -mthumb"
make -s -j"$(nproc)" PROGRAMS="dropbear dropbearkey" MULTI=1 STATIC=1
arm-linux-gnueabihf-strip dropbearmulti
mkdir -p "$SRC/build/arm"
install -m 0755 dropbearmulti "$SRC/build/arm/dropbearmulti"
cd "$SRC/build/arm"
sha256sum dropbearmulti > dropbearmulti.sha256
echo "$VER" > dropbear-VERSION.txt
file dropbearmulti
ls -l dropbearmulti
cat dropbearmulti.sha256
