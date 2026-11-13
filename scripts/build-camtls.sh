#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build-camtls.sh: mbedTLS 3.6 LTS for camtls, the camera's HTTPS front end (docs/PLAN-TLS.md §B),
# from Debian's signed source package (apt verifies the archive signature and the .dsc hashes),
# static ARMv7 Cortex-A7 hard-float, with our overlay src/camtls/mbedtls-user-config.h. Owner's
# terminal:
#
#   docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-camtls.sh
#
# Output (gitignored):
#   build/arm/mbedtls-VERSION.txt              the Debian source package version
#   build/mbedtls/arm/{include,lib}            the static libraries camtls links (src/camtls/)
#   build/mbedtls-src/                         the same checked source tree, for the host tests
#                                              (scripts/host-tests.sh builds it with clang)
#   build/arm/mbedtls-benchmark (+ .sha256)    mbedTLS's benchmark with our config: step 0 of the
#                                              plan measures ECDSA/ECDH/X25519 and ChaChaPoly/GCM
#                                              on the camera (copy to /tmp there, run, delete)
#   build/arm/camtls (+ .sha256)               once src/camtls/camtls.c exists
#   build/arm/camtls.cam-net                   the CAM_NET it was built for (build-rootfs.sh checks it)
# CAM_NET (required): the camera subnet, the CA's name constraint; -e CAM_NET=... or cam-net.local
# (scripts/cam-net.sh)
set -euo pipefail
. scripts/cam-net.sh
echo "CAM_NET: $CAM_NET"
export DEBIAN_FRONTEND=noninteractive
SRC=$PWD
OVL="$SRC/src/camtls/mbedtls-user-config.h"
[ -f "$OVL" ] || { echo "ERROR: no $OVL"; exit 1; }
# deb-src for every suite in the image's sources (incl. -security), Debian or Ubuntu deb822 files
for f in /etc/apt/sources.list.d/*.sources; do sed -i 's/^Types: deb$/Types: deb deb-src/' "$f"; done
apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
	binutils-arm-linux-gnueabihf make dpkg-dev file python3 >/dev/null
W=/tmp/mbedtls && rm -rf "$W" && mkdir -p "$W" && cd "$W"
apt-get source -qq mbedtls
D=$(find "$W" -maxdepth 1 -type d -name 'mbedtls-*' | head -1)
[ -n "$D" ] || { echo "ERROR: mbedtls source not unpacked"; exit 1; }
cd "$D"
VER=$(dpkg-parsechangelog -S Version)
UP=${VER#*:}; UP=${UP%%-*}; UP=${UP%%+*}
echo "mbedtls source package $VER"
# 3.6 is the LTS line our config and code are written for; 4.x is a different (PSA-only) API
dpkg --compare-versions "$UP" ge 3.6.0 && dpkg --compare-versions "$UP" lt 3.7 ||
	{ echo "ERROR: mbedtls $UP: camtls needs the 3.6 LTS line"; exit 1; }

# every name the overlay touches must be an option of this version's config (a typo would
# silently leave a feature on)
CFG=include/mbedtls/mbedtls_config.h
bad=$(grep -oE '^#(undef|define) MBEDTLS_[A-Z0-9_]+' "$OVL" | awk '{print $2}' | sort -u | while read -r n; do
	grep -qE "^(//)?#define $n\b" "$CFG" || echo "$n"; done)
[ -z "$bad" ] || { echo "ERROR: not options in mbedtls $UP: $bad"; exit 1; }

# the checked source, for the host tests
rm -rf "$SRC/build/mbedtls-src" && mkdir -p "$SRC/build" && cp -a "$D" "$SRC/build/mbedtls-src"
echo "$VER" > "$SRC/build/mbedtls-src/DEBIAN-VERSION.txt"

# ARM mode (-marm), not Thumb: bignum's inline assembly is written for it
ARMFLAGS="-O2 -mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard -marm"
cp "$OVL" "$D/camtls-user-config.h"
make -s -C library CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar \
	CFLAGS="$ARMFLAGS -DMBEDTLS_USER_CONFIG_FILE='\"$D/camtls-user-config.h\"'" \
	libmbedcrypto.a libmbedx509.a libmbedtls.a -j"$(nproc)"
O="$SRC/build/mbedtls/arm"
rm -rf "$O" && mkdir -p "$O/lib"
cp -a include "$O/include"
cp "$D/camtls-user-config.h" "$O/include/camtls-user-config.h"
cp library/libmbedcrypto.a library/libmbedx509.a library/libmbedtls.a "$O/lib/"
LIBS="$O/lib/libmbedtls.a $O/lib/libmbedx509.a $O/lib/libmbedcrypto.a"
CINC="-I$O/include -DMBEDTLS_USER_CONFIG_FILE=\"camtls-user-config.h\""

mkdir -p "$SRC/build/arm"
# shellcheck disable=SC2086
arm-linux-gnueabihf-gcc $ARMFLAGS -static $CINC -o "$SRC/build/arm/mbedtls-benchmark" \
	programs/test/benchmark.c $LIBS
arm-linux-gnueabihf-strip "$SRC/build/arm/mbedtls-benchmark"
if [ -f "$SRC/src/camtls/camtls.c" ]; then
	# shellcheck disable=SC2086
	arm-linux-gnueabihf-gcc -std=c11 $ARMFLAGS -Wall -Wextra -static $CINC $CAM_NET_CFLAGS -I"$SRC/src/rtspd" \
		-o "$SRC/build/arm/camtls" "$SRC/src/camtls/camtls.c" $LIBS
	arm-linux-gnueabihf-strip "$SRC/build/arm/camtls"
	echo "$CAM_NET" > "$SRC/build/arm/camtls.cam-net"
fi
echo "$VER" > "$SRC/build/arm/mbedtls-VERSION.txt"
cd "$SRC/build/arm"
for b in mbedtls-benchmark camtls; do
	[ -f "$b" ] || continue
	sha256sum "$b" > "$b.sha256"
	file "$b"
	ls -l "$b"
	cat "$b.sha256"
done
