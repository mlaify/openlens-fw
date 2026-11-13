#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build.sh: cross-compile the camera userland tools (ARMv7 Cortex-A7, hard-float, static) into
# build/arm/ (gitignored). Runs inside an Ubuntu container with Ubuntu's signed
# gcc-arm-linux-gnueabihf (armhf = ARMv7-A, Thumb-2). From the owner's terminal on the Mac:
#
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
#
# Output: build/arm/{mi-probe,rtspd,iq-dump,camcfg,ae-watch,camhttpd,ntpc,camupdate} + .sha256 files,
# and build/arm/osd-font.copyright (the OSD font's licence, to ship with an image).
# FWVER (default "dev"; [A-Za-z0-9._+-]) is camhttpd's ONVIF FirmwareVersion: -e FWVER=0.1.0
# CAM_NET (required): the camera subnet camcfg accepts for a static address, from -e CAM_NET=...
# or cam-net.local (scripts/cam-net.sh); recorded in build/arm/camcfg.cam-net for build-rootfs.sh
set -euo pipefail
. scripts/cam-net.sh
echo "CAM_NET: $CAM_NET"
export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture armhf                  # libsodium-dev:armhf (static): camupdate, camcfg
apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc-arm-linux-gnueabihf libc6-dev-armhf-cross file \
	libsodium-dev:armhf >/dev/null
CC=arm-linux-gnueabihf-gcc
CFLAGS="-std=c11 -O2 -Wall -Wextra -static -mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard -mthumb -Isrc/mi"
mkdir -p build/arm
# OSD font (src/mi/osd.c): Terminus Font 8x16 from Ubuntu's console-setup-linux, converted to
# build/gen/osd_font.h (never committed). The package's copyright file must give Terminus the
# SIL Open Font License 1.1, else the build stops (THIRD-PARTY-NOTICES.md); it is kept next to
# the binaries as build/arm/osd-font.copyright, to ship with an image.
rm -rf build/font build/gen && mkdir -p build/font/x build/gen
(cd build/font && apt-get download -qq console-setup-linux)
FONT_DEB=$(ls build/font/console-setup-linux_*_all.deb)
dpkg-deb -x "$FONT_DEB" build/font/x
# Its doc directory is a symlink to keyboard-configuration's (same source package, exact version
# in Depends), so the copyright file comes from that package.
FONT_COPYRIGHT=build/font/x/usr/share/doc/console-setup-linux/copyright
if [ ! -f "$FONT_COPYRIGHT" ]; then
	KC_VER=$(dpkg-deb -f "$FONT_DEB" Depends | tr ',' '\n' | sed -n 's/^ *keyboard-configuration (= \(.*\))$/\1/p')
	[ -n "$KC_VER" ] || { echo "ERROR: $FONT_DEB: no copyright file and no keyboard-configuration (= version)" >&2; exit 1; }
	(cd build/font && apt-get download -qq "keyboard-configuration=$KC_VER")
	mkdir -p build/font/kc
	dpkg-deb -x build/font/keyboard-configuration_*_all.deb build/font/kc
	FONT_COPYRIGHT=build/font/kc/usr/share/doc/keyboard-configuration/copyright
fi
[ -f "$FONT_COPYRIGHT" ] || { echo "ERROR: no copyright file for $FONT_DEB" >&2; exit 1; }
# The fonts' licences are in copyright.fonts.gz next to it, one "== <BDF files>" section per font.
# The section for Terminus's 8x16 sources (ter-u16*) must give the SIL OFL 1.1.
FONT_TXT=build/font/copyright.fonts
gzip -dc "$(dirname "$FONT_COPYRIGHT")/copyright.fonts.gz" > "$FONT_TXT" 2>/dev/null ||
	{ echo "ERROR: no copyright.fonts.gz next to $FONT_COPYRIGHT" >&2; exit 1; }
FONT_LIC=$(awk '/^== / { if (sec ~ /ter-u16/) printf "%s", sec; sec = "" } { sec = sec $0 "\n" }
	END { if (sec ~ /ter-u16/) printf "%s", sec }' "$FONT_TXT")
if ! grep -q "Terminus Font is licensed under the SIL Open Font License, Version 1.1" <<<"$FONT_LIC" ||
   ! grep -q "SIL OPEN FONT LICENSE Version 1.1" <<<"$FONT_LIC"; then
	echo "ERROR: $FONT_TXT doesn't license Terminus under the SIL OFL 1.1; check it and" \
	     "THIRD-PARTY-NOTICES.md before using this font:" >&2
	printf '%s\n' "$FONT_LIC" | head -20 >&2
	exit 1
fi
FONT_PSF=""
for f in Lat15-TerminusBold16 Uni2-TerminusBold16 Lat15-Terminus16 Uni2-Terminus16; do
	[ -f "build/font/x/usr/share/consolefonts/$f.psf.gz" ] && { FONT_PSF=build/font/x/usr/share/consolefonts/$f.psf.gz; break; }
done
[ -n "$FONT_PSF" ] || { echo "ERROR: no 8x16 Terminus font in $FONT_DEB" >&2; exit 1; }
FONT_VER=$(dpkg-deb -f "$FONT_DEB" Version)
bash scripts/psf2c.sh "$FONT_PSF" "osd 8x16, from Terminus Font (OFL-1.1), console-setup-linux $FONT_VER" \
	> build/gen/osd_font.h
cat "$FONT_COPYRIGHT" - "$FONT_TXT" > build/arm/osd-font.copyright <<<"--- copyright.fonts (Terminus Font: SIL OFL 1.1, full text below) ---"
echo "OSD font: ${FONT_PSF##*/} from $(basename "$FONT_DEB")"
$CC $CFLAGS -o build/arm/mi-probe tools/mi-probe/mi-probe.c src/mi/mi.c -lm
$CC $CFLAGS -Ibuild/gen '-DOSD_FONT_H="osd_font.h"' -o build/arm/rtspd src/rtspd/rtspd.c src/rtspd/auth.c \
	src/rtspd/daynight.c src/rtspd/motion.c src/rtspd/audio.c src/mi/mi.c src/mi/osd.c -lm
$CC $CFLAGS -Itools/iq-dump -o build/arm/iq-dump tools/iq-dump/iq-dump.c src/mi/mi.c -lm
# camupdate and camcfg (its settings backup, #171): libsodium from Ubuntu's signed package (static
# armhf); only its headers are copied aside so the cross compiler never sees the host's /usr/include
rm -rf build/sodium-inc && mkdir -p build/sodium-inc && cp -r /usr/include/sodium.h /usr/include/sodium build/sodium-inc/
$CC $CFLAGS $CAM_NET_CFLAGS -Isrc/rtspd -Isrc/camupdate -Ibuild/sodium-inc -o build/arm/camcfg src/camcfg/camcfg.c src/rtspd/auth.c \
	/usr/lib/arm-linux-gnueabihf/libsodium.a
echo "$CAM_NET" > build/arm/camcfg.cam-net
$CC $CFLAGS -o build/arm/ae-watch tools/ae-watch/ae-watch.c src/mi/mi.c -lm
FWVER=${FWVER:-dev}
[[ "$FWVER" =~ ^[A-Za-z0-9._+-]{1,32}$ ]] || { echo "bad FWVER" >&2; exit 1; }
# camhttpd refuses WS-UsernameToken while the clock is before the image's build time (no RTC)
EPOCH=$(cat rootfs/SOURCE_DATE_EPOCH)
[[ "$EPOCH" =~ ^[0-9]{9,11}$ ]] || { echo "bad rootfs/SOURCE_DATE_EPOCH" >&2; exit 1; }
$CC $CFLAGS -Isrc/rtspd -DFW_VERSION="\"$FWVER\"" -DBUILD_EPOCH=${EPOCH}LL -o build/arm/camhttpd \
  src/camhttpd/camhttpd.c src/rtspd/auth.c
$CC $CFLAGS -DBUILD_EPOCH=${EPOCH}LL -o build/arm/ntpc src/ntpc/ntpc.c
# camupdate: Ed25519/SHA-512 from libsodium (headers in build/sodium-inc, above)
$CC $CFLAGS -Ibuild/sodium-inc -o build/arm/camupdate src/camupdate/camupdate.c \
	/usr/lib/arm-linux-gnueabihf/libsodium.a
for b in mi-probe rtspd iq-dump camcfg ae-watch camhttpd ntpc camupdate; do
  arm-linux-gnueabihf-strip build/arm/$b
  file build/arm/$b
  (cd build/arm && sha256sum $b | tee $b.sha256)
done
