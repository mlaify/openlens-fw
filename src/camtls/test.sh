#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host test of camtls (docs/PLAN-TLS.md §B, D) under ASan/UBSan: mbedTLS 3.6 from the checked
# Debian source that scripts/build-camtls.sh leaves in build/mbedtls-src (or $MBEDTLS_SRC), built
# here with clang and our overlay config, then cached in $TMPDIR by source version, overlay and
# compiler (a later run takes a few seconds). Not Homebrew's mbedtls: that is 4.x, another API.
#   bash src/camtls/test.sh            (needs clang, make, python3 with ssl, openssl)
# Runs test_camtls (in-process: handshakes, relay, limits, back-pressure, RTSPS) and
# test_camtls.py (Python's ssl/OpenSSL against a camtls test server on socketpairs, the
# certificates and their name constraints, the check helper).
set -euo pipefail
cd "$(dirname "$0")/../.."
# CAM_NET for the tests is the RFC 5737 documentation net, whatever the builder's own is
CAM_NET=192.0.2.0/24
. scripts/cam-net.sh
MS=${MBEDTLS_SRC:-build/mbedtls-src}
if [ ! -f "$MS/include/mbedtls/ssl.h" ] || [ ! -f "$MS/library/Makefile" ]; then
	echo "no mbedTLS source at $MS: run scripts/build-camtls.sh once (see its header; it leaves"
	echo "the checked Debian source in build/mbedtls-src), or set MBEDTLS_SRC to such a tree"
	exit 1
fi
grep -q '#define MBEDTLS_VERSION_STRING  *"3\.6\.' "$MS/include/mbedtls/build_info.h" ||
	{ echo "$MS is not mbedTLS 3.6 (camtls is written for the 3.6 LTS API)"; exit 1; }
OVL=src/camtls/mbedtls-user-config.h
TAG=$( { cat "$MS/DEBIAN-VERSION.txt" 2>/dev/null || grep MBEDTLS_VERSION_STRING "$MS/include/mbedtls/build_info.h"
	cat "$OVL"; clang --version | head -1; echo asan-ubsan-1; } | shasum -a 256 | cut -c1-16)
C=${TMPDIR:-/tmp}/camtls-mbedtls-$TAG
if [ ! -f "$C/built" ]; then
	echo "building mbedTLS for the host test into $C (once)"
	rm -rf "$C" "$C.tmp.$$"
	cp -R "$MS" "$C.tmp.$$"
	mv "$C.tmp.$$" "$C"
	cp "$OVL" "$C/camtls-user-config.h"
	# ranlib's "couldn't create cache file" on macOS is harmless
	make -s -C "$C/library" CC=clang AR=ar -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" \
		CFLAGS="-O1 -g -fsanitize=address,undefined -DMBEDTLS_USER_CONFIG_FILE='\"$C/camtls-user-config.h\"'" \
		libmbedcrypto.a libmbedx509.a libmbedtls.a 2>&1 | grep -v -e 'has no symbols' -e 'cache file' || true
	[ -f "$C/library/libmbedtls.a" ] || { echo "mbedTLS host build failed"; exit 1; }
	touch "$C/built"
fi
T=$(mktemp -d "${TMPDIR:-/tmp}/camtls-test.XXXXXX")
export UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}
[ "$(uname -s)" = Darwin ] && export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0}
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -fno-sanitize-recover=all \
	-I"$C/include" -DMBEDTLS_USER_CONFIG_FILE="\"$C/camtls-user-config.h\"" -Isrc/rtspd $CAM_NET_CFLAGS \
	-o "$T/test_camtls" src/camtls/test_camtls.c \
	"$C/library/libmbedtls.a" "$C/library/libmbedx509.a" "$C/library/libmbedcrypto.a"
echo "== test_camtls (in-process)"
"$T/test_camtls" 2>"$T/camtls.log" || { tail -20 "$T/camtls.log"; exit 1; }
echo "== test_camtls.py (Python ssl / OpenSSL interop)"
python3 -I src/camtls/test_camtls.py "$T/test_camtls" "$T"
