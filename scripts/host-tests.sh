#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# host-tests.sh: every host test under ASan/UBSan, stopping on the first sanitizer report
# (Gate 3 §3.1, docs/GATE3-CRITERIA.md). No camera, no network port. camtls needs the mbedTLS source
# from scripts/build-camtls.sh (build/mbedtls-src) or MBEDTLS_SRC=path.
#   bash scripts/host-tests.sh [LOGDIR]      (needs clang, ffmpeg/ffprobe, libsodium, ssh-keygen)
# Each test's output goes to LOGDIR/<name>.log (default: a new directory in $TMPDIR); the summary
# is one PASS/FAIL line per test, and the exit status is the number of failures.
set -uo pipefail
cd "$(dirname "$0")/.."
L=${1:-$(mktemp -d "${TMPDIR:-/tmp}/host-tests.XXXXXX")}
mkdir -p "$L"
B=$(mktemp -d "${TMPDIR:-/tmp}/host-bin.XXXXXX")
CF=(-std=c11 -Wall -Wextra -g -fsanitize=address,undefined -fno-sanitize-recover=all)
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
# LeakSanitizer isn't supported on macOS/arm64; leave it to the platform default elsewhere
[ "$(uname -s)" = Darwin ] && export ASAN_OPTIONS=detect_leaks=0
fails=0
# CAM_NET for camcfg's tests is the RFC 5737 documentation net, whatever the builder's own is
CAM_NET=192.0.2.0/24
. scripts/cam-net.sh
run() { # run NAME CMD...
	local n=$1; shift
	if "$@" >"$L/$n.log" 2>&1; then echo "PASS $n"
	else echo "FAIL $n (exit $?, see $L/$n.log)"; tail -5 "$L/$n.log" | sed 's/^/    /'; fails=$((fails + 1)); fi
}
unit() { # unit NAME SOURCES/FLAGS... -- ARGS...
	local n=$1; shift
	local src=() args=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do src+=("$1"); shift; done
	[ $# -gt 0 ] && shift
	args=("$@")
	if clang "${CF[@]}" -o "$B/$n" "${src[@]}" >"$L/$n.build.log" 2>&1; then
		run "$n" "$B/$n" ${args[@]+"${args[@]}"}
	else echo "FAIL $n (build, see $L/$n.build.log)"; tail -5 "$L/$n.build.log" | sed 's/^/    /'; fails=$((fails + 1)); fi
}
# libsodium (Homebrew) for camcfg's backup and camupdate
SODIUM_CFLAGS=$(pkg-config --cflags libsodium 2>/dev/null || echo -I/opt/homebrew/include)
SODIUM_LIBS=$(pkg-config --libs libsodium 2>/dev/null || echo "-L/opt/homebrew/lib -lsodium")
# camhttpd's test drives a host build of the real camcfg too (its socket parts need unix-socket
# bind, which the agent sandbox refuses: they print "skip:" there; run this from a terminal)
if clang -std=c11 $CAM_NET_CFLAGS -Isrc/rtspd -Isrc/camupdate $SODIUM_CFLAGS -o "$B/camcfg-host" src/camcfg/camcfg.c src/rtspd/auth.c $SODIUM_LIBS \
	>"$L/camcfg-host.build.log" 2>&1
then export TEST_CAMCFG="$B/camcfg-host"
else echo "FAIL camcfg-host (build, see $L/camcfg-host.build.log)"; fails=$((fails + 1)); fi
unit camhttpd -Isrc/rtspd src/camhttpd/test_camhttpd.c src/rtspd/auth.c
unit camcfg $CAM_NET_CFLAGS -Isrc/rtspd -Isrc/camupdate $SODIUM_CFLAGS src/camcfg/test_camcfg.c src/rtspd/auth.c $SODIUM_LIBS
unit ntpc -Isrc/ntpc src/ntpc/test_ntpc.c
unit mi -Isrc/mi src/mi/test_mi.c -lm
unit osd -Isrc/mi src/mi/test_osd.c -lm
ffmpeg -loglevel error -y -f lavfi -i testsrc2=size=1280x720:rate=25 -t 4 -c:v libx265 \
	-bsf:v hevc_mp4toannexb -f hevc "$B/clip.h265" &&
ffmpeg -loglevel error -y -f lavfi -i testsrc2=size=640x360:rate=20 -t 4 -c:v libx264 -g 40 \
	-bsf:v h264_mp4toannexb -f h264 "$B/clip.h264" ||
	{ echo "FAIL rtspd (ffmpeg couldn't make the test clips)"; fails=$((fails + 1)); }
if [ -s "$B/clip.h265" ] && [ -s "$B/clip.h264" ]; then
	unit rtspd -Isrc/mi -Isrc/rtspd src/rtspd/test_rtspd.c src/rtspd/auth.c src/rtspd/daynight.c \
		src/rtspd/motion.c src/rtspd/audio.c src/mi/osd.c -lm -- "$B/clip.h265" "$B/out.h265" "$B/clip.h264"
	run rtspd-ffprobe ffprobe -v error -show_entries stream=codec_name,width,height "$B/out.h265"
fi
run camupdate bash src/camupdate/test.sh
# camtls: mbedTLS 3.6 from build/mbedtls-src (scripts/build-camtls.sh) or $MBEDTLS_SRC; without
# it this FAILs and says so (the host build is cached in $TMPDIR)
run camtls bash src/camtls/test.sh
for t in scripts/test_*.py; do run "$(basename "$t" .py)" python3 -I "$t"; done
run scan-credentials bash scripts/test-scan-credentials.sh
echo "$fails failed; logs in $L"
exit "$fails"
