#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host test of camupdate --check (#104): a throwaway ed25519 key signs packages with
# `ssh-keygen -Y sign`; valid, tampered and wrong packages are checked. sk-key vectors from the
# owner's YubiKeys go in src/camupdate/testdata/ (public data only) once they exist.
# Bench images (#128): camupdate refuses a payload with the bench trailer (or anything else) after
# the squashfs's padded end, and scripts/make-update.sh refuses a bench build before signing.
# Gate 3 review: an oversized SSHSIG reserved field, an unknown installed version, and the install
# path (RAM copy, retries, watchdog takeover) on the test build's stand-ins for mtd2 and the rest.
#   bash src/camupdate/test.sh      (needs clang, libsodium (Homebrew), ssh-keygen)
set -euo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d "${TMPDIR:-/tmp}/cu.XXXXXX")
INC=$(pkg-config --cflags libsodium 2>/dev/null || echo -I/opt/homebrew/include)
LIB=$(pkg-config --libs libsodium 2>/dev/null || echo "-L/opt/homebrew/lib -lsodium")
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -DCAMUPDATE_TEST $INC \
	-o "$T/camupdate" src/camupdate/camupdate.c $LIB
ssh-keygen -q -t ed25519 -N '' -C "test signer" -f "$T/k"
ssh-keygen -q -t ed25519 -N '' -C "stranger" -f "$T/other"
cp "$T/k.pub" "$T/keys"
echo MCA40E-IFADO > "$T/device"
echo 20261023.1 > "$T/version"
export CU_KEYS="$T/keys" CU_DEVICE="$T/device" CU_VERSION="$T/version"
# a squashfs-shaped payload: "hsqs", bytes_used (u64 LE at 40) = 100000, padded to 4 KiB (102400)
sqfs() { # sqfs OUT USED TOTAL
	python3 -I - "$@" <<'PY'
import os, struct, sys
used, total = int(sys.argv[2]), int(sys.argv[3])
b = bytearray(b"hsqs" + os.urandom(total - 4))
b[40:48] = struct.pack("<Q", used)
open(sys.argv[1], "wb").write(b)
PY
}
sqfs "$T/payload" 100000 102400
SHA=$(shasum -a 256 "$T/payload" | cut -d' ' -f1)
SIZE=$(wc -c < "$T/payload" | tr -d ' ')
# pkg NAME KEY NAMESPACE header-lines...
pkg() {
	local name=$1 key=$2 ns=$3; shift 3
	printf '%s\n' "$@" > "$T/$name.hdr"; printf '\n' >> "$T/$name.hdr"
	ssh-keygen -q -Y sign -f "$key" -n "$ns" "$T/$name.hdr"
	cat "$T/$name.hdr" "$T/$name.hdr.sig" "$T/payload" > "$T/$name.camfw"
}
H=(magic=camfw1 device=MCA40E-IFADO part=rootfs version=20261024.1 "size=$SIZE" "sha256=$SHA" allow-downgrade=0)
pkg good "$T/k" cam-firmware "${H[@]}"
pkg stranger "$T/other" cam-firmware "${H[@]}"
pkg wrongns "$T/k" file "${H[@]}"
pkg device "$T/k" cam-firmware magic=camfw1 device=OTHER part=rootfs version=20261024.1 "size=$SIZE" "sha256=$SHA" allow-downgrade=0
pkg old "$T/k" cam-firmware magic=camfw1 device=MCA40E-IFADO part=rootfs version=20261023.1 "size=$SIZE" "sha256=$SHA" allow-downgrade=0
pkg olddown "$T/k" cam-firmware magic=camfw1 device=MCA40E-IFADO part=rootfs version=20261001.1 "size=$SIZE" "sha256=$SHA" allow-downgrade=1
pkg unknown "$T/k" cam-firmware "${H[@]}" extra=1
# payloads other than the good one, each signed as is: pkgp NAME PAYLOAD
pkgp() {
	local sha size
	sha=$(shasum -a 256 "$2" | cut -d' ' -f1); size=$(wc -c < "$2" | tr -d ' ')
	printf '%s\n' magic=camfw1 device=MCA40E-IFADO part=rootfs version=20261024.1 "size=$size" "sha256=$sha" \
		allow-downgrade=0 > "$T/$1.hdr"; printf '\n' >> "$T/$1.hdr"
	ssh-keygen -q -Y sign -f "$T/k" -n cam-firmware "$T/$1.hdr"
	cat "$T/$1.hdr" "$T/$1.hdr.sig" "$2" > "$T/$1.camfw"
}
{ cat "$T/payload"; printf '%s\n' "CAM-FIRMWARE-DEV BENCH IMAGE: carries the builder's credentials; never flash"; } > "$T/p-bench"
pkgp bench "$T/p-bench"
{ cat "$T/payload"; printf 'x'; } > "$T/p-trail"
pkgp trailing "$T/p-trail"
sqfs "$T/p-used" 200000 102400
pkgp badused "$T/p-used"
sqfs "$T/p-nopad" 100000 100000
pkgp nopad "$T/p-nopad"
pkg kernel "$T/k" cam-firmware magic=camfw1 device=MCA40E-IFADO part=kernel version=20261024.1 "size=$SIZE" "sha256=$SHA" allow-downgrade=0
# tampered: header edited after signing; payload byte flipped; truncated; no signature
sed 's/version=20261024.1/version=20261099.1/' "$T/good.hdr" > "$T/t.hdr"
cat "$T/t.hdr" "$T/good.hdr.sig" "$T/payload" > "$T/hdrtamper.camfw"
cp "$T/good.camfw" "$T/paytamper.camfw"; printf 'X' | dd of="$T/paytamper.camfw" bs=1 seek=$(( $(wc -c < "$T/good.camfw") - 10 )) conv=notrunc 2>/dev/null
head -c $(( $(wc -c < "$T/good.camfw") - 1 )) "$T/good.camfw" > "$T/short.camfw"
cat "$T/good.hdr" "$T/payload" > "$T/nosig.camfw"
fail=0
expect() { # expect ok|refused FILE [reason-substring]; a sanitizer report fails it too
	local want=$1 f=$2 why=${3:-} out
	if out=$("$T/camupdate" --check "$T/$f.camfw" 2>&1); then got=ok; else got=refused; fi
	if [ "$got" != "$want" ] || { [ -n "$why" ] && ! grep -q "$why" <<<"$out"; } ||
	   grep -qE "Sanitizer|runtime error" <<<"$out"; then
		echo "FAIL $f: want $want${why:+ ($why)}, got: $out"; fail=1
	else echo "ok   $f: $(tail -1 <<<"$out")"; fi
}
expect ok good
expect ok olddown
expect refused stranger "untrusted key"
expect refused wrongns "namespace"
expect refused device "another device"
expect refused old "not newer"
expect refused unknown "unknown header key"
expect refused kernel "part=rootfs"
expect refused hdrtamper "bad signature"
expect refused paytamper "SHA-256"
expect refused short "size differs"
expect refused nosig "no signature"
expect refused bench "bench image"
expect refused trailing "data after the squashfs"
expect refused badused "bytes_used"
expect ok nopad
# the installed version must be known (Gate 3 review): a missing or malformed /etc/cam/version is
# refused, unless the package is signed with allow-downgrade=1
echo garbage > "$T/badversion"
CU_VERSION=$T/none expect refused good "installed version unknown"
CU_VERSION=$T/badversion expect refused good "installed version unknown"
CU_VERSION=$T/none expect ok olddown
# a forged block naming the trusted key with a 2000-byte SSHSIG "reserved" field (Gate 3 review: it
# overflowed the signed-data buffer before any crypto); with an empty one it parses to "bad signature"
forge() { # forge RESERVED-LENGTH OUT
	python3 -I - "$T/k.pub" "$1" "$2" <<'PY'
import base64, struct, sys
s = lambda b: struct.pack(">I", len(b)) + b
pk = base64.b64decode(open(sys.argv[1]).read().split()[1])
blob = (b"SSHSIG" + struct.pack(">I", 1) + s(pk) + s(b"cam-firmware") + s(b"A" * int(sys.argv[2])) +
        s(b"sha512") + s(s(b"ssh-ed25519") + s(bytes(64))))
e = base64.b64encode(blob).decode()
open(sys.argv[3], "w").write("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(e[i:i + 70] for i in range(0, len(e), 70)) +
                             "\n-----END SSH SIGNATURE-----\n")
PY
}
forge 2000 "$T/reserved.sig"; cat "$T/good.hdr" "$T/reserved.sig" "$T/payload" > "$T/reserved.camfw"
forge 0 "$T/forged.sig"; cat "$T/good.hdr" "$T/forged.sig" "$T/payload" > "$T/forged.camfw"
expect refused reserved "reserved field is not empty"
expect refused forged "bad signature"
"$T/camupdate" --check - < "$T/good.camfw" > /dev/null && echo "ok   stdin" || { echo "FAIL stdin"; fail=1; }
for i in $(seq 1 300); do                       # garbage and mutated packages: refused, no crash
	head -c $((RANDOM % 4000 + 1)) /dev/urandom > "$T/g.camfw"
	if "$T/camupdate" --check "$T/g.camfw" > /dev/null 2>&1; then echo "FAIL garbage accepted"; fail=1; fi
	cp "$T/good.camfw" "$T/m.camfw"
	printf "\\x$(printf %02x $((RANDOM % 256)))" | dd of="$T/m.camfw" bs=1 seek=$((RANDOM % 900)) conv=notrunc 2>/dev/null
	rc=0; "$T/camupdate" --check "$T/m.camfw" > /dev/null 2>&1 || rc=$?
	[ $rc -le 1 ] || { echo "FAIL crash rc=$rc"; fail=1; }
done
echo "ok   300 garbage + 300 mutated packages: no crash, garbage refused"
# the owner's YubiKey (sk-ssh-ed25519, PIN + touch) over testdata/sk-nano.hdr
D=src/camupdate/testdata
vs() { # vs want HDR SIG KEYS [reason]
	local out got
	if out=$(CU_KEYS=$4 "$T/camupdate" --verify-sig "$2" "$3" 2>&1); then got=ok; else got=refused; fi
	if [ "$got" != "$1" ] || { [ -n "${5:-}" ] && ! grep -q "$5" <<<"$out"; }; then
		echo "FAIL sk $2: want $1${5:+ ($5)}, got: $out"; fail=1
	else echo "ok   sk: $out"; fi
}
vs ok "$D/sk-nano.hdr" "$D/sk-nano.hdr.sig" "$D/sk-keys" "cam-firmware nano"
printf 'magic=tesT\n\n' > "$T/sk.hdr"
vs refused "$T/sk.hdr" "$D/sk-nano.hdr.sig" "$D/sk-keys" "bad signature"
vs refused "$D/sk-nano.hdr" "$D/sk-nano.hdr.sig" "$T/keys" "untrusted key"
python3 -I - "$D/sk-nano.hdr.sig" "$T/sk-noUV.sig" <<'PY'
import base64, sys
a = open(sys.argv[1]).read().splitlines()
b = bytearray(base64.b64decode("".join(a[1:-1])))
b[-5] &= ~0x04                                   # clear user-verified: the PIN flag
e = base64.b64encode(bytes(b)).decode()
open(sys.argv[2], "w").write(a[0] + "\n" + "\n".join(e[i:i + 70] for i in range(0, len(e), 70)) + "\n" + a[-1] + "\n")
PY
vs refused "$D/sk-nano.hdr" "$T/sk-noUV.sig" "$D/sk-keys" "user verification"
# Installing (Gate 3 review) on a test build's stand-ins, never a real device: CU_MTD is a 256 KiB
# file for mtd2, CU_WATCHDOG a file (each feed adds a byte), CU_PROC a directory of fake /proc
# entries for processes started here, CU_TMP the tmpfs. A test build "reboots" with exit status 3.
mkdir -p "$T/tmp" "$T/proc0" "$T/procw"
TMPR=$(cd "$T/tmp" && pwd -P)
echo precious > "$T/victim"; ln -s "$T/victim" "$TMPR/camupdate.run"     # planted in "/tmp"
inst() { # inst [VAR=VALUE...]: install good.camfw; sets rc and out
	head -c 262144 /dev/zero > "$T/mtd"; : > "$T/wdt"
	rc=0; out=$(env CU_MTD="$T/mtd" CU_WATCHDOG="$T/wdt" CU_PROC="$T/proc0" CU_TMP="$TMPR" "$@" \
		"$T/camupdate" "$T/good.camfw" 2>&1) || rc=$?
}
check() { # check NAME CONDITION...: report; on failure show camupdate's output
	local n=$1; shift
	if "$@"; then echo "ok   install: $n"; else echo "FAIL install: $n"; sed 's/^/     /' <<<"$out"; fail=1; fi
}
has() { grep -q -- "$1" <<<"$out"; }
clean() { ! grep -qE "Sanitizer|runtime error" <<<"$out"; }
image() { head -c "$SIZE" "$T/mtd" | cmp -s - "$T/payload"; }
blank() { head -c 262144 /dev/zero | cmp -s - "$T/mtd"; }
out=$("$T/camupdate" "$T/good.camfw" 2>&1) && rc=0 || rc=$?
check "a test build won't install without its stand-ins" [ "$rc" = 1 ]
inst
check "written, verified, rebooted; the watchdog fed" eval '[ "$rc" = 3 ] && has "written and verified" && image && [ -s "$T/wdt" ] && clean'
check "ran from a fresh 0700 directory, 0700 file" eval 'grep -qE "running from $TMPR/camupdate\.[A-Za-z0-9]{6}/camupdate\.run \(dir 700, file 700\)" <<<"$out"'
check "the planted /tmp/camupdate.run not followed; the copy removed itself" \
	eval '[ "$(cat "$T/victim")" = precious ] && [ "$(ls -A "$TMPR")" = camupdate.run ]'
inst CU_FAIL_VERIFY=2
check "2 bad read-backs, then a good pass from RAM" eval '[ "$rc" = 3 ] && has "pass 2 of 3 failed" && has "written and verified" && image && clean'
inst CU_FAIL_ERASE=1
check "a failed erase, then a good pass" eval '[ "$rc" = 3 ] && has "erase at 0x10000" && has "written and verified" && image && clean'
inst CU_FAIL_VERIFY=3
check "3 bad passes: INSTALL FAILED and a reboot, not an exit" \
	eval '[ "$rc" = 3 ] && has "INSTALL FAILED" && has "(test build) reboot" && ! has "written and verified" && clean'
# the watchdog can't be taken: a bystander (stopped, then resumed) and a fake BusyBox feeder
# (killed, then restarted from its /proc exe and cmdline); nothing is written
printf '#!/bin/sh\necho "$0 $*" > "%s/feeder-restarted"\n' "$T" > "$T/watchdog"; chmod +x "$T/watchdog"
( while :; do echo t >> "$T/ticks"; sleep 0.1; done ) & BY=$!
sleep 300 & FD=$!
mkdir -p "$T/procw/$BY" "$T/procw/$FD"
printf 'ticker\0' > "$T/procw/$BY/cmdline"
printf '%s\0' "$T/watchdog" -T 30 > "$T/procw/$FD/cmdline"
ln -s "$T/watchdog" "$T/procw/$FD/exe"
inst CU_PROC="$T/procw" CU_WATCHDOG="$T/nodev/watchdog"
for i in $(seq 1 20); do [ -s "$T/feeder-restarted" ] && break; sleep 0.1; done
n1=$(wc -l < "$T/ticks"); sleep 0.5; n2=$(wc -l < "$T/ticks")
st=0; kill "$FD" 2>/dev/null || true; { wait "$FD"; } 2>/dev/null || st=$?
kill -CONT "$BY" 2>/dev/null || true; kill "$BY" 2>/dev/null || true; { wait "$BY"; } 2>/dev/null || true
check "no watchdog: exit 1 with nothing written" eval '[ "$rc" = 1 ] && has "can.t take the watchdog" && blank && clean'
check "no watchdog: the feeder was killed and is restarted" \
	eval '[ "$st" = 137 ] && [ "$(cat "$T/feeder-restarted" 2>/dev/null)" = "$T/watchdog -T 30" ]'
check "no watchdog: the stopped processes run again" [ "$n2" -gt "$n1" ]
# make-update.sh refuses a bench build before anything is signed (no key is touched: /nonexistent).
# A copy of it runs in a scratch tree ($T/mu), so build/ here is never touched.
mkdir -p "$T/mu/scripts" && cp scripts/make-update.sh "$T/mu/scripts/"
mu() { # mu WHAT REASON: $T/mu/build/rootfs, set up by the caller
	local out
	if out=$(bash "$T/mu/scripts/make-update.sh" /nonexistent/key 2>&1); then
		echo "FAIL make-update $1: packaged: $out"; fail=1
	elif ! grep -q "$2" <<<"$out" || grep -q "signing" <<<"$out"; then
		echo "FAIL make-update $1: want \"$2\", got: $out"; fail=1
	else echo "ok   make-update refuses $1: $(head -1 <<<"$out" | cut -c1-90)"; fi
}
RD=$T/mu/build/rootfs
rd() { # a release-shaped build dir with payload FILE
	rm -rf "$RD"; mkdir -p "$RD/root/etc/cam"
	echo 20261024.1 > "$RD/root/etc/cam/version"; echo MCA40E-IFADO > "$RD/root/etc/cam/device"
	cp "$1" "$RD/rootfs.sqfs"; echo "image: release (no credentials; scan passed)" > "$RD/BUILD-INFO.txt"
}
rd "$T/payload"; touch "$RD/root/etc/cam/bench"; mu "a tree with /etc/cam/bench" "bench image (/etc/cam/bench)"
rd "$T/payload"; echo "image: BENCH (carries the builder's credentials; never flash)" > "$RD/BUILD-INFO.txt"
mu "a BUILD-INFO saying BENCH" "says it is a bench image"
rd "$T/p-bench"; mu "a squashfs with the bench trailer" "has the bench trailer"
rd "$T/p-trail"; mu "data after the squashfs" "bytes after the squashfs"
rd "$T/p-used"; mu "a bytes_used past the end" "bad squashfs bytes_used"
rm -rf "$T"
[ $fail = 0 ] && echo "ALL OK" || { echo "FAILED"; exit 1; }
