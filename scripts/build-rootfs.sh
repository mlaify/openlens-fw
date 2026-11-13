#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build-rootfs.sh: assemble the hardened rootfs for mtd2 (#31) as squashfs-xz, plus a tarball of
# our own files for the chroot test on cam #1. Runs in an Ubuntu container (owner's terminal).
#
# A release image (the default) carries no credential of any kind (#128, docs/CLAIM.md): no
# account, password, password hash, SSH key or root hash. Each camera is claimed by its owner at
# first boot. A scan (scripts/scan-credentials.sh) fails the build if anything of the kind is in it.
#
#   docker run --rm -v "$PWD":/src -w /src \
#     -v <path-to-stock-rootfs>:/vendor:ro \
#     ubuntu:24.04 bash scripts/build-rootfs.sh
#
# --bench (or BENCH=1): a bench image for the RAM chroot test only. It embeds the builder's
# credentials from /secrets (add -v "$HOME/.config/cam-firmware-dev":/secrets:ro), is marked
# /etc/cam/bench, and its rootfs.sqfs ends with a bench trailer after the squashfs, so
# make-update.sh and camupdate refuse it: a bench image is never flashed.
#
# Inputs:
#   build/arm/rtspd (+ .sha256)          from src/build.sh
#   build/arm/dropbearmulti (+ .sha256)  from scripts/build-dropbear.sh (#76)
#   build/arm/camtls (+ .sha256)         from scripts/build-camtls.sh (HTTPS, docs/PLAN-TLS.md §B;
#                                        with build/arm/mbedtls-VERSION.txt)
#   build/arm/{camcfg,camtls}.cam-net    the CAM_NET each was built for; they must match
#   /vendor                              the stock rootfs dump: files in rootfs/vendor-files.tsv,
#                                        checked against their SHA-256 (never committed)
#   --bench only (ignored otherwise):
#   /secrets/users.seed                  bench accounts name:role:password, copied to DATA by
#                                        cam-config (scripts/rtsp-passwd.py writes it)
#   /secrets/authorized_keys             SSH public keys for root (#76), seeded to DATA
#   /secrets/root.hash (optional)        a crypt(3) hash for root: serial login on ttyS0;
#                                        without it root is locked
#   $IQ_PROFILE (default bench-logs/iq-profile-stock.bin)  IQ profile for rtspd -Q (#36)
#   /vendor/config/iqfile/gc4023_{day,night}.bin  stock's IQ bins: scripts/iq-bin2profile.py
#                                        derives /etc/cam/iq-night.bin and iq-day-switch.bin (rtspd -q,
#                                        image.night_tuning); without them, a warning and no night tuning
#   BusyBox: Ubuntu's signed busybox-static armhf package (static, ARMv7 hard-float)
# Outputs (gitignored, contain vendor files; a bench build also the builder's credentials):
#   build/rootfs/rootfs.sqfs (+ .sha256), chroot-test.tgz (our files only), MANIFEST.txt,
#   BUILD-INFO.txt (its "image:" line says release or BENCH)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
BENCH=${BENCH:-0}
for a in "$@"; do
	case $a in
	--bench) BENCH=1 ;;
	*) echo "usage: build-rootfs.sh [--bench]"; exit 2 ;;
	esac
done
[ "$BENCH" = 0 ] || [ "$BENCH" = 1 ] || { echo "BENCH must be 0 or 1"; exit 2; }
# The bench trailer after the squashfs (camupdate and make-update.sh look for it; keep in step)
BENCH_TRAILER="CAM-FIRMWARE-DEV BENCH IMAGE: carries the builder's credentials; never flash"
EPOCH=$(cat rootfs/SOURCE_DATE_EPOCH)
OUT=build/rootfs
R=$OUT/root
MTD2_SIZE=$((0xCB0000))

[ -f build/arm/rtspd ] || { echo "build/arm/rtspd missing: run src/build.sh first"; exit 1; }
(cd build/arm && sha256sum -c rtspd.sha256)
[ -d /vendor/config ] || { echo "/vendor is not the stock rootfs dump"; exit 1; }

dpkg --add-architecture armhf
apt-get update -qq
apt-get install -y -qq --no-install-recommends squashfs-tools file python3 >/dev/null
(cd /tmp && apt-get download -qq busybox-static:armhf && apt-get download -qq busybox-static)
BB_DEB=$(ls /tmp/busybox-static_*_armhf.deb)
rm -rf /tmp/bb /tmp/bbn && dpkg-deb -x "$BB_DEB" /tmp/bb
# The armhf binary can't run here (no AArch32 on Apple Silicon); the native build of the same
# package has the same applet config, so list the applets with it.
dpkg-deb -x "$(ls /tmp/busybox-static_*.deb | grep -v _armhf)" /tmp/bbn
# Ubuntu 24.04 (merged /usr) ships it as usr/bin/busybox; older releases as bin/busybox
BB=$(find /tmp/bb -type f -name busybox | head -1)
BBN=$(find /tmp/bbn -type f -name busybox | head -1)
[ -n "$BB" ] && [ -n "$BBN" ] || { echo "ERROR: busybox binary not found in the packages"; exit 1; }
"$BBN" --list > /tmp/applets
missing=$(grep -v '^#' rootfs/applets.txt | cut -d: -f2 | tr ' ' '\n' | grep -v '^$' | grep -vxFf /tmp/applets || true)
[ -z "$missing" ] || { echo "ERROR: applets not in this BusyBox: $missing"; exit 1; }

rm -rf "$OUT" && mkdir -p "$R"
for d in bin sbin usr/bin usr/sbin etc dev proc sys tmp run root mnt/nand var config; do
	mkdir -p "$R/$d"
done
cp -a rootfs/skel/. "$R/"
install -m 0755 "$BB" "$R/bin/busybox"
ln -s bin/busybox "$R/linuxrc"
grep -v '^#' rootfs/applets.txt | while IFS=: read -r dir list; do
	[ -n "$dir" ] || continue
	rel=$(echo "$dir" | sed 's|^/||; s|[^/]*|..|g')      # /usr/bin -> ../..
	for a in $list; do ln -s "$rel/bin/busybox" "$R$dir/$a"; done
done
install -m 0755 build/arm/rtspd "$R/usr/sbin/rtspd"
# rtspd carries the OSD font (Terminus, SIL OFL 1.1): its licence ships with the image
[ -s build/arm/osd-font.copyright ] || { echo "build/arm/osd-font.copyright missing: run src/build.sh first"; exit 1; }
install -d "$R/usr/share/doc/osd-font"
install -m 0644 build/arm/osd-font.copyright "$R/usr/share/doc/osd-font/copyright"
[ -f build/arm/camcfg ] || { echo "build/arm/camcfg missing: run src/build.sh first"; exit 1; }
(cd build/arm && sha256sum -c camcfg.sha256)
install -m 0755 build/arm/camcfg "$R/usr/sbin/camcfg"
[ -f build/arm/dropbearmulti ] || { echo "build/arm/dropbearmulti missing: run scripts/build-dropbear.sh first"; exit 1; }
(cd build/arm && sha256sum -c dropbearmulti.sha256)
install -m 0755 build/arm/dropbearmulti "$R/usr/sbin/dropbearmulti"
ln -s dropbearmulti "$R/usr/sbin/dropbear"
ln -s ../sbin/dropbearmulti "$R/usr/bin/dropbearkey"
[ -f build/arm/camhttpd ] || { echo "build/arm/camhttpd missing: run src/build.sh first"; exit 1; }
(cd build/arm && sha256sum -c camhttpd.sha256)
install -m 0755 build/arm/camhttpd "$R/usr/sbin/camhttpd"
[ -f build/arm/ntpc ] || { echo "build/arm/ntpc missing: run src/build.sh first"; exit 1; }
(cd build/arm && sha256sum -c ntpc.sha256)
install -m 0755 build/arm/ntpc "$R/usr/sbin/ntpc"
[ -f build/arm/camupdate ] || { echo "build/arm/camupdate missing: run src/build.sh first"; exit 1; }
(cd build/arm && sha256sum -c camupdate.sha256)
install -m 0755 build/arm/camupdate "$R/usr/sbin/camupdate"
# HTTPS (docs/PLAN-TLS.md §B): camtls is in every image, but camtls-run starts it only with
# /etc/cam/tls.on, which the image doesn't carry until the bench test on cam #1 passes
# (rootfs/README.md; /run/tls.on turns it on until the next reboot)
[ -f build/arm/camtls ] || { echo "build/arm/camtls missing: run scripts/build-camtls.sh first"; exit 1; }
(cd build/arm && sha256sum -c camtls.sha256)
install -m 0755 build/arm/camtls "$R/usr/sbin/camtls"
# CAM_NET (scripts/cam-net.sh) is compiled into camcfg and camtls: both must have the same one
CAM_NET_IMG=$(cat build/arm/camcfg.cam-net 2>/dev/null || true)
[ -n "$CAM_NET_IMG" ] && [ "$CAM_NET_IMG" = "$(cat build/arm/camtls.cam-net 2>/dev/null || true)" ] || {
	echo "camcfg and camtls weren't built for the same CAM_NET (build/arm/camcfg.cam-net, camtls.cam-net):" \
	     "rebuild both with the same CAM_NET (src/build.sh, scripts/build-camtls.sh)"; exit 1; }
# update identity (#104): device, version (FW_VERSION or today's date .0), trusted signing keys
echo MCA40E-IFADO > "$R/etc/cam/device"
FW_VERSION=${FW_VERSION:-$(date -u +%Y%m%d).0}
[[ "$FW_VERSION" =~ ^[0-9]{8}\.[0-9]{1,6}$ ]] || { echo "bad FW_VERSION (YYYYMMDD.N)"; exit 1; }
echo "$FW_VERSION" > "$R/etc/cam/version"
# The keys are the builder's own: rootfs/update-keys.local (gitignored) if it exists, else
# rootfs/update-keys, which the repository ships with comments only. A release image without a key
# could never be updated over the network, so the build stops; a bench image (never flashed) warns.
KEYS=rootfs/update-keys
[ -f rootfs/update-keys.local ] && KEYS=rootfs/update-keys.local
if [ -f "$KEYS" ] && grep -qvE '^[[:space:]]*(#|$)' "$KEYS"; then
	grep -vE '^[[:space:]]*(#|$)' "$KEYS" | grep -qvE '^(sk-ssh-ed25519@openssh.com|ssh-ed25519) [A-Za-z0-9+/=]+( .*)?$' &&
		{ echo "ERROR: $KEYS has a line that isn't an ed25519/sk-ed25519 public key"; exit 1; }
	install -m 0644 "$KEYS" "$R/etc/cam/update-keys"
	echo "update keys: $KEYS ($(grep -cvE '^[[:space:]]*(#|$)' "$KEYS") key(s))"
elif [ "$BENCH" = 1 ]; then
	echo "WARNING: no update keys: this bench image's camupdate will refuse every package"
else
	echo "ERROR: no update keys. Put your own signing public keys in rootfs/update-keys.local"
	echo "       (one ssh-ed25519 or sk-ssh-ed25519@openssh.com line each; wiki: Signing-and-update-keys)."
	echo "       An image without them can't be updated over the network."
	exit 1
fi

# vendor files, verified
grep -v '^#' rootfs/vendor-files.tsv | while IFS=$'\t' read -r src dst sum; do
	[ -n "$dst" ] || continue
	mkdir -p "$(dirname "$R/$dst")"
	if [ "${sum#link:}" != "$sum" ]; then
		ln -s "${sum#link:}" "$R/$dst"
	else
		echo "$sum  /vendor/$src" | sha256sum -c --quiet
		install -m 0644 "/vendor/$src" "$R/$dst"
	fi
done

# credentials: none in a release image (#128); the builder's in a bench image only. The image's
# rtspd.htdigest fallback is gone: rtspd's Digest file is always derived from DATA's users.
if [ "$BENCH" = 1 ]; then
	echo "BENCH IMAGE: embedding the builder's credentials from /secrets; never flash it"
	printf '%s\nbench image: carries the builder'"'"'s credentials; never flash\n' "$(date -u +%FT%TZ)" \
		> "$R/etc/cam/bench"
	if [ -s /secrets/users.seed ]; then
		install -m 0600 /secrets/users.seed "$R/etc/cam/users.seed"     # bench accounts (#72)
	else
		echo "WARNING: no /secrets/users.seed: the bench image comes up unclaimed (claim it at /setup)"
	fi
	if [ -s /secrets/authorized_keys ]; then
		# public keys only, one per line: refuse anything else (e.g. a private key by mistake)
		if grep -vE '^[[:space:]]*(#|$)' /secrets/authorized_keys |
			grep -vqE '^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa) [A-Za-z0-9+/=]+( .*)?$'; then
			echo "ERROR: /secrets/authorized_keys has a line that isn't a public key"; exit 1
		fi
		install -m 0600 /secrets/authorized_keys "$R/etc/cam/authorized_keys.seed"   # (#76)
	else
		echo "WARNING: no /secrets/authorized_keys: no SSH access (sshd waits for keys)"
	fi
elif [ -d /secrets ]; then
	echo "release image: /secrets is mounted but ignored (no credentials are embedded; --bench embeds them)"
fi
IQ_PROFILE=${IQ_PROFILE:-bench-logs/iq-profile-stock.bin}
if [ -s "$IQ_PROFILE" ]; then
	install -m 0644 "$IQ_PROFILE" "$R/etc/cam/iq-profile.bin"
else
	echo "WARNING: no IQ profile ($IQ_PROFILE): flat, grey image (#36)"
fi
# Stock night tuning (image.night_tuning): derived from stock's gc4023 day/night bins in the dump
# (pinned SHA-256 in the converter; only the derived groups go into the image, never the bins)
IQD=/vendor/config/iqfile
NT_INFO="none"
if [ -f "$IQD/gc4023_night.bin" ] && [ -f "$IQD/gc4023_day.bin" ]; then
	python3 -I scripts/iq-bin2profile.py "$IQD/gc4023_day.bin" "$IQD/gc4023_night.bin" tools/iq-dump/iq_groups.h \
		"$R/etc/cam/iq-night.bin" "$R/etc/cam/iq-day-switch.bin" | tee /tmp/iq-night.txt
	[ -s "$R/etc/cam/iq-night.bin" ] && [ -s "$R/etc/cam/iq-day-switch.bin" ] ||
		{ echo "ERROR: night tuning files not written"; exit 1; }
	chmod 0644 "$R/etc/cam/iq-night.bin" "$R/etc/cam/iq-day-switch.bin"
	NT_INFO="$(head -1 /tmp/iq-night.txt | sed 's/^iq-bin2profile: //'); iq-night.bin $(sha256sum "$R/etc/cam/iq-night.bin" | cut -d' ' -f1)"
else
	echo "WARNING: no gc4023_night.bin / gc4023_day.bin in /vendor/config/iqfile: night tuning unavailable"
fi
if [ "$BENCH" = 1 ] && [ -s /secrets/root.hash ]; then
	# root's line only: the system users (rtspd, ntpc, camhttpd, camtls; Gate 3) stay locked
	{ printf 'root:%s:19000:0:99999:7:::\n' "$(head -1 /secrets/root.hash)"; grep -v '^root:' rootfs/skel/etc/shadow; } \
		> "$R/etc/shadow"
	echo "root: serial login enabled (bench; hash from /secrets/root.hash)"
fi
chmod 0600 "$R/etc/shadow"
chmod 0700 "$R/root"
chmod 1777 "$R/tmp"
# a release image must carry no credential material: fail the build if it does (#128)
if [ "$BENCH" = 0 ]; then
	bash scripts/scan-credentials.sh "$R" || { echo "ERROR: credential material in a release image"; exit 1; }
fi

mksquashfs "$R" "$OUT/rootfs.sqfs" -comp xz -b 256K -noappend -all-root -no-xattrs \
	-mkfs-time "$EPOCH" -all-time "$EPOCH" -quiet \
	-p "/dev/console c 600 0 0 5 1" -p "/dev/null c 666 0 0 1 3"
# a bench image's squashfs gets the bench trailer after its (4 KiB-padded) end: the kernel reads
# only up to the superblock's bytes_used, and camupdate / make-update.sh refuse it
[ "$BENCH" = 0 ] || printf '%s\n' "$BENCH_TRAILER" >> "$OUT/rootfs.sqfs"
size=$(stat -c %s "$OUT/rootfs.sqfs")
(cd "$OUT" && sha256sum rootfs.sqfs > rootfs.sqfs.sha256)
tar -C "$R" --exclude='./config/*' --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
	-czf "$OUT/chroot-test.tgz" .
(cd "$R" && find . \( -type l -printf '%M %s %p -> %l\n' \) -o -printf '%M %s %p\n') |
	sort -k3 > "$OUT/MANIFEST.txt"
{
	echo "built: $(date -u +%FT%TZ)  epoch: $EPOCH"
	if [ "$BENCH" = 1 ]; then echo "image: BENCH (carries the builder's credentials; never flash)"
	else echo "image: release (no credentials; scan passed)"; fi
	echo "busybox: $(basename "$BB_DEB")"
	echo "rtspd: $(cut -d' ' -f1 build/arm/rtspd.sha256)"
	echo "dropbear: $(cat build/arm/dropbear-VERSION.txt 2>/dev/null) $(cut -d' ' -f1 build/arm/dropbearmulti.sha256)"
	echo "mbedtls: $(cat build/arm/mbedtls-VERSION.txt 2>/dev/null) camtls $(cut -d' ' -f1 build/arm/camtls.sha256)"
	echo "cam_net: $CAM_NET_IMG"
	echo "rootfs.sqfs: $size bytes of $MTD2_SIZE ($((size * 100 / MTD2_SIZE))% of mtd2)"
	echo "version: $FW_VERSION"
	echo "night tuning: $NT_INFO"
	echo "sha256: $(cut -d' ' -f1 "$OUT/rootfs.sqfs.sha256")"
} | tee "$OUT/BUILD-INFO.txt"
file "$R/bin/busybox" "$R/usr/sbin/rtspd" "$R/usr/sbin/dropbearmulti" "$R/usr/sbin/camhttpd" "$R/usr/sbin/ntpc" "$R/usr/sbin/camupdate" "$R/usr/sbin/camtls"
[ "$size" -le "$MTD2_SIZE" ] || { echo "ERROR: rootfs larger than mtd2"; exit 1; }
