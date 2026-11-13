#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host test of scripts/scan-credentials.sh (#128): no Docker, no vendor files. A clean fake rootfs
# (and rootfs/skel itself) passes; each kind of credential material planted in a copy fails the
# scan with its reason.
#   bash scripts/test-scan-credentials.sh
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d "${TMPDIR:-/tmp}/scan.XXXXXX")
trap 'rm -rf "$T"' EXIT
S=scripts/scan-credentials.sh
fail=0
KEY="AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"

# a clean tree: locked root, the update keys (public verification keys), a binary holding key-ish
# strings (a program's strings aren't credentials), symlinks as the image has them
mk() {
	rm -rf "$T/r" && mkdir -p "$T/r/etc/cam" "$T/r/usr/sbin" "$T/r/root" "$T/r/mnt/nand"
	echo 'root:*:19000:0:99999:7:::' > "$T/r/etc/shadow"
	echo 'root:x:0:0:root:/root:/bin/sh' > "$T/r/etc/passwd"
	echo 'root:x:0:' > "$T/r/etc/group"
	echo "sk-ssh-ed25519@openssh.com $KEY cam-firmware nano" > "$T/r/etc/cam/update-keys"
	echo MCA40E-IFADO > "$T/r/etc/cam/device"
	printf 'ELF\0\0-----BEGIN OPENSSH PRIVATE KEY-----\0admin:admin:x\0' > "$T/r/usr/sbin/prog"
	ln -s /mnt/nand/cam/ssh "$T/r/root/.ssh"
	ln -s /tmp/resolv.conf "$T/r/etc/resolv.conf"
}
expect() { # expect pass|fail what [reason-substring]
	local out got
	if out=$(bash "$S" "$T/r" 2>&1); then got=pass; else got=fail; fi
	if [ "$got" != "$1" ] || { [ -n "${3:-}" ] && ! grep -qF -- "$3" <<<"$out"; }; then
		echo "FAIL $2: want $1${3:+ ($3)}, got $got:"; echo "$out"; fail=1
	else
		echo "ok   $2${3:+: $(grep -F -- "$3" <<<"$out" | head -1)}"
	fi
}

mk; expect pass "a clean tree (update keys, a binary with key strings, symlinks)"
out=$(bash "$S" rootfs/skel 2>&1) && echo "ok   rootfs/skel itself is clean" || { echo "FAIL rootfs/skel: $out"; fail=1; }
bash "$S" "$T/missing" > /dev/null 2>&1 && { echo "FAIL a missing dir passes"; fail=1; } || echo "ok   a missing dir is a usage error"

mk; echo 'admin:admin:Secret-pass1' > "$T/r/etc/cam/users.seed"; expect fail "users.seed" "/etc/cam/users.seed: a credential file by its name"
mk; echo "admin:camera:0123456789abcdef0123456789abcdef" > "$T/r/etc/cam/rtspd.htdigest"; expect fail "rtspd.htdigest" "/etc/cam/rtspd.htdigest: a credential file"
mk; echo "ssh-ed25519 $KEY me" > "$T/r/etc/cam/authorized_keys.seed"; expect fail "authorized_keys.seed" "authorized_keys.seed: a credential file"
mk; printf 'x\nbench image\n' > "$T/r/etc/cam/bench"; expect fail "a bench marker" "/etc/cam/bench: a credential file"
mk; mkdir -p "$T/r/etc/dropbear"; echo k > "$T/r/etc/dropbear/dropbear_ed25519_host_key"; expect fail "a baked-in host key" "dropbear_ed25519_host_key"
mk; mkdir -p "$T/r/mnt/nand/cam"; echo x > "$T/r/mnt/nand/cam/cam.conf"; expect fail "DATA leftovers" "/mnt/nand/cam/cam.conf"
mk; echo 'x' > "$T/r/etc/server.pem"; expect fail "a .pem" "/etc/server.pem"
mk; echo 'root:$6$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789./:19000:0:99999:7:::' > "$T/r/etc/shadow"
expect fail "a root hash in shadow" "root has a password or password hash"
mk; echo 'root::19000:0:99999:7:::' > "$T/r/etc/shadow"; expect fail "an empty root password" "root has a password"
mk; printf 'root:*:19000:0:99999:7:::\nsvc:!:19000::::::' > "$T/r/etc/shadow"; expect pass "locked accounts (*, !; no newline at the end)"
mk; echo 'root:abc123:0:0:root:/root:/bin/sh' > "$T/r/etc/passwd"; expect fail "a hash in passwd" "root has a password field other than x"
mk; echo 'admin:admin:Secret-pass1' > "$T/r/etc/cam/accounts"; expect fail "an account file by another name" "/etc/cam/accounts: an account line"
mk; echo 'admin:camera:0123456789abcdef0123456789abcdef' > "$T/r/etc/cam/digest"; expect fail "an htdigest by another name" "/etc/cam/digest: an htdigest line"
mk; printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n-----END OPENSSH PRIVATE KEY-----\n' > "$T/r/etc/key.txt"
expect fail "a private key in a text file" "/etc/key.txt: a private key"
mk; echo 'pw=$1$abcd$0123456789abcdefghij' > "$T/r/etc/app.conf"; expect fail "a crypt hash in a config" "/etc/app.conf: a crypt(3) password hash"
mk; echo "ssh-ed25519 $KEY someone" > "$T/r/etc/motd"; expect fail "an SSH key outside update-keys" "/etc/motd: an SSH public key"
mk; echo 'echo "$1$2" "$6"' > "$T/r/usr/sbin/script"; expect pass "shell positional parameters aren't hashes"

[ "$fail" = 0 ] && echo "ALL OK" || { echo "FAILED"; exit 1; }
