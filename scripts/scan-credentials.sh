#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# scan-credentials.sh ROOTFS-DIR: exit 1, naming each finding on stderr, if the rootfs tree carries
# credential material. A release image must carry none (#128, docs/CLAIM.md): every account, key
# and secret is made per camera by its owner. build-rootfs.sh runs this on every release image;
# scripts/test-scan-credentials.sh tests it on the host (macOS or Linux, no Docker).
#
# Refused:
#   - by name: *.seed, *htdigest*, authorized_keys*, SSH host or client keys (*_host_key*,
#     ssh_host_*, id_rsa*, id_ecdsa*, id_ed25519*, id_dsa*), *.pem, *.p12, *.pfx, root.hash,
#     /etc/cam/bench (a bench image), /etc/cam/users, /etc/cam/recovery, anything under /mnt/nand
#     (DATA is the camera's own);
#   - /etc/shadow with any password field but *, !, !* or !! (a hash, or an empty password);
#     /etc/passwd with a password field but x, * or !;
#   - in any text file (binaries are skipped: strings in a program aren't credentials): a private
#     key block, a crypt(3) hash ($1$, $5$, $6$, $y$, ...), an htdigest line (user:realm:MD5), an
#     account line (name:admin|operator|viewer:password), an SSH public key line (outside
#     /etc/cam/update-keys, which holds the update signing keys: public verification keys).
# Exit 0 clean, 1 findings, 2 usage.
set -euo pipefail
R=${1:-}
[ -n "$R" ] && [ -d "$R" ] || { echo "usage: scan-credentials.sh ROOTFS-DIR" >&2; exit 2; }
R=${R%/}
bad=0
found() { echo "CREDENTIAL: ${1#"$R"}: $2" >&2; bad=1; }

while IFS= read -r f; do
	found "$f" "a credential file by its name"
done < <(find "$R" \( -name '*.seed' -o -iname '*htdigest*' -o -name 'authorized_keys*' \
	-o -name '*_host_key*' -o -name 'ssh_host_*' -o -name 'id_rsa*' -o -name 'id_dsa*' \
	-o -name 'id_ecdsa*' -o -name 'id_ed25519*' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
	-o -name 'root.hash' -o -path "$R/etc/cam/bench" -o -path "$R/etc/cam/users" \
	-o -path "$R/etc/cam/recovery" -o -path "$R/mnt/nand/*" \) -print)

if [ -f "$R/etc/shadow" ]; then
	while IFS=: read -r user pw _ || [ -n "$user" ]; do
		[ -n "$user" ] || continue
		case $pw in
		'*' | '!' | '!*' | '!!') ;;
		*) found "$R/etc/shadow" "$user has a password or password hash (only *, !, !* or !! may ship)" ;;
		esac
	done < "$R/etc/shadow"
fi
if [ -f "$R/etc/passwd" ]; then
	while IFS=: read -r user pw _ || [ -n "$user" ]; do
		[ -n "$user" ] || continue
		case $pw in
		x | '*' | '!') ;;
		*) found "$R/etc/passwd" "$user has a password field other than x" ;;
		esac
	done < "$R/etc/passwd"
fi

# by content, text files only (grep -I); symlinks aren't followed
scan() { # ERE what [path to skip]
	while IFS= read -r f; do
		[ "$f" = "${3:-}" ] && continue
		found "$f" "$2"
	done < <(grep -rlIE -e "$1" "$R" 2>/dev/null || true)
}
scan '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' "a private key"
scan '\$(1|2[abxy]?|5|6|7|y|gy|md5|sha1)\$[^$:[:space:]]*\$[./A-Za-z0-9]{8,}' "a crypt(3) password hash"
scan '^[A-Za-z0-9._-]{1,32}:[^:[:space:]]+:[0-9a-f]{32}$' "an htdigest line (user:realm:MD5)"
scan '^[A-Za-z0-9._-]{1,32}:(admin|operator|viewer):.' "an account line (name:role:password)"
scan '(^|[[:space:]])(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) AAAA[A-Za-z0-9+/]{16,}' \
	"an SSH public key" "$R/etc/cam/update-keys"

if [ "$bad" = 0 ]; then
	echo "scan-credentials: $R: no credential material"
else
	echo "scan-credentials: $R carries credential material (above): not a release image" >&2
fi
exit "$bad"
