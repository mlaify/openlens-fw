# SPDX-License-Identifier: MIT
# cam-net.sh: CAM_NET, the camera subnet, a required build setting (src/camnet.h). Sourced by
# src/build.sh (camcfg), scripts/build-camtls.sh (camtls), scripts/host-tests.sh and
# src/camtls/test.sh:
#   . scripts/cam-net.sh      sets CAM_NET (A.B.C.D/PREFIX) and CAM_NET_CFLAGS, or stops the build
# CAM_NET comes from the environment, else from the first line of cam-net.local at the repository
# root that isn't blank or a comment (gitignored: each builder's own network). With neither, the
# build stops. The prefix is 8..30, and the address is the subnet's network address
# (192.0.2.0/24, not 192.0.2.5/24). The camera CA's name constraint and the static addresses
# camcfg accepts come from it, so a camera can only hold a certificate for an address inside it.
# The host tests set CAM_NET=192.0.2.0/24 (RFC 5737) themselves.
cam_net_load() {
	local v=${CAM_NET:-} f o n=0 p mask
	f="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/cam-net.local"
	if [ -z "$v" ] && [ -f "$f" ]; then
		v=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$f" | head -1 | tr -d '[:space:]')
	fi
	if [ -z "$v" ]; then
		echo "ERROR: CAM_NET is not set. The camera subnet (A.B.C.D/PREFIX, e.g. 192.168.50.0/24) is a" >&2
		echo "  required build setting: set CAM_NET=... or write it to cam-net.local at the repository root." >&2
		return 1
	fi
	if ! [[ "$v" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([1-9][0-9]?)$ ]]; then
		echo "ERROR: CAM_NET=$v: expected A.B.C.D/PREFIX" >&2
		return 1
	fi
	p=${BASH_REMATCH[5]}
	local octets=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}")
	for o in "${octets[@]}"; do
		if ! [[ "$o" =~ ^(0|[1-9][0-9]*)$ ]] || [ "$o" -gt 255 ]; then
			echo "ERROR: CAM_NET=$v: bad octet $o" >&2
			return 1
		fi
		n=$(( (n << 8) | o ))
	done
	if [ "$p" -lt 8 ] || [ "$p" -gt 30 ]; then
		echo "ERROR: CAM_NET=$v: the prefix is 8..30" >&2
		return 1
	fi
	mask=$(( (0xffffffff << (32 - p)) & 0xffffffff ))
	if [ $(( n & ~mask & 0xffffffff )) -ne 0 ]; then
		echo "ERROR: CAM_NET=$v: give the subnet's network address (host bits zero)" >&2
		return 1
	fi
	CAM_NET=$v
	CAM_NET_CFLAGS=$(printf -- '-DCAM_NET_BASE=0x%08xu -DCAM_NET_PREFIX=%d -DCAM_NET_STR="%s"' "$n" "$p" "$v")
}
cam_net_load || exit 1
