/* SPDX-License-Identifier: MIT */
/* camnet.h: the camera subnet (CAM_NET), a required build setting. The camera CA's IPv4 name
 * constraint (camtls) and the static addresses camcfg accepts both come from it, so a camera can
 * only hold an HTTPS certificate for an address in this subnet. scripts/cam-net.sh turns
 * CAM_NET=A.B.C.D/PREFIX (environment or cam-net.local) into the three defines below; a build
 * without them stops here. The host tests use 192.0.2.0/24 (RFC 5737). */
#ifndef CAMNET_H
#define CAMNET_H

#include <stdint.h>

#if !defined(CAM_NET_BASE) || !defined(CAM_NET_PREFIX) || !defined(CAM_NET_STR)
#error "CAM_NET is a required build setting: set CAM_NET=A.B.C.D/PREFIX or write it to cam-net.local (scripts/cam-net.sh)"
#endif

#define NET_BASE ((uint32_t)(CAM_NET_BASE))
#define NET_MASK ((uint32_t)(0xffffffffu << (32 - (CAM_NET_PREFIX))))

_Static_assert(CAM_NET_PREFIX >= 8 && CAM_NET_PREFIX <= 30, "CAM_NET: the prefix is 8..30");
_Static_assert((NET_BASE & ~NET_MASK) == 0, "CAM_NET: the address must be the subnet's network address");

#endif
