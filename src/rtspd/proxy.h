/* SPDX-License-Identifier: MIT */
/*
 * proxy.h: the PROXY v1 line camtls sends first on a UNIX socket (docs/PLAN-TLS.md, B and D), and
 * the uid at the other end of such a socket. Header-only like drop.h, so rtspd and camhttpd can
 * share it without changing their build lines.
 *
 *   proxy_parse(buf, len, ...)  the line at the start of buf: exactly
 *                               "PROXY TCP4 <src> <dst> <sport> <dport>\r\n", at most PROXY_MAX
 *                               bytes, single spaces, dotted quads without leading zeros (then
 *                               inet_pton), ports 1..65535 in decimal without leading zeros; no
 *                               UNKNOWN, no TCP6: exactly what inet_ntop and "%u" write. 1 with the
 *                               fields and *used (the line's length; what follows is the client's),
 *                               0 while more bytes may still make it valid (fewer than PROXY_MAX,
 *                               no line end yet, and what is there starts like "PROXY TCP4 "),
 *                               -1 otherwise.
 *   peer_uid(fd, uid)           SO_PEERCRED on Linux, getpeereid elsewhere (the host tests on a
 *                               Mac): 0, or -1.
 *
 * The includer defines _GNU_SOURCE before its first include: glibc's struct ucred needs it.
 */
#ifndef PROXY_H
#define PROXY_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PROXY_MAX 56                    /* "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n" */
#define PROXY_MS 1000                   /* from accept to the end of the line */

/* A port: 1 to 5 digits, no leading zero, 1..65535; 0, or -1. */
static inline int proxy_port(const char *s, uint16_t *port)
{
	size_t n = strlen(s);
	if (n < 1 || n > 5 || strspn(s, "0123456789") != n || s[0] == '0') return -1;
	long v = 0;
	for (size_t i = 0; i < n; i++) v = v * 10 + (s[i] - '0');
	if (v > 65535) return -1;
	*port = (uint16_t)v;
	return 0;
}

/* A dotted quad as inet_ntop writes it: four 0..255, no leading zeros (macOS's inet_pton takes
 * "01.2.3.4", glibc's doesn't), then inet_pton; 0, or -1. */
static inline int proxy_addr(const char *s, struct in_addr *a)
{
	const char *p = s;
	for (int i = 0; i < 4; i++) {
		size_t n = strspn(p, "0123456789");
		if (n < 1 || n > 3 || (n > 1 && p[0] == '0')) return -1;
		p += n;
		if (*p != (i < 3 ? '.' : 0)) return -1;
		if (i < 3) p++;
	}
	return inet_pton(AF_INET, s, a) == 1 ? 0 : -1;  /* and each part at most 255 */
}

static inline int proxy_parse(const char *buf, size_t len, struct in_addr *src, struct in_addr *dst,
			      uint16_t *sport, uint16_t *dport, size_t *used)
{
	static const char pre[] = "PROXY TCP4 ";
	size_t lim = len < PROXY_MAX ? len : PROXY_MAX;
	size_t k = lim < sizeof pre - 1 ? lim : sizeof pre - 1;
	if (memcmp(buf, pre, k)) return -1;
	const char *lf = memchr(buf, '\n', lim);
	if (!lf) return len < PROXY_MAX ? 0 : -1;
	size_t n = (size_t)(lf - buf) + 1;                      /* with the CR LF */
	if (n < sizeof pre - 1 + 2 || buf[n - 2] != '\r') return -1;
	char line[PROXY_MAX + 1], *f[4], *s;
	memcpy(line, buf, n - 2);
	line[n - 2] = 0;
	if (strlen(line) != n - 2) return -1;                  /* a NUL inside */
	s = line + sizeof pre - 1;
	for (int i = 0; i < 4; i++) {                           /* four fields, one space apart */
		size_t w = strcspn(s, " ");
		if (!w) return -1;
		f[i] = s;
		s += w;
		if (i < 3) {
			if (*s != ' ') return -1;
			*s++ = 0;
		}
	}
	if (*s) return -1;                                      /* a trailing space */
	struct in_addr a, b;
	uint16_t sp, dp;
	if (proxy_addr(f[0], &a) || proxy_addr(f[1], &b) || proxy_port(f[2], &sp) || proxy_port(f[3], &dp))
		return -1;
	*src = a;
	*dst = b;
	*sport = sp;
	*dport = dp;
	*used = n;
	return 1;
}

static inline int peer_uid(int fd, uid_t *uid)
{
#ifdef __linux__
	struct ucred cr;
	socklen_t n = sizeof cr;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &n) || n != sizeof cr) return -1;
	*uid = cr.uid;
	return 0;
#else
	gid_t g;
	return getpeereid(fd, uid, &g) ? -1 : 0;
#endif
}

#endif
