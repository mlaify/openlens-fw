/* SPDX-License-Identifier: MIT */
/*
 * auth.c: RTSP Digest authentication for rtspd (RFC 2617 digest as used by RTSP 1.0 clients:
 * ffmpeg/ffplay, VLC/live555). Credentials come from an Apache htdigest file, one
 * "user:realm:HA1" line per user with HA1 = MD5(user:realm:password) in lowercase hex, so no
 * plaintext password is stored on the camera (scripts/rtsp-passwd.py writes it). MD5 is RFC 1321;
 * it is here only because Digest requires it (static glibc has no hash API).
 */
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "auth.h"

/* ---- MD5 (RFC 1321) ------------------------------------------------------------------ */

struct md5 { uint32_t a, b, c, d; uint64_t len; uint8_t buf[64]; };

static const uint32_t K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};
static const uint8_t R[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_block(struct md5 *m, const uint8_t *p)
{
	uint32_t w[16], a = m->a, b = m->b, c = m->c, d = m->d;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8 | (uint32_t)p[4 * i + 2] << 16 |
		       (uint32_t)p[4 * i + 3] << 24;
	for (int i = 0; i < 64; i++) {
		uint32_t f;
		int g;
		if (i < 16) { f = (b & c) | (~b & d); g = i; }
		else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
		else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
		else { f = c ^ (b | ~d); g = (7 * i) & 15; }
		uint32_t t = d;
		d = c;
		c = b;
		uint32_t x = a + f + K[i] + w[g];
		b = b + (x << R[i] | x >> (32 - R[i]));
		a = t;
	}
	m->a += a; m->b += b; m->c += c; m->d += d;
}

static void md5_init(struct md5 *m)
{
	m->a = 0x67452301; m->b = 0xefcdab89; m->c = 0x98badcfe; m->d = 0x10325476; m->len = 0;
}

static void md5_update(struct md5 *m, const void *data, size_t n)
{
	const uint8_t *p = data;
	size_t have = (size_t)(m->len & 63);
	m->len += n;
	while (n) {
		size_t k = 64 - have < n ? 64 - have : n;
		memcpy(m->buf + have, p, k);
		have += k; p += k; n -= k;
		if (have == 64) { md5_block(m, m->buf); have = 0; }
	}
}

static void md5_hex_final(struct md5 *m, char out[33])
{
	uint64_t bits = m->len * 8;
	uint8_t pad = 0x80, z = 0, len[8];
	md5_update(m, &pad, 1);
	while ((m->len & 63) != 56) md5_update(m, &z, 1);
	for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (8 * i));
	md5_update(m, len, 8);
	uint32_t s[4] = { m->a, m->b, m->c, m->d };
	for (int i = 0; i < 16; i++)
		snprintf(out + 2 * i, 3, "%02x", (s[i / 4] >> (8 * (i % 4))) & 0xff);
}

void md5_hex(const void *data, size_t n, char out[33])
{
	struct md5 m;
	md5_init(&m);
	md5_update(&m, data, n);
	md5_hex_final(&m, out);
}

/* MD5 of the colon-joined strings, as hex. */
static void md5_join(char out[33], int count, ...)
{
	struct md5 m;
	va_list ap;
	md5_init(&m);
	va_start(ap, count);
	for (int i = 0; i < count; i++) {
		const char *s = va_arg(ap, const char *);
		if (i) md5_update(&m, ":", 1);
		md5_update(&m, s, strlen(s));
	}
	va_end(ap);
	md5_hex_final(&m, out);
}

/* ---- credentials --------------------------------------------------------------------- */

/* camcfg and camhttpd allow 16 users; 16 * 97 bytes, twice (the table and auth_load's copy) */
#define MAX_USERS AUTH_MAX_USERS
struct cred { char user[64], ha1[33]; };
static struct cred users[MAX_USERS];
static int nusers, nskipped;
static char realm[64];

/* All or nothing: the table is replaced only by a file with at least one usable line, so a bad
 * reload (#73 auth-reload) keeps the old users rather than leaving the server with none. Usable
 * lines past MAX_USERS are counted (auth_skipped) for the caller to log. */
int auth_load(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	static struct cred nu[MAX_USERS];
	char nrealm[64] = "", line[256];
	int n = 0, over = 0;
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\r\n")] = 0;
		char *u = line, *r = strchr(u, ':'), *h = r ? strchr(r + 1, ':') : NULL;
		if (!r || !h) continue;
		*r++ = 0;
		*h++ = 0;
		if (!*u || strlen(u) >= sizeof nu[0].user || strlen(h) != 32) continue;
		if (!n) snprintf(nrealm, sizeof nrealm, "%s", r);
		else if (strcmp(nrealm, r)) continue;               /* one realm per server */
		if (n == MAX_USERS) { over++; continue; }
		snprintf(nu[n].user, sizeof nu[0].user, "%s", u);
		for (int i = 0; i < 32; i++) nu[n].ha1[i] = (char)tolower((unsigned char)h[i]);
		nu[n].ha1[32] = 0;
		n++;
	}
	fclose(f);
	if (!n) return -1;
	memcpy(users, nu, sizeof users);
	memcpy(realm, nrealm, sizeof realm);
	nusers = n;
	nskipped = over;
	return 0;
}

int auth_skipped(void) { return nskipped; }
int auth_enabled(void) { return nusers > 0; }
const char *auth_realm(void) { return realm; }

/* Value of a Digest parameter (quoted or not) from an Authorization header value. */
static int param(const char *h, const char *name, char *out, size_t cap)
{
	size_t nl = strlen(name);
	for (const char *p = h; (p = strstr(p, name)); p += nl) {
		if (p != h && p[-1] != ' ' && p[-1] != ',' && p[-1] != '\t') continue;
		const char *v = p + nl;
		while (*v == ' ') v++;
		if (*v != '=') continue;
		v++;
		while (*v == ' ') v++;
		size_t n;
		if (*v == '"') { v++; n = strcspn(v, "\""); }
		else n = strcspn(v, ", \t");
		if (n >= cap) return -1;
		memcpy(out, v, n);
		out[n] = 0;
		return 0;
	}
	return -1;
}

static int ct_equal(const char *a, const char *b, size_t n)
{
	unsigned d = 0;
	for (size_t i = 0; i < n; i++) d |= (unsigned)(a[i] ^ b[i]);
	return d == 0;
}

int auth_check(const char *authz, const char *method, const char *nonce, char *who, size_t cap)
{
	char user[64], rlm[64], hnonce[64], uri[256], resp[40], qop[16], nc[16], cnonce[128],
	     ha2[33], want[33];
	if (who && cap) *who = 0;
	if (strncasecmp(authz, "Digest ", 7)) return 0;
	authz += 7;
	if (param(authz, "username", user, sizeof user) || param(authz, "realm", rlm, sizeof rlm) ||
	    param(authz, "nonce", hnonce, sizeof hnonce) || param(authz, "uri", uri, sizeof uri) ||
	    param(authz, "response", resp, sizeof resp))
		return 0;
	if (who) snprintf(who, cap, "%s", user);
	if (strcmp(rlm, realm) || strcmp(hnonce, nonce) || strlen(resp) != 32) return 0;
	const char *ha1 = NULL;
	for (int i = 0; i < nusers; i++)
		if (!strcmp(users[i].user, user)) ha1 = users[i].ha1;
	if (!ha1) return 0;
	md5_join(ha2, 2, method, uri);
	if (!param(authz, "qop", qop, sizeof qop)) {
		if (strcmp(qop, "auth") || param(authz, "nc", nc, sizeof nc) ||
		    param(authz, "cnonce", cnonce, sizeof cnonce))
			return 0;
		md5_join(want, 6, ha1, nonce, nc, cnonce, qop, ha2);
	} else {
		md5_join(want, 3, ha1, nonce, ha2);
	}
	for (int i = 0; i < 32; i++) resp[i] = (char)tolower((unsigned char)resp[i]);
	return ct_equal(want, resp, 32);
}
