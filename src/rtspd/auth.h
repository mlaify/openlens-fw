/* SPDX-License-Identifier: MIT */
/* auth.h: RTSP Digest authentication for rtspd (see auth.c). */
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_MAX_USERS 16               /* as camcfg and camhttpd */

/* Loads an htdigest file ("user:realm:HA1" lines, one realm). 0 on success, -1 if no users. */
int auth_load(const char *path);

/* Usable lines past AUTH_MAX_USERS that the last successful auth_load left out (no RTSP access). */
int auth_skipped(void);

int auth_enabled(void);
const char *auth_realm(void);

/* 1 if `authz` (the Authorization header value) is a valid Digest response for `method` and the
 * connection's `nonce`; `who` gets the claimed user name either way (for logs). */
int auth_check(const char *authz, const char *method, const char *nonce, char *who, size_t cap);

void md5_hex(const void *data, size_t n, char out[33]);

#endif
