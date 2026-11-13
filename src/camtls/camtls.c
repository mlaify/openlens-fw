/* SPDX-License-Identifier: MIT */
/*
 * camtls: the camera's TLS front end (docs/PLAN-TLS.md §B, D). It terminates TLS 1.2/1.3 with
 * mbedTLS 3.6 (our overlay src/camtls/mbedtls-user-config.h, scripts/build-camtls.sh) on one or
 * more TCP ports and passes the plain bytes of each to a UNIX socket, prefixed with a PROXY v1
 * line that names the client: 443 -> camhttpd (HTTPS), 322 -> rtspd (RTSPS). It holds no
 * passwords: camhttpd and rtspd parse and authenticate as before.
 *
 *   camtls -k KEY -c CERT -U USER -L PORT:SOCKET[:http|rtsp] [-L ...] [-l ADDR] [-r READYFILE] [-v]
 *     -k/-c the server key and certificate (PEM; root-only files, read before the drop)
 *     -L a listener: TCP PORT to the UNIX SOCKET, with the limits of its kind (http, or rtsp;
 *        by default rtsp for port 322, http otherwise); up to MAX_LISTEN of them
 *     -p PORT -s SOCKET  shorthand for -L PORT:SOCKET (-p defaults to 443)
 *     -U the user to run as (camtls)   -l IPv4 address to listen on (any)
 *     -r written with our pid once ready (removed at exit)   -v one log line per connection
 *   camtls gen-ca OUTDIR | issue CADIR IP OUTDIR | check DIR [IP]     (helpers, see "---- helpers")
 *
 * As root it seeds the DRBG, loads the key and certificate, binds the ports, then drops to USER
 * with no capabilities (src/rtspd/drop.h), checks setuid(0) fails, writes READYFILE and serves.
 * Exit 3 means "renew and restart me" (camtls-run, root, runs camcfg tls renew): eth0's IPv4
 * (checked at start and every 60 s) differs from the certificate's IP SAN, or the certificate
 * ends within 30 days (at start and hourly; not while the clock is unset, before BUILD_EPOCH).
 *
 * TLS: server only; 1.2 and 1.3; TLS 1.3 ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM and TLS 1.2
 * ECDHE-ECDSA with the same three, in that order (the Cortex-A7 has no AES instructions; TLS 1.2
 * takes our order, TLS 1.3 in mbedTLS takes the client's); groups X25519, P-256; signatures
 * ECDSA-P256-SHA256 only; session tickets (ChaCha20-Poly1305 key in memory, a new key every 24 h,
 * 2 tickets per TLS 1.3 handshake); no renegotiation (compiled out).
 *
 * One select() loop, no threads. A connection's life:
 *   accepted -> waiting (over a limit: un-handshaken, up to WAIT_MS, then closed) -> handshake
 *   (HS_MS) -> first request bytes (FIRST_MS) -> backend connect (non-blocking; a full backlog
 *   or a missing socket is retried every 50 ms for 5 s, then an HTTP 503 over TLS, or for rtsp
 *   just close_notify) -> relay (closed after the kind's idle time with no byte either way;
 *   never while bytes flow) -> close_notify when the backend closes.
 * Limits per listener kind:
 *   http (443): 6 connections past the waiting stage (= camhttpd's MAX_CLIENTS), 4 per client
 *               address (= its PER_PEER: page, CSS, script, preview), idle 120 s;
 *   rtsp (322): 4 (= rtspd's slots; SSS holds 2), 2 per address while not yet relaying (a
 *               session's TCP connection lives for hours), idle 10 min (rtspd ends a dead
 *               session itself; keepalives are RTCP or GET_PARAMETER).
 * Shared: MAX_HS handshakes at a time and a token bucket of full handshakes (a resumed one gets
 * its token back); MAX_WAIT waiting, beyond that new connections stay in the kernel backlog.
 * Back-pressure: per connection one buffer each way, C2B_CAP client->backend and B2C_CAP
 * backend->client, plus CLIENT_SNDBUF in the kernel. camtls reads the backend only when the
 * previous chunk is wholly accepted by the TLS layer (mbedtls_ssl_write returned it all; a
 * WANT_WRITE is retried with the same bytes), and reads the client only while its buffer has
 * room. So a client that stops reading stops the backend: camhttpd's preview writes a frame only
 * after the last one is out, and rtspd drops frames for a viewer whose socket buffer is full.
 */
#define _GNU_SOURCE                    /* inet_ntop, gmtime_r, getopt, fchmod... under -std=c11 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"       /* MBEDTLS_ERR_NET_* codes only (NET_C is off) */
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"     /* mbedtls_platform_zeroize */
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

#include "drop.h"                      /* drop_lookup, drop_to (src/rtspd/drop.h) */
#include "../camnet.h"                 /* CAM_NET: NET_BASE, NET_MASK, CAM_NET_STR (a build setting) */

#ifndef BUILD_EPOCH
#define BUILD_EPOCH 1761091200LL       /* rootfs/SOURCE_DATE_EPOCH: a clock before it is unset */
#endif
#ifndef MONO_MS
#define MONO_MS() mono_ms()            /* the host test moves the monotonic clock */
#endif
#ifndef WALL_NOW
#define WALL_NOW() ((long long)time(NULL))   /* ... and the wall clock (helpers, renew checks) */
#endif
#ifndef BACKEND_CONNECT
#define BACKEND_CONNECT backend_connect      /* ... and stands in for camhttpd's socket */
#endif
#ifndef IFNAME
#define IFNAME "eth0"
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0                 /* macOS (host test): SIGPIPE is ignored instead */
#endif

#define MAX_LISTEN 4
#define MAX_CONN 10                    /* past the waiting stage, all listeners: 443 + 322 (their sum <= this) */
#define HTTP_MAX 6                     /* = camhttpd's MAX_CLIENTS: more would only queue there */
#define HTTP_PER_PEER 4                /* = camhttpd's PER_PEER: page, CSS, script, preview */
#define HTTP_IDLE_MS 120000            /* relaying, no byte either way (a preview never idles) */
#define RTSP_MAX 4                     /* = rtspd's slots */
#define RTSP_PER_PEER 2                /* ... per address, counting those not yet relaying */
#define RTSP_IDLE_MS 600000
#define RTSP_PORT 322                  /* -L 322:SOCKET is rtsp unless it says otherwise */
#define MAX_HS 2                       /* handshakes at a time (an ECDSA sign + ECDHE each) */
#define MAX_WAIT 10                    /* accepted, over a limit, not yet handshaking */
#define BUCKET_RATE 10                 /* full handshakes per second, sustained ... */
#define BUCKET_BURST 20                /* ... and in a burst */
#define WAIT_MS 5000                   /* a waiting connection is closed after this */
#define HS_MS 5000                     /* handshake deadline (slowloris) */
#define FIRST_MS 10000                 /* handshaken, no request byte yet (browser preconnects) */
#define BACKEND_RETRY_MS 50            /* camhttpd's backlog full or socket missing: retry ... */
#define BACKEND_WAIT_MS 5000           /* ... for this long, then 503 */
#define CLOSE_MS 2000                  /* to get our close_notify out */
#define IFADDR_CHECK_MS 60000
#define EXPIRY_CHECK_MS 3600000LL
#define RENEW_BEFORE_S (30LL * 86400)
#define C2B_CAP (16384 + 64)           /* one full TLS record of request + the PROXY line */
#define B2C_CAP 4096                   /* = MBEDTLS_SSL_OUT_CONTENT_LEN: one record per chunk */
#define CLIENT_SNDBUF 32768            /* what the kernel queues towards a slow client (Linux
					  doubles it: 64 KiB), so video isn't seconds behind */
#define TICKET_LIFETIME_S 86400        /* ticket key rotation and ticket lifetime */
#define CA_DAYS 3653                   /* 10 years */
#define LEAF_DAYS 397                  /* Apple's limit for locally trusted roots is 398 */
/* NET_BASE/NET_MASK: CAM_NET, the camera subnet and our name constraint (src/camnet.h) */

#define LOG(...) (fputs("camtls: ", stderr), fprintf(stderr, __VA_ARGS__))

enum { ST_FREE, ST_HS, ST_FIRST, ST_CONNECTING, ST_RELAY, ST_CLOSING };
enum { K_HTTP, K_RTSP };

struct listener {
	int fd, port, kind;
	const char *path;                      /* the backend's UNIX socket */
	int max, per_peer;                     /* per_peer: rtsp counts only those not yet relaying */
	long long idle_ms;
};

struct conn {
	int state, li;                         /* li: the listener (index into lst) */
	int fd, bfd;                           /* client TCP; camhttpd UNIX socket (-1 until connected) */
	struct sockaddr_in peer, local;
	char name[24];                         /* "a.b.c.d:port" for the log */
	long long deadline;                    /* of the current state (ms, monotonic) */
	long long next_try, connect_until;     /* backend connect retries */
	long long last_io;
	int want_write;                        /* the TLS layer has bytes to flush to the client */
	int more;                              /* the last pass stopped at its round limit, not done */
	int backend_eof, resumed;
	mbedtls_ssl_context ssl;
	size_t c2b_off, c2b_len, proxy_len;
	size_t b2c_off, b2c_len;
	unsigned char c2b[C2B_CAP];
	unsigned char b2c[B2C_CAP];
};

struct waiter { int fd, li; struct sockaddr_in peer, local; long long since; };

static struct conn conns[MAX_CONN];
static struct waiter waitq[MAX_WAIT];
static int nwait;
static long long tokens = BUCKET_BURST * 1000LL, tokens_t;   /* milli-tokens */
static struct conn *cur_conn;          /* whose handshake runs: the ticket callback marks it */
static struct listener lst[MAX_LISTEN];
static int nlst, verbose;
static unsigned long stat_admitted, stat_resumed, stat_hs_fail, stat_503;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt own_crt;
static mbedtls_pk_context own_key;
static mbedtls_ssl_ticket_context tickets;
static uint32_t cert_ip;               /* the server certificate's IP SAN (host order), 0 if none */
static long long cert_not_after;       /* its notAfter, seconds since 1970 */

#ifdef CAMTLS_TEST
static int test_ctl_fd = -1;           /* the test's control socket: connections arrive on it */
static void test_ctl_read(long long now);
#endif

/* ---- small helpers -------------------------------------------------------------------------- */

static long long mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void hex(const unsigned char *b, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
	out[2 * n] = 0;
}

static const char *tls_err(int r)
{
	static char buf[128];
	if (r == MBEDTLS_ERR_NET_SEND_FAILED) return "send failed (peer gone)";  /* our bio's codes: */
	if (r == MBEDTLS_ERR_NET_RECV_FAILED) return "recv failed (peer gone)";  /* NET_C is off, so */
	mbedtls_strerror(r, buf, sizeof buf);                                    /* no strings */
	return buf;
}

/* Dotted-quad IPv4 in its one canonical spelling (no leading zeros, no shorthand) -> host order. */
static int ip4_parse(const char *s, uint32_t *ip)
{
	struct in_addr a;
	char back[INET_ADDRSTRLEN];
	if (inet_pton(AF_INET, s, &a) != 1 || !inet_ntop(AF_INET, &a, back, sizeof back) || strcmp(back, s))
		return -1;
	*ip = ntohl(a.s_addr);
	return 0;
}

static void ip4_str(uint32_t ip, char out[INET_ADDRSTRLEN])
{
	struct in_addr a = { htonl(ip) };
	inet_ntop(AF_INET, &a, out, INET_ADDRSTRLEN);
}

/* Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's days_from_civil). */
static long long days_from_civil(long long y, unsigned m, unsigned d)
{
	y -= m <= 2;
	long long era = (y >= 0 ? y : y - 399) / 400;
	unsigned yoe = (unsigned)(y - era * 400);
	unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (long long)doe - 719468;
}

static long long x509_epoch(const mbedtls_x509_time *t)
{
	return days_from_civil(t->year, (unsigned)t->mon, (unsigned)t->day) * 86400 +
	       t->hour * 3600 + t->min * 60 + t->sec;
}

/* "YYYYMMDDhhmmss" (x509write's validity format), or with iso "YYYY-MM-DDTHH:MM:SSZ" */
static void fmt_time(long long t, int iso, char *out, size_t cap)
{
	time_t tt = (time_t)t;
	struct tm tm;
	gmtime_r(&tt, &tm);
	snprintf(out, cap, iso ? "%04d-%02d-%02dT%02d:%02d:%02dZ" : "%04d%02d%02d%02d%02d%02d",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* The certificate's subjectAltName: its IPv4 addresses (the first into *ip) and other names. */
static void crt_sans(const mbedtls_x509_crt *crt, uint32_t *ip, int *nip, int *nother)
{
	*ip = 0;
	*nip = *nother = 0;
	for (const mbedtls_x509_sequence *s = &crt->subject_alt_names; s && s->buf.p; s = s->next) {
		mbedtls_x509_subject_alternative_name san;
		memset(&san, 0, sizeof san);
		if (mbedtls_x509_parse_subject_alt_name(&s->buf, &san)) { (*nother)++; continue; }
		if (san.type == MBEDTLS_X509_SAN_IP_ADDRESS && san.san.unstructured_name.len == 4) {
			const unsigned char *p = san.san.unstructured_name.p;
			if (!*nip) *ip = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
			(*nip)++;
		} else
			(*nother)++;
		mbedtls_x509_free_subject_alt_name(&san);
	}
}

/* eth0's IPv4 address (host order): 0, or -1 if it has none (DHCP not done) */
static int if_addr(const char *ifname, uint32_t *ip)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;
	memset(&ifr, 0, sizeof ifr);
	snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
	int r = ioctl(s, SIOCGIFADDR, &ifr);
	close(s);
	if (r || ifr.ifr_addr.sa_family != AF_INET) return -1;
	*ip = ntohl(((struct sockaddr_in *)(void *)&ifr.ifr_addr)->sin_addr.s_addr);
	return 0;
}

/* Why the certificate must be renewed now (camtls exits 3), or NULL. have_ip: eth0 has ip. */
static const char *need_renew(long long wall, int have_ip, uint32_t ip, char *why, size_t cap)
{
	char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], t[32];
	if (have_ip && ip != cert_ip) {
		ip4_str(ip, a);
		ip4_str(cert_ip, b);
		snprintf(why, cap, "%s is %s, the certificate names %s", IFNAME, a, b);
		return why;
	}
	if (wall >= BUILD_EPOCH && cert_not_after - wall < RENEW_BEFORE_S) {
		fmt_time(cert_not_after, 1, t, sizeof t);
		snprintf(why, cap, "the certificate ends %s (renewal is due 30 days before)", t);
		return why;
	}
	return NULL;
}

static int rng_init(void)
{
	static int done;
	if (done) return 0;
	psa_status_t ps = psa_crypto_init();            /* TLS 1.3 needs PSA; the rest may use it */
	if (ps != PSA_SUCCESS) { LOG("psa_crypto_init failed (%d)\n", (int)ps); return -1; }
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&drbg);
	int r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
				      (const unsigned char *)"camtls", 6);
	if (r) { LOG("can't seed the DRBG: %s\n", tls_err(r)); return -1; }
	done = 1;
	return 0;
}

/* ---- TLS setup ------------------------------------------------------------------------------ */

static const int suites[] = {
	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	0
};
static const uint16_t groups[] = {
	MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, MBEDTLS_SSL_IANA_TLS_GROUP_NONE
};
/* 0x0403: TLS 1.3 ecdsa_secp256r1_sha256 and TLS 1.2 ECDSA+SHA-256, the same code point */
static const uint16_t sig_algs[] = { MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256, MBEDTLS_TLS1_3_SIG_NONE };

/* A ticket that decrypts: this handshake resumes, so it gives back its token (the bucket counts
 * full handshakes; a resumed TLS 1.3 one still does ECDHE but no ECDSA signature). */
static int ticket_parse(void *p, mbedtls_ssl_session *s, unsigned char *buf, size_t len)
{
	int r = mbedtls_ssl_ticket_parse(p, s, buf, len);
	if (!r && cur_conn && !cur_conn->resumed) {
		cur_conn->resumed = 1;
		stat_resumed++;
		tokens += 1000;
		if (tokens > BUCKET_BURST * 1000LL) tokens = BUCKET_BURST * 1000LL;
	}
	return r;
}

/* PSA, the DRBG, our key and certificate (matching, an IP SAN unless any_cert) and the config. */
static int tls_init(const char *key, const char *cert, int any_cert)
{
	if (rng_init()) return -1;
	mbedtls_x509_crt_init(&own_crt);
	mbedtls_pk_init(&own_key);
	int r = mbedtls_x509_crt_parse_file(&own_crt, cert);
	if (r) { LOG("%s: %s\n", cert, tls_err(r)); return -1; }
	r = mbedtls_pk_parse_keyfile(&own_key, key, NULL, mbedtls_ctr_drbg_random, &drbg);
	if (r) { LOG("%s: %s\n", key, tls_err(r)); return -1; }
	if (mbedtls_pk_check_pair(&own_crt.pk, &own_key, mbedtls_ctr_drbg_random, &drbg)) {
		LOG("%s doesn't match %s\n", key, cert);
		return -1;
	}
	int nip, nother;
	crt_sans(&own_crt, &cert_ip, &nip, &nother);
	if (!any_cert && nip != 1) { LOG("%s: not one IPv4 subjectAltName\n", cert); return -1; }
	cert_not_after = x509_epoch(&own_crt.valid_to);

	mbedtls_ssl_config_init(&conf);
	r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
	if (r) { LOG("config: %s\n", tls_err(r)); return -1; }
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_ciphersuites(&conf, suites);
	mbedtls_ssl_conf_groups(&conf, groups);
	mbedtls_ssl_conf_sig_algs(&conf, sig_algs);
	mbedtls_ssl_conf_tls13_key_exchange_modes(&conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL |
						   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);  /* never PSK alone */
#ifdef MBEDTLS_SSL_RENEGOTIATION
	mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif
	r = mbedtls_ssl_conf_own_cert(&conf, &own_crt, &own_key);
	if (r) { LOG("own cert: %s\n", tls_err(r)); return -1; }
	mbedtls_ssl_ticket_init(&tickets);
	r = mbedtls_ssl_ticket_setup(&tickets, mbedtls_ctr_drbg_random, &drbg,
				     MBEDTLS_CIPHER_CHACHA20_POLY1305, TICKET_LIFETIME_S);
	if (r) { LOG("tickets: %s\n", tls_err(r)); return -1; }
	mbedtls_ssl_conf_session_tickets_cb(&conf, mbedtls_ssl_ticket_write, ticket_parse, &tickets);
	mbedtls_ssl_conf_new_session_tickets(&conf, 2);
	tokens_t = MONO_MS();
	return 0;
}

/* ---- connections ---------------------------------------------------------------------------- */

static int set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL);
	return fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) || fcntl(fd, F_SETFD, FD_CLOEXEC) ? -1 : 0;
}

static int bio_send(void *ctx, const unsigned char *b, size_t n)
{
	ssize_t r = send(*(int *)ctx, b, n, MSG_NOSIGNAL);
	if (r >= 0) return (int)r;
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *b, size_t n)
{
	ssize_t r = recv(*(int *)ctx, b, n, 0);
	if (r >= 0) return (int)r;                     /* 0: EOF, mbedtls says CONN_EOF */
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

/* A backend's socket: 0 with *fd connected, 1 to retry (backlog full, not there yet), -1 failed */
static int backend_connect(const char *path, int *fd)
{
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof sa.sun_path) { errno = ENAMETOOLONG; return -1; }
	strcpy(sa.sun_path, path);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || set_nonblock(s)) { if (s >= 0) close(s); return -1; }
	if (!connect(s, (struct sockaddr *)&sa, sizeof sa) || errno == EINPROGRESS) { *fd = s; return 0; }
	int e = errno;
	close(s);
	return e == EAGAIN || e == EWOULDBLOCK || e == ECONNREFUSED || e == ENOENT ? 1 : -1;
}

/* a listener's connections, and those from one address (for rtsp: not yet relaying) */
static int lst_count(int li, uint32_t addr, int *from)
{
	int n = 0;
	*from = 0;
	for (int i = 0; i < MAX_CONN; i++) {
		const struct conn *c = &conns[i];
		if (c->state == ST_FREE || c->li != li) continue;
		n++;
		if (c->peer.sin_addr.s_addr == addr &&
		    (lst[li].kind != K_RTSP || (c->state != ST_RELAY && c->state != ST_CLOSING)))
			(*from)++;
	}
	return n;
}

/* "PORT:/SOCKET[:http|rtsp]" into lst[nlst]; 0, or -1 */
static int add_listener(const char *spec)
{
	char buf[256], *path, *kind;
	struct sockaddr_un sa;
	if (nlst >= MAX_LISTEN || strlen(spec) >= sizeof buf) return -1;
	snprintf(buf, sizeof buf, "%s", spec);
	if (!(path = strchr(buf, ':'))) return -1;
	*path++ = 0;
	long port = drop_num(buf);
	if (port < 1 || port > 65535 || *path != '/') return -1;
	int k = port == RTSP_PORT ? K_RTSP : K_HTTP;
	if ((kind = strchr(path, ':'))) {
		*kind++ = 0;
		if (!strcmp(kind, "http")) k = K_HTTP;
		else if (!strcmp(kind, "rtsp")) k = K_RTSP;
		else return -1;
	}
	if (strlen(path) >= sizeof sa.sun_path) return -1;
	int sum = k == K_RTSP ? RTSP_MAX : HTTP_MAX;
	for (int i = 0; i < nlst; i++) {
		if (lst[i].port == port) return -1;
		sum += lst[i].max;
	}
	if (sum > MAX_CONN) return -1;
	struct listener *l = &lst[nlst];
	if (!(l->path = strdup(path))) return -1;
	l->fd = -1;
	l->port = (int)port;
	l->kind = k;
	l->max = k == K_RTSP ? RTSP_MAX : HTTP_MAX;
	l->per_peer = k == K_RTSP ? RTSP_PER_PEER : HTTP_PER_PEER;
	l->idle_ms = k == K_RTSP ? RTSP_IDLE_MS : HTTP_IDLE_MS;
	nlst++;
	return 0;
}

static int state_count(int st)
{
	int n = 0;
	for (int i = 0; i < MAX_CONN; i++) n += conns[i].state == st;
	return n;
}

static void conn_close(struct conn *c, const char *why)
{
	if (verbose && why) LOG("%s closed: %s\n", c->name, why);
	if (c->bfd >= 0) close(c->bfd);
	mbedtls_ssl_free(&c->ssl);
	close(c->fd);
	c->state = ST_FREE;
	c->fd = c->bfd = -1;
	if (cur_conn == c) cur_conn = NULL;
}

/* A new TCP connection on listener li: it waits (un-handshaken) until admit() lets it start. */
static void conn_accepted(int li, int fd, const struct sockaddr_in *peer, const struct sockaddr_in *local, long long now)
{
	if (nwait >= MAX_WAIT || set_nonblock(fd)) { close(fd); return; }
	int v = CLIENT_SNDBUF, one = 1;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);           /* both fail harmlessly on */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);    /* the test's socketpairs */
	struct waiter *w = &waitq[nwait++];
	w->fd = fd;
	w->li = li;
	w->peer = *peer;
	w->local = *local;
	w->since = now;
}

static void refill(long long now)
{
	if (now > tokens_t) {
		tokens += (now - tokens_t) * BUCKET_RATE;
		if (tokens > BUCKET_BURST * 1000LL) tokens = BUCKET_BURST * 1000LL;
	}
	tokens_t = now;
}

/* Start handshakes for waiting connections, oldest first, within every limit. A connection held
 * back only by its listener's or its address's limit doesn't hold back the others. */
static void admit(long long now)
{
	refill(now);
	for (int i = 0; i < nwait;) {
		struct waiter *w = &waitq[i];
		int slot = -1;
		for (int j = 0; j < MAX_CONN && slot < 0; j++) if (conns[j].state == ST_FREE) slot = j;
		if (slot < 0 || state_count(ST_HS) >= MAX_HS || tokens < 1000) return;
		int from, n = lst_count(w->li, w->peer.sin_addr.s_addr, &from);
		if (n >= lst[w->li].max || from >= lst[w->li].per_peer) { i++; continue; }
		struct conn *c = &conns[slot];
		memset(c, 0, offsetof(struct conn, c2b));      /* the offsets too: none of the last one's bytes */
		c->li = w->li;
		c->fd = w->fd;
		c->bfd = -1;
		c->peer = w->peer;
		c->local = w->local;
		char a[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &c->peer.sin_addr, a, sizeof a);
		snprintf(c->name, sizeof c->name, "%s:%u", a, ntohs(c->peer.sin_port));
		memmove(&waitq[i], &waitq[i + 1], (size_t)(nwait - i - 1) * sizeof *w);
		nwait--;
		mbedtls_ssl_init(&c->ssl);
		int r = mbedtls_ssl_setup(&c->ssl, &conf);
		if (r) {
			LOG("%s: ssl_setup: %s\n", c->name, tls_err(r));
			mbedtls_ssl_free(&c->ssl);
			close(c->fd);
			continue;
		}
		mbedtls_ssl_set_bio(&c->ssl, &c->fd, bio_send, bio_recv, NULL);
		c->state = ST_HS;
		c->deadline = now + HS_MS;
		tokens -= 1000;
		stat_admitted++;
	}
}

/* The backend didn't take the connection: an HTTP client gets a 503, an RTSP one only
 * close_notify (an RTSP reply would need the request's CSeq) */
static void conn_503(struct conn *c)
{
	static const char msg[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n"
		"Content-Length: 12\r\nConnection: close\r\nCache-Control: no-store\r\n\r\ncamera busy\n";
	int http = lst[c->li].kind == K_HTTP;
	LOG("%s: %s didn't take the connection in %d ms%s\n", c->name, lst[c->li].path, BACKEND_WAIT_MS,
	    http ? ": 503" : "");
	stat_503++;
	memcpy(c->b2c, msg, sizeof msg - 1);
	c->b2c_off = 0;
	c->b2c_len = http ? sizeof msg - 1 : 0;
	c->c2b_off = c->c2b_len = 0;
	c->backend_eof = 1;
	c->state = ST_RELAY;
}

/* Everything that can move without blocking: 0 to keep the connection, -1 to close it (*why). */
static int conn_pump(struct conn *c, long long now, const char **why)
{
	int r;
	c->want_write = c->more = 0;
	if (c->state == ST_HS) {
		cur_conn = c;
		r = mbedtls_ssl_handshake(&c->ssl);
		cur_conn = NULL;
		if (r == MBEDTLS_ERR_SSL_WANT_READ) return 0;
		if (r == MBEDTLS_ERR_SSL_WANT_WRITE) { c->want_write = 1; return 0; }
		if (r) {
			static long long last_log;
			static unsigned long quiet;
			stat_hs_fail++;
			if (verbose || now - last_log >= 1000) {        /* scanners: one line a second */
				LOG("%s handshake failed: %s (-0x%04x)%s\n", c->name, tls_err(r), (unsigned)-r,
				    quiet ? " (and others not logged)" : "");
				last_log = now;
				quiet = 0;
			} else
				quiet++;
			*why = NULL;
			return -1;
		}
		if (verbose)
			LOG("%s %s %s%s\n", c->name, mbedtls_ssl_get_version(&c->ssl),
			    mbedtls_ssl_get_ciphersuite(&c->ssl), c->resumed ? " resumed" : "");
		char ci[INET_ADDRSTRLEN], li[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &c->peer.sin_addr, ci, sizeof ci);
		inet_ntop(AF_INET, &c->local.sin_addr, li, sizeof li);
		c->c2b_len = c->proxy_len = (size_t)snprintf((char *)c->c2b, C2B_CAP, "PROXY TCP4 %s %s %u %u\r\n",
							       ci, li, ntohs(c->peer.sin_port), ntohs(c->local.sin_port));
		c->state = ST_FIRST;
		c->deadline = now + FIRST_MS;
	}
	/* at most 16 rounds, so one busy connection can't starve the others; what's left is picked up
	 * on the next pass (select sees the sockets; pending TLS bytes, or a pass cut short with a chunk
	 * read from the backend and not yet written, make it not wait) */
	int moved = 1;
	for (int rounds = 0; moved && rounds < 16; rounds++) {
		moved = 0;
		/* client -> buffer, while it has room; mbedtls may hold more of a record (check_pending),
		 * so this goes on until it says WANT_READ, not just once per readable socket */
		while (c->state != ST_CLOSING && c->c2b_len < C2B_CAP) {
			r = mbedtls_ssl_read(&c->ssl, c->c2b + c->c2b_len, C2B_CAP - c->c2b_len);
			if (r > 0) {
				c->c2b_len += (size_t)r;
				c->last_io = now;
				moved = 1;
				continue;
			}
			if (r == MBEDTLS_ERR_SSL_WANT_READ) break;
			if (r == MBEDTLS_ERR_SSL_WANT_WRITE) { c->want_write = 1; break; }
			if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_SSL_CONN_EOF) {
				*why = "client closed";
				if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) mbedtls_ssl_close_notify(&c->ssl);
				return -1;
			}
			*why = tls_err(r);
			return -1;
		}
		/* the first request bytes: now the backend gets the connection */
		if (c->state == ST_FIRST && c->c2b_len > c->proxy_len) {
			c->state = ST_CONNECTING;
			c->next_try = now;
			c->connect_until = now + BACKEND_WAIT_MS;
		}
		if (c->state == ST_CONNECTING && now >= c->next_try) {
			int fd = -1;
			r = BACKEND_CONNECT(lst[c->li].path, &fd);
			if (r == 0) {
				c->bfd = fd;
				c->state = ST_RELAY;
				c->last_io = now;
				moved = 1;
			} else if (r < 0) {
				LOG("%s: can't connect to %s: %s\n", c->name, lst[c->li].path, strerror(errno));
				conn_503(c);
				moved = 1;
			} else if (now >= c->connect_until) {
				conn_503(c);
				moved = 1;
			} else
				c->next_try = now + BACKEND_RETRY_MS;
		}
		/* buffer -> backend */
		if (c->bfd >= 0 && c->c2b_off < c->c2b_len) {
			ssize_t n = send(c->bfd, c->c2b + c->c2b_off, c->c2b_len - c->c2b_off, MSG_NOSIGNAL);
			if (n > 0) {
				c->c2b_off += (size_t)n;
				if (c->c2b_off == c->c2b_len) c->c2b_off = c->c2b_len = 0;
				moved = 1;
			} else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				c->backend_eof = 1;                    /* the backend went away: finish below */
				c->c2b_off = c->c2b_len = 0;
			}
		}
		/* the TLS write side: the same bytes again after WANT_WRITE */
		if (c->b2c_off < c->b2c_len) {
			r = mbedtls_ssl_write(&c->ssl, c->b2c + c->b2c_off, c->b2c_len - c->b2c_off);
			if (r > 0) {
				c->b2c_off += (size_t)r;
				if (c->b2c_off == c->b2c_len) c->b2c_off = c->b2c_len = 0;
				c->last_io = now;
				moved = 1;
			} else if (r == MBEDTLS_ERR_SSL_WANT_WRITE) {
				c->want_write = 1;
			} else if (r != MBEDTLS_ERR_SSL_WANT_READ) {
				*why = tls_err(r);
				return -1;
			}
		}
		/* backend -> buffer, only once the TLS write side has taken the last chunk */
		if (c->bfd >= 0 && !c->backend_eof && c->b2c_len == 0 && !c->want_write) {
			ssize_t n = recv(c->bfd, c->b2c, B2C_CAP, 0);
			if (n > 0) {
				c->b2c_len = (size_t)n;
				c->last_io = now;
				moved = 1;
			} else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
				c->backend_eof = 1;
		}
		if (c->state == ST_RELAY && c->backend_eof && c->b2c_len == 0 && !c->want_write) {
			c->state = ST_CLOSING;
			c->deadline = now + CLOSE_MS;
		}
	}
	c->more = moved;
	if (c->state == ST_RELAY) c->deadline = c->last_io + lst[c->li].idle_ms;
	if (c->state == ST_CLOSING) {
		r = mbedtls_ssl_close_notify(&c->ssl);
		if (r == MBEDTLS_ERR_SSL_WANT_WRITE) { c->want_write = 1; return 0; }
		*why = "backend closed";
		return -1;
	}
	return 0;
}

static const char *const deadline_why[] = {
	[ST_HS] = "handshake deadline", [ST_FIRST] = "no request", [ST_RELAY] = "idle",
	[ST_CLOSING] = "close_notify not sent"
};

/* One pass: expire, admit, pump every connection, then wait (at most cap_ms, -1: no cap) for the
 * sockets. Returns select's result. */
static int loop_once(long long cap_ms)
{
	long long now = MONO_MS();
	for (int i = 0; i < nwait;) {
		if (now - waitq[i].since >= WAIT_MS) {
			if (verbose) {
				char a[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &waitq[i].peer.sin_addr, a, sizeof a);
				LOG("%s:%u closed: waited %d ms over a limit\n", a, ntohs(waitq[i].peer.sin_port), WAIT_MS);
			}
			close(waitq[i].fd);
			memmove(&waitq[i], &waitq[i + 1], (size_t)(nwait - i - 1) * sizeof waitq[0]);
			nwait--;
		} else
			i++;
	}
	for (int pass = 0; pass < 2; pass++) {          /* a close frees a slot: admit and start it */
		admit(now);
		for (int i = 0; i < MAX_CONN; i++) {
			struct conn *c = &conns[i];
			const char *why = NULL;
			if (c->state == ST_FREE) continue;
			if (c->state != ST_CONNECTING && now >= c->deadline) { conn_close(c, deadline_why[c->state]); continue; }
			if (conn_pump(c, now, &why)) conn_close(c, why);
		}
	}

	fd_set rd, wr;
	FD_ZERO(&rd);
	FD_ZERO(&wr);
	int maxfd = -1;
	long long wake = now + 60000;
#define WATCH(fd, set) do { FD_SET(fd, set); if ((fd) > maxfd) maxfd = (fd); } while (0)
	for (int i = 0; i < nlst; i++)
		if (lst[i].fd >= 0 && nwait < MAX_WAIT) WATCH(lst[i].fd, &rd);
#ifdef CAMTLS_TEST
	if (test_ctl_fd >= 0 && nwait < MAX_WAIT) WATCH(test_ctl_fd, &rd);
#endif
	for (int i = 0; i < nwait; i++)
		if (waitq[i].since + WAIT_MS < wake) wake = waitq[i].since + WAIT_MS;
	if (nwait && tokens < 1000 && now + (1000 - tokens + BUCKET_RATE - 1) / BUCKET_RATE < wake)
		wake = now + (1000 - tokens + BUCKET_RATE - 1) / BUCKET_RATE;
	for (int i = 0; i < MAX_CONN; i++) {
		struct conn *c = &conns[i];
		if (c->state == ST_FREE) continue;
		long long d = c->state == ST_CONNECTING ? c->next_try : c->deadline;
		if (d < wake) wake = d;
		if (c->want_write) WATCH(c->fd, &wr);
		else if (c->state == ST_HS || (c->state != ST_CLOSING && c->c2b_len < C2B_CAP))
			WATCH(c->fd, &rd);
		if ((c->c2b_len < C2B_CAP && mbedtls_ssl_check_pending(&c->ssl)) || c->more) wake = now;
		if (c->bfd >= 0) {
			if (c->c2b_off < c->c2b_len) WATCH(c->bfd, &wr);
			if (!c->backend_eof && c->b2c_len == 0 && !c->want_write) WATCH(c->bfd, &rd);
		}
	}
#undef WATCH
	long long ms = wake - now;
	if (ms < 0) ms = 0;
	if (cap_ms >= 0 && ms > cap_ms) ms = cap_ms;
	struct timeval tv = { (time_t)(ms / 1000), (int)(ms % 1000) * 1000 };
	int n = select(maxfd + 1, &rd, &wr, NULL, &tv);
	if (n <= 0) return n;
	now = MONO_MS();
	for (int i = 0; i < nlst; i++) {
		if (lst[i].fd < 0 || !FD_ISSET(lst[i].fd, &rd)) continue;
		while (nwait < MAX_WAIT) {
			struct sockaddr_in peer, local;
			socklen_t pl = sizeof peer, ll = sizeof local;
			int fd = accept(lst[i].fd, (struct sockaddr *)&peer, &pl);
			if (fd < 0) break;
			if (peer.sin_family != AF_INET || getsockname(fd, (struct sockaddr *)&local, &ll)) { close(fd); continue; }
			conn_accepted(i, fd, &peer, &local, now);
		}
	}
#ifdef CAMTLS_TEST
	if (test_ctl_fd >= 0 && FD_ISSET(test_ctl_fd, &rd)) test_ctl_read(now);
#endif
	return n;
}

/* ---- helpers: gen-ca, issue, check (run as root by camcfg tls) ------------------------------ */

/* The CA's nameConstraints value (RFC 5280 4.2.1.10), DER: permitted iPAddress CAM_NET,
 * iPAddress ::/128 (no IPv6 address can be inside) and dNSName "invalid" (no real DNS name can
 * be inside; RFC 5280 constrains only names of a constrained type). Written back to front. */
static int nc_der(unsigned char *buf, size_t cap, const unsigned char **out, size_t *outlen)
{
	const unsigned char v4[8] = { NET_BASE >> 24, NET_BASE >> 16 & 0xff, NET_BASE >> 8 & 0xff, NET_BASE & 0xff,
				      NET_MASK >> 24, NET_MASK >> 16 & 0xff, NET_MASK >> 8 & 0xff, NET_MASK & 0xff };
	unsigned char v6[32];
	memset(v6, 0, 16);
	memset(v6 + 16, 0xff, 16);
	const struct { unsigned char tag; const unsigned char *v; size_t n; } sub[3] = {
		{ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2, (const unsigned char *)"invalid", 7 },  /* dNSName */
		{ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7, v6, sizeof v6 },                        /* iPAddress */
		{ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7, v4, sizeof v4 },
	};
	unsigned char *p = buf + cap;
	size_t len = 0;
	int ret;
	for (int i = 0; i < 3; i++) {                   /* GeneralSubtree ::= SEQUENCE { base } */
		size_t l = 0;
		MBEDTLS_ASN1_CHK_ADD(l, mbedtls_asn1_write_raw_buffer(&p, buf, sub[i].v, sub[i].n));
		MBEDTLS_ASN1_CHK_ADD(l, mbedtls_asn1_write_len(&p, buf, sub[i].n));
		MBEDTLS_ASN1_CHK_ADD(l, mbedtls_asn1_write_tag(&p, buf, sub[i].tag));
		MBEDTLS_ASN1_CHK_ADD(l, mbedtls_asn1_write_len(&p, buf, l));
		MBEDTLS_ASN1_CHK_ADD(l, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
		len += l;
	}
	/* permittedSubtrees [0] IMPLICIT GeneralSubtrees, inside NameConstraints ::= SEQUENCE */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	*out = p;
	*outlen = len;
	return 0;
}

/* mbedTLS can't use nameConstraints, so parsing our CA needs this callback: it accepts exactly
 * our own critical nameConstraints and nothing else unknown (no global "allow unsupported"). */
static int nc_cb(void *ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid, int critical,
		 const unsigned char *p, const unsigned char *end)
{
	unsigned char buf[128];
	const unsigned char *want;
	size_t wl;
	(void)crt;
	if (!critical || MBEDTLS_OID_CMP(MBEDTLS_OID_NAME_CONSTRAINTS, oid) || nc_der(buf, sizeof buf, &want, &wl) ||
	    (size_t)(end - p) != wl || memcmp(p, want, wl))
		return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
	*(int *)ctx = 1;
	return 0;
}

static int read_file(const char *path, unsigned char *buf, size_t cap, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f) return -1;
	*len = fread(buf, 1, cap, f);
	int bad = ferror(f) || !feof(f) || *len == cap;        /* too big counts as unreadable */
	fclose(f);
	return bad ? -1 : 0;
}

/* DIR/ca.crt (one PEM certificate, ours: self-signed CA with our nameConstraints) into crt.
 * 0, or -1 with *why. */
static int load_ca(const char *dir, mbedtls_x509_crt *crt, const char **why)
{
	char path[512];
	unsigned char buf[8192];
	size_t len, used;
	snprintf(path, sizeof path, "%s/ca.crt", dir);
	if (read_file(path, buf, sizeof buf - 1, &len)) { *why = "missing ca.crt"; return -1; }
	buf[len] = 0;
	mbedtls_pem_context pem;
	mbedtls_pem_init(&pem);
	int r = mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
					buf, NULL, 0, &used);
	size_t dl;
	const unsigned char *der = r ? NULL : mbedtls_pem_get_buffer(&pem, &dl);
	int seen = 0;
	if (!der || strstr((const char *)buf + used, "-----BEGIN"))
		*why = "ca.crt is not one PEM certificate";
	else if (mbedtls_x509_crt_parse_der_with_ext_cb(crt, der, dl, 1, nc_cb, &seen))
		*why = "ca.crt doesn't parse (or has an extension we don't know)";
	else if (!seen)
		*why = "ca.crt has no name constraints";
	else if (!crt->MBEDTLS_PRIVATE(ca_istrue) || crt->MBEDTLS_PRIVATE(max_pathlen) != 1 ||  /* 1 = pathlen 0 */ crt->issuer_raw.len != crt->subject_raw.len ||
		 memcmp(crt->issuer_raw.p, crt->subject_raw.p, crt->subject_raw.len))
		*why = "ca.crt is not a self-signed CA with pathlen 0";
	else
		*why = NULL;
	mbedtls_pem_free(&pem);
	return *why ? -1 : 0;
}

/* Write dir/name atomically (a temporary file, fsync, rename) with mode; 0 or -1. */
static int write_file(const char *dir, const char *name, const void *data, size_t len, mode_t mode)
{
	char tmp[512], path[512];
	snprintf(tmp, sizeof tmp, "%s/.%s.tmp", dir, name);
	snprintf(path, sizeof path, "%s/%s", dir, name);
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
	if (fd < 0) { LOG("%s: %s\n", tmp, strerror(errno)); return -1; }
	const unsigned char *p = data;
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n <= 0) break;
		off += (size_t)n;
	}
	if (off != len || fchmod(fd, mode) || fsync(fd) || close(fd)) {
		LOG("%s: %s\n", tmp, strerror(errno));
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path)) { LOG("%s: %s\n", path, strerror(errno)); unlink(tmp); return -1; }
	return 0;
}

static int gen_key(mbedtls_pk_context *pk)
{
	int r = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (!r) r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, &drbg);
	if (r) LOG("key generation: %s\n", tls_err(r));
	return r ? -1 : 0;
}

static int write_key(const char *dir, const char *name, mbedtls_pk_context *pk)
{
	unsigned char pem[1024];
	int r = mbedtls_pk_write_key_pem(pk, pem, sizeof pem);
	if (!r) r = write_file(dir, name, pem, strlen((char *)pem), 0600);
	mbedtls_platform_zeroize(pem, sizeof pem);
	return r ? -1 : 0;
}

/* notBefore for a new certificate: a day before now, or before the build if the clock is unset
 * (no RTC: every boot starts in the past), so a browser with a right clock accepts it at once */
static long long not_before(void)
{
	long long now = WALL_NOW();
	return (now > BUILD_EPOCH ? now : BUILD_EPOCH) - 86400;
}

/* Sign w into PEM, parse it back (a check of what we wrote) and write dir/name (0644). The DER's
 * SHA-256 into fp (hex). */
static int finish_crt(mbedtls_x509write_cert *w, const char *dir, const char *name, int is_ca, char fp[65])
{
	unsigned char pem[4096], d[32];
	int r = mbedtls_x509write_crt_pem(w, pem, sizeof pem, mbedtls_ctr_drbg_random, &drbg);
	if (r) { LOG("signing %s: %s\n", name, tls_err(r)); return -1; }
	mbedtls_x509_crt back;
	mbedtls_x509_crt_init(&back);
	int seen = 0;
	mbedtls_pem_context pc;
	mbedtls_pem_init(&pc);
	size_t used, dl;
	r = mbedtls_pem_read_buffer(&pc, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pem, NULL, 0, &used);
	const unsigned char *der = r ? NULL : mbedtls_pem_get_buffer(&pc, &dl);
	if (!der || mbedtls_x509_crt_parse_der_with_ext_cb(&back, der, dl, 1, nc_cb, &seen) || seen != is_ca) {
		LOG("%s doesn't parse back\n", name);
		r = -1;
	} else {
		mbedtls_sha256(back.raw.p, back.raw.len, d, 0);
		hex(d, sizeof d, fp);
		r = write_file(dir, name, pem, strlen((char *)pem), 0644);
	}
	mbedtls_pem_free(&pc);
	mbedtls_x509_crt_free(&back);
	return r;
}

/* serial: 16 bytes, top bit clear (positive) and the next set (DER needs no leading zero) */
static int set_serial(mbedtls_x509write_cert *w)
{
	unsigned char s[16];
	if (mbedtls_ctr_drbg_random(&drbg, s, sizeof s)) return -1;
	s[0] = (unsigned char)((s[0] & 0x7f) | 0x40);
	return mbedtls_x509write_crt_set_serial_raw(w, s, sizeof s);
}

/* gen-ca names a new CA O=openlens-fw. A CA made before the rename (O=cam-firmware-dev) is still
 * read and still signs: issue copies the O that the CA's own subject carries into the issuer. */
#define CA_ORG "openlens-fw"
#define CA_ORG_LEGACY "cam-firmware-dev"
static const char *const ca_dn_fmt = "CN=camera CA %.8s,O=%s";

static const char *ca_org(const mbedtls_x509_buf *v)    /* CA_ORG or CA_ORG_LEGACY if v is one, else NULL */
{
	static const char *const orgs[] = { CA_ORG, CA_ORG_LEGACY };
	for (size_t i = 0; i < sizeof orgs / sizeof orgs[0]; i++)
		if (v->len == strlen(orgs[i]) && !memcmp(v->p, orgs[i], v->len)) return orgs[i];
	return NULL;
}

static int helper_gen_ca(const char *dir)
{
	char path[512];
	snprintf(path, sizeof path, "%s/ca.key", dir);
	if (!access(path, F_OK)) { LOG("%s exists: a new CA is made only into an empty directory\n", path); return 2; }
	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	mbedtls_x509write_cert w;
	mbedtls_x509write_crt_init(&w);
	int rc = 1;
	unsigned char spki[200], d[32], ncbuf[128];
	char fp8[65], dn[96], t0[16], t1[16], fp[65];
	const unsigned char *nc;
	size_t ncl;
	if (rng_init() || gen_key(&key)) goto out;
	int l = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);  /* at the end of spki */
	if (l <= 0) goto out;
	mbedtls_sha256(spki + sizeof spki - l, (size_t)l, d, 0);
	hex(d, 4, fp8);
	snprintf(dn, sizeof dn, ca_dn_fmt, fp8, CA_ORG);
	long long nb = not_before();
	fmt_time(nb, 0, t0, sizeof t0);
	fmt_time(nb + CA_DAYS * 86400LL, 0, t1, sizeof t1);
	mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&w, &key);
	mbedtls_x509write_crt_set_issuer_key(&w, &key);
	if (set_serial(&w) || mbedtls_x509write_crt_set_validity(&w, t0, t1) ||
	    mbedtls_x509write_crt_set_subject_name(&w, dn) || mbedtls_x509write_crt_set_issuer_name(&w, dn) ||
	    mbedtls_x509write_crt_set_basic_constraints(&w, 1, 0) ||          /* critical (is_ca) */
	    mbedtls_x509write_crt_set_key_usage(&w, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN) ||
	    mbedtls_x509write_crt_set_subject_key_identifier(&w) ||
	    nc_der(ncbuf, sizeof ncbuf, &nc, &ncl) ||
	    mbedtls_x509write_crt_set_extension(&w, MBEDTLS_OID_NAME_CONSTRAINTS,
						MBEDTLS_OID_SIZE(MBEDTLS_OID_NAME_CONSTRAINTS), 1, nc, ncl)) {
		LOG("building the CA certificate failed\n");
		goto out;
	}
	if (write_key(dir, "ca.key", &key) || finish_crt(&w, dir, "ca.crt", 1, fp)) goto out;
	printf("ok ca_fp=%s\n", fp);
	rc = 0;
out:
	mbedtls_x509write_crt_free(&w);
	mbedtls_pk_free(&key);
	return rc;
}

static int helper_issue(const char *cadir, const char *ipstr, const char *dir)
{
	uint32_t ip;
	if (ip4_parse(ipstr, &ip) || (ip & NET_MASK) != NET_BASE) {
		LOG("%s: not an address in " CAM_NET_STR ": refused\n", ipstr);
		return 2;
	}
	mbedtls_x509_crt ca;
	mbedtls_x509_crt_init(&ca);
	mbedtls_pk_context cakey, key;
	mbedtls_pk_init(&cakey);
	mbedtls_pk_init(&key);
	mbedtls_x509write_cert w;
	mbedtls_x509write_crt_init(&w);
	int rc = 1, reused = 0;
	char path[512], cn[32], fp8[16], t0[16], t1[16], iso[32], fp[65], dn[96];
	const char *why;
	if (rng_init()) goto out;
	if (load_ca(cadir, &ca, &why)) { LOG("%s: %s\n", cadir, why); goto out; }
	snprintf(path, sizeof path, "%s/ca.key", cadir);
	int r = mbedtls_pk_parse_keyfile(&cakey, path, NULL, mbedtls_ctr_drbg_random, &drbg);
	if (r || mbedtls_pk_check_pair(&ca.pk, &cakey, mbedtls_ctr_drbg_random, &drbg)) {
		LOG("%s: %s\n", path, r ? tls_err(r) : "doesn't match ca.crt");
		goto out;
	}
	/* the issuer DN exactly as gen-ca wrote it: our CA's CN and one O (ours, or the pre-rename one),
	 * nothing else */
	fp8[0] = 0;
	int other = 0;
	const char *org = NULL;
	for (const mbedtls_x509_name *n = &ca.subject; n && n->oid.p; n = n->next) {
		int hex8 = n->val.len == 18 && !memcmp(n->val.p, "camera CA ", 10);
		for (int i = 10; hex8 && i < 18; i++) hex8 = n->val.p[i] && strchr("0123456789abcdef", n->val.p[i]);
		if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &n->oid) && hex8)
			snprintf(fp8, sizeof fp8, "%.8s", (const char *)n->val.p + 10);
		else if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_ORGANIZATION, &n->oid) || org || !(org = ca_org(&n->val)))
			other = 1;
	}
	if (!fp8[0] || !org || other) { LOG("%s/ca.crt: not a camtls CA name\n", cadir); goto out; }
	snprintf(dn, sizeof dn, ca_dn_fmt, fp8, org);
	snprintf(path, sizeof path, "%s/server.key", cadir);
	if (!access(path, F_OK)) {
		r = mbedtls_pk_parse_keyfile(&key, path, NULL, mbedtls_ctr_drbg_random, &drbg);
		if (r || mbedtls_pk_get_type(&key) != MBEDTLS_PK_ECKEY ||
		    mbedtls_ecp_keypair_get_group_id(mbedtls_pk_ec(key)) != MBEDTLS_ECP_DP_SECP256R1) {
			LOG("%s: %s\n", path, r ? tls_err(r) : "not a P-256 key");
			goto out;
		}
		reused = 1;
	} else if (gen_key(&key) || write_key(dir, "server.key", &key))
		goto out;
	long long nb = not_before(), na = nb + LEAF_DAYS * 86400LL;
	fmt_time(nb, 0, t0, sizeof t0);
	fmt_time(na, 0, t1, sizeof t1);
	snprintf(cn, sizeof cn, "CN=%s", ipstr);
	unsigned char ipb[4] = { (unsigned char)(ip >> 24), (unsigned char)(ip >> 16), (unsigned char)(ip >> 8), (unsigned char)ip };
	mbedtls_x509_san_list san = { 0 };
	san.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
	san.node.san.unstructured_name.p = ipb;
	san.node.san.unstructured_name.len = sizeof ipb;
	mbedtls_asn1_sequence eku = { 0 };
	eku.buf.tag = MBEDTLS_ASN1_OID;
	eku.buf.p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH;
	eku.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
	mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&w, &key);
	mbedtls_x509write_crt_set_issuer_key(&w, &cakey);
	if (set_serial(&w) || mbedtls_x509write_crt_set_validity(&w, t0, t1) ||
	    mbedtls_x509write_crt_set_subject_name(&w, cn) || mbedtls_x509write_crt_set_issuer_name(&w, dn) ||
	    mbedtls_x509write_crt_set_basic_constraints(&w, 0, -1) ||
	    mbedtls_x509write_crt_set_key_usage(&w, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
	    mbedtls_x509write_crt_set_ext_key_usage(&w, &eku) ||
	    mbedtls_x509write_crt_set_subject_alternative_name(&w, &san) ||
	    mbedtls_x509write_crt_set_subject_key_identifier(&w) ||
	    mbedtls_x509write_crt_set_authority_key_identifier(&w)) {
		LOG("building the server certificate failed\n");
		goto out;
	}
	if (finish_crt(&w, dir, "server.crt", 0, fp)) goto out;
	fmt_time(na, 1, iso, sizeof iso);
	printf("ok san=%s not_after=%s fp=%s key=%s\n", ipstr, iso, fp, reused ? "reused" : "new");
	rc = 0;
out:
	mbedtls_x509write_crt_free(&w);
	mbedtls_pk_free(&key);
	mbedtls_pk_free(&cakey);
	mbedtls_x509_crt_free(&ca);
	return rc;
}

/* check: one line on stdout; 0 ok, 1 renew, 2 bad */
static int helper_check(const char *dir, const char *ipstr)
{
	mbedtls_x509_crt ca, srv;
	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&srv);
	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	char crtp[512], keyp[512], s1[INET_ADDRSTRLEN], na[32], cafp[65], fp[65], info[256];
	unsigned char d[32];
	const char *why;
	uint32_t want = 0, ip;
	int rc = 2, nip, nother;
	if (ipstr && ip4_parse(ipstr, &want)) { printf("bad usage: %s is not an IPv4 address\n", ipstr); goto out; }
	if (rng_init()) { printf("bad no random numbers\n"); goto out; }
	if (load_ca(dir, &ca, &why)) { printf("bad %s\n", why); goto out; }
	snprintf(crtp, sizeof crtp, "%s/server.crt", dir);
	snprintf(keyp, sizeof keyp, "%s/server.key", dir);
	if (access(crtp, F_OK)) { printf("renew missing server.crt\n"); rc = 1; goto out; }
	if (access(keyp, F_OK)) { printf("renew missing server.key\n"); rc = 1; goto out; }
	if (mbedtls_x509_crt_parse_file(&srv, crtp) || srv.next) { printf("bad server.crt is not one certificate\n"); goto out; }
	if (mbedtls_pk_parse_keyfile(&key, keyp, NULL, mbedtls_ctr_drbg_random, &drbg)) { printf("bad server.key doesn't parse\n"); goto out; }
	if (mbedtls_pk_check_pair(&srv.pk, &key, mbedtls_ctr_drbg_random, &drbg)) {
		printf("bad server.key doesn't match server.crt\n");
		goto out;
	}
	uint32_t flags = 0;
	mbedtls_x509_crt_verify(&srv, &ca, NULL, NULL, &flags, NULL, NULL);
	flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);  /* dates: below */
	if (flags) {
		mbedtls_x509_crt_verify_info(info, sizeof info, "", flags);
		info[strcspn(info, "\n")] = 0;
		printf("bad server.crt doesn't verify against ca.crt: %s\n", info);
		goto out;
	}
	crt_sans(&srv, &ip, &nip, &nother);
	if (nip != 1 || nother || (ip & NET_MASK) != NET_BASE || srv.MBEDTLS_PRIVATE(ca_istrue) ||
	    mbedtls_x509_crt_check_extended_key_usage(&srv, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH))) {
		printf("bad server.crt is not a server certificate for one address in " CAM_NET_STR "\n");
		goto out;
	}
	ip4_str(ip, s1);
	long long now = WALL_NOW(), nb = x509_epoch(&srv.valid_from), end = x509_epoch(&srv.valid_to);
	fmt_time(end, 1, na, sizeof na);
	rc = 1;
	if (ipstr && ip != want) { printf("renew ip san=%s want=%s\n", s1, ipstr); goto out; }
	if (now >= BUILD_EPOCH && now < nb) { printf("renew not-yet-valid san=%s\n", s1); goto out; }
	if (now >= BUILD_EPOCH && end - now < RENEW_BEFORE_S) { printf("renew expiring not_after=%s\n", na); goto out; }
	mbedtls_sha256(ca.raw.p, ca.raw.len, d, 0);
	hex(d, sizeof d, cafp);
	mbedtls_sha256(srv.raw.p, srv.raw.len, d, 0);
	hex(d, sizeof d, fp);
	printf("ok san=%s not_after=%s ca_fp=%s fp=%s\n", s1, na, cafp, fp);
	rc = 0;
out:
	mbedtls_pk_free(&key);
	mbedtls_x509_crt_free(&srv);
	mbedtls_x509_crt_free(&ca);
	return rc;
}

/* ---- daemon ----------------------------------------------------------------------------------- */

static volatile sig_atomic_t stop;
static void on_term(int sig) { (void)sig; stop = 1; }

static void usage(void)
{
	fprintf(stderr, "usage: camtls -k KEY -c CERT -U USER -L PORT:SOCKET[:http|rtsp] [-L ...] [-l ADDR]\n"
		"              [-r READYFILE] [-v]        (-p PORT -s SOCKET: one -L PORT:SOCKET, port 443)\n"
		"       camtls gen-ca OUTDIR | issue CADIR IP OUTDIR | check DIR [IP]\n");
}

static int daemon_main(int argc, char **argv)
{
	const char *key = NULL, *cert = NULL, *user = NULL, *ready = NULL, *laddr = NULL, *sock = NULL;
	const char *port = "443";
	int o;
	while ((o = getopt(argc, argv, "k:c:s:U:p:L:l:r:v")) != -1) {
		switch (o) {
		case 'k': key = optarg; break;
		case 'c': cert = optarg; break;
		case 's': sock = optarg; break;
		case 'p': port = optarg; break;
		case 'L':
			if (add_listener(optarg)) {
				LOG("-L %s: PORT:/SOCKET[:http|rtsp] wanted, ports unique, at most %d listeners "
				    "and %d connections in all\n", optarg, MAX_LISTEN, MAX_CONN);
				return 1;
			}
			break;
		case 'U': user = optarg; break;
		case 'l': laddr = optarg; break;
		case 'r': ready = optarg; break;
		case 'v': verbose = 1; break;
		default: usage(); return 1;
		}
	}
	if (sock) {
		char spec[300];
		snprintf(spec, sizeof spec, "%s:%s", port, sock);
		if (add_listener(spec)) { LOG("-p %s -s %s: refused\n", port, sock); return 1; }
	}
	if (optind != argc || !key || !cert || !user || !nlst) { usage(); return 1; }
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	if (laddr && inet_pton(AF_INET, laddr, &sa.sin_addr) != 1) { LOG("-l %s: not an IPv4 address\n", laddr); return 1; }
	struct drop_id id;
	const char *why;
	if (drop_lookup(user, "/etc/passwd", "/etc/group", &id, &why)) { LOG("-U %s: %s\n", user, why); return 1; }
	signal(SIGPIPE, SIG_IGN);
	struct sigaction act;
	memset(&act, 0, sizeof act);
	act.sa_handler = on_term;                       /* no SA_RESTART: select returns EINTR */
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	if (tls_init(key, cert, 0)) return 1;

	char reason[160];
	uint32_t ip = 0;
	int have = !if_addr(IFNAME, &ip);
	if (need_renew(WALL_NOW(), have, ip, reason, sizeof reason)) { LOG("%s: exit 3 (renew)\n", reason); return 3; }

	for (int i = 0; i < nlst; i++) {
		int one = 1, fd = lst[i].fd = socket(AF_INET, SOCK_STREAM, 0);
		sa.sin_port = htons((uint16_t)lst[i].port);
		if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) ||
		    bind(fd, (struct sockaddr *)&sa, sizeof sa) || listen(fd, 16) || set_nonblock(fd)) {
			LOG("listen on port %d: %s\n", lst[i].port, strerror(errno));
			return 1;
		}
	}
	/* a lower priority than rtspd, so a burst of handshakes (about 30 ms of CPU each on the A7)
	 * never starves the video; the image's BusyBox has no nice applet, and lowering is allowed
	 * after the drop too, but raising it again isn't */
	if (setpriority(PRIO_PROCESS, 0, 5)) LOG("setpriority: %s (running at the default priority)\n", strerror(errno));
	if (drop_to(&id, -1, &why)) { LOG("drop to %s: %s\n", user, why); return 1; }
	if (!setuid(0) || !geteuid()) { LOG("still root after the drop\n"); return 1; }
	if (ready) {
		char pid[24];
		int n = snprintf(pid, sizeof pid, "%ld\n", (long)getpid());
		int fd = open(ready, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
		if (fd < 0 || write(fd, pid, (size_t)n) != n || close(fd)) { LOG("%s: %s\n", ready, strerror(errno)); return 1; }
	}
	char cip[INET_ADDRSTRLEN];
	ip4_str(cert_ip, cip);
	for (int i = 0; i < nlst; i++)
		LOG("port %d (%s) -> %s\n", lst[i].port, lst[i].kind == K_RTSP ? "rtsp" : "http", lst[i].path);
	LOG("ready for %s as %s\n", cip, user);

	int rc = 0;
	long long next_ip = MONO_MS() + IFADDR_CHECK_MS, next_exp = MONO_MS() + EXPIRY_CHECK_MS;
	while (!stop) {
		loop_once(-1);
		long long now = MONO_MS();
		if (now >= next_ip || now >= next_exp) {
			have = now >= next_ip && !if_addr(IFNAME, &ip);
			if (now >= next_ip) next_ip = now + IFADDR_CHECK_MS;
			if (now >= next_exp) next_exp = now + EXPIRY_CHECK_MS;
			if (need_renew(WALL_NOW(), have, ip, reason, sizeof reason)) {
				LOG("%s: exit 3 (renew)\n", reason);
				rc = 3;
				break;
			}
		}
	}
	if (ready) unlink(ready);
	LOG("exit %d (%lu handshakes started, %lu resumed, %lu failed, %lu 503)\n", rc, stat_admitted,
	    stat_resumed, stat_hs_fail, stat_503);
	return rc;
}

static int camtls_main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc >= 2 && !strcmp(argv[1], "gen-ca")) {
		if (argc != 3) { usage(); return 2; }
		return helper_gen_ca(argv[2]);
	}
	if (argc >= 2 && !strcmp(argv[1], "issue")) {
		if (argc != 5) { usage(); return 2; }
		return helper_issue(argv[2], argv[3], argv[4]);
	}
	if (argc >= 2 && !strcmp(argv[1], "check")) {
		if (argc != 3 && argc != 4) { printf("bad usage\n"); return 2; }
		return helper_check(argv[2], argc == 4 ? argv[3] : NULL);
	}
	return daemon_main(argc, argv);
}

#ifndef CAMTLS_TEST
int main(int argc, char **argv) { return camtls_main(argc, argv); }
#endif
