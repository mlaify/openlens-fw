/* SPDX-License-Identifier: MIT */
/*
 * camhttpd: the camera's small HTTP server (#74, #75): ONVIF Profile S (Device + Media ver10),
 * WS-Discovery and /snapshot.jpg, so Surveillance Station can add the camera as a generic ONVIF
 * camera. rtspd owns the video hardware; camhttpd only reads the config files and asks rtspd for
 * a JPEG over its root-only control socket ("snapshot" -> "ok <bytes>", file in /run/cam).
 *
 * Single thread, one select() loop: the HTTP listener, at most MAX_CLIENTS connections (one
 * request each, Connection: close, request <= 64 KiB, header/body/send timeouts) and the
 * WS-Discovery socket (UDP 3702, 239.255.255.250 on eth0). No heap use of our own.
 *
 * Auth follows the ONVIF access classes. PRE_AUTH operations need nothing. Everything else needs
 * a WS-Security UsernameToken with PasswordDigest (PasswordText is refused) or HTTP Digest (MD5,
 * qop=auth), both checked against the plaintext users file (name:role:password, camcfg).
 *   viewer   READ_SYSTEM + READ_MEDIA + /snapshot.jpg; web UI status
 *   operator viewer + ACTUATE (encoders, imaging, analytics, OSD); web UI image, OSD, streams,
 *            motion/audio
 *   admin    everything, incl. GetUsers and SetSystemDateAndTime; web UI time, users, SSH, reboot,
 *            firmware update (a signed .camfw: upload, camupdate --check, confirm, camupdate)
 * The web UI (#79) is server-rendered HTML under /ui/ with plain forms and no JavaScript, behind
 * the same HTTP Digest; every POST must come from our own page (Origin/Referer and a per-user
 * token keyed with a per-start secret). Users and SSH keys are changed by camcfg, which also owns
 * every rule about passwords and keys: the UI shows its message.
 * Wrong passwords: 5 from one address in 60 s lock it for the rest of the minute; 20 from all
 * addresses stop checks for any address where no operator or admin logged in lately (auth_blocked).
 * No account is built in (#128, docs/CLAIM.md): a camera whose users file has no admin serves only
 * /setup (first admin, optional SSH key, a recovery code shown once) for 30 minutes after power-on;
 * /recover takes that code in the same window after any power-on. Both run camcfg.
 * UsernameToken is refused while the clock is unset (no RTC), for tokens made before start, and
 * while the clock is behind the latest second it has shown (time_hw, kept over restarts).
 * ONVIF POSTs a browser could send for another site are refused (onvif_from_browser), and the web
 * UI and snapshots answer only by the camera's address (by_name_refused).
 * Settings changed over ONVIF (encoders, NTP, time zone, imaging) are saved with camcfg (fork/exec,
 * no shell). Time zone: cam.conf time.tz (a POSIX TZ string, src/rtspd/tz.h) is our TZ for what we
 * show as local time (Status, Time page, GetSystemDateAndTime's LocalDateTime); logs, UTC times and
 * every auth clock stay UTC.
 * Imaging maps to rtspd's image.* and daynight.mode; Events serves motion (rtspd "motion") to
 * PullPoint subscriptions, holding a PullMessages without blocking the loop; Analytics shows the
 * motion detector as a CellMotionEngine module and a CellMotionDetector rule (motion.sensitivity,
 * motion.mask as ActiveCells). OSD: Media's GetOSDs/GetOSD/GetOSDOptions/SetOSD/CreateOSD/DeleteOSD
 * map the two fixed overlays osd_time / osd_title onto rtspd's osd.* (src/mi/osd.c), as stock does.
 * Audio (#110): the microphone rtspd sends in both RTSP streams
 * (G.711 µ-law, 8 kHz, 64 kbit/s) as AudioSource/AudioSourceConfiguration/AudioEncoderConfiguration,
 * and the speaker rtspd plays from an RTSP backchannel (#117) as AudioOutput/AudioOutputConfiguration/
 * AudioDecoderConfiguration (profiles' Extension; DeviceIO counts it), unless audio.enabled=0.
 * Privilege separation (Gate 3, docs/CAMHTTPD-PRIVSEP.md): with -Z, a root monitor keeps every
 * password, the Digest key and the privileged operations, and the network is parsed by a worker
 * running as that user; without -Z both halves run in this one process, through the same
 * messages ("---- privilege separation", near the end).
 * HTTPS (docs/PLAN-TLS.md B, D): with -t, camtls terminates TLS on 443 and hands each connection to
 * us over a UNIX socket, starting with a PROXY v1 line (the client's and the camera's address); such
 * a connection is "tls" (https Origins, https:// ONVIF addresses, rtsps:// stream URIs). While
 * camtls's ready file exists, the web UI's pages, /setup and /recover on port 80 redirect there, and
 * with cam.conf net.plain=0 port 80's ONVIF and snapshot are refused ("---- HTTPS").
 *
 *   camhttpd [-p port] [-l addr] [-r rtsp-port] [-u ctl-socket] [-U users] [-c cam.conf]
 *            [-S snapshot.jpg] [-i ifname] [-w skew-s] [-Z user|uid:gid] [-t path:user]
 *            [-T ready-file] [-D] [-v]
 *     -p HTTP port (80)          -r RTSP port in stream URIs (554)    -w UsernameToken Created
 *     -D no WS-Discovery         -i interface for discovery/ONVIF (eth0)  may lag, s (300)
 *     -Z the worker's user (a name from /etc/passwd, with its groups, or UID:GID)
 *     -t camtls's UNIX socket and the one user it may connect as (its group gets the socket)
 *     -T the file camtls makes while it serves 443 (/run/camtls/ready)
 */
#define _GNU_SOURCE                    /* memmem, strcasestr; setenv, tzset, localtime_r under -std=c11 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"                      /* md5_hex */
#include "drop.h"                      /* drop_lookup, drop_to: -Z (src/rtspd/drop.h) */
#include "streamcfg.h"                 /* stream sizes, fps range, kbps by size (src/rtspd) */
#include "tz.h"                       /* tz_valid: time.tz */

#ifndef FW_VERSION
#define FW_VERSION "dev"
#endif
#ifndef SET_TIME
#define SET_TIME(tv) settimeofday(tv, NULL)
#endif
#ifndef CTL_CMD
#define CTL_CMD ctl_cmd                /* the host test can stand in for rtspd */
#endif
#ifndef CAMCFG
#define CAMCFG "/usr/sbin/camcfg"
#endif
#ifndef RUN_CAMCFG
#define RUN_CAMCFG run_camcfg          /* ... and for camcfg */
#endif
#ifndef CAMCFG_EXEC
#define CAMCFG_EXEC camcfg_exec        /* ... and for its user and sshkey commands */
#endif
#ifndef DO_REBOOT
#define DO_REBOOT() reboot(RB_AUTOBOOT)
#endif
#ifndef CAMUPDATE
#define CAMUPDATE "/usr/sbin/camupdate"  /* the web UI's firmware update (the host test: a stub) */
#endif
#ifndef SCAN_COUNT
#define SCAN_COUNT(n) ((void)0)        /* the host test counts the bytes the parsers scan */
#endif
#ifndef HASH_COUNT
#define HASH_COUNT(n) ((void)0)        /* ... and the bytes the password checks hash */
#endif
#ifndef MONO_ADJ_MS
#define MONO_ADJ_MS 0                  /* the host test moves the monotonic clock */
#endif
#ifndef BUILD_EPOCH
#define BUILD_EPOCH 1761091200LL       /* rootfs/SOURCE_DATE_EPOCH: a clock before it is unset */
#endif
#ifndef CAMCFG_ENV
#define CAMCFG_ENV clean_env           /* camcfg backup's environment (the host test: a fake mtd0) */
#endif
#ifndef CAMCFG_MS
#define CAMCFG_MS 10000                /* a camcfg run is killed after this long (the host test: less) */
#endif
#ifndef MON_REPLY_SEEN
#define MON_REPLY_SEEN(p, n) ((void)0) /* the host test scans every reply the worker gets */
#endif

/* Measured with SSS against the stock firmware (cam #2, 2026-10-23): 1 HTTP + 1 RTSP connection
 * open at a time, ~0.7 short HTTP requests/s. The security review set 4 slots; the web UI needs
 * more: a browser opens the page's stylesheet, script and preview at once while SSS holds a pull
 * (the preview stayed grey, 2026-10-23). 6 slots (~93 KiB each), 4 per address. */
#define MAX_CLIENTS 6
#define PER_PEER 4                     /* connections from one address */
#define HDR_GRACE_MS 1000              /* a connection may wait this long for its headers before a
				  newcomer can take its slot (a browser's parallel requests can't
				  push each other out) */
#define BODY_IDLE_MS 2000              /* ... and a body that stalls this long, its slot too */
#define BODY_PER_PEER 2                /* unfinished bodies from one address */
#define REQ_CAP (64 * 1024)
#define HDR_CAP (8 * 1024)
#define OUT_CAP (28 * 1024)
#define HDR_TIMEOUT 5                  /* s from connect to the end of the headers */
#define BODY_RATE 4096                 /* then at least this many body bytes a second (+5 s) */
#define SEND_TIMEOUT 30
#define SNAP_MAX (8 << 20)
#define SNAP_REUSE_MS 1000             /* a JPEG from rtspd is served again for this long */
#define CTL_MS 500                     /* total time rtspd gets to answer a control command */
#define NONCE_LIFE 300                 /* s an HTTP Digest nonce stays fresh */
#define FAIL_MAX 5                     /* wrong passwords per address per window */
#define FAIL_GLOBAL 20                 /* wrong passwords from all addresses per window */
#define FAIL_WINDOW 60
#define GOOD_KEEP 600                  /* s a successful login exempts its address from FAIL_GLOBAL */
#define FUTURE_MAX 30                  /* s a UsernameToken Created may be ahead of the camera */
#define REALM "camera"                 /* same realm as rtspd */
#define MODEL "IPC-D240W-S"
#define NTP_MAX 3                      /* servers in time.ntp */
#define NTP_DEFAULT "time.cloudflare.com"

enum { L_PRE, L_VIEWER, L_OPERATOR, L_ADMIN };

static int http_port = 80, rtsp_port = 554, skew = 300, verbose, disco_on = 1;
static const char *ctl_path = "/run/camd.sock", *users_path = "/mnt/nand/cam/users",
		  *conf_path = "/mnt/nand/cam/cam.conf", *snap_path = "/run/cam/snapshot.jpg",
		  *ifname = "eth0";

/* -t / -T (HTTPS, "---- HTTPS"): camtls's socket, made by root before the fork, the worker's */
static const char *tls_spec;           /* -t PATH:USER as given, or NULL (no HTTPS) */
static const char *tls_ready = "/run/camtls/ready";
static int tfd = -1;                   /* the listening socket; -1 without -t or when it couldn't be made */
static uid_t tls_uid;                  /* the only peer uid it takes (USER's; never root) */

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

/* Log lines carry UTC (time.tz is only for what the UI and ONVIF show as local time). */
static void logf_(const char *fmt, ...)
{
	char ts[32];
	time_t t = time(NULL);
	struct tm g;
	if (!gmtime_r(&t, &g)) memset(&g, 0, sizeof g);
	strftime(ts, sizeof ts, "%H:%M:%S", &g);
	fprintf(stderr, "%s ", ts);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#define LOG(...) logf_(__VA_ARGS__)

static long long mono_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000LL + t.tv_nsec / 1000000 + MONO_ADJ_MS;
}

static time_t mono(void) { return (time_t)(mono_ms() / 1000); }

/* /dev/urandom stays open: mdev makes it root's (0660), and with -Z the worker isn't root when it
 * makes an upload id or a subscription. */
static int random_bytes(void *p, size_t n)
{
	static int fd = -1;
	if (fd < 0) fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	ssize_t got = fd >= 0 ? read(fd, p, n) : -1;
	return got == (ssize_t)n ? 0 : -1;
}

static int ct_eq(const void *a, const void *b, size_t n)
{
	const uint8_t *x = a, *y = b;
	unsigned d = 0;
	for (size_t i = 0; i < n; i++) d |= (unsigned)(x[i] ^ y[i]);
	return d == 0;
}

static void hex(const uint8_t *p, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", p[i]);
}

/* ---- SHA-1 (FIPS 180-4) and Base64 (RFC 4648) ------------------------------------------ */

struct sha1 { uint32_t h[5]; uint64_t len; uint8_t buf[64]; };

static void sha1_block(struct sha1 *s, const uint8_t *p)
{
	uint32_t w[80], a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 80; i++) {
		uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		w[i] = x << 1 | x >> 31;
	}
	for (int i = 0; i < 80; i++) {
		uint32_t f, k;
		if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
		else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
		else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
		else { f = b ^ c ^ d; k = 0xca62c1d6; }
		uint32_t t = (a << 5 | a >> 27) + f + e + k + w[i];
		e = d; d = c; c = b << 30 | b >> 2; b = a; a = t;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

static void sha1_init(struct sha1 *s)
{
	static const uint32_t h0[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
	memcpy(s->h, h0, sizeof h0);
	s->len = 0;
}

static void sha1_update(struct sha1 *s, const void *data, size_t n)
{
	const uint8_t *p = data;
	size_t have = (size_t)(s->len & 63);
	HASH_COUNT(n);
	s->len += n;
	while (n) {
		size_t k = 64 - have < n ? 64 - have : n;
		memcpy(s->buf + have, p, k);
		have += k; p += k; n -= k;
		if (have == 64) { sha1_block(s, s->buf); have = 0; }
	}
}

static void sha1_final(struct sha1 *s, uint8_t out[20])
{
	uint64_t bits = s->len * 8;
	uint8_t pad = 0x80, z = 0, len[8];
	sha1_update(s, &pad, 1);
	while ((s->len & 63) != 56) sha1_update(s, &z, 1);
	for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
	sha1_update(s, len, 8);
	for (int i = 0; i < 20; i++) out[i] = (uint8_t)(s->h[i / 4] >> (24 - 8 * (i % 4)));
}

static void sha1(const void *p, size_t n, uint8_t out[20])
{
	struct sha1 s;
	sha1_init(&s);
	sha1_update(&s, p, n);
	sha1_final(&s, out);
}

/* HMAC-SHA1 (RFC 2104) of msg under key (at most 64 bytes). */
static void hmac_sha1_k(const uint8_t *key, size_t kl, const void *msg, size_t n, uint8_t out[20])
{
	uint8_t pad[64], in[20];
	struct sha1 s;
	for (int pass = 0; pass < 2; pass++) {
		memset(pad, pass ? 0x5c : 0x36, sizeof pad);
		for (size_t i = 0; i < kl && i < sizeof pad; i++) pad[i] ^= key[i];
		sha1_init(&s);
		sha1_update(&s, pad, sizeof pad);
		if (pass) sha1_update(&s, in, sizeof in);
		else sha1_update(&s, msg, n);
		sha1_final(&s, pass ? out : in);
	}
}

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* out needs 4 * ((n + 2) / 3) + 1 bytes */
static void b64_enc(const uint8_t *in, size_t n, char *out)
{
	for (size_t i = 0; i < n; i += 3) {
		uint32_t x = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) |
			     (i + 2 < n ? in[i + 2] : 0);
		*out++ = b64t[x >> 18];
		*out++ = b64t[(x >> 12) & 63];
		*out++ = i + 1 < n ? b64t[(x >> 6) & 63] : '=';
		*out++ = i + 2 < n ? b64t[x & 63] : '=';
	}
	*out = 0;
}

/* Strict decode (padding required, no whitespace): byte count, or -1. */
static int b64_dec(const char *in, uint8_t *out, size_t cap)
{
	size_t n = strlen(in), o = 0;
	if (n % 4) return -1;
	for (size_t i = 0; i < n; i += 4) {
		uint32_t x = 0;
		int pad = 0;
		for (int j = 0; j < 4; j++) {
			const char *v = in[i + j] ? strchr(b64t, in[i + j]) : NULL;
			if (in[i + j] == '=' && i + 4 == n && j >= 2) { pad++; x <<= 6; continue; }
			if (!v || pad) return -1;
			x = x << 6 | (uint32_t)(v - b64t);
		}
		for (int j = 0; j < 3 - pad; j++) {
			if (o == cap) return -1;
			out[o++] = (uint8_t)(x >> (16 - 8 * j));
		}
	}
	return (int)o;
}

/* ---- dates ----------------------------------------------------------------------------- */

static long long days_from_civil(int y, int m, int d)
{
	y -= m <= 2;
	int era = (y >= 0 ? y : y - 399) / 400;
	unsigned yoe = (unsigned)(y - era * 400);
	unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
	unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097LL + doe - 719468;
}

static int date_ok(int y, int mo, int d, int h, int mi, int s)
{
	static const int mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int leap = (y % 4 == 0 && y % 100) || y % 400 == 0;
	return y >= 1970 && y <= 2099 && mo >= 1 && mo <= 12 && d >= 1 &&
	       d <= mdays[mo - 1] - (mo == 2 && !leap) && h >= 0 && h <= 23 && mi >= 0 && mi <= 59 &&
	       s >= 0 && s <= 59;
}

/* xs:dateTime "YYYY-MM-DDThh:mm:ss[.f](Z|+hh:mm|-hh:mm)" to seconds since the epoch; -1 if bad. */
static int parse_created(const char *s, long long *out)
{
	int y, mo, d, h, mi, se, n = 0;
	if (strlen(s) < 20 || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &se, &n) != 6 ||
	    n != 19 || !date_ok(y, mo, d, h, mi, se))
		return -1;
	s += 19;
	if (*s == '.') { s++; size_t k = strspn(s, "0123456789"); if (!k) return -1; s += k; }
	long off = 0;
	if (*s == 'Z') s++;
	else if ((*s == '+' || *s == '-') && isdigit((unsigned char)s[1]) && isdigit((unsigned char)s[2]) &&
		 s[3] == ':' && isdigit((unsigned char)s[4]) && isdigit((unsigned char)s[5])) {
		off = (((s[1] - '0') * 10 + s[2] - '0') * 60 + (s[4] - '0') * 10 + s[5] - '0') * 60L;
		if (*s == '-') off = -off;
		s += 6;
	} else return -1;
	if (*s) return -1;
	*out = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - off;
	return 0;
}

/* UTC as xs:dateTime, "YYYY-MM-DDThh:mm:ssZ". */
static void iso(time_t t, char out[24])
{
	struct tm g;
	gmtime_r(&t, &g);
	strftime(out, 24, "%Y-%m-%dT%H:%M:%SZ", &g);
}
/* ---- XML (just enough: local names, any prefix; bounded by `end`) ----------------------- */

/* Bytes from p up to a byte of `stop` (or NUL), never past end. Every name scan stops at '<'
 * too, so a body full of '<' costs linear time, not quadratic. */
static size_t span(const char *p, const char *end, const char *stop)
{
	const char *q = p;
	while (q < end && !strchr(stop, *q)) q++;
	SCAN_COUNT(q - p);
	return (size_t)(q - p);
}

/* Content start of the first element named `name` in [p, end); *tag gets its '<'. */
static const char *xel(const char *p, const char *end, const char *name, const char **tag)
{
	size_t nl = strlen(name);
	while (p < end && (p = memchr(p, '<', (size_t)(end - p)))) {
		const char *q = ++p, *gt;
		if (q >= end || *q == '/' || *q == '?' || *q == '!') continue;
		size_t qn = span(q, end, " \t\r\n/><");
		if (q + qn >= end) return NULL;
		const char *colon = memchr(q, ':', qn), *local = colon ? colon + 1 : q;
		if ((size_t)(q + qn - local) != nl || memcmp(local, name, nl)) continue;
		if (!(gt = memchr(q, '>', (size_t)(end - q)))) return NULL;
		if (tag) *tag = p - 1;
		return gt + 1;
	}
	return NULL;
}

/* The '<' of the first closing tag of `name` in [p, end), or end. */
static const char *xclose(const char *p, const char *end, const char *name)
{
	size_t nl = strlen(name);
	for (const char *q = p; q < end && (q = memmem(q, (size_t)(end - q), "</", 2)); q += 2) {
		const char *s = q + 2;
		size_t qn = span(s, end, " \t\r\n><");
		const char *colon = memchr(s, ':', qn), *local = colon ? colon + 1 : s;
		if (s + qn < end && (size_t)(s + qn - local) == nl && !memcmp(local, name, nl)) return q;
	}
	return end;
}

/* Trimmed, entity-decoded text of the first `name` element in [p, end). 0, or -1 if absent or
 * too long. */
static int xtext(const char *p, const char *end, const char *name, char *out, size_t cap)
{
	static const char *const ent[5][2] = { { "amp;", "&" }, { "lt;", "<" }, { "gt;", ">" },
					      { "quot;", "\"" }, { "apos;", "'" } };
	const char *c = xel(p, end, name, NULL), *e;
	size_t o = 0;
	*out = 0;                                           /* "" on every failure */
	if (!c) return -1;
	if (c[-2] == '/') return 0;                         /* <x/> */
	while (c < end && isspace((unsigned char)*c)) c++;
	for (e = c; e < end && *e != '<'; e++) {}
	if (e >= end) return -1;
	while (e > c && isspace((unsigned char)e[-1])) e--;
	while (c < e) {
		char ch = *c++;
		if (ch == '&') {
			int k = 0;
			while (k < 5 && ((size_t)(e - c) < strlen(ent[k][0]) ||
					 memcmp(c, ent[k][0], strlen(ent[k][0]))))
				k++;
			if (k == 5) { *out = 0; return -1; }
			c += strlen(ent[k][0]);
			ch = ent[k][1][0];
		}
		if (o + 1 >= cap) { *out = 0; return -1; }
		out[o++] = ch;
	}
	out[o] = 0;
	return 0;
}

/* Value of attribute `name` in the start tag at `tag`. */
static int xattr(const char *tag, const char *end, const char *name, char *out, size_t cap)
{
	const char *gt = memchr(tag, '>', (size_t)(end - tag));
	size_t nl = strlen(name);
	if (!gt) return -1;
	for (const char *p = tag + 1; p + nl + 2 < gt; p++) {
		if (!isspace((unsigned char)p[-1]) || memcmp(p, name, nl) || p[nl] != '=' ||
		    (p[nl + 1] != '"' && p[nl + 1] != '\''))
			continue;
		const char *v = p + nl + 2, *q = memchr(v, p[nl + 1], (size_t)(gt - v));
		if (!q || (size_t)(q - v) >= cap) return -1;
		memcpy(out, v, (size_t)(q - v));
		out[q - v] = 0;
		return 0;
	}
	return -1;
}

/* ---- users and stream settings -------------------------------------------------------- */

#define MAX_USERS 16

/* The privilege separation's calls (defined under "---- privilege separation"). The worker asks
 * the monitor for these; every privileged one carries the grant its request's login got. */
enum { MON_AUTH = 1, MON_SET, MON_USER, MON_SSHKEY, MON_SETTIME, MON_REBOOT, MON_UPD_BEGIN, MON_UPD_CHECK,
       MON_UPD_INSTALL, MON_CLAIM, MON_RECOVER, MON_CONF, MON_USERS, MON_BK_EXPORT, MON_BK_RESTORE, MON_BK_SETUP,
       MON_UNLOCK_CH, MON_UNLOCK, MON_NOPS };
#define MON_MSG (16 * 1024)            /* a message, either way, at most */
/* Reply statuses besides camcfg's exit status (0, 1, ...) and -1 (it couldn't run, or failed): */
#define MON_DENIED (-2)                /* unknown op; a grant missing, expired, used up or too low */
#define MON_BLOCKED (-3)               /* recover: the address is locked out */
#define MON_CLOSED (-4)                /* claim, recover, restore: the window is shut, the camera (un)claimed, the
					  rate, a reboot coming */
#define MON_AUTH_FAULT (-5)            /* auth: a wrong UsernameToken password (a fault, no challenge) */
static char mon_rbuf[MON_MSG];         /* the last reply's text, NUL-terminated */
static size_t mon_rlen;
static uint64_t req_grant;             /* the grant of the request being answered; 0: none */
static int mon_call(int op, uint64_t grant, int nf, const char *const *f, int *rfd);
static int cfg_set(const char *key, const char *val);
static int cfg_exec(int op, int nf, const char *const *f, char *out, size_t cap);
static FILE *conf_open(void);

/* The worker's account list: names and roles, never a password (MON_USERS). */
struct user { char name[33]; int role; };
static struct user users[MAX_USERS];
static int nusers;

/* Re-read on every authenticated request (the monitor reads the file each time): camcfg's
 * atomic renames are picked up at once. Lines "ROLE NAME", checked as the monitor wrote them. */
static void users_load(void)
{
	memset(users, 0, sizeof users);
	nusers = 0;
	if (mon_call(MON_USERS, 0, 0, NULL, NULL)) return;
	for (char *l = mon_rbuf, *e; *l && nusers < MAX_USERS; l = e + (*e == '\n')) {
		e = l + strcspn(l, "\n");
		size_t nl = (size_t)(e - l);
		if (nl < 3 || l[0] < '1' || l[0] > '3' || l[1] != ' ' || nl - 2 > 32) continue;
		snprintf(users[nusers].name, sizeof users[0].name, "%.*s", (int)(nl - 2), l + 2);
		users[nusers++].role = l[0] - '0';
	}
}

static const struct user *user_find(const char *name)
{
	for (int i = 0; i < nusers; i++)
		if (!strcmp(users[i].name, name)) return &users[i];
	return NULL;
}

/* The monitor's: the users file itself, passwords and all (name:role:password, camcfg). */
struct muser { char name[33], pw[65]; int role; };
static struct muser musers[MAX_USERS];
static int nmusers;

/* Re-read on every authentication: camcfg's atomic renames are picked up at once. */
static void musers_load(void)
{
	memset(musers, 0, sizeof musers);
	nmusers = 0;
	FILE *f = fopen(users_path, "r");
	if (!f) return;
	char line[160];
	while (nmusers < MAX_USERS && fgets(line, sizeof line, f)) {
		size_t n = strcspn(line, "\n");
		if (line[n] != '\n' && !feof(f)) {          /* overlong: skip the rest */
			int ch;
			while ((ch = fgetc(f)) != EOF && ch != '\n') {}
			continue;
		}
		line[n] = 0;
		char *r = strchr(line, ':'), *p = r ? strchr(r + 1, ':') : NULL;
		if (!p) continue;
		*r++ = 0;
		*p++ = 0;
		int role = !strcmp(r, "admin") ? L_ADMIN : !strcmp(r, "operator") ? L_OPERATOR :
			   !strcmp(r, "viewer") ? L_VIEWER : 0;
		size_t nl = strlen(line);                  /* names as camcfg allows them */
		if (!role || !nl || nl > 32 || strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		    "0123456789._-") != nl || !*p || strlen(p) > 64)
			continue;
		struct muser *u = &musers[nmusers++];
		snprintf(u->name, sizeof u->name, "%s", line);
		snprintf(u->pw, sizeof u->pw, "%s", p);
		u->role = role;
	}
	memset(line, 0, sizeof line);
	fclose(f);
}

static const struct muser *muser_find(const char *name)
{
	for (int i = 0; i < nmusers; i++)
		if (!strcmp(musers[i].name, name)) return &musers[i];
	return NULL;
}

struct stream { int on, w, h, fps, kbps, gop, h265; const char *profile; int kbps_set; };
static struct stream st[2];
static int audio_on = 1;               /* cam.conf audio.enabled (rtspd applies it at its start) */

/* cam.conf stream.* with rtspd's defaults and ranges (bad values ignored, like rtspd). The file
 * is what rtspd uses at its next start, and st[] what it runs: an unset kbps is the size's
 * (streamcfg.h; kbps_set 0), the sub's fps at most the main's (rtspd's stream_resolve). */
static void streams_resolve(void)
{
	for (int i = 0; i < 2; i++)
		if (!st[i].kbps_set) st[i].kbps = stream_kbps_default(i, st[i].w, st[i].h);
	if (st[1].fps > st[0].fps) st[1].fps = st[0].fps;
}

static void streams_load(void)
{
	st[0] = (struct stream){ 1, 2560, 1440, STREAM_FPS_DEFAULT, 0, 100, 0, "High", 0 };
	st[1] = (struct stream){ 1, 640, 360, STREAM_FPS_DEFAULT, 0, 100, 0, "High", 0 };
	audio_on = 1;
	FILE *f = conf_open();
	if (!f) {
		streams_resolve();
		return;
	}
	char line[640];                                    /* motion.mask lines are 268 characters */
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\r\n")] = 0;
		char *v = strchr(line, '=');
		if (!v) continue;
		*v++ = 0;
		if (!strcmp(line, "audio.enabled") && (!strcmp(v, "0") || !strcmp(v, "1"))) audio_on = *v == '1';
		int sub = !strncmp(line, "stream.sub.", 11);
		if (!sub && strncmp(line, "stream.main.", 12)) continue;
		struct stream *s = &st[sub];
		const char *k = line + (sub ? 11 : 12);
		size_t vl = strlen(v);
		int x = vl >= 1 && vl <= 5 && strspn(v, "0123456789") == vl ? atoi(v) : -1;
		if (!strcmp(k, "codec") && (!strcmp(v, "h264") || !strcmp(v, "h265"))) s->h265 = v[3] == '5';
		else if (!strcmp(k, "kbps") && x >= 64 && x <= 16384) { s->kbps = x; s->kbps_set = 1; }
		else if (!strcmp(k, "fps") && x >= 1 && x <= STREAM_FPS_MAX) s->fps = x;
		else if (!strcmp(k, "gop") && x >= 1 && x <= 1000) s->gop = x;
		else if (!strcmp(k, "profile") && !strcmp(v, "high")) s->profile = "High";
		else if (!strcmp(k, "profile") && !strcmp(v, "main")) s->profile = "Main";
		else if (!strcmp(k, "profile") && !strcmp(v, "baseline")) s->profile = "Baseline";
		else if (sub && !strcmp(k, "enabled") && (x == 0 || x == 1)) s->on = x;
		else if (!strcmp(k, "size") && stream_size_find(sub, v)) {
			s->w = stream_size_find(sub, v)->w;
			s->h = stream_size_find(sub, v)->h;
		}
	}
	fclose(f);
	streams_resolve();
}

/* The value of `key` in cam.conf: 1 if the key is there (out holds it), 0 if not. */
static int conf_get(const char *key, char *out, size_t cap)
{
	FILE *f = conf_open();
	char line[640];                                    /* motion.mask=<256 hex> fits */
	size_t kl = strlen(key);
	int found = 0;
	*out = 0;
	if (!f) return 0;
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\r\n")] = 0;
		if (strncmp(line, key, kl) || line[kl] != '=') continue;
		snprintf(out, cap, "%s", line + kl + 1);
		found = 1;                                 /* the last line wins, as for camcfg */
	}
	fclose(f);
	return found;
}

/* An NTP server as time.ntp holds it: a host name or IPv4 address, [A-Za-z0-9.-]{1,63}. */
static int ntp_name_ok(const char *n)
{
	size_t l = strlen(n);
	return l >= 1 && l <= 63 && strspn(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
					 "0123456789.-") == l && n[0] != '-' && n[0] != '.';
}

/* The NTP servers (cam.conf time.ntp, comma-separated; NTP_DEFAULT when the key is absent, none
 * when it is empty). Entries that don't validate are skipped. */
static int ntp_servers(char out[NTP_MAX][64])
{
	char v[256], *save;
	int n = 0;
	if (!conf_get("time.ntp", v, sizeof v)) snprintf(v, sizeof v, "%s", NTP_DEFAULT);
	for (char *t = strtok_r(v, ",", &save); t && n < NTP_MAX; t = strtok_r(NULL, ",", &save))
		if (ntp_name_ok(t)) snprintf(out[n++], 64, "%s", t);
	return n;
}

/* The time zone (cam.conf time.tz; UTC0 without it, or when tz.h refuses it) made this process's
 * TZ, so localtime_r gives the camera's local time. Read again on every use: camcfg may change it
 * behind us. The zone in force goes to out. Logs, ONVIF's UTC times and the auth clocks stay UTC. */
static void tz_sync(char out[TZ_BUF])
{
	static char cur[TZ_BUF];
	if (!conf_get("time.tz", out, TZ_BUF) || !tz_valid(out)) snprintf(out, TZ_BUF, "%s", TZ_DEFAULT);
	if (strcmp(out, cur) && !setenv("TZ", out, 1)) {
		tzset();
		memcpy(cur, out, TZ_BUF);
	}
}

/* t as local time: "2026-10-23 09:12:03 CDT (UTC-5, daylight saving time)"; for a zone without
 * daylight saving just "(UTC+5:30)". */
static void local_text(time_t t, char *out, size_t cap)
{
	char tz[TZ_BUF], ts[24], ab[24], off[16];
	struct tm l;
	tz_sync(tz);
	if (!localtime_r(&t, &l)) { snprintf(out, cap, "unknown"); return; }
	strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &l);
	if (!strftime(ab, sizeof ab, "%Z", &l)) *ab = 0;
	long long d = days_from_civil(l.tm_year + 1900, l.tm_mon + 1, l.tm_mday) * 86400 + l.tm_hour * 3600 +
		      l.tm_min * 60 + l.tm_sec - (long long)t;       /* local minus UTC, s */
	long long am = (d < 0 ? -d : d) / 60;
	int a = am > 48 * 60 ? 48 * 60 : (int)am;               /* minutes; tz.h keeps it under 25 h */
	if (!a) snprintf(off, sizeof off, "UTC");
	else if (a % 60) snprintf(off, sizeof off, "UTC%c%d:%02d", d < 0 ? '-' : '+', a / 60, a % 60);
	else snprintf(off, sizeof off, "UTC%c%d", d < 0 ? '-' : '+', a / 60);
	snprintf(out, cap, "%s%s%s (%s%s)", ts, *ab ? " " : "", ab, off, tz_valid(tz) < 2 ? "" :
		 l.tm_isdst > 0 ? ", daylight saving time" : ", standard time");
}

/* camcfg -d <cam.conf's directory> set KEY VALUE: fork/exec with a fixed argv, no shell, PATH
 * only. 0 if it exited 0. Blocks the loop while camcfg writes (lock, fsync, rename), CAMCFG_MS at
 * most: then it is killed and counts as a failure. */
static void dir_of(const char *path, char *dir, size_t cap)
{
	const char *slash = strrchr(path, '/');
	if (!slash) snprintf(dir, cap, ".");
	else snprintf(dir, cap, "%.*s", slash == path ? 1 : (int)(slash - path), path);
}

/* Every program camhttpd runs (camcfg, camupdate) gets this environment and nothing of ours. */
static char *const clean_env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };

/* Wait for child pid until `until` (mono ms), then SIGKILL it: 0 with *status, or -1 (killed or
 * lost). The loop still waits for camcfg, as before, but no longer than CAMCFG_MS. */
static int child_wait(pid_t pid, long long until, int *status)
{
	for (;;) {
		pid_t w = waitpid(pid, status, WNOHANG);
		if (w == pid) return 0;
		if (w < 0 && errno != EINTR) return -1;
		if (mono_ms() >= until) break;
		struct timespec nap = { 0, 5 * 1000000L };
		nanosleep(&nap, NULL);
	}
	kill(pid, SIGKILL);
	while (waitpid(pid, status, 0) < 0 && errno == EINTR) {}
	LOG("camcfg (pid %d) took over %d ms: killed\n", (int)pid, CAMCFG_MS);
	return -1;
}

static int run_camcfg(const char *key, const char *val)
{
	char dir[256];
	dir_of(conf_path, dir, sizeof dir);
	long long until = mono_ms() + CAMCFG_MS;
	pid_t pid = fork();
	if (pid < 0) return -1;
	if (pid == 0) {
		int fd = open("/dev/null", O_RDONLY);
		if (fd >= 0) dup2(fd, 0);
		for (int i = 3; i < 1024; i++) close(i);     /* no sockets for camcfg */
		char *const argv[] = { "camcfg", "-d", dir, "set", (char *)key, (char *)val, NULL };
		execve(CAMCFG, argv, clean_env);
		_exit(127);
	}
	int status;
	if (child_wait(pid, until, &status)) return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* camcfg -d DIR ARGS... (web UI: users, SSH keys) with `in` on its stdin (a password or a key
 * line: never in argv, which ps shows) and its stdout and stderr in out, so the page can show
 * camcfg's own reason. Its exit status, or -1. Blocks the loop like run_camcfg, CAMCFG_MS at most. */
static int camcfg_exec(const char *dir, const char *const *args, const char *in, char *out, size_t cap)
{
	int pin[2], pout[2], status;
	size_t got = 0;
	long long until = mono_ms() + CAMCFG_MS, left;
	*out = 0;
	if (pipe(pin)) return -1;
	if (pipe(pout)) { close(pin[0]); close(pin[1]); return -1; }
	pid_t pid = fork();
	if (pid < 0) { close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]); return -1; }
	if (pid == 0) {
		char *argv[12] = { "camcfg", "-d", (char *)dir };
		int n = 3;
		dup2(pin[0], 0);
		dup2(pout[1], 1);
		dup2(pout[1], 2);
		for (int i = 3; i < 1024; i++) close(i);     /* no sockets for camcfg */
		while (n < 11 && args[n - 3]) { argv[n] = (char *)args[n - 3]; n++; }
		argv[n] = NULL;
		execve(CAMCFG, argv, clean_env);
		_exit(127);
	}
	close(pin[0]);
	close(pout[1]);
	/* a password or a key line is far below a pipe's buffer: this write never waits on camcfg */
	if (in && write(pin[1], in, strlen(in)) < 0) { /* camcfg is gone: its status says why */ }
	close(pin[1]);
	/* its output until EOF, but not past `until`: a camcfg that hangs is killed below */
	while ((left = until - mono_ms()) > 0) {
		fd_set rf;
		struct timeval tv = { (time_t)(left / 1000), (suseconds_t)(left % 1000 * 1000) };
		char junk[256];
		FD_ZERO(&rf);
		FD_SET(pout[0], &rf);
		int s = select(pout[0] + 1, &rf, NULL, NULL, &tv);
		if (s < 0 && errno == EINTR) continue;
		if (s <= 0) break;
		ssize_t k = got < cap - 1 ? read(pout[0], out + got, cap - 1 - got) : read(pout[0], junk, sizeof junk);
		if (k == 0 || (k < 0 && errno != EINTR)) break;
		if (k > 0 && got < cap - 1) got += (size_t)k;   /* past cap: read on so camcfg isn't stuck */
	}
	out[got] = 0;
	close(pout[0]);
	if (child_wait(pid, until, &status)) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ---- the network interface ------------------------------------------------------------ */

#ifdef __linux__
static int if_info(uint8_t mac[6], struct in_addr *ip, struct in_addr *mask, int *mtu)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), rc = -1;
	memset(mac, 0, 6);
	ip->s_addr = mask->s_addr = 0;
	*mtu = 1500;
	if (fd < 0) return -1;
	memset(&ifr, 0, sizeof ifr);
	snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
	if (!ioctl(fd, SIOCGIFHWADDR, &ifr)) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	if (!ioctl(fd, SIOCGIFMTU, &ifr)) *mtu = ifr.ifr_mtu;
	if (!ioctl(fd, SIOCGIFNETMASK, &ifr)) *mask = ((struct sockaddr_in *)(void *)&ifr.ifr_netmask)->sin_addr;
	if (!ioctl(fd, SIOCGIFADDR, &ifr)) {
		*ip = ((struct sockaddr_in *)(void *)&ifr.ifr_addr)->sin_addr;
		rc = 0;
	}
	close(fd);
	return rc;
}
#else  /* host test build: documentation values, no real interface */
static int if_info(uint8_t mac[6], struct in_addr *ip, struct in_addr *mask, int *mtu)
{
	static const uint8_t m[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	memcpy(mac, m, 6);
	inet_pton(AF_INET, "192.0.2.10", ip);
	inet_pton(AF_INET, "255.255.255.0", mask);
	*mtu = 1500;
	return 0;
}
#endif

/* ---- camhttpd's own small files on DATA, beside the users file (-U) ----------------------
 * Two, both written rarely: EPR_SECRET once per camera, TIME_FLOOR at most once an hour (NAND). */

#define EPR_SECRET "epr-secret"        /* 32 random bytes keying the EndpointReference */
#define TIME_FLOOR "time-floor"        /* the latest wall-clock second seen (UsernameToken floor) */

static void data_path(const char *name, char *out, size_t cap)
{
	char dir[256];
	dir_of(users_path, dir, sizeof dir);
	snprintf(out, cap, "%s/%s", dir, name);
}

/* path's bytes (a regular file, no symlink) into buf: how many (at most cap), or -1 with errno. */
static int file_get(const char *path, void *buf, size_t cap)
{
	struct stat sb;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC), e;
	if (fd < 0) return -1;
	if (fstat(fd, &sb) || !S_ISREG(sb.st_mode)) { close(fd); errno = EINVAL; return -1; }
	ssize_t n = read(fd, buf, cap);
	e = errno;
	close(fd);
	errno = e;
	return n < 0 ? -1 : (int)n;
}

/* path = n bytes, atomically: a 0600 file beside it, fsync, rename over. 0, or -1 (nothing changed). */
static int file_put(const char *path, const void *p, size_t n)
{
	char tmp[320];
	if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) return -1;
	unlink(tmp);                                   /* left by a crash between open and rename */
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) return -1;
	int bad = write(fd, p, n) != (ssize_t)n || fsync(fd);
	if (close(fd) || bad || rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

static char epr[46];                   /* urn:uuid:..., a name-based UUID of the MAC */
static uint8_t epr_key[32];
static int epr_keyed = -1;             /* 1: EPR_SECRET read or made; 0: unusable (logged once); -1: not tried */
static int epr_fixed;                  /* the worker: made by root before the fork, its key wiped */

/* EPR_SECRET: read it, or on the first start make it from /dev/urandom. */
static void epr_key_load(void)
{
	char p[300];
	uint8_t k[33];
	data_path(EPR_SECRET, p, sizeof p);
	int n = file_get(p, k, sizeof k);
	if (n < 0 && errno == ENOENT && !random_bytes(k, 32) && !file_put(p, k, 32)) {
		LOG("made %s: it keys the EndpointReference from now on\n", p);
		n = 32;
	}
	epr_keyed = n == 32;
	if (epr_keyed) memcpy(epr_key, k, 32);
	else LOG("%s can't be read or written (%s): the EndpointReference is an unkeyed hash of the MAC\n", p,
		 n < 0 ? strerror(errno) : "not 32 bytes");
	memset(k, 0, sizeof k);
}

static void uuid_str(uint8_t b[16], int version, char out[37])
{
	b[6] = (uint8_t)((b[6] & 0x0f) | version << 4);
	b[8] = (b[8] & 0x3f) | 0x80;
	hex(b, 4, out); out[8] = '-';
	hex(b + 4, 2, out + 9); out[13] = '-';
	hex(b + 6, 2, out + 14); out[18] = '-';
	hex(b + 8, 2, out + 19); out[23] = '-';
	hex(b + 10, 6, out + 24);
}

/* Stable across reboots and unique per camera: HMAC-SHA1(EPR_SECRET, prefix + MAC), so without the
 * secret the MAC can't be found from it (an unkeyed hash falls to a sweep of the 2^24 addresses
 * under a vendor's OUI in seconds). Only if the secret can't be read or made: SHA-1(prefix + MAC). */
static void epr_make(void)
{
	static const char pfx[] = "openlens-fw/onvif/";
	uint8_t mac[6], h[20], m[sizeof pfx - 1 + 6];
	struct in_addr ip, mask;
	int mtu;
	char u[37];
	if (epr_fixed) return;
	if_info(mac, &ip, &mask, &mtu);
	memcpy(m, pfx, sizeof pfx - 1);
	memcpy(m + sizeof pfx - 1, mac, 6);
	if (epr_keyed < 0) epr_key_load();
	if (epr_keyed) hmac_sha1_k(epr_key, sizeof epr_key, m, sizeof m, h);
	else sha1(m, sizeof m, h);
	uuid_str(h, 5, u);
	snprintf(epr, sizeof epr, "urn:uuid:%s", u);
}

/* ---- authentication (the monitor's, see "---- privilege separation") ---------------------- */

static uint8_t secret[20];             /* keys the stateless Digest nonces */
static uint8_t ui_key[20];             /* keys the web UI's form tokens (a separate secret) */
static unsigned long nonce_off;        /* random per boot: a nonce doesn't show the uptime */
static const char dummy_pw[] = "no-such-user-0123";   /* unknown users cost the same hashing */

/* nonce = 8 hex digits of (monotonic time + nonce_off), 8 of a counter (two clients in one second
 * get different nonces) and 24 of SHA1(secret, both): issued by us, without keeping state. */
#define NONCE_LEN 40
static void nonce_make(unsigned long t, unsigned long ctr, char out[NONCE_LEN + 1])
{
	char tc[17];
	uint8_t h[20];
	snprintf(tc, sizeof tc, "%08lx%08lx", (t + nonce_off) & 0xffffffffUL, ctr & 0xffffffffUL);
	struct sha1 s;
	sha1_init(&s);
	sha1_update(&s, secret, sizeof secret);
	sha1_update(&s, tc, 16);
	sha1_final(&s, h);
	memcpy(out, tc, 16);
	hex(h, 12, out + 16);
}

/* 0 fresh, 1 ours but stale, -1 not ours; *t and *ctr: when and as which it was issued */
static int nonce_check(const char *n, time_t now, unsigned long *t, unsigned long *ctr)
{
	char want[NONCE_LEN + 1], ts[9], cs[9];
	if (strlen(n) != NONCE_LEN || strspn(n, "0123456789abcdef") != NONCE_LEN) return -1;
	snprintf(ts, sizeof ts, "%.8s", n);
	snprintf(cs, sizeof cs, "%.8s", n + 8);
	*t = (strtoul(ts, NULL, 16) - nonce_off) & 0xffffffffUL;
	*ctr = strtoul(cs, NULL, 16);
	nonce_make(*t, *ctr, want);
	if (!ct_eq(want, n, NONCE_LEN)) return -1;
	return (unsigned long)now < *t || (unsigned long)now - *t > NONCE_LIFE ? 1 : 0;
}

/* Digest nc replay cache: the highest nc per nonce (by its counter). Nonces are counted out in
 * order, so when a live entry has to go, the oldest goes and every nonce counted out up to it
 * turns stale (its client gets a new one): a full cache never lets a replay through, and churning
 * it costs other clients at most one retry. */
#define NCS_N 64
static struct { unsigned long ctr, t, nc; int used; } ncs[NCS_N];
static unsigned long nc_floor;
static int nc_floor_set;

static int nc_use(unsigned long ctr, unsigned long t, unsigned long nc, time_t now)
{
	int slot = -1, old = -1;
	if (nc_floor_set && ctr <= nc_floor) return -1;
	for (int i = 0; i < NCS_N; i++) {
		if (ncs[i].used && ncs[i].ctr == ctr) {
			if (nc <= ncs[i].nc) return -1;
			ncs[i].nc = nc;
			return 0;
		}
		if (!ncs[i].used || (unsigned long)now - ncs[i].t > NONCE_LIFE) { if (slot < 0) slot = i; }
		else if (old < 0 || ncs[i].ctr < ncs[old].ctr) old = i;
	}
	if (slot < 0) {
		slot = old;
		nc_floor = ncs[old].ctr;
		nc_floor_set = 1;
	}
	ncs[slot].ctr = ctr;
	ncs[slot].t = t;
	ncs[slot].nc = nc;
	ncs[slot].used = 1;
	return 0;
}

/* The counter of the nonces we issue. A nonce carries 32 bits of it and nc_use orders nonces by
 * it, so after 2^32 challenges the count would restart below nc_floor and every nonce would be
 * stale for good. At the wrap the nonce key changes (an outstanding nonce is then foreign: its
 * client gets one more challenge) and the nc cache and its floor start over. */
static unsigned long nonce_ctr;

static unsigned long nonce_next(void)
{
	if (nonce_ctr >= 0xffffffffUL) {
		uint8_t old[20];
		memcpy(old, secret, sizeof old);
		if (random_bytes(secret, sizeof secret)) sha1(old, sizeof old, secret);   /* new all the same */
		memset(old, 0, sizeof old);
		memset(ncs, 0, sizeof ncs);
		nc_floor = 0;
		nc_floor_set = 0;
		nonce_ctr = 0;
		LOG("Digest nonce counter wrapped: new nonce key, nc cache cleared\n");
	}
	return ++nonce_ctr;
}

/* Value of a Digest parameter (quoted or not) from an Authorization header value. */
static int dparam(const char *h, const char *name, char *out, size_t cap)
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

static void md5_str(char out[33], const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	size_t len = n < 0 ? 0 : (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1;
	HASH_COUNT(len);
	md5_hex(buf, len, out);
	memset(buf, 0, sizeof buf);                         /* may have held a password */
}

/* Credential checks return the user's role (> 0); A_WRONG for a wrong password or unknown user
 * (the only result that counts as a failed attempt); A_STALE for a stale or reused Digest nonce
 * (retry with a new one); A_REFUSED for anything refused before a password was compared. */
enum { A_REFUSED = -2, A_STALE = -1, A_WRONG = 0 };

/* HTTP Digest (RFC 7616 MD5, qop=auth) for `method` on request-target `uri`. */
static int digest_auth(const char *authz, const char *method, const char *uri, time_t now,
		       char *who, size_t cap)
{
	char user[64], rlm[64], nonce[64], duri[300], resp[64], qop[16], nc[16], cnonce[128], alg[16];
	char ha1[33], ha2[33], want[33];
	unsigned long t, ctr;
	if (strncasecmp(authz, "Digest ", 7)) return A_REFUSED;
	authz += 7;
	if (dparam(authz, "username", user, sizeof user) || dparam(authz, "realm", rlm, sizeof rlm) ||
	    dparam(authz, "nonce", nonce, sizeof nonce) || dparam(authz, "uri", duri, sizeof duri) ||
	    dparam(authz, "response", resp, sizeof resp) || dparam(authz, "qop", qop, sizeof qop) ||
	    dparam(authz, "nc", nc, sizeof nc) || dparam(authz, "cnonce", cnonce, sizeof cnonce))
		return A_REFUSED;
	snprintf(who, cap, "%s", user);
	if ((!dparam(authz, "algorithm", alg, sizeof alg) && strcasecmp(alg, "MD5")) ||
	    strcmp(rlm, REALM) || strcmp(duri, uri) || strcmp(qop, "auth") || strlen(nc) != 8 ||
	    strspn(nc, "0123456789abcdefABCDEF") != 8 || strlen(resp) != 32 || !*cnonce)
		return A_REFUSED;
	int fresh = nonce_check(nonce, now, &t, &ctr);
	if (fresh < 0) return A_REFUSED;
	if (fresh > 0) return A_STALE;
	musers_load();
	const struct muser *u = muser_find(user);
	md5_str(ha1, "%s:%s:%s", user, REALM, u ? u->pw : dummy_pw);
	md5_str(ha2, "%s:%s", method, uri);
	md5_str(want, "%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
	for (int i = 0; i < 32; i++) resp[i] = (char)tolower((unsigned char)resp[i]);
	if (!ct_eq(want, resp, 32) || !u) return A_WRONG;
	if (nc_use(ctr, t, strtoul(nc, NULL, 16), now)) return A_STALE;
	return u->role;
}

/* UsernameToken replay protection. The cache keeps the SHA-1 of each nonce until its Created
 * leaves the window; when it is full of live entries the new token is refused (nothing live is
 * forgotten). Shares: one user may hold at most SEEN_PER_USER (an NVR sending a token every
 * second, PullMessages included, fits in the 300 s window); viewers together at most half the
 * cache and viewers and operators together three quarters, so whatever lower roles send, every
 * operator keeps room for SEEN_PER_USER tokens and every admin too. Tokens created at or before
 * seen_floor are refused: the process start, the moment the clock became valid, the time of a
 * SetSystemDateAndTime, the TIME_FLOOR saved before a restart, and while the clock is behind the
 * latest second it has shown (time_hw: ntpc stepped it back), that second. While the clock is
 * unset (before BUILD_EPOCH: no RTC, so every boot starts from the same time) UsernameToken is
 * refused altogether, since a token captured in an earlier boot would be fresh again; HTTP Digest
 * doesn't depend on the clock. */
/* SSS sends ~0.7 tokens/s (measured against stock): ~210 per 300 s window, so a user needs more
 * than the reviewed 64; 512 per user is a 2x margin. 2048 entries of 32 bytes: 64 KiB. */
#define SEEN_N 2048
#define SEEN_PER_USER (SEEN_N / 4)
static struct { long long c; uint8_t h[20]; short user; signed char role, used; } seen[SEEN_N];
static long long seen_floor = -1, build_epoch = BUILD_EPOCH;
static int clock_unset;

/* What the entries of users with roles up to `role` may hold together. */
static int seen_cap(int role)
{
	return role >= L_ADMIN ? SEEN_N : role == L_OPERATOR ? SEEN_N - SEEN_PER_USER : SEEN_N - 2 * SEEN_PER_USER;
}

static int clock_valid(long long now)
{
	if (now < build_epoch) { clock_unset = 1; return 0; }
	if (clock_unset) {
		clock_unset = 0;
		if (now > seen_floor) seen_floor = now;
	}
	return 1;
}

/* The wall clock's high-water mark, raised every loop and on every token. The replay cache forgets
 * a token once the clock has passed its Created + skew; if ntpc (or anyone) then steps the clock
 * back, that token would be inside the window again with nothing remembering it. So while
 * time(NULL) is below the mark, tokens created at or before the mark are refused: the clients'
 * next tokens work once the clock has passed it again (Digest works meanwhile). The mark is saved
 * to TIME_FLOOR at most once an hour (NAND wear) and at a clean exit or reboot, and read at start
 * as a floor, so a respawn or a reboot doesn't forget it (up to an hour of it, after a crash or a
 * power cut). */
#define FLOOR_SAVE_S 3600
static long long time_hw = -1, hw_saved = -1;
static time_t hw_saved_at;             /* mono s of the last save (or of the start) */

static void clock_hw(long long now)
{
	if (now > time_hw) time_hw = now;
}

/* TIME_FLOOR = time_hw, if it moved and the clock is set: at most every FLOOR_SAVE_S, or now. */
static void hw_save(int now_too)
{
	char p[300], v[24];
	time_t m = mono();
	if (time_hw <= hw_saved || time_hw < build_epoch || (!now_too && m - hw_saved_at < FLOOR_SAVE_S)) return;
	hw_saved_at = m;
	hw_saved = time_hw;
	data_path(TIME_FLOOR, p, sizeof p);
	int n = snprintf(v, sizeof v, "%lld\n", time_hw);
	if (file_put(p, v, (size_t)n)) LOG("%s: %s (the UsernameToken floor isn't kept over a restart)\n", p, strerror(errno));
}

/* At start: TIME_FLOOR, if there is one, is a floor and the high-water mark. */
static void hw_load(void)
{
	char p[300], v[24];
	data_path(TIME_FLOOR, p, sizeof p);
	hw_saved_at = mono();
	int n = file_get(p, v, sizeof v - 1);
	if (n <= 0) return;
	v[n] = 0;
	size_t d = strspn(v, "0123456789");
	if (!d || d > 18 || (v[d] && strcmp(v + d, "\n"))) {
		LOG("%s: not a time, ignored\n", p);
		return;
	}
	long long t = atoll(v);
	if (t > seen_floor) seen_floor = t;
	clock_hw(t);
	hw_saved = t;
}

/* 0 new (now recorded), 1 a replay, -1 no room (the cache, the user's share or its role's) */
static int replayed(const uint8_t *nonce, size_t n, long long created, long long now, int user, int role)
{
	uint8_t h[20];
	int slot = -1, mine = 0, tier = 0;
	sha1(nonce, n, h);
	for (int i = 0; i < SEEN_N; i++) {
		if (seen[i].used && seen[i].c < now - skew) seen[i].used = 0;
		if (!seen[i].used) { if (slot < 0) slot = i; continue; }
		if (!memcmp(seen[i].h, h, 20)) return 1;
		mine += seen[i].user == user;
		tier += seen[i].role <= role;
	}
	if (slot < 0 || mine >= SEEN_PER_USER || tier >= seen_cap(role)) return -1;
	memcpy(seen[slot].h, h, 20);
	seen[slot].c = created;
	seen[slot].user = (short)user;
	seen[slot].role = (signed char)role;
	seen[slot].used = 1;
	return 0;
}

/* WS-Security UsernameToken (PasswordDigest only) in the SOAP header [h, he). */
static int wsse_auth(const char *h, const char *he, char *who, size_t cap)
{
	char user[64], pw[64], nonce[128], created[48], type[160];
	uint8_t nraw[64], got[20], want[20];
	const char *ptag, *ut = xel(h, he, "UsernameToken", NULL);
	long long c, now = time(NULL);
	if (!ut) return A_REFUSED;
	he = xclose(ut, he, "UsernameToken");
	if (xtext(ut, he, "Username", user, sizeof user)) return A_REFUSED;
	snprintf(who, cap, "%s", user);
	size_t tl;
	if (!xel(ut, he, "Password", &ptag) || xattr(ptag, he, "Type", type, sizeof type) ||
	    (tl = strlen(type)) < 15 || strcmp(type + tl - 15, "#PasswordDigest"))
		return A_REFUSED;                           /* PasswordText (or no Type) refused */
	if (xtext(ut, he, "Password", pw, sizeof pw) || xtext(ut, he, "Nonce", nonce, sizeof nonce) ||
	    xtext(ut, he, "Created", created, sizeof created))
		return A_REFUSED;
	int nn = b64_dec(nonce, nraw, sizeof nraw);
	if (nn < 8 || b64_dec(pw, got, sizeof got) != 20 || parse_created(created, &c) || !clock_valid(now))
		return A_REFUSED;
	long long lowest = seen_floor;                      /* (clock_valid may just have raised it) */
	clock_hw(now);
	if (now < time_hw && time_hw > lowest) lowest = time_hw;  /* the clock went back: see time_hw */
	if (c <= lowest || c < now - skew || c > now + FUTURE_MAX) return A_REFUSED;
	musers_load();
	const struct muser *u = muser_find(user);
	struct sha1 s;
	sha1_init(&s);
	sha1_update(&s, nraw, (size_t)nn);
	sha1_update(&s, created, strlen(created));
	sha1_update(&s, u ? u->pw : dummy_pw, strlen(u ? u->pw : dummy_pw));
	sha1_final(&s, want);
	if (!ct_eq(want, got, 20) || !u) return A_WRONG;
	if (replayed(nraw, (size_t)nn, c, now, (int)(u - musers), u->role)) return A_REFUSED;
	return u->role;
}

/* Wrong passwords. Per address: FAIL_MAX in a FAIL_WINDOW lock that address until the window
 * ends; a locked entry is never evicted, and a newcomer that finds every entry locked counts as
 * locked. All addresses together: FAIL_GLOBAL in a window stop the checks for everyone except
 * addresses where an operator or admin logged in within GOOD_KEEP s (GOOD_SLOTS of them), so the
 * NVR keeps working while someone guesses from many addresses. A viewer's login exempts nothing,
 * an entry younger than GOOD_KEEP is never pushed out (a newcomer then isn't exempt), and a wrong
 * password from an exempt address ends its exemption: past FAIL_GLOBAL, at most one more guess
 * per exempt address is checked in a window. While blocked, credentials aren't checked at all. */
#define FAIL_SLOTS 32
#define GOOD_SLOTS 8
static struct { struct in_addr ip; time_t t; int n; } fails[FAIL_SLOTS];
static struct { time_t t; int n; } gfail;
static struct { struct in_addr ip; time_t t; } good[GOOD_SLOTS];

static int fail_live(int i, time_t now) { return fails[i].n && now - fails[i].t <= FAIL_WINDOW; }

static int auth_blocked(struct in_addr ip, time_t now)
{
	int room = 0;
	for (int i = 0; i < FAIL_SLOTS; i++) {
		if (!fail_live(i, now)) { room = 1; continue; }
		if (fails[i].ip.s_addr == ip.s_addr) {
			if (fails[i].n >= FAIL_MAX) return 1;
			room = 1;
		} else if (fails[i].n < FAIL_MAX) room = 1;
	}
	if (!room) return 1;
	if (gfail.n >= FAIL_GLOBAL && now - gfail.t <= FAIL_WINDOW) {
		for (int i = 0; i < GOOD_SLOTS; i++)
			if (good[i].t && good[i].ip.s_addr == ip.s_addr && now - good[i].t <= GOOD_KEEP) return 0;
		return 1;
	}
	return 0;
}

static void auth_failed(struct in_addr ip, time_t now)
{
	int slot = -1, old = -1;
	if (now - gfail.t > FAIL_WINDOW) { gfail.t = now; gfail.n = 0; }
	gfail.n++;
	for (int i = 0; i < GOOD_SLOTS; i++)            /* no longer exempt from FAIL_GLOBAL */
		if (good[i].ip.s_addr == ip.s_addr) good[i].t = 0;
	for (int i = 0; i < FAIL_SLOTS; i++) {
		if (fail_live(i, now) && fails[i].ip.s_addr == ip.s_addr) { fails[i].n++; return; }
		if (!fail_live(i, now)) { if (slot < 0) slot = i; }
		else if (fails[i].n < FAIL_MAX && (old < 0 || fails[i].t < fails[old].t)) old = i;
	}
	if (slot < 0) slot = old;                       /* never a locked one */
	if (slot < 0) return;
	fails[slot].ip = ip;
	fails[slot].t = now;
	fails[slot].n = 1;
}

/* An operator's or admin's login from ip (the caller checks the role). */
static void auth_good(struct in_addr ip, time_t now)
{
	int slot = -1;
	for (int i = 0; i < GOOD_SLOTS; i++) {
		if (good[i].t && good[i].ip.s_addr == ip.s_addr) { good[i].t = now; return; }
		if (slot < 0 && (!good[i].t || now - good[i].t > GOOD_KEEP)) slot = i;
	}
	if (slot < 0) return;                          /* every entry is younger than GOOD_KEEP: kept */
	good[slot].ip = ip;
	good[slot].t = now;
}

/* At start (and the host test's "restart"): new secrets; tokens from before now don't count. */
static int auth_init(void)
{
	if (random_bytes(secret, sizeof secret) || random_bytes(&nonce_off, sizeof nonce_off) ||
	    random_bytes(ui_key, sizeof ui_key))
		return -1;
	memset(seen, 0, sizeof seen);
	seen_floor = time(NULL);
	clock_unset = seen_floor < build_epoch;
	return 0;
}

/* ---- responses ------------------------------------------------------------------------ */

struct client {
	int fd, state;                     /* 0 reading, 1 sending, 2 a held PullMessages, 3 a preview,
					      4 a firmware upload's body, 5 its camupdate --check */
	struct in_addr peer;
	char local[INET_ADDRSTRLEN];       /* the address the request came in on */
	int tls;                           /* 1: from camtls (HTTPS), its PROXY line taken */
	int proxy;                         /* 1: from camtls, its PROXY line not in yet (peer 0.0.0.0) */
	char in[REQ_CAP + 1];
	size_t in_len, hdr_len, body_len, scanned;  /* scanned: header-end search done up to here */
	time_t deadline;
	long long since;                   /* accepted (ms), for picking a slowloris to drop */
	long long last_rx;                 /* its last byte in (ms): a stalled body can be dropped too */
	char out[OUT_CAP];
	size_t out_off, out_len;
	int file_fd;
	long file_left;
	char park_id[17];                  /* held PullMessages: its subscription, */
	long long park_until;              /* when it times out (mono ms) */
	int park_limit;                    /* and its MessageLimit */
	long long pv_end, pv_next, pv_sent;  /* preview: its cap, next frame, last frame sent (mono ms) */
	ino_t pv_ino;                      /* ... and which JPEG that was */
	time_t pv_mtime;
	long pv_size;
};

static struct client clients[MAX_CLIENTS];

static char sb[24 * 1024];             /* SOAP body (or a discovery message) being built */
static size_t sbn;
static int sbover;

static void S(const char *fmt, ...)
{
	va_list ap;
	if (sbover) return;
	va_start(ap, fmt);
	int n = vsnprintf(sb + sbn, sizeof sb - sbn, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof sb - sbn) sbover = 1;
	else sbn += (size_t)n;
}

static const char *status_text(int code)
{
	switch (code) {
	case 200: return "OK";
	case 302: return "Found";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 409: return "Conflict";
	case 411: return "Length Required";
	case 413: return "Content Too Large";
	case 415: return "Unsupported Media Type";
	case 421: return "Misdirected Request";
	case 422: return "Unprocessable Content";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 501: return "Not Implemented";
	case 503: return "Service Unavailable";
	case 507: return "Insufficient Storage";
	default: return "Internal Server Error";
	}
}

static int out_add(struct client *c, const void *p, size_t n)
{
	if (OUT_CAP - c->out_len < n) return -1;
	memcpy(c->out + c->out_len, p, n);
	c->out_len += n;
	return 0;
}

/* Set while a web UI request is answered: every reply to it, errors and challenges included,
 * carries these too. */
static int ui_resp;
#define UI_HEADERS "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; " \
	"script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" \
	"\r\nX-Frame-Options: DENY\r\n" \
	"X-Content-Type-Options: nosniff\r\nReferrer-Policy: same-origin\r\n"

/* Status line and headers for a body of `clen` bytes, after anything already queued (100). */
static int http_head(struct client *c, int code, const char *extra, const char *ctype, size_t clen)
{
	char h[1024];
	int n = snprintf(h, sizeof h, "HTTP/1.1 %d %s\r\nServer: camhttpd\r\nConnection: close\r\n"
			 "Cache-Control: no-store\r\n%s%s%s%s%sContent-Length: %zu\r\n\r\n", code,
			 status_text(code), ui_resp ? UI_HEADERS : "", extra ? extra : "",
			 ctype ? "Content-Type: " : "", ctype ? ctype : "", ctype ? "\r\n" : "", clen);
	c->state = 1;
	if (n < 0 || n >= (int)sizeof h || out_add(c, h, (size_t)n)) return -1;
	return 0;
}

static void http_reply(struct client *c, int code, const char *extra, const char *text)
{
	size_t mark = c->out_len, n = text ? strlen(text) : 0;
	if (http_head(c, code, extra, text ? "text/plain" : NULL, n) || out_add(c, text, n)) {
		c->out_len = mark;
		http_head(c, 500, NULL, NULL, 0);
	}
}

#define SOAP_ENV "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope " \
	"xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" " \
	"xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" " \
	"xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" " \
	"xmlns:timg=\"http://www.onvif.org/ver20/imaging/wsdl\" " \
	"xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" " \
	"xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\" " \
	"xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" " \
	"xmlns:tt=\"http://www.onvif.org/ver10/schema\" " \
	"xmlns:ter=\"http://www.onvif.org/ver10/error\" " \
	"xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" " \
	"xmlns:wstop=\"http://docs.oasis-open.org/wsn/t-1\" " \
	"xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" " \
	"xmlns:wsrf-r=\"http://docs.oasis-open.org/wsrf/r-2\" " \
	"xmlns:wsrf-bf=\"http://docs.oasis-open.org/wsrf/bf-2\" " \
	"xmlns:tns1=\"http://www.onvif.org/ver10/topics\" " \
	"xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">"
#define SOAP_POST "</env:Body></env:Envelope>\n"

static const char *resp_action;        /* wsa:Action for the reply's header (Events), or NULL */

static void soap_send(struct client *c, int code, const char *extra)
{
	char head[200] = "";
	if (resp_action)
		snprintf(head, sizeof head, "<env:Header><wsa:Action>%s</wsa:Action></env:Header>", resp_action);
	resp_action = NULL;
	size_t mark = c->out_len, hl = strlen(head);
	if (!sbover && !http_head(c, code, extra, "application/soap+xml; charset=utf-8",
				  strlen(SOAP_ENV) + hl + 10 + sbn + strlen(SOAP_POST)) &&
	    !out_add(c, SOAP_ENV, strlen(SOAP_ENV)) && !out_add(c, head, hl) &&
	    !out_add(c, "<env:Body>", 10) && !out_add(c, sb, sbn) &&
	    !out_add(c, SOAP_POST, strlen(SOAP_POST)))
		return;
	c->out_len = mark;
	http_head(c, 500, NULL, NULL, 0);
}

enum { F_NONE, F_ACTION, F_NOSERVICE, F_AUDIO, F_AUTH, F_WELLFORMED, F_ARGS, F_NOPROFILE,
       F_NOCONFIG, F_STREAMSETUP, F_DATETIME, F_NTP, F_TIME, F_CONFIGMODIFY, F_SAVE, F_IPV4, F_DNS,
       F_NOSOURCE, F_SETTINGS, F_NOSUB, F_BUSY, F_NOMODULE, F_BADMODULE, F_NORULE, F_BADRULE,
       F_TOOMANYRULES, F_AUDIOOUT, F_TZ, F_UNCLAIMED, F_PLAIN, F_LOCKED };
static const struct { int code; const char *sub, *sub2, *text; } faults[] = {
	[F_ACTION] = { 500, "ter:ActionNotSupported", NULL, "Optional Action Not Implemented" },
	[F_NOSERVICE] = { 500, "ter:ActionNotSupported", "ter:NoSuchService", "No such service" },
	[F_AUDIO] = { 500, "ter:ActionNotSupported", "ter:AudioNotSupported", "Audio is not supported" },
	[F_AUDIOOUT] = { 500, "ter:ActionNotSupported", "ter:AudioOutputNotSupported",
			 "There is no audio output" },
	[F_AUTH] = { 400, "ter:NotAuthorized", NULL, "Sender not Authorized" },
	[F_WELLFORMED] = { 400, "ter:WellFormed", NULL, "Not a SOAP request" },
	[F_ARGS] = { 400, "ter:InvalidArgVal", "ter:InvalidArgs", "Invalid arguments" },
	[F_NOPROFILE] = { 400, "ter:InvalidArgVal", "ter:NoProfile", "No such profile" },
	[F_NOCONFIG] = { 400, "ter:InvalidArgVal", "ter:NoConfig", "No such configuration" },
	[F_STREAMSETUP] = { 400, "ter:InvalidArgVal", "ter:InvalidStreamSetup", "Multicast is not supported" },
	[F_DATETIME] = { 400, "ter:InvalidArgVal", "ter:InvalidDateTime", "Invalid date or time" },
	[F_NTP] = { 400, "ter:InvalidArgVal", "ter:NtpServerUndefined", "No NTP server is set" },
	[F_TIME] = { 500, "ter:Action", NULL, "The time could not be set" },
	[F_TZ] = { 400, "ter:InvalidArgVal", "ter:InvalidTimeZone", "Not a POSIX TZ string the camera takes" },
	[F_CONFIGMODIFY] = { 400, "ter:InvalidArgVal", "ter:ConfigModify",
			     "The configuration parameters are not possible to set" },
	[F_SAVE] = { 500, "ter:Action", NULL, "The settings could not be saved" },
	[F_IPV4] = { 400, "ter:InvalidArgVal", "ter:InvalidIPv4Address", "Invalid IPv4 address" },
	[F_DNS] = { 400, "ter:InvalidArgVal", "ter:InvalidDnsName", "Invalid DNS name" },
	[F_NOSOURCE] = { 400, "ter:InvalidArgVal", "ter:NoSource", "No such video source" },
	[F_SETTINGS] = { 400, "ter:InvalidArgVal", "ter:SettingsInvalid", "Invalid imaging settings" },
	[F_NOSUB] = { 400, "ter:InvalidArgVal", NULL, "Unknown or expired subscription" },
	[F_BUSY] = { 500, "ter:Action", NULL, "Every subscription is in use" },
	[F_NOMODULE] = { 400, "ter:InvalidArgVal", "ter:ModuleNotExistent", "No such analytics module" },
	[F_BADMODULE] = { 400, "ter:InvalidArgVal", "ter:InvalidModule", "Invalid analytics module parameters" },
	[F_NORULE] = { 400, "ter:InvalidArgVal", "ter:RuleNotExistent", "No such rule" },
	[F_BADRULE] = { 400, "ter:InvalidArgVal", "ter:InvalidRule", "Invalid rule parameters" },
	[F_TOOMANYRULES] = { 500, "ter:Action", "ter:TooManyRules", "There is one motion detector rule" },
	[F_UNCLAIMED] = { 400, "ter:NotAuthorized", NULL,
			  "The camera is not set up yet: claim it in a browser at /setup" },
	[F_PLAIN] = { 400, "ter:NotAuthorized", NULL, "Plain HTTP is off on this camera (net.plain=0): use https://" },
	[F_LOCKED] = { 400, "ter:NotAuthorized", NULL,
		       "The camera is locked: its storage failed; recover it in a browser at its address" },
};

/* SOAP 1.2 fault: env:Sender faults are HTTP 400, env:Receiver 500 (SOAP 1.2 part 2, 7.5.1). */
static void soap_fault(struct client *c, int f, const char *extra, int code)
{
	sbn = 0;
	sbover = 0;
	S("<env:Fault><env:Code><env:Value>env:%s</env:Value><env:Subcode><env:Value>%s</env:Value>",
	  faults[f].code == 400 ? "Sender" : "Receiver", faults[f].sub);
	if (faults[f].sub2) S("<env:Subcode><env:Value>%s</env:Value></env:Subcode>", faults[f].sub2);
	S("</env:Subcode></env:Code><env:Reason><env:Text xml:lang=\"en\">%s</env:Text></env:Reason>",
	  faults[f].text);
	if (f == F_NOSUB) {                            /* WS-ResourceFramework's own fault */
		char ts[24];
		iso(time(NULL), ts);
		S("<env:Detail><wsrf-r:ResourceUnknownFault><wsrf-bf:Timestamp>%s</wsrf-bf:Timestamp>"
		  "</wsrf-r:ResourceUnknownFault></env:Detail>", ts);
	}
	S("</env:Fault>");
	resp_action = NULL;
	soap_send(c, code ? code : faults[f].code, extra);
}

/* A fresh nonce the monitor sent with a refusal (authenticate), for the challenge that follows. */
static char auth_nonce[NONCE_LEN + 1];
static int mon_auth_probe(struct in_addr peer, char nonce[NONCE_LEN + 1]);

/* 401 with a fresh Digest challenge (and a NotAuthorized fault body for SOAP, else `text`). The
 * nonce is the monitor's (it holds the key): the one its refusal brought, else a new one. */
static void challenge_text(struct client *c, int stale, int soap, const char *text)
{
	char nonce[NONCE_LEN + 1], h[256];
	if (*auth_nonce) memcpy(nonce, auth_nonce, sizeof nonce);
	else mon_auth_probe(c->peer, nonce);
	*auth_nonce = 0;
	snprintf(h, sizeof h, "WWW-Authenticate: Digest realm=\"" REALM "\", qop=\"auth\", "
		 "algorithm=MD5, nonce=\"%s\"%s\r\n", nonce, stale ? ", stale=true" : "");
	if (soap) soap_fault(c, F_AUTH, h, 401);
	else http_reply(c, 401, h, text);
}

static void challenge(struct client *c, int stale, int soap)
{
	challenge_text(c, stale, soap, "authentication required\n");
}

static int ctl_cmd(const char *line, char *out, size_t cap, int ms);

/* ---- ONVIF operations ----------------------------------------------------------------- */

enum { SVC_DEVICE, SVC_MEDIA, SVC_IMAGING, SVC_EVENTS, SVC_ANALYTICS, SVC_DEVICEIO };

struct req {
	struct client *c;
	const char *op, *end;              /* the operation element's content */
	const char *target, *hb, *he;      /* request-target; the SOAP header [hb, he) */
	int svc;                           /* the service its path named (SVC_*) */
	const char *name;                  /* the operation's local name */
	char user[64];
};

#define RTSPS_PORT 322                 /* camtls's RTSPS listener (stage D), relaying to rtspd */

static int tls_up(void);

/* cam.conf net.plain: 1 (the default) or 0, which the owner sets once SSS uses HTTPS and RTSPS.
 * plain_off: it is 0 and HTTPS is up: then port 80's ONVIF and /snapshot.jpg are refused, no
 * rtsp:// URI is given and discovery names https:// only. While HTTPS is down everything stays
 * plain (the same fallback as the claim's): net.plain alone never cuts the camera off. */
static int plain_on(void)
{
	char v[8];
	return !conf_get("net.plain", v, sizeof v) || strcmp(v, "0");
}

static int plain_off(void) { return tls_up() && !plain_on(); }

/* The ONVIF base URL as this request reached us: https://ADDRESS from camtls, else
 * http://ADDRESS[:port]. Every service address we give (GetCapabilities, GetServices,
 * GetSnapshotUri, the PullPoint subscription) follows it. */
static void base_url(const struct req *r, char *out, size_t cap)
{
	char port[8] = "";
	if (r->c->tls) { snprintf(out, cap, "https://%s", r->c->local); return; }
	if (http_port != 80) snprintf(port, sizeof port, ":%d", http_port);
	snprintf(out, cap, "http://%s%s", r->c->local, port);
}

static int save_live(const char *key, const char *val, const char *user);
static void E(const char *s);

/* UTCDateTime exact; TZ = time.tz, LocalDateTime in it. DaylightSavings stays false (the TZ string
 * carries the rule). */
static int op_time(const struct req *r)
{
	(void)r;
	char ntp[NTP_MAX][64], tz[TZ_BUF];
	time_t t = time(NULL);
	struct tm g, l;
	tz_sync(tz);
	gmtime_r(&t, &g);
	if (!localtime_r(&t, &l)) l = g;
	S("<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>%s"
	  "</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>",
	  ntp_servers(ntp) ? "NTP" : "Manual");
	E(tz);                                              /* <+05>-5 */
	S("</tt:TZ></tt:TimeZone>");
	for (int i = 0; i < 2; i++) {
		const struct tm *x = i ? &l : &g;
		S("<tt:%s><tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second>"
		  "</tt:Time><tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day>"
		  "</tt:Date></tt:%s>", i ? "LocalDateTime" : "UTCDateTime", x->tm_hour, x->tm_min,
		  x->tm_sec, x->tm_year + 1900, x->tm_mon + 1, x->tm_mday, i ? "LocalDateTime" : "UTCDateTime");
	}
	S("</tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>");
	return 0;
}

/* Manual sets the clock (UTC); NTP is acknowledged without touching it (ntpc keeps it, from
 * time.ntp), and refused when no server is set. Manual doesn't switch NTP off: SetNTP with no
 * servers does. A TimeZone TZ is checked as camcfg checks time.tz (InvalidTimeZone if not), then,
 * when it differs, saved with camcfg and applied live (rtspd's OSD clock); an empty or missing one
 * changes nothing. DaylightSavings is ignored: the TZ string carries the rule. */
static int op_settime(const struct req *r)
{
	static const char *const f[6] = { "Year", "Month", "Day", "Hour", "Minute", "Second" };
	char type[16], ntp[NTP_MAX][64], tz[TZ_BUF], cur[TZ_BUF];
	int x[6] = { 0 }, manual;
	long long e = 0;
	const char *u = NULL;
	if (xtext(r->op, r->end, "DateTimeType", type, sizeof type)) return F_ARGS;
	if (!(manual = !strcmp(type, "Manual")) && strcmp(type, "NTP")) return F_ARGS;
	const char *z = xel(r->op, r->end, "TimeZone", NULL);
	*tz = 0;
	if (z) {
		const char *ze = xclose(z, r->end, "TimeZone");
		if (xtext(z, ze, "TZ", tz, sizeof tz) && xel(z, ze, "TZ", NULL)) return F_TZ;   /* too long */
		if (*tz && !tz_valid(tz)) return F_TZ;
	}
	if (!manual && !ntp_servers(ntp)) return F_NTP;
	if (manual && (u = xel(r->op, r->end, "UTCDateTime", NULL))) {
		const char *ue = xclose(u, r->end, "UTCDateTime");
		for (int i = 0; i < 6; i++) {
			char b[8];
			if (xtext(u, ue, f[i], b, sizeof b) || !*b || b[strspn(b, "0123456789")] || strlen(b) > 4)
				return F_DATETIME;
			x[i] = atoi(b);
		}
		if (!date_ok(x[0], x[1], x[2], x[3], x[4], x[5])) return F_DATETIME;
		e = days_from_civil(x[0], x[1], x[2]) * 86400 + x[3] * 3600 + x[4] * 60 + x[5];
		if ((long long)(time_t)e != e) return F_DATETIME;
	}
	tz_sync(cur);
	if (*tz && strcmp(tz, cur)) {
		if (save_live("time.tz", tz, r->user)) return F_SAVE;
		tz_sync(cur);
	}
	if (u) {
		char secs[24];
		const char *f[2] = { secs, "0" };
		snprintf(secs, sizeof secs, "%lld", e);
		/* the monitor sets it, then raises the UsernameToken floor (mon_settime) */
		if (mon_call(MON_SETTIME, req_grant, 2, f, NULL)) return F_TIME;
		LOG("time set to %04d-%02d-%02d %02d:%02d:%02d UTC by %s\n", x[0], x[1], x[2], x[3], x[4],
		    x[5], r->user);
	}
	S("<tds:SetSystemDateAndTimeResponse/>");
	return 0;
}

static int op_devinfo(const struct req *r)
{
	(void)r;
	S("<tds:GetDeviceInformationResponse><tds:Manufacturer>openlens-fw</tds:Manufacturer>"
	  "<tds:Model>" MODEL "</tds:Model><tds:FirmwareVersion>%s</tds:FirmwareVersion>"
	  "<tds:SerialNumber>0</tds:SerialNumber><tds:HardwareId>" MODEL "</tds:HardwareId>"
	  "</tds:GetDeviceInformationResponse>", FW_VERSION);
	return 0;
}

static void dev_caps(void)
{
	S("<tds:Capabilities><tds:Network IPFilter=\"false\" ZeroConfiguration=\"false\" "
	  "IPVersion6=\"false\" DynDNS=\"false\" Dot11Configuration=\"false\" "
	  "HostnameFromDHCP=\"false\" NTP=\"%d\"/><tds:Security TLS1.0=\"false\" TLS1.1=\"false\" "
	  "TLS1.2=\"%s\" OnboardKeyGeneration=\"false\" AccessPolicyConfig=\"false\" "
	  "DefaultAccessPolicy=\"false\" Dot1X=\"false\" RemoteUserHandling=\"false\" "
	  "X.509Token=\"false\" SAMLToken=\"false\" KerberosToken=\"false\" UsernameToken=\"true\" "
	  "HttpDigest=\"true\" RELToken=\"false\" MaxUsers=\"%d\"/><tds:System "
	  "DiscoveryResolve=\"false\" DiscoveryBye=\"true\" RemoteDiscovery=\"false\" "
	  "SystemBackup=\"false\" SystemLogging=\"false\" FirmwareUpgrade=\"false\" "
	  "HttpFirmwareUpgrade=\"false\" HttpSystemBackup=\"false\" HttpSystemLogging=\"false\" "
	  "HttpSupportInformation=\"false\"/></tds:Capabilities>", NTP_MAX,
	  tls_up() ? "true" : "false", MAX_USERS);    /* TLS1.2: camtls (1.2 and 1.3) while it runs */
}

static void media_caps(void)
{
	S("<trt:Capabilities SnapshotUri=\"true\" Rotation=\"true\" VideoSourceMode=\"false\" "
	  "OSD=\"true\"><trt:ProfileCapabilities MaximumNumberOfProfiles=\"2\"/>"
	  "<trt:StreamingCapabilities RTPMulticast=\"false\" RTP_TCP=\"false\" RTP_RTSP_TCP=\"true\" "
	  "NonAggregateControl=\"false\" NoRTSPStreaming=\"false\"/></trt:Capabilities>");
}

static void img_caps(void)
{
	S("<timg:Capabilities ImageStabilization=\"false\" Presets=\"false\" AdaptablePreset=\"false\"/>");
}

static void an_caps(void)
{
	S("<tan:Capabilities RuleSupport=\"true\" AnalyticsModuleSupport=\"true\" "
	  "CellBasedSceneDescriptionSupported=\"false\" RuleOptionsSupported=\"false\" "
	  "AnalyticsModuleOptionsSupported=\"false\"/>");
}

/* DeviceIO (ver10) counts the inputs and outputs; NVRs read AudioOutputs there for a talk button. */
static void dio_caps(void)
{
	S("<tmd:Capabilities VideoSources=\"1\" VideoOutputs=\"0\" AudioSources=\"%d\" AudioOutputs=\"%d\" "
	  "RelayOutputs=\"0\" SerialPorts=\"0\" DigitalInputs=\"0\" DigitalInputOptions=\"false\"/>",
	  audio_on, audio_on);
}

#define MAX_SUBS 2                     /* an NVR needs one; held pulls leave MAX_CLIENTS - 2 free */
_Static_assert(MAX_SUBS < MAX_CLIENTS, "held pulls must not take every connection slot");

static void ev_caps(void)
{
	S("<tev:Capabilities WSSubscriptionPolicySupport=\"false\" WSPullPointSupport=\"true\" "
	  "WSPausableSubscriptionManagerInterfaceSupport=\"false\" MaxNotificationProducers=\"0\" "
	  "MaxPullPoints=\"%d\" PersistentNotificationStorage=\"false\"/>", MAX_SUBS);
}

/* The services, in GetServices order: namespace, path, service capabilities, prefix. */
static const struct { const char *ns, *path, *pfx; void (*caps)(void); } svcs[] = {
	[SVC_DEVICE] = { "http://www.onvif.org/ver10/device/wsdl", "device_service", "tds", dev_caps },
	[SVC_MEDIA] = { "http://www.onvif.org/ver10/media/wsdl", "media_service", "trt", media_caps },
	[SVC_IMAGING] = { "http://www.onvif.org/ver20/imaging/wsdl", "imaging_service", "timg", img_caps },
	[SVC_EVENTS] = { "http://www.onvif.org/ver10/events/wsdl", "event_service", "tev", ev_caps },
	[SVC_ANALYTICS] = { "http://www.onvif.org/ver20/analytics/wsdl", "analytics_service", "tan", an_caps },
	[SVC_DEVICEIO] = { "http://www.onvif.org/ver10/deviceIO/wsdl", "deviceio_service", "tmd", dio_caps },
};

static int op_caps(const struct req *r)
{
	char cat[16] = "All", base[64];
	if (xtext(r->op, r->end, "Category", cat, sizeof cat) || !*cat) strcpy(cat, "All");
	int all = !strcmp(cat, "All"), dev = all || !strcmp(cat, "Device"), med = all || !strcmp(cat, "Media"),
	    ev = all || !strcmp(cat, "Events"), img = all || !strcmp(cat, "Imaging"),
	    an = all || !strcmp(cat, "Analytics");
	if (!dev && !med && !ev && !img && !an) return F_NOSERVICE;
	base_url(r, base, sizeof base);
	S("<tds:GetCapabilitiesResponse><tds:Capabilities>");
	if (an)
		S("<tt:Analytics><tt:XAddr>%s/onvif/analytics_service</tt:XAddr><tt:RuleSupport>true"
		  "</tt:RuleSupport><tt:AnalyticsModuleSupport>true</tt:AnalyticsModuleSupport>"
		  "</tt:Analytics>", base);
	if (dev)
		S("<tt:Device><tt:XAddr>%s/onvif/device_service</tt:XAddr><tt:Network><tt:IPFilter>false"
		  "</tt:IPFilter><tt:ZeroConfiguration>false</tt:ZeroConfiguration><tt:IPVersion6>false"
		  "</tt:IPVersion6><tt:DynDNS>false</tt:DynDNS></tt:Network><tt:System>"
		  "<tt:DiscoveryResolve>false</tt:DiscoveryResolve><tt:DiscoveryBye>true</tt:DiscoveryBye>"
		  "<tt:RemoteDiscovery>false</tt:RemoteDiscovery><tt:SystemBackup>false</tt:SystemBackup>"
		  "<tt:SystemLogging>false</tt:SystemLogging><tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>"
		  "<tt:SupportedVersions><tt:Major>2</tt:Major><tt:Minor>40</tt:Minor></tt:SupportedVersions>"
		  "</tt:System><tt:IO><tt:InputConnectors>0</tt:InputConnectors><tt:RelayOutputs>0"
		  "</tt:RelayOutputs></tt:IO><tt:Security><tt:TLS1.1>false</tt:TLS1.1><tt:TLS1.2>%s"
		  "</tt:TLS1.2><tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration>"
		  "<tt:AccessPolicyConfig>false</tt:AccessPolicyConfig><tt:X.509Token>false</tt:X.509Token>"
		  "<tt:SAMLToken>false</tt:SAMLToken><tt:KerberosToken>false</tt:KerberosToken>"
		  "<tt:RELToken>false</tt:RELToken></tt:Security></tt:Device>", base,
		  tls_up() ? "true" : "false");          /* HTTPS through camtls (SSS: "HTTPS supported") */
	if (ev)
		S("<tt:Events><tt:XAddr>%s/onvif/event_service</tt:XAddr><tt:WSSubscriptionPolicySupport>"
		  "false</tt:WSSubscriptionPolicySupport><tt:WSPullPointSupport>true</tt:WSPullPointSupport>"
		  "<tt:WSPausableSubscriptionManagerInterfaceSupport>false"
		  "</tt:WSPausableSubscriptionManagerInterfaceSupport></tt:Events>", base);
	if (img) S("<tt:Imaging><tt:XAddr>%s/onvif/imaging_service</tt:XAddr></tt:Imaging>", base);
	if (med)
		S("<tt:Media><tt:XAddr>%s/onvif/media_service</tt:XAddr><tt:StreamingCapabilities>"
		  "<tt:RTPMulticast>false</tt:RTPMulticast><tt:RTP_TCP>false</tt:RTP_TCP>"
		  "<tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP></tt:StreamingCapabilities></tt:Media>", base);
	if (all)                                           /* tt:CapabilitiesExtension */
		S("<tt:Extension><tt:DeviceIO><tt:XAddr>%s/onvif/deviceio_service</tt:XAddr><tt:VideoSources>1"
		  "</tt:VideoSources><tt:VideoOutputs>0</tt:VideoOutputs><tt:AudioSources>%d</tt:AudioSources>"
		  "<tt:AudioOutputs>%d</tt:AudioOutputs><tt:RelayOutputs>0</tt:RelayOutputs></tt:DeviceIO>"
		  "</tt:Extension>", base, audio_on, audio_on);
	S("</tds:Capabilities></tds:GetCapabilitiesResponse>");
	return 0;
}

static int op_services(const struct req *r)
{
	char inc[8] = "", base[64];
	xtext(r->op, r->end, "IncludeCapability", inc, sizeof inc);
	int caps = !strcmp(inc, "true") || !strcmp(inc, "1");
	base_url(r, base, sizeof base);
	S("<tds:GetServicesResponse>");
	for (size_t i = 0; i < sizeof svcs / sizeof svcs[0]; i++) {
		S("<tds:Service><tds:Namespace>%s</tds:Namespace><tds:XAddr>%s/onvif/%s</tds:XAddr>",
		  svcs[i].ns, base, svcs[i].path);
		if (caps) {
			S("<tds:Capabilities>");
			svcs[i].caps();
			S("</tds:Capabilities>");
		}
		S("<tds:Version><tt:Major>2</tt:Major><tt:Minor>40</tt:Minor></tds:Version></tds:Service>");
	}
	S("</tds:GetServicesResponse>");
	return 0;
}

static int op_servcaps(const struct req *r)
{
	S("<%s:GetServiceCapabilitiesResponse>", svcs[r->svc].pfx);
	svcs[r->svc].caps();
	S("</%s:GetServiceCapabilitiesResponse>", svcs[r->svc].pfx);
	return 0;
}
static const char *const scopes[] = {
	"onvif://www.onvif.org/type/video_encoder", "onvif://www.onvif.org/Profile/Streaming",
	("onvif://www.onvif.org/hardware/" MODEL), "onvif://www.onvif.org/name/openlens-fw",
};
#define NSCOPES (int)(sizeof scopes / sizeof scopes[0])

static int op_scopes(const struct req *r)
{
	(void)r;
	S("<tds:GetScopesResponse>");
	for (int i = 0; i < NSCOPES; i++)
		S("<tds:Scopes><tt:ScopeDef>Fixed</tt:ScopeDef><tt:ScopeItem>%s</tt:ScopeItem></tds:Scopes>",
		  scopes[i]);
	S("</tds:GetScopesResponse>");
	return 0;
}

static int op_hostname(const struct req *r)
{
	(void)r;
	char h[65] = "", o[65];
	size_t n = 0;
	gethostname(h, sizeof h - 1);
	for (const char *p = h; *p && n < sizeof o - 1; p++)
		if (isalnum((unsigned char)*p) || *p == '-' || *p == '.') o[n++] = *p;
	o[n] = 0;
	S("<tds:GetHostnameResponse><tds:HostnameInformation><tt:FromDHCP>false</tt:FromDHCP>"
	  "<tt:Name>%s</tt:Name></tds:HostnameInformation></tds:GetHostnameResponse>", o);
	return 0;
}

static size_t pub_read(const char *path, char *out, size_t cap);
static const char *net_status_path = "/run/net-status";   /* net-up's (#80); the host test: its own */

/* Is eth0's address a static one? net-up's /run/net-status says "mode=static" (0644, rcS's). */
static int net_static(void)
{
	char s[512];
	if (!pub_read(net_status_path, s, sizeof s)) return 0;
	return !strncmp(s, "mode=static\n", 12) || strstr(s, "\nmode=static\n") != NULL;
}

static int op_netif(const struct req *r)
{
	(void)r;
	uint8_t m[6];
	struct in_addr ip, mask;
	int mtu, prefix = 0, st = net_static();
	char ips[INET_ADDRSTRLEN];
	if_info(m, &ip, &mask, &mtu);
	for (uint32_t v = ntohl(mask.s_addr); v & 0x80000000u; v <<= 1) prefix++;
	inet_ntop(AF_INET, &ip, ips, sizeof ips);
	S("<tds:GetNetworkInterfacesResponse><tds:NetworkInterfaces token=\"%s\"><tt:Enabled>true"
	  "</tt:Enabled><tt:Info><tt:Name>%s</tt:Name><tt:HwAddress>%02x:%02x:%02x:%02x:%02x:%02x"
	  "</tt:HwAddress><tt:MTU>%d</tt:MTU></tt:Info><tt:IPv4><tt:Enabled>true</tt:Enabled>"
	  "<tt:Config><tt:%s><tt:Address>%s</tt:Address><tt:PrefixLength>%d</tt:PrefixLength>"
	  "</tt:%s><tt:DHCP>%s</tt:DHCP></tt:Config></tt:IPv4></tds:NetworkInterfaces>"
	  "</tds:GetNetworkInterfacesResponse>", ifname, ifname, m[0], m[1], m[2], m[3], m[4], m[5],
	  mtu, st ? "Manual" : "FromDHCP", ips, prefix, st ? "Manual" : "FromDHCP", st ? "false" : "true");
	return 0;
}

/* HTTP and RTSP, and HTTPS 443 while camtls is up (ONVIF's NetworkProtocolType has no RTSPS). */
static int op_netproto(const struct req *r)
{
	(void)r;
	S("<tds:GetNetworkProtocolsResponse><tds:NetworkProtocols><tt:Name>HTTP</tt:Name><tt:Enabled>"
	  "true</tt:Enabled><tt:Port>%d</tt:Port></tds:NetworkProtocols>", http_port);
	if (tls_up())
		S("<tds:NetworkProtocols><tt:Name>HTTPS</tt:Name><tt:Enabled>true</tt:Enabled><tt:Port>443"
		  "</tt:Port></tds:NetworkProtocols>");
	S("<tds:NetworkProtocols><tt:Name>RTSP</tt:Name><tt:Enabled>true</tt:Enabled><tt:Port>%d</tt:Port>"
	  "</tds:NetworkProtocols></tds:GetNetworkProtocolsResponse>", rtsp_port);
	return 0;
}

static int op_discmode(const struct req *r)
{
	(void)r;
	S("<tds:GetDiscoveryModeResponse><tds:DiscoveryMode>%s</tds:DiscoveryMode>"
	  "</tds:GetDiscoveryModeResponse>", disco_on ? "Discoverable" : "NonDiscoverable");
	return 0;
}

static int op_users(const struct req *r)
{
	(void)r;
	static const char *const level[] = { "Anonymous", "User", "Operator", "Administrator" };
	users_load();
	S("<tds:GetUsersResponse>");
	for (int i = 0; i < nusers; i++)
		S("<tds:User><tt:Username>%s</tt:Username><tt:UserLevel>%s</tt:UserLevel></tds:User>",
		  users[i].name, level[users[i].role]);   /* names are [A-Za-z0-9._-] (camcfg) */
	S("</tds:GetUsersResponse>");
	return 0;
}

static int op_wsdl(const struct req *r)
{
	(void)r;
	S("<tds:GetWsdlUrlResponse><tds:WsdlUrl>http://www.onvif.org/</tds:WsdlUrl></tds:GetWsdlUrlResponse>");
	return 0;
}

static int op_epr(const struct req *r)
{
	(void)r;
	if (!*epr) epr_make();
	S("<tds:GetEndpointReferenceResponse><tds:GUID>%s</tds:GUID></tds:GetEndpointReferenceResponse>",
	  epr);
	return 0;
}

static int op_relays(const struct req *r)
{
	S("<%s:GetRelayOutputsResponse/>", r->svc == SVC_DEVICEIO ? "tmd" : "tds");   /* none */
	return 0;
}

static int op_getntp(const struct req *r)
{
	(void)r;
	char ntp[NTP_MAX][64];
	struct in_addr a;
	int n = ntp_servers(ntp);
	S("<tds:GetNTPResponse><tds:NTPInformation><tt:FromDHCP>false</tt:FromDHCP>");
	for (int i = 0; i < n; i++) {
		int v4 = inet_pton(AF_INET, ntp[i], &a) == 1;
		S("<tt:NTPManual><tt:Type>%s</tt:Type><tt:%s>%s</tt:%s></tt:NTPManual>", v4 ? "IPv4" : "DNS",
		  v4 ? "IPv4Address" : "DNSname", ntp[i], v4 ? "IPv4Address" : "DNSname");
	}
	S("</tds:NTPInformation></tds:GetNTPResponse>");
	return 0;
}

/* FromDHCP=false with up to NTP_MAX NTPManual hosts (DNS or IPv4), saved as cam.conf time.ntp;
 * ntpc re-reads it on its next poll. No hosts = no NTP. */
static int op_setntp(const struct req *r)
{
	char dhcp[8], type[8], host[80], list[NTP_MAX * 64 + 4] = "";
	const char *p = r->op, *tag;
	int n = 0;
	struct in_addr a;
	if (xtext(r->op, r->end, "FromDHCP", dhcp, sizeof dhcp) || (strcmp(dhcp, "false") && strcmp(dhcp, "0")))
		return F_ARGS;                                  /* no DHCP-supplied servers */
	while ((p = xel(p, r->end, "NTPManual", &tag))) {
		const char *e = tag[strcspn(tag, ">") - 1] == '/' ? p : xclose(p, r->end, "NTPManual");
		if (++n > NTP_MAX || xtext(p, e, "Type", type, sizeof type)) return F_ARGS;
		if (!strcmp(type, "IPv4")) {
			if (xtext(p, e, "IPv4Address", host, sizeof host) || inet_pton(AF_INET, host, &a) != 1)
				return F_IPV4;
		} else if (!strcmp(type, "DNS")) {
			if (xtext(p, e, "DNSname", host, sizeof host) || !ntp_name_ok(host)) return F_DNS;
		} else {
			return F_ARGS;                              /* IPv6 isn't used here */
		}
		snprintf(list + strlen(list), sizeof list - strlen(list), "%s%s", n > 1 ? "," : "", host);
		p = e;
	}
	if (cfg_set("time.ntp", list)) return F_SAVE;
	LOG("NTP servers set to \"%s\" by %s\n", list, r->user);
	S("<tds:SetNTPResponse/>");
	return 0;
}

/* -- media -- */

static int token_idx(const struct req *r, const char *el, const char *prefix)
{
	char tok[64];
	size_t pl = strlen(prefix);
	if (xtext(r->op, r->end, el, tok, sizeof tok) || strncmp(tok, prefix, pl) ||
	    (strcmp(tok + pl, "1") && strcmp(tok + pl, "2")))
		return -1;
	int i = tok[pl] - '1';
	return st[i].on ? i : -1;
}

/* Orientation as cam.conf has it (image.mirror / image.flip, #133). */
static void orient_get(int *mirror, int *flip)
{
	char v[8];
	*mirror = conf_get("image.mirror", v, sizeof v) && !strcmp(v, "1");
	*flip = conf_get("image.flip", v, sizeof v) && !strcmp(v, "1");
}

/* tt:VideoSourceConfiguration with Extension/Rotate (ONVIF video orientation, which SSS's "Video
 * Orientation" panel reads). Rotate 180 = mirror + flip on the sensor; mirror or flip alone isn't
 * a rotation, so it reads as OFF. 90/270 need a real rotation (#123). Stock reports Rotate but
 * marks Rotation "false" and ignores a Set (docs/STOCK-ONVIF-ORIENTATION.md). */
static void vsc(const char *el)
{
	int m, f;
	orient_get(&m, &f);
	S("<%s token=\"VideoSourceConfig_1\"><tt:Name>VideoSourceConfig_1</tt:Name><tt:UseCount>%d"
	  "</tt:UseCount><tt:SourceToken>VideoSource_1</tt:SourceToken><tt:Bounds x=\"0\" y=\"0\" "
	  "width=\"%d\" height=\"%d\"/><tt:Extension><tt:Rotate><tt:Mode>%s</tt:Mode><tt:Degree>%d"
	  "</tt:Degree></tt:Rotate></tt:Extension></%s>", el, 1 + st[1].on, SENSOR_W, SENSOR_H,
	  m && f ? "ON" : "OFF", m && f ? 180 : 0, el);
}

/* Media ver10 has no H.265 encoding; an h265 stream is reported as "H265" (not in the schema). */
static void vec(const char *el, int i)
{
	const struct stream *s = &st[i];
	S("<%s token=\"VideoEncoder_%d\"><tt:Name>VideoEncoder_%d</tt:Name><tt:UseCount>1</tt:UseCount>"
	  "<tt:Encoding>%s</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d"
	  "</tt:Height></tt:Resolution><tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>"
	  "%d</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>%d"
	  "</tt:BitrateLimit></tt:RateControl>", el, i + 1, i + 1, s->h265 ? "H265" : "H264", s->w,
	  s->h, s->fps, s->kbps);
	if (!s->h265)
		S("<tt:H264><tt:GovLength>%d</tt:GovLength><tt:H264Profile>%s</tt:H264Profile></tt:H264>",
		  s->gop, s->profile);
	S("<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address>"
	  "</tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart>"
	  "</tt:Multicast><tt:SessionTimeout>PT60S</tt:SessionTimeout></%s>", el);
}

/* ---- motion detection settings (#77): what Analytics and Media show and change ---------- */

#define GRID 32                        /* rtspd's motion grid: GRID x GRID cells */
#define MASK_BYTES (GRID * GRID / 8)   /* motion.mask: row-major from the top-left, MSB first */
#define VA_TOKEN "VideoAnalyticsConfig_1"
#define MODULE_NAME "MyCellMotionModule"
#define RULE_NAME "MyMotionDetectorRule"

struct mset { int enabled, sens; uint8_t mask[MASK_BYTES]; };
static int level(const char *v);       /* an xs:float 0..100 (Imaging) */

static int hexval(int ch)
{
	return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 :
	       ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
}

/* motion.mask's 256 hex digits into 128 bytes; -1 if it isn't exactly that. */
static int mask_from_hex(const char *h, uint8_t mask[MASK_BYTES])
{
	if (strlen(h) != 2 * MASK_BYTES) return -1;
	for (int i = 0; i < MASK_BYTES; i++) {
		int a = hexval((unsigned char)h[2 * i]), b = hexval((unsigned char)h[2 * i + 1]);
		if (a < 0 || b < 0) return -1;
		mask[i] = (uint8_t)(a << 4 | b);
	}
	return 0;
}

static void mset_kv(struct mset *m, const char *k, const char *v)
{
	size_t vl = strlen(v);
	int x = vl >= 1 && vl <= 3 && strspn(v, "0123456789") == vl ? atoi(v) : -1;
	uint8_t mk[MASK_BYTES];
	if (!strcmp(k, "motion.enabled") && (x == 0 || x == 1)) m->enabled = x;
	else if (!strcmp(k, "motion.sensitivity") && x >= 0 && x <= 100) m->sens = x;
	else if (!strcmp(k, "motion.mask") && !mask_from_hex(v, mk)) memcpy(m->mask, mk, sizeof mk);
}

/* The motion detector's settings: live from rtspd's "get" (about 1.2 KiB with the mask), else
 * cam.conf, else rtspd's defaults (on, 50, every cell). 1 if live. */
static int motion_settings(struct mset *m)
{
	static const char *const keys[3] = { "motion.enabled", "motion.sensitivity", "motion.mask" };
	char rep[4096], v[300], *save;
	m->enabled = 1;
	m->sens = 50;
	memset(m->mask, 0xff, sizeof m->mask);
	if (!CTL_CMD("get\n", rep, sizeof rep, CTL_MS) && !strstr(rep, "err")) {
		for (char *l = strtok_r(rep, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
			char *eq = strchr(l, '=');
			if (!eq) continue;
			*eq = 0;
			mset_kv(m, l, eq + 1);
		}
		return 1;
	}
	for (int i = 0; i < 3; i++)
		if (conf_get(keys[i], v, sizeof v)) mset_kv(m, keys[i], v);
	return 0;
}

/* PackBits (Apple / TIFF), as ONVIF's CellMotionDetector ActiveCells use it: a header byte
 * 0..127 copies the next n+1 bytes, -1..-127 repeats the next byte 1-n times, -128 is a no-op.
 * Runs of 3 or more become run packets, everything else literals, so the output never exceeds
 * n + n / 128 + 1 bytes (a 2-byte run between literals would cost more than it saves). */
static size_t packbits_enc(const uint8_t *in, size_t n, uint8_t *out)
{
	size_t i = 0, o = 0;
	while (i < n) {
		size_t run = 1;
		while (i + run < n && run < 128 && in[i + run] == in[i]) run++;
		if (run >= 3) {
			out[o++] = (uint8_t)(257 - run);
			out[o++] = in[i];
			i += run;
			continue;
		}
		size_t lit = 1;                            /* up to the next run of three */
		while (i + lit < n && lit < 128 && !(i + lit + 2 < n && in[i + lit] == in[i + lit + 1] &&
						     in[i + lit] == in[i + lit + 2]))
			lit++;
		out[o++] = (uint8_t)(lit - 1);
		memcpy(out + o, in + i, lit);
		o += lit;
		i += lit;
	}
	return o;
}

/* Strict: every packet must fit, and the result must be exactly `want` bytes. 0 or -1. */
static int packbits_dec(const uint8_t *in, size_t n, uint8_t *out, size_t want)
{
	size_t i = 0, o = 0;
	while (i < n) {
		int h = (int8_t)in[i++];
		if (h >= 0) {
			size_t k = (size_t)h + 1;
			if (k > n - i || k > want - o) return -1;
			memcpy(out + o, in + i, k);
			i += k;
			o += k;
		} else if (h != -128) {
			size_t k = (size_t)(1 - h);
			if (i == n || k > want - o) return -1;
			memset(out + o, in[i++], k);
			o += k;
		}
	}
	return o == want ? 0 : -1;
}

/* ActiveCells as clients write them: base64, the '=' padding optional (the spec's own example
 * has too much of it). Bytes decoded, or -1. */
static int b64_dec_loose(const char *in, uint8_t *out, size_t cap)
{
	char b[1024];
	size_t n = strlen(in);
	while (n && in[n - 1] == '=') n--;
	if (!n || n % 4 == 1 || n + 4 >= sizeof b) return -1;
	memcpy(b, in, n);
	while (n % 4) b[n++] = '=';
	b[n] = 0;
	return b64_dec(b, out, cap);
}

/* The CellMotionEngine module and the CellMotionDetector rule, as Analytics and Media show them.
 * The layout puts cell (c, r) at x = -1 + c * 2/32, y = -1 + r * 2/32 of the normalized frame
 * (the Hikvision-style transformation clients use to draw the grid). MinCount, AlarmOnDelay and
 * AlarmOffDelay describe rtspd's detector (fixed: about 2 of 3 evaluations 200 ms apart to start,
 * 5 s without motion to end). */
static void module_xml(const char *el, int sens)
{
	S("<%s Name=\"" MODULE_NAME "\" Type=\"tt:CellMotionEngine\"><tt:Parameters><tt:SimpleItem "
	  "Name=\"Sensitivity\" Value=\"%d\"/><tt:ElementItem Name=\"Layout\"><tt:CellLayout Columns=\"%d\" "
	  "Rows=\"%d\"><tt:Transformation><tt:Translate x=\"-1.000000\" y=\"-1.000000\"/><tt:Scale "
	  "x=\"%.6f\" y=\"%.6f\"/></tt:Transformation></tt:CellLayout></tt:ElementItem></tt:Parameters></%s>",
	  el, sens, GRID, GRID, 2.0 / GRID, 2.0 / GRID, el);
}

static void rule_xml(const char *el, const uint8_t mask[MASK_BYTES])
{
	uint8_t pb[MASK_BYTES + MASK_BYTES / 128 + 1];
	char b64[4 * (sizeof pb + 2) / 3 + 4];
	b64_enc(pb, packbits_enc(mask, MASK_BYTES, pb), b64);
	S("<%s Name=\"" RULE_NAME "\" Type=\"tt:CellMotionDetector\"><tt:Parameters><tt:SimpleItem "
	  "Name=\"MinCount\" Value=\"1\"/><tt:SimpleItem Name=\"AlarmOnDelay\" Value=\"400\"/>"
	  "<tt:SimpleItem Name=\"AlarmOffDelay\" Value=\"5000\"/><tt:SimpleItem Name=\"ActiveCells\" "
	  "Value=\"%s\"/></tt:Parameters></%s>", el, b64, el);
}

/* Media ver10 VideoAnalyticsConfiguration: our one module and rule, in both profiles. */
static void vac(const char *el, const struct mset *m)
{
	S("<%s token=\"" VA_TOKEN "\"><tt:Name>" VA_TOKEN "</tt:Name><tt:UseCount>%d</tt:UseCount>"
	  "<tt:AnalyticsEngineConfiguration>", el, 1 + st[1].on);
	module_xml("tt:AnalyticsModule", m->sens);
	S("</tt:AnalyticsEngineConfiguration><tt:RuleEngineConfiguration>");
	rule_xml("tt:Rule", m->mask);
	S("</tt:RuleEngineConfiguration></%s>", el);
}

/* The SimpleItem named `name` in [p, end): 0 with its Value in out, -1 if there is none, -2 if
 * its Value is missing or longer than cap. */
static int simple_item(const char *p, const char *end, const char *name, char *out, size_t cap)
{
	const char *tag;
	char n[64];
	*out = 0;
	while ((p = xel(p, end, "SimpleItem", &tag)))
		if (!xattr(tag, end, "Name", n, sizeof n) && !strcmp(n, name))
			return xattr(tag, end, "Value", out, cap) ? -2 : 0;
	return -1;
}

/* Does the Type attribute (a QName, any prefix) of the element at tag name `local`? */
static int type_is(const char *tag, const char *end, const char *local)
{
	char t[64];
	if (xattr(tag, end, "Type", t, sizeof t)) return 1;           /* no Type: fine */
	const char *c = strchr(t, ':');
	return !strcmp(c ? c + 1 : t, local);
}

/* AnalyticsModule elements in [p, end) into w: ours only (else ModuleNotExistent), Sensitivity
 * 0..100 (rounded), a Layout only if it is our 32x32 grid. 0 or a fault. */
static int parse_modules(const char *p, const char *end, struct mset *w)
{
	const char *tag, *c;
	char v[64];
	while ((c = xel(p, end, "AnalyticsModule", &tag))) {
		const char *e = c[-2] == '/' ? c : xclose(c, end, "AnalyticsModule"), *lt;
		if (xattr(tag, end, "Name", v, sizeof v) || strcmp(v, MODULE_NAME)) return F_NOMODULE;
		if (!type_is(tag, end, "CellMotionEngine")) return F_BADMODULE;
		int s = simple_item(c, e, "Sensitivity", v, sizeof v);
		if (s == -2 || (!s && (w->sens = level(v)) < 0)) return F_BADMODULE;
		if (xel(c, e, "CellLayout", &lt)) {
			char cols[8], rows[8];
			if (xattr(lt, e, "Columns", cols, sizeof cols) || xattr(lt, e, "Rows", rows, sizeof rows) ||
			    atoi(cols) != GRID || atoi(rows) != GRID || strspn(cols, "0123456789") != strlen(cols) ||
			    strspn(rows, "0123456789") != strlen(rows))
				return F_BADMODULE;
		}
		p = e;
	}
	return 0;
}

/* Rule elements in [p, end) into w: ours only (else RuleNotExistent; CreateRules: TooManyRules),
 * ActiveCells base64 of PackBits of exactly 32x32 bits; MinCount, AlarmOnDelay and AlarmOffDelay
 * must be whole numbers and are otherwise ignored. 0 or a fault. */
static int parse_rules(const char *p, const char *end, struct mset *w, int create)
{
	static const char *const ints[3] = { "MinCount", "AlarmOnDelay", "AlarmOffDelay" };
	const char *tag, *c;
	char v[800];
	uint8_t raw[600];
	while ((c = xel(p, end, "Rule", &tag))) {
		const char *e = c[-2] == '/' ? c : xclose(c, end, "Rule");
		if (xattr(tag, end, "Name", v, sizeof v) || strcmp(v, RULE_NAME)) return create ? F_TOOMANYRULES : F_NORULE;
		if (!type_is(tag, end, "CellMotionDetector")) return F_BADRULE;
		for (int i = 0; i < 3; i++) {
			int s = simple_item(c, e, ints[i], v, sizeof v);
			if (s == -2 || (!s && (!*v || strlen(v) > 9 || strspn(v, "0123456789") != strlen(v))))
				return F_BADRULE;
		}
		int s = simple_item(c, e, "ActiveCells", v, sizeof v);   /* none: the cells stay */
		if (s == -2) return F_BADRULE;
		if (!s) {
			int n = b64_dec_loose(v, raw, sizeof raw);
			if (n < 1 || packbits_dec(raw, (size_t)n, w->mask, MASK_BYTES)) return F_BADRULE;
		}
		p = e;
	}
	return 0;
}

/* Saves (camcfg) and applies (rtspd "set") what differs between cur and w. 0 or F_SAVE. */
static int mset_apply(const struct mset *cur, const struct mset *w, const char *user)
{
	char val[2 * MASK_BYTES + 1], line[300], rep[64];
	for (int k = 0; k < 2; k++) {
		const char *key = k ? "motion.mask" : "motion.sensitivity";
		if (k ? !memcmp(cur->mask, w->mask, MASK_BYTES) : cur->sens == w->sens) continue;
		if (k) hex(w->mask, MASK_BYTES, val);
		else snprintf(val, sizeof val, "%d", w->sens);
		if (cfg_set(key, val)) {
			LOG("camcfg set %s failed\n", key);
			return F_SAVE;
		}
		snprintf(line, sizeof line, "set %s %s\n", key, val);
		if (CTL_CMD(line, rep, sizeof rep, CTL_MS) || strncmp(rep, "ok", 2))
			LOG("%s saved; rtspd didn't apply it live (not running?)\n", key);
		LOG("%s set by %s\n", key, user);
	}
	return 0;
}

/* ---- audio (#110): rtspd's microphone track, G.711 mu-law 8 kHz mono, in both RTSP streams ---- */

#define AS_TOKEN "AudioSource_1"
#define ASC_TOKEN "AudioSourceConfig_1"
#define AEC_TOKEN "AudioEncoderConfig_1"

static void asc(const char *el)
{
	S("<%s token=\"" ASC_TOKEN "\"><tt:Name>" ASC_TOKEN "</tt:Name><tt:UseCount>%d</tt:UseCount>"
	  "<tt:SourceToken>" AS_TOKEN "</tt:SourceToken></%s>", el, 1 + st[1].on, el);
}

static void aec(const char *el)
{
	S("<%s token=\"" AEC_TOKEN "\"><tt:Name>" AEC_TOKEN "</tt:Name><tt:UseCount>%d</tt:UseCount>"
	  "<tt:Encoding>G711</tt:Encoding><tt:Bitrate>64</tt:Bitrate><tt:SampleRate>8</tt:SampleRate>"
	  "<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address>"
	  "</tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart>"
	  "</tt:Multicast><tt:SessionTimeout>PT60S</tt:SessionTimeout></%s>", el, 1 + st[1].on, el);
}

#define AO_TOKEN "AudioOutput_1"
#define AOC_TOKEN "AudioOutputConfig_1"
#define ADC_TOKEN "AudioDecoderConfig_1"
#define AO_LEVEL 100                   /* OutputLevel: nothing sets the speaker volume yet */

static void aoc(const char *el)
{
	S("<%s token=\"" AOC_TOKEN "\"><tt:Name>" AOC_TOKEN "</tt:Name><tt:UseCount>%d</tt:UseCount>"
	  "<tt:OutputToken>" AO_TOKEN "</tt:OutputToken><tt:SendPrimacy>www.onvif.org/ver20/HalfDuplex/Auto"
	  "</tt:SendPrimacy><tt:OutputLevel>%d</tt:OutputLevel></%s>", el, 1 + st[1].on, AO_LEVEL, el);
}

static void adc(const char *el)
{
	S("<%s token=\"" ADC_TOKEN "\"><tt:Name>" ADC_TOKEN "</tt:Name><tt:UseCount>%d</tt:UseCount></%s>",
	  el, 1 + st[1].on, el);
}

/* tt:Profile's order: VideoSource, AudioSource, VideoEncoder, AudioEncoder, VideoAnalytics, then
 * Extension (AudioOutput, AudioDecoder). */
static void profile(const char *el, int i, const struct mset *m)
{
	S("<%s token=\"Profile_%d\" fixed=\"true\"><tt:Name>%s</tt:Name>", el, i + 1,
	  i ? "SubStream" : "MainStream");
	vsc("tt:VideoSourceConfiguration");
	if (audio_on) asc("tt:AudioSourceConfiguration");
	vec("tt:VideoEncoderConfiguration", i);
	if (audio_on) aec("tt:AudioEncoderConfiguration");
	vac("tt:VideoAnalyticsConfiguration", m);
	if (audio_on) {                                    /* tt:ProfileExtension (#117) */
		S("<tt:Extension>");
		aoc("tt:AudioOutputConfiguration");
		adc("tt:AudioDecoderConfiguration");
		S("</tt:Extension>");
	}
	S("</%s>", el);
}

static int op_profiles(const struct req *r)
{
	(void)r;
	struct mset m;
	motion_settings(&m);
	S("<trt:GetProfilesResponse>");
	for (int i = 0; i < 2; i++)
		if (st[i].on) profile("trt:Profiles", i, &m);
	S("</trt:GetProfilesResponse>");
	return 0;
}

static int op_profile(const struct req *r)
{
	struct mset m;
	int i = token_idx(r, "ProfileToken", "Profile_");
	if (i < 0) return F_NOPROFILE;
	motion_settings(&m);
	S("<trt:GetProfileResponse>");
	profile("trt:Profile", i, &m);
	S("</trt:GetProfileResponse>");
	return 0;
}

static void media_uri(const char *op, const char *uri)
{
	S("<trt:%sResponse><trt:MediaUri><tt:Uri>%s</tt:Uri><tt:InvalidAfterConnect>false"
	  "</tt:InvalidAfterConnect><tt:InvalidAfterReboot>false</tt:InvalidAfterReboot><tt:Timeout>"
	  "PT0S</tt:Timeout></trt:MediaUri></trt:%sResponse>", op, uri, op);
}

/* rtsps://ADDRESS:322/ (camtls, relaying to rtspd) while HTTPS is up, for a request that came over
 * it or always once net.plain is 0; else rtsp://ADDRESS:554/ as before. camtls's one ready file
 * covers its RTSPS listener too (tls_up). */
static int op_streamuri(const struct req *r)
{
	char mode[24] = "", uri[96];
	int i = token_idx(r, "ProfileToken", "Profile_");
	if (i < 0) return F_NOPROFILE;
	xtext(r->op, r->end, "Stream", mode, sizeof mode);
	if (!strcmp(mode, "RTP-Multicast")) return F_STREAMSETUP;
	if (tls_up() && (r->c->tls || !plain_on()))
		snprintf(uri, sizeof uri, "rtsps://%s:%d/%s", r->c->local, RTSPS_PORT, i ? "sub" : "");
	else snprintf(uri, sizeof uri, "rtsp://%s:%d/%s", r->c->local, rtsp_port, i ? "sub" : "");
	media_uri("GetStreamUri", uri);
	return 0;
}

static int op_snapuri(const struct req *r)
{
	char uri[96];
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	base_url(r, uri, sizeof uri - 16);
	strcat(uri, "/snapshot.jpg");
	media_uri("GetSnapshotUri", uri);
	return 0;
}

static int op_vsources(const struct req *r)
{
	if (r->svc == SVC_DEVICEIO) {                      /* DeviceIO: just the tokens */
		S("<tmd:GetVideoSourcesResponse><tmd:Token>VideoSource_1</tmd:Token></tmd:GetVideoSourcesResponse>");
		return 0;
	}
	S("<trt:GetVideoSourcesResponse><trt:VideoSources token=\"VideoSource_1\"><tt:Framerate>%d"
	  "</tt:Framerate><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height>"
	  "</tt:Resolution></trt:VideoSources></trt:GetVideoSourcesResponse>", st[0].fps, SENSOR_W, SENSOR_H);
	return 0;
}

static int op_vsconfs(const struct req *r)
{
	int compat = !!xel(r->op, r->end, "ProfileToken", NULL);
	if (compat && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	const char *op = compat ? "GetCompatibleVideoSourceConfigurations" : "GetVideoSourceConfigurations";
	S("<trt:%sResponse>", op);
	vsc("trt:Configurations");
	S("</trt:%sResponse>", op);
	return 0;
}

static int op_vsconf(const struct req *r)
{
	char tok[64];
	if (xtext(r->op, r->end, "ConfigurationToken", tok, sizeof tok) || strcmp(tok, "VideoSourceConfig_1"))
		return F_NOCONFIG;
	S("<trt:GetVideoSourceConfigurationResponse>");
	vsc("trt:Configuration");
	S("</trt:GetVideoSourceConfigurationResponse>");
	return 0;
}

static int op_vecs(const struct req *r)
{
	int compat = !!xel(r->op, r->end, "ProfileToken", NULL), only = -1;
	if (compat && (only = token_idx(r, "ProfileToken", "Profile_")) < 0) return F_NOPROFILE;
	const char *op = compat ? "GetCompatibleVideoEncoderConfigurations" : "GetVideoEncoderConfigurations";
	S("<trt:%sResponse>", op);
	for (int i = 0; i < 2; i++)
		if (st[i].on && (only < 0 || only == i)) vec("trt:Configurations", i);
	S("</trt:%sResponse>", op);
	return 0;
}

static int op_vec(const struct req *r)
{
	int i = token_idx(r, "ConfigurationToken", "VideoEncoder_");
	if (i < 0) return F_NOCONFIG;
	S("<trt:GetVideoEncoderConfigurationResponse>");
	vec("trt:Configuration", i);
	S("</trt:GetVideoEncoderConfigurationResponse>");
	return 0;
}

/* ResolutionsAvailable: every size stream.<main|sub>.size takes (streamcfg.h) for the encoder
 * asked about; with none named, both encoders' (1280x720 once). */
static void h264_opts(int sel, int ext)
{
	const struct stream_size *z;
	S("<tt:H264>");
	for (int i = 0; i < 2; i++) {
		if (!st[i].on || (sel >= 0 && sel != i)) continue;
		for (int k = 0; (z = stream_size_at(i, k)); k++)
			if (sel >= 0 || !i || !st[0].on || !stream_size_find(0, z->name))
				S("<tt:ResolutionsAvailable><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height>"
				  "</tt:ResolutionsAvailable>", z->w, z->h);
	}
	S("<tt:GovLengthRange><tt:Min>1</tt:Min><tt:Max>1000</tt:Max></tt:GovLengthRange>"
	  "<tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>%d</tt:Max></tt:FrameRateRange>"
	  "<tt:EncodingIntervalRange><tt:Min>1</tt:Min><tt:Max>1</tt:Max></tt:EncodingIntervalRange>"
	  "<tt:H264ProfilesSupported>Baseline</tt:H264ProfilesSupported><tt:H264ProfilesSupported>"
	  "Main</tt:H264ProfilesSupported><tt:H264ProfilesSupported>High</tt:H264ProfilesSupported>",
	  STREAM_FPS_MAX);
	if (ext) S("<tt:BitrateRange><tt:Min>64</tt:Min><tt:Max>16384</tt:Max></tt:BitrateRange>");
	S("</tt:H264>");
}

/* Read-only: options describe what cam.conf (camcfg) accepts. */
static int op_vecopts(const struct req *r)
{
	int sel = -1;
	if (xel(r->op, r->end, "ConfigurationToken", NULL)) {
		if ((sel = token_idx(r, "ConfigurationToken", "VideoEncoder_")) < 0) return F_NOCONFIG;
	} else if (xel(r->op, r->end, "ProfileToken", NULL)) {
		if ((sel = token_idx(r, "ProfileToken", "Profile_")) < 0) return F_NOPROFILE;
	}
	S("<trt:GetVideoEncoderConfigurationOptionsResponse><trt:Options><tt:QualityRange><tt:Min>0"
	  "</tt:Min><tt:Max>10</tt:Max></tt:QualityRange>");
	h264_opts(sel, 0);
	S("<tt:Extension>");
	h264_opts(sel, 1);
	S("</tt:Extension></trt:Options></trt:GetVideoEncoderConfigurationOptionsResponse>");
	return 0;
}

static int op_guaranteed(const struct req *r)
{
	char tok[64];
	if (!xtext(r->op, r->end, "ConfigurationToken", tok, sizeof tok) && strcmp(tok, "VideoSourceConfig_1"))
		return F_NOCONFIG;
	int n = st[0].on + st[1].on, h265 = st[0].h265 + st[1].on * st[1].h265;
	S("<trt:GetGuaranteedNumberOfVideoEncoderInstancesResponse><trt:TotalNumber>%d</trt:TotalNumber>"
	  "<trt:JPEG>0</trt:JPEG><trt:H264>%d</trt:H264><trt:MPEG4>0</trt:MPEG4>"
	  "</trt:GetGuaranteedNumberOfVideoEncoderInstancesResponse>", n, n - h265);
	return 0;
}

static int op_vscopts(const struct req *r)
{
	char tok[64];
	if (!xtext(r->op, r->end, "ConfigurationToken", tok, sizeof tok) && strcmp(tok, "VideoSourceConfig_1"))
		return F_NOCONFIG;
	if (xel(r->op, r->end, "ProfileToken", NULL) && token_idx(r, "ProfileToken", "Profile_") < 0)
		return F_NOPROFILE;
	S("<trt:GetVideoSourceConfigurationOptionsResponse><trt:Options><tt:BoundsRange><tt:XRange>"
	  "<tt:Min>0</tt:Min><tt:Max>0</tt:Max></tt:XRange><tt:YRange><tt:Min>0</tt:Min><tt:Max>0</tt:Max>"
	  "</tt:YRange><tt:WidthRange><tt:Min>%d</tt:Min><tt:Max>%d</tt:Max></tt:WidthRange><tt:HeightRange>"
	  "<tt:Min>%d</tt:Min><tt:Max>%d</tt:Max></tt:HeightRange></tt:BoundsRange>"
	  "<tt:VideoSourceTokensAvailable>VideoSource_1</tt:VideoSourceTokensAvailable><tt:Extension>"
	  "<tt:Rotate><tt:Mode>OFF</tt:Mode><tt:Mode>ON</tt:Mode><tt:DegreeList><tt:Items>180</tt:Items>"
	  "</tt:DegreeList></tt:Rotate></tt:Extension></trt:Options>"
	  "</trt:GetVideoSourceConfigurationOptionsResponse>", SENSOR_W, SENSOR_W, SENSOR_H, SENSOR_H);
	return 0;
}

/* SetVideoSourceConfiguration: only the orientation can change (Bounds must stay the full sensor
 * picture). Rotate OFF (or ON 0) = no mirror/flip, ON 180 = both; saved with camcfg and applied
 * live like the web UI's Orientation. What a client sends is logged, so its mapping of separate
 * Mirror/Flip controls shows (SSS is closed). */
static int save_live(const char *key, const char *val, const char *user);
static int ui_int(const char *v, int lo, int hi);
static char *log_clean(char *p);

static int op_setvsc(const struct req *r)
{
	char tok[64], mode[8] = "", deg[16] = "";
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	int x = 0, y = 0, w = SENSOR_W, h = SENSOR_H, m, f, want;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, "VideoSourceConfig_1")) return F_NOCONFIG;
	const char *ce = c[-2] == '/' ? c : xclose(c, r->end, "Configuration");
	if (xel(c, ce, "SourceToken", NULL) && (xtext(c, ce, "SourceToken", tok, sizeof tok) || strcmp(tok, "VideoSource_1")))
		return F_CONFIGMODIFY;
	const char *bt, *b = xel(c, ce, "Bounds", &bt);
	if (b) {
		char v[16];
		const char *n[4] = { "x", "y", "width", "height" };
		int *o[4] = { &x, &y, &w, &h };
		for (int i = 0; i < 4; i++)
			if (!xattr(bt, ce, n[i], v, sizeof v) && ((*o[i] = ui_int(v, 0, 99999)) < 0)) return F_CONFIGMODIFY;
		if (x || y || w != SENSOR_W || h != SENSOR_H) return F_CONFIGMODIFY;
	}
	const char *rt = xel(c, ce, "Rotate", NULL);
	if (!rt) {
		S("<trt:SetVideoSourceConfigurationResponse/>");
		return 0;
	}
	const char *re = xclose(rt, ce, "Rotate");
	xtext(rt, re, "Mode", mode, sizeof mode);
	xtext(rt, re, "Degree", deg, sizeof deg);
	LOG("SetVideoSourceConfiguration by %s: Rotate Mode '%s' Degree '%s'\n", r->user, log_clean(mode), log_clean(deg));
	if (!strcmp(mode, "OFF") || (!strcmp(mode, "ON") && (!*deg || !strcmp(deg, "0")))) want = 0;
	else if (!strcmp(mode, "ON") && !strcmp(deg, "180")) want = 1;
	else return F_CONFIGMODIFY;                        /* AUTO, 90, 270: not without #123 */
	orient_get(&m, &f);
	if ((m != want && save_live("image.mirror", want ? "1" : "0", r->user)) ||
	    (f != want && save_live("image.flip", want ? "1" : "0", r->user)))
		return F_SAVE;
	S("<trt:SetVideoSourceConfigurationResponse/>");
	return 0;
}

/* Is the token element `el` present and equal to `want`? -1 absent, 0 different, 1 equal. */
static int token_is(const struct req *r, const char *el, const char *want)
{
	char tok[64];
	if (!xel(r->op, r->end, el, NULL)) return -1;
	return !xtext(r->op, r->end, el, tok, sizeof tok) && !strcmp(tok, want);
}

/* With audio off (audio.enabled=0) the options stay empty, as before there was audio. */
static int op_aecopts(const struct req *r)
{
	if (audio_on && !token_is(r, "ConfigurationToken", AEC_TOKEN)) return F_NOCONFIG;
	if (audio_on && xel(r->op, r->end, "ProfileToken", NULL) && token_idx(r, "ProfileToken", "Profile_") < 0)
		return F_NOPROFILE;
	S("<trt:GetAudioEncoderConfigurationOptionsResponse>");
	if (audio_on)
		S("<trt:Options><tt:Options><tt:Encoding>G711</tt:Encoding><tt:BitrateList><tt:Items>64"
		  "</tt:Items></tt:BitrateList><tt:SampleRateList><tt:Items>8</tt:Items></tt:SampleRateList>"
		  "</tt:Options></trt:Options>");
	else
		S("<trt:Options/>");
	S("</trt:GetAudioEncoderConfigurationOptionsResponse>");
	return 0;
}

static int op_asources(const struct req *r)
{
	if (!audio_on) return F_AUDIO;
	if (r->svc == SVC_DEVICEIO) {
		S("<tmd:GetAudioSourcesResponse><tmd:Token>" AS_TOKEN "</tmd:Token></tmd:GetAudioSourcesResponse>");
		return 0;
	}
	S("<trt:GetAudioSourcesResponse><trt:AudioSources token=\"" AS_TOKEN "\"><tt:Channels>1"
	  "</tt:Channels></trt:AudioSources></trt:GetAudioSourcesResponse>");
	return 0;
}

/* GetAudioSourceConfigurations, and GetCompatibleAudioSourceConfigurations (ProfileToken) */
static int op_ascs(const struct req *r)
{
	int compat = !!xel(r->op, r->end, "ProfileToken", NULL);
	if (!audio_on) return F_AUDIO;
	if (compat && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	const char *op = compat ? "GetCompatibleAudioSourceConfigurations" : "GetAudioSourceConfigurations";
	S("<trt:%sResponse>", op);
	asc("trt:Configurations");
	S("</trt:%sResponse>", op);
	return 0;
}

static int op_ascone(const struct req *r)
{
	if (!audio_on) return F_AUDIO;
	if (token_is(r, "ConfigurationToken", ASC_TOKEN) != 1) return F_NOCONFIG;
	S("<trt:GetAudioSourceConfigurationResponse>");
	asc("trt:Configuration");
	S("</trt:GetAudioSourceConfigurationResponse>");
	return 0;
}

static int op_ascopts(const struct req *r)
{
	if (!audio_on) return F_AUDIO;
	if (!token_is(r, "ConfigurationToken", ASC_TOKEN)) return F_NOCONFIG;
	if (xel(r->op, r->end, "ProfileToken", NULL) && token_idx(r, "ProfileToken", "Profile_") < 0)
		return F_NOPROFILE;
	S("<trt:GetAudioSourceConfigurationOptionsResponse><trt:Options><tt:InputTokensAvailable>" AS_TOKEN
	  "</tt:InputTokensAvailable></trt:Options></trt:GetAudioSourceConfigurationOptionsResponse>");
	return 0;
}

/* GetAudioEncoderConfigurations, and GetCompatibleAudioEncoderConfigurations (ProfileToken) */
static int op_aecs(const struct req *r)
{
	int compat = !!xel(r->op, r->end, "ProfileToken", NULL);
	if (!audio_on) return F_AUDIO;
	if (compat && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	const char *op = compat ? "GetCompatibleAudioEncoderConfigurations" : "GetAudioEncoderConfigurations";
	S("<trt:%sResponse>", op);
	aec("trt:Configurations");
	S("</trt:%sResponse>", op);
	return 0;
}

static int op_aecone(const struct req *r)
{
	if (!audio_on) return F_AUDIO;
	if (token_is(r, "ConfigurationToken", AEC_TOKEN) != 1) return F_NOCONFIG;
	S("<trt:GetAudioEncoderConfigurationResponse>");
	aec("trt:Configuration");
	S("</trt:GetAudioEncoderConfigurationResponse>");
	return 0;
}

/* Add*: both profiles already carry the audio configurations, so adding ours is a no-op. */
static int add_audio(const struct req *r, const char *tok, const char *op)
{
	if (!audio_on) return F_AUDIO;
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	if (token_is(r, "ConfigurationToken", tok) != 1) return F_NOCONFIG;
	S("<trt:%sResponse/>", op);
	return 0;
}

static int op_addasc(const struct req *r) { return add_audio(r, ASC_TOKEN, "AddAudioSourceConfiguration"); }
static int op_addaec(const struct req *r) { return add_audio(r, AEC_TOKEN, "AddAudioEncoderConfiguration"); }

/* Remove*: acknowledged and ignored. A client can't switch the microphone off this way (that
 * would also take it out of the other profile and every RTSP stream); audio.enabled=0 does. */
static int rm_audio(const struct req *r, const char *op)
{
	if (!audio_on) return F_AUDIO;
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	if (verbose) LOG("%s ignored: the microphone stays in both profiles\n", op);
	S("<trt:%sResponse/>", op);
	return 0;
}

static int op_rmasc(const struct req *r) { return rm_audio(r, "RemoveAudioSourceConfiguration"); }
static int op_rmaec(const struct req *r) { return rm_audio(r, "RemoveAudioEncoderConfiguration"); }

/* Set*: only what we have (AudioSource_1; G.711, 64 kbit/s, 8 kHz) is accepted, and changes
 * nothing; anything else is ConfigModify. */
static int op_setasc(const struct req *r)
{
	char tok[64], v[64];
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	if (!audio_on) return F_AUDIO;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, ASC_TOKEN)) return F_NOCONFIG;
	const char *ce = c[-2] == '/' ? c : xclose(c, r->end, "Configuration");
	if (xel(c, ce, "SourceToken", NULL) && (xtext(c, ce, "SourceToken", v, sizeof v) || strcmp(v, AS_TOKEN)))
		return F_CONFIGMODIFY;
	S("<trt:SetAudioSourceConfigurationResponse/>");
	return 0;
}

static int op_setaec(const struct req *r)
{
	static const char *const want[3][2] = { { "Encoding", "G711" }, { "Bitrate", "64" }, { "SampleRate", "8" } };
	char tok[64], v[64];
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	if (!audio_on) return F_AUDIO;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, AEC_TOKEN)) return F_NOCONFIG;
	const char *ce = c[-2] == '/' ? c : xclose(c, r->end, "Configuration");
	for (int i = 0; i < 3; i++)
		if (xel(c, ce, want[i][0], NULL) && (xtext(c, ce, want[i][0], v, sizeof v) || strcmp(v, want[i][1])))
			return F_CONFIGMODIFY;
	S("<trt:SetAudioEncoderConfigurationResponse/>");
	return 0;
}

/* ---- the speaker (#117): rtspd plays what a client sends on the RTSP backchannel ------------ */

static int xint(const char *p, const char *end, const char *name, int lo, int hi, int *out);

static int op_aouts(const struct req *r)
{
	if (!audio_on) return F_AUDIOOUT;
	if (r->svc == SVC_DEVICEIO)
		S("<tmd:GetAudioOutputsResponse><tmd:Token>" AO_TOKEN "</tmd:Token></tmd:GetAudioOutputsResponse>");
	else
		S("<trt:GetAudioOutputsResponse><trt:AudioOutputs token=\"" AO_TOKEN "\"/></trt:GetAudioOutputsResponse>");
	return 0;
}

/* Output or decoder configuration, by the operation's name. */
static void ocfg_xml(const struct req *r, const char *el)
{
	if (strstr(r->name, "AudioDecoder")) adc(el);
	else aoc(el);
}

static const char *ocfg_token(const struct req *r)
{
	return strstr(r->name, "AudioDecoder") ? ADC_TOKEN : AOC_TOKEN;
}

/* Get(Compatible)AudioOutputConfigurations, Get(Compatible)AudioDecoderConfigurations */
static int op_ocfgs(const struct req *r)
{
	if (!audio_on) return F_AUDIOOUT;
	if (xel(r->op, r->end, "ProfileToken", NULL) && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	S("<trt:%sResponse>", r->name);
	ocfg_xml(r, "trt:Configurations");
	S("</trt:%sResponse>", r->name);
	return 0;
}

static int op_ocfg(const struct req *r)
{
	if (!audio_on) return F_AUDIOOUT;
	if (token_is(r, "ConfigurationToken", ocfg_token(r)) != 1) return F_NOCONFIG;
	S("<trt:%sResponse>", r->name);
	ocfg_xml(r, "trt:Configuration");
	S("</trt:%sResponse>", r->name);
	return 0;
}

static int ocfg_opts_tokens(const struct req *r)
{
	if (!token_is(r, "ConfigurationToken", ocfg_token(r))) return F_NOCONFIG;
	if (xel(r->op, r->end, "ProfileToken", NULL) && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	return 0;
}

#define PRIMACY "www.onvif.org/ver20/HalfDuplex/"
static const char *const primacy[3] = { PRIMACY "Server", PRIMACY "Client", PRIMACY "Auto" };

static int op_aocopts(const struct req *r)
{
	int f;
	if (!audio_on) return F_AUDIOOUT;
	if ((f = ocfg_opts_tokens(r))) return f;
	S("<trt:GetAudioOutputConfigurationOptionsResponse><trt:Options><tt:OutputTokensAvailable>" AO_TOKEN
	  "</tt:OutputTokensAvailable>");
	for (int i = 0; i < 3; i++) S("<tt:SendPrimacyOptions>%s</tt:SendPrimacyOptions>", primacy[i]);
	S("<tt:OutputLevelRange><tt:Min>0</tt:Min><tt:Max>100</tt:Max></tt:OutputLevelRange></trt:Options>"
	  "</trt:GetAudioOutputConfigurationOptionsResponse>");
	return 0;
}

/* rtspd's backchannel takes PCMU or PCMA at 8 kHz: G.711, 64 kbit/s */
static int op_adcopts(const struct req *r)
{
	int f;
	if (!audio_on) return F_AUDIOOUT;
	if ((f = ocfg_opts_tokens(r))) return f;
	S("<trt:GetAudioDecoderConfigurationOptionsResponse><trt:Options><tt:G711DecOptions><tt:Bitrate>"
	  "<tt:Items>64</tt:Items></tt:Bitrate><tt:SampleRateRange><tt:Items>8</tt:Items></tt:SampleRateRange>"
	  "</tt:G711DecOptions></trt:Options></trt:GetAudioDecoderConfigurationOptionsResponse>");
	return 0;
}

/* Add: both profiles already carry them. Remove: acknowledged and ignored, as for the microphone
 * (the talk path is the RTSP backchannel; audio.enabled=0 turns audio off). */
static int op_oadd(const struct req *r)
{
	if (!audio_on) return F_AUDIOOUT;
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	if (token_is(r, "ConfigurationToken", ocfg_token(r)) != 1) return F_NOCONFIG;
	S("<trt:%sResponse/>", r->name);
	return 0;
}

static int op_orm(const struct req *r)
{
	if (!audio_on) return F_AUDIOOUT;
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	if (verbose) LOG("%s ignored: the speaker stays in both profiles\n", r->name);
	S("<trt:%sResponse/>", r->name);
	return 0;
}

/* SetAudioOutputConfiguration: OutputToken AudioOutput_1, any of the three SendPrimacy values,
 * OutputLevel 0..100. Accepted and not stored: nothing sets the speaker volume yet. */
static int op_setaoc(const struct req *r)
{
	char tok[64], v[80];
	int level;
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	if (!audio_on) return F_AUDIOOUT;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, AOC_TOKEN)) return F_NOCONFIG;
	const char *ce = c[-2] == '/' ? c : xclose(c, r->end, "Configuration");
	if (xel(c, ce, "OutputToken", NULL) && (xtext(c, ce, "OutputToken", v, sizeof v) || strcmp(v, AO_TOKEN)))
		return F_CONFIGMODIFY;
	if (xel(c, ce, "SendPrimacy", NULL)) {
		if (xtext(c, ce, "SendPrimacy", v, sizeof v)) return F_CONFIGMODIFY;
		if (strcmp(v, primacy[0]) && strcmp(v, primacy[1]) && strcmp(v, primacy[2])) return F_CONFIGMODIFY;
	}
	if (xint(c, ce, "OutputLevel", 0, 100, &level) < 0) return F_CONFIGMODIFY;
	S("<trt:SetAudioOutputConfigurationResponse/>");
	return 0;
}

static int op_setadc(const struct req *r)
{
	char tok[64];
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	if (!audio_on) return F_AUDIOOUT;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, ADC_TOKEN)) return F_NOCONFIG;
	S("<trt:SetAudioDecoderConfigurationResponse/>");
	return 0;
}


/* A whole number lo..hi in element `name` of [p, end): 1 (in *out), 0 if absent, -1 if bad. */
static int xint(const char *p, const char *end, const char *name, int lo, int hi, int *out)
{
	char b[12];
	if (!xel(p, end, name, NULL)) return 0;
	if (xtext(p, end, name, b, sizeof b) || !*b || strlen(b) > 6 || b[strspn(b, "0123456789")])
		return -1;
	int v = atoi(b);
	if (v < lo || v > hi) return -1;
	*out = v;
	return 1;
}

/* Client text about to be logged: printable ASCII only. */
static char *log_clean(char *p)
{
	for (char *q = p; *q; q++)
		if (!isgraph((unsigned char)*q)) *q = '?';
	return p;
}

/* Saves what differs between stream i as cam.conf has it and `want`, one camcfg set
 * stream.<main|sub>.KEY per change: the number saved, or -1 if camcfg failed. rtspd reads them
 * at its next start. (SetVideoEncoderConfiguration and the web UI's streams page.) An unset
 * kbps left at its size's default stays unset, so it follows a new size. */
static int stream_save(int i, const struct stream *want, const char *user)
{
	struct { const char *key; char val[16]; } ch[6];
	int n = 0;
	if (want->h265 != st[i].h265) { ch[n].key = "codec"; snprintf(ch[n++].val, 16, "%s", want->h265 ? "h265" : "h264"); }
	if (want->kbps != st[i].kbps) { ch[n].key = "kbps"; snprintf(ch[n++].val, 16, "%d", want->kbps); }
	if (want->fps != st[i].fps) { ch[n].key = "fps"; snprintf(ch[n++].val, 16, "%d", want->fps); }
	if (want->gop != st[i].gop) { ch[n].key = "gop"; snprintf(ch[n++].val, 16, "%d", want->gop); }
	if (strcmp(want->profile, st[i].profile)) {
		ch[n].key = "profile";
		snprintf(ch[n].val, 16, "%c%s", tolower((unsigned char)want->profile[0]), want->profile + 1);
		n++;
	}
	if (want->w != st[i].w || want->h != st[i].h) { ch[n].key = "size"; snprintf(ch[n++].val, 16, "%dx%d", want->w, want->h); }
	for (int k = 0; k < n; k++) {
		char key[32];
		snprintf(key, sizeof key, "stream.%s.%s", i ? "sub" : "main", ch[k].key);
		if (cfg_set(key, ch[k].val)) {
			LOG("camcfg set %s %s failed\n", key, ch[k].val);
			return -1;
		}
		LOG("%s set by %s to %s\n", key, user, ch[k].val);
	}
	return n;
}

/* rtspd exits on "restart"; init starts it again with the saved settings in ~3 s. */
static void rtspd_restart_now(void)
{
	char rep[64];
	if (CTL_CMD("restart\n", rep, sizeof rep, CTL_MS) || strncmp(rep, "ok", 2))
		LOG("rtspd didn't acknowledge restart (not running?): settings apply at its next start\n");
}

/* At most one rtspd restart per RESTART_GAP_MS, however often an operator saves (SSS sets both
 * encoders back to back, too). A change saved inside the gap is kept and its restart put off to
 * the end of the gap; changes saved meanwhile join that one restart (restart_tick). Returns the
 * seconds until the restart: 0 = now. */
#define RESTART_GAP_MS 10000
static long long restart_last = -RESTART_GAP_MS, restart_due;   /* mono ms */
static int restart_wanted;

static int rtspd_restart(void)
{
	long long now = mono_ms();
	if (!restart_wanted && now - restart_last >= RESTART_GAP_MS) {
		restart_last = now;
		rtspd_restart_now();
		return 0;
	}
	if (!restart_wanted) {
		restart_wanted = 1;
		restart_due = restart_last + RESTART_GAP_MS;
		LOG("rtspd restarted %lld ms ago: the next restart, for the settings just saved, is at most %d s away\n",
		    now - restart_last, (int)((restart_due - now + 999) / 1000));
	}
	return (int)((restart_due - now + 999) / 1000);
}

/* From the loop (and at exit): the restart put off by rtspd_restart, once its time has come. */
static void restart_tick(long long now)
{
	if (!restart_wanted || now < restart_due) return;
	restart_wanted = 0;
	restart_last = now;
	rtspd_restart_now();
}

/* SetVideoEncoderConfiguration: what GetVideoEncoderConfigurationOptions offers (the stream's
 * listed resolutions, saved as stream.<main|sub>.size; fps 1..30, the sub at most the main's;
 * interval 1, kbps 64..16384, GOP 1..1000, H.264 profile) is saved with
 * camcfg, one key per change, and only if something changed rtspd restarts to apply it (init
 * brings it back in ~3 s; at most one restart per RESTART_GAP_MS, see rtspd_restart). Quality,
 * Multicast, SessionTimeout and ForcePersistence are accepted and ignored; rate control (VBR/CBR)
 * stays as cam.conf has it. */
static int op_setvec(const struct req *r)
{
	char tok[32] = "?", enc[8], prof[16];
	/* a refusal names the field and what was sent: SSS's values are what we need to see */
#define REFUSE(what, ...) do { LOG("SetVideoEncoderConfiguration %s refused: " what "\n", log_clean(tok), __VA_ARGS__); \
	return F_CONFIGMODIFY; } while (0)
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	int w, h, ei = 1;
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok)) return F_NOCONFIG;
	int i = !strcmp(tok, "VideoEncoder_1") ? 0 : !strcmp(tok, "VideoEncoder_2") ? 1 : -1;
	if (i < 0 || !st[i].on) return F_NOCONFIG;
	const char *ce = xclose(c, r->end, "Configuration");
	struct stream want = st[i];
	w = want.w;
	h = want.h;
	if (!xtext(c, ce, "Encoding", enc, sizeof enc)) {
		if (!strcmp(enc, "H264")) want.h265 = 0;
		else if (!strcmp(enc, "H265")) want.h265 = 1;  /* as vec() reports it */
		else REFUSE("Encoding %s", log_clean(enc));
	}
	char wh[32];
	const struct stream_size *z = NULL;
	if (xint(c, ce, "Width", 1, 99999, &w) >= 0 && xint(c, ce, "Height", 1, 99999, &h) >= 0) {
		snprintf(wh, sizeof wh, "%dx%d", w, h);
		z = stream_size_find(i, wh);
	}
	if (!z)
		REFUSE("resolution %dx%d (only %s)", w, h, i ? "640x360, 960x540, 1280x720" :
		       "2560x1440, 2304x1296, 1920x1080, 1280x720");
	want.w = z->w;
	want.h = z->h;
	const char *rc = xel(c, ce, "RateControl", NULL);
	if (rc) {
		const char *re = xclose(rc, ce, "RateControl");
		char fr[16] = "", iv[16] = "", br[16] = "";
		xtext(rc, re, "FrameRateLimit", fr, sizeof fr);
		xtext(rc, re, "EncodingInterval", iv, sizeof iv);
		xtext(rc, re, "BitrateLimit", br, sizeof br);
		if (xint(rc, re, "FrameRateLimit", 1, STREAM_FPS_MAX, &want.fps) < 0 ||
		    xint(rc, re, "EncodingInterval", 1, 1, &ei) < 0 ||
		    xint(rc, re, "BitrateLimit", 64, 16384, &want.kbps) < 0)
			REFUSE("FrameRateLimit '%s' EncodingInterval '%s' BitrateLimit '%s' (fps 1..30, "
			       "interval 1, kbps 64..16384)", log_clean(fr), log_clean(iv), log_clean(br));
	}
	/* the sub-stream runs at most at the main's fps: a higher one is taken as the main's, and a
	 * main slower than the sub takes the sub down with it (saved too) */
	struct stream sub = st[1];
	if (i && want.fps > st[0].fps) {
		LOG("SetVideoEncoderConfiguration %s: FrameRateLimit %d above the main stream's: %d\n", tok, want.fps,
		    st[0].fps);
		want.fps = st[0].fps;
	}
	if (!i && st[1].on && sub.fps > want.fps) sub.fps = want.fps;
	const char *hp = xel(c, ce, "H264", NULL);
	if (hp) {
		const char *he = xclose(hp, ce, "H264");
		if (xint(hp, he, "GovLength", 1, 1000, &want.gop) < 0) REFUSE("GovLength (1..1000)%s", "");
		if (!xtext(hp, he, "H264Profile", prof, sizeof prof)) {
			if (!strcmp(prof, "Baseline")) want.profile = "Baseline";
			else if (!strcmp(prof, "Main")) want.profile = "Main";
			else if (!strcmp(prof, "High")) want.profile = "High";
			else REFUSE("H264Profile %s", log_clean(prof));
		}
	}
	int n = stream_save(i, &want, r->user), k = n < 0 || i ? 0 : stream_save(1, &sub, r->user);
	if (n < 0 || k < 0) return F_SAVE;
	if (n + k) rtspd_restart();                    /* now, or with the next one (saved either way) */
	S("<trt:SetVideoEncoderConfigurationResponse/>");
	return 0;
#undef REFUSE
}

/* ---- Imaging (ver20): rtspd's image.* (0..100) and daynight.mode ------------------------ */

enum { IMG_BRIGHTNESS, IMG_CONTRAST, IMG_SATURATION, IMG_SHARPNESS, IMG_N };
static const char *const img_key[IMG_N] = { "image.brightness", "image.contrast", "image.saturation",
					    "image.sharpness" };
static const char *const img_el[IMG_N] = { "Brightness", "Contrast", "ColorSaturation", "Sharpness" };

/* One "key=value" of rtspd's get (or cam.conf) into img[] / mode; bad values are skipped. */
static void image_kv(const char *k, const char *v, int img[IMG_N], char mode[8])
{
	size_t vl = strlen(v);
	for (int i = 0; i < IMG_N; i++)
		if (!strcmp(k, img_key[i]) && vl >= 1 && vl <= 3 && strspn(v, "0123456789") == vl && atoi(v) <= 100)
			img[i] = atoi(v);
	if (!strcmp(k, "daynight.mode") && (!strcmp(v, "auto") || !strcmp(v, "day") || !strcmp(v, "night")))
		snprintf(mode, 8, "%s", v);
}

/* The image settings and day/night mode: live from rtspd's "get", else from cam.conf (what rtspd
 * applies at its next start), else the defaults (50, auto). 1 if live. */
static int image_get(int img[IMG_N], char mode[8])
{
	char rep[4096], v[32], *save;                     /* get: ~1.2 KiB with motion.mask */
	for (int i = 0; i < IMG_N; i++) img[i] = 50;
	snprintf(mode, 8, "auto");
	if (!CTL_CMD("get\n", rep, sizeof rep, CTL_MS) && !strstr(rep, "err")) {
		for (char *l = strtok_r(rep, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
			char *eq = strchr(l, '=');
			if (!eq) continue;
			*eq = 0;
			image_kv(l, eq + 1, img, mode);
		}
		return 1;
	}
	for (int i = 0; i < IMG_N; i++)
		if (conf_get(img_key[i], v, sizeof v)) image_kv(img_key[i], v, img, mode);
	if (conf_get("daynight.mode", v, sizeof v)) image_kv("daynight.mode", v, img, mode);
	return 0;
}

static int source_ok(const struct req *r)
{
	char tok[64];
	return !xtext(r->op, r->end, "VideoSourceToken", tok, sizeof tok) && !strcmp(tok, "VideoSource_1");
}

/* ONVIF IrCutFilter ON = the filter is in (day, colour), OFF = out (night), AUTO = rtspd decides. */
static const char *ircut(const char *mode)
{
	return !strcmp(mode, "day") ? "ON" : !strcmp(mode, "night") ? "OFF" : "AUTO";
}

static int op_imgget(const struct req *r)
{
	int img[IMG_N];
	char mode[8];
	if (!source_ok(r)) return F_NOSOURCE;
	image_get(img, mode);
	S("<timg:GetImagingSettingsResponse><timg:ImagingSettings><tt:Brightness>%d</tt:Brightness>"
	  "<tt:ColorSaturation>%d</tt:ColorSaturation><tt:Contrast>%d</tt:Contrast><tt:IrCutFilter>%s"
	  "</tt:IrCutFilter><tt:Sharpness>%d</tt:Sharpness></timg:ImagingSettings>"
	  "</timg:GetImagingSettingsResponse>", img[IMG_BRIGHTNESS], img[IMG_SATURATION],
	  img[IMG_CONTRAST], ircut(mode), img[IMG_SHARPNESS]);
	return 0;
}

static int op_imgopts(const struct req *r)
{
	if (!source_ok(r)) return F_NOSOURCE;
#define RANGE(el) "<tt:" el "><tt:Min>0</tt:Min><tt:Max>100</tt:Max></tt:" el ">"
	S("<timg:GetOptionsResponse><timg:ImagingOptions>" RANGE("Brightness") RANGE("ColorSaturation")
	  RANGE("Contrast") "<tt:IrCutFilterModes>ON</tt:IrCutFilterModes><tt:IrCutFilterModes>OFF"
	  "</tt:IrCutFilterModes><tt:IrCutFilterModes>AUTO</tt:IrCutFilterModes>" RANGE("Sharpness")
	  "</timg:ImagingOptions></timg:GetOptionsResponse>");
#undef RANGE
	return 0;
}

/* An xs:float 0..100 as ONVIF sends a level ("55", "40.5"): rounded, or -1. */
static int level(const char *v)
{
	size_t n = strspn(v, "0123456789");
	if (n < 1 || n > 3 || (v[n] && (v[n] != '.' || strspn(v + n + 1, "0123456789") != strlen(v + n + 1))))
		return -1;
	double x = strtod(v, NULL);
	return x <= 100.0 ? (int)(x + 0.5) : -1;
}

/* camcfg set KEY VAL, then "set KEY VAL" to rtspd so it applies now (for image.*, daynight.* and
 * motion.* camcfg sends it too, harmlessly). -1 if camcfg failed; rtspd not answering is only
 * logged, it takes the value at its next start. (SetImagingSettings and the web UI.) */
static int save_live(const char *key, const char *val, const char *user)
{
	char line[300], rep[64];
	if (cfg_set(key, val)) {
		LOG("camcfg set %s %s failed\n", key, val);
		return -1;
	}
	snprintf(line, sizeof line, "set %s %s\n", key, val);
	if (CTL_CMD(line, rep, sizeof rep, CTL_MS) || strncmp(rep, "ok", 2))
		LOG("%s saved; rtspd didn't apply it live (not running?)\n", key);
	LOG("%s set by %s to %s\n", key, user, val);
	return 0;
}

/* SetImagingSettings: Brightness, ColorSaturation, Contrast, Sharpness (0..100) and IrCutFilter
 * (ON/OFF/AUTO -> daynight.mode day/night/auto). Each changed value is saved with camcfg, then
 * applied live with "set"; if rtspd isn't answering it takes them at its next start. Exposure,
 * Focus, WideDynamicRange, BacklightCompensation, WhiteBalance and ForcePersistence are ignored
 * (logged with -v): clients send back whatever they read. */
static int op_imgset(const struct req *r)
{
	static const char *const ignored[] = { "BacklightCompensation", "Exposure", "Focus",
					       "WideDynamicRange", "WhiteBalance" };
	int cur[IMG_N], want[IMG_N];
	char mode[8], wmode[8], v[24], val[8];
	if (!source_ok(r)) return F_NOSOURCE;
	const char *is = xel(r->op, r->end, "ImagingSettings", NULL);
	if (!is) return F_SETTINGS;
	const char *ie = xclose(is, r->end, "ImagingSettings");
	image_get(cur, mode);
	memcpy(want, cur, sizeof want);
	snprintf(wmode, sizeof wmode, "%s", mode);
	for (int i = 0; i < IMG_N; i++)
		if (xel(is, ie, img_el[i], NULL) &&
		    (xtext(is, ie, img_el[i], v, sizeof v) || (want[i] = level(v)) < 0))
			return F_SETTINGS;
	if (xel(is, ie, "IrCutFilter", NULL)) {
		if (xtext(is, ie, "IrCutFilter", v, sizeof v)) return F_SETTINGS;
		if (!strcmp(v, "ON")) strcpy(wmode, "day");
		else if (!strcmp(v, "OFF")) strcpy(wmode, "night");
		else if (!strcmp(v, "AUTO")) strcpy(wmode, "auto");
		else return F_SETTINGS;
	}
	for (size_t i = 0; verbose && i < sizeof ignored / sizeof ignored[0]; i++)
		if (xel(is, ie, ignored[i], NULL)) LOG("SetImagingSettings: %s ignored\n", ignored[i]);
	for (int i = 0; i <= IMG_N; i++) {
		const char *key = i < IMG_N ? img_key[i] : "daynight.mode";
		if (i < IMG_N && want[i] == cur[i]) continue;
		if (i == IMG_N && !strcmp(wmode, mode)) continue;
		if (i < IMG_N) snprintf(val, sizeof val, "%d", want[i]);
		else snprintf(val, sizeof val, "%s", wmode);
		if (save_live(key, val, r->user)) return F_SAVE;
	}
	S("<timg:SetImagingSettingsResponse/>");
	return 0;
}

static int op_imgstatus(const struct req *r)
{
	if (!source_ok(r)) return F_NOSOURCE;
	S("<timg:GetStatusResponse><timg:Status/></timg:GetStatusResponse>");   /* no focus motor */
	return 0;
}

static int op_imgmoveopts(const struct req *r)
{
	if (!source_ok(r)) return F_NOSOURCE;
	S("<timg:GetMoveOptionsResponse><timg:MoveOptions/></timg:GetMoveOptionsResponse>");
	return 0;
}

/* ---- Events (ver10, PullPoint): rtspd's motion detector -------------------------------- */

#define SUB_DEFAULT 60                 /* s a subscription lasts without InitialTerminationTime */
#define SUB_MAX 3600                   /* s at most, per subscribe or renew */
#define PULL_MAX_MS 10000              /* longest a PullMessages is held */
#define POLL_MS 500                    /* how often rtspd is asked while one is held */
#define REPLIED (-1)                   /* an op's result: it answered (or will answer) itself */
#define T_MOTION 1                     /* tns1:RuleEngine/CellMotionDetector/Motion */
#define T_ALARM 2                      /* tns1:VideoSource/MotionAlarm */
#define ACT_EV "http://www.onvif.org/ver10/events/wsdl/"
#define ACT_SM "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/"

static const char *const topic_path[2] = { "RuleEngine/CellMotionDetector/Motion",
					   "VideoSource/MotionAlarm" };

/* rtspd's motion state as last read; ok 0 when rtspd didn't answer (nothing is reported then). */
static struct { int ok, state; unsigned long seq; long since; } mot;
static long long mot_polled = -1000000;

static void motion_poll(void)
{
	char rep[256], *save;
	long st = -1, seq = -1, since = 0;
	mot_polled = mono_ms();
	mot.ok = 0;
	if (CTL_CMD("motion\n", rep, sizeof rep, CTL_MS) || strstr(rep, "err")) return;
	for (char *l = strtok_r(rep, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
		char *eq = strchr(l, '=');
		if (!eq || !eq[1] || strspn(eq + 1, "0123456789") != strlen(eq + 1) || strlen(eq + 1) > 9) continue;
		*eq = 0;
		long v = atol(eq + 1);
		if (!strcmp(l, "motion.state") && v <= 1) st = v;
		else if (!strcmp(l, "motion.seq")) seq = v;
		else if (!strcmp(l, "motion.since")) since = v;
	}
	if (st < 0 || seq < 0) return;
	mot.ok = 1;
	mot.state = (int)st;
	mot.seq = (unsigned long)seq;
	mot.since = since;
}

#define SUB_QUEUE 8                    /* messages waiting for the next pulls (one per pull) */

static struct sub {
	char id[17];                       /* 16 random hex digits, in the subscription address */
	char owner[64];                    /* the user who made it: only they may pull, renew, unsubscribe */
	long long expires, used, ttl;      /* mono ms; ttl in s: each pull extends it by that much */
	int live, topics, init, state;     /* init: the next pull reports motion if it is on */
	unsigned long seq;                 /* what this subscription has been told */
	struct { int t, state; time_t at; } q[SUB_QUEUE];
	int qn;
} subs[MAX_SUBS];

static int sub_find(const char *id, long long now)
{
	for (int i = 0; i < MAX_SUBS; i++) {
		if (subs[i].live && now > subs[i].expires) subs[i].live = 0;
		if (subs[i].live && *id && !strcmp(subs[i].id, id)) return i;
	}
	return -1;
}

/* sub_find, for a user: another user's subscription is as unknown as an expired one. */
static int sub_mine(const char *id, const struct req *r, long long now)
{
	int i = sub_find(id, now);
	if (i >= 0 && strcmp(subs[i].owner, r->user)) {
		if (verbose) LOG("subscription %d is %s's: %s refused for %s\n", i, subs[i].owner, r->name, r->user);
		return -1;
	}
	return i;
}

static int sub_held(int i)
{
	for (int k = 0; k < MAX_CLIENTS; k++)
		if (clients[k].fd >= 0 && clients[k].state == 2 && !strcmp(clients[k].park_id, subs[i].id)) return 1;
	return 0;
}

/* The subscription a request addresses: "sub=<id>" in the request-target's query, or in the
 * wsa:To header. Not a credential: the request is authenticated like any other. */
static void sub_id(const struct req *r, char id[17])
{
	char to[256];
	const char *q = strchr(r->target, '?'), *s = q ? strstr(q, "sub=") : NULL;
	*id = 0;
	if (!s && r->hb && !xtext(r->hb, r->he, "To", to, sizeof to) && (q = strchr(to, '?')))
		s = strstr(q, "sub=");
	if (s && strspn(s + 4, "0123456789abcdef") == 16 && !isxdigit((unsigned char)s[20]))
		snprintf(id, 17, "%.16s", s + 4);
}

/* xs:duration ("PT60S", "PT1M", "P1DT2H", fractions of a second dropped) or an xs:dateTime:
 * seconds from now; -1 if neither. */
static long long when(const char *v)
{
	long long t = 0, n;
	int in_t = 0, any = 0;
	if (*v != 'P') {
		long long at;
		return parse_created(v, &at) ? -1 : at - time(NULL);
	}
	for (const char *p = v + 1; *p; p++) {
		if (*p == 'T' && !in_t) { in_t = 1; continue; }
		if (!isdigit((unsigned char)*p)) return -1;
		for (n = 0; isdigit((unsigned char)*p); p++)
			if ((n = n * 10 + (*p - '0')) > 100000000) return -1;
		if (*p == '.') for (p++; isdigit((unsigned char)*p); p++) {}
		if (*p == 'D' && !in_t) t += n * 86400;
		else if (*p == 'H' && in_t) t += n * 3600;
		else if (*p == 'M' && in_t) t += n * 60;
		else if (*p == 'S' && in_t) t += n;
		else return -1;
		any = 1;
	}
	return any ? t : -1;
}

/* The topics (T_*) a TopicExpression selects: alternatives split by '|', namespace prefixes
 * dropped, "*" for one level, a trailing "//." for everything below. 0 if it names none of ours. */
static int topic_mask(const char *expr)
{
	char e[256], *s1;
	int mask = 0;
	snprintf(e, sizeof e, "%s", expr);
	for (char *alt = strtok_r(e, "|", &s1); alt; alt = strtok_r(NULL, "|", &s1)) {
		char pat[4][64], *s2;
		int np = 0, deep = 0;
		size_t l;
		while (isspace((unsigned char)*alt)) alt++;
		for (l = strlen(alt); l && isspace((unsigned char)alt[l - 1]); l--) alt[l - 1] = 0;
		if (l >= 3 && !strcmp(alt + l - 3, "//.")) { deep = 1; alt[l - 3] = 0; }
		for (char *seg = strtok_r(alt, "/", &s2); seg; seg = strtok_r(NULL, "/", &s2)) {
			char *c = strchr(seg, ':');
			if (np == 4) { np = 0; break; }        /* deeper than any of ours */
			snprintf(pat[np++], 64, "%s", c ? c + 1 : seg);
		}
		for (int t = 0; t < 2; t++) {
			char tp[64], *s3, *seg[4];
			int nt = 0, ok;
			snprintf(tp, sizeof tp, "%s", topic_path[t]);
			for (char *x = strtok_r(tp, "/", &s3); x && nt < 4; x = strtok_r(NULL, "/", &s3)) seg[nt++] = x;
			ok = np > 0 && (deep ? np <= nt : np == nt);
			for (int k = 0; ok && k < np; k++) ok = !strcmp(pat[k], "*") || !strcmp(pat[k], seg[k]);
			if (ok) mask |= 1 << t;
		}
	}
	return mask;
}

static int sub_news(const struct sub *s)
{
	return s->qn || (mot.ok && (s->init || mot.seq != s->seq || mot.state != s->state));
}

static void notification(int t, int state, const char *op, time_t at)
{
	char ts[24];
	iso(at, ts);
	S("<wsnt:NotificationMessage><wsnt:Topic Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/"
	  "ConcreteSet\">tns1:%s</wsnt:Topic><wsnt:Message><tt:Message UtcTime=\"%s\" PropertyOperation="
	  "\"%s\"><tt:Source>", topic_path[t], ts, op);
	if (t == 0)
		S("<tt:SimpleItem Name=\"VideoSourceConfigurationToken\" Value=\"VideoSourceConfig_1\"/>"
		  "<tt:SimpleItem Name=\"VideoAnalyticsConfigurationToken\" Value=\"VideoAnalyticsConfig_1\"/>"
		  "<tt:SimpleItem Name=\"Rule\" Value=\"" RULE_NAME "\"/>");
	else
		S("<tt:SimpleItem Name=\"Source\" Value=\"VideoSource_1\"/>");
	S("</tt:Source><tt:Data><tt:SimpleItem Name=\"%s\" Value=\"%s\"/></tt:Data></tt:Message>"
	  "</wsnt:Message></wsnt:NotificationMessage>", t ? "State" : "IsMotion", state ? "true" : "false");
}

/* Queue for subscription i what changed since it last heard, per topic at most fall/rise/fall
 * (several rising edges in between collapse into one). As stock does (and SSS takes): after a
 * subscribe or SetSynchronizationPoint only motion that is on is reported, and every message is
 * "Changed" (stock never sends "Initialized"). A seq below the last one means rtspd restarted:
 * only a state change is reported then. A full queue drops its oldest message. */
static void sub_fill(struct sub *s)
{
	int seq[3], n = 0;
	if (!mot.ok) return;
	if (s->init) { if (mot.state) seq[n++] = 1; }
	else if (mot.seq > s->seq) {
		if (s->state) seq[n++] = 0;
		seq[n++] = 1;
		if (!mot.state) seq[n++] = 0;
	} else if (mot.state != s->state) seq[n++] = mot.state;
	for (int k = 0; k < n; k++)
		for (int t = 0; t < 2; t++)
			if (s->topics & (1 << t)) {
				if (s->qn == SUB_QUEUE) memmove(s->q, s->q + 1, --s->qn * sizeof s->q[0]);
				s->q[s->qn].t = t;
				s->q[s->qn].state = seq[k];
				s->q[s->qn++].at = time(NULL) - (s->init ? 0 : mot.since);
			}
	s->state = mot.state;
	s->seq = mot.seq;
	s->init = 0;
}

/* PullMessagesResponse for subscription i: one queued message per response, as stock sends (the
 * next pull is answered at once while more wait). */
static void pull_reply(struct client *c, int i, int limit)
{
	struct sub *s = &subs[i];
	char now_s[24], end_s[24];
	long long now = mono_ms();
	(void)limit;                                       /* 1 <= MessageLimit: one is always allowed */
	sub_fill(s);
	iso(time(NULL), now_s);
	iso(time(NULL) + (time_t)((s->expires - now) / 1000), end_s);
	sbn = 0;
	sbover = 0;
	S("<tev:PullMessagesResponse><tev:CurrentTime>%s</tev:CurrentTime><tev:TerminationTime>%s"
	  "</tev:TerminationTime>", now_s, end_s);
	if (s->qn) {
		notification(s->q[0].t, s->q[0].state, "Changed", s->q[0].at);
		if (verbose) LOG("event to subscription %d: %s %s\n", i, topic_path[s->q[0].t], s->q[0].state ? "true" : "false");
		memmove(s->q, s->q + 1, --s->qn * sizeof s->q[0]);
	}
	S("</tev:PullMessagesResponse>");
	s->used = now;
	resp_action = ACT_EV "PullPointSubscription/PullMessagesResponse";
	soap_send(c, 200, NULL);
}

/* A held PullMessages: answered when its subscription has news, when it has gone, or at its
 * timeout (then with no messages). */
static void park_check(struct client *c, long long now)
{
	int i = sub_find(c->park_id, now);
	if (i < 0) soap_fault(c, F_NOSUB, NULL, 0);
	else if (sub_news(&subs[i]) || now >= c->park_until) pull_reply(c, i, c->park_limit);
	else return;
	c->deadline = mono() + SEND_TIMEOUT;
}

/* From the loop: while any PullMessages is held, ask rtspd every POLL_MS and answer what can be. */
static void events_tick(long long now)
{
	int held = 0;
	for (int k = 0; k < MAX_CLIENTS; k++) held += clients[k].fd >= 0 && clients[k].state == 2;
	if (!held) return;
	if (now - mot_polled >= POLL_MS) motion_poll();
	for (int k = 0; k < MAX_CLIENTS; k++)
		if (clients[k].fd >= 0 && clients[k].state == 2) park_check(&clients[k], now);
}

static int op_evprops(const struct req *r)
{
	(void)r;
	S("<tev:GetEventPropertiesResponse><tev:TopicNamespaceLocation>"
	  "http://www.onvif.org/onvif/ver10/topics/topicns.xml</tev:TopicNamespaceLocation>"
	  "<wsnt:FixedTopicSet>true</wsnt:FixedTopicSet><wstop:TopicSet>"
	  "<tns1:RuleEngine wstop:topic=\"false\"><CellMotionDetector wstop:topic=\"false\">"
	  "<Motion wstop:topic=\"true\"><tt:MessageDescription IsProperty=\"true\"><tt:Source>"
	  "<tt:SimpleItemDescription Name=\"VideoSourceConfigurationToken\" Type=\"tt:ReferenceToken\"/>"
	  "<tt:SimpleItemDescription Name=\"VideoAnalyticsConfigurationToken\" Type=\"tt:ReferenceToken\"/>"
	  "<tt:SimpleItemDescription Name=\"Rule\" Type=\"xs:string\"/></tt:Source><tt:Data>"
	  "<tt:SimpleItemDescription Name=\"IsMotion\" Type=\"xs:boolean\"/></tt:Data>"
	  "</tt:MessageDescription></Motion></CellMotionDetector></tns1:RuleEngine>"
	  "<tns1:VideoSource wstop:topic=\"false\"><MotionAlarm wstop:topic=\"true\">"
	  "<tt:MessageDescription IsProperty=\"true\"><tt:Source><tt:SimpleItemDescription "
	  "Name=\"Source\" Type=\"tt:ReferenceToken\"/></tt:Source><tt:Data><tt:SimpleItemDescription "
	  "Name=\"State\" Type=\"xs:boolean\"/></tt:Data></tt:MessageDescription></MotionAlarm>"
	  "</tns1:VideoSource></wstop:TopicSet><wsnt:TopicExpressionDialect>"
	  "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet</wsnt:TopicExpressionDialect>"
	  "<wsnt:TopicExpressionDialect>http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete"
	  "</wsnt:TopicExpressionDialect><tev:MessageContentFilterDialect>"
	  "http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter</tev:MessageContentFilterDialect>"
	  "<tev:MessageContentSchemaLocation>http://www.onvif.org/onvif/ver10/schema/onvif.xsd"
	  "</tev:MessageContentSchemaLocation></tev:GetEventPropertiesResponse>");
	resp_action = ACT_EV "EventPortType/GetEventPropertiesResponse";
	return 0;
}

/* CreatePullPointSubscription: a TopicExpression filter on our two topics is honoured (anything
 * else means both); message-content filters are ignored. At most MAX_SUBS: an expired one is
 * reused, else the same user's least recently pulled one that has no PullMessages held; another
 * user's live subscription is never taken (a viewer can't push the NVR's out). */
static int op_subscribe(const struct req *r)
{
	char v[256], base[64], now_s[24], end_s[24];
	long long now = mono_ms(), ttl = SUB_DEFAULT;
	int topics = T_MOTION | T_ALARM, i = -1;
	uint8_t rnd[8];
	if (!xtext(r->op, r->end, "TopicExpression", v, sizeof v) && topic_mask(v)) topics = topic_mask(v);
	if (!xtext(r->op, r->end, "InitialTerminationTime", v, sizeof v) && *v && (ttl = when(v)) <= 0)
		return F_ARGS;
	if (ttl > SUB_MAX) ttl = SUB_MAX;
	for (int k = 0; k < MAX_SUBS && i < 0; k++)
		if (!subs[k].live || now > subs[k].expires) i = k;
	if (i < 0)
		for (int k = 0; k < MAX_SUBS; k++)
			if (!strcmp(subs[k].owner, r->user) && !sub_held(k) && (i < 0 || subs[k].used < subs[i].used)) i = k;
	if (i < 0) return F_BUSY;
	if (random_bytes(rnd, sizeof rnd)) return F_BUSY;
	memset(&subs[i], 0, sizeof subs[i]);
	hex(rnd, sizeof rnd, subs[i].id);
	snprintf(subs[i].owner, sizeof subs[i].owner, "%s", r->user);
	subs[i].expires = now + ttl * 1000;
	subs[i].ttl = ttl;
	subs[i].used = now;
	subs[i].live = subs[i].init = 1;
	subs[i].topics = topics;
	base_url(r, base, sizeof base);
	iso(time(NULL), now_s);
	iso(time(NULL) + (time_t)ttl, end_s);
	S("<tev:CreatePullPointSubscriptionResponse><tev:SubscriptionReference><wsa:Address>"
	  "%s/onvif/event_service?sub=%s</wsa:Address></tev:SubscriptionReference><wsnt:CurrentTime>%s"
	  "</wsnt:CurrentTime><wsnt:TerminationTime>%s</wsnt:TerminationTime>"
	  "</tev:CreatePullPointSubscriptionResponse>", base, subs[i].id, now_s, end_s);
	if (verbose) LOG("subscription %d for %s, %lld s, topics %d\n", i, r->user, ttl, topics);
	resp_action = ACT_EV "EventPortType/CreatePullPointSubscriptionResponse";
	return 0;
}

/* PullMessages: answered at once if the subscription has news (or Timeout is 0, or another
 * pull on it is already held: one held pull per subscription, so at most MAX_SUBS connections
 * are ever held), else held without blocking the loop until news or Timeout (at most
 * PULL_MAX_MS). */
static int op_pull(const struct req *r)
{
	char id[17], v[32];
	long long now = mono_ms(), tmo = 0;
	int limit = 100, i;
	sub_id(r, id);
	if ((i = sub_mine(id, r, now)) < 0) return F_NOSUB;
	if (!xtext(r->op, r->end, "Timeout", v, sizeof v) && (*v != 'P' || (tmo = when(v)) < 0)) return F_ARGS;
	if (xint(r->op, r->end, "MessageLimit", 1, 999999, &limit) < 0) return F_ARGS;
	subs[i].used = now;
	/* a pull keeps the subscription alive: stock grants a year and SSS never renews */
	if (subs[i].expires < now + subs[i].ttl * 1000) subs[i].expires = now + subs[i].ttl * 1000;
	motion_poll();
	if (sub_news(&subs[i]) || tmo <= 0 || sub_held(i)) {
		pull_reply(r->c, i, limit);
		return REPLIED;
	}
	struct client *c = r->c;
	snprintf(c->park_id, sizeof c->park_id, "%s", id);
	c->park_until = now + (tmo * 1000 < PULL_MAX_MS ? tmo * 1000 : PULL_MAX_MS);
	c->park_limit = limit;
	c->state = 2;
	c->deadline = (time_t)(c->park_until / 1000) + SEND_TIMEOUT;
	return REPLIED;                               /* held: park_check answers */
}

static int op_renew(const struct req *r)
{
	char id[17], v[64], now_s[24], end_s[24];
	long long now = mono_ms(), ttl = SUB_DEFAULT;
	int i;
	sub_id(r, id);
	if ((i = sub_mine(id, r, now)) < 0) return F_NOSUB;
	if (!xtext(r->op, r->end, "TerminationTime", v, sizeof v) && *v && (ttl = when(v)) <= 0) return F_ARGS;
	if (ttl > SUB_MAX) ttl = SUB_MAX;
	subs[i].expires = now + ttl * 1000;
	subs[i].ttl = ttl;
	iso(time(NULL), now_s);
	iso(time(NULL) + (time_t)ttl, end_s);
	S("<wsnt:RenewResponse><wsnt:TerminationTime>%s</wsnt:TerminationTime><wsnt:CurrentTime>%s"
	  "</wsnt:CurrentTime></wsnt:RenewResponse>", end_s, now_s);
	resp_action = ACT_SM "RenewResponse";
	return 0;
}

static int op_unsubscribe(const struct req *r)
{
	char id[17];
	int i;
	sub_id(r, id);
	if ((i = sub_mine(id, r, mono_ms())) < 0) return F_NOSUB;
	subs[i].live = 0;                              /* a held pull on it gets the fault */
	S("<wsnt:UnsubscribeResponse/>");
	resp_action = ACT_SM "UnsubscribeResponse";
	return 0;
}

static int op_syncpoint(const struct req *r)
{
	char id[17];
	int i;
	sub_id(r, id);
	if ((i = sub_find(id, mono_ms())) < 0) return F_NOSUB;
	subs[i].init = 1;
	S("<tev:SetSynchronizationPointResponse/>");
	resp_action = ACT_EV "PullPointSubscription/SetSynchronizationPointResponse";
	return 0;
}

/* ---- Analytics (ver20) and Media's VideoAnalyticsConfiguration: the motion detector -------- */

static int va_token_ok(const struct req *r)
{
	char tok[64];
	return !xtext(r->op, r->end, "ConfigurationToken", tok, sizeof tok) && !strcmp(tok, VA_TOKEN);
}

static int op_vacs(const struct req *r)
{
	struct mset m;
	int compat = !!xel(r->op, r->end, "ProfileToken", NULL);
	if (compat && token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	const char *op = compat ? "GetCompatibleVideoAnalyticsConfigurations" : "GetVideoAnalyticsConfigurations";
	motion_settings(&m);
	S("<trt:%sResponse>", op);
	vac("trt:Configurations", &m);
	S("</trt:%sResponse>", op);
	return 0;
}

static int op_vac(const struct req *r)
{
	struct mset m;
	if (!va_token_ok(r)) return F_NOCONFIG;
	motion_settings(&m);
	S("<trt:GetVideoAnalyticsConfigurationResponse>");
	vac("trt:Configuration", &m);
	S("</trt:GetVideoAnalyticsConfigurationResponse>");
	return 0;
}

/* Both profiles already carry it: adding it again is a no-op. */
static int op_addvac(const struct req *r)
{
	if (token_idx(r, "ProfileToken", "Profile_") < 0) return F_NOPROFILE;
	if (!va_token_ok(r)) return F_NOCONFIG;
	S("<trt:AddVideoAnalyticsConfigurationResponse/>");
	return 0;
}

/* Media's way to change the module and rule in one go (same rules as Modify*). */
static int op_setvac(const struct req *r)
{
	struct mset cur, w;
	char tok[64];
	const char *tag, *c = xel(r->op, r->end, "Configuration", &tag);
	if (!c || xattr(tag, r->end, "token", tok, sizeof tok) || strcmp(tok, VA_TOKEN)) return F_NOCONFIG;
	const char *ce = c[-2] == '/' ? c : xclose(c, r->end, "Configuration");
	int f;
	motion_settings(&cur);
	w = cur;
	if ((f = parse_modules(c, ce, &w)) || (f = parse_rules(c, ce, &w, 0)) || (f = mset_apply(&cur, &w, r->user)))
		return f;
	S("<trt:SetVideoAnalyticsConfigurationResponse/>");
	return 0;
}

#define MOTION_SOURCE "<tt:Source><tt:SimpleItemDescription Name=\"VideoSourceConfigurationToken\" " \
	"Type=\"tt:ReferenceToken\"/><tt:SimpleItemDescription Name=\"VideoAnalyticsConfigurationToken\" " \
	"Type=\"tt:ReferenceToken\"/><tt:SimpleItemDescription Name=\"Rule\" Type=\"xs:string\"/></tt:Source>"

static int op_supmodules(const struct req *r)
{
	if (!va_token_ok(r)) return F_NOCONFIG;
	S("<tan:GetSupportedAnalyticsModulesResponse><tan:SupportedAnalyticsModules>"
	  "<tt:AnalyticsModuleContentSchemaLocation>http://www.onvif.org/ver10/schema/onvif.xsd"
	  "</tt:AnalyticsModuleContentSchemaLocation><tt:AnalyticsModuleDescription Name=\"tt:CellMotionEngine\">"
	  "<tt:Parameters><tt:SimpleItemDescription Name=\"Sensitivity\" Type=\"xs:integer\"/>"
	  "<tt:ElementItemDescription Name=\"Layout\" Type=\"tt:CellLayout\"/></tt:Parameters>"
	  "</tt:AnalyticsModuleDescription></tan:SupportedAnalyticsModules>"
	  "</tan:GetSupportedAnalyticsModulesResponse>");
	return 0;
}

static int op_modules(const struct req *r)
{
	struct mset m;
	if (!va_token_ok(r)) return F_NOCONFIG;
	motion_settings(&m);
	S("<tan:GetAnalyticsModulesResponse>");
	module_xml("tan:AnalyticsModule", m.sens);
	S("</tan:GetAnalyticsModulesResponse>");
	return 0;
}

/* Sensitivity only; the layout is fixed (a 32x32 one is accepted, any other refused). */
static int op_modmodules(const struct req *r)
{
	struct mset cur, w;
	int f;
	if (!va_token_ok(r)) return F_NOCONFIG;
	motion_settings(&cur);
	w = cur;
	if ((f = parse_modules(r->op, r->end, &w)) || (f = mset_apply(&cur, &w, r->user))) return f;
	S("<tan:ModifyAnalyticsModulesResponse/>");
	return 0;
}

static int op_suprules(const struct req *r)
{
	if (!va_token_ok(r)) return F_NOCONFIG;
	S("<tan:GetSupportedRulesResponse><tan:SupportedRules><tt:RuleContentSchemaLocation>"
	  "http://www.onvif.org/ver10/schema/onvif.xsd</tt:RuleContentSchemaLocation>"
	  "<tt:RuleDescription Name=\"tt:CellMotionDetector\"><tt:Parameters>"
	  "<tt:SimpleItemDescription Name=\"MinCount\" Type=\"xs:integer\"/>"
	  "<tt:SimpleItemDescription Name=\"AlarmOnDelay\" Type=\"xs:integer\"/>"
	  "<tt:SimpleItemDescription Name=\"AlarmOffDelay\" Type=\"xs:integer\"/>"
	  "<tt:SimpleItemDescription Name=\"ActiveCells\" Type=\"xs:base64Binary\"/></tt:Parameters>"
	  "<tt:Messages IsProperty=\"true\">" MOTION_SOURCE "<tt:Data><tt:SimpleItemDescription "
	  "Name=\"IsMotion\" Type=\"xs:boolean\"/></tt:Data><tt:ParentTopic>"
	  "tns1:RuleEngine/CellMotionDetector/Motion</tt:ParentTopic></tt:Messages></tt:RuleDescription>"
	  "</tan:SupportedRules></tan:GetSupportedRulesResponse>");
	return 0;
}

static int op_rules(const struct req *r)
{
	struct mset m;
	if (!va_token_ok(r)) return F_NOCONFIG;
	motion_settings(&m);
	S("<tan:GetRulesResponse>");
	rule_xml("tan:Rule", m.mask);
	S("</tan:GetRulesResponse>");
	return 0;
}

/* ModifyRules, and CreateRules for our one rule (it always exists, so creating it modifies it;
 * any other name: TooManyRules). The ActiveCells become motion.mask. */
static int rules_change(const struct req *r, int create)
{
	struct mset cur, w;
	int f;
	if (!va_token_ok(r)) return F_NOCONFIG;
	motion_settings(&cur);
	w = cur;
	if ((f = parse_rules(r->op, r->end, &w, create)) || (f = mset_apply(&cur, &w, r->user))) return f;
	S("<tan:%sRulesResponse/>", create ? "Create" : "Modify");
	return 0;
}

static int op_modrules(const struct req *r) { return rules_change(r, 0); }
static int op_createrules(const struct req *r) { return rules_change(r, 1); }

/* ---- OSD (Media ver10): rtspd's date/time and title overlays (src/mi/osd.c) -------------- */

/* As stock: two fixed overlays, osd_time (TextString DateAndTime) and osd_title (Plain), on
 * VideoSourceConfig_1. A line that is off isn't listed (DeleteOSD turns it off, CreateOSD or SetOSD
 * on). Positions: the four corners, or Custom with Pos x, y in -1..1 (y up) <-> osd.*.x / .y 0..100
 * (% of the room left, from the top left). FontSize is the text height in main-stream pixels for
 * osd.size small / medium / large (the nearest is taken). Saved with camcfg and applied live, like
 * SetImagingSettings. */
#define OSD_TEXT 48
enum { OK_TIME_POS, OK_TIME_X, OK_TIME_Y, OK_FORMAT, OK_12H, OK_WEEKDAY, OK_TITLE_POS, OK_TITLE_X,
       OK_TITLE_Y, OK_TEXT, OK_SIZE, OK_STYLE, OK_TIME_ON, OK_TITLE_ON, OK_N };
static const char *const osd_keys[OK_N] = { "osd.time.pos", "osd.time.x", "osd.time.y", "osd.time.format",
	"osd.time.12h", "osd.time.weekday", "osd.title.pos", "osd.title.x", "osd.title.y",
	"osd.title.text", "osd.size", "osd.style", "osd.time.enabled", "osd.title.enabled" };  /* "on" last */
static const char *const osd_tok[2] = { "osd_time", "osd_title" };
static const char *const osd_pos[5] = { "ul", "ur", "ll", "lr", "custom" };
static const char *const osd_pos_onvif[5] = { "UpperLeft", "UpperRight", "LowerLeft", "LowerRight", "Custom" };
static const char *const osd_fmts[6] = { "yyyy-MM-dd", "yyyy/MM/dd", "dd/MM/yyyy", "MM/dd/yyyy", "dd-MM-yyyy",
					 "MM-dd-yyyy" };
static const char *const osd_sizes[3] = { "small", "medium", "large" };
static const char *const osd_styles[3] = { "border", "black-on-white", "white-on-black" };
static const char *const osd_tfmt[2] = { "HH:mm:ss", "hh:mm:ss tt" };

struct osdset { int on[2], pos[2], x[2], y[2], fmt, h12, weekday, size, style; char text[OSD_TEXT + 1]; };

static void live_load(void);
static void setting(const char *key, const char *def, char *out, size_t cap);

static int osd_pick(const char *v, const char *const *names, int n)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(v, names[i])) return i;
	return -1;
}

/* A whole number lo..hi as osd.* holds them (optional '-', no leading zeros), else -1000000. */
static int osd_int(const char *v, int lo, int hi)
{
	const char *d = v + (*v == '-');
	size_t n = strlen(d);
	if (n < 1 || n > 4 || strspn(d, "0123456789") != n || (n > 1 && *d == '0') || (*v == '-' && *d == '0'))
		return -1000000;
	int x = atoi(v);
	return x >= lo && x <= hi ? x : -1000000;
}

static int osd_text_ok(const char *v)
{
	size_t n = strlen(v);
	for (size_t i = 0; i < n; i++)
		if ((unsigned char)v[i] < 0x20 || (unsigned char)v[i] > 0x7e) return 0;
	return n <= OSD_TEXT;
}

/* The settings as rtspd runs them, else as cam.conf has them, else the defaults (time on, top
 * left; title off, bottom left). fetch: ask rtspd first (a web page already did). */
static void osd_load(struct osdset *o, int fetch)
{
	char v[OSD_TEXT + 16];
	int x;
	*o = (struct osdset){ { 1, 0 }, { 0, 2 }, { 0, 0 }, { 0, 0 }, 0, 0, 0, 0, 0, "" };
	if (fetch) live_load();
	for (int k = 0; k < OK_N; k++) {
		setting(osd_keys[k], "", v, sizeof v);
		if (!*v && k != OK_TEXT) continue;
		int l = k >= OK_TITLE_POS && k <= OK_TEXT ? 1 : k == OK_TITLE_ON;
		switch (k) {
		case OK_TIME_POS: case OK_TITLE_POS: if ((x = osd_pick(v, osd_pos, 5)) >= 0) o->pos[l] = x; break;
		case OK_TIME_X: case OK_TITLE_X: if ((x = osd_int(v, 0, 100)) >= 0) o->x[l] = x; break;
		case OK_TIME_Y: case OK_TITLE_Y: if ((x = osd_int(v, 0, 100)) >= 0) o->y[l] = x; break;
		case OK_FORMAT: if ((x = osd_pick(v, osd_fmts, 6)) >= 0) o->fmt = x; break;
		case OK_12H: if ((x = osd_int(v, 0, 1)) >= 0) o->h12 = x; break;
		case OK_WEEKDAY: if ((x = osd_int(v, 0, 1)) >= 0) o->weekday = x; break;
		case OK_TEXT: if (osd_text_ok(v)) snprintf(o->text, sizeof o->text, "%s", v); break;
		case OK_SIZE: if ((x = osd_pick(v, osd_sizes, 3)) >= 0) o->size = x; break;
		case OK_STYLE: if ((x = osd_pick(v, osd_styles, 3)) >= 0) o->style = x; break;
		default: if ((x = osd_int(v, 0, 1)) >= 0) o->on[l] = x; break;
		}
	}
}

static void osd_val(const struct osdset *o, int k, char *out, size_t cap)
{
	int l = k >= OK_TITLE_POS && k <= OK_TEXT ? 1 : k == OK_TITLE_ON;
	switch (k) {
	case OK_TIME_POS: case OK_TITLE_POS: snprintf(out, cap, "%s", osd_pos[o->pos[l]]); break;
	case OK_TIME_X: case OK_TITLE_X: snprintf(out, cap, "%d", o->x[l]); break;
	case OK_TIME_Y: case OK_TITLE_Y: snprintf(out, cap, "%d", o->y[l]); break;
	case OK_FORMAT: snprintf(out, cap, "%s", osd_fmts[o->fmt]); break;
	case OK_12H: snprintf(out, cap, "%d", o->h12); break;
	case OK_WEEKDAY: snprintf(out, cap, "%d", o->weekday); break;
	case OK_TEXT: snprintf(out, cap, "%s", o->text); break;
	case OK_SIZE: snprintf(out, cap, "%s", osd_sizes[o->size]); break;
	case OK_STYLE: snprintf(out, cap, "%s", osd_styles[o->style]); break;
	default: snprintf(out, cap, "%d", o->on[l]); break;
	}
}

/* Every value that differs saved and applied (save_live), the "enabled" keys last so a line
 * comes on in its new place. The number saved, or -1 if camcfg failed. */
static int osd_save(const struct osdset *cur, const struct osdset *want, const char *user)
{
	char a[OSD_TEXT + 16], b[OSD_TEXT + 16];
	int n = 0;
	for (int k = 0; k < OK_N; k++) {
		osd_val(cur, k, a, sizeof a);
		osd_val(want, k, b, sizeof b);
		if (strcmp(a, b) && save_live(osd_keys[k], b, user)) return -1;
		n += !!strcmp(a, b);
	}
	return n;
}

/* The text height in main-stream pixels for osd.size (src/mi/osd.c's scale: 2560 -> x4 small,
 * 1920 and 2304 -> x3, 1280 -> x2; the configured stream.main.size). */
static int osd_px(int size)
{
	int s = st[0].w / 640 < 1 ? 1 : st[0].w / 640;
	return 16 * (size == 2 ? 2 * s + (s == 1) : size == 1 ? s + (s + 1) / 2 : s);
}

static void osd_xml(const char *el, int l, const struct osdset *o)
{
	S("<%s token=\"%s\"><tt:VideoSourceConfigurationToken>VideoSourceConfig_1</tt:VideoSourceConfigurationToken>"
	  "<tt:Type>Text</tt:Type><tt:Position><tt:Type>%s</tt:Type>", el, osd_tok[l], osd_pos_onvif[o->pos[l]]);
	if (o->pos[l] == 4)
		S("<tt:Pos x=\"%g\" y=\"%g\"/>", o->x[l] / 50.0 - 1, 1 - o->y[l] / 50.0);
	S("</tt:Position><tt:TextString><tt:Type>%s</tt:Type>", l ? "Plain" : "DateAndTime");
	if (!l)
		S("<tt:DateFormat>%s</tt:DateFormat><tt:TimeFormat>%s</tt:TimeFormat>", osd_fmts[o->fmt], osd_tfmt[o->h12]);
	S("<tt:FontSize>%d</tt:FontSize>", osd_px(o->size));
	if (l) {
		S("<tt:PlainText>");
		E(o->text);
		S("</tt:PlainText>");
	}
	S("</tt:TextString></%s>", el);
}

/* The OSDToken / ConfigurationToken element's line: 0 time, 1 title, -1 unknown. */
static int osd_token(const struct req *r, const char *el)
{
	char tok[32];
	if (xtext(r->op, r->end, el, tok, sizeof tok)) return -1;
	return !strcmp(tok, osd_tok[0]) ? 0 : !strcmp(tok, osd_tok[1]) ? 1 : -1;
}

static int vsc_given_ok(const struct req *r, const char *el)
{
	char tok[64];
	return !xel(r->op, r->end, el, NULL) || (!xtext(r->op, r->end, el, tok, sizeof tok) &&
						  !strcmp(tok, "VideoSourceConfig_1"));
}

static int op_osds(const struct req *r)
{
	struct osdset o;
	if (!vsc_given_ok(r, "ConfigurationToken")) return F_NOCONFIG;
	osd_load(&o, 1);
	S("<trt:GetOSDsResponse>");
	for (int l = 0; l < 2; l++)
		if (o.on[l]) osd_xml("trt:OSDs", l, &o);
	S("</trt:GetOSDsResponse>");
	return 0;
}

static int op_osd(const struct req *r)
{
	struct osdset o;
	int l = osd_token(r, "OSDToken");
	if (l < 0) return F_NOCONFIG;
	osd_load(&o, 1);
	if (!o.on[l]) return F_NOCONFIG;                   /* off: deleted, as far as ONVIF goes */
	S("<trt:GetOSDResponse>");
	osd_xml("trt:OSD", l, &o);
	S("</trt:GetOSDResponse>");
	return 0;
}

static int op_osdopts(const struct req *r)
{
	if (!xel(r->op, r->end, "ConfigurationToken", NULL) || !vsc_given_ok(r, "ConfigurationToken")) return F_NOCONFIG;
	S("<trt:GetOSDOptionsResponse><trt:OSDOptions><tt:MaximumNumberOfOSDs Total=\"2\" Image=\"0\" "
	  "PlainText=\"1\" Date=\"0\" Time=\"0\" DateAndTime=\"1\"/><tt:Type>Text</tt:Type>");
	for (int i = 0; i < 5; i++) S("<tt:PositionOption>%s</tt:PositionOption>", osd_pos_onvif[i]);
	S("<tt:TextOption><tt:Type>Plain</tt:Type><tt:Type>DateAndTime</tt:Type><tt:FontSizeRange><tt:Min>%d"
	  "</tt:Min><tt:Max>%d</tt:Max></tt:FontSizeRange>", osd_px(0), osd_px(2));
	for (int i = 0; i < 6; i++) S("<tt:DateFormat>%s</tt:DateFormat>", osd_fmts[i]);
	for (int i = 0; i < 2; i++) S("<tt:TimeFormat>%s</tt:TimeFormat>", osd_tfmt[i]);
	S("</tt:TextOption></trt:OSDOptions></trt:GetOSDOptionsResponse>");
	return 0;
}

/* An xs:float in -1..1 ("0.5", "-1", "1.0E0"), else 2. */
static double osd_unit(const char *v)
{
	char *e;
	if (!*v || strlen(v) > 24 || strspn(v, "+-0123456789.eE") != strlen(v)) return 2;
	double x = strtod(v, &e);
	return *e || !(x >= -1.0 && x <= 1.0) ? 2 : x;
}

/* SetOSD / CreateOSD's OSD element over *o (the current settings); *line gets its line: SetOSD's
 * token names it, CreateOSD's TextString/Type does (its token is ignored). 0, or the fault. */
static int osd_parse(const struct req *r, struct osdset *o, int create, int *line)
{
	const char *tag, *c = xel(r->op, r->end, "OSD", &tag), *ce, *lim, *t;
	char v[OSD_TEXT + 16], x[32], y[32];
	if (!c) return F_ARGS;
	ce = c[-2] == '/' ? c : xclose(c, r->end, "OSD");
	*line = -1;
	if (!create) {
		if (xattr(tag, r->end, "token", v, sizeof v)) return F_NOCONFIG;
		*line = !strcmp(v, osd_tok[0]) ? 0 : !strcmp(v, osd_tok[1]) ? 1 : -1;
		if (*line < 0) return F_NOCONFIG;
	}
	if (xel(c, ce, "VideoSourceConfigurationToken", NULL) &&
	    (xtext(c, ce, "VideoSourceConfigurationToken", v, sizeof v) || strcmp(v, "VideoSourceConfig_1")))
		return F_NOCONFIG;
	/* the OSD's own Type comes before Position / TextString / Image */
	lim = ce;
	if ((t = xel(c, ce, "Position", &tag)) && tag < lim) lim = tag;
	if ((t = xel(c, ce, "TextString", &tag)) && tag < lim) lim = tag;
	if ((t = xel(c, ce, "Image", &tag)) && tag < lim) lim = tag;
	if (xel(c, lim, "Type", NULL) && (xtext(c, lim, "Type", v, sizeof v) || strcmp(v, "Text"))) return F_CONFIGMODIFY;
	if (xel(c, ce, "Image", NULL)) return F_CONFIGMODIFY;
	const char *ts = xel(c, ce, "TextString", NULL), *tse = ts ? xclose(ts, ce, "TextString") : NULL;
	if (*line < 0 && !ts) return F_CONFIGMODIFY;                       /* CreateOSD: which one? */
	if (ts) {
		if (xtext(ts, tse, "Type", v, sizeof v)) return F_CONFIGMODIFY;
		int l = !strcmp(v, "DateAndTime") ? 0 : !strcmp(v, "Plain") ? 1 : -1;
		if (l < 0 || (*line >= 0 && l != *line)) return F_CONFIGMODIFY;
		*line = l;
		if (xel(ts, tse, "DateFormat", NULL)) {
			if (xtext(ts, tse, "DateFormat", v, sizeof v) || (o->fmt = osd_pick(v, osd_fmts, 6)) < 0)
				return F_CONFIGMODIFY;
		}
		if (xel(ts, tse, "TimeFormat", NULL)) {
			if (xtext(ts, tse, "TimeFormat", v, sizeof v) || (o->h12 = osd_pick(v, osd_tfmt, 2)) < 0)
				return F_CONFIGMODIFY;
		}
		if (xel(ts, tse, "FontSize", NULL)) {
			int fs = osd_int(xtext(ts, tse, "FontSize", v, sizeof v) ? "" : v, 1, 1000), best = 0;
			if (fs < 0) return F_CONFIGMODIFY;
			for (int i = 1; i < 3; i++)
				if (abs(osd_px(i) - fs) < abs(osd_px(best) - fs)) best = i;
			o->size = best;
		}
		if (l == 1 && xel(ts, tse, "PlainText", NULL)) {
			if (xtext(ts, tse, "PlainText", v, sizeof v) || !osd_text_ok(v)) return F_CONFIGMODIFY;
			snprintf(o->text, sizeof o->text, "%s", v);
		}
	}
	const char *ps = xel(c, ce, "Position", NULL), *pse = ps ? xclose(ps, ce, "Position") : NULL;
	if (ps) {
		int p;
		if (xtext(ps, pse, "Type", v, sizeof v) || (p = osd_pick(v, osd_pos_onvif, 5)) < 0) return F_CONFIGMODIFY;
		if (p == 4) {
			const char *pt;
			double fx, fy;
			if (!xel(ps, pse, "Pos", &pt) || xattr(pt, pse, "x", x, sizeof x) || xattr(pt, pse, "y", y, sizeof y) ||
			    (fx = osd_unit(x)) > 1 || (fy = osd_unit(y)) > 1)
				return F_CONFIGMODIFY;
			o->x[*line] = (int)((fx + 1) * 50 + 0.5);
			o->y[*line] = (int)((1 - fy) * 50 + 0.5);
		}
		o->pos[*line] = p;
	}
	o->on[*line] = 1;
	return 0;
}

static int op_setosd(const struct req *r)
{
	struct osdset cur, want;
	int l;
	osd_load(&cur, 1);
	want = cur;
	int f = osd_parse(r, &want, 0, &l);
	if (f) return f;
	if (osd_save(&cur, &want, r->user) < 0) return F_SAVE;
	S("<trt:SetOSDResponse/>");
	return 0;
}

static int op_createosd(const struct req *r)
{
	struct osdset cur, want;
	int l;
	osd_load(&cur, 1);
	want = cur;
	int f = osd_parse(r, &want, 1, &l);
	if (f) return f;
	if (osd_save(&cur, &want, r->user) < 0) return F_SAVE;
	S("<trt:CreateOSDResponse><trt:OSDToken>%s</trt:OSDToken></trt:CreateOSDResponse>", osd_tok[l]);
	return 0;
}

static int op_deleteosd(const struct req *r)
{
	struct osdset cur, want;
	int l = osd_token(r, "OSDToken");
	if (l < 0) return F_NOCONFIG;
	osd_load(&cur, 1);
	want = cur;
	want.on[l] = 0;
	if (osd_save(&cur, &want, r->user) < 0) return F_SAVE;
	S("<trt:DeleteOSDResponse/>");
	return 0;
}

static const struct op { const char *name; int level; int (*fn)(const struct req *); } ops[] = {
	{ "GetSystemDateAndTime", L_PRE, op_time },
	{ "GetCapabilities", L_PRE, op_caps },
	{ "GetServices", L_PRE, op_services },
	{ "GetServiceCapabilities", L_PRE, op_servcaps },
	{ "GetHostname", L_PRE, op_hostname },
	{ "GetWsdlUrl", L_PRE, op_wsdl },
	{ "GetEndpointReference", L_PRE, op_epr },
	{ "GetDeviceInformation", L_VIEWER, op_devinfo },
	{ "GetScopes", L_VIEWER, op_scopes },
	{ "GetNetworkInterfaces", L_VIEWER, op_netif },
	{ "GetNetworkProtocols", L_VIEWER, op_netproto },
	{ "GetDiscoveryMode", L_VIEWER, op_discmode },
	{ "GetUsers", L_ADMIN, op_users },
	{ "SetSystemDateAndTime", L_ADMIN, op_settime },
	{ "GetProfiles", L_VIEWER, op_profiles },
	{ "GetProfile", L_VIEWER, op_profile },
	{ "GetStreamUri", L_VIEWER, op_streamuri },
	{ "GetSnapshotUri", L_VIEWER, op_snapuri },
	{ "GetVideoSources", L_VIEWER, op_vsources },
	{ "GetVideoSourceConfigurations", L_VIEWER, op_vsconfs },
	{ "GetCompatibleVideoSourceConfigurations", L_VIEWER, op_vsconfs },
	{ "GetVideoSourceConfiguration", L_VIEWER, op_vsconf },
	{ "GetVideoEncoderConfigurations", L_VIEWER, op_vecs },
	{ "GetCompatibleVideoEncoderConfigurations", L_VIEWER, op_vecs },
	{ "GetVideoEncoderConfiguration", L_VIEWER, op_vec },
	{ "GetVideoEncoderConfigurationOptions", L_VIEWER, op_vecopts },
	{ "SetVideoEncoderConfiguration", L_OPERATOR, op_setvec },
	{ "GetGuaranteedNumberOfVideoEncoderInstances", L_VIEWER, op_guaranteed },
	{ "GetVideoSourceConfigurationOptions", L_VIEWER, op_vscopts },
	{ "SetVideoSourceConfiguration", L_OPERATOR, op_setvsc },
	{ "GetAudioEncoderConfigurationOptions", L_VIEWER, op_aecopts },
	{ "GetAudioSources", L_VIEWER, op_asources },
	{ "GetAudioSourceConfigurations", L_VIEWER, op_ascs },
	{ "GetCompatibleAudioSourceConfigurations", L_VIEWER, op_ascs },
	{ "GetAudioSourceConfiguration", L_VIEWER, op_ascone },
	{ "GetAudioSourceConfigurationOptions", L_VIEWER, op_ascopts },
	{ "GetAudioEncoderConfigurations", L_VIEWER, op_aecs },
	{ "GetCompatibleAudioEncoderConfigurations", L_VIEWER, op_aecs },
	{ "GetAudioEncoderConfiguration", L_VIEWER, op_aecone },
	{ "AddAudioSourceConfiguration", L_OPERATOR, op_addasc },
	{ "AddAudioEncoderConfiguration", L_OPERATOR, op_addaec },
	{ "RemoveAudioSourceConfiguration", L_OPERATOR, op_rmasc },
	{ "RemoveAudioEncoderConfiguration", L_OPERATOR, op_rmaec },
	{ "SetAudioSourceConfiguration", L_OPERATOR, op_setasc },
	{ "SetAudioEncoderConfiguration", L_OPERATOR, op_setaec },
	{ "GetAudioOutputs", L_VIEWER, op_aouts },
	{ "GetAudioOutputConfigurations", L_VIEWER, op_ocfgs },
	{ "GetCompatibleAudioOutputConfigurations", L_VIEWER, op_ocfgs },
	{ "GetAudioOutputConfiguration", L_VIEWER, op_ocfg },
	{ "GetAudioOutputConfigurationOptions", L_VIEWER, op_aocopts },
	{ "GetAudioDecoderConfigurations", L_VIEWER, op_ocfgs },
	{ "GetCompatibleAudioDecoderConfigurations", L_VIEWER, op_ocfgs },
	{ "GetAudioDecoderConfiguration", L_VIEWER, op_ocfg },
	{ "GetAudioDecoderConfigurationOptions", L_VIEWER, op_adcopts },
	{ "AddAudioOutputConfiguration", L_OPERATOR, op_oadd },
	{ "AddAudioDecoderConfiguration", L_OPERATOR, op_oadd },
	{ "RemoveAudioOutputConfiguration", L_OPERATOR, op_orm },
	{ "RemoveAudioDecoderConfiguration", L_OPERATOR, op_orm },
	{ "SetAudioOutputConfiguration", L_OPERATOR, op_setaoc },
	{ "SetAudioDecoderConfiguration", L_OPERATOR, op_setadc },
	{ "GetRelayOutputs", L_VIEWER, op_relays },
	{ "GetNTP", L_VIEWER, op_getntp },
	{ "SetNTP", L_ADMIN, op_setntp },
	{ "GetImagingSettings", L_VIEWER, op_imgget },
	{ "GetOptions", L_VIEWER, op_imgopts },
	{ "SetImagingSettings", L_OPERATOR, op_imgset },
	{ "GetStatus", L_VIEWER, op_imgstatus },
	{ "GetMoveOptions", L_VIEWER, op_imgmoveopts },
	{ "GetEventProperties", L_VIEWER, op_evprops },
	{ "CreatePullPointSubscription", L_VIEWER, op_subscribe },
	{ "PullMessages", L_VIEWER, op_pull },
	{ "Renew", L_VIEWER, op_renew },
	{ "Unsubscribe", L_VIEWER, op_unsubscribe },
	{ "SetSynchronizationPoint", L_VIEWER, op_syncpoint },
	{ "GetVideoAnalyticsConfigurations", L_VIEWER, op_vacs },
	{ "GetCompatibleVideoAnalyticsConfigurations", L_VIEWER, op_vacs },
	{ "GetVideoAnalyticsConfiguration", L_VIEWER, op_vac },
	{ "AddVideoAnalyticsConfiguration", L_OPERATOR, op_addvac },
	{ "SetVideoAnalyticsConfiguration", L_OPERATOR, op_setvac },
	{ "GetSupportedAnalyticsModules", L_VIEWER, op_supmodules },
	{ "GetAnalyticsModules", L_VIEWER, op_modules },
	{ "ModifyAnalyticsModules", L_OPERATOR, op_modmodules },
	{ "GetSupportedRules", L_VIEWER, op_suprules },
	{ "GetRules", L_VIEWER, op_rules },
	{ "ModifyRules", L_OPERATOR, op_modrules },
	{ "CreateRules", L_OPERATOR, op_createrules },
	{ "GetOSDs", L_VIEWER, op_osds },
	{ "GetOSD", L_VIEWER, op_osd },
	{ "GetOSDOptions", L_VIEWER, op_osdopts },
	{ "SetOSD", L_OPERATOR, op_setosd },
	{ "CreateOSD", L_OPERATOR, op_createosd },
	{ "DeleteOSD", L_OPERATOR, op_deleteosd },
};

/* ---- HTTP ----------------------------------------------------------------------------- */

/* Value of header `name` (case-insensitive), trimmed; returns how many times it appears. */
static int hdr(const char *req, const char *name, char *val, size_t cap)
{
	size_t nl = strlen(name);
	int count = 0;
	*val = 0;
	for (const char *p = strchr(req, '\n'); p; p = strchr(p, '\n')) {
		p++;
		if (strncasecmp(p, name, nl) || p[nl] != ':') continue;
		if (count++) continue;
		p += nl + 1;
		while (*p == ' ' || *p == '\t') p++;
		size_t n = strcspn(p, "\r\n");
		while (n && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
		if (n >= cap) n = cap - 1;
		memcpy(val, p, n);
		val[n] = 0;
	}
	return count;
}

/* Credentials on the request: the role (0 = none given), or -1 after replying with an error.
 * Every credential given must be valid; with both, the lower role counts. An Authorization
 * header of another scheme (a pre-emptive Basic, say) is ignored, not counted as a failure.
 * The monitor checks them (mon_auth: Digest, UsernameToken, the lockout) and keeps every secret:
 * the worker sends the header and the UsernameToken element, and gets the role, the user and the
 * request's grant, or a refusal with a fresh nonce. A UsernameToken too large to send (no client
 * sends one) or with a NUL in it goes as an empty token, which the monitor refuses. */
#define MON_WS_MAX (MON_MSG - 2048)
static int authenticate(struct client *c, const char *method, const char *target, const char *hb,
			const char *he, char *who, size_t cap)
{
	static char ws[MON_WS_MAX + 1];
	char authz[1024], ip[INET_ADDRSTRLEN];
	const char *tag = NULL, *ut = hb ? xel(hb, he, "UsernameToken", &tag) : NULL;
	req_grant = 0;
	*auth_nonce = 0;
	hdr(c->in, "Authorization", authz, sizeof authz);
	if (strncasecmp(authz, "Digest ", 7)) *authz = 0;
	if (!*authz && !ut) return 0;
	size_t wl = ut ? (size_t)(xclose(ut, he, "UsernameToken") - tag) : 0;
	if (wl > MON_WS_MAX || (wl && memchr(tag, 0, wl))) snprintf(ws, sizeof ws, "<UsernameToken>");
	else snprintf(ws, sizeof ws, "%.*s", (int)wl, wl ? tag : "");
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	const char *f[5] = { ip, method, target, authz, ws };
	int st = mon_call(MON_AUTH, 0, 5, f, NULL);
	/* the reply: grant (hex), nonce, stale, blocked, user; NUL-separated */
	const char *g = mon_rbuf, *n = g + strlen(g) + 1, *sl = n + strlen(n) + 1, *bl = sl + strlen(sl) + 1,
		   *u = bl + strlen(bl) + 1;
	int ok = u <= mon_rbuf + mon_rlen;                 /* every field there (the text is NUL-ended) */
	snprintf(who, cap, "%s", ok ? u : "");
	if (ok && st >= L_VIEWER && st <= L_ADMIN) {
		req_grant = strtoull(g, NULL, 16);
		return st;
	}
	if (ok && strlen(n) == NONCE_LEN) memcpy(auth_nonce, n, sizeof auth_nonce);
	if (st == MON_AUTH_FAULT) soap_fault(c, F_AUTH, NULL, 0);
	else challenge(c, ok && *sl == '1', hb != NULL);
	return -1;
}

static void soap(struct client *c, int svc, const char *target)
{
	const char *body = c->in + c->hdr_len, *end = body + c->body_len, *btag = NULL, *op;
	struct req r = { .c = c, .svc = svc, .end = end, .target = target };
	char name[64];
	sbn = 0;
	sbover = 0;
	resp_action = NULL;
	const char *b = xel(body, end, "Body", &btag);
	/* the first child element of Body names the operation */
	for (op = b; op && (op = memchr(op, '<', (size_t)(end - op))) && op + 1 < end &&
	     (op[1] == '!' || op[1] == '?');)
		op++;
	if (!b || !op || op + 1 >= end || op[1] == '/') { soap_fault(c, F_WELLFORMED, NULL, 0); return; }
	size_t qn = span(op + 1, end, " \t\r\n/><");
	const char *colon = memchr(op + 1, ':', qn), *local = colon ? colon + 1 : op + 1;
	size_t ln = (size_t)(op + 1 + qn - local);
	if (!ln || ln >= sizeof name || op + 1 + qn >= end || strspn(local, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789_-.") < ln || !(r.op = memchr(op, '>', (size_t)(end - op)))) {
		soap_fault(c, F_WELLFORMED, NULL, 0);
		return;
	}
	memcpy(name, local, ln);
	name[ln] = 0;
	r.op++;
	r.end = r.op[-2] == '/' ? r.op : xclose(r.op, end, name);   /* the operation's own content */
	r.name = name;
	const struct op *o = NULL;
	for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
		if (!strcmp(ops[i].name, name)) o = &ops[i];
	streams_load();                                    /* audio_on, for the fault below too */
	if (!o) {
		if (verbose) LOG("unsupported operation %s\n", name);
		soap_fault(c, !audio_on && (strstr(name, "AudioOutput") || strstr(name, "AudioDecoder")) ? F_AUDIOOUT :
			   strstr(name, "Audio") && !audio_on ? F_AUDIO : F_ACTION, NULL, 0);
		return;
	}
	r.hb = xel(body, btag, "Header", NULL);
	r.he = btag;
	if (o->level > L_PRE) {
		int role = authenticate(c, "POST", target, r.hb ? r.hb : body, btag, r.user, sizeof r.user);
		if (role < 0) return;
		if (role == 0) { challenge(c, 0, 1); return; }
		if (role < o->level) {
			LOG("user %s may not %s\n", r.user, name);
			soap_fault(c, F_AUTH, NULL, 0);
			return;
		}
	}
	if (verbose) LOG("%s %s\n", *r.user ? r.user : "-", name);
	int f = o->fn(&r);
	if (f == REPLIED) return;                      /* answered already, or held (PullMessages) */
	if (f) soap_fault(c, f, NULL, 0);
	else soap_send(c, 200, NULL);
}

/* A control-socket reply is complete when its last line starts with "ok" or "err". */
static int ctl_done(const char *out, size_t got)
{
	if (!got || out[got - 1] != '\n') return 0;
	const char *l = out + got - 1;
	while (l > out && l[-1] != '\n') l--;
	return !strncmp(l, "ok", 2) || !strncmp(l, "err", 3);
}

/* One line to rtspd's control socket; its reply (one or more lines, the last "ok…" or "err…")
 * in out. At most `ms` in all. */
static int ctl_cmd(const char *line, char *out, size_t cap, int ms)
{
	struct sockaddr_un a;
	size_t got = 0;
	long long until = mono_ms() + ms;
	int fd;
	if (strlen(ctl_path) >= sizeof a.sun_path || (fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) return -1;
	struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strcpy(a.sun_path, ctl_path);
	if (!connect(fd, (struct sockaddr *)&a, sizeof a) &&
	    write(fd, line, strlen(line)) == (ssize_t)strlen(line)) {
		long long left;
		ssize_t n;
		while (got < cap - 1 && !ctl_done(out, got) && (left = until - mono_ms()) > 0) {
			tv.tv_sec = (time_t)(left / 1000);
			tv.tv_usec = (suseconds_t)(left % 1000 * 1000);
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
			if ((n = read(fd, out + got, cap - 1 - got)) <= 0) break;
			got += (size_t)n;
		}
	}
	close(fd);
	out[got] = 0;
	return ctl_done(out, got) ? 0 : -1;
}

/* rtspd is asked at most once per SNAP_REUSE_MS: requests in between get the same JPEG (or the
 * same 503), so a client can't hold the loop in ctl_cmd back to back. */
static long long snap_asked = -SNAP_REUSE_MS;
static int snap_ok;

/* The latest JPEG (rtspd refuses one older than 5 s): an open fd, *sb its stat, or -1. Shared by
 * /snapshot.jpg and /preview.mjpg, so together they ask rtspd at most once a second. */
static int snap_open(struct stat *sb, int quiet)
{
	char rep[64] = "", *e;
	int fd = -1, asked = 0;
	long want = -1;
	long long now = mono_ms();
	if (now - snap_asked >= SNAP_REUSE_MS) {
		snap_asked = now;
		snap_ok = 0;
		asked = 1;
		if (CTL_CMD("snapshot\n", rep, sizeof rep, CTL_MS) || strncmp(rep, "ok", 2)) goto fail;
		if (rep[2] == ' ') {
			want = strtol(rep + 3, &e, 10);
			if (e == rep + 3 || *e != '\n') goto fail;
		} else if (rep[2] != '\n') goto fail;
	} else if (!snap_ok) goto fail;
	fd = open(snap_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0 || fstat(fd, sb) || !S_ISREG(sb->st_mode) || sb->st_size <= 0 ||
	    sb->st_size > SNAP_MAX || (want >= 0 && want != (long)sb->st_size))
		goto fail;
	snap_ok = 1;
	return fd;
fail:
	if (fd >= 0) close(fd);
	if (asked && !quiet) LOG("snapshot unavailable (rtspd: %.*s)\n", (int)strcspn(rep, "\n"), rep);
	return -1;
}

static void snapshot(struct client *c, const char *target)
{
	char who[64] = "";
	struct stat sbuf;
	size_t mark = c->out_len;
	int role = authenticate(c, "GET", target, NULL, NULL, who, sizeof who), fd;
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	if ((fd = snap_open(&sbuf, 0)) >= 0 && !http_head(c, 200, NULL, "image/jpeg", (size_t)sbuf.st_size)) {
		c->file_fd = fd;
		c->file_left = (long)sbuf.st_size;
		return;
	}
	if (fd >= 0) close(fd);
	c->out_len = mark;
	http_reply(c, 503, "Retry-After: 2\r\n", "snapshot unavailable\n");
}

/* ---- /preview.mjpg (#79): the snapshot JPEG as a multipart stream, for the Image page ------ */

/* One stream at a time, 5 minutes at most. The slot budget: SSS holds up to MAX_SUBS pulls, the
 * preview one more, and at least one slot stays for ONVIF requests (slot_for only evicts a
 * connection whose request isn't in yet, so never one that has been authenticated). */
#define PREVIEW_MAX 1
#define PREVIEW_MS (5 * 60 * 1000)
#define PREVIEW_EVERY_MS 1000          /* rtspd's JPEG channel runs at 1 fps */
#define PREVIEW_REPEAT_MS 3000         /* an unchanged JPEG is sent again at most this often */
#define PV_BOUNDARY "camframe"
#define PV_DELIM "\r\n--" PV_BOUNDARY "\r\n"
#define UPD_SLOTS 1                    /* firmware uploads at a time (the web UI's System page) */
_Static_assert(MAX_SUBS + PREVIEW_MAX + UPD_SLOTS < MAX_CLIENTS,
	       "held pulls, the preview and a firmware upload must leave a slot for ONVIF");

static void preview_start(struct client *c, const char *target)
{
	char who[64] = "", h[700];
	int role = authenticate(c, "GET", target, NULL, NULL, who, sizeof who), n = 0;
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	for (int i = 0; i < MAX_CLIENTS; i++) n += clients[i].fd >= 0 && clients[i].state == 3;
	if (n >= PREVIEW_MAX) {
		http_reply(c, 503, "Retry-After: 30\r\n", "one preview at a time: another one is open\n");
		return;
	}
	int k = snprintf(h, sizeof h, "HTTP/1.1 200 OK\r\nServer: camhttpd\r\nConnection: close\r\n"
			 "Cache-Control: no-store\r\n" UI_HEADERS "Content-Type: multipart/x-mixed-replace; "
			 "boundary=" PV_BOUNDARY "\r\n\r\n--" PV_BOUNDARY "\r\n");
	if (k < 0 || k >= (int)sizeof h || out_add(c, h, (size_t)k)) { http_reply(c, 500, NULL, NULL); return; }
	c->state = 3;
	c->pv_end = mono_ms() + PREVIEW_MS;
	c->pv_next = 0;                    /* the first frame at the next tick */
	c->pv_sent = 0;
	c->pv_ino = 0;
	c->pv_size = -1;
	if (verbose) LOG("preview for %s\n", who);
}

/* Each loop: a preview connection gets a frame once its last one is fully sent and a second has
 * passed; a slow reader just misses frames (never more than one frame queued). At the cap it is
 * closed once the frame in flight is out. */
static void preview_tick(long long now)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *c = &clients[i];
		struct stat sb;
		char h[96];
		if (c->fd < 0 || c->state != 3) continue;
		c->deadline = mono() + SEND_TIMEOUT;     /* a reader that stops entirely still goes */
		if (c->out_len > c->out_off || c->file_left > 0 || c->file_fd >= 0 || now < c->pv_next) continue;
		if (now >= c->pv_end) {
			c->state = 1;                          /* client_write closes it */
			continue;
		}
		c->pv_next = now + PREVIEW_EVERY_MS;
		int fd = snap_open(&sb, 1);
		if (fd < 0) continue;
		if (sb.st_ino == c->pv_ino && sb.st_mtime == c->pv_mtime && (long)sb.st_size == c->pv_size &&
		    now - c->pv_sent < PREVIEW_REPEAT_MS) {
			close(fd);
			continue;
		}
		int k = snprintf(h, sizeof h, "Content-Type: image/jpeg\r\nContent-Length: %ld\r\n\r\n", (long)sb.st_size);
		c->out_off = c->out_len = 0;
		out_add(c, h, (size_t)k);
		c->file_fd = fd;
		c->file_left = (long)sb.st_size;
		c->pv_ino = sb.st_ino;
		c->pv_mtime = sb.st_mtime;
		c->pv_size = (long)sb.st_size;
		c->pv_sent = now;
	}
}

/* ---- Web UI (#79): server-rendered pages under /ui/, plain forms, no JavaScript ---------- */

#define UI_BODY_MAX 8192               /* a form; an RSA key line is the largest field */
#define PP_CAP 1024                    /* a backup passphrase as it may cross (camcfg: 12..256 bytes) */
#define FORM_MAX 36                    /* the Image form sends 35 (night tuning ticked) */
#define CSRF_BUCKET 900                /* s: a page's forms work for 15 to 30 minutes */
#define UI_KEYS 16                     /* camcfg sshkey's limit */

static const char *version_path = "/etc/cam/version", *uptime_path = "/proc/uptime",
		  *meminfo_path = "/proc/meminfo", *route_path = "/proc/net/route",
		  *resolv_path = "/etc/resolv.conf";
static long long reboot_at;            /* mono ms a reboot was asked for, 0 if none */
static struct client *reboot_c;        /* ... whose reply goes out first */
static uint64_t reboot_grant;          /* ... and its login's grant (MON_REBOOT) */
static int bk_rebooting;               /* a restore worked: the monitor reboots the camera */

static const char ui_css[] =
	"body{margin:0;font:16px/1.4 system-ui,sans-serif;background:#f5f5f3;color:#1f2328}"
	"header{background:#24323f;color:#fff;padding:.4em 1em}header a{color:#fff;margin-right:1em;"
	"display:inline-block;padding:.25em 0;text-decoration:none}header a.on{border-bottom:2px solid #fff}"
	".who{float:right;opacity:.8;padding:.25em 0}main{max-width:42em;margin:0 auto;padding:.5em 1em 2em}"
	"h1{font-size:1.4em}h2{font-size:1.1em;margin-top:1.6em}table{border-collapse:collapse;width:100%}"
	"th,td{text-align:left;padding:.3em .4em;border-bottom:1px solid #ddd;vertical-align:top;"
	"overflow-wrap:anywhere}label{display:block;margin:.7em 0 .2em}"
	"input,select,button{font:inherit;max-width:100%;box-sizing:border-box}"
	"input[type=range]{width:68%;vertical-align:middle}input[type=number]{width:6.5em}"
	"input[type=text],input[type=password]{width:100%}button{margin-top:.8em;padding:.4em 1.2em}"
	"td button{margin:0}.msg{padding:.6em .8em;background:#e2f1e0;border-left:4px solid #2e7d32}"
	".err{background:#fbe3e3;border-color:#c62828}.warn{padding:.6em .8em;background:#fff5d6;"
	"border-left:4px solid #d39e00}.note{color:#555;font-size:.9em}img{max-width:100%;height:auto;"
	"background:#ccc}pre{overflow-x:auto;font-size:12px;line-height:1.15}"
	".code{font:1.3em/1.5 ui-monospace,monospace;letter-spacing:.05em;padding:.5em .8em;background:#fff;"
	"border:1px solid #bbb;overflow-wrap:anywhere}\n";

/* The one script (no inline code: CSP script-src 'self'). The pages work without it; with it a
 * slider and its number field follow each other while dragging, a form marked data-live (the
 * image settings) is applied when a slider is released, and an img marked data-refresh (the
 * preview) is reloaded about once a second while the page is visible. The firmware upload (a form
 * marked data-upload, System page) needs it: the file goes as the raw body of a POST, with the
 * page's token in X-CSRF-Token, after a GET of the same path (it renews the Digest nonce and says
 * whether another upload is under way, before megabytes are sent); then the page reloads to show
 * camupdate's verdict and the Install button. */
static const char ui_js[] =
	"'use strict';\n"
	"for (const r of document.querySelectorAll('input[type=range]')) {\n"
	"  const n = r.form.elements[r.name + '_n'];\n"
	"  if (!n) continue;\n"
	"  r.addEventListener('input', () => { n.value = r.value; });\n"
	"  n.addEventListener('input', () => { if (n.value !== '') r.value = n.value; });\n"
	"  if (!r.form.hasAttribute('data-live')) continue;\n"
	"  for (const e of [r, n]) e.addEventListener('change', () => apply(r.form));\n"
	"}\n"
	"for (const img of document.querySelectorAll('img[data-refresh]')) {\n"
	"  const base = img.getAttribute('src');\n"
	"  let busy = false;\n"
	"  setInterval(() => {\n"
	"    if (busy || document.hidden) return;\n"
	"    busy = true;\n"
	"    const next = new Image();\n"
	"    next.onload = () => { img.src = next.src; busy = false; };\n"
	"    next.onerror = () => { busy = false; };\n"
	"    next.src = base + '?t=' + Date.now();\n"
	"  }, 1000);\n"
	"}\n"
	"for (const s of document.querySelectorAll('form[data-live] select, form[data-live] input[type=checkbox]'))\n"
	"  s.addEventListener('change', () => apply(s.form));\n"
	"function apply(f) {\n"
	"  const out = f.querySelector('.live');\n"
	"  fetch(f.action, { method: 'POST', body: new URLSearchParams(new FormData(f)), credentials: 'same-origin' })\n"
	"    .then(r => { if (out) out.textContent = r.ok ? 'Applied.' : r.status === 403 ?\n"
	"      'Not applied: reload the page.' : 'Not applied (' + r.status + ').'; })\n"
	"    .catch(() => { if (out) out.textContent = 'Not applied (no answer).'; });\n"
	"}\n"
	"for (const f of document.querySelectorAll('form[data-upload]')) f.addEventListener('submit', e => {\n"
	"  e.preventDefault();\n"
	"  const out = f.querySelector('.live'), b = f.querySelector('button'), file = f.elements.file.files[0];\n"
	"  const say = t => { out.textContent = t; b.disabled = false; };\n"
	"  if (!file) return say('Choose a .camfw file first.');\n"
	"  if (file.size > Number(f.dataset.max)) return say('Too large for a camera package.');\n"
	"  b.disabled = true;\n"
	"  out.textContent = 'Uploading and checking...';\n"
	"  fetch(f.action, { credentials: 'same-origin' })\n"
	"    .then(r => !r.ok ? r : fetch(f.action, { method: 'POST', body: file, credentials: 'same-origin',\n"
	"      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': f.elements.csrf.value } }))\n"
	"    .then(r => r.text().then(t => { if (r.ok) location.assign(location.pathname);\n"
	"      else say(r.status === 403 ? 'Not accepted: reload the page.' : t); }))\n"
	"    .catch(() => say('No answer: reload the page and try again.'));\n"
	"});\n"
	"for (const f of document.querySelectorAll('form[data-unlock]')) {\n"
	"  const msg = f.querySelector('.msg'), out = f.querySelector('.live'), b = f.querySelector('button');\n"
	"  let sha = 'none';\n"
	"  const act = () => f.elements.action.value;\n"
	"  const show = () => { msg.textContent = 'cam-recover 1\\nchallenge ' + f.dataset.challenge + '\\ndevice ' +\n"
	"    f.dataset.device + '\\nfirmware ' + f.dataset.firmware + '\\naction ' + act() + '\\nbackup ' +\n"
	"    (act() === 'restore' ? sha : 'none') + '\\n'; };\n"
	"  f.elements.file.addEventListener('change', () => {\n"
	"    const file = f.elements.file.files[0];\n"
	"    sha = 'none';\n"
	"    if (!file) return show();\n"
	"    if (!window.crypto || !crypto.subtle) { sha = '(open this page over HTTPS)'; return show(); }\n"
	"    file.arrayBuffer().then(a => crypto.subtle.digest('SHA-256', a)).then(d => {\n"
	"      sha = Array.from(new Uint8Array(d), x => x.toString(16).padStart(2, '0')).join(''); show(); });\n"
	"  });\n"
	"  for (const r of f.querySelectorAll('input[name=action]')) r.addEventListener('change', show);\n"
	"  show();\n"
	"  f.addEventListener('submit', e => {\n"
	"    e.preventDefault();\n"
	"    const restore = act() === 'restore', file = f.elements.file.files[0], enc = new TextEncoder();\n"
	"    const say = t => { out.textContent = t; b.disabled = false; };\n"
	"    if (restore && !file) return say('Choose the backup file.');\n"
	"    const sig = f.elements.sig.value.trim() + '\\n';\n"
	"    const parts = restore ? [enc.encode(f.elements.pp.value + '\\n'), enc.encode(sig), file] : [enc.encode(sig)];\n"
	"    b.disabled = true;\n"
	"    out.textContent = 'Checking: this takes up to a minute...';\n"
	"    fetch(f.action, { method: 'POST', body: new Blob(parts), headers: { 'Content-Type': 'application/octet-stream',\n"
	"      'X-Unlock-Action': act(), 'X-Unlock-Challenge': f.dataset.challenge } })\n"
	"      .then(r => r.text().then(t => { out.textContent = t; if (!r.ok) b.disabled = false; }))\n"
	"      .catch(() => say('No answer: reload the page (a new challenge) and try again.'));\n"
	"  });\n"
	"}\n";

/* The POST's form: names and values decoded into buf. */
static struct { int n; const char *k[FORM_MAX], *v[FORM_MAX]; char buf[UI_BODY_MAX + 2]; } form;

/* application/x-www-form-urlencoded, strictly: name=value pairs joined by '&', names [a-z0-9_]
 * (1..24), no empty pair, no name twice; values may use '+' for a space and %XX, and otherwise
 * only printable ASCII as browsers send it. A NUL (%00) is refused, since it would cut a value
 * short; anything else a value holds is for its handler (camcfg) to judge. 0, or -1. */
static int form_parse(const char *p, size_t n)
{
	const char *end = p + n;
	char *o = form.buf;
	form.n = 0;
	if (n > UI_BODY_MAX) return -1;
	while (p < end) {
		const char *amp = memchr(p, '&', (size_t)(end - p)), *e = amp ? amp : end;
		const char *eq = memchr(p, '=', (size_t)(e - p));
		size_t kl = eq ? (size_t)(eq - p) : 0;
		if (!kl || kl > 24 || form.n == FORM_MAX || (amp && amp + 1 == end)) return -1;
		for (size_t i = 0; i < kl; i++)
			if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= '0' && p[i] <= '9') || p[i] == '_')) return -1;
		form.k[form.n] = o;
		memcpy(o, p, kl);
		o += kl;
		*o++ = 0;
		for (int i = 0; i < form.n; i++)
			if (!strcmp(form.k[i], form.k[form.n])) return -1;
		form.v[form.n] = o;
		for (const char *q = eq + 1; q < e; q++) {
			int ch = (unsigned char)*q;
			if (ch == '+') ch = ' ';
			else if (ch == '%') {
				int a = e - q >= 3 ? hexval((unsigned char)q[1]) : -1, b = a >= 0 ? hexval((unsigned char)q[2]) : -1;
				if (b < 0) return -1;
				ch = a << 4 | b;
				q += 2;
				if (!ch) return -1;
			} else if (ch < 0x21 || ch > 0x7e) return -1;
			*o++ = (char)ch;
		}
		*o++ = 0;
		form.n++;
		p = e + (amp != NULL);
	}
	return 0;
}

static const char *form_get(const char *k)
{
	for (int i = 0; i < form.n; i++)
		if (!strcmp(form.k[i], k)) return form.v[i];
	return NULL;
}

/* multipart/form-data (RFC 7578), as a browser sends a form with a file (the backup restores, #172
 * and #173), strictly: the boundary from the Content-Type ct (1..70 characters, quoted or not);
 * the body starts with "--B\r\n"; each part has headers up to a blank line, among them
 * Content-Disposition: form-data; name="N" (names [a-z0-9_], 1..24, each once, at most MP_MAX
 * parts), then its value up to "\r\n--B"; "--B--" ends it, with at most a CRLF after. Values
 * point into the body (len bytes, not NUL-terminated). 0, or -1. */
#define MP_MAX 6
struct mp { int n; char k[MP_MAX][25]; const char *v[MP_MAX]; size_t len[MP_MAX]; };

static int mp_parse(const char *b, size_t n, const char *ct, struct mp *m)
{
	char bd[80] = "\r\n--";
	const char *end = b + n, *q, *p;
	size_t bl;
	m->n = 0;
	if (strncasecmp(ct, "multipart/form-data", 19) || (ct[19] && ct[19] != ';' && ct[19] != ' ')) return -1;
	if (!(q = strcasestr(ct, "boundary="))) return -1;
	q += 9;
	if (*q == '"') {
		const char *e = strchr(++q, '"');
		bl = e ? (size_t)(e - q) : 0;
	} else {
		bl = strcspn(q, "; \t");
	}
	if (!bl || bl > 70) return -1;
	memcpy(bd + 4, q, bl);
	bd[4 + bl] = 0;
	bl += 4;                                           /* "\r\n--" + the boundary */
	if (n < bl - 2 || memcmp(b, bd + 2, bl - 2)) return -1;
	p = b + bl - 2;                                    /* just past the first "--B" */
	for (;;) {
		if (end - p >= 2 && !memcmp(p, "--", 2)) {   /* the last one */
			p += 2;
			return p == end || (end - p == 2 && !memcmp(p, "\r\n", 2)) ? 0 : -1;
		}
		if (end - p < 2 || memcmp(p, "\r\n", 2) || m->n == MP_MAX) return -1;
		p += 2;
		const char *he = memmem(p, (size_t)(end - p) < 1024 ? (size_t)(end - p) : 1024, "\r\n\r\n", 4);
		if (!he) return -1;
		int named = 0;
		for (const char *l = p; l < he + 2;) {            /* each header line */
			const char *le = memmem(l, (size_t)(he + 2 - l), "\r\n", 2);
			size_t ll = (size_t)(le - l);
			char h[512];
			if (ll >= sizeof h) return -1;
			memcpy(h, l, ll);
			h[ll] = 0;
			if (memchr(l, 0, ll)) return -1;
			if (!strncasecmp(h, "Content-Disposition:", 20)) {
				const char *nm = strstr(h, "; name=\"");
				char *ne;
				if (named || !strcasestr(h, "form-data") || !nm || !(ne = strchr(nm + 8, '"'))) return -1;
				size_t kl = (size_t)(ne - (nm + 8));
				if (!kl || kl > 24 || strspn(nm + 8, "abcdefghijklmnopqrstuvwxyz0123456789_") < kl) return -1;
				memcpy(m->k[m->n], nm + 8, kl);
				m->k[m->n][kl] = 0;
				for (int i = 0; i < m->n; i++)
					if (!strcmp(m->k[i], m->k[m->n])) return -1;
				named = 1;
			}
			l = le + 2;
		}
		if (!named) return -1;
		const char *v = he + 4, *ve = memmem(v, (size_t)(end - v), bd, bl);
		if (!ve) return -1;
		m->v[m->n] = v;
		m->len[m->n++] = (size_t)(ve - v);
		p = ve + bl;
	}
}

/* Part `k` of m: its bytes in *len, or NULL if there is none. */
static const char *mp_get(const struct mp *m, const char *k, size_t *len)
{
	for (int i = 0; i < m->n; i++)
		if (!strcmp(m->k[i], k)) { *len = m->len[i]; return m->v[i]; }
	*len = 0;
	return NULL;
}

/* Part `k` as text into out: 1, 0 if there is none, -1 if it is cap bytes or more or holds a NUL,
 * CR or LF (a camcfg stdin line). */
static int mp_text(const struct mp *m, const char *k, char *out, size_t cap)
{
	size_t n;
	const char *v = mp_get(m, k, &n);
	*out = 0;
	if (!v) return 0;
	if (n >= cap || memchr(v, 0, n) || memchr(v, '\r', n) || memchr(v, '\n', n)) return -1;
	memcpy(out, v, n);
	out[n] = 0;
	return 1;
}

/* A whole number lo..hi (lo >= 0), or -1. */
static int ui_int(const char *v, int lo, int hi)
{
	size_t n = v ? strlen(v) : 0;
	if (n < 1 || n > 5 || strspn(v, "0123456789") != n) return -1;
	int x = atoi(v);
	return x >= lo && x <= hi ? x : -1;
}

/* HMAC-SHA1 (RFC 2104) under ui_key. */
static void hmac_sha1(const void *msg, size_t n, uint8_t out[20])
{
	hmac_sha1_k(ui_key, sizeof ui_key, msg, n, out);
}

/* A form's csrf token: HMAC(per-start key, user, 15-minute bucket of the monotonic clock, which
 * doesn't jump when NTP or SetSystemDateAndTime sets the time). */
static void csrf_token(const char *user, long long bucket, char out[41])
{
	char m[96];
	uint8_t h[20];
	int n = snprintf(m, sizeof m, "csrf\n%s\n%lld", user, bucket);
	hmac_sha1(m, (size_t)n, h);
	hex(h, 20, out);
}

static int csrf_ok(const char *user, const char *tok)
{
	char want[41];
	long long b = (long long)mono() / CSRF_BUCKET;
	if (!tok || strlen(tok) != 40) return 0;
	for (int i = 0; i < 2; i++) {                      /* this bucket or the one before */
		csrf_token(user, b - i, want);
		if (ct_eq(want, tok, 40)) return 1;
	}
	return 0;
}

/* The request's Origin, or without one its Referer, is http://<its own Host> (https:// on a
 * connection from camtls, and only that): a form on our own page. Browsers resend Digest
 * credentials to us from any page, so this and the token are what stop another site's form. */
static int same_origin(const struct client *c)
{
	const char *req = c->in, *scheme = c->tls ? "https://" : "http://";
	char host[128], v[300];
	size_t hl, sl = strlen(scheme);
	if (hdr(req, "Host", host, sizeof host) != 1 || !(hl = strlen(host)) || hl == sizeof host - 1) return 0;
	int no = hdr(req, "Origin", v, sizeof v);
	if (no > 1 || (!no && hdr(req, "Referer", v, sizeof v) != 1)) return 0;
	if (strlen(v) == sizeof v - 1 || strncasecmp(v, scheme, sl) || strncasecmp(v + sl, host, hl)) return 0;
	return no ? !v[sl + hl] : !v[sl + hl] || v[sl + hl] == '/';
}

/* Raw bytes onto the page being built (sb). */
static void sb_add(const char *p, size_t n)
{
	if (sbover || n >= sizeof sb - sbn) { sbover = 1; return; }
	memcpy(sb + sbn, p, n);
	sbn += n;
}

/* Text onto the page, HTML-escaped; control characters other than newline become '?'. */
static void E(const char *s)
{
	while (*s) {
		size_t k = strcspn(s, "&<>\"'");
		for (size_t i = 0; i < k; i++)
			if ((unsigned char)s[i] < 0x20 && s[i] != '\n') { k = i; break; }
		sb_add(s, k);
		s += k;
		if (!*s) break;
		const char *ent = *s == '&' ? "&amp;" : *s == '<' ? "&lt;" : *s == '>' ? "&gt;" :
				  *s == '"' ? "&quot;" : *s == '\'' ? "&#39;" : "?";
		sb_add(ent, strlen(ent));
		s++;
	}
}

static void first_line(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "r");
	*out = 0;
	if (f && fgets(out, (int)cap, f)) out[strcspn(out, "\r\n")] = 0;
	if (f) fclose(f);
}

/* rtspd's "get", read once per page; empty when rtspd isn't answering. */
static char live[4096];

static void live_load(void)
{
	if (CTL_CMD("get\n", live, sizeof live, CTL_MS) || strstr(live, "err")) *live = 0;
}

static int live_get(const char *key, char *out, size_t cap)
{
	size_t kl = strlen(key);
	for (const char *l = live; *l; l += strcspn(l, "\n"), l += *l == '\n') {
		if (strncmp(l, key, kl) || l[kl] != '=') continue;
		snprintf(out, cap, "%.*s", (int)strcspn(l + kl + 1, "\n"), l + kl + 1);
		return 1;
	}
	return 0;
}

/* A setting as rtspd runs it, else as cam.conf has it (what rtspd takes at its next start), else
 * the default. */
static void setting(const char *key, const char *def, char *out, size_t cap)
{
	if (!live_get(key, out, cap) && !conf_get(key, out, cap)) snprintf(out, cap, "%s", def);
}

static int setting_int(const char *key, int def, int lo, int hi)
{
	char v[32];
	setting(key, "", v, sizeof v);
	int x = ui_int(v, lo, hi);
	return x < 0 ? def : x;
}

struct ui {
	struct client *c;
	int role, page, code, sent;        /* sent: the POST answered itself (a backup's download) */
	char user[64], csrf[41], msg[600];
};

/* The outcome of a POST, shown at the top of the page (escaped); code >= 400 is an error. */
static void ui_say(struct ui *u, int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(u->msg, sizeof u->msg, fmt, ap);
	va_end(ap);
	u->code = code;
}

static void page_status(struct ui *u), page_image(struct ui *u), post_image(struct ui *u),
	    page_osd(struct ui *u), post_osd(struct ui *u),
	    page_streams(struct ui *u), post_streams(struct ui *u), page_motion(struct ui *u),
	    post_motion(struct ui *u), page_time(struct ui *u), post_time(struct ui *u),
	    page_users(struct ui *u), post_users(struct ui *u), page_ssh(struct ui *u), post_ssh(struct ui *u),
	    page_system(struct ui *u), post_system(struct ui *u);

/* Each page needs at least `level` to see it and to POST to it. */
static const struct page {
	const char *path, *title;
	int level, live;
	void (*show)(struct ui *), (*post)(struct ui *);
} pages[] = {
	{ "/ui/", "Status", L_VIEWER, 1, page_status, NULL },
	{ "/ui/image", "Image", L_OPERATOR, 1, page_image, post_image },
	{ "/ui/osd", "OSD", L_OPERATOR, 1, page_osd, post_osd },
	{ "/ui/streams", "Streams", L_OPERATOR, 0, page_streams, post_streams },
	{ "/ui/motion", "Motion &amp; audio", L_OPERATOR, 1, page_motion, post_motion },
	{ "/ui/time", "Time", L_ADMIN, 0, page_time, post_time },
	{ "/ui/users", "Users", L_ADMIN, 0, page_users, post_users },
	{ "/ui/ssh", "SSH keys", L_ADMIN, 0, page_ssh, post_ssh },
	{ "/ui/system", "System", L_ADMIN, 0, page_system, post_system },
};
#define NPAGES (int)(sizeof pages / sizeof pages[0])

static const char *const role_name[] = { "-", "viewer", "operator", "admin" };

static void form_open(const struct ui *u, const char *act)
{
	S("<form method=\"post\" action=\"%s\"%s><input type=\"hidden\" name=\"csrf\" value=\"%s\">",
	  pages[u->page].path, act && !strcmp(act, "live") ? " data-live" : "", u->csrf);
	if (act && !strcmp(act, "live")) return;
	if (act) S("<input type=\"hidden\" name=\"do\" value=\"%s\">", act);
}

/* A slider and a number field for one setting: /ui.js keeps them in step; without it the number
 * counts when it was changed, else the slider (see pick). */
static void slider(const char *name, const char *label, int v, int lo, int hi)
{
	S("<label>%s <input type=\"range\" name=\"%s\" min=\"%d\" max=\"%d\" value=\"%d\"> <input "
	  "type=\"number\" name=\"%s_n\" min=\"%d\" max=\"%d\" value=\"%d\"></label>", label, name, lo, hi, v,
	  name, lo, hi, v);
}

/* The value a slider pair sent: the number field if it differs from cur, else the slider; cur if
 * neither was sent. -1 if one that was sent isn't a whole number lo..hi. */
static int pick(const char *name, int cur, int lo, int hi)
{
	char nn[40];
	snprintf(nn, sizeof nn, "%s_n", name);
	const char *r = form_get(name), *n = form_get(nn);
	int rv = r ? ui_int(r, lo, hi) : cur, nv = n ? ui_int(n, lo, hi) : cur;
	if (rv < 0 || nv < 0) return -1;
	return nv != cur ? nv : rv;
}

static void number(const char *name, const char *label, int v, int lo, int hi)
{
	S("<label>%s <input type=\"number\" name=\"%s\" min=\"%d\" max=\"%d\" value=\"%d\"></label>", label,
	  name, lo, hi, v);
}

/* vals[i] is sent, labels[i] shown */
static void choice(const char *name, const char *label, const char *const *vals, const char *const *labels,
		   int n, const char *cur)
{
	S("<label>%s <select name=\"%s\">", label, name);
	for (int i = 0; i < n; i++)
		S("<option value=\"%s\"%s>%s</option>", vals[i], !strcmp(vals[i], cur) ? " selected" : "", labels[i]);
	S("</select></label>");
}

static void checkbox(const char *name, const char *label, int on)
{
	S("<label><input type=\"checkbox\" name=\"%s\" value=\"1\"%s> %s</label>", name, on ? " checked" : "", label);
}

/* A checkbox as sent: 1 ticked, 0 not (browsers leave it out), -1 a value no form sends. */
static int ticked(const char *name)
{
	const char *v = form_get(name);
	return !v ? 0 : !strcmp(v, "1") ? 1 : -1;
}

static void row(const char *k, const char *v)
{
	S("<tr><th>%s</th><td>", k);
	E(v);
	S("</td></tr>");
}

static void fw_version(char *v, size_t cap)
{
	first_line(version_path, v, cap);
	if (!*v || strlen(v) > 32 || strspn(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-") != strlen(v))
		snprintf(v, cap, "%s", FW_VERSION);
}

/* -- status (viewer) -- */

static void page_status(struct ui *u)
{
	char v[200], w[64], a[INET_ADDRSTRLEN], m[INET_ADDRSTRLEN], ts[24], ntp[NTP_MAX][64], rep[256] = "", line[256];
	uint8_t mac[6];
	struct in_addr ip, mask;
	int mtu, n, prefix = 0;
	double up;
	(void)u;
	S("<p><img src=\"/snapshot.jpg\" alt=\"snapshot\" width=\"640\" height=\"360\"></p><table>");
	fw_version(v, sizeof v);
	row("Firmware", v);
	FILE *f = fopen(uptime_path, "r");
	if (f && fscanf(f, "%lf", &up) == 1 && up >= 0 && up < 1e9) {
		long s = (long)up;
		snprintf(v, sizeof v, "%ld d %02ld:%02ld", s / 86400, s / 3600 % 24, s / 60 % 60);
	} else snprintf(v, sizeof v, "unknown");
	if (f) fclose(f);
	row("Uptime", v);
	time_t now = time(NULL);
	iso(now, ts);
	ts[10] = ' ';
	ts[19] = 0;
	snprintf(v, sizeof v, "%s UTC%s", ts, (long long)now < build_epoch ? " (not set yet)" : "");
	row("Time", v);
	local_text(now, v, sizeof v);
	row("Local time", v);
	n = ntp_servers(ntp);
	*v = 0;
	for (int i = 0; i < n; i++) snprintf(v + strlen(v), sizeof v - strlen(v), "%s%s", i ? ", " : "", ntp[i]);
	row("NTP", n ? v : "off");
	if (*live) {
		setting("daynight.state", "unknown", w, sizeof w);
		setting("daynight.mode", "auto", a, sizeof a);
		snprintf(v, sizeof v, "%s (mode %s)", w, a);
	} else snprintf(v, sizeof v, "unknown (rtspd isn't answering)");
	row("Day/night", v);
	if (!setting_int("motion.enabled", 1, 0, 1)) snprintf(v, sizeof v, "detection off");
	else if (!CTL_CMD("motion\n", rep, sizeof rep, CTL_MS) && strstr(rep, "motion.state=1\n")) snprintf(v, sizeof v, "motion");
	else if (strstr(rep, "motion.state=0\n")) snprintf(v, sizeof v, "no motion");
	else snprintf(v, sizeof v, "unknown");
	row("Motion", v);
	streams_load();
	for (int i = 0; i < 2; i++) {
		if (st[i].on)
			snprintf(v, sizeof v, "%s %dx%d, %d fps, %d kbit/s", st[i].h265 ? "H.265" : "H.264", st[i].w, st[i].h,
				 st[i].fps, st[i].kbps);
		else snprintf(v, sizeof v, "off");
		row(i ? "Sub stream" : "Main stream", v);
	}
	long tot = -1, avail = -1;
	if ((f = fopen(meminfo_path, "r"))) {
		while (fgets(line, sizeof line, f)) {
			sscanf(line, "MemTotal: %ld kB", &tot);
			sscanf(line, "MemAvailable: %ld kB", &avail);
		}
		fclose(f);
	}
	if (tot > 0 && avail >= 0) snprintf(v, sizeof v, "%ld MiB free of %ld MiB", avail / 1024, tot / 1024);
	else snprintf(v, sizeof v, "unknown");
	row("Memory", v);
	if_info(mac, &ip, &mask, &mtu);
	for (uint32_t x = ntohl(mask.s_addr); x & 0x80000000u; x <<= 1) prefix++;
	inet_ntop(AF_INET, &ip, a, sizeof a);
	inet_ntop(AF_INET, &mask, m, sizeof m);
	snprintf(v, sizeof v, "%s/%d (netmask %s) on %s", a, prefix, m, ifname);
	row("Address", v);
	snprintf(v, sizeof v, "none");
	if ((f = fopen(route_path, "r"))) {                /* the default route on our interface */
		char ifn[IFNAMSIZ + 1];
		unsigned long dst, gw;
		unsigned fl;
		while (fgets(line, sizeof line, f))
			if (sscanf(line, "%16s %lx %lx %x", ifn, &dst, &gw, &fl) == 4 && !strcmp(ifn, ifname) && !dst &&
			    (fl & 2)) {
				struct in_addr g = { (in_addr_t)gw };     /* /proc prints it in network order */
				inet_ntop(AF_INET, &g, v, sizeof v);
				break;
			}
		fclose(f);
	}
	row("Gateway", v);
	*v = 0;
	if ((f = fopen(resolv_path, "r"))) {
		char ns[64];
		for (int k = 0; k < 3 && fgets(line, sizeof line, f);)
			if (sscanf(line, "nameserver %63s", ns) == 1 && strspn(ns, "0123456789abcdefABCDEF.:") == strlen(ns))
				snprintf(v + strlen(v), sizeof v - strlen(v), "%s%s", k++ ? ", " : "", ns);
		fclose(f);
	}
	row("DNS", *v ? v : "none");
	snprintf(v, sizeof v, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	row("MAC", v);
	S("</table><p class=\"note\">Streams as configured (rtspd uses them from its start). The network "
	  "is set by DHCP.</p>");
}

/* -- image (operator) -- */

static const char *const img_ui_key[6] = { "image.brightness", "image.contrast", "image.saturation",
					   "image.sharpness", "image.exposure", "daynight.irled" };
static const char *const img_ui_name[6] = { "brightness", "contrast", "saturation", "sharpness", "exposure",
					    "irled" };
static const char *const img_ui_label[6] = { "Brightness", "Contrast", "Saturation", "Sharpness", "Exposure",
					     "IR LED at night (%)" };
static const char *const dn_modes[3] = { "auto", "day", "night" };
static const char *const dn_labels[3] = { "Automatic", "Day (colour)", "Night (black and white, IR)" };
static const char *const off_on[2] = { "0", "1" }, *const off_on_labels[2] = { "Off", "On" };

/* Shutter limits (rtspd image.shutter_day_max / _night_max, microseconds, 0 = automatic). Night
 * stops at 1/25 s: rtspd allows at most stock's 1/20 s (a longer shutter would lower the frame
 * rate), so 1/12 s isn't offered. */
#define SH_DAY_N 10
#define SH_NIGHT_N 4
static const char *const sh_day_us[SH_DAY_N] = { "0", "40000", "20000", "10000", "4000", "2000", "1000", "500",
						 "200", "100" };
static const char *const sh_day_labels[SH_DAY_N] = { "Automatic (one frame)", "1/25 s", "1/50 s", "1/100 s",
						     "1/250 s", "1/500 s", "1/1000 s", "1/2000 s", "1/5000 s",
						     "1/10000 s" };
static const char *const sh_night_us[SH_NIGHT_N] = { "0", "40000", "20000", "10000" };
static const char *const sh_night_labels[SH_NIGHT_N] = { "Automatic (1/20 s, as stock)", "1/25 s", "1/50 s",
							 "1/100 s" };
static const char *const sh_key[2] = { "image.shutter_day_max", "image.shutter_night_max" };
static const char *const sh_name[2] = { "shutter_day", "shutter_night" };

/* Night exposure (rtspd image.exposure_night: "day" = as image.exposure, else 0..100): a select
 * (the same as by day / its own value) and a slider, which counts only with its own value. */
static const char *const en_modes[2] = { "day", "own" };
static const char *const en_labels[2] = { "Same as day", "Own value" };

/* image.exposure_night now: -1 for "day" (also unset or not a value rtspd takes), else 0..100 */
static int exposure_night_cur(void)
{
	char v[16];
	setting("image.exposure_night", "day", v, sizeof v);
	return !strcmp(v, "day") ? -1 : ui_int(v, 0, 100);
}

/* A whole number lo..hi of up to 7 digits (the day/night thresholds go to 1000000), else -1 */
static long ui_long(const char *v, long lo, long hi)
{
	size_t n = v ? strlen(v) : 0;
	if (n < 1 || n > 7 || strspn(v, "0123456789") != n) return -1;
	long x = atol(v);
	return x >= lo && x <= hi ? x : -1;
}

static long setting_long(const char *key, long def, long lo, long hi)
{
	char v[32];
	setting(key, "", v, sizeof v);
	long x = ui_long(v, lo, hi);
	return x < 0 ? def : x;
}

/* The shutter limit now (us; 0 if unset or not a value rtspd takes) */
static long shutter_cur(int night)
{
	return setting_long(sh_key[night], 0, 0, night ? 50000 : 1000000);
}

/* A shutter select: the fixed choices, plus the current value if camcfg set another one, so that
 * applying the form (every slider release does) keeps it. */
static void shutter_choice(int night, const char *label)
{
	const char *v[SH_DAY_N + 1], *l[SH_DAY_N + 1];
	char cur[16], custom[40];
	int n = night ? SH_NIGHT_N : SH_DAY_N, have = 0;
	snprintf(cur, sizeof cur, "%ld", shutter_cur(night));
	for (int i = 0; i < n; i++) {
		v[i] = night ? sh_night_us[i] : sh_day_us[i];
		l[i] = night ? sh_night_labels[i] : sh_day_labels[i];
		have |= !strcmp(v[i], cur);
	}
	if (!have) {
		snprintf(custom, sizeof custom, "%s us (set elsewhere)", cur);
		v[n] = cur;
		l[n++] = custom;
	}
	choice(sh_name[night], label, v, l, n, cur);
}

/* Advanced (ISP tuning and anti-flicker; rtspd image.nr2d / nr3d / wdr / blc 0..255, image.mains_hz
 * 50|60, image.antiflicker 0|1; docs/STOCK-IMAGE-TUNING.md). The WDR select and its strength slider
 * make one setting: Off sends image.wdr 0 (the profile as tuned), On the slider's 1..255. */
static const char *const tune_ui_key[4] = { "image.nr2d", "image.nr3d", "image.wdr", "image.blc" };
static const char *const mains_vals[2] = { "50", "60" }, *const mains_labels[2] = { "50 Hz", "60 Hz" };
static const char *const wdr_labels[2] = { "Off (as tuned)", "On" };

static void page_tuning(void)
{
	int nr2d = setting_int(tune_ui_key[0], 128, 0, 255), nr3d = setting_int(tune_ui_key[1], 128, 0, 255),
	    wdr = setting_int(tune_ui_key[2], 0, 0, 255), blc = setting_int(tune_ui_key[3], 0, 0, 255);
	int af = setting_int("image.antiflicker", 0, 0, 1), hz = setting_int("image.mains_hz", 60, 50, 60);
	S("<h2>Advanced</h2>");
	slider("nr2d", "2D noise reduction (128 = as tuned)", nr2d, 0, 255);
	slider("nr3d", "3D noise reduction (128 = as tuned)", nr3d, 0, 255);
	S("<p class=\"note\">128 is the stock tuning; lower keeps more detail and more noise, higher smooths "
	  "more (3D: also more smearing of moving things).</p>");
	choice("wdr_on", "Wide dynamic range", off_on, wdr_labels, 2, off_on[wdr > 0]);
	slider("wdr", "WDR strength (128 = as tuned)", wdr ? wdr : 128, 1, 255);
	slider("blc", "Backlight compensation (with WDR off; 0 = as tuned)", blc, 0, 255);
	S("<p class=\"note\">The stock tuning already runs a moderate WDR; Off keeps it. On scales it by the "
	  "strength. Backlight compensation sets one fixed strength instead, for a subject in front of a "
	  "bright background, and only works with WDR off.</p>");
	choice("mains", "Mains frequency", mains_vals, mains_labels, 2, hz == 50 ? "50" : "60");
	choice("antiflicker", "Anti-flicker", off_on, off_on_labels, 2, off_on[af]);
	S("<p class=\"note\">Anti-flicker stops bands and pulsing under lamps on AC mains: the shutter is "
	  "kept to whole half mains cycles (1/100 s at 50 Hz, 1/120 s at 60 Hz), so in bright light the "
	  "picture may be too bright. It can't work with a longest shutter shorter than that.</p>");
}

/* The Advanced group's wanted values, in tune_ui_key order then mains, antiflicker; NULL if fine,
 * else the reason (nothing saved). */
static const char *post_tuning(int cur[6], int want[6])
{
	cur[0] = setting_int(tune_ui_key[0], 128, 0, 255);
	cur[1] = setting_int(tune_ui_key[1], 128, 0, 255);
	cur[2] = setting_int(tune_ui_key[2], 0, 0, 255);
	cur[3] = setting_int(tune_ui_key[3], 0, 0, 255);
	cur[4] = setting_int("image.mains_hz", 60, 50, 60) == 50 ? 50 : 60;
	cur[5] = setting_int("image.antiflicker", 0, 0, 1);
	for (int i = 0; i < 2; i++)
		if ((want[i] = pick(i ? "nr3d" : "nr2d", cur[i], 0, 255)) < 0) return "Noise reduction: 0 to 255.";
	const char *on = form_get("wdr_on");
	int strength = pick("wdr", cur[2] ? cur[2] : 128, 1, 255);
	if (on && strcmp(on, "0") && strcmp(on, "1")) return "Wide dynamic range: off or on.";
	if (strength < 0) return "WDR strength: 1 to 255.";
	want[2] = !on ? cur[2] : !strcmp(on, "0") ? 0 : strength;
	if ((want[3] = pick("blc", cur[3], 0, 255)) < 0) return "Backlight compensation: 0 to 255.";
	const char *m = form_get("mains"), *a = form_get("antiflicker");
	want[4] = !m ? cur[4] : !strcmp(m, "50") ? 50 : !strcmp(m, "60") ? 60 : -1;
	if (want[4] < 0) return "Mains frequency: 50 or 60 Hz.";
	want[5] = !a ? cur[5] : !strcmp(a, "0") ? 0 : !strcmp(a, "1") ? 1 : -1;
	if (want[5] < 0) return "Anti-flicker: off or on.";
	return NULL;
}

static void page_image(struct ui *u)
{
	char mode[8], score[16];
	int m, f;
	/* /ui.js reloads the snapshot about once a second: plain image loads work in every browser
	 * (Safari in Lockdown Mode drew /preview.mjpg grey while holding its slot, 2026-10-23) and hold
	 * no connection. Without scripts the stream is a link. */
	S("<p><img src=\"/snapshot.jpg\" data-refresh alt=\"preview\" width=\"640\" height=\"360\"></p>"
	  "<p class=\"note\">Preview, about a frame a second while this page is visible.</p><noscript><p "
	  "class=\"note\">Scripts are off: reload for a new picture, or open the <a href=\"/preview.mjpg\">"
	  "live stream</a> (one at a time, 5 minutes).</p></noscript>");
	form_open(u, "live");
	S("<h2>Picture</h2>");
	for (int i = 0; i < 5; i++) slider(img_ui_name[i], img_ui_label[i], setting_int(img_ui_key[i], 50, 0, 100), 0, 100);
	S("<p class=\"note\">50 is the stock picture.</p><h2>Orientation</h2>");
	m = setting_int("image.mirror", 0, 0, 1);
	f = setting_int("image.flip", 0, 0, 1);
	choice("mirror", "Mirror (left-right)", off_on, off_on_labels, 2, off_on[m]);
	choice("flip", "Flip (upside down)", off_on, off_on_labels, 2, off_on[f]);
	S("<p class=\"note\">Off and Off is the stock picture; both On turn it by 180&deg;. Turning it by "
	  "90&deg; is issue #123. A motion area drawn in Surveillance Station applies to the picture as it "
	  "is shown, so draw it again after changing this.</p><h2>Day/night</h2>");
	setting("daynight.mode", "auto", mode, sizeof mode);
	choice("mode", "Mode", dn_modes, dn_labels, 3, mode);
	number("night_below", "Switch to night below", (int)setting_long("daynight.night_below", 15, 1, 1000000), 1, 1000000);
	number("day_above", "Back to day above", (int)setting_long("daynight.day_above", 1500, 1, 1000000), 1, 1000000);
	setting("daynight.score", "", score, sizeof score);
	S("<p class=\"note\">In automatic mode the camera follows a brightness score: the picture's "
	  "brightness divided by its exposure (shutter in seconds &times; gain). Daylight scores about "
	  "10000 to 100000, dusk without the IR LEDs about 8, the IR-lit night about 170. Night must be "
	  "below day; keep the day value well above what the IR LEDs alone give, or it switches back and "
	  "forth. Defaults 15 and 1500.");
	if (ui_long(score, 0, 1000000) >= 0) S(" Score now: %s.", score);
	S("</p>");
	slider(img_ui_name[5], img_ui_label[5], setting_int(img_ui_key[5], 96, 0, 100), 0, 100);
	int en = exposure_night_cur();
	choice("exposure_night_mode", "Exposure at night", en_modes, en_labels, 2, en_modes[en >= 0]);
	slider("exposure_night", "Night exposure (with Own value)", en >= 0 ? en : setting_int(img_ui_key[4], 50, 0, 100),
	       0, 100);
	S("<p class=\"note\">At night the camera can aim for another brightness than by day (50 is the stock "
	  "picture). Try 30 where a street light or other lamp makes the night picture washed out and grey.</p>");
	checkbox("night_tuning", "Stock night tuning: stronger noise reduction, softer sharpening, darker shadows at night",
		 setting_int("image.night_tuning", 0, 0, 1));
	S("<h2>Exposure</h2>");
	shutter_choice(0, "Longest shutter by day");
	shutter_choice(1, "Longest shutter at night");
	S("<p class=\"note\">A shorter shutter freezes movement (number plates, faces) but needs more gain, "
	  "so the picture gets noisier and, in poor light, darker. Automatic is one frame by day and "
	  "1/20 s at night, as stock.</p>");
	page_tuning();
	S("<button type=\"submit\">Apply</button> <span class=\"live\"></span></form><p class=\"note\">A "
	  "change applies when you let go of a slider or pick a choice (number fields with Apply) and is "
	  "kept.</p>");
}

static void post_image(struct ui *u)
{
	const char *key[24], *val[24];
	char buf[24][16], mode[8];
	int cur[6], want[6], n = 0;
	const char *m = form_get("mode");
	for (int i = 0; i < 6; i++) {
		cur[i] = setting_int(img_ui_key[i], i < 5 ? 50 : 96, 0, 100);
		if ((want[i] = pick(img_ui_name[i], cur[i], 0, 100)) < 0) {
			ui_say(u, 400, "%s: a whole number from 0 to 100.", img_ui_label[i]);
			return;
		}
	}
	setting("daynight.mode", "auto", mode, sizeof mode);
	if (m && strcmp(m, "auto") && strcmp(m, "day") && strcmp(m, "night")) {
		ui_say(u, 400, "Day/night: auto, day or night.");
		return;
	}
	/* orientation: 0 or 1 */
	static const char *const or_key[2] = { "image.mirror", "image.flip" }, *const or_name[2] = { "mirror", "flip" };
	int or_cur[2], or_want[2];
	for (int i = 0; i < 2; i++) {
		const char *v = form_get(or_name[i]);
		or_cur[i] = setting_int(or_key[i], 0, 0, 1);
		or_want[i] = !v ? or_cur[i] : !strcmp(v, "0") ? 0 : !strcmp(v, "1") ? 1 : -1;
		if (or_want[i] < 0) {
			ui_say(u, 400, "%s: off or on.", i ? "Flip" : "Mirror");
			return;
		}
	}
	/* thresholds: each 1..1000000, night below day */
	long nb_cur = setting_long("daynight.night_below", 15, 1, 1000000), da_cur = setting_long("daynight.day_above", 1500, 1, 1000000);
	const char *nbv = form_get("night_below"), *dav = form_get("day_above");
	long nb = nbv ? ui_long(nbv, 1, 1000000) : nb_cur, da = dav ? ui_long(dav, 1, 1000000) : da_cur;
	if (nb < 0 || da < 0) {
		ui_say(u, 400, "Day/night thresholds: whole numbers from 1 to 1000000.");
		return;
	}
	if (nb >= da) {
		ui_say(u, 400, "Day/night: \"Switch to night below\" must be lower than \"Back to day above\".");
		return;
	}
	/* night exposure: "day", or the slider's value with "own" (the slider showed the day value while
	 * it was "day"); without the mode, the slider counts only if it has its own value already */
	int en_cur = exposure_night_cur(), en_want;
	const char *em = form_get("exposure_night_mode");
	int en_slider = pick("exposure_night", en_cur >= 0 ? en_cur : cur[4], 0, 100);
	if ((em && strcmp(em, "day") && strcmp(em, "own")) || en_slider < 0) {
		ui_say(u, 400, "Exposure at night: the same as by day, or its own value from 0 to 100.");
		return;
	}
	en_want = !em ? (en_cur >= 0 ? en_slider : -1) : !strcmp(em, "day") ? -1 : en_slider;
	/* stock night tuning: a checkbox (an unticked one isn't sent: off) */
	int nt_cur = setting_int("image.night_tuning", 0, 0, 1), nt_want = ticked("night_tuning");
	if (nt_want < 0) {
		ui_say(u, 400, "Stock night tuning: a checkbox sent a value no form sends.");
		return;
	}
	/* shutter limits: one of the choices, or the value already set */
	long sh_cur[2], sh_want[2];
	for (int i = 0; i < 2; i++) {
		const char *v = form_get(sh_name[i]);
		sh_cur[i] = sh_want[i] = shutter_cur(i);
		if (!v) continue;
		int ok = 0;
		for (int k = 0; k < (i ? SH_NIGHT_N : SH_DAY_N); k++) ok |= !strcmp(v, i ? sh_night_us[k] : sh_day_us[k]);
		sh_want[i] = ok ? atol(v) : ui_long(v, 0, 1000000);
		if (!ok && sh_want[i] != sh_cur[i]) {
			ui_say(u, 400, "Longest shutter %s: pick one of the choices.", i ? "at night" : "by day");
			return;
		}
	}
	int tc[6], tw[6];
	const char *why = post_tuning(tc, tw);
	if (why) {
		ui_say(u, 400, "%s", why);
		return;
	}
	/* the changes, in an order that keeps night_below < day_above at every step (camcfg and rtspd
	 * refuse a pair that doesn't) */
#define CHANGE(k, fmt, x) do { key[n] = (k); snprintf(buf[n], sizeof buf[n], fmt, x); val[n] = buf[n]; n++; } while (0)
	for (int i = 0; i < 6; i++)
		if (want[i] != cur[i]) CHANGE(img_ui_key[i], "%d", want[i]);
	if (m && strcmp(m, mode)) CHANGE("daynight.mode", "%s", m);
	for (int i = 0; i < 2; i++)
		if (or_want[i] != or_cur[i]) CHANGE(or_key[i], "%d", or_want[i]);
	if (nb >= da_cur) {
		if (da != da_cur) CHANGE("daynight.day_above", "%ld", da);
		if (nb != nb_cur) CHANGE("daynight.night_below", "%ld", nb);
	} else {
		if (nb != nb_cur) CHANGE("daynight.night_below", "%ld", nb);
		if (da != da_cur) CHANGE("daynight.day_above", "%ld", da);
	}
	if (en_want != en_cur) {
		if (en_want < 0) CHANGE("image.exposure_night", "%s", "day");
		else CHANGE("image.exposure_night", "%d", en_want);
	}
	if (nt_want != nt_cur) CHANGE("image.night_tuning", "%d", nt_want);
	for (int i = 0; i < 2; i++)
		if (sh_want[i] != sh_cur[i]) CHANGE(sh_key[i], "%ld", sh_want[i]);
	/* Advanced: NR, WDR, BLC, then the mains frequency before anti-flicker */
	static const char *const tk[6] = { "image.nr2d", "image.nr3d", "image.wdr", "image.blc", "image.mains_hz",
					   "image.antiflicker" };
	for (int i = 0; i < 6; i++)
		if (tw[i] != tc[i]) CHANGE(tk[i], "%d", tw[i]);
#undef CHANGE
	for (int i = 0; i < n; i++)
		if (save_live(key[i], val[i], u->user)) {
			ui_say(u, 500, "Saving %s failed (camcfg).", key[i]);
			return;
		}
	ui_say(u, 200, n ? "Saved and applied." : "Nothing changed.");
}

/* -- OSD (operator): the date/time and title overlays -- */

static const char *const osd_pos_labels[5] = { "Top left", "Top right", "Bottom left", "Bottom right",
					       "Custom (below)" };
static const char *const osd_fmt_labels[6] = { "2026-10-23 (yyyy-MM-dd)", "2026/10/23 (yyyy/MM/dd)",
					       "23/10/2026 (dd/MM/yyyy)", "10/23/2026 (MM/dd/yyyy)",
					       "23-10-2026 (dd-MM-yyyy)", "10-23-2026 (MM-dd-yyyy)" };
static const char *const osd_size_labels[3] = { "Small", "Medium", "Large" };
static const char *const osd_style_labels[3] = { "White, black outline, no box", "Black on white",
						 "White on black" };
static const char *const osd_clock_labels[2] = { "24-hour", "12-hour (AM/PM)" };

static void page_osd(struct ui *u)
{
	struct osdset o;
	char status[16];
	osd_load(&o, 0);
	S("<p><img src=\"/snapshot.jpg\" data-refresh alt=\"preview\" width=\"640\" height=\"360\"></p>"
	  "<p class=\"note\">Preview (the snapshot channel, which carries the sub-stream's overlay), about a frame "
	  "a second. Surveillance Station can set the same overlays (its OSD settings).</p>");
	setting("osd.status", "", status, sizeof status);
	if (!strcmp(status, "failed"))
		S("<p class=\"warn\">The camera's overlay driver refused a request, so the overlay is off until the "
		  "video restarts (Streams, or a reboot). The settings are still saved.</p>");
	form_open(u, "live");
	S("<h2>Date and time</h2>");
	choice("time_on", "Show", off_on, off_on_labels, 2, off_on[o.on[0]]);
	choice("time_pos", "Place", osd_pos, osd_pos_labels, 5, osd_pos[o.pos[0]]);
	number("time_x", "Custom place: across (0 left to 100 right)", o.x[0], 0, 100);
	number("time_y", "Custom place: down (0 top to 100 bottom)", o.y[0], 0, 100);
	choice("time_format", "Date", osd_fmts, osd_fmt_labels, 6, osd_fmts[o.fmt]);
	choice("clock", "Clock", off_on, osd_clock_labels, 2, off_on[o.h12]);
	choice("weekday", "Weekday", off_on, off_on_labels, 2, off_on[o.weekday]);
	S("<p class=\"note\">The time shown is the camera's local time: set the time zone on the ");
	if (u->role >= L_ADMIN) S("<a href=\"/ui/time\">Time page</a>");
	else S("Time page (admin)");
	S(".</p><h2>Title</h2>");
	choice("title_on", "Show", off_on, off_on_labels, 2, off_on[o.on[1]]);
	S("<label>Text (up to %d letters, digits, spaces and symbols) <input type=\"text\" name=\"title\" "
	  "maxlength=\"%d\" value=\"", OSD_TEXT, OSD_TEXT);
	E(o.text);
	S("\"></label>");
	choice("title_pos", "Place", osd_pos, osd_pos_labels, 5, osd_pos[o.pos[1]]);
	number("title_x", "Custom place: across (0 left to 100 right)", o.x[1], 0, 100);
	number("title_y", "Custom place: down (0 top to 100 bottom)", o.y[1], 0, 100);
	S("<p class=\"note\">Both in the same corner: the title goes next to the time.</p><h2>Look</h2>");
	choice("size", "Size", osd_sizes, osd_size_labels, 3, osd_sizes[o.size]);
	choice("style", "Style", osd_styles, osd_style_labels, 3, osd_styles[o.style]);
	S("<button type=\"submit\">Apply</button> <span class=\"live\"></span></form><p class=\"note\">A choice "
	  "applies when you pick it; text and number fields with Apply. Changes are kept.</p>");
}

static void post_osd(struct ui *u)
{
	struct osdset cur, want;
	const char *v;
	int x;
	osd_load(&cur, 0);
	want = cur;
	static const char *const nm[2][4] = { { "time_on", "time_pos", "time_x", "time_y" },
					      { "title_on", "title_pos", "title_x", "title_y" } };
	for (int l = 0; l < 2; l++) {
		const char *what = l ? "Title" : "Date and time";
		if ((v = form_get(nm[l][0]))) {
			if ((x = osd_pick(v, off_on, 2)) < 0) { ui_say(u, 400, "%s: show off or on.", what); return; }
			want.on[l] = x;
		}
		if ((v = form_get(nm[l][1]))) {
			if ((x = osd_pick(v, osd_pos, 5)) < 0) { ui_say(u, 400, "%s: pick a place.", what); return; }
			want.pos[l] = x;
		}
		for (int k = 2; k < 4; k++)
			if ((v = form_get(nm[l][k]))) {
				if ((x = ui_int(v, 0, 100)) < 0) { ui_say(u, 400, "%s: custom place 0 to 100.", what); return; }
				*(k == 2 ? &want.x[l] : &want.y[l]) = x;
			}
	}
	if ((v = form_get("time_format")) && (want.fmt = osd_pick(v, osd_fmts, 6)) < 0) {
		ui_say(u, 400, "Date: pick one of the formats.");
		return;
	}
	if ((v = form_get("clock")) && (want.h12 = osd_pick(v, off_on, 2)) < 0) {
		ui_say(u, 400, "Clock: 24-hour or 12-hour.");
		return;
	}
	if ((v = form_get("weekday")) && (want.weekday = osd_pick(v, off_on, 2)) < 0) {
		ui_say(u, 400, "Weekday: off or on.");
		return;
	}
	if ((v = form_get("title"))) {
		if (!osd_text_ok(v)) {
			ui_say(u, 400, "Title: at most %d letters, digits, spaces and symbols (ASCII; no accents).", OSD_TEXT);
			return;
		}
		snprintf(want.text, sizeof want.text, "%s", v);
	}
	if ((v = form_get("size")) && (want.size = osd_pick(v, osd_sizes, 3)) < 0) {
		ui_say(u, 400, "Size: small, medium or large.");
		return;
	}
	if ((v = form_get("style")) && (want.style = osd_pick(v, osd_styles, 3)) < 0) {
		ui_say(u, 400, "Style: pick one of the choices.");
		return;
	}
	int n = osd_save(&cur, &want, u->user);
	if (n < 0) ui_say(u, 500, "Saving failed (camcfg).");
	else ui_say(u, 200, n ? "Saved and applied." : "Nothing changed.");
}

/* -- streams (operator) -- */

static const char *const codecs[2] = { "h264", "h265" }, *const codec_labels[2] = { "H.264", "H.265" };
static const char *const profiles[3] = { "high", "main", "baseline" }, *const profile_labels[3] = { "High", "Main", "Baseline" };

static void page_streams(struct ui *u)
{
	char name[24], prof[16], cur[16];
	streams_load();
	S("<p class=\"warn\">Saving a change restarts the video for a few seconds. Surveillance Station is "
	  "slow to reconnect, and when it does it may set its own stream settings again.</p>");
	form_open(u, NULL);
	for (int i = 0; i < 2; i++) {
		const char *s = i ? "sub" : "main", *sizes[4];
		const struct stream_size *z;
		int nz = 0;
		S("<h2>%s stream, %dx%d</h2>", i ? "Sub" : "Main", st[i].w, st[i].h);
		if (!st[i].on) { S("<p>Off (stream.sub.enabled=0).</p>"); continue; }
		snprintf(name, sizeof name, "%s_size", s);
		while (nz < 4 && (z = stream_size_at(i, nz))) sizes[nz++] = z->name;
		snprintf(cur, sizeof cur, "%dx%d", st[i].w, st[i].h);
		choice(name, "Size", sizes, sizes, nz, cur);
		snprintf(name, sizeof name, "%s_codec", s);
		choice(name, "Codec", codecs, codec_labels, 2, codecs[st[i].h265]);
		snprintf(name, sizeof name, "%s_kbps", s);
		number(name, st[i].kbps_set ? "Bit rate (kbit/s, 64 to 16384)" :
		       "Bit rate (kbit/s, 64 to 16384; not set: the size's default)", st[i].kbps, 64, 16384);
		snprintf(name, sizeof name, "%s_fps", s);
		number(name, i ? "Frame rate (1 to 30, at most the main stream's)" : "Frame rate (1 to 30)", st[i].fps, 1,
		       STREAM_FPS_MAX);
		snprintf(name, sizeof name, "%s_gop", s);
		number(name, "Keyframe interval (frames, 1 to 1000)", st[i].gop, 1, 1000);
		snprintf(name, sizeof name, "%s_profile", s);
		snprintf(prof, sizeof prof, "%c%s", tolower((unsigned char)st[i].profile[0]), st[i].profile + 1);
		choice(name, "H.264 profile", profiles, profile_labels, 3, prof);
	}
	S("<p class=\"note\">A bit rate left at its default follows the size: main 4000, 3500, 3000 or 1500 "
	  "kbit/s (2560x1440 to 1280x720), sub 500, 900 or 1500 kbit/s (640x360 to 1280x720). Snapshots and "
	  "the preview are the sub-stream's size.</p><button type=\"submit\">Save</button></form>");
}

static void post_streams(struct ui *u)
{
	struct stream want[2];
	char name[24];
	int n = 0;
	streams_load();
	for (int i = 0; i < 2; i++) {
		const char *s = i ? "sub" : "main", *v;
		int x;
		want[i] = st[i];
		if (!st[i].on) continue;
#define FIELD(k) (snprintf(name, sizeof name, "%s_%s", s, k), form_get(name))
		if ((v = FIELD("codec"))) {
			if (strcmp(v, "h264") && strcmp(v, "h265")) { ui_say(u, 400, "Codec: H.264 or H.265."); return; }
			want[i].h265 = v[3] == '5';
		}
		if ((v = FIELD("kbps")) && (x = ui_int(v, 64, 16384)) < 0) { ui_say(u, 400, "Bit rate: 64 to 16384 kbit/s."); return; }
		if (v) want[i].kbps = x;
		if ((v = FIELD("fps")) && (x = ui_int(v, 1, STREAM_FPS_MAX)) < 0) { ui_say(u, 400, "Frame rate: 1 to 30."); return; }
		if (v) want[i].fps = x;
		if ((v = FIELD("size"))) {
			const struct stream_size *z = stream_size_find(i, v);
			if (!z) {
				ui_say(u, 400, "Size: %s.", i ? "640x360, 960x540 or 1280x720" : "2560x1440, 2304x1296, 1920x1080 or 1280x720");
				return;
			}
			want[i].w = z->w;
			want[i].h = z->h;
		}
		if ((v = FIELD("gop")) && (x = ui_int(v, 1, 1000)) < 0) { ui_say(u, 400, "Keyframe interval: 1 to 1000 frames."); return; }
		if (v) want[i].gop = x;
		if ((v = FIELD("profile"))) {
			if (!strcmp(v, "high")) want[i].profile = "High";
			else if (!strcmp(v, "main")) want[i].profile = "Main";
			else if (!strcmp(v, "baseline")) want[i].profile = "Baseline";
			else { ui_say(u, 400, "H.264 profile: high, main or baseline."); return; }
		}
#undef FIELD
	}
	if (want[1].fps > want[0].fps) want[1].fps = want[0].fps;   /* the sub at most the main's (rtspd) */
	for (int i = 0; i < 2; i++) {
		int k = st[i].on ? stream_save(i, &want[i], u->user) : 0;
		if (k < 0) {
			ui_say(u, 500, "Saving failed (camcfg)%s; nothing was restarted.", n ? " after some changes" : "");
			return;
		}
		n += k;
	}
	int wait = n ? rtspd_restart() : 0;
	if (!n) ui_say(u, 200, "Nothing changed.");
	else if (!wait) ui_say(u, 200, "Saved. The video restarts now (about 3 s).");
	else ui_say(u, 200, "Saved. The video restarted moments ago: it restarts again with these settings in %d s.", wait);
}

/* -- motion and audio (operator) -- */

static void page_motion(struct ui *u)
{
	char map[4096];
	form_open(u, NULL);
	S("<h2>Motion detection</h2>");
	checkbox("motion", "Detect motion", setting_int("motion.enabled", 1, 0, 1));
	slider("sensitivity", "Sensitivity", setting_int("motion.sensitivity", 50, 0, 100), 0, 100);
	S("<h2>Microphone</h2>");
	checkbox("audio", "Send audio with the video", setting_int("audio.enabled", 1, 0, 1));
	slider("gain", "Gain (14 is stock)", setting_int("audio.gain", 14, 0, 19), 0, 19);
	S("<p class=\"note\">A microphone change restarts the video for a few seconds.</p>"
	  "<button type=\"submit\">Save</button></form><h2>Motion map</h2><p class=\"note\">The detection "
	  "area is drawn in Surveillance Station. One character per cell: - outside the area, # counted as "
	  "motion, 0 to 9 the change in tens of %%.</p>");
	if (!CTL_CMD("motion map\n", map, sizeof map, CTL_MS) && !strstr(map, "\nerr") && strncmp(map, "err", 3)) {
		char *ok = strstr(map, "ok\n");
		if (ok) *ok = 0;
		S("<pre>");
		E(map);
		S("</pre>");
	} else {
		S("<p>rtspd isn't answering.</p>");
	}
}

static void post_motion(struct ui *u)
{
	int cur[4], want[4], n = 0, audio = 0;
	static const char *const keys[4] = { "motion.enabled", "motion.sensitivity", "audio.enabled", "audio.gain" };
	char val[8];
	cur[0] = setting_int(keys[0], 1, 0, 1);
	cur[1] = setting_int(keys[1], 50, 0, 100);
	cur[2] = setting_int(keys[2], 1, 0, 1);
	cur[3] = setting_int(keys[3], 14, 0, 19);
	want[0] = ticked("motion");
	want[1] = pick("sensitivity", cur[1], 0, 100);
	want[2] = ticked("audio");
	want[3] = pick("gain", cur[3], 0, 19);
	if (want[0] < 0 || want[2] < 0) { ui_say(u, 400, "A checkbox sent a value no form sends."); return; }
	if (want[1] < 0) { ui_say(u, 400, "Sensitivity: a whole number from 0 to 100."); return; }
	if (want[3] < 0) { ui_say(u, 400, "Gain: a whole number from 0 to 19."); return; }
	for (int i = 0; i < 4; i++) {
		if (want[i] == cur[i]) continue;
		snprintf(val, sizeof val, "%d", want[i]);
		if (i < 2 ? save_live(keys[i], val, u->user) : cfg_set(keys[i], val)) {
			if (i >= 2) LOG("camcfg set %s %s failed\n", keys[i], val);
			ui_say(u, 500, "Saving %s failed (camcfg).", keys[i]);
			return;
		}
		if (i >= 2) { LOG("%s set by %s to %s\n", keys[i], u->user, val); audio = 1; }
		n++;
	}
	int wait = audio ? rtspd_restart() : 0;          /* rtspd reads audio.* only at its start */
	if (!n) ui_say(u, 200, "Nothing changed.");
	else if (!audio) ui_say(u, 200, "Saved and applied.");
	else if (!wait) ui_say(u, 200, "Saved. The video restarts now (about 3 s).");
	else ui_say(u, 200, "Saved. The video restarted moments ago: it restarts again with these settings in %d s.", wait);
}

/* -- time (admin) -- */

/* The time zone choices (time.tz): POSIX TZ strings, so daylight saving switches by itself. The
 * owner's US zones first; then whole-hour fixed offsets (tz_fixed); anything else as Custom. */
static const struct { int group; const char *tz, *label; } tz_presets[] = {
	{ 0, "HST10", "UTC&minus;10 Hawaii (HST, no daylight saving)" },
	{ 0, "AKST9AKDT,M3.2.0,M11.1.0", "UTC&minus;9 Alaska (AKST/AKDT)" },
	{ 0, "PST8PDT,M3.2.0,M11.1.0", "UTC&minus;8 US Pacific (PST/PDT)" },
	{ 0, "MST7MDT,M3.2.0,M11.1.0", "UTC&minus;7 US Mountain (MST/MDT)" },
	{ 0, "MST7", "UTC&minus;7 Arizona (MST, no daylight saving)" },
	{ 0, "CST6CDT,M3.2.0,M11.1.0", "UTC&minus;6 US Central (CST/CDT)" },
	{ 0, "EST5EDT,M3.2.0,M11.1.0", "UTC&minus;5 US Eastern (EST/EDT)" },
	{ 0, "AST4ADT,M3.2.0,M11.1.0", "UTC&minus;4 Atlantic (AST/ADT)" },
	{ 0, "NST3:30NDT,M3.2.0,M11.1.0", "UTC&minus;3:30 Newfoundland (NST/NDT)" },
	{ 1, "GMT0BST,M3.5.0/1,M10.5.0", "UTC&plusmn;0 UK and Ireland (GMT/BST)" },
	{ 1, "CET-1CEST,M3.5.0,M10.5.0/3", "UTC+1 Central Europe (CET/CEST)" },
	{ 1, "EET-2EEST,M3.5.0/3,M10.5.0/4", "UTC+2 Eastern Europe (EET/EEST)" },
	{ 1, "MSK-3", "UTC+3 Moscow (MSK, no daylight saving)" },
	{ 2, "IST-5:30", "UTC+5:30 India (IST, no daylight saving)" },
	{ 2, "CST-8", "UTC+8 China, Singapore (CST, no daylight saving)" },
	{ 2, "JST-9", "UTC+9 Japan, Korea (JST, no daylight saving)" },
	{ 2, "AEST-10AEDT,M10.1.0,M4.1.0/3", "UTC+10 Sydney (AEST/AEDT)" },
	{ 2, "NZST-12NZDT,M9.5.0,M4.1.0/3", "UTC+12 New Zealand (NZST/NZDT)" },
};
#define NTZ_PRESETS (int)(sizeof tz_presets / sizeof tz_presets[0])
static const char *const tz_groups[3] = { "North America", "Europe", "Asia and Pacific" };

/* A whole-hour offset h (-12..14) without daylight saving: UTC0, or <-05>5, <+01>-1 (POSIX's
 * sign is the other way round). */
static void tz_fixed(int h, char out[32])
{
	if (!h) snprintf(out, 32, "UTC0");
	else snprintf(out, 32, "<%c%02d>%d", h < 0 ? '-' : '+', h < 0 ? -h : h, -h);
}

/* tz is one of the select's values */
static int tz_offered(const char *tz)
{
	char f[32];
	for (int i = 0; i < NTZ_PRESETS; i++)
		if (!strcmp(tz, tz_presets[i].tz)) return 1;
	for (int h = -12; h <= 14; h++) {
		tz_fixed(h, f);
		if (!strcmp(tz, f)) return 1;
	}
	return 0;
}

static void tz_option(const char *tz, const char *label, const char *cur)
{
	S("<option value=\"");
	E(tz);
	S("\"%s>%s</option>", !strcmp(tz, cur) ? " selected" : "", label);
}

static void page_time(struct ui *u)
{
	char ts[24], v[256], tz[TZ_BUF], f[32], lb[64];
	time_t now = time(NULL);
	iso(now, ts);
	ts[10] = ' ';
	ts[19] = 0;
	S("<p>Camera time: %s UTC%s. The camera has no clock battery; NTP keeps its clock, in UTC.</p>", ts,
	  (long long)now < build_epoch ? " (not set yet)" : "");
	local_text(now, v, sizeof v);
	S("<p>Local time: ");
	E(v);
	S("</p>");
	if (!conf_get("time.ntp", v, sizeof v)) snprintf(v, sizeof v, "%s", NTP_DEFAULT);
	form_open(u, NULL);
	S("<label>NTP servers <input type=\"text\" name=\"ntp\" maxlength=\"200\" value=\"");
	E(v);
	S("\"></label><p class=\"note\">Up to 3 host names or IPv4 addresses, separated by commas. Empty "
	  "turns NTP off.</p><button type=\"submit\">Save</button></form>");
	tz_sync(tz);
	int custom = !tz_offered(tz);
	S("<h2>Time zone</h2>");
	form_open(u, "zone");
	S("<label>Time zone <select name=\"zone\">");
	for (int g = 0; g < 3; g++) {
		S("<optgroup label=\"%s\">", tz_groups[g]);
		for (int i = 0; i < NTZ_PRESETS; i++)
			if (tz_presets[i].group == g) tz_option(tz_presets[i].tz, tz_presets[i].label, tz);
		S("</optgroup>");
	}
	S("<optgroup label=\"Fixed offsets (no daylight saving)\">");
	for (int h = -12; h <= 14; h++) {
		tz_fixed(h, f);
		if (!h) snprintf(lb, sizeof lb, "UTC (no daylight saving)");
		else snprintf(lb, sizeof lb, "UTC%s%d (no daylight saving)", h < 0 ? "&minus;" : "+", h < 0 ? -h : h);
		tz_option(f, lb, tz);
	}
	S("</optgroup><optgroup label=\"Other\"><option value=\"custom\"%s>Custom (POSIX TZ, below)</option>"
	  "</optgroup></select></label>", custom ? " selected" : "");
	S("<label>Custom POSIX TZ <input type=\"text\" name=\"tz\" maxlength=\"%d\" value=\"", TZ_LEN);
	if (custom) E(tz);
	S("\"></label><p class=\"note\">Daylight saving switches by itself. The zone sets the clock on the "
	  "video (OSD) and the local time here and over ONVIF; logs, NTP and ONVIF's UTC time stay UTC. "
	  "Custom: a POSIX TZ string such as CST6CDT,M3.2.0,M11.1.0, where the offset counts west of UTC as "
	  "positive (CST6 is UTC&minus;6).</p><button type=\"submit\">Save</button></form>");
}

/* The time zone form: a preset, or Custom with a POSIX TZ string (tz.h, as camcfg checks it).
 * Saved with camcfg and applied live (rtspd's OSD clock and our own TZ). */
static void post_zone(struct ui *u)
{
	const char *z = form_get("zone"), *v = z && !strcmp(z, "custom") ? form_get("tz") : z;
	char cur[TZ_BUF], when[160];
	if (!v || !*v) { ui_say(u, 400, "Pick a time zone, or Custom with a POSIX TZ string."); return; }
	if (v == z && !tz_offered(v)) { ui_say(u, 400, "Pick a time zone from the list."); return; }
	if (!tz_valid(v)) {
		ui_say(u, 400, "\"%.*s%s\" is not a POSIX TZ string the camera takes (at most %d characters, e.g. "
		       "CST6CDT,M3.2.0,M11.1.0).", 80, v, strlen(v) > 80 ? "..." : "", TZ_LEN);
		return;
	}
	tz_sync(cur);
	if (!strcmp(v, cur)) { ui_say(u, 200, "Nothing changed."); return; }
	if (save_live("time.tz", v, u->user)) { ui_say(u, 500, "Saving failed (camcfg)."); return; }
	local_text(time(NULL), when, sizeof when);
	ui_say(u, 200, "Saved and applied. Local time now: %s.", when);
}

/* The same servers SetNTP accepts: up to 3, each a host name, or an IPv4 address if all digits
 * and dots. */
static void post_time(struct ui *u)
{
	const char *d = form_get("do");
	if (d && !strcmp(d, "zone")) { post_zone(u); return; }
	const char *v = form_get("ntp");
	char list[NTP_MAX * 64 + 4] = "", tok[64];
	struct in_addr a;
	int n = 0;
	if (!v) { ui_say(u, 400, "No NTP field."); return; }
	for (const char *p = v + strspn(v, ", "); *p; p += strspn(p, ", ")) {
		size_t l = strcspn(p, ", ");
		snprintf(tok, sizeof tok, "%.*s", (int)(l < sizeof tok ? l : sizeof tok - 1), p);
		p += l;
		if (++n > NTP_MAX) { ui_say(u, 400, "At most 3 NTP servers."); return; }
		if (l >= sizeof tok || !ntp_name_ok(tok) ||
		    (strspn(tok, "0123456789.") == l && inet_pton(AF_INET, tok, &a) != 1)) {
			ui_say(u, 400, "\"%s%s\" is not a host name or an IPv4 address.", tok, l >= sizeof tok ? "..." : "");
			return;
		}
		snprintf(list + strlen(list), sizeof list - strlen(list), "%s%s", n > 1 ? "," : "", tok);
	}
	if (cfg_set("time.ntp", list)) { ui_say(u, 500, "Saving failed (camcfg)."); return; }
	LOG("NTP servers set to \"%s\" by %s\n", list, u->user);
	ui_say(u, 200, n ? "Saved. ntpc uses them from its next poll." : "Saved: NTP is off.");
}

/* -- users (admin) -- */

/* The users a form may name. others: not you, and not the last admin (whose role and account the
 * server refuses to change anyway). The number offered. */
static int user_choice(const struct ui *u, int others)
{
	int admins = 0, n = 0;
	for (int i = 0; i < nusers; i++) admins += users[i].role == L_ADMIN;
	S("<label>User <select name=\"name\">");
	for (int i = 0; i < nusers; i++) {
		if (others && (!strcmp(users[i].name, u->user) || (users[i].role == L_ADMIN && admins <= 1))) continue;
		S("<option>");
		E(users[i].name);
		S("</option>");
		n++;
	}
	S("</select></label>");
	return n;
}

static const char *const roles[3] = { "viewer", "operator", "admin" };
static const char *const role_labels[3] = { "viewer: status and snapshot", "operator: also image, streams, motion and audio",
					    "admin: also time, users, SSH keys and reboot" };

static void page_users(struct ui *u)
{
	users_load();
	S("<table><tr><th>User</th><th>Role</th></tr>");
	for (int i = 0; i < nusers; i++) {
		S("<tr><td>");
		E(users[i].name);
		S("</td><td>%s</td></tr>", role_name[users[i].role]);
	}
	S("</table><p class=\"note\">Passwords: 8 to 64 characters; letters, digits, symbols and spaces "
	  "(ASCII only); no space at the start or end; not the user name. They work for this page, ONVIF "
	  "(Surveillance Station) and RTSP alike.</p><h2>Add a user</h2>");
	form_open(u, "add");
	S("<label>Name <input type=\"text\" name=\"name\" maxlength=\"32\" autocomplete=\"off\"></label>");
	choice("role", "Role", roles, role_labels, 3, "viewer");
	S("<label>Password <input type=\"password\" name=\"pw\" autocomplete=\"new-password\"></label>"
	  "<label>Password again <input type=\"password\" name=\"pw2\" autocomplete=\"new-password\"></label>"
	  "<button type=\"submit\">Add</button></form><h2>Change a password</h2>");
	form_open(u, "passwd");
	user_choice(u, 0);
	S("<label>New password <input type=\"password\" name=\"pw\" autocomplete=\"new-password\"></label>"
	  "<label>Again <input type=\"password\" name=\"pw2\" autocomplete=\"new-password\"></label>"
	  "<button type=\"submit\">Change</button></form><p class=\"note\">After changing your own, the "
	  "browser asks for it again.</p>");
	int others = 0;
	for (int i = 0; i < nusers; i++) others += strcmp(users[i].name, u->user) != 0;
	if (!others) {
		S("<p class=\"note\">Roles and deletion apply to other users: add one first. Your own role and "
		  "account, and the last admin's, can't be changed here.</p>");
		return;
	}
	S("<h2>Change a role</h2>");
	form_open(u, "role");
	user_choice(u, 1);
	choice("role", "Role", roles, role_labels, 3, "viewer");
	S("<button type=\"submit\">Change</button></form><h2>Delete a user</h2>");
	form_open(u, "del");
	user_choice(u, 1);
	S("<button type=\"submit\">Delete</button></form><p class=\"note\">Your own role and account, and "
	  "the last admin's, can't be changed here.</p>");
}

/* camcfg checks names, roles and passwords (and shows why not); here only what camcfg can't
 * know: the two password fields, who is asking, and the last admin. */
static void post_users(struct ui *u)
{
	const char *act = form_get("do"), *name = form_get("name"), *role = form_get("role"),
		   *pw = form_get("pw"), *pw2 = form_get("pw2");
	char out[512], *msg = out;
	int admins = 0;
	users_load();
	for (int i = 0; i < nusers; i++) admins += users[i].role == L_ADMIN;
	const struct user *t = name ? user_find(name) : NULL;
	int add = act && !strcmp(act, "add"), pwd = act && !strcmp(act, "passwd"), rl = act && !strcmp(act, "role"),
	    del = act && !strcmp(act, "del");
	if (!name || (!add && !pwd && !rl && !del) || ((add || rl) && !role) || ((add || pwd) && (!pw || !pw2))) {
		ui_say(u, 400, "Incomplete form.");
		return;
	}
	if ((add || pwd) && strcmp(pw, pw2)) { ui_say(u, 400, "The two passwords differ."); return; }
	if (add && nusers >= MAX_USERS) { ui_say(u, 400, "At most %d users.", MAX_USERS); return; }
	if (!add && !t) { ui_say(u, 400, "No user \"%s\".", name); return; }
	if (del && !strcmp(name, u->user)) { ui_say(u, 400, "You can't delete yourself."); return; }
	if (rl && !strcmp(name, u->user)) { ui_say(u, 400, "You can't change your own role."); return; }
	if ((del || (rl && strcmp(role, "admin"))) && t && t->role == L_ADMIN && admins <= 1) {
		ui_say(u, 400, "%s is the last admin: make another user admin first.", name);
		return;
	}
	/* the monitor runs camcfg -d DIR user ACT NAME [ROLE], the password (whole, so camcfg sees a
	 * long one whole) on its stdin; the form, which holds it, is wiped after this (ui) */
	const char *f[4] = { act, name, add || rl ? role : "", add || pwd ? pw : "" };
	int rc = cfg_exec(MON_USER, 4, f, out, sizeof out);
	if (rc) {
		if (!strncmp(msg, "camcfg: ", 8)) msg += 8;
		msg[strcspn(msg, "\n")] = 0;
		ui_say(u, rc == 1 ? 400 : 500, "%s", *msg ? msg : "camcfg failed.");
		return;
	}
	LOG("user %s: %s%s%s by %s\n", name, act, add || rl ? " " : "", add || rl ? role : "", u->user);
	ui_say(u, 200, add ? "User added." : pwd ? "Password changed." : rl ? "Role changed." : "User deleted.");
}

/* -- SSH keys (admin) -- */

struct skey { char n[4], type[48], fp[56], com[210]; };
static struct skey skeys[UI_KEYS + 1];

/* camcfg sshkey list, parsed: the number of keys, or -1 with camcfg's reason in err. */
static int keys_list(char *err, size_t cap)
{
	static char out[8192];
	const char *f[2] = { "list", "" };
	int n = 0;
	if (cfg_exec(MON_SSHKEY, 2, f, out, sizeof out)) {
		snprintf(err, cap, "%.*s", (int)strcspn(out, "\n"), strncmp(out, "camcfg: ", 8) ? out : out + 8);
		return -1;
	}
	for (char *l = out, *e; *l && n <= UI_KEYS; l = e + (*e == '\n')) {
		e = l + strcspn(l, "\n");
		char *t1 = memchr(l, '\t', (size_t)(e - l)), *t2 = t1 ? memchr(t1 + 1, '\t', (size_t)(e - t1 - 1)) : NULL,
		     *t3 = t2 ? memchr(t2 + 1, '\t', (size_t)(e - t2 - 1)) : NULL;
		if (!t3) continue;
		struct skey *k = &skeys[n++];
		snprintf(k->n, sizeof k->n, "%.*s", (int)(t1 - l), l);
		snprintf(k->type, sizeof k->type, "%.*s", (int)(t2 - t1 - 1), t1 + 1);
		snprintf(k->fp, sizeof k->fp, "%.*s", (int)(t3 - t2 - 1), t2 + 1);
		snprintf(k->com, sizeof k->com, "%.*s", (int)(e - t3 - 1), t3 + 1);
	}
	return n;
}

static void page_ssh(struct ui *u)
{
	char err[300];
	int n = keys_list(err, sizeof err);
	if (n < 0) {
		S("<p class=\"msg err\">sshkey list: ");
		E(err);
		S("</p>");
	} else if (!n) {
		S("<p class=\"warn\">No keys: nobody can log in over SSH (sshd starts only once there is a key).</p>");
	} else {
		S("<table><tr><th>#</th><th>Type</th><th>Fingerprint</th><th>Comment</th><th></th></tr>");
		for (int i = 0; i < n; i++) {
			S("<tr><td>");
			E(skeys[i].n);
			S("</td><td>");
			E(skeys[i].type);
			S("</td><td>");
			E(skeys[i].fp);
			S("</td><td>");
			E(skeys[i].com);
			S("</td><td>");
			form_open(u, "del");
			S("<input type=\"hidden\" name=\"n\" value=\"");
			E(skeys[i].n);
			S("\"><input type=\"hidden\" name=\"fp\" value=\"");
			E(skeys[i].fp);
			S("\"><button type=\"submit\">Delete</button></form></td></tr>");
		}
		S("</table>");
	}
	S("<h2>Add a key</h2>");
	form_open(u, "add");
	S("<label>Public key line <input type=\"text\" name=\"key\" maxlength=\"4096\" autocomplete=\"off\" "
	  "spellcheck=\"false\"></label><button type=\"submit\">Add</button></form><p class=\"note\">One line as "
	  "in id_ed25519.pub: ssh-ed25519, sk-ssh-ed25519@openssh.com, ecdsa-sha2-nistp256, "
	  "sk-ecdsa-sha2-nistp256@openssh.com or ssh-rsa, no options; at most %d keys. Deleting the last key "
	  "turns SSH logins off.</p>", UI_KEYS);
}

static void post_ssh(struct ui *u)
{
	const char *act = form_get("do");
	char out[512], err[300], *msg = out;
	int rc;
	if (act && !strcmp(act, "add")) {
		const char *key = form_get("key"), *f[2] = { "add", key };
		if (!key || !*key) { ui_say(u, 400, "Paste a public key line."); return; }
		rc = cfg_exec(MON_SSHKEY, 2, f, out, sizeof out);   /* the key line on camcfg's stdin */
	} else if (act && !strcmp(act, "del")) {
		int n = ui_int(form_get("n"), 1, UI_KEYS), have = keys_list(err, sizeof err), at = -1;
		const char *fp = form_get("fp");
		for (int i = 0; n > 0 && i < have; i++)
			if (atoi(skeys[i].n) == n) at = i;
		if (at < 0 || !fp || strcmp(fp, skeys[at].fp)) {
			ui_say(u, 400, "The key list has changed: check it and try again.");
			return;
		}
		const char *f[2] = { "del", skeys[at].n };
		rc = cfg_exec(MON_SSHKEY, 2, f, out, sizeof out);
		if (!rc) LOG("SSH key %d (%s) deleted by %s\n", n, log_clean(skeys[at].fp), u->user);
	} else {
		ui_say(u, 400, "Incomplete form.");
		return;
	}
	if (rc) {
		if (!strncmp(msg, "camcfg: ", 8)) msg += 8;
		msg[strcspn(msg, "\n")] = 0;
		ui_say(u, rc == 1 ? 400 : 500, "%s", *msg ? msg : "camcfg failed.");
		return;
	}
	if (*act == 'a') {                                /* camcfg printed its list line */
		msg[strcspn(msg, "\n")] = 0;
		for (char *p = msg; *p; p++) *p = *p == '\t' ? ' ' : isprint((unsigned char)*p) ? *p : '?';
		LOG("SSH key added by %s: %s\n", u->user, msg);
	}
	ui_say(u, 200, *act == 'a' ? "Key added." : "Key deleted.");
}

/* -- firmware update (admin; #104, docs/UPDATE-PATH.md "Delivery") --
 * The System page uploads a signed .camfw: /ui.js POSTs the file as the raw body
 * (application/octet-stream, the page's token in X-CSRF-Token) to UPD_PATH. Everything is decided
 * from the headers, before a byte of the body is taken: credentials, admin, Origin/Referer, token,
 * type, Content-Length 1..UPD_MAX, no other upload, install or reboot under way, and MemAvailable
 * for the file twice over (camupdate reads the whole package into its heap). The body is streamed
 * into UPD_FILE in upd_dir, a tmpfs of its own (rcS: camhttpd's 0700, 6 MiB), never held in memory;
 * the time limit is every request's (5 s + 1 s per BODY_RATE bytes) plus UPD_IDLE s without a
 * byte. Then the monitor runs camupdate --check with the file as its stdin (fork/exec, no shell, an
 * environment of PATH only; mon_upd_check) without blocking the loop, and its verdict is the
 * reply. OK keeps the file for UPD_KEEP_MS; REFUSED, a lost
 * connection mid-body, a timeout, Discard or a new upload delete it. The page then shows version,
 * device, signer and size beside the installed version, and Install: a form bound to that upload
 * (a random id; the uploader's own login; the file's SHA-1 taken while streaming, checked again)
 * behind a confirm box. The reply goes out first, then the monitor starts camupdate detached:
 * double fork and setsid, so neither camhttpd nor camhttpd-run is its ancestor (camupdate would
 * spare them and leave them running from the flash it rewrites); it SIGSTOPs us with everything
 * else. Its stdio go to UPD_LOG. If it exits instead of rebooting, the page shows its last line. */

#define UPD_PATH "/ui/firmware"
#define UPD_FILE "upload.camfw"
#define UPD_LOG "install.log"
#define UPD_MAX (5 << 20)              /* bytes: our image is ~3.4 MiB; RAM 64 MiB, ~11 MiB free */
#define UPD_MEM_SLACK (2 << 20)        /* MemAvailable must cover the file twice and this */
#define UPD_IDLE 30                    /* s an upload may go without a byte */
#define UPD_CHECK_MS 60000             /* camupdate --check gets this long */
#define UPD_KEEP_MS (15 * 60 * 1000)   /* a checked upload waits this long for Install */
#define UPD_START_MS 3000              /* the install starts once its reply is out, or this long after */
#define ST_UPLOAD 4                    /* client states: the upload's body is coming in */
#define ST_CHECK 5                     /* ... and camupdate --check runs on it */

static const char *upd_dir = "/run/fw";

enum { UPD_NONE, UPD_RECV, UPD_CHECK, UPD_READY, UPD_PENDING, UPD_RUNNING };
static struct {
	int state, fd, out, err, downgrade;  /* fd: the file being written; out: the check's record */
	int end;                           /* the install's pipe: EOF once camupdate has ended */
	struct client *c;                  /* the upload's connection until its verdict is sent */
	struct client *ic;                 /* the Install reply's connection */
	size_t want, got, textn;
	struct sha1 h;
	uint8_t sha[20];                   /* SHA-1 of what was received */
	pid_t pid;                         /* camupdate --check, then camupdate */
	long long t;                       /* mono ms: check started, verdict, or Install confirmed */
	time_t body_end;                   /* the body's deadline (BODY_RATE) */
	unsigned long size;                /* the payload's bytes, as camupdate says */
	uint64_t grant, igrant;            /* the upload's grant (pinned for its check), the Install's */
	char user[64], ip[INET_ADDRSTRLEN], id[17], version[33], device[65], signer[129];
	char text[600];                    /* camupdate's output */
	char rec[608];                     /* the check's record as it comes in (mon_upd_check) */
	char note[400];                    /* the last outcome, for the System page */
} upd = { .fd = -1, .out = -1, .end = -1 };

static int claimed(void);
static int host_is_us(const struct client *c);
static void page_by_address(struct client *c, const char *path);
static int tls_up(void);
static void tls_moved(struct client *c, int post, int head, const char *target, const char *path);

static void upd_path(const char *name, char *out, size_t cap) { snprintf(out, cap, "%s/%s", upd_dir, name); }

/* Close and delete the staged upload (a check still running is killed: closing its pipe tells
 * the monitor's runner, mon_upd_check); `why` is logged. */
static void upd_drop(const char *why)
{
	char p[300];
	if (upd.fd >= 0) close(upd.fd);
	if (upd.out >= 0) close(upd.out);
	if (upd.end >= 0) close(upd.end);
	upd.fd = upd.out = upd.end = -1;
	upd.pid = 0;
	upd_path(UPD_FILE, p, sizeof p);
	if (unlink(p) && errno != ENOENT) LOG("firmware upload: %s: %s\n", p, strerror(errno));
	if (why) LOG("firmware upload by %s %s\n", upd.user, why);
	upd.state = UPD_NONE;
	upd.c = NULL;
	memset(upd.id, 0, sizeof upd.id);
}

static void upd_note(int err, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(upd.note, sizeof upd.note, fmt, ap);
	va_end(ap);
	for (char *p = upd.note; *p; p++)
		if (!isprint((unsigned char)*p)) *p = '?';
	upd.err = err;
}

/* A text reply with the UI's headers, from wherever it is sent (the loop's tick too). */
static void upd_reply(struct client *c, int code, const char *fmt, ...)
{
	char t[600];
	int was = ui_resp;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	for (char *p = t; *p; p++)
		if (!isprint((unsigned char)*p) && *p != '\n') *p = '?';
	ui_resp = 1;
	http_reply(c, code, NULL, t);
	ui_resp = was;
	c->deadline = mono() + SEND_TIMEOUT;               /* also when the loop's tick sends it */
}

/* /proc/meminfo's MemAvailable in KiB, or -1. */
static long mem_avail_kb(void)
{
	char line[128];
	long kb = -1;
	FILE *f = fopen(meminfo_path, "r");
	while (f && fgets(line, sizeof line, f))
		if (sscanf(line, "MemAvailable: %ld kB", &kb) == 1) break;
	if (f) fclose(f);
	return kb;
}

/* Why no upload may start now, or NULL. */
static const char *upd_busy(void)
{
	if (upd.state == UPD_RECV || upd.state == UPD_CHECK)
		return "Another firmware upload is being received or checked: try again in a minute.";
	if (upd.state == UPD_PENDING || upd.state == UPD_RUNNING || reboot_at)
		return "The camera is installing firmware or rebooting.";
	return NULL;
}

/* The connection deadline while the body comes in: BODY_RATE overall, UPD_IDLE without a byte. */
static void upd_deadline(struct client *c)
{
	time_t idle = mono() + UPD_IDLE;
	c->deadline = upd.body_end < idle ? upd.body_end : idle;
}

static void upd_check(struct client *c);

/* Body bytes onto the staged file (never past Content-Length); at the last one, the check. */
static void upd_take(struct client *c, const char *p, size_t n)
{
	if (n > upd.want - upd.got) n = upd.want - upd.got;
	sha1_update(&upd.h, p, n);
	while (n) {
		ssize_t k = write(upd.fd, p, n);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) {
			char why[160];
			snprintf(why, sizeof why, "failed after %zu of %zu bytes: %s", upd.got, upd.want,
				 k < 0 ? strerror(errno) : "short write");
			upd_note(1, "The last upload failed: the camera's upload area is full or broken.");
			upd_drop(why);
			upd_reply(c, 507, "The camera couldn't store the file (its upload area is full).\n");
			return;
		}
		p += k;
		n -= (size_t)k;
		upd.got += (size_t)k;
	}
	upd_deadline(c);
	if (upd.got == upd.want) upd_check(c);
}

/* POST UPD_PATH, at the end of its headers (http_feed): 0 if this is not one. Otherwise it is
 * refused with a reply, or the connection goes on as ST_UPLOAD with the body streamed to the
 * file. Order: plain HTTP while HTTPS is up (403, tls_moved), Host (421, by_name_refused),
 * credentials, role, Origin/Referer, token (header), type, length, busy, memory. */
static int upd_route(struct client *c, int ncl)
{
	static const char line[] = "POST " UPD_PATH " ";
	char ip[INET_ADDRSTRLEN], user[64] = "", v[128], p[300];
	const char *why = NULL, *t = c->in + sizeof line - 1;
	req_grant = 0;                                     /* only this request's login may grant */
	if (strncmp(c->in, line, sizeof line - 1) || (strncmp(t, "HTTP/1.1\r\n", 10) && strncmp(t, "HTTP/1.0\r\n", 10)))
		return 0;
	if (!c->tls && tls_up()) {                         /* before the login, as http_request */
		tls_moved(c, 1, 0, UPD_PATH, UPD_PATH);
		return 1;
	}
	if (!claimed()) return 0;
	ui_resp = 1;
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	if (!host_is_us(c)) {
		page_by_address(c, UPD_PATH);
		goto done;
	}
	int role = authenticate(c, "POST", UPD_PATH, NULL, NULL, user, sizeof user);
	if (role < 0) goto done;
	if (role < L_VIEWER) { challenge(c, 0, 0); goto done; }
	if (role < L_ADMIN) {
		LOG("%s: user %s may not post to %s\n", ip, user, UPD_PATH);
		http_reply(c, 403, NULL, "forbidden\n");
		goto done;
	}
	if (!same_origin(c)) why = "no Origin or Referer of this host";
	else if (hdr(c->in, "X-CSRF-Token", v, sizeof v) != 1 || !csrf_ok(user, v)) why = "missing, stale or foreign form token";
	if (why) {
		LOG("%s: POST %s by %s refused: %s\n", ip, UPD_PATH, user, why);
		http_reply(c, 403, NULL, "forbidden: reload the page and try again\n");
		goto done;
	}
	if (hdr(c->in, "Content-Type", v, sizeof v) != 1 || strcasecmp(v, "application/octet-stream")) {
		http_reply(c, 415, NULL, "uploads come from the System page's script, as application/octet-stream\n");
		goto done;
	}
	if (ncl != 1 || !c->body_len) {
		http_reply(c, 411, NULL, "a Content-Length is needed\n");
		goto done;
	}
	if (c->body_len > UPD_MAX) {
		LOG("%s: firmware upload by %s refused: %zu bytes, over %d\n", ip, user, c->body_len, UPD_MAX);
		upd_reply(c, 413, "The file is larger than %d MiB: not a camera package.\n", UPD_MAX >> 20);
		goto done;
	}
	if ((why = upd_busy())) {
		LOG("%s: firmware upload by %s refused: busy\n", ip, user);
		upd_reply(c, 409, "%s\n", why);
		goto done;
	}
	if (upd.state == UPD_READY) upd_drop("replaced by a new upload");   /* frees its RAM first */
	long kb = mem_avail_kb(), need = (long)((2 * c->body_len + UPD_MEM_SLACK) >> 10);
	if (kb < need) {
		LOG("%s: firmware upload by %s refused: MemAvailable %ld KiB, %ld KiB needed\n", ip, user, kb, need);
		upd_reply(c, 507, "Not enough free memory for this file: %ld KiB needed, %ld KiB available.\n", need, kb);
		goto done;
	}
	/* the check runs once the body is in, which may be long after this login's grant has
	 * expired: the monitor pins it for that one check (MON_UPD_BEGIN) */
	if (mon_call(MON_UPD_BEGIN, req_grant, 0, NULL, NULL)) {
		LOG("%s: firmware upload by %s refused by the monitor: %s\n", ip, user, mon_rbuf);
		upd_reply(c, 503, "The camera couldn't start the upload.\n");
		goto done;
	}
	upd.grant = req_grant;
	uint8_t r[8];
	upd_path(UPD_FILE, p, sizeof p);
	unlink(p);
	if (random_bytes(r, sizeof r) || (upd.fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)) < 0) {
		LOG("firmware upload: %s: %s\n", p, strerror(errno));
		upd_reply(c, 503, "The camera has no upload area (%s).\n", upd_dir);
		goto done;
	}
	hex(r, sizeof r, upd.id);
	upd.state = UPD_RECV;
	upd.c = c;
	upd.want = c->body_len;
	upd.got = 0;
	sha1_init(&upd.h);
	snprintf(upd.user, sizeof upd.user, "%s", user);
	snprintf(upd.ip, sizeof upd.ip, "%s", ip);
	*upd.note = 0;
	upd.body_end = mono() + 5 + (time_t)(upd.want / BODY_RATE);
	LOG("%s: firmware upload by %s: %zu bytes\n", ip, user, upd.want);
	if (hdr(c->in, "Expect", v, sizeof v) && !strcasecmp(v, "100-continue") && c->in_len < c->hdr_len + c->body_len)
		out_add(c, "HTTP/1.1 100 Continue\r\n\r\n", 25);
	c->state = ST_UPLOAD;
	size_t have = c->in_len - c->hdr_len;             /* body bytes that came with the headers */
	c->in_len = c->hdr_len;
	upd_take(c, c->in + c->hdr_len, have);
done:
	ui_resp = 0;
	return 1;
}

/* All of the body is in: the monitor runs camupdate --check on UPD_FILE (as its stdin) and hands
 * back a socket the loop reads; the verdict comes on it as one record, then EOF (mon_upd_check). */
static void upd_check(struct client *c)
{
	int fd = -1;
	close(upd.fd);
	upd.fd = -1;
	sha1_final(&upd.h, upd.sha);
	upd.textn = 0;
	*upd.text = 0;
	if (mon_call(MON_UPD_CHECK, upd.grant, 0, NULL, &fd) || fd < 0) {
		if (fd >= 0) close(fd);
		upd_note(1, "The last upload couldn't be checked: %s.", *mon_rbuf ? mon_rbuf : "no answer");
		upd_drop("not checked: the monitor couldn't run camupdate");
		upd_reply(c, 500, "The camera couldn't run camupdate.\n");
		return;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	upd.out = fd;
	upd.pid = 0;
	upd.state = UPD_CHECK;
	upd.t = mono_ms();
	c->state = ST_CHECK;
	c->deadline = mono() + UPD_CHECK_MS / 1000 + 5;
}

/* "camupdate: OK: version V for DEV, N bytes, signed by S[ (downgrade allowed)]" (camupdate.c's
 * printf) into upd; 0, or -1 if it isn't that. */
static int upd_parse_ok(const char *s)
{
	static const char vtag[] = "camupdate: OK: version ", btag[] = " bytes, signed by ", dg[] = " (downgrade allowed)";
	const char *e, *nl;
	char *end;
	if (!(s = strstr(s, vtag))) return -1;
	s += sizeof vtag - 1;
	nl = s + strcspn(s, "\n");
	if (!(e = strstr(s, " for ")) || e > nl || e == s || e - s >= (long)sizeof upd.version) return -1;
	snprintf(upd.version, sizeof upd.version, "%.*s", (int)(e - s), s);
	s = e + 5;
	if (!(e = strstr(s, ", ")) || e > nl || e == s || e - s >= (long)sizeof upd.device) return -1;
	snprintf(upd.device, sizeof upd.device, "%.*s", (int)(e - s), s);
	s = e + 2;
	if (!isdigit((unsigned char)*s)) return -1;
	upd.size = strtoul(s, &end, 10);
	if (strncmp(end, btag, sizeof btag - 1)) return -1;
	s = end + sizeof btag - 1;
	size_t n = (size_t)(nl - s);
	upd.downgrade = n >= sizeof dg - 1 && !strncmp(nl - (sizeof dg - 1), dg, sizeof dg - 1);
	if (upd.downgrade) n -= sizeof dg - 1;
	if (!n || n >= sizeof upd.signer) return -1;
	snprintf(upd.signer, sizeof upd.signer, "%.*s", (int)n, s);
	if (strspn(upd.version, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-") != strlen(upd.version))
		return -1;
	for (char *q = upd.device; *q; q++) if (!isprint((unsigned char)*q)) *q = '?';
	for (char *q = upd.signer; *q; q++) if (!isprint((unsigned char)*q)) *q = '?';
	return 0;
}

/* camupdate --check has ended (status st; timeout: it was killed): the verdict, kept and sent. */
static void upd_verdict(int st, int timeout)
{
	struct client *c = upd.c;
	char why[300], installed[64];
	close(upd.out);
	upd.out = -1;
	upd.pid = 0;
	int ok = !timeout && WIFEXITED(st) && !WEXITSTATUS(st) && !upd_parse_ok(upd.text);
	if (ok && upd.downgrade) {
		/* the owner's decision: the web UI never installs a package signed to allow a downgrade
		 * (no rollback is planned); camupdate over SSH still takes one */
		fw_version(installed, sizeof installed);
		snprintf(why, sizeof why, "version %s is signed to allow a downgrade (installed: %s); the web UI "
			 "doesn't install those, use SSH", upd.version, installed);
		for (char *q = why; *q; q++) if (!isprint((unsigned char)*q)) *q = '?';
		upd_note(1, "The last upload was refused: %s.", why);
		upd_drop(NULL);
		LOG("firmware upload by %s refused: %s\n", upd.user, why);
		if (c) upd_reply(c, 422, "REFUSED: %s\n", why);
		return;
	}
	if (ok) {
		upd.state = UPD_READY;
		upd.t = mono_ms();
		upd.c = NULL;
		fw_version(installed, sizeof installed);
		LOG("firmware upload by %s checked OK: version %s for %s, %lu bytes, signed by %s\n", upd.user,
		    upd.version, upd.device, upd.size, upd.signer);
		if (c)                                     /* still connected (upd_lost clears it) */
			upd_reply(c, 200, "OK: version %s for %s, %lu bytes, signed by %s. Installed now: %s.\n", upd.version,
				  upd.device, upd.size, upd.signer, installed);
		return;
	}
	const char *r = strstr(upd.text, "REFUSED: ");
	if (timeout) snprintf(why, sizeof why, "camupdate --check took longer than %d s", UPD_CHECK_MS / 1000);
	else if (WIFSIGNALED(st)) snprintf(why, sizeof why, "camupdate --check was stopped (signal %d)", WTERMSIG(st));
	else if (WIFEXITED(st) && WEXITSTATUS(st) == 127) snprintf(why, sizeof why, "camupdate isn't installed");
	else if (WIFEXITED(st) && !WEXITSTATUS(st)) snprintf(why, sizeof why, "camupdate's answer wasn't understood");
	else {
		if (r) r += 9;
		else r = strncmp(upd.text, "camupdate: ", 11) ? upd.text : upd.text + 11;
		snprintf(why, sizeof why, "%.*s", (int)strcspn(r, "\n"), r);
		if (!*why) snprintf(why, sizeof why, "camupdate --check failed (exit %d)", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	}
	for (char *q = why; *q; q++) if (!isprint((unsigned char)*q)) *q = '?';
	upd_note(1, "The last upload was refused: %s.", why);
	upd_drop(NULL);
	LOG("firmware upload by %s refused by camupdate: %s\n", upd.user, why);
	if (c) upd_reply(c, 422, "REFUSED: %s\n", why);
}

/* Install confirmed: the file must still be what was received (size and SHA-1). 0 if so. */
static int upd_same(void)
{
	char p[300], buf[4096];
	struct sha1 s;
	struct stat st;
	uint8_t d[20];
	ssize_t k = 0;
	size_t n = 0;
	upd_path(UPD_FILE, p, sizeof p);
	int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || (size_t)st.st_size != upd.want) {
		if (fd >= 0) close(fd);
		return -1;
	}
	sha1_init(&s);
	while ((k = read(fd, buf, sizeof buf)) > 0 || (k < 0 && errno == EINTR))
		if (k > 0) {
			sha1_update(&s, buf, (size_t)k);
			n += (size_t)k;
		}
	close(fd);
	sha1_final(&s, d);
	return k < 0 || n != upd.want || !ct_eq(d, upd.sha, sizeof d) ? -1 : 0;
}

/* After the Install reply: the monitor starts camupdate on UPD_FILE (its stdin), detached (see the
 * top of this section and mon_upd_install), and hands back the read end of a pipe whose only write
 * end camupdate holds (the one fd it keeps open across exec): EOF on it once camupdate and
 * anything it left running have ended. Not kill(pid, 0) on the grandchild, which a zombie or a
 * reused pid would fool. */
static void upd_launch(void)
{
	char lp[300];
	int ep = -1;
	long g = -1;
	upd_path(UPD_LOG, lp, sizeof lp);
	if (!mon_call(MON_UPD_INSTALL, upd.igrant, 0, NULL, &ep) && ep >= 0) g = atol(mon_rbuf);
	if (g <= 0) {
		if (ep >= 0) close(ep);
		LOG("firmware %s: camupdate didn't start: %s\n", upd.version, mon_rbuf);
		upd_note(1, "The install of %s didn't start: the camera couldn't run camupdate. Nothing was written.",
			 upd.version);
		upd_drop("not installed: camupdate didn't start");
		return;
	}
	fcntl(ep, F_SETFL, fcntl(ep, F_GETFL) | O_NONBLOCK);
	fcntl(ep, F_SETFD, FD_CLOEXEC);
	upd.end = ep;
	upd.pid = (pid_t)g;
	upd.state = UPD_RUNNING;
	LOG("firmware %s: camupdate started (pid %d, log %s); the camera reboots once it is written\n", upd.version,
	    (int)g, lp);
}

/* The install's camupdate has ended: EOF (or an error) on its pipe; EAGAIN while it runs. */
static int upd_ended(void)
{
	char b[16];
	ssize_t k = read(upd.end, b, sizeof b);
	return k == 0 || (k < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR);
}

/* The loop's tick: the check's output and end, a checked upload's expiry, the install's start
 * (after its reply), and a camupdate that ended without rebooting. */
static void upd_tick(long long now)
{
	if (upd.state == UPD_CHECK) {
		/* the record: 1 byte "killed at its time limit", camupdate's wait status (4 bytes), its
		 * output; then EOF. Too slow here: the verdict is a timeout, and closing the pipe makes the
		 * runner kill camupdate. */
		int st = -1, timeout = 0;
		char buf[256];
		ssize_t k;
		while ((k = read(upd.out, buf, sizeof buf)) > 0) {
			size_t n = (size_t)k < sizeof upd.rec - upd.textn ? (size_t)k : sizeof upd.rec - upd.textn;
			memcpy(upd.rec + upd.textn, buf, n);
			upd.textn += n;
		}
		if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
			if (now - upd.t < UPD_CHECK_MS) return;
			timeout = 1;
		} else if (upd.textn >= 5) {                    /* EOF (or an error) after the record */
			timeout = upd.rec[0] != 0;
			memcpy(&st, upd.rec + 1, sizeof st);
			snprintf(upd.text, sizeof upd.text, "%.*s", (int)(upd.textn - 5), upd.rec + 5);
		}
		upd_verdict(st, timeout);
	} else if (upd.state == UPD_READY && now - upd.t > UPD_KEEP_MS) {
		upd_note(0, "The checked upload (%s) was discarded: it wasn't installed within %d minutes.", upd.version,
			 UPD_KEEP_MS / 60000);
		upd_drop("discarded: not installed in time");
	} else if (upd.state == UPD_PENDING && (!upd.ic || upd.ic->fd < 0 || now - upd.t >= UPD_START_MS)) {
		upd_launch();
	} else if (upd.state == UPD_RUNNING && upd_ended()) {
		char lp[300], line[200] = "", last[200] = "";
		upd_path(UPD_LOG, lp, sizeof lp);
		FILE *f = fopen(lp, "r");
		while (f && fgets(line, sizeof line, f))
			if (line[strspn(line, " \r\n")]) snprintf(last, sizeof last, "%.*s", (int)strcspn(line, "\r\n"), line);
		if (f) fclose(f);
		for (char *q = last; *q; q++) if (!isprint((unsigned char)*q)) *q = '?';
		/* it stops every process, us too, before it erases: we only see it end before that */
		upd_note(1, "The install of %s ended without a reboot, before writing the flash. camupdate said: %s",
			 upd.version, *last ? last : "nothing");
		LOG("firmware %s: camupdate ended without rebooting: %s\n", upd.version, last);
		upd_drop(NULL);
	}
}

/* The upload's connection is closing: mid-body, the upload is cancelled; during the check, the
 * check goes on and the System page shows its outcome. */
static void upd_lost(struct client *c)
{
	char why[96];
	if (c != upd.c) return;
	upd.c = NULL;
	if (upd.state != UPD_RECV) return;
	snprintf(why, sizeof why, "cancelled after %zu of %zu bytes (closed or timed out)", upd.got, upd.want);
	upd_note(1, "The last upload stopped after %zu of %zu bytes: try again.", upd.got, upd.want);
	upd_drop(why);
}

/* GET UPD_PATH (/ui.js asks before it sends the file): 200 if an upload may start. */
static void upd_status(struct client *c, const char *target, int get)
{
	char user[64] = "", ip[INET_ADDRSTRLEN];
	const char *busy;
	if (!get) { http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n"); return; }
	int role = authenticate(c, "GET", target, NULL, NULL, user, sizeof user);
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	if (role < L_ADMIN) {
		inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
		LOG("%s: user %s may not open %s\n", ip, user, UPD_PATH);
		http_reply(c, 403, NULL, "forbidden\n");
		return;
	}
	if ((busy = upd_busy())) upd_reply(c, 409, "%s\n", busy);
	else upd_reply(c, 200, "ready: up to %d bytes\n", UPD_MAX);
}

/* -- system (admin) -- */

static void page_backup(struct ui *u), post_backup(struct ui *u);   /* the settings backup (#172) */

/* HTTPS on the System page (#183): camtls-run's public files (0644 in /run/camtls), read as they
 * are, no X.509 here. info is camtls check's line: "ok san=IP not_after=TIME ca_fp=HEX fp=HEX".
 * /run/camtls is camtls's directory, so a file there is opened without following a link, must be
 * a small regular file, and is shown only if it looks like what camtls-run writes. */
#define CA_PATH "/ui/ca.crt"
#define CA_MAX 8192                    /* bytes; the camera's CA (EC P-256, PEM) is under 1 KiB */
static const char *tls_ca_path = "/run/camtls/ca.crt", *tls_info_path = "/run/camtls/info";

/* path's bytes into out (NUL-terminated); its length, or 0 if it's missing, a link, not a regular
 * file, empty, or over cap - 1 bytes. */
static size_t pub_read(const char *path, char *out, size_t cap)
{
	struct stat st;
	size_t n = 0;
	ssize_t k;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	*out = 0;
	if (fd < 0) return 0;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || (size_t)st.st_size >= cap) {
		close(fd);
		return 0;
	}
	while (n < cap - 1 && (k = read(fd, out + n, cap - 1 - n)) > 0) n += (size_t)k;
	close(fd);
	out[n] = 0;
	return n == (size_t)st.st_size ? n : (*out = 0, 0);
}

/* The camera's CA certificate, PEM: its length, or 0 (HTTPS off, or not one PEM certificate). */
static size_t ca_pem(char *out, size_t cap)
{
	static const char b[] = "-----BEGIN CERTIFICATE-----\n", e[] = "-----END CERTIFICATE-----\n";
	size_t n = pub_read(tls_ca_path, out, cap);
	if (n < sizeof b + sizeof e || memcmp(out, b, sizeof b - 1) || strcmp(out + n - (sizeof e - 1), e) ||
	    strstr(out + 1, "-----BEGIN") || strlen(out) != n)     /* one certificate, no NUL inside */
		return *out = 0, 0;
	return n;
}

struct tls_info { char san[INET_ADDRSTRLEN], until[32], ca_fp[96], fp[96]; };

/* A SHA-256 as camtls prints it (64 lowercase hex digits) into "AB:CD:..." (95 characters), as
 * Keychain Access and Firefox show it. -1 if it isn't one. */
static int fp_pairs(const char *hex, size_t len, char out[96])
{
	if (len != 64 || strspn(hex, "0123456789abcdef") < 64) return -1;
	for (int i = 0; i < 32; i++) {
		out[3 * i] = (char)toupper((unsigned char)hex[2 * i]);
		out[3 * i + 1] = (char)toupper((unsigned char)hex[2 * i + 1]);
		out[3 * i + 2] = i < 31 ? ':' : 0;
	}
	return 0;
}

/* /run/camtls/info into t: 0, or -1 if it's missing or not camtls check's "ok" line. */
static int tls_info(struct tls_info *t)
{
	char line[512], *s, *save = NULL;
	int have = 0;
	struct in_addr a;
	memset(t, 0, sizeof *t);
	if (!pub_read(tls_info_path, line, sizeof line)) return -1;
	line[strcspn(line, "\r\n")] = 0;
	if (strncmp(line, "ok ", 3)) return -1;
	for (s = strtok_r(line + 3, " ", &save); s; s = strtok_r(NULL, " ", &save)) {
		size_t l = strlen(s);
		if (!strncmp(s, "san=", 4) && l - 4 < sizeof t->san && inet_pton(AF_INET, s + 4, &a) == 1) {
			memcpy(t->san, s + 4, l - 3);
			have |= 1;
		} else if (!strncmp(s, "not_after=", 10) && l - 10 < sizeof t->until && l > 10 &&
			   strspn(s + 10, "0123456789-:TZ") == l - 10) {
			memcpy(t->until, s + 10, l - 9);
			have |= 2;
		} else if (!strncmp(s, "ca_fp=", 6) && !fp_pairs(s + 6, l - 6, t->ca_fp)) {
			have |= 4;
		} else if (!strncmp(s, "fp=", 3) && !fp_pairs(s + 3, l - 3, t->fp)) {
			have |= 8;
		}
	}
	return have == 15 ? 0 : -1;
}

/* The System page's HTTPS part: camtls's status, the CA to download, and how to trust it. */
static void system_https(struct ui *u)
{
	struct tls_info t;
	char pem[CA_MAX];
	S("<h2>HTTPS</h2>");
	if (!ca_pem(pem, sizeof pem)) {
		S("<p class=\"note\">HTTPS is off: camtls hasn't published the camera's CA certificate (it runs only "
		  "with /etc/cam/tls.on in the image). The web UI is on plain HTTP; nothing to download.</p>");
		return;
	}
	S("<p>%s</p>", tls_up() ? "On: these pages are served over HTTPS (camtls, port 443), with a certificate "
	  "the camera's own CA issued." : "camtls isn't serving port 443 right now; this is what it published at "
	  "its last start.");
	if (!tls_info(&t)) {
		S("<table>");
		row("Certificate for", t.san);
		row("Valid until (UTC)", t.until);
		row("CA fingerprint (SHA-256)", t.ca_fp);
		row("Certificate fingerprint (SHA-256)", t.fp);
		S("</table>");
		if (u->c->tls && strcmp(t.san, u->c->local))
			S("<p class=\"warn\">The certificate is for another address than this page's: camtls issues a new "
			  "one at its next start.</p>");
	} else {
		S("<p class=\"note\">camtls's status (/run/camtls/info) can't be read.</p>");
	}
	S("<p><a href=\"" CA_PATH "\">Download the camera's CA certificate</a></p>"
	  "<p class=\"note\">Trust it once per computer, and your browser shows these pages without a warning, even "
	  "after DHCP gives the camera another address. It can only vouch for addresses on the camera network, "
	  "not for other sites.</p><ol>"
	  "<li><b>Check it first.</b> This download came over the network, so compare its fingerprint with one "
	  "you get another way: over SSH, <code>camcfg tls show</code> prints the CA's (ca_fp=). On the computer, "
	  "<code>openssl x509 -in FILE -noout -fingerprint -sha256</code> prints the file's. They must match "
	  "(colons and case don't matter). If they don't, don't trust it.</li>"
	  "<li><b>macOS (Safari, Chrome):</b> open the file; Keychain Access adds it to the login keychain. "
	  "Double-click it there, open Trust, set \"Secure Sockets Layer (SSL)\" to Always Trust, close the "
	  "window and enter your password.</li>"
	  "<li><b>Firefox:</b> Settings, Privacy &amp; Security, Certificates, View Certificates, Authorities, "
	  "Import; tick \"Trust this CA to identify websites\".</li></ol>");
}

/* GET CA_PATH (admin): the camera's CA certificate as a file to trust (system_https). The path is
 * fixed: nothing in the request names a file. */
static void ca_download(struct client *c, const char *target, int get)
{
	char user[64] = "", ip[INET_ADDRSTRLEN], h[160], pem[CA_MAX];
	size_t n;
	if (!get) { http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n"); return; }
	int role = authenticate(c, "GET", target, NULL, NULL, user, sizeof user);
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	if (role < L_ADMIN) {
		inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
		LOG("%s: user %s may not open %s\n", ip, user, CA_PATH);
		http_reply(c, 403, NULL, "forbidden\n");
		return;
	}
	if (!(n = ca_pem(pem, sizeof pem))) {
		http_reply(c, 404, NULL, "HTTPS is off: camtls hasn't published the camera's CA certificate\n");
		return;
	}
	snprintf(h, sizeof h, "Content-Disposition: attachment; filename=\"camera-ca-%s.crt\"\r\n", c->local);
	if (http_head(c, 200, h, "application/x-x509-ca-cert", n) || out_add(c, pem, n)) {
		c->out_len = 0;
		http_reply(c, 500, NULL, NULL);
	}
}

static void page_system(struct ui *u)
{
	char v[64], n[80];
	fw_version(v, sizeof v);
	S("<p>Firmware ");
	E(v);
	S("</p>");
	if (upd.state == UPD_PENDING || upd.state == UPD_RUNNING) {
		S("<p class=\"warn\">Installing firmware ");
		E(upd.version);
		S(": the camera writes it and reboots by itself, in about 1 to 2 minutes. Reload this page then. "
		  "Settings, users and keys are kept.</p>");
		return;
	}
	if (reboot_at || bk_rebooting) return;
	S("<h2>Firmware update</h2>");
	if (*upd.note) {
		S("<p class=\"msg%s\">", upd.err ? " err" : "");
		E(upd.note);
		S("</p>");
	}
	if (upd.state == UPD_READY) {
		S("<p>camupdate checked the uploaded package: it is signed by a key in /etc/cam/update-keys.</p><table>");
		row("Installed", v);
		row("New version", upd.version);
		row("Device", upd.device);
		row("Signed by", upd.signer);
		snprintf(n, sizeof n, "%lu bytes (the package %zu)", upd.size, upd.want);
		row("Size", n);
		row("Uploaded by", upd.user);
		S("</table>");
		if (!strcmp(u->user, upd.user)) {
			form_open(u, "install");
			S("<input type=\"hidden\" name=\"fw\" value=\"%s\">", upd.id);
			checkbox("confirm", "Yes, install this firmware and reboot the camera", 0);
			S("<button type=\"submit\">Install</button></form>");
		} else {
			S("<p class=\"note\">");
			E(upd.user);
			S(" uploaded it: only they can install it.</p>");
		}
		form_open(u, "discard");
		S("<input type=\"hidden\" name=\"fw\" value=\"%s\"><button type=\"submit\">Discard</button></form>"
		  "<p class=\"note\">Installing takes about 1 to 2 minutes and ends with a reboot; video stops meanwhile. "
		  "Settings, users and keys are kept. The upload is discarded if it isn't installed within %d "
		  "minutes.</p>", upd.id, UPD_KEEP_MS / 60000);
	} else if (upd.state == UPD_RECV || upd.state == UPD_CHECK) {
		S("<p>");
		E(upd.user);
		S(" is uploading a package; the camera checks it when it has arrived. Reload this page in a minute.</p>");
	} else {
		S("<form method=\"post\" action=\"%s\" data-upload data-max=\"%d\"><input type=\"hidden\" name=\"csrf\" "
		  "value=\"%s\"><label>Package (.camfw) <input type=\"file\" name=\"file\" accept=\".camfw\"></label>"
		  "<button type=\"submit\">Upload and check</button> <span class=\"live\"></span></form>"
		  "<noscript><p class=\"warn\">Uploading needs this page's script. Without it, use SSH: "
		  "camupdate --check, then camupdate.</p></noscript><p class=\"note\">Only a package signed with one of "
		  "the owner's keys is accepted. The camera checks it first and shows its version and signer; nothing is "
		  "installed until you confirm.</p>", UPD_PATH, UPD_MAX, u->csrf);
	}
	page_backup(u);
	system_https(u);
	S("<h2>Reboot</h2>");
	form_open(u, "reboot");
	checkbox("confirm", "Yes, reboot the camera", 0);
	S("<button type=\"submit\">Reboot</button></form><p class=\"note\">The camera is back in about a minute.</p>");
}

/* Install or Discard the checked upload: only the one this page showed (its id). */
static void post_firmware(struct ui *u, int install)
{
	const char *id = form_get("fw");
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &u->c->peer, ip, sizeof ip);
	if (upd.state != UPD_READY) {
		ui_say(u, 409, "No checked upload is waiting: upload the package again.");
		return;
	}
	if (!id || strlen(id) != 16 || !ct_eq(id, upd.id, 16)) {
		LOG("%s: firmware %s by %s refused: the form is for another upload\n", ip, install ? "install" : "discard", u->user);
		ui_say(u, 409, "This page showed another upload: reload it and check the version again.");
		return;
	}
	if (!install) {
		char why[96];
		snprintf(why, sizeof why, "discarded by %s", u->user);
		upd_drop(why);
		ui_say(u, 200, "The upload was discarded.");
		return;
	}
	if (strcmp(u->user, upd.user)) {
		ui_say(u, 403, "%s uploaded this package: only they can install it.", upd.user);
		return;
	}
	if (ticked("confirm") != 1) { ui_say(u, 400, "Tick the box to confirm."); return; }
	if (reboot_at) { ui_say(u, 409, "The camera is rebooting."); return; }
	if (upd_same()) {
		upd_note(1, "The checked upload changed on the camera before it was installed, so it was deleted.");
		upd_drop("deleted: the staged file changed after the check");
		ui_say(u, 500, "The uploaded file changed after the check: upload it again.");
		return;
	}
	upd.state = UPD_PENDING;
	upd.t = mono_ms();
	upd.ic = u->c;
	upd.igrant = req_grant;                            /* camupdate starts after the reply */
	LOG("%s: firmware %s (signed by %s) install confirmed by %s\n", ip, upd.version, upd.signer, u->user);
	ui_say(u, 200, "Installing %s. The camera writes it and reboots by itself in about 1 to 2 minutes; reload "
	       "this page then. Settings, users and keys are kept.", upd.version);
}

static void post_system(struct ui *u)
{
	const char *act = form_get("do");
	if (act && !strcmp(act, "backup")) {
		post_backup(u);
		return;
	}
	if (act && (!strcmp(act, "install") || !strcmp(act, "discard"))) {
		post_firmware(u, !strcmp(act, "install"));
		return;
	}
	if (upd.state == UPD_PENDING || upd.state == UPD_RUNNING) {
		ui_say(u, 409, "Firmware is being installed: the camera reboots by itself.");
		return;
	}
	if (ticked("confirm") != 1) { ui_say(u, 400, "Tick the box to confirm."); return; }
	reboot_at = mono_ms() > 0 ? mono_ms() : 1;
	reboot_c = u->c;
	reboot_grant = req_grant;
	LOG("reboot requested by %s\n", u->user);
	ui_say(u, 200, "Rebooting now. The camera is back in about a minute.");
}

/* A requested reboot, once its reply has gone out (its connection closed) or 3 s on. */
static void reboot_check(long long now)
{
	if (!reboot_at || (reboot_c->fd >= 0 && now - reboot_at < 3000)) return;
	reboot_at = 0;
	LOG("rebooting\n");
	/* the monitor saves the UsernameToken floor, syncs and reboots (mon_reboot) */
	if (mon_call(MON_REBOOT, reboot_grant, 0, NULL, NULL)) LOG("reboot: %s\n", mon_rbuf);
}

static void html_send(struct client *c, int code)
{
	size_t mark = c->out_len;
	if (!sbover && !http_head(c, code, NULL, "text/html; charset=utf-8", sbn) && !out_add(c, sb, sbn)) return;
	c->out_len = mark;
	http_head(c, 500, NULL, NULL, 0);
}

static void ui_page(struct ui *u)
{
	const struct page *p = &pages[u->page];
	csrf_token(u->user, (long long)mono() / CSRF_BUCKET, u->csrf);
	sbn = 0;
	sbover = 0;
	S("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
	  "content=\"width=device-width,initial-scale=1\"><title>%s - camera</title><link rel=\"stylesheet\" "
	  "href=\"/ui.css\"><script src=\"/ui.js\" defer></script></head><body><header><span class=\"who\">", p->title);
	E(u->user);
	S(" (%s)</span><nav>", role_name[u->role]);
	for (int i = 0; i < NPAGES; i++)
		if (u->role >= pages[i].level)
			S("<a href=\"%s\"%s>%s</a>", pages[i].path, i == u->page ? " class=\"on\"" : "", pages[i].title);
	S("</nav></header><main><h1>%s</h1>", p->title);
	if (*u->msg) {
		S("<p class=\"msg%s\">", u->code >= 400 ? " err" : "");
		E(u->msg);
		S("</p>");
	}
	if (p->live) live_load();
	p->show(u);
	S("</main></body></html>\n");
	html_send(u->c, u->code);
}

/* ---- First-boot claim and admin recovery (#128, docs/CLAIM.md) ---------------------------------
 * The image carries no account. A camera whose users file has no admin is unclaimed: it serves
 * only /setup (and /ui.css) for the first CLAIM_WINDOW seconds after power-on, everything else
 * redirects there, ONVIF answers ter:NotAuthorized and the snapshot 503; after the window it
 * serves only a page saying to power-cycle and claim. /setup makes the first admin through
 * "camcfg claim" (camcfg owns DATA and every rule), which also adds the optional SSH key and
 * returns a recovery code, shown once. Once claimed, /setup is a 404. /recover takes that code and
 * a new password ("camcfg recover"), in the same window after power-on, and wrong codes count as
 * failed logins (auth_failed: the same lockout). Both forms need Host = the address the request
 * came in on (DNS rebinding), an Origin/Referer of that host and a token keyed with the per-start
 * ui_key (there is no user yet); their POSTs that pass those checks share a small rate limit. */

#define CLAIM_WINDOW (30 * 60)         /* s after power-on that /setup and /recover are open */
#define CLAIM_POSTS 10                 /* /setup + /recover POSTs per CLAIM_RATE s, all addresses */
#define CLAIM_RATE 60
#define WRONG_CODE 3                   /* camcfg recover's exit status for a wrong code */

struct rate { time_t t; int n; };
static struct rate claim_rate;         /* the worker's (claim_form) */
static struct rate mon_claim_rate;     /* the monitor's own, for what reaches camcfg */

/* Claimed = the users file has an admin; read on every request, like the users themselves. */
static int claimed(void)
{
	users_load();
	for (int i = 0; i < nusers; i++)
		if (users[i].role == L_ADMIN) return 1;
	return 0;
}

/* Seconds since power-on from /proc/uptime (CLOCK_BOOTTIME: NTP and SetSystemDateAndTime don't
 * move it, a camhttpd restart doesn't reset it), or -1 if unreadable: the window is then shut. */
static long boot_seconds(void)
{
	double up = -1;
	FILE *f = fopen(uptime_path, "r");
	if (f) {
		if (fscanf(f, "%lf", &up) != 1) up = -1;
		fclose(f);
	}
	return up >= 0 && up < 1e9 ? (long)up : -1;
}

static int claim_window(void)
{
	long s = boot_seconds();
	return s >= 0 && s < CLAIM_WINDOW;
}

static long window_left_min(void) { return (CLAIM_WINDOW - boot_seconds() + 59) / 60; }

/* Host is the address the request came in on (":port" optional on 80; from camtls, on 443). A
 * name that resolves to the camera (DNS rebinding: another site's script on the owner's browser)
 * is turned away. */
static int host_is_us(const struct client *c)
{
	char host[128], want[INET_ADDRSTRLEN + 8];
	int port = c->tls ? 443 : http_port;
	if (hdr(c->in, "Host", host, sizeof host) != 1) return 0;
	if ((c->tls || http_port == 80) && !strcmp(host, c->local)) return 1;
	snprintf(want, sizeof want, "%s:%d", c->local, port);
	return !strcmp(host, want);
}

/* The camera's own URL as this connection reached it, for a link on a page: https://ADDRESS from
 * camtls, else http://ADDRESS[:port]. */
static void self_url(const struct client *c, char *out, size_t cap)
{
	if (c->tls) snprintf(out, cap, "https://%s", c->local);
	else if (http_port != 80) snprintf(out, cap, "http://%s:%d", c->local, http_port);
	else snprintf(out, cap, "http://%s", c->local);
}

static int claim_post_ok(struct rate *r, time_t now)
{
	if (now - r->t >= CLAIM_RATE || now < r->t) {
		r->t = now;
		r->n = 0;
	}
	return r->n++ < CLAIM_POSTS;
}

static void bare_page(const char *title)
{
	sbn = 0;
	sbover = 0;
	S("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
	  "content=\"width=device-width,initial-scale=1\"><title>%s - camera</title><link rel=\"stylesheet\" "
	  "href=\"/ui.css\"></head><body><header><span>Camera</span></header><main><h1>%s</h1>", title, title);
}

static void bare_end(struct client *c, int code)
{
	S("</main></body></html>\n");
	html_send(c, code);
}

static void page_unclaimed_closed(struct client *c)
{
	char url[48];
	self_url(c, url, sizeof url);
	bare_page("Not set up");
	S("<p>This camera has not been claimed yet, and setup is closed: it is open only for the first 30 "
	  "minutes after the camera powers on.</p><p>Power-cycle the camera, then open <b>");
	E(url);
	S("/setup</b> within 30 minutes and claim it (or run scripts/cam-claim.py). Do it on a network "
	  "only you use: until it is claimed, anyone who reaches the camera can claim it.</p>");
	bare_end(c, 503);
}

static void page_by_address(struct client *c, const char *path)
{
	char url[48];
	self_url(c, url, sizeof url);
	bare_page("Open this page by the camera's address");
	S("<p>The camera's pages only answer at its own address: <a href=\"");
	E(url);
	E(path);
	S("\">");
	E(url);
	E(path);
	S("</a></p>");
	bare_end(c, 421);
}

static void page_setup(struct client *c, int code, const char *msg, const char *name)
{
	char tok[41];
	csrf_token("/setup", (long long)mono() / CSRF_BUCKET, tok);
	bare_page("Set up this camera");
	if (msg) {
		S("<p class=\"msg err\">");
		E(msg);
		S("</p>");
	}
	S("<p class=\"warn\">Until it is claimed, anyone who reaches this camera can claim it: do this on a "
	  "network only you use. Setup closes 30 minutes after power-on (%ld min left); a power cycle opens "
	  "it again while no admin exists.</p><p>Create the camera's first admin. The account works for these "
	  "pages, ONVIF (Surveillance Station) and RTSP. You also get a recovery code, shown once, that "
	  "resets an admin password if it is lost.</p>", window_left_min());
	S("<form method=\"post\" action=\"/setup\"><input type=\"hidden\" name=\"csrf\" value=\"%s\">", tok);
	S("<label>Admin name <input type=\"text\" name=\"name\" maxlength=\"32\" autocomplete=\"username\" value=\"");
	E(name ? name : "admin");
	S("\"></label><label>Password <input type=\"password\" name=\"pw\" autocomplete=\"new-password\"></label>"
	  "<label>Password again <input type=\"password\" name=\"pw2\" autocomplete=\"new-password\"></label>"
	  "<label>SSH public key (optional; one line: ssh-ed25519 AAAA&hellip; comment) <input type=\"text\" "
	  "name=\"key\" autocomplete=\"off\"></label><button type=\"submit\">Claim this camera</button></form>"
	  "<p class=\"note\">Passwords: 8 to 64 characters; letters, digits, symbols and spaces (ASCII only); "
	  "no space at the start or end; not the user name. Names: 1 to 32 of A-Z a-z 0-9 . _ -. Without a "
	  "key, SSH stays off until an admin adds one on the SSH keys page.</p>");
	/* #173: this camera's own backup instead of a new claim (BK_SETUP_PATH, setup_restore) */
	S("<h2>Or restore this camera's backup</h2><p>Set up before, with a backup (.cambak) of this camera? "
	  "Restore it instead: the settings, users, keys and HTTPS CA come back and the camera reboots. Only "
	  "this camera's own backup works. Wrong passphrases count as failed logins.</p><form method=\"post\" "
	  "action=\"/setup/restore\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf\" "
	  "value=\"%s\"><label>Backup (.cambak) <input type=\"file\" name=\"file\" accept=\".cambak\"></label>"
	  "<label>Its passphrase <input type=\"password\" name=\"pp\" autocomplete=\"off\"></label><button "
	  "type=\"submit\">Restore this camera</button></form>", tok);
	bare_end(c, code);
}

/* The recovery code, once. After a claim (admin: the new admin's name) also the offer of a first
 * backup (#173): the System page's download form, with a token for that admin; the browser asks
 * for the login as it posts. Over plain HTTP (the claim's fallback) only a pointer to it. */
static void page_code(struct client *c, const char *title, const char *intro, const char *code, const char *admin)
{
	char tok[41];
	bare_page(title);
	S("<p class=\"msg\">");
	E(intro);
	S("</p><h2>Recovery code</h2><p class=\"code\" id=\"code\">");
	E(code);
	S("</p><p class=\"warn\">Write this code down or save it now: it is shown only this once, and the "
	  "camera keeps only a hash of it. It sets a new admin password at /recover, within 30 minutes after "
	  "a power-on, and using it replaces it with a new one.</p><p><a href=\"/ui/\">I've saved it: open "
	  "the camera's pages</a> (log in as the admin).</p>");
	if (admin && c->tls) {
		csrf_token(admin, (long long)mono() / CSRF_BUCKET, tok);
		S("<h2>Back up these first settings</h2><p>Recommended: download a backup now, so a copy exists "
		  "before anything can go wrong with the camera's storage. It holds the settings, this admin, the SSH "
		  "key and the camera's HTTPS CA, encrypted with a passphrase you choose, and restores only on this "
		  "camera. It is a snapshot: download a new one on the System page after changing settings, users or "
		  "keys.</p><form method=\"post\" action=\"/ui/system\"><input type=\"hidden\" name=\"csrf\" "
		  "value=\"%s\"><input type=\"hidden\" name=\"do\" value=\"backup\"><label>Passphrase (at least 12 "
		  "characters) <input type=\"password\" name=\"pp\" autocomplete=\"new-password\"></label><label>"
		  "Passphrase again <input type=\"password\" name=\"pp2\" autocomplete=\"new-password\"></label><button "
		  "type=\"submit\">Download a backup</button></form><p class=\"note\">Your browser asks for the admin "
		  "login (", tok);
		E(admin);
		S(") first. You can skip this: the System page has the same form. Keep the file and its passphrase "
		  "as safe as the admin password.</p>");
	} else if (admin) {
		S("<p class=\"note\">Back up these first settings once HTTPS is on (System page), or now over SSH: "
		  "camcfg backup export &gt; FILE.</p>");
	}
	bare_end(c, 200);
}

static void page_recover(struct client *c, int code, const char *msg)
{
	char tok[41];
	csrf_token("/recover", (long long)mono() / CSRF_BUCKET, tok);
	bare_page("Reset an admin password");
	if (msg) {
		S("<p class=\"msg err\">");
		E(msg);
		S("</p>");
	}
	S("<p>The recovery code from setup (or from the last recovery) sets a new password for an admin and is "
	  "then replaced. This page is open for 30 minutes after power-on (%ld min left). Wrong codes count as "
	  "failed logins: 5 in a minute lock your address for the rest of it.</p>", window_left_min());
	S("<form method=\"post\" action=\"/recover\"><input type=\"hidden\" name=\"csrf\" value=\"%s\">"
	  "<label>Admin name (empty: the admin the code was made for) <input type=\"text\" name=\"name\" "
	  "maxlength=\"32\" autocomplete=\"username\"></label><label>Recovery code <input type=\"text\" "
	  "name=\"code\" autocomplete=\"off\"></label><label>New password <input type=\"password\" name=\"pw\" "
	  "autocomplete=\"new-password\"></label><label>Again <input type=\"password\" name=\"pw2\" "
	  "autocomplete=\"new-password\"></label><button type=\"submit\">Set the password</button></form>"
	  "<p class=\"note\">With an admin SSH key: camcfg user passwd NAME (the password on stdin).</p>", tok);
	bare_end(c, code);
}

/* A claim page POST: Origin/Referer, size, type, form syntax, token (`what` is its path, standing
 * in for the user the UI keys tokens with), then the rate: only a POST that passed the rest counts
 * against CLAIM_POSTS, so another site's posts can't use the budget up. 0, or -1 after replying
 * (logged). */
static int claim_form(struct client *c, const char *what, const char *ip)
{
	char ct[128];
	const char *why = NULL;
	if (!same_origin(c)) why = "no Origin or Referer of this host";
	else if (c->body_len > UI_BODY_MAX) { http_reply(c, 413, NULL, "form too large\n"); return -1; }
	else if (hdr(c->in, "Content-Type", ct, sizeof ct) != 1 ||
		 strncasecmp(ct, "application/x-www-form-urlencoded", 33) || (ct[33] && ct[33] != ';')) {
		http_reply(c, 415, NULL, "forms only\n");
		return -1;
	} else if (form_parse(c->in + c->hdr_len, c->body_len)) {
		memset(&form, 0, sizeof form);
		http_reply(c, 400, NULL, "malformed form\n");
		return -1;
	} else if (!csrf_ok(what, form_get("csrf"))) why = "missing, stale or foreign form token";
	if (why) {
		memset(&form, 0, sizeof form);
		LOG("%s: POST %s refused: %s\n", ip, what, why);
		http_reply(c, 403, NULL, "forbidden: reload the page and try again\n");
		return -1;
	}
	if (!claim_post_ok(&claim_rate, mono())) {
		memset(&form, 0, sizeof form);
		LOG("%s: POST %s refused: more than %d claim/recovery attempts a minute\n", ip, what, CLAIM_POSTS);
		http_reply(c, 429, "Retry-After: 60\r\n", "too many attempts: wait a minute\n");
		return -1;
	}
	return 0;
}

/* Printable ASCII, one line: what camcfg's stdin lines may carry (a newline would start another). */
static int one_line(const char *v)
{
	for (; v && *v; v++)
		if ((unsigned char)*v < 0x20 || (unsigned char)*v > 0x7e) return 0;
	return 1;
}

/* camcfg's "recovery-code: XXXX-…" line (its output also carries notes) into code. 0 or -1. */
static int code_from(const char *out, char code[40])
{
	for (const char *p = out; (p = strstr(p, "recovery-code: ")); p++) {
		if (p != out && p[-1] != '\n') continue;
		p += 15;
		size_t n = strcspn(p, "\n");
		if (n < 26 || n >= 40 || strspn(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-") != n) return -1;
		memcpy(code, p, n);
		code[n] = 0;
		return 0;
	}
	return -1;
}

/* camcfg's stderr line as the page shows it */
static const char *camcfg_msg(char *out, const char *dflt)
{
	char *msg = out;
	if (!strncmp(msg, "camcfg: ", 8)) msg += 8;
	msg[strcspn(msg, "\n")] = 0;
	return *msg ? msg : dflt;
}

static void setup(struct client *c, int get, int post, const char *ip)
{
	char out[512], code[40], nm[40];
	if (!get && !post) { http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n"); return; }
	if (get) { page_setup(c, 200, NULL, NULL); return; }
	if (claim_form(c, "/setup", ip)) return;
	const char *name = form_get("name"), *pw = form_get("pw"), *pw2 = form_get("pw2"), *key = form_get("key");
	if (!name || !*name || !pw || !pw2) page_setup(c, 400, "Incomplete form.", name);
	else if (strcmp(pw, pw2)) page_setup(c, 400, "The two passwords differ.", name);
	else if (!one_line(pw) || !one_line(key))
		page_setup(c, 400, "The password and the key must be one line of ASCII letters, digits, symbols and "
			   "spaces.", name);
	else {
		/* the monitor checks the window, that nobody has claimed and its own rate, then runs
		 * camcfg claim NAME with the password and the key line on its stdin (mon_claim) */
		const char *f[4] = { ip, name, pw, key ? key : "" };
		snprintf(nm, sizeof nm, "%s", name);
		log_clean(nm);                                  /* client-supplied (camcfg checks it) */
		int rc = cfg_exec(MON_CLAIM, 4, f, out, sizeof out);
		if (rc == 0 && !code_from(out, code)) {
			LOG("%s: camera claimed: admin %s%s\n", ip, nm, key && *key ? ", SSH key added" : "");
			page_code(c, "This camera is yours", "The admin was created. Log in with it on the next page.", code,
				  nm);
		} else if (rc == 0) {
			LOG("%s: camera claimed: admin %s, but camcfg returned no recovery code\n", ip, nm);
			bare_page("This camera is yours");
			S("<p class=\"msg err\">The admin was created, but no recovery code came back. Set one over SSH "
			  "(camcfg recovery set, 26 characters of A-Z and 2-7 on stdin).</p><p><a href=\"/ui/\">Open the "
			  "camera's pages</a></p>");
			bare_end(c, 500);
		} else if (rc == MON_CLOSED) {                  /* claimed or closed meanwhile, or the rate */
			LOG("%s: claim as \"%s\" refused by the monitor: %s\n", ip, nm, out);
			page_setup(c, 403, out, name);
		} else {
			LOG("%s: claim as \"%s\" refused by camcfg\n", ip, nm);
			page_setup(c, rc == 1 ? 400 : 500, camcfg_msg(out, "camcfg failed."), name);
		}
		memset(out, 0, sizeof out);
		memset(code, 0, sizeof code);
	}
	memset(&form, 0, sizeof form);                         /* it held the password */
}

static void recover(struct client *c, int get, int post, const char *ip)
{
	char out[512], code[40], who[64] = "";
	static const char locked[] = "Too many wrong codes or passwords from this address: wait a minute.";
	if (!get && !post) { http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n"); return; }
	if (get) { page_recover(c, 200, NULL); return; }
	if (mon_auth_probe(c->peer, NULL) > 0) {                /* checked first: a locked address learns nothing */
		LOG("%s: POST /recover refused: address locked out\n", ip);
		page_recover(c, 429, locked);
		return;
	}
	if (claim_form(c, "/recover", ip)) return;
	const char *name = form_get("name"), *rc_in = form_get("code"), *pw = form_get("pw"), *pw2 = form_get("pw2");
	if (!rc_in || !*rc_in || !pw || !pw2) page_recover(c, 400, "Incomplete form.");
	else if (strcmp(pw, pw2)) page_recover(c, 400, "The two passwords differ.");
	else if (!one_line(pw) || !one_line(rc_in) || !one_line(name))
		page_recover(c, 400, "The code, name and password must be one line of ASCII letters, digits, symbols "
			     "and spaces.");
	else {
		/* the monitor checks the lockout, the window and its own rate, runs camcfg recover [NAME]
		 * with the code and the password on its stdin, and counts a wrong code as a failed login
		 * (mon_recover) */
		const char *f[4] = { ip, name ? name : "", rc_in, pw };
		int rc = cfg_exec(MON_RECOVER, 4, f, out, sizeof out);
		const char *a = strstr(out, "admin: ");
		if (a && (a == out || a[-1] == '\n')) snprintf(who, sizeof who, "%.*s", (int)strcspn(a + 7, "\n"), a + 7);
		log_clean(who);
		if (rc == 0 && !code_from(out, code)) {
			LOG("%s: admin %s's password reset with the recovery code; a new code was issued\n", ip, who);
			page_code(c, "Password changed", "The admin's password is changed and the old recovery code no "
				  "longer works. Log in on the next page.", code, NULL);
		} else if (rc == 0) {
			LOG("%s: admin %s's password reset with the recovery code; no new code came back\n", ip, who);
			page_recover(c, 500, "The password was changed, but no new recovery code came back: the old one "
				     "may still work. Set a new one over SSH (camcfg recovery set).");
		} else if (rc == WRONG_CODE) {                  /* counted and logged by the monitor */
			page_recover(c, 403, "Wrong recovery code.");
		} else if (rc == MON_BLOCKED) {
			page_recover(c, 429, locked);
		} else if (rc == MON_CLOSED) {
			page_recover(c, 403, out);
		} else {
			page_recover(c, rc == 1 ? 400 : 500, camcfg_msg(out, "camcfg failed."));
		}
		memset(out, 0, sizeof out);
		memset(code, 0, sizeof code);
	}
	memset(&form, 0, sizeof form);
}

/* ---- Settings backup in the web UI (#172) and at setup (#173), docs/PLAN-DATA-LOCK.md Part 1 ----
 * camcfg backup export|import does the work (camcfg owns DATA and every rule; the monitor runs it
 * with a fixed argv, mon_bk_export / mon_bk_import). Download: the System page's form (passphrase
 * twice) POSTs do=backup; the monitor hands back the .cambak as an fd, served as the reply.
 * Restore: a multipart form (the file, its passphrase and, on the System page, the admin's
 * password again) POSTs to BK_PATH, or to BK_SETUP_PATH on an unclaimed camera instead of a claim;
 * the worker stages the file as BK_FILE in upd_dir and the monitor opens it itself. Both need
 * HTTPS on the System page (the file and its passphrase together give every password and the CA
 * key; without camtls, SSH does it). The setup restore follows /setup's rule: HTTPS while camtls
 * is up, else plain HTTP (the claim's fallback, logged). A restore that works reboots the camera. */

#define BK_PATH "/ui/backup-restore"   /* the System page's restore form */
#define BK_SETUP_PATH "/setup/restore" /* restore instead of a claim (unclaimed, in the window) */
#define BK_FILE "restore.cambak"       /* the staged upload, in upd_dir */
#define BK_UP_MAX (48 * 1024)          /* the web UI's limit (REQ_CAP); larger: over SSH */
#define BK_DL_MAX (1024 * 1024 + 1024) /* a .cambak at most (camcfg's BK_MAX) */
#define BK_REBOOT_MS 3000              /* a restore's reply is out by then */

/* The System page's part: download and restore. */
static void page_backup(struct ui *u)
{
	S("<h2>Settings backup</h2>");
	if (!u->c->tls) {
		S("<p class=\"note\">Backups need HTTPS: open this page at https://. Over SSH: camcfg backup export "
		  "&gt; FILE, and camcfg backup import FILE.</p>");
		return;
	}
	S("<p>One encrypted file with this camera's settings, its users and their passwords, the SSH keys and "
	  "host key, and its HTTPS CA with the CA's key. It restores only on this camera, and only with its "
	  "passphrase.</p><p class=\"warn\">Keep the file and its passphrase as safe as the admin password: "
	  "together they give the ONVIF passwords (kept in clear, as ONVIF needs) and the CA key your "
	  "computers trust. A backup is a snapshot: download a new one after changing settings, users or "
	  "keys.</p>");
	form_open(u, "backup");
	S("<label>Passphrase (at least 12 characters) <input type=\"password\" name=\"pp\" "
	  "autocomplete=\"new-password\"></label><label>Passphrase again <input type=\"password\" name=\"pp2\" "
	  "autocomplete=\"new-password\"></label><button type=\"submit\">Download backup</button></form>"
	  "<p class=\"note\">Making the backup takes a few seconds.</p>");
	S("<form method=\"post\" action=\"" BK_PATH "\" enctype=\"multipart/form-data\"><input type=\"hidden\" "
	  "name=\"csrf\" value=\"%s\"><label>Backup (.cambak) <input type=\"file\" name=\"file\" "
	  "accept=\".cambak\"></label><label>Its passphrase <input type=\"password\" name=\"pp\" "
	  "autocomplete=\"off\"></label><label>Your password (", u->csrf);
	E(u->user);
	S(") <input type=\"password\" name=\"pw\" autocomplete=\"current-password\"></label><button "
	  "type=\"submit\">Restore and reboot</button></form><p class=\"note\">Restoring replaces every setting, "
	  "user and key with the backup's (files added since are removed), then reboots; log in with the "
	  "backup's accounts afterwards. Wrong passphrases and passwords count as failed logins. A backup over "
	  "%d KiB restores over SSH only.</p>", BK_UP_MAX / 1024);
}

/* do=backup on the System page: the .cambak as a download, or the page with camcfg's reason. */
static void post_backup(struct ui *u)
{
	struct client *c = u->c;
	const char *pp = form_get("pp"), *pp2 = form_get("pp2");
	char ip[INET_ADDRSTRLEN], h[200], day[16];
	struct stat sb;
	struct tm tm;
	time_t now = time(NULL);
	int fd = -1;
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	if (!c->tls) { ui_say(u, 403, "Backups need HTTPS: open this page at https://."); return; }
	if (!pp || !pp2 || !*pp) { ui_say(u, 400, "Enter the passphrase twice."); return; }
	if (strcmp(pp, pp2)) { ui_say(u, 400, "The two passphrases differ."); return; }
	if (strlen(pp) > PP_CAP || strchr(pp, '\r')) { ui_say(u, 400, "passphrase: at most 256 bytes, on one line"); return; }
	if (reboot_at || bk_rebooting || upd.state == UPD_PENDING || upd.state == UPD_RUNNING) {
		ui_say(u, 409, "The camera is installing firmware or rebooting.");
		return;
	}
	const char *f[1] = { pp };
	int rc = mon_call(MON_BK_EXPORT, req_grant, 1, f, &fd);
	if (rc || fd < 0 || fstat(fd, &sb) || sb.st_size < 1 || sb.st_size > BK_DL_MAX) {
		LOG("%s: settings backup by %s failed (%d)\n", ip, u->user, rc);
		ui_say(u, rc == 1 ? 400 : rc == MON_CLOSED ? 409 : 500, "%s",
		       camcfg_msg(mon_rbuf, "The backup failed."));
		memset(mon_rbuf, 0, mon_rlen);
		if (fd >= 0) close(fd);
		return;
	}
	memset(mon_rbuf, 0, mon_rlen);
	gmtime_r(&now, &tm);
	strftime(day, sizeof day, "%Y%m%d", &tm);
	snprintf(h, sizeof h, "Content-Disposition: attachment; filename=\"camera-%s-%s.cambak\"\r\n", c->local, day);
	if (http_head(c, 200, h, "application/octet-stream", (size_t)sb.st_size)) {
		close(fd);
		c->out_len = 0;
		ui_say(u, 500, "The backup couldn't be sent.");
		return;
	}
	c->file_fd = fd;
	c->file_left = (long)sb.st_size;
	u->sent = 1;
	LOG("%s: settings backup downloaded by %s (%ld bytes)\n", ip, u->user, (long)sb.st_size);
}

/* The upload staged, restored by the monitor (setup: bk-setup, else bk-restore with this request's
 * grant), the file deleted: the monitor's status, its text (camcfg's) in out. */
static int bk_import_call(int setup, const char *ip, const char *file, size_t n, const char *pw, const char *pp,
			  char *out, size_t cap)
{
	char p[300];
	size_t put = 0;
	upd_path(BK_FILE, p, sizeof p);
	unlink(p);
	int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		LOG("backup restore: %s: %s\n", p, strerror(errno));
		snprintf(out, cap, "The camera has no upload area (%s).", upd_dir);
		return -1;
	}
	while (put < n) {
		ssize_t k = write(fd, file + put, n - put);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		put += (size_t)k;
	}
	if (close(fd) || put < n) {
		unlink(p);
		snprintf(out, cap, "The camera couldn't store the file (its upload area is full).");
		return -1;
	}
	const char *fr[3] = { ip, pw, pp }, *fs[2] = { ip, pp };
	int rc = setup ? mon_call(MON_BK_SETUP, 0, 2, fs, NULL) : mon_call(MON_BK_RESTORE, req_grant, 3, fr, NULL);
	snprintf(out, cap, "%s", mon_rbuf);
	memset(mon_rbuf, 0, mon_rlen);
	unlink(p);
	return rc;
}

/* A restore form's POST: Origin/Referer, multipart, token (keyed with `who`: the user, or "/setup").
 * 0 with the parts in m, or -1 after replying (logged). */
static int bk_form(struct client *c, const char *who, const char *ip, struct mp *m)
{
	char ct[200], tok[48];
	const char *why = NULL;
	if (!same_origin(c)) why = "no Origin or Referer of this host";
	else if (hdr(c->in, "Content-Type", ct, sizeof ct) != 1 || strncasecmp(ct, "multipart/form-data", 19)) {
		http_reply(c, 415, NULL, "a multipart form only\n");
		return -1;
	} else if (mp_parse(c->in + c->hdr_len, c->body_len, ct, m)) {
		http_reply(c, 400, NULL, "malformed form\n");
		return -1;
	} else if (mp_text(m, "csrf", tok, sizeof tok) != 1 || !csrf_ok(who, tok)) why = "missing, stale or foreign form token";
	if (why) {
		LOG("%s: POST %s by %s refused: %s\n", ip, who[0] == '/' ? BK_SETUP_PATH : BK_PATH, who, why);
		http_reply(c, 403, NULL, "forbidden: reload the page and try again\n");
		return -1;
	}
	return 0;
}

/* The file and passphrase parts checked: NULL, or why not (a page's message). */
static const char *bk_parts(const struct mp *m, const char **file, size_t *n, char *pp, size_t cap)
{
	*file = mp_get(m, "file", n);
	int t = mp_text(m, "pp", pp, cap);
	if (!*file || !*n) return "Choose the backup file (.cambak).";
	if (*n > BK_UP_MAX) return "The file is larger than 48 KiB: restore it over SSH (camcfg backup import).";
	if (t < 0) return "passphrase: at most 256 bytes, on one line";
	if (!t || !*pp) return "Enter the backup's passphrase.";
	return NULL;
}

static void bk_restore_form(struct client *c, const char *target, struct ui *u, const char *ip)
{
	static char pp[PP_CAP + 1], pw[UI_BODY_MAX + 1];
	char out[512];
	struct mp m;
	const char *file, *why;
	size_t n;
	int role = authenticate(c, "POST", target, NULL, NULL, u->user, sizeof u->user);
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	u->role = role;
	if (role < L_ADMIN) {
		LOG("%s: user %s may not post to %s\n", ip, u->user, BK_PATH);
		http_reply(c, 403, NULL, "forbidden\n");
		return;
	}
	if (bk_form(c, u->user, ip, &m)) return;
	int pt = mp_text(&m, "pw", pw, sizeof pw);
	if (!c->tls) ui_say(u, 403, "Backups need HTTPS: open this page at https://.");
	else if (reboot_at || bk_rebooting || upd.state == UPD_PENDING || upd.state == UPD_RUNNING)
		ui_say(u, 409, "The camera is installing firmware or rebooting.");
	else if ((why = bk_parts(&m, &file, &n, pp, sizeof pp))) ui_say(u, 400, "%s", why);
	else if (pt != 1 || !*pw || !one_line(pw)) ui_say(u, 400, "Enter your password (the one you log in with).");
	else {
		int rc = bk_import_call(0, ip, file, n, pw, pp, out, sizeof out);
		if (rc == 0) {
			bk_rebooting = 1;
			LOG("%s: settings restored from a backup by %s: the camera reboots\n", ip, u->user);
			ui_say(u, 200, "Restored from the backup. The camera reboots now and is back in about a minute; "
			       "log in with the backup's accounts.");
		} else if (rc == WRONG_CODE) {
			ui_say(u, 403, "Wrong passphrase, or the file was changed: nothing was restored.");
		} else if (rc == MON_AUTH_FAULT) {
			ui_say(u, 403, "Wrong password: nothing was restored.");
		} else if (rc == MON_BLOCKED) {
			ui_say(u, 429, "Too many wrong passwords or passphrases from this address: wait a minute.");
		} else if (rc == MON_CLOSED) {
			ui_say(u, 409, "%s", out);
		} else if (rc == MON_DENIED) {
			ui_say(u, 403, "Not accepted: reload the page and try again.");
		} else {
			ui_say(u, rc == 1 ? 400 : 500, "%s", camcfg_msg(out, "The restore failed."));
		}
		memset(out, 0, sizeof out);
	}
	memset(pp, 0, sizeof pp);
	memset(pw, 0, sizeof pw);
	ui_page(u);
}

/* POST BK_PATH (admin): the outcome on the System page. The body (the file, the passphrase and
 * the password) is wiped once answered. */
static void bk_restore(struct client *c, const char *target, int get, int post)
{
	struct ui u;
	char ip[INET_ADDRSTRLEN];
	if (!post) {
		if (get) http_reply(c, 302, "Location: /ui/system\r\n", "the restore form is on /ui/system\n");
		else http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n");
		return;
	}
	memset(&u, 0, sizeof u);
	u.c = c;
	u.code = 200;
	for (int i = 0; i < NPAGES; i++)
		if (!strcmp(pages[i].path, "/ui/system")) u.page = i;
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	bk_restore_form(c, target, &u, ip);
	memset(c->in + c->hdr_len, 0, c->body_len);
}

/* POST BK_SETUP_PATH: on an unclaimed camera, its own backup in place of a claim. */
static void setup_restore_form(struct client *c, const char *ip)
{
	static char pp[PP_CAP + 1];
	static const char locked[] = "Too many wrong passphrases or codes from this address: wait a minute.";
	char out[512];
	struct mp m;
	const char *file, *why;
	size_t n;
	if (mon_auth_probe(c->peer, NULL) > 0) {                /* checked first: a locked address learns nothing */
		LOG("%s: POST %s refused: address locked out\n", ip, BK_SETUP_PATH);
		page_setup(c, 429, locked, NULL);
		return;
	}
	if (bk_form(c, "/setup", ip, &m)) return;
	if (!claim_post_ok(&claim_rate, mono())) {
		LOG("%s: POST %s refused: more than %d claim/recovery attempts a minute\n", ip, BK_SETUP_PATH, CLAIM_POSTS);
		http_reply(c, 429, "Retry-After: 60\r\n", "too many attempts: wait a minute\n");
		return;
	}
	if ((why = bk_parts(&m, &file, &n, pp, sizeof pp))) {
		page_setup(c, 400, why, NULL);
	} else {
		int rc = bk_import_call(1, ip, file, n, "", pp, out, sizeof out);
		if (rc == 0) {
			LOG("%s: camera restored from its backup at setup: it reboots\n", ip);
			bare_page("Restored");
			S("<p class=\"msg\">This camera is set up again from its backup: its settings, users, keys and "
			  "HTTPS CA are back. It reboots now and is back in about a minute.</p><p>Then open <a "
			  "href=\"/ui/\">the camera's pages</a> and log in with the backup's admin. Its recovery code "
			  "is the one saved with that backup's claim.</p>");
			bare_end(c, 200);
		} else if (rc == WRONG_CODE) {
			page_setup(c, 403, "Wrong passphrase, or the file was changed: nothing was restored.", NULL);
		} else if (rc == MON_BLOCKED) {
			page_setup(c, 429, locked, NULL);
		} else if (rc == MON_CLOSED) {
			page_setup(c, 403, out, NULL);
		} else {
			page_setup(c, rc == 1 ? 400 : 500, camcfg_msg(out, "The restore failed."), NULL);
		}
		memset(out, 0, sizeof out);
	}
	memset(pp, 0, sizeof pp);
}

static void setup_restore(struct client *c, int get, int post, const char *ip)
{
	if (!post) {
		if (get) http_reply(c, 302, "Location: /setup\r\n", "the restore form is on /setup\n");
		else http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n");
		return;
	}
	setup_restore_form(c, ip);
	memset(c->in + c->hdr_len, 0, c->body_len);
}

/* ---- lock mode (#175, docs/PLAN-DATA-LOCK.md Part 2): DATA failed ----------------------------
 * rcS writes data_failed_path (the reason, one line, 0644) when DATA didn't mount or lost a claimed
 * camera's users file. Then every path answers with the lock page: no login, no claim, no media.
 * It shows the reason and how to recover: a backup restored, or DATA erased, signed with one of
 * the image's update keys over the monitor's one-time challenge (unlock-ch; GET UNLOCK_CH_PATH
 * for scripts/cam-recover.py), POSTed to UNLOCK_PATH as the raw body camcfg unlock reads (the
 * passphrase line, the signature, the backup) with the action and the challenge in headers; or
 * from the command line. The worker stages the body as UNLOCK_FILE in upd_dir; the monitor checks
 * the challenge and runs camcfg unlock on it. Port 80 sends these paths to HTTPS while camtls is
 * up (it runs with a throwaway CA in lock mode). */
#define UNLOCK_PATH "/unlock"
#define UNLOCK_CH_PATH "/unlock/challenge"
#define UNLOCK_FILE "unlock.bin"
#define UNLOCK_UP_MAX (60 * 1024)      /* the passphrase, the signature and a backup the web UI takes */
#define UNLOCK_S 600                   /* a challenge's life, s */
#define UNLOCK_MS 120000               /* camcfg unlock: Argon2id, erasing 1 MiB of NOR, writing it */

#define LOCKED_SAY "The camera is locked: its storage failed (see its lock page)."
static const char *data_failed_path = "/run/data-failed";   /* rcS's (#174); the host test: its own */

static int locked(void) { return !access(data_failed_path, F_OK); }

/* The page, a 503: the alert, the reason, the form (when the monitor gave a challenge), the
 * command line. */
static void page_locked(struct client *c)
{
	char why[256] = "", ch[400] = "", hex[65] = "", dev[40] = "", fw[40] = "", url[48];
	FILE *f = fopen(data_failed_path, "r");
	if (f) {
		if (!fgets(why, sizeof why, f)) *why = 0;
		fclose(f);
	}
	why[strcspn(why, "\r\n")] = 0;
	int have = !mon_call(MON_UNLOCK_CH, 0, 0, NULL, NULL) &&
		   sscanf(mon_rbuf, "challenge %64s device %39s firmware %39s", hex, dev, fw) == 3;
	if (!have) snprintf(ch, sizeof ch, "%s", mon_rbuf);
	self_url(c, url, sizeof url);
	sbn = 0;
	sbover = 0;
	S("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
	  "content=\"width=device-width,initial-scale=1\"><title>Locked - camera</title><link rel=\"stylesheet\" "
	  "href=\"/ui.css\"><script src=\"/ui.js\" defer></script></head><body><header><span>Camera</span></header>"
	  "<main><h1>&#9888; This camera is locked</h1><p class=\"msg err\">Its data partition (DATA) is corrupt");
	if (*why) { S(": "); E(why); }
	S(".</p><p>Its settings, accounts and keys can't be read, so it streams nothing and nobody can claim it "
	  "until it is recovered with one of the keys that sign its firmware (its update keys).</p>"
	  "<p class=\"note\">Recover it on the camera network only you use, or a direct cable. This page's "
	  "certificate is a throwaway one (the camera's CA was on DATA), so the browser warns and can't vouch "
	  "for the connection; someone on the path could read the passphrase you type here.</p>"
	  "<h2>Restore from this page</h2>");
	if (have) {
		S("<ol><li>Choose: restore a backup of this camera (.cambak), or erase DATA and claim it afresh.</li>"
		  "<li>Copy the message below into a file (msg.txt) and sign it with an update key: "
		  "<code>ssh-keygen -Y sign -n cam-recover -f KEY msg.txt</code></li>"
		  "<li>Paste msg.txt.sig below and press Unlock. The camera checks the signature and the whole "
		  "backup before it erases anything, then reboots.</li></ol>"
		  "<form data-unlock action=\"" UNLOCK_PATH "\" method=\"post\" data-challenge=\"");
		E(hex);
		S("\" data-device=\"");
		E(dev);
		S("\" data-firmware=\"");
		E(fw);
		S("\"><p><label><input type=\"radio\" name=\"action\" value=\"restore\" checked> Restore a backup</label> "
		  "<label><input type=\"radio\" name=\"action\" value=\"erase\"> Erase DATA (no backup: claim the camera "
		  "afresh after)</label></p><p><label>Backup file <input type=\"file\" name=\"file\" accept=\".cambak\">"
		  "</label></p><p><label>Its passphrase <input type=\"password\" name=\"pp\" autocomplete=\"off\"></label>"
		  "</p><p>Message to sign (it follows the action and the file):</p><pre class=\"msg\"></pre>"
		  "<p><label>Signature<br><textarea name=\"sig\" rows=\"8\" cols=\"72\" spellcheck=\"false\"></textarea>"
		  "</label></p><p><button>Unlock</button> <span class=\"live\"></span></p></form>"
		  "<p class=\"note\">The challenge lasts 10 minutes and one attempt: reload the page for a new one. "
		  "This page needs JavaScript and HTTPS (it hashes the file).</p>");
	} else {
		S("<p class=\"msg err\">No challenge: ");
		E(ch);
		S("</p>");
	}
	S("<h2>From the command line</h2><pre>python3 scripts/cam-recover.py ");
	E(c->local);
	S(" --backup FILE.cambak --key ~/.ssh/KEY\npython3 scripts/cam-recover.py ");
	E(c->local);
	S(" --erase --key ~/.ssh/KEY</pre><p>Or over SSH as root with an update key (the camera has a new host "
	  "key, so SSH warns):</p><pre>{ printf '%%s\\n' \"$PASS\"; cat FILE.cambak; } | ssh root@");
	E(c->local);
	S(" camcfg unlock restore -\nssh root@");
	E(c->local);
	S(" camcfg unlock erase</pre><p>then <code>reboot</code>.</p><h2>No backup?</h2><p>Erase DATA, then claim "
	  "the camera at <b>");
	E(url);
	S("/setup</b> as a new one and set it up again.</p></main></body></html>\n");
	html_send(c, 503);
}

/* POST UNLOCK_PATH: the page's script or cam-recover.py. Same origin, octet-stream, the action and
 * the challenge in X-Unlock-Action / X-Unlock-Challenge; the body staged, the monitor's verdict as
 * text. The body (passphrase and all) is wiped. */
static void unlock_post(struct client *c, const char *ip)
{
	char act[16], ch[80], ct[64], p[300], msg[MON_MSG / 4];
	const char *why = !same_origin(c) ? "not from this camera's page (Origin)" :
			  hdr(c->in, "Content-Type", ct, sizeof ct) != 1 || strcasecmp(ct, "application/octet-stream") ?
			  "the body must be application/octet-stream" :
			  hdr(c->in, "X-Unlock-Action", act, sizeof act) != 1 || (strcmp(act, "restore") && strcmp(act, "erase")) ?
			  "X-Unlock-Action: restore or erase" :
			  hdr(c->in, "X-Unlock-Challenge", ch, sizeof ch) != 1 || strlen(ch) != 64 ||
			  strspn(ch, "0123456789abcdef") != 64 ? "X-Unlock-Challenge: the page's 64 hex digits" :
			  !c->body_len || c->body_len > UNLOCK_UP_MAX ? "the body is empty or larger than 60 KiB" : NULL;
	char *body = c->in + c->hdr_len;
	if (why) {
		LOG("%s: POST " UNLOCK_PATH " refused: %s\n", ip, why);
		memset(body, 0, c->body_len);
		http_reply(c, 400, NULL, why);
		return;
	}
	upd_path(UNLOCK_FILE, p, sizeof p);
	unlink(p);
	int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	size_t put = 0;
	while (fd >= 0 && put < c->body_len) {
		ssize_t k = write(fd, body + put, c->body_len - put);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		put += (size_t)k;
	}
	memset(body, 0, c->body_len);
	if (fd < 0 || close(fd) || put < c->body_len) {
		unlink(p);
		http_reply(c, 500, NULL, "the camera couldn't stage the upload\n");
		return;
	}
	const char *f[3] = { ip, act, ch };
	int rc = mon_call(MON_UNLOCK, 0, 3, f, NULL);
	unlink(p);
	if (!rc) snprintf(msg, sizeof msg, "ok: %s\nThe camera reboots now.\n", mon_rbuf);
	else snprintf(msg, sizeof msg, "refused: %s\nReload the page for a new challenge.\n", mon_rbuf);
	memset(mon_rbuf, 0, mon_rlen);
	http_reply(c, rc ? (rc == MON_BLOCKED ? 429 : 403) : 200, NULL, msg);
}

/* Every request while DATA has failed. */
static void lock_mode(struct client *c, const char *path, int get, int post)
{
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	if (!strncasecmp(path, "/onvif/", 7)) {               /* an NVR shows this fault's text */
		if (post) soap_fault(c, F_LOCKED, NULL, 0);
		else http_reply(c, 405, "Allow: POST\r\n", "method not allowed\n");
		return;
	}
	ui_resp = 1;
	if (!strcmp(path, "/ui.css") || !strcmp(path, "/ui.js")) {
		int css = path[4] == 'c';
		if (!get) http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
		else if (http_head(c, 200, NULL, css ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8",
				   css ? sizeof ui_css - 1 : sizeof ui_js - 1) ||
			 out_add(c, css ? ui_css : ui_js, css ? sizeof ui_css - 1 : sizeof ui_js - 1)) {
			c->out_len = 0;
			http_reply(c, 500, NULL, NULL);
		}
	} else if (!strcmp(path, "/snapshot.jpg") || !strcmp(path, "/preview.mjpg")) {
		http_reply(c, 503, NULL, "the camera is locked: its storage failed\n");
	} else if (!host_is_us(c)) {
		page_by_address(c, "/");
	} else if (!strcmp(path, UNLOCK_CH_PATH)) {
		if (!get) http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
		else if (mon_call(MON_UNLOCK_CH, 0, 0, NULL, NULL)) http_reply(c, 503, NULL, mon_rbuf);
		else {
			size_t n = strlen(mon_rbuf);
			if (http_head(c, 200, "Cache-Control: no-store\r\n", "text/plain; charset=utf-8", n) ||
			    out_add(c, mon_rbuf, n)) {
				c->out_len = 0;
				http_reply(c, 500, NULL, NULL);
			}
		}
	} else if (!strcmp(path, UNLOCK_PATH)) {
		if (post) unlock_post(c, ip);
		else if (get) http_reply(c, 302, "Location: /\r\n", "the lock page is /\n");
		else http_reply(c, 405, "Allow: GET, POST\r\n", "method not allowed\n");
	} else if (get) {
		page_locked(c);
	} else {
		http_reply(c, 403, NULL, "the camera is locked: its storage failed\n");
	}
}

/* Every request while no admin exists. */
static void unclaimed(struct client *c, const char *path, int get, int post)
{
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	if (!strncasecmp(path, "/onvif/", 7)) {               /* an NVR shows this fault's text */
		if (post) soap_fault(c, F_UNCLAIMED, NULL, 0);
		else http_reply(c, 405, "Allow: POST\r\n", "method not allowed\n");
		return;
	}
	ui_resp = 1;
	if (!strcmp(path, "/snapshot.jpg") || !strcmp(path, "/preview.mjpg"))
		http_reply(c, 503, NULL, "the camera is not set up yet: claim it at /setup\n");
	else if (!claim_window()) page_unclaimed_closed(c);
	else if (!strcmp(path, "/ui.css") && get) {
		if (http_head(c, 200, NULL, "text/css; charset=utf-8", sizeof ui_css - 1) || out_add(c, ui_css, sizeof ui_css - 1)) {
			c->out_len = 0;
			http_reply(c, 500, NULL, NULL);
		}
	} else if (!strcmp(path, BK_SETUP_PATH)) {
		if (!host_is_us(c)) page_by_address(c, "/setup");
		else setup_restore(c, get, post, ip);
	} else if (strcmp(path, "/setup")) http_reply(c, 302, "Location: /setup\r\n", "not set up yet: /setup\n");
	else if (!host_is_us(c)) page_by_address(c, "/setup");
	else setup(c, get, post, ip);
}

/* GET shows a page, POST runs its form and shows it again with the outcome. Order for a POST:
 * credentials, role, Origin/Referer, body, token; every refusal after the credentials is 403 or
 * 4xx and logged where it could be an attack. */
static void ui(struct client *c, const char *path, const char *target, int get, int post)
{
	struct ui u;
	char ip[INET_ADDRSTRLEN], ct[128];
	memset(&u, 0, sizeof u);
	u.c = c;
	u.code = 200;
	u.page = -1;
	for (int i = 0; i < NPAGES; i++)
		if (!strcmp(path, pages[i].path)) u.page = i;
	if (u.page < 0) { http_reply(c, 404, NULL, "not found\n"); return; }
	if (!get && !(post && pages[u.page].post)) {
		http_reply(c, 405, pages[u.page].post ? "Allow: GET, POST\r\n" : "Allow: GET\r\n", "method not allowed\n");
		return;
	}
	int role = authenticate(c, get ? "GET" : "POST", target, NULL, NULL, u.user, sizeof u.user);
	if (role < 0) return;
	if (role < L_VIEWER) { challenge(c, 0, 0); return; }
	u.role = role;
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	if (role < pages[u.page].level) {
		LOG("%s: user %s may not %s %s\n", ip, u.user, get ? "open" : "post to", path);
		http_reply(c, 403, NULL, "forbidden\n");
		return;
	}
	if (post) {
		const char *why = NULL;
		if (!same_origin(c)) why = "no Origin or Referer of this host";
		else if (c->body_len > UI_BODY_MAX) { http_reply(c, 413, NULL, "form too large\n"); return; }
		else if (hdr(c->in, "Content-Type", ct, sizeof ct) != 1 ||
			 strncasecmp(ct, "application/x-www-form-urlencoded", 33) || (ct[33] && ct[33] != ';')) {
			http_reply(c, 415, NULL, "forms only\n");
			return;
		} else if (form_parse(c->in + c->hdr_len, c->body_len)) {
			memset(&form, 0, sizeof form);
			http_reply(c, 400, NULL, "malformed form\n");
			return;
		} else if (!csrf_ok(u.user, form_get("csrf"))) why = "missing, stale or foreign form token";
		if (why) {
			memset(&form, 0, sizeof form);
			LOG("%s: POST %s by %s refused: %s\n", ip, path, u.user, why);
			http_reply(c, 403, NULL, "forbidden: reload the page and try again\n");
			return;
		}
		if (pages[u.page].live) live_load();
		pages[u.page].post(&u);
		memset(&form, 0, sizeof form);                  /* it may have held a password */
	}
	if (!u.sent) ui_page(&u);
}

/* The web UI (/ui/..., /ui/firmware), /snapshot.jpg and /preview.mjpg answer only when Host is the
 * address the request came in on (host_is_us): a page of another site whose name was made to
 * resolve to the camera (DNS rebinding) gets 421 before any credential is looked at. /ui.css,
 * /ui.js and the redirects hold nothing and stay open, so the 421 page keeps its style. Not ONVIF:
 * NVRs' Host values vary, and onvif_from_browser covers what a browser could send there. */
static int by_name_refused(const struct client *c, const char *path)
{
	if (strcmp(path, "/snapshot.jpg") && strcmp(path, "/preview.mjpg") && strncmp(path, "/ui/", 4)) return 0;
	return !host_is_us(c);
}

/* An ONVIF POST another site's page could make the browser send (with the Digest login it keeps
 * for the camera: realm "camera", as the web UI's), refused before any credential is looked at:
 * an Origin that isn't http://<Host> (same_origin), or a Sec-Fetch-Site other than same-origin or
 * none, gets 403; a Content-Type other than application/soap+xml, text/xml or application/xml
 * (parameters allowed) gets 415, which also stops the form and text/plain POSTs a page may send
 * cross-site without a preflight. NVRs send neither header, and SOAP's type. 1 if refused. */
static int onvif_from_browser(struct client *c, const char *path)
{
	char v[256], ip[INET_ADDRSTRLEN], p[48];
	const char *why = NULL;
	int n;
	inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
	snprintf(p, sizeof p, "%s", path);
	log_clean(p);                                  /* client-supplied */
	if (hdr(c->in, "Origin", v, sizeof v) && !same_origin(c)) why = "an Origin of another site";
	else if ((n = hdr(c->in, "Sec-Fetch-Site", v, sizeof v)) > 1 ||
		 (n && strcasecmp(v, "same-origin") && strcasecmp(v, "none")))
		why = "a browser's Sec-Fetch-Site of another site";
	if (why) {
		LOG("%s: POST %s refused: %s\n", ip, p, why);
		http_reply(c, 403, NULL, "forbidden: a browser request from another site\n");
		return 1;
	}
	n = hdr(c->in, "Content-Type", v, sizeof v);
	size_t l = strcspn(v, ";");
	while (l && (v[l - 1] == ' ' || v[l - 1] == '\t')) l--;
	if (n == 1 && ((l == 20 && !strncasecmp(v, "application/soap+xml", 20)) || (l == 8 && !strncasecmp(v, "text/xml", 8)) ||
		       (l == 15 && !strncasecmp(v, "application/xml", 15))))
		return 0;
	v[l < 60 ? l : 60] = 0;
	LOG("%s: POST %s refused: Content-Type \"%s\"%s\n", ip, p, log_clean(v), n > 1 ? " (more than one)" : "");
	http_reply(c, 415, NULL, "ONVIF requests are SOAP: Content-Type application/soap+xml\n");
	return 1;
}

/* ---- HTTPS (docs/PLAN-TLS.md B): camtls in front, plain HTTP behind -------------------------
 * camtls terminates TLS on 443 and opens a connection to -t's UNIX socket for each client (only
 * its uid gets in: client_attach). Its first bytes are a PROXY v1 line naming the client and the
 * camera's address it reached; until that line is in the connection has no address (0.0.0.0, so
 * at most PER_PEER of them), has PROXY_MS to send it and can be evicted like one waiting for its
 * headers. Then the client's address counts for PER_PEER, BODY_PER_PEER, the lockout and the logs
 * as on port 80, and the connection is "tls": Origin/Referer https://<Host>, Host the address or
 * address:443, links https://, and every ONVIF address it is given https:// (base_url) and its
 * stream URIs rtsps://ADDRESS:322/ (op_streamuri). GetNetworkProtocols adds HTTPS 443 and the
 * WS-Discovery XAddrs add the https:// address while HTTPS is up (disco_target).
 * Port 80 while HTTPS is up (tls_up: the socket was made and camtls's ready file exists, one stat
 * per request for these paths): the pages (/, /ui, /ui/..., /setup, /recover, /preview.mjpg) are
 * a 302 to https:// for GET and HEAD and a 403 for POST, before any login and before the
 * unclaimed redirect; /ui.css, /ui.js, /onvif/ and /snapshot.jpg stay (SSS uses the last two)
 * until the owner sets net.plain=0 (plain_off): then those two get 403 there too.
 * The owner's fallback: without the ready file /setup and /recover keep working on port 80, and
 * the log says so at most once a minute. A PROXY line on port 80 is just a bad request. */

#define PROXY_MAX 56                   /* "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n" */
#define PROXY_MS 1000                  /* from connect to the end of the PROXY line */
#define TLS_SNDBUF (32 * 1024)         /* a UNIX socket's own buffer would hide the preview's
					  back-pressure (preview_tick waits for the last frame) */
#define TLS_NOTE_MS 60000              /* "TLS not running" at most this often */

static long long tls_noted = -TLS_NOTE_MS;

/* A dotted quad as inet_pton takes it, and no octet with a leading zero (inet_pton's own rule
 * differs between libcs). 0, or -1. */
static int proxy_addr(const char *s, struct in_addr *a)
{
	size_t n = strlen(s);
	if (n < 7 || n > 15 || strspn(s, "0123456789.") != n) return -1;
	for (size_t i = 0; i < n; i++)
		if (s[i] == '0' && (!i || s[i - 1] == '.') && i + 1 < n && s[i + 1] != '.') return -1;
	return inet_pton(AF_INET, s, a) == 1 ? 0 : -1;
}

/* A port 1..65535: decimal, no leading zero, no sign. -1 if not. */
static int proxy_port(const char *s)
{
	size_t n = strlen(s);
	if (n < 1 || n > 5 || strspn(s, "0123456789") != n || *s == '0') return -1;
	long v = atol(s);
	return v <= 65535 ? (int)v : -1;
}

/* camtls's PROXY v1 line at the start of p (n bytes): exactly "PROXY TCP4 SRC DST SPORT DPORT\r\n",
 * single spaces, at most PROXY_MAX bytes, no UNKNOWN or TCP6. Its length (the request follows it),
 * 0 while it may still come (no "\r\n" yet, under PROXY_MAX, a prefix of "PROXY TCP4 "), or -1. */
static int proxy_parse(const char *p, size_t n, struct in_addr *src, struct in_addr *dst, int *sport, int *dport)
{
	static const char pre[] = "PROXY TCP4 ";
	char line[PROXY_MAX + 1], *f[4], *s;
	size_t k = n < sizeof pre - 1 ? n : sizeof pre - 1;
	if (memcmp(p, pre, k)) return -1;
	const char *nl = memchr(p, '\n', n < PROXY_MAX ? n : PROXY_MAX);
	if (!nl) return n >= PROXY_MAX ? -1 : 0;
	size_t len = (size_t)(nl - p) + 1;
	if (len < sizeof pre + 1 || nl[-1] != '\r' || memchr(p, 0, len)) return -1;
	memcpy(line, p, len - 2);
	line[len - 2] = 0;
	s = line + sizeof pre - 1;
	for (int i = 0; i < 4; i++) {                      /* four fields, one space between */
		f[i] = s;
		s += strcspn(s, " ");
		if (i < 3 && *s != ' ') return -1;
		if (i < 3) *s++ = 0;
	}
	if (*s || proxy_addr(f[0], src) || proxy_addr(f[1], dst) || (*sport = proxy_port(f[2])) < 0 ||
	    (*dport = proxy_port(f[3])) < 0)
		return -1;
	return (int)len;
}

/* HTTPS is up: camtls's socket is ours and camtls has made its ready file. */
static int tls_up(void)
{
	struct stat st;
	return tfd >= 0 && !stat(tls_ready, &st);
}

/* The paths that move to HTTPS while it is up. */
static int tls_page(const char *path)
{
	return !strcmp(path, "/") || !strcmp(path, "/ui") || !strncmp(path, "/ui/", 4) || !strcmp(path, "/setup") ||
	       !strcmp(path, "/setup/restore") || !strcmp(path, "/recover") || !strcmp(path, "/preview.mjpg") ||
	       !strcmp(path, "/unlock") || !strcmp(path, "/unlock/challenge");
}

/* One of those on port 80 while HTTPS is up: GET and HEAD get a 302 to https://<the address it came
 * in on><target> (the target as sent; printable ASCII, else 400), a POST a 403 page with the https
 * link (its body crossed in clear already: it is never used). No login is asked for. */
static void tls_moved(struct client *c, int post, int head, const char *target, const char *path)
{
	char h[INET_ADDRSTRLEN + 300], ip[INET_ADDRSTRLEN], p[48];
	int was = ui_resp;
	ui_resp = 1;
	if (!post) {
		for (const char *q = target; *q; q++)
			if ((unsigned char)*q < 0x21 || (unsigned char)*q > 0x7e) {
				http_reply(c, 400, NULL, "bad request\n");
				ui_resp = was;
				return;
			}
		snprintf(h, sizeof h, "Location: https://%s%s\r\n", c->local, target);
		http_reply(c, 302, h, head ? NULL : "the camera's pages are served over HTTPS\n");
	} else {
		inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
		snprintf(p, sizeof p, "%s", path);
		LOG("%s: POST %s over plain HTTP refused: HTTPS is up\n", ip, log_clean(p));
		bare_page("Use HTTPS");
		S("<p>This camera's pages are served over HTTPS; nothing sent here was used: <a href=\"https://");
		E(c->local);
		E(path);
		S("\">https://");
		E(c->local);
		E(path);
		S("</a></p>");
		bare_end(c, 403);
	}
	ui_resp = was;
}

/* -t without camtls's ready file: /setup and /recover still work on port 80 (the owner's
 * fallback), and the log says so at most once a minute. */
static void tls_plain_note(const char *path)
{
	long long now = mono_ms();
	if (now - tls_noted < TLS_NOTE_MS) return;
	tls_noted = now;
	LOG("TLS not running: %s over plain HTTP\n", path);
}

/* Port 80's ONVIF or /snapshot.jpg while net.plain is 0 and HTTPS is up: 403 (a SOAP fault for
 * /onvif/), before any login; logged at most once a minute. */
static long long plain_noted = -TLS_NOTE_MS;
static void plain_refused(struct client *c, const char *path)
{
	char ip[INET_ADDRSTRLEN], p[48];
	long long now = mono_ms();
	if (now - plain_noted >= TLS_NOTE_MS) {
		plain_noted = now;
		inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
		snprintf(p, sizeof p, "%s", path);
		LOG("%s: %s on port 80 refused: net.plain=0 (this line at most once a minute)\n", ip, log_clean(p));
	}
	if (path[1] == 'o' || path[1] == 'O') soap_fault(c, F_PLAIN, NULL, 403);
	else http_reply(c, 403, NULL, "plain HTTP is off on this camera (net.plain=0): use https://\n");
}

static void client_close(struct client *c);

/* A connection from camtls, before its request: the PROXY line. Once it is in, the client's address
 * is the peer (PER_PEER applies to it again: over it, closed) and the camera's the local address;
 * what came after the line stays in c->in as the start of the request. 0 when taken, 1 while more
 * is needed, -1 if the connection was closed (logged). */
static int proxy_take(struct client *c)
{
	struct in_addr src, dst;
	char ip[INET_ADDRSTRLEN];
	int sport, dport, mine = 0, n = proxy_parse(c->in, c->in_len, &src, &dst, &sport, &dport);
	if (!n) return 1;
	if (n < 0) {
		LOG("camtls: not a PROXY TCP4 line (%zu bytes): closed\n", c->in_len);
		client_close(c);
		return -1;
	}
	inet_ntop(AF_INET, &src, ip, sizeof ip);
	for (int i = 0; i < MAX_CLIENTS; i++)
		mine += &clients[i] != c && clients[i].fd >= 0 && clients[i].peer.s_addr == src.s_addr;
	if (mine >= PER_PEER) {
		LOG("%s: over %d connections from this address (HTTPS): closed\n", ip, PER_PEER);
		client_close(c);
		return -1;
	}
	c->peer = src;
	inet_ntop(AF_INET, &dst, c->local, sizeof c->local);
	c->tls = 1;
	c->proxy = 0;
	c->in_len -= (size_t)n;
	memmove(c->in, c->in + n, c->in_len);
	c->in[c->in_len] = 0;
	if (verbose) LOG("%s:%d: HTTPS to %s:%d\n", ip, sport, c->local, dport);
	return 0;
}

static void http_request(struct client *c)
{
	char target[256], path[256];
	size_t ml = strcspn(c->in, " \r\n"), tl;
	const char *t = c->in + ml + 1;
	req_grant = 0;                                     /* only this request's login may grant */
	if (ml == 0 || ml > 7 || c->in[ml] != ' ' || *t != '/' || (tl = strcspn(t, " \r\n")) >= sizeof target ||
	    t[tl] != ' ' || (strncmp(t + tl + 1, "HTTP/1.1\r\n", 10) && strncmp(t + tl + 1, "HTTP/1.0\r\n", 10))) {
		http_reply(c, 400, NULL, "bad request\n");
		return;
	}
	memcpy(target, t, tl);
	target[tl] = 0;
	snprintf(path, sizeof path, "%.*s", (int)strcspn(target, "?"), target);
	int get = ml == 3 && !memcmp(c->in, "GET", 3), post = ml == 4 && !memcmp(c->in, "POST", 4),
	    head = ml == 4 && !memcmp(c->in, "HEAD", 4);
	if (!c->tls && tls_page(path)) {                   /* port 80: HTTPS first, if it is up */
		int up = tls_up();
		if (up && (get || head || post)) {
			tls_moved(c, post, head, target, path);
			return;
		}
		if (!up && tls_spec && (!strcmp(path, "/setup") || !strcmp(path, "/recover") || !strcmp(path, BK_SETUP_PATH)))
			tls_plain_note(path);
	}
	if (!c->tls && (!strncasecmp(path, "/onvif/", 7) || !strcmp(path, "/snapshot.jpg")) && plain_off()) {
		plain_refused(c, path);                        /* net.plain=0: SSS has moved to HTTPS */
		return;
	}
	if (locked()) {                                    /* DATA failed: the lock page only (#175) */
		lock_mode(c, path, get, post);
	} else if (!claimed()) {                           /* no admin yet: setup only (#128) */
		unclaimed(c, path, get, post);
	} else if (!strcmp(path, "/recover")) {            /* admin recovery code (#128) */
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
		ui_resp = 1;
		if (!claim_window()) {
			bare_page("Recovery is closed");
			S("<p>Admin recovery is open only for the first 30 minutes after the camera powers on. "
			  "Power-cycle the camera and open this page again within 30 minutes.</p>");
			bare_end(c, 403);
		} else if (!host_is_us(c)) page_by_address(c, "/recover");
		else recover(c, get, post, ip);
	} else if (by_name_refused(c, path)) {           /* DNS rebinding: see host_is_us */
		ui_resp = 1;
		page_by_address(c, path);
	} else if (!strcmp(path, "/snapshot.jpg")) {
		if (get) snapshot(c, target);
		else http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
	} else if (!strncasecmp(path, "/onvif/", 7)) {
		if (!post) http_reply(c, 405, "Allow: POST\r\n", "method not allowed\n");
		else if (!onvif_from_browser(c, path))
			soap(c, strcasestr(path, "media") ? SVC_MEDIA : strcasestr(path, "imaging") ? SVC_IMAGING :
			     strcasestr(path, "event") ? SVC_EVENTS : strcasestr(path, "analytics") ? SVC_ANALYTICS :
			     strcasestr(path, "deviceio") ? SVC_DEVICEIO : SVC_DEVICE, target);
	} else if (!strcmp(path, "/") || !strcmp(path, "/ui")) {
		ui_resp = 1;
		if (get) http_reply(c, 302, "Location: /ui/\r\n", "the camera's pages are at /ui/\n");
		else http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
	} else if (!strcmp(path, "/ui.css")) {             /* no secrets: served without a login */
		ui_resp = 1;
		if (!get) http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
		else if (http_head(c, 200, NULL, "text/css; charset=utf-8", sizeof ui_css - 1) ||
			 out_add(c, ui_css, sizeof ui_css - 1)) {
			c->out_len = 0;
			http_reply(c, 500, NULL, NULL);
		}
	} else if (!strcmp(path, "/ui.js")) {              /* no secrets: served without a login */
		ui_resp = 1;
		if (!get) http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
		else if (http_head(c, 200, NULL, "text/javascript; charset=utf-8", sizeof ui_js - 1) ||
			 out_add(c, ui_js, sizeof ui_js - 1)) {
			c->out_len = 0;
			http_reply(c, 500, NULL, NULL);
		}
	} else if (!strcmp(path, "/preview.mjpg")) {
		ui_resp = 1;
		if (get) preview_start(c, target);
		else http_reply(c, 405, "Allow: GET\r\n", "method not allowed\n");
	} else if (!strcmp(path, UPD_PATH)) {             /* its POST is upd_route's, at the headers */
		ui_resp = 1;
		upd_status(c, target, get);
	} else if (!strcmp(path, CA_PATH)) {
		ui_resp = 1;
		ca_download(c, target, get);
	} else if (!strcmp(path, BK_PATH)) {               /* a multipart form: not ui()'s */
		ui_resp = 1;
		bk_restore(c, target, get, post);
	} else if (!strncmp(path, "/ui/", 4)) {
		ui_resp = 1;
		ui(c, path, target, get, post);
	} else {
		http_reply(c, 404, NULL, "not found\n");
	}
	ui_resp = 0;                       /* a held pull answered later is no UI reply */
}

/* Other connections from c's address in their body (headers in, body not yet: unauthenticated). */
static int bodies_from(const struct client *c)
{
	int n = 0;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		const struct client *o = &clients[i];
		n += o != c && o->fd >= 0 && !o->state && o->hdr_len && o->peer.s_addr == c->peer.s_addr;
	}
	return n;
}

/* Frame the request in c->in; once complete, answer it (c->state = 1). */
static void http_feed(struct client *c)
{
	if (c->state) return;
	c->in[c->in_len] = 0;
	if (c->proxy && proxy_take(c)) return;             /* camtls's PROXY line first */
	if (!c->hdr_len) {
		size_t from = c->scanned > 3 ? c->scanned - 3 : 0, upto = c->in_len < HDR_CAP ? c->in_len : HDR_CAP;
		char *e = upto > from ? memmem(c->in + from, upto - from, "\r\n\r\n", 4) : NULL, cl[24], v[64];
		SCAN_COUNT(upto > from ? upto - from : 0);
		c->scanned = upto;
		if (!e) {
			if (c->in_len >= HDR_CAP) http_reply(c, 431, NULL, "request headers too large\n");
			return;
		}
		c->hdr_len = (size_t)(e - c->in) + 4;
		e[2] = 0;                                  /* headers: a string ending "\r\n" */
		if (memchr(c->in, 0, c->hdr_len - 2)) { http_reply(c, 400, NULL, "bad request\n"); return; }
		int ncl = hdr(c->in, "Content-Length", cl, sizeof cl);
		size_t n = strlen(cl);
		if (hdr(c->in, "Transfer-Encoding", v, sizeof v)) { http_reply(c, 501, NULL, "no chunked bodies\n"); return; }
		if (ncl > 1 || (ncl && (!n || n > 7 || strspn(cl, "0123456789") != n))) {
			http_reply(c, 400, NULL, "bad Content-Length\n");
			return;
		}
		c->body_len = ncl ? (size_t)atol(cl) : 0;
		if (upd_route(c, ncl)) return;             /* a firmware upload: streamed, not buffered */
		if (c->hdr_len + c->body_len > REQ_CAP) { http_reply(c, 413, NULL, "request too large\n"); return; }
		if (c->in_len < c->hdr_len + c->body_len && bodies_from(c) >= BODY_PER_PEER) {
			http_reply(c, 429, "Retry-After: 2\r\n", "too many unfinished requests from this address\n");
			return;
		}
		if (hdr(c->in, "Expect", v, sizeof v) && !strcasecmp(v, "100-continue") &&
		    c->in_len < c->hdr_len + c->body_len)
			out_add(c, "HTTP/1.1 100 Continue\r\n\r\n", 25);
	}
	if (c->in_len < c->hdr_len + c->body_len) return;
	c->in[c->hdr_len + c->body_len] = 0;              /* ignore anything pipelined after it */
	http_request(c);
	if (!c->state) c->state = 1;
}

/* ---- WS-Discovery (2005/04, as ONVIF Core 7.3) --------------------------------------- */

#define WSD_PORT 3702
#define WSD_GROUP "239.255.255.250"
#define NS_DN "http://www.onvif.org/ver10/network/wsdl"
#define NS_TDS "http://www.onvif.org/ver10/device/wsdl"

#define WSD_MIN 200                    /* shorter than any real Probe: nothing to amplify */
#define WSD_PER_SRC 2                  /* replies a second to one address */
#define WSD_ALL 20                     /* replies a second in all */

static int dfd = -1, disco_joined;
static struct in_addr disco_ip, disco_mask;
static unsigned long instance, msgno;

static void disco_head(const char *action, const char *relates, const char *to)
{
	uint8_t r[16];
	char id[37];
	if (random_bytes(r, sizeof r)) {
		struct timespec t;
		clock_gettime(CLOCK_MONOTONIC, &t);
		memcpy(r, &t, sizeof t < sizeof r ? sizeof t : sizeof r);
	}
	uuid_str(r, 4, id);
	id[36] = 0;
	sbn = 0;
	sbover = 0;
	S("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope "
	  "xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" "
	  "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
	  "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"" NS_DN "\" "
	  "xmlns:tds=\"" NS_TDS "\"><env:Header><wsa:MessageID>urn:uuid:%s</wsa:MessageID>", id);
	if (relates) S("<wsa:RelatesTo>%s</wsa:RelatesTo>", relates);
	S("<wsa:To>%s</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/%s"
	  "</wsa:Action><d:AppSequence InstanceId=\"%lu\" MessageNumber=\"%lu\"/></env:Header>"
	  "<env:Body>", to, action, instance, ++msgno);
}

/* XAddrs: http://ADDRESS/onvif/device_service, then (space-separated, as WS-Discovery allows) the
 * https:// one while HTTPS is up; https:// alone once net.plain is 0 (port 80 refuses ONVIF then). */
static void disco_target(const char *ip)
{
	char port[8] = "";
	int up = tls_up(), plain = !up || plain_on();
	if (http_port != 80) snprintf(port, sizeof port, ":%d", http_port);
	S("<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>"
	  "<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types><d:Scopes>", epr);
	for (int i = 0; i < NSCOPES; i++) S("%s%s", i ? " " : "", scopes[i]);
	S("</d:Scopes><d:XAddrs>");
	if (plain) S("http://%s%s/onvif/device_service", ip, port);
	if (up) S("%shttps://%s/onvif/device_service", plain ? " " : "", ip);
	S("</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion>");
}

/* Is prefix (pl bytes; 0 = default namespace) bound to uri anywhere in the message? */
static int ns_is(const char *msg, const char *prefix, size_t pl, const char *uri)
{
	char pat[160];
	for (int q = 0; q < 2; q++) {
		snprintf(pat, sizeof pat, "xmlns%s%.*s=%c%s%c", pl ? ":" : "", (int)pl, prefix,
			 q ? '\'' : '"', uri, q ? '\'' : '"');
		if (strstr(msg, pat)) return 1;
	}
	return 0;
}

/* The ProbeMatches for a Probe (msg, n bytes) that matches us, in sb; its length, 0 = no reply. */
static size_t disco_probe(const char *msg, size_t n, const char *ip)
{
	static char buf[8193];
	char id[160], types[512] = "", sc[1024] = "", by[128] = "", *save;
	const char *ptag, *stag;
	if (n < WSD_MIN || n >= sizeof buf) return 0;
	memcpy(buf, msg, n);
	buf[n] = 0;
	const char *end = buf + n, *pr = xel(buf, end, "Probe", &ptag);
	if (!pr || xtext(buf, ptag, "MessageID", id, sizeof id) || !*id ||
	    strspn(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:-._/") != strlen(id))
		return 0;                                  /* echoed back: keep it plain */
	const char *pe = xclose(pr, end, "Probe");
	if (xel(pr, pe, "Types", NULL) && xtext(pr, pe, "Types", types, sizeof types)) return 0;
	int nt = 0;
	for (char *t = strtok_r(types, " \t\r\n", &save); t; t = strtok_r(NULL, " \t\r\n", &save)) {
		char *colon = strchr(t, ':');
		if (++nt > 4) return 0;                    /* we have two types */
		const char *local = colon ? colon + 1 : t;
		size_t pl = colon ? (size_t)(colon - t) : 0;
		if (!(!strcmp(local, "NetworkVideoTransmitter") && ns_is(buf, t, pl, NS_DN)) &&
		    !(!strcmp(local, "Device") && ns_is(buf, t, pl, NS_TDS)))
			return 0;
	}
	if (xel(pr, pe, "Scopes", &stag)) {
		if (xtext(pr, pe, "Scopes", sc, sizeof sc)) return 0;
		xattr(stag, pe, "MatchBy", by, sizeof by);
		int exact = strstr(by, "strcmp0") != NULL;
		if (*by && !exact && !strstr(by, "rfc3986")) return 0;
		int ns = 0;
		for (char *s = strtok_r(sc, " \t\r\n", &save); s; s = strtok_r(NULL, " \t\r\n", &save)) {
			size_t k = strlen(s);
			int ok = 0;
			if (++ns > 2 * NSCOPES) return 0;
			for (int i = 0; i < NSCOPES && !ok; i++)
				ok = exact ? !strcmp(scopes[i], s) : !strncmp(scopes[i], s, k) &&
				     (!scopes[i][k] || scopes[i][k] == '/' || s[k - 1] == '/');
			if (!ok) return 0;
		}
	}
	if (!*epr) epr_make();
	disco_head("ProbeMatches", id, "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
	S("<d:ProbeMatches><d:ProbeMatch>");
	disco_target(ip);
	S("</d:ProbeMatch></d:ProbeMatches></env:Body></env:Envelope>");
	return sbover ? 0 : sbn;
}

static void disco_announce(const char *kind)
{
	struct sockaddr_in to;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &disco_ip, ip, sizeof ip);
	disco_head(kind, NULL, "urn:schemas-xmlsoap-org:ws:2005:04:discovery");
	S("<d:%s>", kind);
	if (!strcmp(kind, "Hello")) disco_target(ip);
	else S("<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>", epr);
	S("</d:%s></env:Body></env:Envelope>", kind);
	memset(&to, 0, sizeof to);
	to.sin_family = AF_INET;
	to.sin_port = htons(WSD_PORT);
	inet_pton(AF_INET, WSD_GROUP, &to.sin_addr);
	if (!sbover && sendto(dfd, sb, sbn, 0, (struct sockaddr *)&to, sizeof to) < 0)
		LOG("discovery %s: %s\n", kind, strerror(errno));
}

static int disco_open(void)
{
	struct sockaddr_in a;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
	unsigned char ttl = 1, loop = 0;
	if (fd < 0) return -1;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons(WSD_PORT);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);
	if (bind(fd, (struct sockaddr *)&a, sizeof a)) {
		LOG("discovery: bind udp %d: %s\n", WSD_PORT, strerror(errno));
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	return fd;
}

/* Join the group on the interface's current IPv4 address (DHCP may come later or change it). */
static void disco_tick(void)
{
	uint8_t mac[6];
	struct in_addr ip, mask;
	struct ip_mreq m;
	int mtu;
	if (if_info(mac, &ip, &mask, &mtu) || !ip.s_addr) return;
	if (disco_joined && ip.s_addr == disco_ip.s_addr) return;
	inet_pton(AF_INET, WSD_GROUP, &m.imr_multiaddr);
	if (disco_joined) {
		m.imr_interface = disco_ip;
		setsockopt(dfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &m, sizeof m);
		disco_joined = 0;
	}
	m.imr_interface = ip;
	if (setsockopt(dfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m)) return;
	setsockopt(dfd, IPPROTO_IP, IP_MULTICAST_IF, &ip, sizeof ip);
	epr_make();
	disco_ip = ip;
	disco_mask = mask;
	disco_joined = 1;
	LOG("discovery: on %s, %s\n", ifname, epr);
	disco_announce("Hello");
}

/* May a datagram from `from` be parsed and answered? Only from eth0's subnet (a reply goes back
 * to the source address, which UDP doesn't verify), WSD_PER_SRC a second per address and WSD_ALL
 * in all; checked before any parsing. A netmask of 0 or shorter than /8 would make "the subnet"
 * most of the Internet: then nothing is answered (logged once). */
static int disco_allow(struct in_addr from, time_t now)
{
	static struct { struct in_addr ip; time_t t; int n; } rl[8];
	static time_t all_t;
	static int all_n, wide_logged;
	int slot = -1;
	if (disco_joined && (ntohl(disco_mask.s_addr) & 0xff000000u) != 0xff000000u) {
		if (!wide_logged) {
			char m[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &disco_mask, m, sizeof m);
			LOG("discovery: %s's netmask %s is wider than /8: Probes are not answered\n", ifname, m);
			wide_logged = 1;
		}
		return 0;
	}
	if (!disco_joined || !from.s_addr || ((from.s_addr ^ disco_ip.s_addr) & disco_mask.s_addr))
		return 0;
	if (now != all_t) { all_t = now; all_n = 0; }
	if (all_n >= WSD_ALL) return 0;
	for (int i = 0; i < 8; i++) {
		if (rl[i].t == now && rl[i].ip.s_addr == from.s_addr) {
			if (rl[i].n >= WSD_PER_SRC) return 0;
			slot = i;
			break;
		}
		if (rl[i].t != now && slot < 0) slot = i;
	}
	if (slot < 0) return 0;                        /* 8 sources this second already */
	if (rl[slot].t != now || rl[slot].ip.s_addr != from.s_addr) {
		rl[slot].ip = from;
		rl[slot].t = now;
		rl[slot].n = 0;
	}
	rl[slot].n++;
	all_n++;
	return 1;
}

static void disco_read(void)
{
	static char buf[8192];
	struct sockaddr_in from;
	socklen_t fl = sizeof from;
	char ip[INET_ADDRSTRLEN];
	ssize_t n = recvfrom(dfd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
	if (n < WSD_MIN || !from.sin_port || !disco_allow(from.sin_addr, mono())) return;
	inet_ntop(AF_INET, &disco_ip, ip, sizeof ip);
	size_t len = disco_probe(buf, (size_t)n, ip);
	if (len) sendto(dfd, sb, len, 0, (struct sockaddr *)&from, fl);
}

/* ---- privilege separation (Gate 3, docs/CAMHTTPD-PRIVSEP.md) ------------------------------------
 * With -Z, main forks once everything root-only is open: the parent stays root as the monitor and
 * the child, the worker, leaves root for -Z's user (supplementary group camctl: rtspd's control
 * socket and /run/cam) and runs the loop: HTTP, SOAP, the web UI, WS-Discovery. The monitor reads
 * the users file, holds the Digest nonce key and the UsernameToken replay state and floor, keeps the
 * lockout, and does everything that needs root; the worker never holds a password, an HA1, a
 * recovery hash or the nonce key. Without -Z both halves are this one process (in-process mode,
 * mon_fd < 0: mon_call serialises the request and calls mon_dispatch directly), which is also how
 * the host test runs every request through the same checks.
 *
 * Messages (SOCK_SEQPACKET; a datagram socket pair on hosts without it, the host test), one per
 * request and one per reply, at most MON_MSG bytes:
 *   request  u32 op, u64 grant, u32 len, then the op's fields, each ending in NUL
 *   reply    i32 status, u32 len, then text; conf, upd-check and upd-install pass an fd too
 * A message that isn't exactly that (short, a length that doesn't match, a field count other than
 * the op's, an unterminated field, anything ancillary) is malformed: the monitor kills the worker
 * and exits, and init's respawn of camhttpd-run starts both again. Everything else it doesn't take
 * is refused with a status (MON_DENIED, or 1 where camcfg would have said no) and changes nothing:
 * an unknown op; a grant missing, unknown, expired, used up or too low for the op; a field too
 * long or holding a newline (or, for the argv fields, anything but printable ASCII).
 *
 * A grant is a random 64-bit id the monitor issues with every successful login (mon_auth), bound
 * to that user, role and address: valid for GRANT_S seconds and GRANT_OPS privileged operations
 * (the Image form saves 35 keys). A worker can thus act only while a real user of that role is
 * sending requests, and only within that role. The one exception is the firmware upload: its body
 * may take up to UPD_GRANT_S, so upd-begin pins its grant for that upload's one upd-check.
 *
 *   op           fields                     role      the monitor
 *   auth         peer method target         -         Digest and UsernameToken (mon_auth); the
 *                authorization usernametoken          role, user and grant, or a refusal and a nonce
 *   set          key value                  operator  camcfg -d DIR set KEY VALUE; time.* admin
 *   user         act name role password     admin     camcfg -d DIR user ACT NAME [ROLE], stdin
 *   sshkey       act arg                    admin     camcfg -d DIR sshkey list|add (stdin)|del N
 *   settime      seconds microseconds       admin     settimeofday, then the replay floor
 *   reboot                                  admin     the floor saved, sync, reboot
 *   upd-begin                               admin     pins the grant for the upload's check
 *   upd-check                               admin     camupdate --check - (the upload as stdin): a socket
 *   upd-install                             admin     camupdate -, detached: a pipe for its end
 *   claim        peer name password key     -         unclaimed, the window, a rate: camcfg claim
 *   recover      peer name code password    -         lockout, the window, a rate: camcfg recover
 *   conf                                    -         cam.conf, open for reading (an fd)
 *   users                                   -         "ROLE NAME" lines: no password
 *   bk-export    passphrase                 admin     camcfg backup export: the .cambak as an fd
 *   bk-restore   peer password passphrase   admin     the grant's admin password again, the lockout:
 *                                                     camcfg backup import of the staged upload
 *   bk-setup     peer passphrase            -         lockout, unclaimed, the window, a rate: the same
 *   (a restore that worked reboots the camera BK_REBOOT_MS later, from the monitor's tick)
 * Passwords and codes cross only in user, claim and recover requests, never in a reply; both sides
 * wipe them once used. camcfg stays the authority on content: the monitor checks only shape. */

#define MON_HDR 16                     /* u32 op, u64 grant, u32 len */
#define MON_RHDR 8                     /* i32 status, u32 len */
#define MON_NF 5                       /* fields in a request, at most */
#define GRANT_S 30
#define GRANT_OPS 48
#define GRANT_N 64                     /* grants kept; a full table drops the oldest */
#define UPD_GRANT_S (10 + UPD_MAX / BODY_RATE)   /* the longest an upload's body may take (upd_route) */
#define CAMCFG_OUT 8192                /* camcfg's output a reply carries (sshkey list) */

enum { C_PRINT, C_TEXT, C_HDR, C_XML };  /* printable ASCII; no newline; no CR or LF; anything */
static const struct mon_op {
	const char *name;
	int nf, role;                      /* fields; the role its grant needs (L_PRE: it takes none) */
	unsigned char cls[MON_NF];
	unsigned short max[MON_NF];        /* each field's longest */
	const char *fn[MON_NF];            /* and its name, for a refusal (camcfg's words where it has them) */
} mon_ops[MON_NOPS] = {
	[MON_AUTH] = { "auth", 5, L_PRE, { C_PRINT, C_PRINT, C_HDR, C_HDR, C_XML }, { 15, 7, 255, 1023, MON_MSG },
		       { "address", "method", "target", "Authorization", "UsernameToken" } },
	[MON_SET] = { "set", 2, L_OPERATOR, { C_PRINT, C_PRINT }, { 40, 280 }, { "key", "value" } },
	[MON_USER] = { "user", 4, L_ADMIN, { C_PRINT, C_TEXT, C_PRINT, C_TEXT }, { 8, UI_BODY_MAX, 64, UI_BODY_MAX },
		       { "action", "name", "role", "password" } },
	[MON_SSHKEY] = { "sshkey", 2, L_ADMIN, { C_PRINT, C_TEXT }, { 8, UI_BODY_MAX }, { "action", "key line" } },
	[MON_SETTIME] = { "settime", 2, L_ADMIN, { C_PRINT, C_PRINT }, { 12, 6 }, { "seconds", "microseconds" } },
	[MON_REBOOT] = { "reboot", 0, L_ADMIN, { 0 }, { 0 }, { 0 } },
	[MON_UPD_BEGIN] = { "upd-begin", 0, L_ADMIN, { 0 }, { 0 }, { 0 } },
	[MON_UPD_CHECK] = { "upd-check", 0, L_ADMIN, { 0 }, { 0 }, { 0 } },
	[MON_UPD_INSTALL] = { "upd-install", 0, L_ADMIN, { 0 }, { 0 }, { 0 } },
	[MON_CLAIM] = { "claim", 4, L_PRE, { C_PRINT, C_TEXT, C_TEXT, C_TEXT }, { 15, UI_BODY_MAX, UI_BODY_MAX, UI_BODY_MAX },
			{ "address", "name", "password", "key line" } },
	[MON_RECOVER] = { "recover", 4, L_PRE, { C_PRINT, C_TEXT, C_TEXT, C_TEXT }, { 15, UI_BODY_MAX, UI_BODY_MAX, UI_BODY_MAX },
			  { "address", "name", "code", "password" } },
	[MON_CONF] = { "conf", 0, L_PRE, { 0 }, { 0 }, { 0 } },
	[MON_USERS] = { "users", 0, L_PRE, { 0 }, { 0 }, { 0 } },
	[MON_BK_EXPORT] = { "bk-export", 1, L_ADMIN, { C_TEXT }, { PP_CAP }, { "passphrase" } },
	[MON_BK_RESTORE] = { "bk-restore", 3, L_ADMIN, { C_PRINT, C_TEXT, C_TEXT }, { 15, UI_BODY_MAX, PP_CAP },
			     { "address", "password", "passphrase" } },
	[MON_BK_SETUP] = { "bk-setup", 2, L_PRE, { C_PRINT, C_TEXT }, { 15, PP_CAP }, { "address", "passphrase" } },
	[MON_UNLOCK_CH] = { "unlock-ch", 0, L_PRE, { 0 }, { 0 }, { 0 } },
	[MON_UNLOCK] = { "unlock", 3, L_PRE, { C_PRINT, C_PRINT, C_PRINT }, { 15, 7, 64 },
			 { "address", "action", "challenge" } },
};

static int mon_fd = -1;                /* the worker's end of the socket pair; -1: in-process */
static int w_drop;                     /* -Z: the worker's ids, for the install log it reads */
static uid_t w_uid;
static gid_t w_gid;

static struct grant { uint64_t id; time_t t; int role, uses, pin; struct in_addr peer; char user[33]; } grants[GRANT_N];

/* A new grant for a login (mono seconds; MONO_ADJ_MS moves them in the host test): a free or
 * expired slot, else the oldest that isn't pinned. 0 if /dev/urandom fails. */
static uint64_t grant_issue(int role, const char *user, struct in_addr peer)
{
	time_t now = mono();
	int slot = -1;
	for (int i = 0; i < GRANT_N; i++) {
		struct grant *g = &grants[i];
		if (!g->id || now - g->t > (g->pin ? UPD_GRANT_S : GRANT_S)) { slot = i; break; }
		if (!g->pin && (slot < 0 || g->t < grants[slot].t)) slot = i;
	}
	struct grant *g = &grants[slot < 0 ? 0 : slot];
	memset(g, 0, sizeof *g);
	while (!g->id)
		if (random_bytes(&g->id, sizeof g->id)) { g->id = 0; return 0; }
	g->t = now;
	g->role = role;
	g->peer = peer;
	snprintf(g->user, sizeof g->user, "%s", user);
	return g->id;
}

/* The grant `id` if it may do an operation needing `need` now (check: the upload's pinned one, for
 * upd-check), else NULL with *why. Nothing changes here: mon_run spends it once the op is taken. */
static struct grant *grant_find(uint64_t id, int need, int check, const char **why)
{
	struct grant *g = NULL;
	for (int i = 0; id && i < GRANT_N; i++)
		if (grants[i].id == id) g = &grants[i];
	time_t age = g ? mono() - g->t : 0;
	if (!id) *why = "no grant";
	else if (!g) *why = "an unknown grant (forged, or dropped)";
	else if (age < 0 || age > (check ? UPD_GRANT_S : GRANT_S)) *why = "an expired grant";
	else if (check && !g->pin) *why = "not the upload's grant";
	else if (g->uses >= GRANT_OPS) *why = "a used-up grant";
	else if (g->role < need) *why = "a grant of a lower role";
	else return g;
	return NULL;
}

/* A reply's text: printf-style into t (cap bytes); the status is passed through. */
static int say(char *t, size_t cap, size_t *tn, int st, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(t, cap, fmt, ap);
	va_end(ap);
	*tn = n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
	return st;
}

/* NULL if field s fits its class and length, else why not ("must be one line", as camcfg says). */
static const char *field_why(const char *s, int cls, size_t max)
{
	if (strlen(s) > max) return "is too long";
	for (; *s; s++) {
		unsigned char ch = (unsigned char)*s;
		if ((cls == C_TEXT || cls == C_HDR) && (ch == '\n' || (cls == C_HDR && ch == '\r'))) return "must be one line";
		if (cls == C_PRINT && (ch < 0x20 || ch > 0x7e)) return "must be printable ASCII";
	}
	return NULL;
}

/* What camhttpd may set: the keys its pages and ONVIF save. camcfg checks every value. */
static int key_ok(const char *k)
{
	static const char *const pfx[] = { "image.", "stream.main.", "stream.sub.", "daynight.", "motion.", "audio.",
					   "osd." };
	size_t n = strlen(k);
	if (!n || n > 40 || strspn(k, "abcdefghijklmnopqrstuvwxyz0123456789._") != n) return 0;
	if (!strcmp(k, "time.ntp") || !strcmp(k, "time.tz")) return 1;
	for (size_t i = 0; i < sizeof pfx / sizeof pfx[0]; i++)
		if (!strncmp(k, pfx[i], strlen(pfx[i])) && k[strlen(pfx[i])]) return 1;
	return 0;
}

/* camcfg ARGS with stdin `in` (wiped here): its exit status, its output as the reply's text. */
static int mon_camcfg(const char *dirpath, const char *const *args, char *in, char *t, size_t *tn)
{
	char dir[256];
	dir_of(dirpath, dir, sizeof dir);
	int rc = CAMCFG_EXEC(dir, args, in, t, CAMCFG_OUT);
	if (in) memset(in, 0, strlen(in));
	*tn = strlen(t);
	return rc;
}

/* auth: the credentials as authenticate used to check them. The reply's text: the grant (hex, "0"
 * if none), a nonce for the challenge (when refused or none given), stale (0/1), whether the
 * address is locked out now (0/1), and the user named; NUL-separated. Status: the role (0: no
 * credentials), MON_AUTH_FAULT (a wrong UsernameToken password: a fault, not a challenge) or -1
 * (a challenge). */
static int mon_auth(char **f, char *t, size_t cap, size_t *tn)
{
	struct in_addr peer;
	char who[64] = "", nonce[NONCE_LEN + 1] = "";
	const char *authz = f[3], *ws = f[4];
	size_t wl = strlen(ws);
	time_t now = mono();
	int role = L_ADMIN, wrong = 0, wswrong = 0, retry = 0, stale = 0, st;
	uint64_t grant = 0;
	if (inet_pton(AF_INET, f[0], &peer) != 1 || (strcmp(f[1], "GET") && strcmp(f[1], "POST")))
		return say(t, cap, tn, MON_DENIED, "auth: a bad address or method");
	int blocked = auth_blocked(peer, now);
	if (!*authz && !wl) {
		role = 0;                                       /* none given: a nonce for the challenge */
	} else if (blocked) {
		wswrong = wl > 0;                               /* not even checked */
	} else {
		if (*authz) {
			int d = digest_auth(authz, f[1], f[2], now, who, sizeof who);
			if (d == A_STALE) stale = 1;
			else if (d == A_WRONG) wrong = 1;
			else if (d < 0) retry = 1;
			else role = d;
		}
		if (wl) {
			int w = wsse_auth(ws, ws + wl, who, sizeof who);
			if (w == A_WRONG) wrong = wswrong = 1;
			else if (w < 0) retry = 1;              /* clock, window, replay: Digest may still work */
			else if (w < role) role = w;
		}
	}
	if (role && !blocked && !wrong && !stale && !retry) {
		if (role >= L_OPERATOR) auth_good(peer, now);   /* a viewer's login exempts nothing */
		grant = grant_issue(role, who, peer);
		st = role;
	} else {
		if (wrong) {
			for (char *p = who; *p; p++)               /* client-supplied: keep the log clean */
				if (!isgraph((unsigned char)*p)) *p = '?';
			auth_failed(peer, now);
			LOG("%s: wrong password for \"%s\"%s\n", f[0], who, auth_blocked(peer, now) ? ", blocked" : "");
		}
		st = !role ? 0 : wswrong ? MON_AUTH_FAULT : -1;
		if (st != MON_AUTH_FAULT) nonce_make((unsigned long)mono(), nonce_next(), nonce);
		stale = stale && !wrong && !retry;
	}
	int n = snprintf(t, cap, "%llx%c%s%c%d%c%d%c%s", (unsigned long long)grant, 0, nonce, 0, stale, 0,
			 auth_blocked(peer, now), 0, who);
	*tn = n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
	return st;
}

/* settime: the clock, then tokens made before the change (on either clock) never count again. */
static int mon_settime(char **f, char *t, size_t cap, size_t *tn)
{
	long long e = atoll(f[0]);
	long us = atol(f[1]);
	struct timeval tv = { (time_t)e, (suseconds_t)us };
	long long before = time(NULL);
	if (SET_TIME(&tv)) return say(t, cap, tn, -1, "settimeofday: %s", strerror(errno));
	if (before > seen_floor) seen_floor = before;
	if (e > seen_floor) seen_floor = e;
	clock_valid(e);
	return say(t, cap, tn, 0, "");
}

/* reboot: the UsernameToken floor saved for after it, then sync and reboot. */
static int mon_reboot(char *t, size_t cap, size_t *tn)
{
	clock_hw(time(NULL));
	hw_save(1);
	sync();
	if (DO_REBOOT()) return say(t, cap, tn, -1, "%s", strerror(errno));
	return say(t, cap, tn, 0, "");
}

/* The staged upload for camupdate's stdin, opened here and not by name in camupdate: the worker
 * owns the directory. No symlink, no FIFO (O_NONBLOCK), a regular file with one link, 1..UPD_MAX
 * bytes. Its fd, or -1 with *why. */
static int upd_open(const char **why)
{
	char p[300];
	struct stat sb;
	upd_path(UPD_FILE, p, sizeof p);
	int fd = open(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		*why = errno == ELOOP ? "the staged upload is a symlink: refused" : "the staged upload can't be opened";
		return -1;
	}
	if (fstat(fd, &sb) || !S_ISREG(sb.st_mode) || sb.st_nlink != 1 || sb.st_size < 1 || sb.st_size > UPD_MAX) {
		*why = "the staged upload isn't a regular file of 1 byte to 5 MiB";
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	return fd;
}

/* The check's runner, a grandchild of the monitor (init adopts it): camupdate --check - with the
 * upload on its stdin and its output into a pipe, then the record on `out` (killed: 1 byte,
 * camupdate's wait status: 4, its output: at most 599 bytes, the size of upd.text) and exit. `out`
 * is a stream socket the worker only reads: readable here means the worker closed it (upd_drop,
 * or its own UPD_CHECK_MS), and camupdate is killed at once (a pipe's write end doesn't say so on
 * every system). UPD_CHECK_MS and 10 s more is the runner's own limit. */
static void upd_runner(int in, int out)
{
	int a[2], st = 0, open_a = 1;
	char rec[5 + 599], buf[256];
	size_t rn = 5;
	for (int i = 3; i < 1024; i++)
		if (i != in && i != out) close(i);
	if (pipe(a)) _exit(1);
	pid_t c = fork();
	if (c < 0) _exit(1);
	if (c == 0) {
		dup2(in, 0);
		dup2(a[1], 1);
		dup2(a[1], 2);
		for (int i = 3; i < 1024; i++) close(i);
		char *const argv[] = { "camupdate", "--check", "-", NULL };
		execve(CAMUPDATE, argv, clean_env);
		_exit(127);
	}
	close(a[1]);
	close(in);
	rec[0] = 0;
	long long until = mono_ms() + UPD_CHECK_MS + 10000;
	for (;;) {
		struct pollfd p[2] = { { open_a ? a[0] : -1, POLLIN, 0 }, { out, POLLIN, 0 } };
		long long left = until - mono_ms();
		if (left <= 0) {
			kill(c, SIGKILL);
			rec[0] = 1;
			while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
			break;
		}
		poll(p, 2, !open_a ? 20 : left > 1000 ? 1000 : (int)left);
		if (p[1].revents) {                                 /* the worker gave up on it */
			kill(c, SIGKILL);
			while (waitpid(c, NULL, 0) < 0 && errno == EINTR) {}
			_exit(0);
		}
		if (open_a && p[0].revents) {
			ssize_t k = read(a[0], buf, sizeof buf);
			if (k > 0) {
				size_t n = (size_t)k < sizeof rec - rn ? (size_t)k : sizeof rec - rn;
				memcpy(rec + rn, buf, n);
				rn += n;
			} else if (k == 0 || errno != EINTR) {
				open_a = 0;
			}
		}
		if (!open_a && waitpid(c, &st, WNOHANG) == c) break;
	}
	memcpy(rec + 1, &st, sizeof st);
	if (write(out, rec, rn) < 0) { /* the worker is gone: nobody to tell */ }
	_exit(0);
}

/* upd-check: the runner started; the reply passes the worker's end of the record's socket. */
static int mon_upd_check(char *t, size_t cap, size_t *tn, int *rfd)
{
	const char *why = "";
	int in = upd_open(&why), b[2], st = -1;
	if (in < 0) return say(t, cap, tn, 1, "%s", why);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, b)) {
		close(in);
		return say(t, cap, tn, -1, "no socket pair: %s", strerror(errno));
	}
	pid_t pid = fork();
	if (pid == 0) {
		close(b[0]);
		pid_t g = fork();
		if (g == 0) upd_runner(in, b[1]);
		_exit(g > 0 ? 0 : 1);
	}
	close(in);
	close(b[1]);
	if (pid > 0)
		while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
	if (pid < 0 || !WIFEXITED(st) || WEXITSTATUS(st)) {
		close(b[0]);
		return say(t, cap, tn, -1, "no fork");
	}
	*rfd = b[0];
	return say(t, cap, tn, 0, "");
}

/* upd-install: camupdate - with the upload on its stdin, detached: double fork and setsid, so
 * neither camhttpd nor camhttpd-run is its ancestor (camupdate would spare them and leave them
 * running from the flash it rewrites); it SIGSTOPs us with everything else. Its stdio go to UPD_LOG
 * (the worker's, which reads its last line if it ends without a reboot). The reply: its pid, and
 * the read end of a pipe only camupdate holds the write end of (EOF: it has ended). */
static int mon_upd_install(char *t, size_t cap, size_t *tn, int *rfd)
{
	char lp[300];
	const char *why = "";
	int pp[2] = { -1, -1 }, ep[2] = { -1, -1 }, lg = -1, in = upd_open(&why);
	pid_t pid = -1, g = -1;
	if (in < 0) return say(t, cap, tn, 1, "%s", why);
	upd_path(UPD_LOG, lp, sizeof lp);
	unlink(lp);
	lg = open(lp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (lg >= 0 && w_drop && fchown(lg, w_uid, w_gid)) {
		close(lg);
		lg = -1;
	}
	if (lg >= 0 && !pipe(pp) && !pipe(ep) && (pid = fork()) == 0) {
		setsid();                                  /* no terminal, out of camhttpd-run's group */
		g = fork();
		if (g == 0) {
			dup2(in, 0);
			dup2(lg, 1);
			dup2(lg, 2);
			for (int i = 3; i < 1024; i++)
				if (i != ep[1]) close(i);
			fcntl(ep[1], F_SETFD, 0);          /* kept across exec: the pipe's write end */
			char *const argv[] = { "camupdate", "-", NULL };
			execve(CAMUPDATE, argv, clean_env);
			_exit(127);
		}
		ssize_t w = write(pp[1], &g, sizeof g);   /* init adopts it once we exit */
		_exit(w == (ssize_t)sizeof g && g > 0 ? 0 : 1);
	}
	close(in);
	if (pp[1] >= 0) close(pp[1]);
	if (ep[1] >= 0) close(ep[1]);                  /* only camupdate holds it now */
	if (lg >= 0) close(lg);
	if (pid > 0) {
		if (read(pp[0], &g, sizeof g) != (ssize_t)sizeof g) g = -1;
		while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
	}
	if (pp[0] >= 0) close(pp[0]);
	if (g <= 0) {
		if (ep[0] >= 0) close(ep[0]);
		return say(t, cap, tn, -1, "camupdate didn't start (%s)", lg < 0 ? "no log file" : "no fork or pipe");
	}
	*rfd = ep[0];
	return say(t, cap, tn, 0, "%ld", (long)g);
}

static int mon_has_admin(void)
{
	musers_load();
	for (int i = 0; i < nmusers; i++)
		if (musers[i].role == L_ADMIN) return 1;
	return 0;
}

/* claim and recover: the monitor's own gate, whatever the worker checked. stdin: two lines. */
static int mon_claim(int recover, char **f, char *t, size_t cap, size_t *tn)
{
	static char in[2 * UI_BODY_MAX + 4];
	struct in_addr peer;
	time_t now = mono();
	if (inet_pton(AF_INET, f[0], &peer) != 1) return say(t, cap, tn, 1, "a bad address");
	if (locked()) return say(t, cap, tn, MON_CLOSED, LOCKED_SAY);
	if (recover && auth_blocked(peer, now)) return say(t, cap, tn, MON_BLOCKED, "locked out");
	if (!claim_window())
		return say(t, cap, tn, MON_CLOSED, "%s is open only for the first 30 minutes after power-on.",
			   recover ? "Recovery" : "Setup");
	if (mon_has_admin() != recover)
		return say(t, cap, tn, MON_CLOSED, recover ? "This camera isn't claimed yet." : "This camera is claimed already.");
	if (!recover && !*f[1]) return say(t, cap, tn, 1, "camcfg: a name is needed");
	if (!claim_post_ok(&mon_claim_rate, now))
		return say(t, cap, tn, MON_CLOSED, "Too many attempts: wait a minute.");
	const char *args[] = { recover ? "recover" : "claim", *f[1] ? f[1] : NULL, NULL };
	snprintf(in, sizeof in, "%s\n%s\n", f[2], f[3]);       /* claim: password, key; recover: code, password */
	int rc = mon_camcfg(users_path, args, in, t, tn);
	if (recover && rc == WRONG_CODE) {
		auth_failed(peer, now);
		LOG("%s: wrong recovery code%s\n", f[0], auth_blocked(peer, now) ? ", blocked" : "");
	}
	return rc;
}

/* ---- settings backup (#172, #173): camcfg backup export | import, run by the monitor ---- */

#ifdef __linux__
#define BK_FD3 "/proc/self/fd/3"       /* camcfg backup import's FILE: the upload the monitor opened */
#else
#define BK_FD3 "/dev/fd/3"
#endif
static const char *bk_tmp_dir = "/run";  /* root's tmpfs: export's output, a file with no name */
static long long mon_reboot_at;        /* mono ms: the reboot after a restore (mon_tick) */

/* camcfg -d DIR backup ARGS (DIR: the users file's): `in`, the passphrase line, on its stdin
 * (wiped here); fd3 (-1: none) as its fd 3; its stdout into fd1 (-1: with its stderr into t, as
 * camcfg_exec). CAMCFG_MS at most; its exit status, or -1. */
static int mon_camcfg_bk(const char *const *args, char *in, int fd3, int fd1, char *t, size_t cap, size_t *tn)
{
	char dir[256];
	int pin[2], pout[2], status;
	size_t got = 0;
	long long until = mono_ms() + CAMCFG_MS, left;
	size_t inl = strlen(in);
	dir_of(users_path, dir, sizeof dir);
	*t = 0;
	*tn = 0;
	if (pipe(pin)) { memset(in, 0, inl); return -1; }
	if (pipe(pout)) { close(pin[0]); close(pin[1]); memset(in, 0, inl); return -1; }
	pid_t pid = fork();
	if (pid < 0) {
		close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]);
		memset(in, 0, inl);
		return -1;
	}
	if (pid == 0) {
		char *argv[8] = { "camcfg", "-d", dir, "backup" };
		int n = 4;
		dup2(pin[0], 0);
		dup2(fd1 >= 0 ? fd1 : pout[1], 1);
		dup2(pout[1], 2);
		if (fd3 >= 0) {
			dup2(fd3, 3);
			fcntl(3, F_SETFD, 0);                  /* kept across exec (dup2 onto itself keeps the flag) */
		}
		for (int i = fd3 >= 0 ? 4 : 3; i < 1024; i++) close(i);   /* no sockets for camcfg */
		while (n < 7 && args[n - 4]) { argv[n] = (char *)args[n - 4]; n++; }
		argv[n] = NULL;
		execve(CAMCFG, argv, CAMCFG_ENV);
		_exit(127);
	}
	close(pin[0]);
	close(pout[1]);
	if (write(pin[1], in, inl) < 0) { /* camcfg is gone: its status says why */ }
	memset(in, 0, inl);
	close(pin[1]);
	while ((left = until - mono_ms()) > 0) {         /* its messages until EOF, as camcfg_exec */
		fd_set rf;
		struct timeval tv = { (time_t)(left / 1000), (suseconds_t)(left % 1000 * 1000) };
		char junk[256];
		FD_ZERO(&rf);
		FD_SET(pout[0], &rf);
		int s = select(pout[0] + 1, &rf, NULL, NULL, &tv);
		if (s < 0 && errno == EINTR) continue;
		if (s <= 0) break;
		ssize_t k = got < cap - 1 ? read(pout[0], t + got, cap - 1 - got) : read(pout[0], junk, sizeof junk);
		if (k == 0 || (k < 0 && errno != EINTR)) break;
		if (k > 0 && got < cap - 1) got += (size_t)k;
	}
	t[got] = 0;
	*tn = got;
	close(pout[0]);
	if (child_wait(pid, until, &status)) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* A file with no name for export's output, root's (bk_tmp_dir): O_TMPFILE, else a name made with
 * mkstemp and removed at once. -1 if neither works. */
static int bk_tmpfile(void)
{
	char p[300];
	int fd = -1;
#ifdef O_TMPFILE
	fd = open(bk_tmp_dir, O_TMPFILE | O_RDWR | O_EXCL | O_CLOEXEC, 0600);
#endif
	if (fd < 0) {
		snprintf(p, sizeof p, "%s/.cambak-XXXXXX", bk_tmp_dir);
		if ((fd = mkstemp(p)) >= 0) {
			unlink(p);
			fcntl(fd, F_SETFD, FD_CLOEXEC);
		}
	}
	return fd;
}

/* bk-export: the reply passes the .cambak (an fd at its start); its text is camcfg's line. */
static int mon_bk_export(char **f, char *t, size_t cap, size_t *tn, int *rfd)
{
	static char in[PP_CAP + 2];
	const char *args[] = { "export", NULL };
	struct stat sb;
	if (mon_reboot_at) return say(t, cap, tn, MON_CLOSED, "The camera is rebooting.");
	int fd = bk_tmpfile();
	if (fd < 0) return say(t, cap, tn, -1, "no file for the backup in %s: %s", bk_tmp_dir, strerror(errno));
	snprintf(in, sizeof in, "%s\n", f[0]);
	int rc = mon_camcfg_bk(args, in, -1, fd, t, cap, tn);
	if (!rc && (fstat(fd, &sb) || sb.st_size < 1 || lseek(fd, 0, SEEK_SET)))
		rc = say(t, cap, tn, -1, "camcfg wrote no backup");
	if (rc) {
		close(fd);
		return rc;
	}
	*rfd = fd;
	return 0;
}

/* A staged upload (`name` in upd_dir, the worker's): opened here and handed to camcfg as an fd,
 * never by name; as upd_open, no symlink, no FIFO, a regular file with one link, 1 to max bytes.
 * Its fd, or -1 with *why. */
static int staged_open(const char *name, long max, const char **why)
{
	char p[300];
	struct stat sb;
	upd_path(name, p, sizeof p);
	int fd = open(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		*why = errno == ELOOP ? "the staged upload is a symlink: refused" : "the staged upload can't be opened";
		return -1;
	}
	if (fstat(fd, &sb) || !S_ISREG(sb.st_mode) || sb.st_nlink != 1 || sb.st_size < 1 || sb.st_size > max) {
		*why = "the staged upload isn't a regular file of the right size";
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	return fd;
}

/* The staged backup (BK_FILE): passed to camcfg backup import as its fd 3, at most BK_UP_MAX. */
static int bk_open(const char **why) { return staged_open(BK_FILE, BK_UP_MAX, why); }

/* bk-restore (admin, g its grant; f: peer, password, passphrase) and bk-setup (unclaimed; f: peer,
 * passphrase): the monitor's own checks, then camcfg backup import on the staged upload. A wrong
 * password or passphrase (camcfg's exit 3) counts as a failed login. Success: the reboot. */
static int mon_bk_import(int setup, const struct grant *g, char **f, char *t, size_t cap, size_t *tn)
{
	static char in[PP_CAP + 2];
	struct in_addr peer;
	time_t now = mono();
	const char *why = "", *args[] = { "import", BK_FD3, NULL };
	if (inet_pton(AF_INET, f[0], &peer) != 1) return say(t, cap, tn, 1, "a bad address");
	if (auth_blocked(peer, now)) return say(t, cap, tn, MON_BLOCKED, "locked out");
	if (mon_reboot_at) return say(t, cap, tn, MON_CLOSED, "The camera is rebooting.");
	if (setup && locked()) return say(t, cap, tn, MON_CLOSED, LOCKED_SAY);
	if (setup) {
		if (!claim_window())
			return say(t, cap, tn, MON_CLOSED, "Setup is open only for the first 30 minutes after power-on.");
		if (mon_has_admin()) return say(t, cap, tn, MON_CLOSED, "This camera is claimed already.");
		if (!claim_post_ok(&mon_claim_rate, now)) return say(t, cap, tn, MON_CLOSED, "Too many attempts: wait a minute.");
	} else {
		/* the admin's own password again: a browser left logged in can't replace every account */
		int ok = 0;
		size_t pl = strlen(f[1]);
		musers_load();
		for (int i = 0; i < nmusers; i++)
			if (musers[i].role == L_ADMIN && !strcmp(musers[i].name, g->user))
				ok = pl == strlen(musers[i].pw) && ct_eq(f[1], musers[i].pw, pl);
		if (!ok) {
			auth_failed(peer, now);
			LOG("%s: backup restore by %s refused: wrong password%s\n", f[0], g->user,
			    auth_blocked(peer, now) ? ", blocked" : "");
			return say(t, cap, tn, MON_AUTH_FAULT, "Wrong password.");
		}
	}
	int fd = bk_open(&why);
	if (fd < 0) return say(t, cap, tn, 1, "%s", why);
	snprintf(in, sizeof in, "%s\n", setup ? f[1] : f[2]);
	int rc = mon_camcfg_bk(args, in, fd, -1, t, cap, tn);
	close(fd);
	if (rc == WRONG_CODE) {
		auth_failed(peer, now);
		LOG("%s: backup restore%s: wrong passphrase (or a changed file)%s\n", f[0], setup ? " at setup" : "",
		    auth_blocked(peer, now) ? ", blocked" : "");
	} else if (!rc) {
		mon_reboot_at = mono_ms() + BK_REBOOT_MS;
		LOG("%s: settings restored from a backup%s%s: rebooting\n", f[0], setup ? " at setup" : " by ",
		    setup ? "" : g->user);
	}
	return rc;
}

/* ---- lock mode's signed recovery (#175, #176; docs/PLAN-DATA-LOCK.md Part 3) ---------------- */

static uint8_t unlock_ch[32];          /* the one-time challenge; unlock_until 0: none */
static time_t unlock_until;            /* mono s it expires */
static char unlock_id[96];             /* "device ID\nfirmware VERSION\n" (camcfg unlock info), once */

/* camcfg ARGS (no -d: unlock works on mtd3 itself) with in_fd (-1: /dev/null) as its stdin, its
 * stdout and stderr into t; ms at most. Its exit status, or -1. */
static int mon_camcfg_fd(const char *const *args, int in_fd, long long ms, char *t, size_t cap, size_t *tn)
{
	int pout[2], status;
	size_t got = 0;
	long long until = mono_ms() + ms, left;
	*t = 0;
	*tn = 0;
	if (pipe(pout)) return -1;
	pid_t pid = fork();
	if (pid < 0) {
		close(pout[0]);
		close(pout[1]);
		return -1;
	}
	if (pid == 0) {
		char *argv[10] = { "camcfg" };
		int n = 1, nul = in_fd >= 0 ? in_fd : open("/dev/null", O_RDONLY);
		if (nul < 0 || dup2(nul, 0) < 0 || dup2(pout[1], 1) < 0 || dup2(pout[1], 2) < 0) _exit(127);
		for (int i = 3; i < 1024; i++) close(i);       /* no sockets for camcfg */
		while (n < 9 && args[n - 1]) { argv[n] = (char *)args[n - 1]; n++; }
		argv[n] = NULL;
		execve(CAMCFG, argv, CAMCFG_ENV);
		_exit(127);
	}
	close(pout[1]);
	while ((left = until - mono_ms()) > 0) {
		fd_set rf;
		struct timeval tv = { (time_t)(left / 1000), (suseconds_t)(left % 1000 * 1000) };
		char junk[256];
		FD_ZERO(&rf);
		FD_SET(pout[0], &rf);
		int s = select(pout[0] + 1, &rf, NULL, NULL, &tv);
		if (s < 0 && errno == EINTR) continue;
		if (s <= 0) break;
		ssize_t k = got < cap - 1 ? read(pout[0], t + got, cap - 1 - got) : read(pout[0], junk, sizeof junk);
		if (k == 0 || (k < 0 && errno != EINTR)) break;
		if (k > 0 && got < cap - 1) got += (size_t)k;
	}
	t[got] = 0;
	while (got && (t[got - 1] == '\n' || t[got - 1] == ' ')) t[--got] = 0;
	*tn = got;
	close(pout[0]);
	if (child_wait(pid, until, &status)) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* unlock-ch: the challenge (a new one if there is none or it expired), with the camera's device
 * ID and firmware: "challenge HEX\ndevice ID\nfirmware VERSION\nexpires-in SECONDS\n". */
static int mon_unlock_ch(char *t, size_t cap, size_t *tn)
{
	static const char *info[] = { "unlock", "info", NULL };
	char hex[65];
	time_t now = mono();
	if (!locked()) return say(t, cap, tn, MON_CLOSED, "The camera isn't locked.");
	if (!*unlock_id) {
		char out[256], dev[40], fw[40];
		size_t on;
		int rc = mon_camcfg_fd(info, -1, CAMCFG_MS, out, sizeof out, &on);
		if (rc || sscanf(out, "device %39s firmware %39s", dev, fw) != 2 || strlen(dev) != 32 ||
		    strspn(dev, "0123456789abcdef") != 32)
			return say(t, cap, tn, -1, "no device ID: %s", rc ? out : "camcfg unlock info said something else");
		snprintf(unlock_id, sizeof unlock_id, "device %s\nfirmware %s\n", dev, fw);
	}
	if (!unlock_until || now >= unlock_until) {
		if (random_bytes(unlock_ch, sizeof unlock_ch)) return say(t, cap, tn, -1, "no random bytes");
		unlock_until = now + UNLOCK_S;
	}
	for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", unlock_ch[i]);
	return say(t, cap, tn, 0, "challenge %s\n%sexpires-in %ld\n", hex, unlock_id, (long)(unlock_until - now));
}

/* unlock (f: peer, restore|erase, the challenge it was signed for): the address not locked out,
 * the rate, the challenge (this one, unexpired; it is spent by any attempt, good or bad), then
 * camcfg unlock ACTION -c CHALLENGE [-] with the staged upload (UNLOCK_FILE: the passphrase line,
 * the signature, the backup) as its stdin. A bad signature or passphrase (exit 3) counts as a failed
 * login. Success: the reboot. */
static int mon_unlock(char **f, char *t, size_t cap, size_t *tn)
{
	struct in_addr peer;
	time_t now = mono();
	char hex[65];
	const char *why = "";
	int restore = !strcmp(f[1], "restore");
	if (inet_pton(AF_INET, f[0], &peer) != 1) return say(t, cap, tn, 1, "a bad address");
	if (!locked()) return say(t, cap, tn, MON_CLOSED, "The camera isn't locked.");
	if (!restore && strcmp(f[1], "erase")) return say(t, cap, tn, 1, "the action is restore or erase");
	if (auth_blocked(peer, now)) return say(t, cap, tn, MON_BLOCKED, "locked out");
	if (mon_reboot_at) return say(t, cap, tn, MON_CLOSED, "The camera is rebooting.");
	if (!claim_post_ok(&mon_claim_rate, now)) return say(t, cap, tn, MON_CLOSED, "Too many attempts: wait a minute.");
	for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", unlock_ch[i]);
	int fresh = unlock_until && now < unlock_until && strlen(f[2]) == 64 && ct_eq(f[2], hex, 64);
	unlock_until = 0;                                  /* one attempt per challenge */
	if (!fresh) {
		LOG("%s: unlock (%s) refused: not the current challenge\n", f[0], f[1]);
		return say(t, cap, tn, MON_CLOSED, "That challenge expired or was used: reload the page for a new one.");
	}
	int fd = staged_open(UNLOCK_FILE, UNLOCK_UP_MAX, &why);
	if (fd < 0) return say(t, cap, tn, 1, "%s", why);
	const char *args[] = { "unlock", f[1], "-c", f[2], restore ? "-" : NULL, NULL };
	int rc = mon_camcfg_fd(args, fd, UNLOCK_MS, t, cap, tn);
	close(fd);
	if (rc == WRONG_CODE) {
		auth_failed(peer, now);
		LOG("%s: unlock (%s) refused: %s%s\n", f[0], f[1], t, auth_blocked(peer, now) ? ", blocked" : "");
	} else if (!rc) {
		mon_reboot_at = mono_ms() + BK_REBOOT_MS;
		LOG("%s: unlocked (%s): %s; rebooting\n", f[0], f[1], t);
	} else {
		LOG("%s: unlock (%s) failed: %s\n", f[0], f[1], t);
	}
	return rc;
}

/* A request the dispatcher has framed: fields as the op wants them, the grant, then the op. */
static int mon_run(int op, uint64_t grant, char **f, char *t, size_t cap, size_t *tn, int *rfd)
{
	static char in[UI_BODY_MAX + 2];
	const struct mon_op *o = &mon_ops[op];
	const char *why = "";
	struct grant *g = NULL;
	int bad = op == MON_SET || op == MON_USER || op == MON_SSHKEY || op == MON_CLAIM || op == MON_RECOVER ||
		  op == MON_BK_EXPORT || op == MON_BK_RESTORE || op == MON_BK_SETUP || op == MON_UNLOCK ? 1 : MON_DENIED;
	for (int i = 0; i < o->nf; i++)
		if ((why = field_why(f[i], o->cls[i], o->max[i]))) return say(t, cap, tn, bad, "%s %s", o->fn[i], why);
	if (o->role == L_PRE) {
		if (grant) return say(t, cap, tn, MON_DENIED, "%s takes no grant", o->name);
	} else {
		int need = op == MON_SET && !strncmp(f[0], "time.", 5) ? L_ADMIN : o->role;
		if (!(g = grant_find(grant, need, op == MON_UPD_CHECK, &why))) {
			LOG("monitor: %s refused: %s\n", o->name, why);
			return say(t, cap, tn, MON_DENIED, "%s: %s", o->name, why);
		}
	}
	/* the op's own shape; then the grant is spent */
	switch (op) {
	case MON_SET:
		if (!key_ok(f[0])) return say(t, cap, tn, 1, "set: %s isn't a key camhttpd sets", f[0]);
		break;
	case MON_USER: {
		int add = !strcmp(f[0], "add"), pwd = !strcmp(f[0], "passwd"), rl = !strcmp(f[0], "role"),
		    del = !strcmp(f[0], "del");
		if ((!add && !pwd && !rl && !del) || !*f[1] || (add || rl) != (*f[2] != 0) || (!add && !pwd && *f[3]))
			return say(t, cap, tn, 1, "user: a bad request");
		break;
	}
	case MON_SSHKEY:
		if (!(!strcmp(f[0], "list") && !*f[1]) && !(!strcmp(f[0], "add") && *f[1]) &&
		    !(!strcmp(f[0], "del") && strlen(f[1]) >= 1 && strlen(f[1]) <= 2 && strspn(f[1], "0123456789") == strlen(f[1])))
			return say(t, cap, tn, 1, "sshkey: a bad request");
		break;
	case MON_SETTIME: {
		size_t a = strlen(f[0]), b = strlen(f[1]);
		long long e = atoll(f[0]);
		if (!a || strspn(f[0], "0123456789") != a || !b || strspn(f[1], "0123456789") != b ||
		    (long long)(time_t)e != e)
			return say(t, cap, tn, MON_DENIED, "settime: a bad time");
		break;
	}
	}
	if (g) g->uses++;
	switch (op) {
	case MON_AUTH: return mon_auth(f, t, cap, tn);
	case MON_SET: {
		int rc = RUN_CAMCFG(f[0], f[1]);
		return say(t, cap, tn, rc ? -1 : 0, rc ? "camcfg set failed" : "");
	}
	case MON_USER: {
		const char *args[] = { "user", f[0], f[1], *f[2] ? f[2] : NULL, NULL };
		int pw = !strcmp(f[0], "add") || !strcmp(f[0], "passwd");
		if (pw) snprintf(in, sizeof in, "%s\n", f[3]);
		return mon_camcfg(users_path, args, pw ? in : NULL, t, tn);
	}
	case MON_SSHKEY: {
		const char *args[] = { "sshkey", f[0], !strcmp(f[0], "del") ? f[1] : NULL, NULL };
		int add = !strcmp(f[0], "add");
		if (add) snprintf(in, sizeof in, "%s\n", f[1]);
		return mon_camcfg(conf_path, args, add ? in : NULL, t, tn);
	}
	case MON_SETTIME: return mon_settime(f, t, cap, tn);
	case MON_REBOOT: return mon_reboot(t, cap, tn);
	case MON_UPD_BEGIN:
		for (int i = 0; i < GRANT_N; i++) grants[i].pin = 0;
		g->pin = 1;
		return say(t, cap, tn, 0, "");
	case MON_UPD_CHECK:
		g->pin = 0;                                     /* one check per upload */
		return mon_upd_check(t, cap, tn, rfd);
	case MON_UPD_INSTALL: return mon_upd_install(t, cap, tn, rfd);
	case MON_CLAIM: return mon_claim(0, f, t, cap, tn);
	case MON_RECOVER: return mon_claim(1, f, t, cap, tn);
	case MON_BK_EXPORT: return mon_bk_export(f, t, cap, tn, rfd);
	case MON_BK_RESTORE: return mon_bk_import(0, g, f, t, cap, tn);
	case MON_BK_SETUP: return mon_bk_import(1, NULL, f, t, cap, tn);
	case MON_UNLOCK_CH: return mon_unlock_ch(t, cap, tn);
	case MON_UNLOCK: return mon_unlock(f, t, cap, tn);
	case MON_CONF: {
		int fd = open(conf_path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) return say(t, cap, tn, -1, "%s", strerror(errno));
		*rfd = fd;
		return say(t, cap, tn, 0, "");
	}
	case MON_USERS:
		musers_load();
		*tn = 0;
		for (int i = 0; i < nmusers; i++)
			*tn += (size_t)snprintf(t + *tn, cap - *tn, "%d %s\n", musers[i].role, musers[i].name);
		return 0;
	}
	return say(t, cap, tn, MON_DENIED, "unknown op");
}

/* One message from the worker: 0 with the reply in rep (*rn bytes, at most MON_MSG) and an fd for
 * it in *rfd (else -1), or -1 if the message is malformed. Its copy is wiped (passwords). */
static int mon_dispatch(const char *msg, size_t n, char *rep, size_t *rn, int *rfd)
{
	static char in[MON_MSG];
	char *f[MON_NF];
	size_t tn = 0, len;
	uint32_t op, l;
	uint64_t grant;
	int32_t st;
	int nf = 0;
	*rfd = -1;
	if (n < MON_HDR || n > MON_MSG) return -1;
	memcpy(&op, msg, 4);
	memcpy(&grant, msg + 4, 8);
	memcpy(&l, msg + 12, 4);
	len = l;
	if (len != n - MON_HDR || (len && msg[n - 1])) return -1;   /* the length, the last field's NUL */
	memcpy(in, msg + MON_HDR, len);
	for (size_t i = 0; i < len; i += strlen(in + i) + 1) {
		if (nf == MON_NF) { memset(in, 0, len); return -1; }
		f[nf++] = in + i;
	}
	if (!op || op >= MON_NOPS) {
		st = say(rep + MON_RHDR, MON_MSG - MON_RHDR, &tn, MON_DENIED, "unknown op %u", (unsigned)op);
	} else if (nf != mon_ops[op].nf) {
		memset(in, 0, len);
		return -1;
	} else {
		st = mon_run((int)op, grant, f, rep + MON_RHDR, MON_MSG - MON_RHDR, &tn, rfd);
	}
	memset(in, 0, len);
	l = (uint32_t)tn;
	memcpy(rep, &st, 4);
	memcpy(rep + 4, &l, 4);
	*rn = MON_RHDR + tn;
	return 0;
}

/* One message out, with fd `pass` (>= 0) as SCM_RIGHTS: 0, or -1. */
static int mon_send(int fd, const void *p, size_t n, int pass)
{
	struct iovec iov = { (void *)p, n };
	struct msghdr m;
	union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u;
	ssize_t k;
	memset(&m, 0, sizeof m);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	if (pass >= 0) {
		memset(&u, 0, sizeof u);
		m.msg_control = u.b;
		m.msg_controllen = sizeof u.b;
		struct cmsghdr *c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), &pass, sizeof pass);
	}
	while ((k = sendmsg(fd, &m, 0)) < 0 && errno == EINTR) {}
	return k == (ssize_t)n ? 0 : -1;
}

/* One message in (cap bytes at most): its length, 0 at EOF, -1 on an error, -2 if it was cut short
 * or brought more than one fd (those are closed). *got: the fd that came with it, or -1. */
static ssize_t mon_recv(int fd, void *buf, size_t cap, int *got)
{
	struct iovec iov = { buf, cap };
	struct msghdr m;
	union { struct cmsghdr h; char b[CMSG_SPACE(2 * sizeof(int))]; } u;
	ssize_t n;
	int bad = 0;
	memset(&m, 0, sizeof m);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = u.b;
	m.msg_controllen = sizeof u.b;
	*got = -1;
	while ((n = recvmsg(fd, &m, 0)) < 0 && errno == EINTR) {}
	if (n < 0) return -1;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
		size_t k = c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS ?
			   (c->cmsg_len - CMSG_LEN(0)) / sizeof(int) : 0;
		bad |= !k;
		for (size_t i = 0; i < k; i++) {
			int x;
			memcpy(&x, CMSG_DATA(c) + i * sizeof(int), sizeof x);
			if (*got < 0) *got = x;
			else { close(x); bad = 1; }
		}
	}
	if (*got >= 0) fcntl(*got, F_SETFD, FD_CLOEXEC);
	if (bad || (m.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
		if (*got >= 0) close(*got);
		*got = -1;
		return -2;
	}
	return n;
}

/* The monitor's clock duties, at least once a second: the UsernameToken high-water mark and its
 * hourly save (in-process: from the loop); a restore's reboot. */
static void mon_tick(void)
{
	clock_hw(time(NULL));
	hw_save(0);
	if (mon_reboot_at && mono_ms() >= mon_reboot_at) {   /* a restore's: its reply is out by now */
		char t[160];
		size_t tn;
		mon_reboot_at = 0;
		LOG("monitor: rebooting after a restore\n");
		if (mon_reboot(t, sizeof t, &tn)) LOG("reboot: %s\n", t);
	}
}

/* The monitor's loop (-Z, the parent, root): one request at a time from the worker's socket,
 * until the worker goes (EOF), sends a malformed message (it is killed), or we are stopped (it is
 * told to stop). Then the floor is saved and we exit too. */
static int mon_serve(int fd, pid_t worker)
{
	static char msg[MON_MSG + 1], rep[MON_MSG];
	int code = 0, status;
	while (!stop) {
		struct pollfd p = { fd, POLLIN, 0 };
		int k = poll(&p, 1, 1000), got = -1, rfd = -1;
		size_t rn = 0;
		mon_tick();
		if (k < 0 && errno != EINTR) break;
		if (k <= 0) continue;
		ssize_t n = mon_recv(fd, msg, sizeof msg, &got);
		if (n == 0 || n == -1) break;                   /* the worker has gone */
		if (got >= 0) close(got);                       /* the worker passes no fd */
		if (n < 0 || got >= 0 || mon_dispatch(msg, (size_t)n, rep, &rn, &rfd)) {
			memset(msg, 0, sizeof msg);
			LOG("monitor: a malformed message from the worker: stopping it\n");
			if (worker > 0) kill(worker, SIGKILL);
			code = 1;
			break;
		}
		memset(msg, 0, (size_t)n);                      /* it may have held a password */
		int sent = mon_send(fd, rep, rn, rfd);
		if (rfd >= 0) close(rfd);
		if (sent) break;
	}
	close(fd);                                          /* a worker still asking learns we're gone */
	if (worker > 0) {                                   /* (0: the host test's, not our child) */
		kill(worker, SIGTERM);
		for (int i = 0; i < 300 && waitpid(worker, &status, WNOHANG) == 0; i++) {
			struct timespec nap = { 0, 10 * 1000000L };
			nanosleep(&nap, NULL);
		}
		if (waitpid(worker, &status, WNOHANG) == 0) {
			kill(worker, SIGKILL);
			while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {}
		}
	}
	clock_hw(time(NULL));
	hw_save(1);
	LOG("monitor: exiting\n");
	return code;
}

/* ---- the worker's side of it */

static char mon_msg[MON_MSG], mon_rep[MON_MSG];

/* One request to the monitor (fields f, nf of them) and its reply: the status, the text in
 * mon_rbuf (mon_rlen bytes, NUL-terminated), and the fd that came with it in *rfd (rfd NULL:
 * closed). The request is wiped once sent (it may hold a password). If the monitor is gone, so is
 * the worker. */
static int mon_call(int op, uint64_t grant, int nf, const char *const *f, int *rfd)
{
	size_t n = MON_HDR, rn = 0;
	uint32_t o = (uint32_t)op, len;
	int32_t st = -1;
	int fd = -1;
	if (rfd) *rfd = -1;
	*mon_rbuf = 0;
	mon_rlen = 0;
	for (int i = 0; i < nf; i++) {
		size_t l = strlen(f[i]) + 1;
		if (l > MON_MSG - n) {
			memset(mon_msg, 0, n);
			mon_rlen = (size_t)snprintf(mon_rbuf, sizeof mon_rbuf, "camhttpd: too long for the monitor");
			return 1;
		}
		memcpy(mon_msg + n, f[i], l);
		n += l;
	}
	len = (uint32_t)(n - MON_HDR);
	memcpy(mon_msg, &o, 4);
	memcpy(mon_msg + 4, &grant, 8);
	memcpy(mon_msg + 12, &len, 4);
	if (mon_fd < 0) {                                   /* in-process: the dispatcher itself */
		if (mon_dispatch(mon_msg, n, mon_rep, &rn, &fd)) rn = 0;
	} else {
		ssize_t k = -1;
		if (!mon_send(mon_fd, mon_msg, n, -1)) k = mon_recv(mon_fd, mon_rep, sizeof mon_rep, &fd);
		if (k <= 0) {
			memset(mon_msg, 0, n);
			LOG("worker: the monitor is gone (%s): exiting\n", k == 0 ? "closed" : strerror(errno));
			_exit(1);
		}
		rn = (size_t)k;
	}
	memset(mon_msg, 0, n);
	uint32_t tl = 0;
	if (rn >= MON_RHDR) {
		memcpy(&st, mon_rep, 4);
		memcpy(&tl, mon_rep + 4, 4);
	}
	if (rn < MON_RHDR || tl != rn - MON_RHDR || tl > sizeof mon_rbuf - 8) {
		LOG("worker: no proper reply to %s\n", op > 0 && op < MON_NOPS ? mon_ops[op].name : "?");
		if (fd >= 0) close(fd);
		return -1;
	}
	memcpy(mon_rbuf, mon_rep + MON_RHDR, tl);
	memset(mon_rbuf + tl, 0, 8);                        /* the text ends in NULs (authenticate) */
	mon_rlen = tl;
	memset(mon_rep, 0, rn);
	MON_REPLY_SEEN(mon_rbuf, mon_rlen);
	if (rfd) *rfd = fd;
	else if (fd >= 0) close(fd);
	return st;
}

static int cfg_set(const char *key, const char *val)
{
	const char *f[2] = { key, val };
	return mon_call(MON_SET, req_grant, 2, f, NULL) ? -1 : 0;
}

/* A camcfg op through the monitor (user, sshkey with the request's grant; claim, recover with
 * none): its status, camcfg's output into out. */
static int cfg_exec(int op, int nf, const char *const *f, char *out, size_t cap)
{
	int rc = mon_call(op, op == MON_CLAIM || op == MON_RECOVER ? 0 : req_grant, nf, f, NULL);
	snprintf(out, cap, "%s", mon_rbuf);
	memset(mon_rbuf, 0, mon_rlen);                      /* a recovery code, say */
	return rc;
}

/* cam.conf (root-only on DATA) as the monitor opened it. */
static FILE *conf_open(void)
{
	int fd = -1;
	if (mon_call(MON_CONF, 0, 0, NULL, &fd) || fd < 0) {
		if (fd >= 0) close(fd);
		return NULL;
	}
	FILE *f = fdopen(fd, "r");
	if (!f) close(fd);
	return f;
}

/* auth with no credentials: whether peer is locked out now (1, 0; -1 without an answer) and a fresh
 * nonce for a challenge (nonce may be NULL). */
static int mon_auth_probe(struct in_addr peer, char nonce[NONCE_LEN + 1])
{
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &peer, ip, sizeof ip);
	const char *f[5] = { ip, "GET", "/", "", "" };
	int st = mon_call(MON_AUTH, 0, 5, f, NULL);
	const char *g = mon_rbuf, *n = g + strlen(g) + 1, *sl = n + strlen(n) + 1, *bl = sl + strlen(sl) + 1,
		   *u = bl + strlen(bl) + 1;
	int ok = st == 0 && u <= mon_rbuf + mon_rlen;
	if (nonce) snprintf(nonce, NONCE_LEN + 1, "%s", ok && strlen(n) == NONCE_LEN ? n : "");
	return ok ? *bl == '1' : -1;
}

/* The worker after the fork: nothing of the monitor's stays in its memory. */
static void worker_forget(void)
{
	memset(secret, 0, sizeof secret);
	nonce_off = 0;
	memset(epr_key, 0, sizeof epr_key);
	epr_fixed = 1;                                      /* epr is made: keep it */
	memset(musers, 0, sizeof musers);
	nmusers = 0;
	memset(grants, 0, sizeof grants);
	memset(ncs, 0, sizeof ncs);
	memset(seen, 0, sizeof seen);
}

/* The monitor's socket pair: message boundaries kept, room for a whole message either way. */
static int mon_socketpair(int sv[2])
{
	int buf = 4 * MON_MSG;
#ifdef __linux__
	int type = SOCK_SEQPACKET;
#else
	int type = SOCK_DGRAM;                              /* macOS (the host test) has no SEQPACKET unix sockets */
#endif
	if (socketpair(AF_UNIX, type, 0, sv)) return -1;
	for (int i = 0; i < 2; i++) {
		setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
		setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
		fcntl(sv[i], F_SETFD, FD_CLOEXEC);
	}
	return 0;
}

/* -Z: the socket pair and the fork. The parent serves as the monitor and exits with it; the
 * child leaves root for `who` and returns 0 to run the loop. */
static int privsep(const struct drop_id *who, int lfd, int dfd)
{
	int sv[2];
	const char *why = "";
	if (mon_socketpair(sv)) {
		LOG("socketpair: %s\n", strerror(errno));
		return -1;
	}
	w_drop = 1;
	w_uid = who->uid;
	w_gid = who->gid;
	pid_t pid = fork();
	if (pid < 0) {
		LOG("fork: %s\n", strerror(errno));
		return -1;
	}
	if (pid > 0) {                                      /* the monitor */
		close(sv[1]);
		close(lfd);
		if (dfd >= 0) close(dfd);
		if (tfd >= 0) close(tfd);                   /* camtls's socket is the worker's */
		memset(ui_key, 0, sizeof ui_key);
		LOG("monitor: root, pid %d; the worker is pid %d\n", (int)getpid(), (int)pid);
		exit(mon_serve(sv[0], pid));
	}
	close(sv[0]);
	mon_fd = sv[1];
	worker_forget();
	if (drop_to(who, -1, &why)) {
		LOG("worker: can't leave root for %s: %s (%s); stopping\n", who->name, why, strerror(errno));
		_exit(1);
	}
	LOG("worker: running as %s (uid %u, gid %u, %d groups); setuid(0) refused\n", who->name,
	    (unsigned)getuid(), (unsigned)getgid(), who->ngroups);
	return 0;
}

/* ---- main ----------------------------------------------------------------------------- */

static void client_close(struct client *c)
{
	upd_lost(c);                                   /* mid-upload: the staged file goes too */
	close(c->fd);
	if (c->file_fd >= 0) close(c->file_fd);
	c->fd = c->file_fd = -1;
}

static void client_write(struct client *c)
{
	for (;;) {
		if (c->out_off == c->out_len) {
			c->out_off = c->out_len = 0;
			if (c->file_left <= 0 && c->state == 3 && c->file_fd >= 0) {
				close(c->file_fd);                 /* a preview frame is out: end its part */
				c->file_fd = -1;
				out_add(c, PV_DELIM, sizeof PV_DELIM - 1);
				continue;
			}
			if (c->file_left <= 0) break;
			ssize_t n = read(c->file_fd, c->out, c->file_left < OUT_CAP ? (size_t)c->file_left : OUT_CAP);
			if (n <= 0) { client_close(c); return; }
			c->out_len = (size_t)n;
			c->file_left -= n;
		}
		ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, 0);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) client_close(c);
			return;
		}
		c->out_off += (size_t)n;
	}
	if (c->state == 1) client_close(c);
}

static void client_read(struct client *c)
{
	if (c->state == ST_UPLOAD) {                   /* a firmware upload: straight to its file */
		size_t room = upd.want - upd.got;
		ssize_t n = recv(c->fd, c->in, room < REQ_CAP ? room : REQ_CAP, 0);
		if (n <= 0) {
			if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) client_close(c);
			return;
		}
		upd_take(c, c->in, (size_t)n);
		if (c->state == 1) c->deadline = mono() + SEND_TIMEOUT;
		return;
	}
	if (c->state >= 2) {                           /* held, preview or check: notice the client leaving */
		char junk[256];
		ssize_t k = recv(c->fd, junk, sizeof junk, 0);
		if (k == 0 || (k < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
			client_close(c);
		return;
	}
	ssize_t n = recv(c->fd, c->in + c->in_len, REQ_CAP - c->in_len, 0);
	if (n <= 0) {
		if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) client_close(c);
		return;
	}
	c->in_len += (size_t)n;
	c->last_rx = mono_ms();
	size_t had = c->hdr_len;
	http_feed(c);
	if (!had && c->hdr_len) c->deadline = mono() + 5 + (time_t)(c->body_len / BODY_RATE);
	if (c->state == 1) c->deadline = mono() + SEND_TIMEOUT;
	else if (c->state == ST_UPLOAD) upd_deadline(c);
	else if (c->state == ST_CHECK) c->deadline = mono() + UPD_CHECK_MS / 1000 + 5;
}

/* The slot a newcomer may take when none is free (slowloris): a connection still waiting for its
 * headers after HDR_GRACE_MS, or one in its body that has had no byte for BODY_IDLE_MS; of those,
 * the one stalled longest (since it was accepted, or since its last byte). Only state 0 qualifies:
 * nothing there is authenticated yet (credentials are checked once the whole request is in). A
 * held pull (2), a preview (3), a firmware upload (4: an admin, checked at its headers) or its
 * check (5), and a reply being sent (1) are never taken. NULL if none. */
static struct client *slot_victim(void)
{
	struct client *victim = NULL;
	long long now = mono_ms(), vt = 0;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *c = &clients[i];
		long long t = c->hdr_len ? c->last_rx : c->since;
		if (c->fd < 0 || c->state || now - t <= (c->hdr_len ? BODY_IDLE_MS : HDR_GRACE_MS)) continue;
		if (!victim || t < vt) {
			victim = c;
			vt = t;
		}
	}
	return victim;
}

/* Whether a connection could get a slot now; if not, it waits in the listen backlog instead of
 * being accepted and closed. */
static int can_accept(void)
{
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd < 0) return 1;
	return slot_victim() != NULL;
}

/* A slot for a new connection from `peer`: a free one, else slot_victim's, which is dropped for it.
 * NULL if `peer` already has PER_PEER connections or no slot can be had. */
static struct client *slot_for(struct in_addr peer)
{
	struct client *free_c = NULL, *victim = slot_victim();
	int mine = 0;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *c = &clients[i];
		if (c->fd < 0) { if (!free_c) free_c = c; continue; }
		mine += c->peer.s_addr == peer.s_addr;
	}
	if (mine >= PER_PEER) return NULL;
	if (free_c) return free_c;
	if (victim) client_close(victim);
	return victim;
}

static void client_reset(struct client *c, int fd)
{
	upd_lost(c);                                   /* (a slot is reused only once closed) */
	c->fd = fd;
	c->state = 0;
	c->in_len = c->hdr_len = c->body_len = c->scanned = 0;
	c->since = c->last_rx = mono_ms();
	c->out_off = c->out_len = 0;
	c->file_fd = -1;
	c->file_left = 0;
	c->deadline = mono() + HDR_TIMEOUT;
	c->park_id[0] = 0;
	strcpy(c->local, "0.0.0.0");
	c->tls = c->proxy = 0;
}

enum { C_TCP, C_TLS };                         /* client_attach: port 80, or camtls's socket */

/* The uid at the other end of a UNIX socket (SO_PEERCRED on Linux, getpeereid on the Mac the host
 * test runs on). 0, or -1. */
static int peer_uid(int fd, uid_t *uid)
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

/* A new connection into a slot (slot_for), or closed: NULL. Port 80's has its peer and local
 * address from the socket. camtls's must come from tls_uid (anything else is closed and logged,
 * before it can take a slot), gets the placeholder 0.0.0.0 until its PROXY line (proxy_take) and a
 * small send buffer (TLS_SNDBUF). */
static struct client *client_attach(int fd, int kind)
{
	struct sockaddr_in pa, la;
	socklen_t pl = sizeof pa, ll = sizeof la;
	struct in_addr peer = { 0 };
	uid_t uid = (uid_t)-1;                         /* -1: the kernel didn't say */
	if (kind == C_TLS && (peer_uid(fd, &uid) || uid != tls_uid || !tls_uid)) {
		LOG("camtls socket: a connection from uid %ld refused (only uid %u)\n", uid == (uid_t)-1 ? -1L : (long)uid,
		    (unsigned)tls_uid);
		close(fd);
		return NULL;
	}
	if (kind == C_TCP) {
		if (getpeername(fd, (struct sockaddr *)&pa, &pl) || pa.sin_family != AF_INET) {
			close(fd);
			return NULL;
		}
		peer = pa.sin_addr;
	}
	struct client *c = slot_for(peer);
	if (!c) { close(fd); return NULL; }            /* busy: the client retries */
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	client_reset(c, fd);
	c->peer = peer;
	if (kind == C_TLS) {
		int buf = TLS_SNDBUF;
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
		c->proxy = 1;
	} else if (!getsockname(fd, (struct sockaddr *)&la, &ll))
		inet_ntop(AF_INET, &la.sin_addr, c->local, sizeof c->local);
	return c;
}

static void accept_client(int lfd, int kind)
{
	int fd = accept(lfd, NULL, NULL);
	if (fd >= 0) client_attach(fd, kind);
}

/* camtls connections whose PROXY line hasn't come within PROXY_MS: closed. */
static void tls_tick(long long now)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *c = &clients[i];
		if (c->fd < 0 || !c->proxy || now - c->since <= PROXY_MS) continue;
		LOG("camtls: no PROXY line within %d ms: closed\n", PROXY_MS);
		client_close(c);
	}
}

/* -t PATH:USER, as root before the fork: a UNIX stream socket at PATH (a stale socket there is
 * removed; anything else there, or no parent directory, and there is none), root's, group USER's
 * primary group, mode 0660 (from the umask at bind, so never wider), non-blocking; USER's uid is
 * the only peer it takes. USER: a name in /etc/passwd or UID:GID (drop_lookup, as -Z; root
 * refused). The fd, or -1 (logged): camhttpd then runs without HTTPS, as before -t. */
static int tls_listen(const char *spec, const char *passwd, const char *group)
{
	struct sockaddr_un a;
	struct drop_id id;
	struct stat st;
	const char *why = "", *colon = strchr(spec, ':');
	size_t pl = colon ? (size_t)(colon - spec) : 0;
	int fd = -1;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	if (!pl || pl >= sizeof a.sun_path || spec[0] != '/') { why = "PATH:USER wanted, PATH absolute and short"; goto fail; }
	if (drop_lookup(colon + 1, passwd, group, &id, &why)) goto fail;
	memcpy(a.sun_path, spec, pl);
	if (!lstat(a.sun_path, &st)) {
		if (!S_ISSOCK(st.st_mode)) { why = "something other than a socket is there"; goto fail; }
		if (unlink(a.sun_path)) { why = strerror(errno); goto fail; }
	}
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) { why = strerror(errno); goto fail; }
	mode_t was = umask(0117);                          /* bind makes it 0660 root:root at once */
	int b = bind(fd, (struct sockaddr *)&a, sizeof a);
	umask(was);
	if (b || lchown(a.sun_path, 0, id.gid) || listen(fd, 8)) {   /* lchown: never through a symlink */
		why = strerror(errno);
		if (!b) unlink(a.sun_path);
		goto fail;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	tls_uid = id.uid;
	LOG("camtls socket %s: uid %u, group %u, 0660\n", a.sun_path, (unsigned)id.uid, (unsigned)id.gid);
	return fd;
fail:
	if (fd >= 0) close(fd);
	LOG("-t %s: %s; running without HTTPS\n", spec, why);
	return -1;
}

static int listen_on(const char *addr, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	if (fd < 0 || inet_pton(AF_INET, addr, &a.sin_addr) != 1) return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 8)) {
		LOG("listen %s:%d: %s\n", addr, port, strerror(errno));
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	return fd;
}

int main(int argc, char **argv)
{
	const char *addr = "0.0.0.0", *user = NULL, *why = "";
	struct drop_id who = { .ngroups = 0 };
	int c;
	while ((c = getopt(argc, argv, "p:l:r:u:U:c:S:i:w:Z:t:T:Dv")) != -1) {
		switch (c) {
		case 'p': http_port = atoi(optarg); break;
		case 'l': addr = optarg; break;
		case 'r': rtsp_port = atoi(optarg); break;
		case 'u': ctl_path = optarg; break;
		case 'U': users_path = optarg; break;
		case 'c': conf_path = optarg; break;
		case 'S': snap_path = optarg; break;
		case 'i': ifname = optarg; break;
		case 'w': skew = atoi(optarg); break;
		case 'Z': user = optarg; break;
		case 't': tls_spec = optarg; break;
		case 'T': tls_ready = optarg; break;
		case 'D': disco_on = 0; break;
		case 'v': verbose++; break;
		default:
			fprintf(stderr, "usage: %s [-p port] [-l addr] [-r rtsp-port] [-u ctl-socket] "
				"[-U users] [-c cam.conf] [-S snapshot.jpg] [-i ifname] [-w skew-s] [-Z user|uid:gid] "
				"[-t path:user] [-T ready-file] [-D] [-v]\n",
				argv[0]);
			return 2;
		}
	}
	if (http_port < 1 || http_port > 65535 || rtsp_port < 1 || rtsp_port > 65535 || skew < 1 ||
	    skew > 86400 || strlen(ifname) >= IFNAMSIZ) {
		fprintf(stderr, "bad port, interface or -w (1..86400 s)\n");
		return 2;
	}
	if (tls_spec && (*tls_spec != '/' || !strchr(tls_spec, ':') || !strchr(tls_spec, ':')[1])) {
		fprintf(stderr, "-t PATH:USER wanted (PATH absolute)\n");
		return 2;
	}
	/* -Z before anything starts: a user that isn't there stops camhttpd here */
	if (user && drop_lookup(user, "/etc/passwd", "/etc/group", &who, &why)) {
		fprintf(stderr, "-Z %s: %s\n", user, why);
		return 2;
	}
	if (auth_init()) {
		fprintf(stderr, "no /dev/urandom\n");
		return 1;
	}
	hw_load();                                         /* TIME_FLOOR: tokens from before it never count */
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	signal(SIGPIPE, SIG_IGN);
	for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = clients[i].file_fd = -1;
	int lfd = listen_on(addr, http_port);
	if (lfd < 0) return 1;
	instance = (unsigned long)time(NULL);
	if (disco_on) dfd = disco_open();
	/* -t: unlike -Z's, a user or socket that isn't there doesn't stop camhttpd: it serves port 80
	 * as before -t (tls_up is then never true, so nothing redirects to an HTTPS that can't reach us) */
	if (tls_spec) tfd = tls_listen(tls_spec, "/etc/passwd", "/etc/group");
	char stale[300];                                   /* an upload from before a respawn: no form is */
	upd_path(UPD_FILE, stale, sizeof stale);           /* bound to it any more, and it holds RAM */
	if (!unlink(stale)) LOG("removed %s, an upload from before this start\n", stale);
	/* -Z (Gate 3): everything that needs root is open or made (port 80, the discovery socket,
	 * /dev/urandom, the EndpointReference from its root-only secret); the monitor keeps root and
	 * the worker leaves it for good before the first client. Nothing of the users file is read
	 * before this: its passwords would be in the worker's memory. */
	epr_make();
	if (user && privsep(&who, lfd, dfd)) return 1;
	int owned = claimed();
	LOG("camhttpd %s: http://%s:%d/ (ONVIF, /snapshot.jpg, web UI /ui/), %d users, discovery %s\n", FW_VERSION,
	    addr, http_port, nusers, dfd >= 0 ? "on" : "off");
	if (!owned)
		LOG("not claimed yet (no admin): only /setup is served, for the first %d minutes after power-on "
		    "(up %ld s)\n", CLAIM_WINDOW / 60, boot_seconds());
	time_t last_tick = 0;
	while (!stop) {
		fd_set rf, wf;
		FD_ZERO(&rf);
		FD_ZERO(&wf);
		int maxfd = lfd, accepting = can_accept();
		if (accepting) FD_SET(lfd, &rf);                /* else new connections wait in the backlog */
		if (accepting && tfd >= 0) { FD_SET(tfd, &rf); if (tfd > maxfd) maxfd = tfd; }   /* ... camtls's too */
		if (dfd >= 0) { FD_SET(dfd, &rf); if (dfd > maxfd) maxfd = dfd; }
		if (mon_fd >= 0) { FD_SET(mon_fd, &rf); if (mon_fd > maxfd) maxfd = mon_fd; }   /* EOF: it's gone */
		int held = 0;
		for (int i = 0; i < MAX_CLIENTS; i++) {
			struct client *cl = &clients[i];
			if (cl->fd < 0) continue;
			if (cl->state != 1) FD_SET(cl->fd, &rf);
			if (cl->out_len > cl->out_off || cl->file_left > 0 || cl->state == 1) FD_SET(cl->fd, &wf);
			if (cl->fd > maxfd) maxfd = cl->fd;
			held += cl->state >= 2 || cl->proxy;   /* held pulls, previews and PROXY_MS want short ticks */
		}
		/* short ticks while a held pull, a preview or a PROXY line runs, or while the backlog waits */
		struct timeval tv = { held || !accepting ? 0 : 1, held || !accepting ? 100000 : 0 };
		if (select(maxfd + 1, &rf, &wf, NULL, &tv) < 0 && errno != EINTR) {
			LOG("select: %s\n", strerror(errno));
			break;
		}
		time_t now = mono();
		if (mon_fd >= 0 && FD_ISSET(mon_fd, &rf)) {
			LOG("worker: the monitor is gone: exiting\n");
			break;
		}
		if (accepting && FD_ISSET(lfd, &rf)) accept_client(lfd, C_TCP);
		if (accepting && tfd >= 0 && FD_ISSET(tfd, &rf) && can_accept())   /* port 80's may have taken the last */
			accept_client(tfd, C_TLS);
		if (dfd >= 0 && FD_ISSET(dfd, &rf)) disco_read();
		for (int i = 0; i < MAX_CLIENTS; i++) {
			struct client *cl = &clients[i];
			if (cl->fd >= 0 && FD_ISSET(cl->fd, &rf)) client_read(cl);
			if (cl->fd >= 0 && FD_ISSET(cl->fd, &wf)) client_write(cl);
			if (cl->fd >= 0 && now > cl->deadline) client_close(cl);
		}
		tls_tick(mono_ms());
		events_tick(mono_ms());
		preview_tick(mono_ms());
		restart_tick(mono_ms());
		if (mon_fd < 0) mon_tick();                     /* in-process: the monitor's clock duties */
		reboot_check(mono_ms());
		upd_tick(mono_ms());
		if (dfd >= 0 && now - last_tick >= 5) { disco_tick(); last_tick = now; }
	}
	if (restart_wanted) rtspd_restart_now();          /* settings saved but not yet applied */
	if (mon_fd < 0) {                                  /* in-process (with -Z the monitor does it) */
		clock_hw(time(NULL));
		hw_save(1);
	}
	if (dfd >= 0 && disco_joined) disco_announce("Bye");
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd >= 0) client_close(&clients[i]);
	close(lfd);
	if (dfd >= 0) close(dfd);
	if (tfd >= 0) close(tfd);
	return 0;
}
