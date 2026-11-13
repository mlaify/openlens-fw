/* SPDX-License-Identifier: MIT */
/*
 * rtspd: minimal RTSP server for the Ifado camera (issue #29), on our MI layer (src/mi).
 *
 * Two streams like stock: main (rtsp://cam:port/, 2560x1440 H.265 by default) and sub
 * (rtsp://cam:port/sub, 640x360 H.264 by default), each H.265 or H.264. RTP over the RTSP TCP
 * connection (interleaved, RFC 2326 10.12); H.265 payload per RFC 7798, H.264 per RFC 6184
 * (single NAL units and FU / FU-A fragments). Single thread, one select() loop: the listening
 * socket, up to MAX_CLIENTS connections, the encoders' /dev/mi_poll fds and /dev/isp_fe (3A).
 * Each client has a bounded output buffer; a client that falls behind drops whole frames and
 * resumes at the next keyframe, so a slow viewer can't grow memory.
 *
 * Authentication: RTSP Digest against an htdigest file (-a; see auth.c), or explicitly none (-N);
 * rtspd refuses to start with neither. OPTIONS is open, everything else needs a valid response.
 * Wrong passwords lock the address out (auth_blocked), and connections that haven't logged in
 * can't hold the slots: LOGIN_MS to log in, PER_IP_UNAUTHED per address, and a newcomer finding
 * every slot taken evicts the oldest of them (never a logged-in client; client_admit).
 * Not yet: RTP over UDP (SETUP answers 461, clients retry with TCP).
 *
 *   rtspd (-a htdigest | -N) [-p port] [-l bind-addr] [-w W -h H] [-b kbps] [-f fps] [-c codec]
 *         [-s WxH|0] [-d codec] [-k kbps] [-g fps] [-F] [-T y] [-e us:gain] [-W r:g:b] [-v]
 *     -i  settings file (cam.conf, #72): image.* values applied at start
 *     -u  control socket (default /run/camd.sock, "" = none): line commands for root, and with -G
 *         for that group too (the socket file then 0660; else 0600 with -U, root's 0700 without)
 *         "get", "set image.<brightness|contrast|saturation|sharpness|exposure> 0..100",
 *         "set image.<mirror|flip> 0|1", "set image.shutter_day_max 0|100..1000000",
 *         "set image.shutter_night_max 0|100..50000" (us, 0 = auto), "set image.antiflicker 0|1",
 *         "set image.mains_hz 50|60", "set image.<nr2d|nr3d|wdr|blc> 0..255",
 *         "set image.night_tuning 0|1", "set image.exposure_night day|0..100" (day = as
 *         image.exposure), "set image.isp_gain_day_max|isp_gain_night_max 1..4" (x),
 *         "set daynight.<key> value"; "get" also reports the AE (ae.y, ae.target, ae.shutter_us,
 *         ae.sensor_gain, ae.isp_gain; gains 1024 = 1x),
 *         "set osd.<key> value" (on-screen display, src/mi/osd.c; "set osd.title.text TEXT" takes
 *         the rest of the line), "set time.tz TZ" (the time zone, a POSIX TZ string: tz.h),
 *         "auth-reload" (re-read the -a file after the users changed)
 *     Time zone: time.tz from -i (default UTC0) becomes rtspd's TZ (setenv + tzset), live with
 *         "set time.tz". Only the OSD clock uses it (localtime_r); the log stays UTC.
 *     -w/-h main size (2560x1440), -b its kbps (by size, streamcfg.h: 4000 at 2560x1440), -f its
 *         fps, also the sensor's (30)
 *     -c  main codec h265 (default) or h264
 *     -s  sub-stream size (default 640x360), 0 = no sub-stream; -d its codec (default h264),
 *         -k its kbps (by size: 500 at 640x360), -g its fps (30, at most the main's)
 *     cam.conf's stream.* (-i) win over these; stream.<main|sub>.size takes only streamcfg.h's sizes
 *     -a  Digest credentials (htdigest "user:realm:HA1" lines; scripts/rtsp-passwd.py)
 *     -N  no authentication (bench only)
 *     -F  bind SCL->VENC as FRAME_BASE instead of HW_RING (stock main stream)
 *     -T  AE target, stats mean Y (default 40)
 *     -P  ISP output pixel format (default 11 NV12; 0 YUYV skips the ISP's later YUV stages)
 *     -Q  apply the image-pipeline groups of an iq-dump file (stock tuning, #36)
 *     -q  NIGHT,DAY: stock night tuning files (iq-night.bin,iq-day-switch.bin from
 *         scripts/iq-bin2profile.py), used at night when image.night_tuning is 1 (default 0)
 *     -U  user (Gate 3): a name from /etc/passwd, or UID:GID. rtspd leaves root for it once the
 *         port, the control socket, the settings, /dev/urandom and every device are open, before
 *         the first client (drop.h: no capability kept; setuid(0) must fail, else rtspd exits).
 *         What it still opens afterwards: /run/cam (its own: snapshot.jpg, the -a file on
 *         auth-reload), the IR LED pwm and amplifier GPIO attributes (made its own at boot by
 *         /etc/init.d/rtspd-prep), /etc/cam (world-readable IQ files). Without -U, rtspd stays root.
 *     -G  group for the control socket (a name from /etc/group, or a GID), for its clients that
 *         aren't root (camhttpd's worker, next)
 *     -t  PATH:USER (RTSPS, docs/PLAN-TLS.md D): also listen on the UNIX socket PATH for camtls,
 *         which ends TLS on port 322. The socket file is 0660, group USER's (a name from
 *         /etc/passwd, or UID:GID), made as root before the drop; only USER's uid may connect.
 *         Each connection starts with a PROXY v1 line (proxy.h) within PROXY_MS, naming the
 *         client and the camera's address; then it is an RTSP client like one on the port, under
 *         the client's address (tls_take, tls_proxy_in). A bad -t or a socket that can't be made
 *         is logged and rtspd goes on without it: the port always streams.
 *   URL: rtsp://<camera>:<port>/  (any path); rtsps://<camera>:322/ through camtls
 */
#define _GNU_SOURCE                    /* memmem; setenv, tzset, gmtime_r under -std=c11 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "daynight.h"
#include "drop.h"
#include "motion.h"
#include "audio.h"
#include "mi.h"
#include "osd.h"
#include "proxy.h"
#include "streamcfg.h"
#include "tz.h"

#define MAX_CLIENTS 4
#define IN_CAP 4096
#define OUT_CAP (1024 * 1024)
#define RTP_PAYLOAD 1400                /* keeps each RTP packet under a 1500-byte MTU */
#define SESSION_TIMEOUT 60              /* s without a request, RTCP or send progress */
#define LOGIN_MS 10000                  /* to authenticate after connecting, whatever is sent */
#define CLOSING_MS 2000                 /* for a closing client to read its last reply */
#define PER_IP_UNAUTHED 2               /* connections not yet logged in, per address (SSS: 2) */
#define FAIL_MAX 5                      /* wrong passwords per address per window */
#define FAIL_GLOBAL 20                  /* wrong passwords from all addresses per window */
#define FAIL_WINDOW 60
#define GOOD_KEEP 600                   /* s a good login exempts its address from FAIL_GLOBAL */
#define MAX_NALS 64
#ifndef MONO_ADJ_MS
#define MONO_ADJ_MS 0                   /* the host test moves the monotonic clock */
#endif
#ifndef PEER_UID
#define PEER_UID(fd, u) peer_uid(fd, u) /* the host test chooses the uid of its socketpairs */
#endif
#define TLS_SNDBUF (64 * 1024)          /* camtls's socket: rtspd still sees a slow viewer (send_frame) */

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

/* Log lines carry UTC (time.tz only changes the OSD clock). */
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

/* ---- clients ------------------------------------------------------------------------- */

struct client {
	int fd;
	char peer[48];
	struct in_addr ip;                 /* the peer's IPv4 address (lockout, PER_IP_UNAUTHED) */
	long long since_ms, closing_ms;    /* mono_ms() at accept; when closing was first seen */
	char in[IN_CAP];
	size_t in_len;
	uint8_t out[OUT_CAP];
	size_t out_off, out_len;           /* pending bytes are out[out_off .. out_len) */
	int ready, playing, want_key, closing;
	int ch;                            /* interleaved RTP channel (RTCP is ch + 1, ignored) */
	uint16_t seq;
	uint32_t ssrc;
	char session[17];
	time_t last;
	unsigned long long sent;
	unsigned drops;
	int stream;                        /* 0 main, 1 sub (chosen by the URL at DESCRIBE/SETUP) */
	int video;                         /* video track set up (a talk-only client gets no video) */
	int audio, ach;                    /* audio track set up (#110); its interleaved channel */
	int talk, tch;                     /* backchannel set up (#117): this client talks to the speaker */
	uint16_t aseq;
	uint32_t assrc;
	char nonce[33];                    /* Digest nonce, fresh per connection */
	int authed, auth_fails;
	int tls;                           /* through camtls (RTSPS): ip is the PROXY line's client */
	struct in_addr local;              /* tls: the camera's address and port the client reached */
	uint16_t lport;                    /* (the PROXY line's), for the SDP and Content-Base */
};

static struct client clients[MAX_CLIENTS];
/* The client the speaker plays (#117). Every client may set up the backchannel (SSS opens more
 * than one connection and drops them all if one SETUP is refused); a client takes the speaker
 * with audible audio once the current talker has been quiet for TALK_IDLE_MS, so a connection
 * that streams silence doesn't hold it. */
static struct client *talker;
static long long talk_loud_ms;          /* the talker's last audible packet */
#define TALK_LOUD 300                   /* peak sample counted as audible (about -40 dBFS) */
#define TALK_IDLE_MS 500
static long long mono_ms(void);

/* /dev/urandom stays open: mdev makes it root's (0660), and with -U rtspd is no longer root when
 * clients come (main opens it before the drop). */
static int urandom_fd = -1;

static void random_bytes(void *p, size_t n)
{
	if (urandom_fd < 0) urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (urandom_fd < 0 || read(urandom_fd, p, n) != (ssize_t)n) {
		/* never fatal: these are session ids and SSRCs, not secrets */
		for (size_t i = 0; i < n; i++) ((uint8_t *)p)[i] = (uint8_t)(rand() ^ (int)time(NULL));
	}
}

static void client_close(struct client *c, const char *why)
{
	LOG("client %s closed (%s): %llu bytes sent, %u frames dropped\n", c->peer, why, c->sent,
	    c->drops);
	close(c->fd);
	c->fd = -1;
	if (talker == c) talker = NULL;
	c->talk = 0;
}

static int out_room(const struct client *c)
{
	return (int)(OUT_CAP - (c->out_len - c->out_off));
}

static void out_compact(struct client *c)
{
	if (c->out_off == 0) return;
	memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
	c->out_len -= c->out_off;
	c->out_off = 0;
}

static int out_put(struct client *c, const void *p, size_t n)
{
	if (OUT_CAP - c->out_len < n) out_compact(c);
	if (OUT_CAP - c->out_len < n) return -1;
	memcpy(c->out + c->out_len, p, n);
	c->out_len += n;
	return 0;
}

static void out_flush(struct client *c)
{
	while (c->out_off < c->out_len) {
		ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off,
				 MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
			client_close(c, strerror(errno));
			return;
		}
		c->out_off += (size_t)n;
		c->sent += (unsigned long long)n;
		c->last = time(NULL);          /* a viewer that keeps reading is alive even if silent */
	}
	c->out_off = c->out_len = 0;
	if (c->closing) client_close(c, "teardown");
}

/* ---- streams ------------------------------------------------------------------------- */

#define NSTREAMS 2
static struct stream {
	int on, codec;                     /* codec: MI_H265 / MI_H264 */
	struct { uint8_t d[256]; size_t n; } ps[3];   /* parameter sets for the SDP: H.265 VPS,
							 SPS, PPS; H.264 -, SPS, PPS */
	unsigned long long frames, bytes;
} streams[NSTREAMS];

static int audio_on;                    /* microphone captured: SDP offers PCMU/8000 (#110) */
static int audio_cfg_on = 1, audio_gain = -1;   /* cam.conf audio.enabled, audio.gain (0..19) */
static int speaker_on;                  /* MI_AO up: DESCRIBE with Require backchannel offers track2 */

/* the speaker's sink; mi_ao_write is a no-op until MI_AO is up */
static void speaker_pcm(const int16_t *pcm, unsigned n) { mi_ao_write(pcm, n); }

static int nal_type(int codec, const uint8_t *p)
{
	return codec == MI_H264 ? p[0] & 0x1f : (p[0] >> 1) & 0x3f;
}

/* The path of a request URL, any scheme (rtsp://, and rtsps:// through camtls): from the first '/'
 * after "scheme://host", or the whole of a URL without "://"; NULL if a URL has no path. */
static const char *url_path(const char *url)
{
	const char *path = strstr(url, "://");
	return path ? strchr(path + 3, '/') : url;
}

/* URL path "/sub…" selects the sub-stream, anything else the main stream; -1 if not available. */
static int url_stream(const char *url)
{
	const char *path = url_path(url);
	if (path && !strncmp(path, "/sub", 4)) return streams[1].on ? 1 : -1;
	return 0;
}

static void b64(const uint8_t *in, size_t n, char *out)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i = 0;
	for (; i + 2 < n; i += 3) {
		*out++ = t[in[i] >> 2];
		*out++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		*out++ = t[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
		*out++ = t[in[i + 2] & 63];
	}
	if (i < n) {
		*out++ = t[in[i] >> 2];
		if (i + 1 < n) {
			*out++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
			*out++ = t[(in[i + 1] & 15) << 2];
		} else {
			*out++ = t[(in[i] & 3) << 4];
			*out++ = '=';
		}
		*out++ = '=';
	}
	*out = 0;
}

/* ---- logins -------------------------------------------------------------------------- */

static time_t mono_s(void) { return (time_t)(mono_ms() / 1000); }

/* With -N every client counts as logged in: no login deadline, no eviction. */
static int client_authed(const struct client *c) { return c->authed || !auth_enabled(); }

/* Wrong passwords, as camhttpd. Per address: FAIL_MAX in a FAIL_WINDOW lock that address until
 * the window ends; a locked entry is never evicted, and a newcomer that finds every entry locked
 * counts as locked. All addresses together: FAIL_GLOBAL in a window stop the checks for everyone
 * except addresses that logged in within GOOD_KEEP s, so the NVR can reconnect while someone
 * guesses from many addresses. While blocked, credentials aren't checked at all (the reply is the
 * same 401 challenge, so it gives nothing away). */
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

static void auth_good(struct in_addr ip, time_t now)
{
	int slot = 0;
	for (int i = 0; i < GOOD_SLOTS; i++) {
		if (good[i].t && good[i].ip.s_addr == ip.s_addr) { slot = i; break; }
		if (good[i].t < good[slot].t) slot = i;
	}
	good[slot].ip = ip;
	good[slot].t = now;
}

/* ---- RTSP ---------------------------------------------------------------------------- */

/* Value of header `name` in the request (case-insensitive), trimmed; "" if absent. */
static void hdr(const char *req, const char *name, char *val, size_t cap)
{
	size_t nl = strlen(name);
	*val = 0;
	for (const char *p = strchr(req, '\n'); p; p = strchr(p, '\n')) {
		p++;
		if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
			p += nl + 1;
			while (*p == ' ' || *p == '\t') p++;
			size_t n = strcspn(p, "\r\n");
			if (n >= cap) n = cap - 1;
			memcpy(val, p, n);
			val[n] = 0;
			return;
		}
	}
}

static void reply(struct client *c, int code, const char *status, const char *cseq,
		  const char *extra, const char *body)
{
	char h[1024];
	size_t blen = body ? strlen(body) : 0;
	int n = snprintf(h, sizeof h, "RTSP/1.0 %d %s\r\nCSeq: %s\r\nServer: rtspd\r\n%s", code,
			 status, cseq, extra ? extra : "");
	if (blen) n += snprintf(h + n, sizeof h - (size_t)n, "Content-Length: %zu\r\n", blen);
	n += snprintf(h + n, sizeof h - (size_t)n, "\r\n");
	if (n >= (int)sizeof h || out_put(c, h, (size_t)n) || (blen && out_put(c, body, blen)))
		c->closing = 1;
}

static void handle_request(struct client *c, char *req)
{
	char method[16], url[256], cseq[16], sess[64], transport[256], extra[512];
	if (sscanf(req, "%15s %255s", method, url) != 2) { c->closing = 1; return; }
	hdr(req, "CSeq", cseq, sizeof cseq);
	hdr(req, "Session", sess, sizeof sess);
	sess[strcspn(sess, ";")] = 0;
	if (mi_verbose) LOG("%s: %s %s\n", c->peer, method, url);

	if (auth_enabled() && !c->authed && strcmp(method, "OPTIONS")) {
		char authz[1024], who[64] = "";
		time_t now = mono_s();
		hdr(req, "Authorization", authz, sizeof authz);
		int blocked = *authz && auth_blocked(c->ip, now);
		if (*authz && !blocked && auth_check(authz, method, c->nonce, who, sizeof who)) {
			c->authed = 1;
			auth_good(c->ip, now);
			LOG("client %s authenticated as %s\n", c->peer, who);
		} else {
			if (*authz) {
				if (blocked) {
					LOG("client %s: address locked out, credentials not checked\n", c->peer);
				} else {
					auth_failed(c->ip, now);
					LOG("client %s: bad credentials for \"%s\"%s\n", c->peer, who,
					    auth_blocked(c->ip, now) ? ", locked out" : "");
				}
				/* checked or not: no reply, and client_input reads nothing more */
				if (++c->auth_fails >= 5) { c->closing = 1; return; }
			}
			snprintf(extra, sizeof extra,
				 "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5\r\n",
				 auth_realm(), c->nonce);
			reply(c, 401, "Unauthorized", cseq, extra, NULL);
			return;
		}
	}

	if (!strcmp(method, "OPTIONS")) {
		reply(c, 200, "OK", cseq,
		      "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER\r\n", NULL);
	} else if (!strcmp(method, "DESCRIBE")) {
		int si = url_stream(url);
		if (si < 0) {
			reply(c, 404, "Not Found", cseq, NULL, NULL);
			return;
		}
		c->stream = si;
		const struct stream *st = &streams[si];
		struct sockaddr_in la;
		socklen_t ll = sizeof la;
		char ip[INET_ADDRSTRLEN] = "0.0.0.0", fmtp[1200] = "", sdp[2048], rq[160];
		hdr(req, "Require", rq, sizeof rq);
		int bc = speaker_on && strstr(rq, "backchannel") != NULL;     /* ONVIF talk (#117) */
		char v[348], sp[348], pp[348];             /* base64 of <= 256 bytes is 344 chars */
		if (c->tls)                                /* camtls's UNIX socket: the PROXY line's */
			inet_ntop(AF_INET, &c->local, ip, sizeof ip);
		else if (!getsockname(c->fd, (struct sockaddr *)&la, &ll))
			inet_ntop(AF_INET, &la.sin_addr, ip, sizeof ip);
		if (st->codec == MI_H264) {
			if (st->ps[1].n >= 4 && st->ps[2].n) {
				b64(st->ps[1].d, st->ps[1].n, sp);
				b64(st->ps[2].d, st->ps[2].n, pp);
				snprintf(fmtp, sizeof fmtp, "a=fmtp:96 packetization-mode=1;profile-level-id="
					 "%02X%02X%02X;sprop-parameter-sets=%s,%s\r\n", st->ps[1].d[1],
					 st->ps[1].d[2], st->ps[1].d[3], sp, pp);
			} else {
				snprintf(fmtp, sizeof fmtp, "a=fmtp:96 packetization-mode=1\r\n");
			}
		} else if (st->ps[0].n && st->ps[1].n && st->ps[2].n) {
			b64(st->ps[0].d, st->ps[0].n, v);
			b64(st->ps[1].d, st->ps[1].n, sp);
			b64(st->ps[2].d, st->ps[2].n, pp);
			snprintf(fmtp, sizeof fmtp, "a=fmtp:96 sprop-vps=%s;sprop-sps=%s;sprop-pps=%s\r\n",
				 v, sp, pp);
		}
		snprintf(sdp, sizeof sdp,
			 "v=0\r\no=- 1 1 IN IP4 %s\r\ns=camera\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
			 "a=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 %s/90000\r\n%s"
			 "a=control:track0\r\n%s%s", ip, st->codec == MI_H264 ? "H264" : "H265", fmtp,
			 audio_on ? "m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:track1\r\n" : "",
			 bc ? "m=audio 0 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
			      "a=control:track2\r\na=sendonly\r\n" : "");
		/* the request URL; through camtls rebuilt as rtsps://<camera>:<port>, the address the
		 * client reached (whatever scheme or host it wrote), so tracks resolve to RTSPS */
		if (c->tls) {
			const char *path = url_path(url);
			snprintf(extra, sizeof extra, "Content-Base: rtsps://%s:%u%s/\r\nContent-Type: "
				 "application/sdp\r\n", ip, (unsigned)c->lport, path && *path == '/' ? path : "");
		} else {
			snprintf(extra, sizeof extra, "Content-Base: %s/\r\nContent-Type: application/sdp\r\n",
				 url);
		}
		reply(c, 200, "OK", cseq, extra, sdp);
	} else if (!strcmp(method, "SETUP")) {
		int si = url_stream(url);
		if (si < 0) {
			reply(c, 404, "Not Found", cseq, NULL, NULL);
			return;
		}
		c->stream = si;
		hdr(req, "Transport", transport, sizeof transport);
		if (!strstr(transport, "RTP/AVP/TCP")) {
			reply(c, 461, "Unsupported Transport", cseq, NULL, NULL);
			return;
		}
		if (strstr(url, "/track2")) {                   /* the backchannel: the client talks */
			if (!speaker_on) { reply(c, 404, "Not Found", cseq, NULL, NULL); return; }
			int a = 4, b = 5;
			const char *il = strstr(transport, "interleaved=");
			if (il && sscanf(il + 12, "%d-%d", &a, &b) < 1) a = 4;
			if (a < 0 || a > 254) a = 4;
			c->tch = a;
			c->talk = 1;
			if (!c->ready) {
				uint8_t r[8];
				random_bytes(r, sizeof r);
				for (int i = 0; i < 8; i++) snprintf(c->session + 2 * i, 3, "%02X", r[i]);
			}
			c->ready = 1;
			snprintf(extra, sizeof extra, "Transport: RTP/AVP/TCP;unicast;interleaved=%d-%d\r\n"
				 "Session: %s;timeout=%d\r\n", a, a + 1, c->session, SESSION_TIMEOUT);
			reply(c, 200, "OK", cseq, extra, NULL);
			LOG("client %s set up the backchannel\n", c->peer);
			return;
		}
		int is_audio = strstr(url, "/track1") != NULL;
		if (is_audio && !audio_on) {
			reply(c, 404, "Not Found", cseq, NULL, NULL);
			return;
		}
		int a = is_audio ? 2 : 0, b = a + 1;
		const char *il = strstr(transport, "interleaved=");
		if (il && sscanf(il + 12, "%d-%d", &a, &b) < 1) a = is_audio ? 2 : 0;
		if (a < 0 || a > 254) a = is_audio ? 2 : 0;
		if (is_audio) {
			c->ach = a;
			c->audio = 1;
			random_bytes(&c->assrc, sizeof c->assrc);
			random_bytes(&c->aseq, sizeof c->aseq);
		} else {
			c->ch = a;
			c->video = 1;
		}
		if (!c->ready) {
			uint8_t r[8];
			random_bytes(r, sizeof r);
			for (int i = 0; i < 8; i++) snprintf(c->session + 2 * i, 3, "%02X", r[i]);
			random_bytes(&c->ssrc, sizeof c->ssrc);
			random_bytes(&c->seq, sizeof c->seq);
		}
		c->ready = 1;
		snprintf(extra, sizeof extra,
			 "Transport: RTP/AVP/TCP;unicast;interleaved=%d-%d;ssrc=%08X\r\n"
			 "Session: %s;timeout=%d\r\n", a, a + 1, (unsigned)(is_audio ? c->assrc : c->ssrc), c->session,
			 SESSION_TIMEOUT);
		reply(c, 200, "OK", cseq, extra, NULL);
	} else if (!strcmp(method, "PLAY") || !strcmp(method, "PAUSE")) {
		if (!c->ready || strcmp(sess, c->session)) {
			reply(c, c->ready ? 454 : 455, c->ready ? "Session Not Found"
				  : "Method Not Valid in This State", cseq, NULL, NULL);
			return;
		}
		int play = !strcmp(method, "PLAY");
		snprintf(extra, sizeof extra, "Session: %s\r\n%s", c->session,
			 play ? "Range: npt=0.000-\r\n" : "");
		reply(c, 200, "OK", cseq, extra, NULL);
		if (play && !c->playing) c->want_key = 1;
		c->playing = play;
		LOG("client %s %s\n", c->peer, play ? "playing" : "paused");
	} else if (!strcmp(method, "TEARDOWN")) {
		snprintf(extra, sizeof extra, "Session: %s\r\n", c->session);
		reply(c, 200, "OK", cseq, extra, NULL);
		c->playing = 0;
		c->closing = 1;
	} else if (!strcmp(method, "GET_PARAMETER") || !strcmp(method, "SET_PARAMETER")) {
		reply(c, 200, "OK", cseq, NULL, NULL);
	} else {
		reply(c, 501, "Not Implemented", cseq, NULL, NULL);
	}
}

/* A backchannel packet: the talker's go to the speaker; another client's audible packet takes
 * the speaker once the talker has been quiet for TALK_IDLE_MS. */
static void talk_in(struct client *c, const uint8_t *p, unsigned n)
{
	int peak = audio_rtp_in(p, n, NULL);
	if (peak < 0) return;
	long long now = mono_ms();
	if (talker != c) {
		if (peak < TALK_LOUD || (talker && now - talk_loud_ms < TALK_IDLE_MS)) return;
		talker = c;
		LOG("client %s talks to the speaker\n", c->peer);
	}
	if (peak >= TALK_LOUD) talk_loud_ms = now;
	audio_rtp_in(p, n, speaker_pcm);
}

/* Consume complete requests and interleaved packets (the client's RTCP) from c->in. Once the
 * client is closing (TEARDOWN, 5 wrong passwords, a full buffer...), nothing more it sent is
 * handled, not even requests already buffered behind the one that closed it: pipelining can't
 * get past the wrong-password limit. What arrives then is read and dropped (CLOSING_MS ends it). */
static void client_input(struct client *c)
{
	ssize_t n = recv(c->fd, c->in + c->in_len, IN_CAP - c->in_len, MSG_DONTWAIT);
	if (n == 0) { client_close(c, "peer closed"); return; }
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			client_close(c, strerror(errno));
		return;
	}
	c->in_len += (size_t)n;
	c->last = time(NULL);
	for (;;) {
		size_t used;
		if (c->closing) { c->in_len = 0; break; }
		if (c->in_len >= 1 && c->in[0] == '$') {
			if (c->in_len < 4) break;
			used = 4 + (((size_t)(uint8_t)c->in[2] << 8) | (uint8_t)c->in[3]);
			if (used > IN_CAP) { client_close(c, "oversized interleaved packet"); return; }
			if (c->in_len < used) break;
			if (c->talk && c->playing && (uint8_t)c->in[1] == c->tch)
				talk_in(c, (const uint8_t *)c->in + 4, (unsigned)(used - 4));
		} else {
			char *end = memmem(c->in, c->in_len, "\r\n\r\n", 4);
			if (!end) {
				if (c->in_len == IN_CAP) { client_close(c, "request too large"); return; }
				break;
			}
			used = (size_t)(end - c->in) + 4;
			char cl[16];
			*end = 0;
			hdr(c->in, "Content-Length", cl, sizeof cl);
			long body = atol(cl);
			if (body < 0 || used + (size_t)body > IN_CAP) {
				client_close(c, "bad Content-Length");
				return;
			}
			if (c->in_len < used + (size_t)body) { *end = '\r'; break; }
			used += (size_t)body;
			handle_request(c, c->in);
		}
		memmove(c->in, c->in + used, c->in_len - used);
		c->in_len -= used;
	}
	out_flush(c);
}

/* ---- RTP (RFC 7798) ------------------------------------------------------------------ */

struct nal { const uint8_t *p; size_t n; };

/* Split an Annex-B access unit into NAL units (start codes removed). */
static int split_nals(const uint8_t *b, size_t n, struct nal *out, int max)
{
	int count = 0;
	size_t i = 0, start = 0;
	int in_nal = 0;
	while (i + 3 <= n) {
		if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) {
			if (in_nal && count < max) {
				size_t e = i;
				while (e > start && b[e - 1] == 0) e--;      /* 4-byte start code / trailing zeros */
				out[count].p = b + start;
				out[count].n = e - start;
				count++;
			}
			i += 3;
			start = i;
			in_nal = 1;
		} else {
			i++;
		}
	}
	if (in_nal && start < n && count < max) {
		out[count].p = b + start;
		out[count].n = n - start;
		count++;
	}
	return count;
}

static void rtp_packet(struct client *c, const uint8_t *h, size_t hn, const uint8_t *p, size_t pn,
		       int marker, uint32_t ts)
{
	size_t len = 12 + hn + pn;
	uint8_t hd[4 + 12 + 3];
	hd[0] = '$';
	hd[1] = (uint8_t)c->ch;
	hd[2] = (uint8_t)(len >> 8);
	hd[3] = (uint8_t)len;
	hd[4] = 0x80;
	hd[5] = (uint8_t)((marker ? 0x80 : 0) | 96);
	hd[6] = (uint8_t)(c->seq >> 8);
	hd[7] = (uint8_t)c->seq;
	hd[8] = (uint8_t)(ts >> 24); hd[9] = (uint8_t)(ts >> 16); hd[10] = (uint8_t)(ts >> 8); hd[11] = (uint8_t)ts;
	hd[12] = (uint8_t)(c->ssrc >> 24); hd[13] = (uint8_t)(c->ssrc >> 16);
	hd[14] = (uint8_t)(c->ssrc >> 8); hd[15] = (uint8_t)c->ssrc;
	memcpy(hd + 16, h, hn);
	c->seq++;
	/* room was checked for the whole frame before the first packet */
	out_put(c, hd, 16 + hn);
	out_put(c, p, pn);
}

static void send_frame(struct client *c, int codec, const struct nal *nals, int count, size_t bytes,
		       int key, uint32_t ts)
{
	if (c->want_key && !key) return;
	size_t worst = bytes + (bytes / RTP_PAYLOAD + (size_t)count + 1) * 20;
	if ((size_t)out_room(c) < worst) {
		c->drops++;
		c->want_key = 1;
		return;
	}
	c->want_key = 0;
	for (int i = 0; i < count; i++) {
		const uint8_t *p = nals[i].p;
		size_t n = nals[i].n;
		int last = i == count - 1;
		if (n < 2) continue;
		if (n <= RTP_PAYLOAD) {
			rtp_packet(c, NULL, 0, p, n, last, ts);
			continue;
		}
		if (codec == MI_H264) {                                 /* RFC 6184 FU-A */
			uint8_t fa[2];
			fa[0] = (uint8_t)((p[0] & 0xe0) | 28);           /* FU indicator: F, NRI, type 28 */
			size_t off = 1;
			while (off < n) {
				size_t chunk = n - off > RTP_PAYLOAD ? RTP_PAYLOAD : n - off;
				int s = off == 1, e = off + chunk == n;
				fa[1] = (uint8_t)((s ? 0x80 : 0) | (e ? 0x40 : 0) | (p[0] & 0x1f));
				rtp_packet(c, fa, 2, p + off, chunk, last && e, ts);
				off += chunk;
			}
			continue;
		}
		if (n < 3) continue;
		uint8_t fu[3];
		fu[0] = (uint8_t)((p[0] & 0x81) | (49 << 1));       /* PayloadHdr: F, type 49, LayerId */
		fu[1] = p[1];                                       /* LayerId low, TID */
		uint8_t type = (p[0] >> 1) & 0x3f;
		size_t off = 2;
		while (off < n) {
			size_t chunk = n - off > RTP_PAYLOAD ? RTP_PAYLOAD : n - off;
			int s = off == 2, e = off + chunk == n;
			fu[2] = (uint8_t)((s ? 0x80 : 0) | (e ? 0x40 : 0) | type);
			rtp_packet(c, fu, 3, p + off, chunk, last && e, ts);
			off += chunk;
		}
	}
	out_flush(c);
}

/* One 40 ms PCMU frame to every playing client with the audio track set up (PT 0; the marker
 * bit on every packet, as stock). A client without room skips the frame. */
static void audio_emit(const uint8_t *f, uint32_t ts)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *c = &clients[i];
		if (c->fd < 0 || !c->playing || !c->audio || c->closing) continue;
		if (out_room(c) < AUDIO_FRAME + 16) continue;
		uint8_t hd[16];
		size_t len = 12 + AUDIO_FRAME;
		hd[0] = '$'; hd[1] = (uint8_t)c->ach; hd[2] = (uint8_t)(len >> 8); hd[3] = (uint8_t)len;
		hd[4] = 0x80; hd[5] = 0x80 | 0;
		hd[6] = (uint8_t)(c->aseq >> 8); hd[7] = (uint8_t)c->aseq;
		hd[8] = (uint8_t)(ts >> 24); hd[9] = (uint8_t)(ts >> 16); hd[10] = (uint8_t)(ts >> 8); hd[11] = (uint8_t)ts;
		hd[12] = (uint8_t)(c->assrc >> 24); hd[13] = (uint8_t)(c->assrc >> 16);
		hd[14] = (uint8_t)(c->assrc >> 8); hd[15] = (uint8_t)c->assrc;
		c->aseq++;
		out_put(c, hd, sizeof hd);
		out_put(c, f, AUDIO_FRAME);
		out_flush(c);
	}
}

static uint8_t frame[1 << 20], frame_sub[1 << 20];   /* the sub can be 720p (stream.sub.size): same cap as main */

/* JPEG snapshots (#75): the latest frame of the 1 fps JPEG channel; "snapshot" on the control
 * socket writes it to snap_path (atomically) for camhttpd's /snapshot.jpg. 0640: /run/cam is
 * setgid camctl (rtspd-prep), so a camhttpd that isn't root can read it through that group. */
static uint8_t snap[512 << 10], snap_rd[512 << 10];
static size_t snap_len;
static time_t snap_time;
static const char *snap_path = "/run/cam/snapshot.jpg";

static long long mono_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000LL + t.tv_nsec / 1000000 + MONO_ADJ_MS;
}

/* motion.* (#77): 0 if valid (stored in m), -1 if not */
static int motion_setting(struct motion_cfg *m, const char *k, const char *v)
{
	size_t n = strlen(v);
	int x = n >= 1 && n <= 3 && strspn(v, "0123456789") == n ? atoi(v) : -1;
	if (!strcmp(k, "motion.enabled") && (x == 0 || x == 1)) { m->enabled = x; return 0; }
	if (!strcmp(k, "motion.sensitivity") && x >= 0 && x <= 100) { m->sensitivity = x; return 0; }
	if (!strcmp(k, "motion.mask")) return motion_set_mask(v);       /* applied at once */
	return -1;
}

static void snap_frame(const uint8_t *p, size_t n)
{
	if (n < 4 || p[0] != 0xff || p[1] != 0xd8) return;      /* not a JPEG (SOI) */
	memcpy(snap, p, n);
	snap_len = n;
	snap_time = time(NULL);
}

static int snap_write(void)
{
	char tmp[256];
	snprintf(tmp, sizeof tmp, "%s.tmp", snap_path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0640);   /* /run/cam isn't root's */
	if (fd < 0) return -1;
	int ok = write(fd, snap, snap_len) == (ssize_t)snap_len;
	close(fd);
	if (!ok || rename(tmp, snap_path)) { unlink(tmp); return -1; }
	return 0;
}

static void on_frame(int si, const uint8_t *buf, size_t n)
{
	struct stream *st = &streams[si];
	struct nal nals[MAX_NALS];
	int count = split_nals(buf, n, nals, MAX_NALS), key = 0;
	for (int i = 0; i < count; i++) {
		int type = nal_type(st->codec, nals[i].p), slot = -1;
		if (st->codec == MI_H264) {
			if (type == 5) key = 1;                             /* IDR */
			if (type == 7 || type == 8) slot = type - 6;        /* SPS -> 1, PPS -> 2 */
		} else {
			if (type >= 16 && type <= 21) key = 1;              /* IRAP */
			if (type >= 32 && type <= 34) slot = type - 32;     /* VPS, SPS, PPS */
		}
		if (slot >= 0 && nals[i].n <= sizeof st->ps[0].d) {
			memcpy(st->ps[slot].d, nals[i].p, nals[i].n);
			st->ps[slot].n = nals[i].n;
		}
	}
	st->frames++;
	st->bytes += n;
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint32_t ts = (uint32_t)((uint64_t)t.tv_sec * 90000 + (uint64_t)t.tv_nsec / 11111);
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd >= 0 && clients[i].playing && !clients[i].closing &&
		    clients[i].video && clients[i].stream == si)
			send_frame(&clients[i], st->codec, nals, count, n, key, ts);
}

/* ---- control socket (#73) ------------------------------------------------------------ */

static const char *img_keys[MI_IMG_COUNT] = { "image.brightness", "image.contrast",
	"image.saturation", "image.sharpness", "image.exposure" };
static const char *htdigest_path;

/* auth_load, saying when the file has more users than auth.c keeps (they can't log in) */
static int users_load(const char *path)
{
	if (auth_load(path)) return -1;
	if (auth_skipped())
		LOG("%s: more than %d users; the %d after the first %d have no RTSP access\n", path,
		    AUTH_MAX_USERS, auth_skipped(), AUTH_MAX_USERS);
	return 0;
}

static int img_key(const char *k)
{
	for (int i = 0; i < MI_IMG_COUNT; i++)
		if (!strcmp(k, img_keys[i])) return i;
	return -1;
}

/* Orientation, shutter limits, anti-flicker, stock night tuning and the AE's ISP gain limits:
 * image.mirror / image.flip 0|1, image.shutter_day_max 0 or 100..1000000 us,
 * image.shutter_night_max 0 or 100..50000 us (0 = auto), image.antiflicker 0|1, image.mains_hz
 * 50|60, image.night_tuning 0|1, image.isp_gain_day_max / _night_max 1..4 (x; 4 / 2, as stock) (mi.h). */
enum { IX_MIRROR, IX_FLIP, IX_SHUTTER_DAY, IX_SHUTTER_NIGHT, IX_ANTIFLICKER, IX_MAINS, IX_NIGHT_TUNING, IX_ISP_DAY,
       IX_ISP_NIGHT, IX_N };
static const char *const ix_keys[IX_N] = { "image.mirror", "image.flip", "image.shutter_day_max",
	"image.shutter_night_max", "image.antiflicker", "image.mains_hz", "image.night_tuning",
	"image.isp_gain_day_max", "image.isp_gain_night_max" };

static int ix_key(const char *k)
{
	for (int i = 0; i < IX_N; i++)
		if (!strcmp(k, ix_keys[i])) return i;
	return -1;
}

/* The value v for key i, or -1 if it isn't a valid one */
static long ix_value(int i, const char *v)
{
	size_t n = strlen(v);
	long x = n >= 1 && n <= 7 && strspn(v, "0123456789") == n ? atol(v) : -1;
	if (i == IX_MIRROR || i == IX_FLIP || i == IX_ANTIFLICKER || i == IX_NIGHT_TUNING) return x == 0 || x == 1 ? x : -1;
	if (i == IX_MAINS) return x == 50 || x == 60 ? x : -1;
	if (i == IX_ISP_DAY || i == IX_ISP_NIGHT) return x >= 1 && x <= MI_ISP_GAIN_MAX ? x : -1;
	long max = i == IX_SHUTTER_DAY ? MI_DAY_SHUTTER_MAX_US : MI_NIGHT_SHUTTER_US;
	return x == 0 || (x >= MI_SHUTTER_MIN_US && x <= max) ? x : -1;
}

static void ix_store(struct mi_cfg *c, int i, long x)
{
	if (i == IX_MIRROR) c->mirror = (int)x;
	else if (i == IX_FLIP) c->flip = (int)x;
	else if (i == IX_SHUTTER_DAY) c->shutter_day_max = (uint32_t)x;
	else if (i == IX_SHUTTER_NIGHT) c->shutter_night_max = (uint32_t)x;
	else if (i == IX_ANTIFLICKER) c->antiflicker = (int)x;
	else if (i == IX_NIGHT_TUNING) c->night_tuning = (int)x;
	else if (i == IX_ISP_DAY) c->isp_gain_day_max = (int)x;
	else if (i == IX_ISP_NIGHT) c->isp_gain_night_max = (int)x;
	else c->mains_hz = (int)x;
}

/* The running values (mi), and a change applied live: 0, or -1 if MI refused it */
static void ix_current(struct mi_cfg *c)
{
	mi_orient_get(&c->mirror, &c->flip);
	mi_shutter_max_get(&c->shutter_day_max, &c->shutter_night_max);
	mi_antiflicker_get(&c->antiflicker, &c->mains_hz);
	c->night_tuning = mi_night_tuning_get();
	mi_isp_gain_max_get(&c->isp_gain_day_max, &c->isp_gain_night_max);
}

static int ix_apply(int i, long x)
{
	struct mi_cfg c;
	memset(&c, 0, sizeof c);
	ix_current(&c);
	ix_store(&c, i, x);
	if (i <= IX_FLIP) return mi_orient(c.mirror, c.flip);
	if (i <= IX_SHUTTER_NIGHT) return mi_shutter_max(c.shutter_day_max, c.shutter_night_max);
	if (i == IX_NIGHT_TUNING) return mi_night_tuning(c.night_tuning);
	if (i == IX_ISP_DAY || i == IX_ISP_NIGHT) return mi_isp_gain_max(c.isp_gain_day_max, c.isp_gain_night_max);
	return mi_antiflicker(c.antiflicker, c.mains_hz);
}

/* image.exposure_night: "day" (MI_EXPOSURE_SAME: follow image.exposure, the default) or 0..100 as
 * written (1 to 3 digits); -2 if neither */
static int exposure_night_value(const char *v)
{
	size_t n = strlen(v);
	if (!strcmp(v, "day")) return MI_EXPOSURE_SAME;
	int x = n >= 1 && n <= 3 && strspn(v, "0123456789") == n ? atoi(v) : -2;
	return x <= 100 ? x : -2;
}

/* ISP tuning (mi_tune_set): image.nr2d / nr3d 0..255 (128 = as tuned), image.wdr 0..255 (0 = as
 * tuned), image.blc 0..255 (with image.wdr 0; 0 = as tuned). Before the IQ profile is in, MI keeps
 * them. */
static const char *const tune_keys[MI_TUNE_COUNT] = { "image.nr2d", "image.nr3d", "image.wdr", "image.blc" };

static int tune_key(const char *k)
{
	for (int i = 0; i < MI_TUNE_COUNT; i++)
		if (!strcmp(k, tune_keys[i])) return i;
	return -1;
}

/* 0..255 as written (1 to 3 digits), else -1 */
static int tune_value(const char *v)
{
	size_t n = strlen(v);
	int x = n >= 1 && n <= 3 && strspn(v, "0123456789") == n ? atoi(v) : -1;
	return x <= 255 ? x : -1;
}

static const char *dn_mode_names[] = { "auto", "day", "night" };

/* A brightness score threshold (daynight.night_below / day_above): 1..1000000, else -1 */
static long dn_threshold(const char *v)
{
	size_t n = strlen(v);
	long t = n >= 1 && n <= 7 && strspn(v, "0123456789") == n ? atol(v) : -1;
	return t >= 1 && t <= 1000000 ? t : -1;
}

/* daynight.* (#30): 0 if the key and value are valid (and stored in d), -1 if not */
static int daynight_setting(struct dn_cfg *d, const char *k, const char *v)
{
	size_t n = strlen(v);
	int num = n >= 1 && n <= 3 && strspn(v, "0123456789") == n, x = num ? atoi(v) : -1;
	if (!strcmp(k, "daynight.mode")) {
		for (int i = 0; i < 3; i++)
			if (!strcmp(v, dn_mode_names[i])) { d->mode = i; return 0; }
		return -1;
	}
	if (!strcmp(k, "daynight.irled") && x >= 0 && x <= 100) { d->irled = x; return 0; }
	if (!strcmp(k, "daynight.source")) {
		if (!strcmp(v, "image")) { d->source = DN_SRC_IMAGE; return 0; }
		if (!strcmp(v, "sensor")) { d->source = DN_SRC_SENSOR; return 0; }
		return -1;
	}
	if (!strcmp(k, "daynight.night_below") || !strcmp(k, "daynight.day_above")) {
		long t = dn_threshold(v);
		if (t < 0) return -1;
		struct dn_cfg c = *d;
		*(!strcmp(k, "daynight.night_below") ? &c.night_below : &c.day_above) = (int)t;
		if (c.night_below >= c.day_above) return -1;    /* keep the hysteresis */
		*d = c;
		return 0;
	}
	if (!strcmp(k, "daynight.invert") && (x == 0 || x == 1)) { d->invert = x; return 0; }
	return -1;
}

/* time.tz (tz.h): the time zone the OSD clock shows; UTC0 until a valid one is set. */
static char cur_tz[TZ_BUF] = TZ_DEFAULT;

/* A valid TZ string becomes this process's TZ (setenv + tzset, so localtime_r sees it): 0, else -1
 * and nothing changes. */
static int tz_apply(const char *v)
{
	if (!tz_valid(v) || setenv("TZ", v, 1)) return -1;
	tzset();
	snprintf(cur_tz, sizeof cur_tz, "%s", v);
	return 0;
}

/* One command line in, the reply (ending "ok\n" or "err …\n") out. */
static void ctl_line(char *line, char *out, size_t cap)
{
	char cmd[16] = "", key[40] = "", val[16] = "", extra;
	int v = -1, n = 0;
	line[strcspn(line, "\r\n")] = 0;
	if (!strncmp(line, "set time.tz", 11) && (!line[11] || line[11] == ' ')) {   /* longer than val */
		if (tz_apply(line[11] ? line + 12 : "")) {
			snprintf(out, cap, "err time.tz: a POSIX TZ string of at most %d characters, e.g. "
				 "CST6CDT,M3.2.0,M11.1.0\n", TZ_LEN);
		} else {
			LOG("control: time.tz = %s\n", cur_tz);
			snprintf(out, cap, "ok\n");
		}
		return;
	}
	if (!strncmp(line, "set osd.title.text", 18) && (!line[18] || line[18] == ' ')) {   /* spaces */
		const char *t = line[18] ? line + 19 : "";
		if (osd_set("osd.title.text", t)) snprintf(out, cap, "err osd.title.text: printable ASCII, at most %d\n", OSD_TITLE_MAX);
		else { LOG("control: osd.title.text set\n"); snprintf(out, cap, "ok\n"); }
		return;
	}
	if (!strncmp(line, "set motion.mask ", 16)) {           /* 256 hex digits: too long for val */
		if (motion_set_mask(line + 16)) snprintf(out, cap, "err motion.mask: %d hex digits\n", MOTION_MASK_HEX);
		else { LOG("control: motion.mask set\n"); snprintf(out, cap, "ok\n"); }
		return;
	}
	int got = sscanf(line, "%15s %39s %15s %c", cmd, key, val, &extra);
	if (got == 3 && val[strspn(val, "0123456789")] == 0 && strlen(val) <= 3) v = atoi(val);
	if (got == 4) val[0] = 0;                       /* trailing junk */
	if (!strcmp(cmd, "get")) {
		for (int i = 0; i < MI_IMG_COUNT; i++)
			n += snprintf(out + n, cap - (size_t)n, "%s=%d\n", img_keys[i], mi_image_get(i));
		if (mi_exposure_night_get() == MI_EXPOSURE_SAME)
			n += snprintf(out + n, cap - (size_t)n, "image.exposure_night=day\n");
		else
			n += snprintf(out + n, cap - (size_t)n, "image.exposure_night=%d\n", mi_exposure_night_get());
		struct mi_cfg ic;
		memset(&ic, 0, sizeof ic);
		ix_current(&ic);
		n += snprintf(out + n, cap - (size_t)n, "%s=%d\n%s=%d\n%s=%u\n%s=%u\n%s=%d\n%s=%d\n", ix_keys[IX_MIRROR],
			      ic.mirror, ix_keys[IX_FLIP], ic.flip, ix_keys[IX_SHUTTER_DAY], ic.shutter_day_max,
			      ix_keys[IX_SHUTTER_NIGHT], ic.shutter_night_max, ix_keys[IX_ANTIFLICKER], ic.antiflicker,
			      ix_keys[IX_MAINS], ic.mains_hz);
		for (int i = 0; i < MI_TUNE_COUNT; i++)
			n += snprintf(out + n, cap - (size_t)n, "%s=%d\n", tune_keys[i], mi_tune_get(i));
		n += snprintf(out + n, cap - (size_t)n, "%s=%d\n%s=%d\n%s=%d\n", ix_keys[IX_NIGHT_TUNING], ic.night_tuning,
			      ix_keys[IX_ISP_DAY], ic.isp_gain_day_max, ix_keys[IX_ISP_NIGHT], ic.isp_gain_night_max);
		const struct dn_cfg *d = dn_get();
		n += snprintf(out + n, cap - (size_t)n, "daynight.mode=%s\ndaynight.irled=%d\n"
			      "daynight.invert=%d\ndaynight.source=%s\ndaynight.night_below=%d\n"
			      "daynight.day_above=%d\ndaynight.state=%s\ndaynight.raw=%d\ndaynight.score=%d\n",
			      dn_mode_names[d->mode], d->irled, d->invert,
			      d->source == DN_SRC_SENSOR ? "sensor" : "image", d->night_below, d->day_above,
			      dn_state() == DN_NIGHT ? "night" : dn_state() == DN_DAY ? "day" : "unknown", dn_raw(),
			      dn_score());
		/* the AE now: mean Y and its target (0..255), shutter (us), gains (1024 = 1x) */
		struct mi_ae_state ae;
		mi_ae_state(&ae);
		n += snprintf(out + n, cap - (size_t)n, "ae.y=%.1f\nae.target=%.1f\nae.shutter_us=%u\nae.sensor_gain=%u\n"
			      "ae.isp_gain=%u\n", ae.y, ae.target, ae.shutter_us, ae.sensor_gain, ae.isp_gain);
		const struct motion_cfg *mc = motion_get();
		char mh[MOTION_MASK_HEX + 1];
		motion_get_mask(mh);
		n += snprintf(out + n, cap - (size_t)n, "motion.enabled=%d\nmotion.sensitivity=%d\n"
			      "motion.grid=%dx%d\nmotion.mask=%s\naudio.on=%d\n", mc->enabled, mc->sensitivity,
			      MOTION_GRID_W, MOTION_GRID_H, mh, audio_on);
		n += (int)osd_get(out + n, cap - (size_t)n);
		if ((size_t)n < cap) n += snprintf(out + n, cap - (size_t)n, "time.tz=%s\n", cur_tz);
		if ((size_t)n < cap) snprintf(out + n, cap - (size_t)n, "ok\n");
	} else if (!strcmp(cmd, "set") && !strncmp(key, "osd.", 4)) {
		if (got != 3 || osd_set(key, val)) {
			snprintf(out, cap, "err osd.time|title.enabled 0|1, .pos ul|ur|ll|lr|custom, .x/.y 0..100, "
				 "osd.time.format, osd.time.12h|weekday 0|1, osd.size small|medium|large, osd.style "
				 "border|black-on-white|white-on-black\n");
		} else {
			LOG("control: %s = %s\n", key, val);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set") && !strncmp(key, "motion.", 7)) {
		struct motion_cfg m = *motion_get();
		if (motion_setting(&m, key, val)) {
			snprintf(out, cap, "err motion.enabled 0|1, motion.sensitivity 0..100\n");
		} else {
			motion_set(&m);
			LOG("control: %s = %s\n", key, val);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set") && !strncmp(key, "daynight.", 9)) {
		struct dn_cfg d = *dn_get();
		if (daynight_setting(&d, key, val)) {
			snprintf(out, cap, "err daynight.mode auto|day|night, irled 0..100, invert 0|1, "
				 "source image|sensor, night_below < day_above (1..1000000)\n");
		} else {
			dn_set(&d);
			LOG("control: %s = %s\n", key, val);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set") && ix_key(key) >= 0) {
		int i = ix_key(key);
		long x = got == 3 ? ix_value(i, val) : -1;
		if (x < 0 && i == IX_NIGHT_TUNING)
			snprintf(out, cap, "err image.night_tuning 0|1\n");
		else if (x < 0 && (i == IX_ISP_DAY || i == IX_ISP_NIGHT))
			snprintf(out, cap, "err image.isp_gain_day_max|isp_gain_night_max 1..%d (x)\n", MI_ISP_GAIN_MAX);
		else if (x < 0)
			snprintf(out, cap, "err image.mirror|flip 0|1, image.shutter_day_max 0|100..1000000, "
				 "image.shutter_night_max 0|100..50000 (us, 0 = auto), image.antiflicker 0|1, "
				 "image.mains_hz 50|60\n");
		else if (ix_apply(i, x))
			snprintf(out, cap, i == IX_NIGHT_TUNING && x && !mi_night_tuning_get() ?
				 "err image.night_tuning: no usable night tuning files in this image\n" : "err apply failed\n");
		else {
			LOG("control: %s = %ld\n", key, x);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set") && !strcmp(key, "image.exposure_night")) {
		int x = got == 3 ? exposure_night_value(val) : -2;
		if (x < -1) snprintf(out, cap, "err image.exposure_night day (as image.exposure) or 0..100\n");
		else if (mi_exposure_night(x)) snprintf(out, cap, "err apply failed\n");
		else {
			LOG("control: %s = %s\n", key, val);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set") && tune_key(key) >= 0) {
		int x = got == 3 ? tune_value(val) : -1;
		if (x < 0) snprintf(out, cap, "err image.nr2d|nr3d|wdr|blc 0..255\n");
		else if (mi_tune_set(tune_key(key), x)) snprintf(out, cap, "err apply failed\n");
		else {
			LOG("control: %s = %d\n", key, x);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "set")) {
		int k = img_key(key);
		if (k < 0) snprintf(out, cap, "err unknown key\n");
		else if (v < 0 || v > 100) snprintf(out, cap, "err value must be 0..100\n");
		else if (mi_image_set(k, v)) snprintf(out, cap, "err apply failed\n");
		else {
			LOG("control: %s = %d\n", key, v);
			snprintf(out, cap, "ok\n");
		}
	} else if (!strcmp(cmd, "motion") && (!strcmp(key, "map") || !strcmp(key, "luma") || !strcmp(key, "noise"))) {
		if (motion_map(out, cap, !strcmp(key, "luma") ? 1 : !strcmp(key, "noise") ? 2 : 0))
			snprintf(out, cap, "err map too large\n");
	} else if (!strcmp(cmd, "motion")) {
		unsigned sq;
		long long since;
		int st = motion_state(&sq, &since);
		snprintf(out, cap, "motion.state=%d\nmotion.seq=%u\nmotion.since=%lld\nmotion.cells=%d\n"
			 "motion.peak=%d\nmotion.need=%d\nok\n", st, sq, (mono_ms() - since) / 1000,
			 motion_cells(), motion_peak(), motion_need());
	} else if (!strcmp(cmd, "snapshot")) {
		if (!snap_len || time(NULL) - snap_time > 5) snprintf(out, cap, "err no recent snapshot\n");
		else if (snap_write()) snprintf(out, cap, "err can't write %s\n", snap_path);
		else snprintf(out, cap, "ok %zu\n", snap_len);
	} else if (!strcmp(cmd, "restart")) {           /* stream settings: init starts us again */
		LOG("control: restart requested\n");
		stop = 1;
		snprintf(out, cap, "ok\n");
	} else if (!strcmp(cmd, "auth-reload")) {
		if (!htdigest_path) snprintf(out, cap, "err no -a file\n");
		else if (users_load(htdigest_path)) snprintf(out, cap, "err %s unusable, kept old users\n",
							    htdigest_path);
		else {
			LOG("control: users reloaded\n");
			snprintf(out, cap, "ok\n");
		}
	} else {
		snprintf(out, cap, "err unknown command\n");
	}
}

static int ctl_listen(const char *path)
{
	struct sockaddr_un a;
	if (!path || !*path || strlen(path) >= sizeof a.sun_path) return -1;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strcpy(a.sun_path, path);
	unlink(path);
	mode_t old = umask(077);                      /* the socket file: root only */
	int r = bind(fd, (struct sockaddr *)&a, sizeof a);
	umask(old);
	if (r || listen(fd, 2)) {
		int e = errno;
		LOG("control socket %s: %s\n", path, strerror(e));
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

/* The socket file's owner and group (-U, -G; (uid_t)-1 / (gid_t)-1 = leave it): 0660 with a
 * group, else 0600. Root's clients (camcfg, and camhttpd for now) connect whatever the owner and
 * mode: connect() needs write permission on the file (unix(7)), which root's CAP_DAC_OVERRIDE
 * covers. 0, or -1. */
static int ctl_perm(const char *path, uid_t uid, gid_t gid)
{
	if (uid == (uid_t)-1 && gid == (gid_t)-1) return 0;
	if (chown(path, uid, gid) || chmod(path, gid != (gid_t)-1 ? 0660 : 0600)) {
		LOG("control socket %s: owner/mode: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static void ctl_serve(int lfd)
{
	int fd = accept(lfd, NULL, NULL);
	if (fd < 0) return;
	struct timeval tv = { 0, 300000 };             /* a stuck client can't hold the loop */
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	char line[512], out[4096];                     /* get: ~1.6 KiB with the motion mask and OSD */
	ssize_t n = recv(fd, line, sizeof line - 1, 0);
	if (n > 0) {
		line[n] = 0;
		ctl_line(line, out, sizeof out);
		if (send(fd, out, strlen(out), MSG_NOSIGNAL) < 0) { /* client gone */ }
	}
	close(fd);
}

/* Stream settings in cam.conf (#79/#80 UI later; owner 2026-10-23: H.264 by default for both,
 * Surveillance Station's event detection can't use H.265). Out-of-range values are ignored.
 * size: streamcfg.h's sizes only; the sub's only while the sub-stream is on (stream.sub.enabled=0
 * or -s 0 keep it off, in any line order). */
static int stream_setting(struct mi_cfg *cfg, const char *k, const char *v)
{
	int sub = !strncmp(k, "stream.sub.", 11), n = atoi(v);
	if (!sub && strncmp(k, "stream.main.", 12)) return 0;
	k += sub ? 11 : 12;
	if (!strcmp(k, "codec")) {
		if (strcmp(v, "h264") && strcmp(v, "h265")) return -1;
		*(sub ? &cfg->sub_codec : &cfg->codec) = !strcmp(v, "h264") ? MI_H264 : MI_H265;
	} else if (!strcmp(k, "kbps")) {
		if (n < 64 || n > 16384) return -1;
		*(sub ? &cfg->sub_kbps : &cfg->kbps) = n;
	} else if (!strcmp(k, "fps")) {
		if (n < 1 || n > STREAM_FPS_MAX) return -1;
		*(sub ? &cfg->sub_fps : &cfg->fps) = n;
	} else if (!strcmp(k, "size")) {
		const struct stream_size *s = stream_size_find(sub, v);
		if (!s) return -1;
		if (!sub) { cfg->w = s->w; cfg->h = s->h; }
		else if (cfg->sub_w) { cfg->sub_w = s->w; cfg->sub_h = s->h; }
	} else if (!strcmp(k, "gop")) {
		if (n < 1 || n > 1000) return -1;
		*(sub ? &cfg->sub_gop : &cfg->gop) = n;
	} else if (!strcmp(k, "rc")) {
		if (strcmp(v, "cbr") && strcmp(v, "vbr")) return -1;
		*(sub ? &cfg->sub_rc : &cfg->rc) = !strcmp(v, "vbr") ? MI_RC_VBR : MI_RC_CBR;
	} else if (!strcmp(k, "profile")) {
		int p = !strcmp(v, "high") ? MI_PROFILE_HIGH : !strcmp(v, "main") ? MI_PROFILE_MAIN :
			!strcmp(v, "baseline") ? MI_PROFILE_BASELINE : -1;
		if (p < 0) return -1;
		*(sub ? &cfg->sub_profile : &cfg->profile) = p;
	} else if (sub && !strcmp(k, "enabled")) {
		if (strcmp(v, "0") && strcmp(v, "1")) return -1;
		if (!n) cfg->sub_w = cfg->sub_h = 0;
	} else {
		return -1;
	}
	return 0;
}

/* Once the command line and cam.conf are in: an unset bit rate (0) follows its stream's size
 * (streamcfg.h); a sub-stream bigger than the main picture is off (only -w/-h/-s can ask for
 * one); the sub-stream runs at most at the main's frame rate (SCL port 1 gets the main's frames,
 * and the bind can only drop some). */
static void stream_resolve(struct mi_cfg *cfg)
{
	if (!cfg->kbps) cfg->kbps = stream_kbps_default(0, cfg->w, cfg->h);
	if (cfg->sub_w && (cfg->sub_w > cfg->w || cfg->sub_h > cfg->h)) {
		LOG("rtspd: sub-stream %dx%d is bigger than the main %dx%d: no sub-stream\n", cfg->sub_w,
		    cfg->sub_h, cfg->w, cfg->h);
		cfg->sub_w = cfg->sub_h = 0;
	}
	if (!cfg->sub_kbps) cfg->sub_kbps = stream_kbps_default(1, cfg->sub_w, cfg->sub_h);
	if (cfg->sub_w && cfg->sub_fps > cfg->fps) {
		LOG("rtspd: sub-stream fps %d is above the main's %d: it runs at %d\n", cfg->sub_fps, cfg->fps,
		    cfg->fps);
		cfg->sub_fps = cfg->fps;
	}
}

/* cam.conf: stream.*, image.mirror/flip, the shutter limits, anti-flicker, night tuning and the ISP gain
 * limits go into cfg (before the pipeline starts), daynight.* into dn, image.exposure_night into MI at
 * once (it only steers the AE target), the other image.* (levels, NR, WDR, BLC) are queued
 * until the IQ is in; time.tz becomes TZ at once (a leftover osd.tz_offset, which it replaced, is
 * skipped with a hint when there's no time.tz). Settings win over
 * the command line. The day/night thresholds are checked as a pair once the file is read (camcfg
 * keeps night_below < day_above, in whatever order the lines are). */
static void load_settings(const char *path, struct mi_cfg *cfg, struct dn_cfg *dn)
{
	FILE *f = fopen(path, "r");
	if (!f) return;
	char line[512];
	long nb = dn->night_below, da = dn->day_above;
	int old_tz = 0, new_tz = 0;
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\r\n")] = 0;
		char *eq = strchr(line, '=');
		if (!eq) continue;
		*eq = 0;
		int k = img_key(line), ix = ix_key(line), tk = tune_key(line);
		long t = -1;
		if (k >= 0) mi_image_set(k, atoi(eq + 1));
		else if (tk >= 0) {
			if ((t = tune_value(eq + 1)) < 0) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
			else mi_tune_set(tk, (int)t);
		}
		else if (ix >= 0) {
			if ((t = ix_value(ix, eq + 1)) < 0) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
			else ix_store(cfg, ix, t);
		} else if (!strcmp(line, "daynight.night_below") || !strcmp(line, "daynight.day_above")) {
			if ((t = dn_threshold(eq + 1)) < 0) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
			else *(!strcmp(line, "daynight.night_below") ? &nb : &da) = t;
		} else if (!strcmp(line, "image.exposure_night")) {
			if ((t = exposure_night_value(eq + 1)) < -1) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
			else mi_exposure_night((int)t);
		}
		else if (!strcmp(line, "snapshot.quality") && atoi(eq + 1) >= 10 && atoi(eq + 1) <= 99)
			cfg->snapshot_q = atoi(eq + 1);
		else if (!strcmp(line, "snapshot.enabled") && (!strcmp(eq + 1, "0") || !strcmp(eq + 1, "1")))
			cfg->snapshot = atoi(eq + 1);
		else if (!strcmp(line, "audio.enabled") && (!strcmp(eq + 1, "0") || !strcmp(eq + 1, "1")))
			audio_cfg_on = atoi(eq + 1);
		else if (!strcmp(line, "audio.gain") && strspn(eq + 1, "0123456789") == strlen(eq + 1) &&
			 strlen(eq + 1) && strlen(eq + 1) <= 2 && atoi(eq + 1) <= 19)
			audio_gain = atoi(eq + 1);
		else if (!strncmp(line, "motion.", 7)) {
			struct motion_cfg m = *motion_get();
			if (motion_setting(&m, line, eq + 1)) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
			else motion_set(&m);
		} else if (!strncmp(line, "daynight.", 9)) {
			if (daynight_setting(dn, line, eq + 1)) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
		} else if (!strcmp(line, "osd.tz_offset")) {
			old_tz = 1;                       /* gone: time.tz replaced it (2026-10-23) */
		} else if (!strncmp(line, "osd.", 4)) {
			if (osd_set(line, eq + 1)) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
		} else if (!strcmp(line, "time.tz")) {
			if (tz_apply(eq + 1)) LOG("%s: ignored %s=%s (not a POSIX TZ string)\n", path, line, eq + 1);
			else new_tz = 1;
		} else if (stream_setting(cfg, line, eq + 1) < 0) LOG("%s: ignored %s=%s\n", path, line, eq + 1);
	}
	fclose(f);
	if (old_tz && !new_tz)
		LOG("%s: osd.tz_offset is no longer used; set the time zone on the web UI's Time page "
		    "(time.tz), and drop the old line with: camcfg unset osd.tz_offset\n", path);
	if (nb < da) {
		dn->night_below = (int)nb;
		dn->day_above = (int)da;
	} else {
		LOG("%s: ignored daynight.night_below=%ld / day_above=%ld (night_below must be below day_above)\n",
		    path, nb, da);
	}
}

/* ---- main ---------------------------------------------------------------------------- */

static long rss_kb(void)
{
	FILE *f = fopen("/proc/self/statm", "r");
	long pages = 0, res = 0;
	if (f) {
		if (fscanf(f, "%ld %ld", &pages, &res) != 2) res = 0;
		fclose(f);
	}
	return res * (sysconf(_SC_PAGESIZE) / 1024);
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

/* A new connection (fd, from ip, "a.b.c.d:port" for the log) takes a slot, or is closed and NULL
 * returned. At most PER_IP_UNAUTHED connections per address may be waiting to log in; with every
 * slot taken, the oldest connection that hasn't logged in is evicted for it (a logged-in one,
 * the NVR's, never is), so connections that never log in can't lock everyone out. */
static struct client *client_admit(int fd, struct in_addr ip, const char *peer)
{
	struct client *c = NULL, *oldest = NULL;
	int same = 0;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		struct client *o = &clients[i];
		if (o->fd < 0) { if (!c) c = o; continue; }
		if (client_authed(o)) continue;
		if (o->ip.s_addr == ip.s_addr) same++;
		if (!oldest || o->since_ms < oldest->since_ms) oldest = o;
	}
	if (same >= PER_IP_UNAUTHED) {
		LOG("client %s refused: %d connections from it not logged in yet\n", peer, same);
		close(fd);
		return NULL;
	}
	if (!c && oldest) {
		client_close(oldest, "evicted: not logged in, and every slot taken");
		c = oldest;
	}
	if (!c) {
		LOG("client %s refused: %d clients already\n", peer, MAX_CLIENTS);
		close(fd);
		return NULL;
	}
	/* the whole slot, so nothing (tracks, channels, talk, auth) carries over from the last
	 * client; the 1 MiB output buffer is left alone, out_off/out_len = 0 make it empty */
	memset(c, 0, offsetof(struct client, out));
	memset((char *)c + offsetof(struct client, out_off), 0,
	       sizeof *c - offsetof(struct client, out_off));
	uint8_t r[16];
	random_bytes(r, sizeof r);
	for (int i = 0; i < 16; i++) snprintf(c->nonce + 2 * i, 3, "%02x", r[i]);
	c->fd = fd;
	c->ip = ip;
	c->last = time(NULL);
	c->since_ms = mono_ms();
	snprintf(c->peer, sizeof c->peer, "%s", peer);
	LOG("client %s connected\n", c->peer);
	return c;
}

static void accept_client(int lfd)
{
	struct sockaddr_in pa;
	socklen_t pl = sizeof pa;
	int fd = accept(lfd, (struct sockaddr *)&pa, &pl);
	if (fd < 0) return;
	char peer[48];
	inet_ntop(AF_INET, &pa.sin_addr, peer, sizeof peer);
	snprintf(peer + strlen(peer), sizeof peer - strlen(peer), ":%u", ntohs(pa.sin_port));
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	int sndbuf = 256 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
	client_admit(fd, pa.sin_addr, peer);
}

/* ---- RTSPS through camtls (-t) --------------------------------------------------------
 * camtls ends TLS on port 322 and connects to this UNIX socket once per client. A connection
 * from any other uid is closed at once. One from camtls waits here, outside the client slots and
 * under the placeholder "camtls", until its PROXY line is in (PROXY_MS from accept, else closed);
 * then it goes through client_admit under the client's address like a connection on the port
 * (PER_IP_UNAUTHED, eviction, and the lockout keyed by c->ip), with LOGIN_MS counted from the
 * accept here. A PROXY line on the port is never taken: there it is an ordinary bad request. */
#define TLS_WAITING MAX_CLIENTS
static const char *tls_path;            /* -t PATH */
static uid_t tls_uid;                   /* -t USER: the only peer */
static gid_t tls_gid;                   /* the socket file's group */
static struct { int on, fd; long long since_ms; size_t len; char line[PROXY_MAX]; } tls_wait[TLS_WAITING];

/* -t PATH:USER, USER a name in passwd_path or UID:GID (drop_lookup): 0, or -1 with *why. */
static int tls_option(const char *opt, const char *passwd_path, const char *group_path, const char **why)
{
	static char path[sizeof ((struct sockaddr_un *)0)->sun_path];
	const char *colon = strchr(opt, ':');
	struct drop_id id;
	if (!colon || colon == opt || (size_t)(colon - opt) >= sizeof path) {
		*why = "PATH:USER wanted, PATH shorter than a socket path's limit";
		return -1;
	}
	if (drop_lookup(colon + 1, passwd_path, group_path, &id, why)) return -1;
	memcpy(path, opt, (size_t)(colon - opt));
	path[colon - opt] = 0;
	tls_path = path;
	tls_uid = id.uid;
	tls_gid = id.gid;
	return 0;
}

/* The listening socket: made as root, 0660 root:tls_gid, non-blocking; the fd, or -1 (logged). */
static int tls_listen(const char *path, gid_t gid)
{
	struct sockaddr_un a;
	if (strlen(path) >= sizeof a.sun_path) { LOG("tls socket %s: path too long; no RTSPS\n", path); return -1; }
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) { LOG("tls socket %s: %s; no RTSPS\n", path, strerror(errno)); return -1; }
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strcpy(a.sun_path, path);
	unlink(path);                                   /* a stale one from the last run */
	mode_t old = umask(077);                        /* nobody gets in before the chmod */
	int r = bind(fd, (struct sockaddr *)&a, sizeof a);
	umask(old);
	if (r || chown(path, (uid_t)-1, gid) || chmod(path, 0660) || listen(fd, TLS_WAITING)) {
		int e = errno;
		LOG("tls socket %s: %s; no RTSPS\n", path, strerror(e));
		if (!r) unlink(path);
		close(fd);
		errno = e;
		return -1;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	return fd;
}

/* A connection on the socket: camtls's uid only; it waits for its PROXY line. */
static void tls_take(int fd)
{
	uid_t u;
	int i = 0;
	if (PEER_UID(fd, &u) || u != tls_uid) {
		LOG("tls socket: a peer that isn't uid %u: closed\n", (unsigned)tls_uid);
		close(fd);
		return;
	}
	while (i < TLS_WAITING && tls_wait[i].on) i++;
	if (i == TLS_WAITING) {
		LOG("tls socket: %d connections already waiting for their PROXY line: closed\n", TLS_WAITING);
		close(fd);
		return;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	int sndbuf = TLS_SNDBUF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
	tls_wait[i].on = 1;
	tls_wait[i].fd = fd;
	tls_wait[i].since_ms = mono_ms();
	tls_wait[i].len = 0;
}

static void tls_accept(int lfd)
{
	int fd = accept(lfd, NULL, NULL);
	if (fd >= 0) tls_take(fd);
}

static void tls_drop(int i, const char *why)
{
	LOG("tls socket: connection closed: %s\n", why);
	close(tls_wait[i].fd);
	tls_wait[i].on = 0;
}

/* Bytes on a waiting connection: the PROXY line only (peeked, then read up to its LF, so the
 * client's first request stays in the socket); once complete, the client takes a slot. */
static void tls_proxy_in(int i)
{
	char *b = tls_wait[i].line + tls_wait[i].len;
	ssize_t n = recv(tls_wait[i].fd, b, PROXY_MAX - tls_wait[i].len, MSG_PEEK | MSG_DONTWAIT);
	if (n == 0) { tls_drop(i, "closed before its PROXY line"); return; }
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) tls_drop(i, strerror(errno));
		return;
	}
	const char *lf = memchr(b, '\n', (size_t)n);
	size_t take = lf ? (size_t)(lf - b) + 1 : (size_t)n;
	if (recv(tls_wait[i].fd, b, take, MSG_DONTWAIT) != (ssize_t)take) { tls_drop(i, "short read"); return; }
	tls_wait[i].len += take;
	struct in_addr src, dst;
	uint16_t sport, dport;
	size_t used;
	int r = proxy_parse(tls_wait[i].line, tls_wait[i].len, &src, &dst, &sport, &dport, &used);
	if (r == 0) return;
	if (r < 0) { tls_drop(i, "not a PROXY TCP4 line"); return; }
	char peer[48];
	inet_ntop(AF_INET, &src, peer, sizeof peer);
	snprintf(peer + strlen(peer), sizeof peer - strlen(peer), ":%u (TLS)", (unsigned)sport);
	int fd = tls_wait[i].fd;
	long long since = tls_wait[i].since_ms;
	tls_wait[i].on = 0;
	struct client *c = client_admit(fd, src, peer);
	if (!c) return;
	c->tls = 1;
	c->local = dst;
	c->lport = dport;
	c->since_ms = since;                            /* LOGIN_MS from the accept */
}

/* Waiting connections without a whole PROXY line after PROXY_MS: closed. */
static void tls_tick(long long now_ms)
{
	for (int i = 0; i < TLS_WAITING; i++)
		if (tls_wait[i].on && now_ms - tls_wait[i].since_ms > PROXY_MS)
			tls_drop(i, "no PROXY line in time");
}

/* Deadlines, every loop: LOGIN_MS to log in however much is sent; a closing client gets
 * CLOSING_MS to read its last reply, however much it sends; SESSION_TIMEOUT s idle. */
static void client_tick(struct client *c, long long now_ms, time_t t)
{
	if (c->fd < 0) return;
	if (!client_authed(c) && now_ms - c->since_ms > LOGIN_MS) {
		client_close(c, "not logged in in time");
		return;
	}
	if (c->closing && !c->closing_ms) c->closing_ms = now_ms;
	if (c->closing && now_ms - c->closing_ms > CLOSING_MS) {
		client_close(c, "closing, reply not read");
		return;
	}
	if (t - c->last > SESSION_TIMEOUT) client_close(c, "timeout");
}

int main(int argc, char **argv)
{
	/* NV12 ISP output: with YUYV the ISP's later YUV stages (saturation…) never reach the
	 * picture (#36). AE target 40 matches stock's brightness with stock's IQ applied.
	 * Streams as the owner's stock settings: H.264 High profile VBR both, main 2560x1440 4000 kbps,
	 * sub 640x360 500 kbps, keyframe every 100 frames; 30 fps, the sensor's (owner 2026-10-25).
	 * kbps 0 = by size (stream_resolve, streamcfg.h). */
	struct mi_cfg cfg = { .w = 2560, .h = 1440, .kbps = 0, .fps = STREAM_FPS_DEFAULT, .gop = 100, .ring = 1,
			      .auto3a = 1, .ae_target = 40, .isp_outfmt = 11, .codec = MI_H264,
			      .sub_w = 640, .sub_h = 360, .sub_kbps = 0, .sub_fps = STREAM_FPS_DEFAULT, .sub_gop = 100,
			      .sub_codec = MI_H264, .rc = MI_RC_VBR, .sub_rc = MI_RC_VBR,
			      .profile = MI_PROFILE_HIGH, .sub_profile = MI_PROFILE_HIGH,
			      .snapshot = 1, .snapshot_q = 80,
			      /* image.isp_gain_*_max unset: stock's MaxISPGain, 4x by day, 2x at night */
			      .isp_gain_day_max = MI_ISP_GAIN_DAY_DEFAULT, .isp_gain_night_max = MI_ISP_GAIN_NIGHT_DEFAULT };
	const char *addr = "0.0.0.0", *htdigest = NULL, *settings = NULL, *ctl_path = "/run/camd.sock";
	const char *user = NULL, *ctl_group = NULL, *tls_opt = NULL;
	int port = 554, c, no_auth = 0, daynight = 1;   /* stock and SSS use 554 */
	while ((c = getopt(argc, argv, "a:Ni:u:p:l:w:h:b:f:c:s:d:k:g:o:O:nFT:e:W:X:Q:q:C:P:U:G:t:v")) != -1) {
		switch (c) {
		case 'U': user = optarg; break;
		case 'G': ctl_group = optarg; break;
		case 't': tls_opt = optarg; break;
		case 'a': htdigest = optarg; break;
		case 'N': no_auth = 1; break;
		case 'i': settings = optarg; break;
		case 'u': ctl_path = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'l': addr = optarg; break;
		case 'w': cfg.w = atoi(optarg); break;
		case 'h': cfg.h = atoi(optarg); break;
		case 'b': cfg.kbps = atoi(optarg); break;
		case 'f': cfg.fps = atoi(optarg); break;
		case 'c': cfg.codec = !strcmp(optarg, "h264") ? MI_H264 : MI_H265; break;
		case 's':
			if (sscanf(optarg, "%dx%d", &cfg.sub_w, &cfg.sub_h) != 2) cfg.sub_w = cfg.sub_h = 0;
			break;
		case 'd': cfg.sub_codec = !strcmp(optarg, "h265") ? MI_H265 : MI_H264; break;
		case 'k': cfg.sub_kbps = atoi(optarg); break;
		case 'g': cfg.sub_fps = atoi(optarg); break;
		case 'o': cfg.gop = atoi(optarg); break;
		case 'O': cfg.sub_gop = atoi(optarg); break;
		case 'F': cfg.ring = 0; break;
		case 'n': daynight = 0; break;
		case 'T': cfg.ae_target = atof(optarg); break;
		case 'e': sscanf(optarg, "%u:%u", &cfg.shutter_us, &cfg.gain); break;
		case 'W': sscanf(optarg, "%u:%u:%u", &cfg.wb_r, &cfg.wb_g, &cfg.wb_b); break;
		case 'X': cfg.ae_extra = optarg; break;
		case 'Q': cfg.iq_profile = optarg; break;
		case 'q': {                                     /* NIGHT,DAY */
			char *comma = strchr(optarg, ',');
			if (comma) { *comma = 0; cfg.iq_night = optarg; cfg.iq_day = comma + 1; }
			else fprintf(stderr, "-q wants NIGHT,DAY; night tuning unavailable\n");
			break;
		}
		case 'C': cfg.cus3a = optarg; break;
		case 'P': cfg.isp_outfmt = atoi(optarg); break;
		case 'v': mi_verbose++; break;
		default:
			fprintf(stderr, "usage: %s (-a htdigest | -N) [-i cam.conf] [-u ctl-socket] [-p port] [-l addr] [-w W -h H] [-b kbps] [-f fps] "
				"[-c h264|h265] [-o gop] [-s WxH|0] [-d h264|h265] [-k kbps] [-g fps] [-O gop] [-n] [-F] "
				"[-T y] [-e us:gain] [-W r:g:b] [-X ae-fields] [-Q iq-profile] [-q night.bin,day.bin] [-C ae:awb:af] "
				"[-P isp-outfmt] [-U user|uid:gid] [-G ctl-group] [-t tls-socket:user] [-v]\n", argv[0]);
			return 2;
		}
	}
	/* -U / -G before anything starts: a user or group that isn't there stops rtspd here */
	struct drop_id who = { .ngroups = 0 };
	gid_t ctl_gid = (gid_t)-1;
	const char *why = "";
	if (user && drop_lookup(user, "/etc/passwd", "/etc/group", &who, &why)) {
		fprintf(stderr, "-U %s: %s\n", user, why);
		return 2;
	}
	if (ctl_group && drop_group(ctl_group, "/etc/group", &ctl_gid, &why)) {
		fprintf(stderr, "-G %s: %s\n", ctl_group, why);
		return 2;
	}
	/* -t: never fatal, the port streams whatever happens to RTSPS */
	if (tls_opt && tls_option(tls_opt, "/etc/passwd", "/etc/group", &why))
		LOG("-t %s: %s; no RTSPS\n", tls_opt, why);
	if (htdigest) {
		htdigest_path = htdigest;
		if (users_load(htdigest)) {
			fprintf(stderr, "%s: no usable user:realm:HA1 lines\n", htdigest);
			return 1;
		}
	} else if (!no_auth) {
		fprintf(stderr, "refusing to start without authentication: give -a htdigest, or -N\n");
		return 2;
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	signal(SIGPIPE, SIG_IGN);
	for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;

	struct dn_cfg dn = DN_CFG_DEFAULT;              /* stock IR LED 96 %; follow the picture */
	tz_apply(TZ_DEFAULT);                           /* UTC until time.tz, whatever TZ we inherited */
	if (settings) load_settings(settings, &cfg, &dn);   /* stream.* now; image.* once the IQ is in */
	stream_resolve(&cfg);
	streams[0].on = 1;
	streams[0].codec = cfg.codec;
	streams[1].on = cfg.sub_w > 0;
	streams[1].codec = cfg.sub_codec;
	int lfd = listen_on(addr, port);
	if (lfd < 0) return 1;
	int cfd = ctl_listen(ctl_path);
	if (cfd >= 0) ctl_perm(ctl_path, user ? who.uid : (uid_t)-1, ctl_gid);
	int tfd = tls_path ? tls_listen(tls_path, tls_gid) : -1;    /* before the drop: /run/rtspd is root's */
	if (tfd >= 0) LOG("rtspd: RTSPS through camtls on %s (uid %u only)\n", tls_path, (unsigned)tls_uid);
	osd_enable();                                  /* regions attach inside mi_start */
	if (mi_start(&cfg)) { osd_stop(); mi_stop(); return 1; }
	if (daynight) dn_init("/dev/irled", "/sys/class/pwm/pwmchip4", &dn);
	if (audio_cfg_on) {
		if (mi_audio_start(audio_gain)) LOG("audio: microphone not started; streams without audio\n");
		else {
			uint32_t ts0;
			random_bytes(&ts0, sizeof ts0);
			audio_reset(ts0);
			audio_on = 1;
		}
	}
	if (audio_cfg_on) {                                     /* the speaker, for ONVIF talk (#117) */
		if (mi_ao_start()) LOG("audio: speaker not started; no backchannel\n");
		else speaker_on = 1;
	}
	int afd = audio_on ? mi_audio_fd() : -1;
	int vfd[NSTREAMS] = { mi_venc_fd(0), mi_venc_fd(1) }, jfd = mi_venc_fd(2), ffd, unused;
	mi_fds(&unused, &ffd);
	LOG("rtspd: main %dx%d %d fps %d kbps %s on rtsp://%s:%d/ (RTP over TCP), %s\n", cfg.w, cfg.h,
	    cfg.fps, cfg.kbps, cfg.codec == MI_H264 ? "H.264" : "H.265", addr, port,
	    auth_enabled() ? "Digest auth" : "NO AUTH");
	if (streams[1].on)
		LOG("rtspd: sub %dx%d %d fps %d kbps %s on rtsp://%s:%d/sub\n", cfg.sub_w, cfg.sub_h,
		    cfg.sub_fps, cfg.sub_kbps, cfg.sub_codec == MI_H264 ? "H.264" : "H.265", addr, port);

	/* -U (Gate 3): everything that needs root is open (port 554, the control socket, the settings,
	 * the -a file, MI and its fds, /dev/irled, AI/AO); open what is still opened later and is
	 * root's (/dev/urandom, /dev/mi_rgn), then leave root for good before the first client.
	 * If that fails, rtspd stops: it never serves as root when asked not to. */
	int rc = 0;
	if (user) {
		uint8_t r1;
		random_bytes(&r1, 1);                   /* opens /dev/urandom; the fd stays */
		if (urandom_fd < 0) LOG("rtspd: /dev/urandom: %s\n", strerror(errno));
		if (osd_open()) LOG("rtspd: /dev/mi_rgn not open: no OSD once enabled\n");
		if (drop_to(&who, -1, &why)) {
			LOG("rtspd: can't leave root for %s: %s (%s); stopping\n", user, why, strerror(errno));
			rc = 1;
			stop = 1;
		} else {
			LOG("rtspd: running as %s (uid %u, gid %u, %d groups); setuid(0) refused\n", user,
			    (unsigned)getuid(), (unsigned)getgid(), who.ngroups);
		}
	}

	struct timespec last_read[NSTREAMS];
	clock_gettime(CLOCK_MONOTONIC, &last_read[0]);
	last_read[1] = last_read[0];
	time_t last_stats = time(NULL), last_dn = 0;
	while (!stop) {
		fd_set rf, wf;
		FD_ZERO(&rf);
		FD_ZERO(&wf);
		int maxfd = lfd;
		FD_SET(lfd, &rf);
		if (cfd >= 0) { FD_SET(cfd, &rf); if (cfd > maxfd) maxfd = cfd; }
		if (tfd >= 0) { FD_SET(tfd, &rf); if (tfd > maxfd) maxfd = tfd; }
		for (int i = 0; i < TLS_WAITING; i++)
			if (tls_wait[i].on) { FD_SET(tls_wait[i].fd, &rf); if (tls_wait[i].fd > maxfd) maxfd = tls_wait[i].fd; }
		for (int si = 0; si < NSTREAMS; si++)
			if (vfd[si] >= 0) { FD_SET(vfd[si], &rf); if (vfd[si] > maxfd) maxfd = vfd[si]; }
		if (ffd >= 0) { FD_SET(ffd, &rf); if (ffd > maxfd) maxfd = ffd; }
		if (jfd >= 0) { FD_SET(jfd, &rf); if (jfd > maxfd) maxfd = jfd; }
		if (afd >= 0) { FD_SET(afd, &rf); if (afd > maxfd) maxfd = afd; }
		for (int i = 0; i < MAX_CLIENTS; i++) {
			struct client *cl = &clients[i];
			if (cl->fd < 0) continue;
			FD_SET(cl->fd, &rf);
			if (cl->out_len > cl->out_off) FD_SET(cl->fd, &wf);
			if (cl->fd > maxfd) maxfd = cl->fd;
		}
		struct timeval tv = { 0, 40000 };
		if (select(maxfd + 1, &rf, &wf, NULL, &tv) < 0 && errno != EINTR) {
			LOG("select: %s\n", strerror(errno));
			rc = 1;
			break;
		}
		if (ffd >= 0 && FD_ISSET(ffd, &rf)) mi_fe_ready();

		/* frames: on mi_poll readiness, or every 100 ms in case readiness never fires */
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		for (int si = 0; si < NSTREAMS; si++) {
			if (vfd[si] < 0) continue;
			long since = (now.tv_sec - last_read[si].tv_sec) * 1000 +
				     (now.tv_nsec - last_read[si].tv_nsec) / 1000000;
			if (!FD_ISSET(vfd[si], &rf) && since < 100) continue;
			last_read[si] = now;
			uint8_t *buf = si ? frame_sub : frame;
			uint32_t cap = si ? sizeof frame_sub : sizeof frame;
			for (int k = 0; k < 4; k++) {
				int n = mi_read_stream(si, buf, cap, NULL);
				if (n < 0) { rc = 1; stop = 1; break; }
				if (n == 0) break;
				on_frame(si, buf, (size_t)n);
			}
		}

		static struct timespec last_jpeg;
		if (jfd >= 0 && (FD_ISSET(jfd, &rf) || now.tv_sec - last_jpeg.tv_sec >= 1)) {
			last_jpeg = now;
			int n = mi_read_stream(2, snap_rd, sizeof snap_rd, NULL);
			if (n > 0) snap_frame(snap_rd, (size_t)n);
		}

		static struct timespec last_audio;
		if (audio_on && ((afd >= 0 && FD_ISSET(afd, &rf)) ||
				 (now.tv_sec - last_audio.tv_sec) * 1000 + (now.tv_nsec - last_audio.tv_nsec) / 1000000 >= 40)) {
			static int16_t pcm[4096];
			last_audio = now;
			for (int k = 0; k < 4; k++) {                   /* drain: 80 ms buffers */
				int n = mi_audio_read(pcm, sizeof pcm / sizeof pcm[0], NULL);
				if (n <= 0) break;
				audio_feed(pcm, (unsigned)n, audio_emit);
			}
		}

		if (speaker_on) mi_ao_pump();

		if (FD_ISSET(lfd, &rf)) accept_client(lfd);
		if (cfd >= 0 && FD_ISSET(cfd, &rf)) ctl_serve(cfd);
		time_t t = time(NULL);
		long long now_ms = mono_ms();
		for (int i = 0; i < TLS_WAITING; i++)           /* before the accept: a new fd isn't in rf */
			if (tls_wait[i].on && FD_ISSET(tls_wait[i].fd, &rf)) tls_proxy_in(i);
		if (tfd >= 0 && FD_ISSET(tfd, &rf)) tls_accept(tfd);
		tls_tick(now_ms);
		for (int i = 0; i < MAX_CLIENTS; i++) {
			struct client *cl = &clients[i];
			if (cl->fd >= 0 && FD_ISSET(cl->fd, &rf)) client_input(cl);
			if (cl->fd >= 0 && FD_ISSET(cl->fd, &wf)) out_flush(cl);
			client_tick(cl, now_ms, t);
		}
		if (daynight && t != last_dn) { dn_tick(); last_dn = t; }
		osd_tick(t);
		motion_tick(mono_ms());
		if (t - last_stats >= 60) {
			int n = 0;
			for (int i = 0; i < MAX_CLIENTS; i++) n += clients[i].fd >= 0;
			LOG("stats: main %llu frames %llu bytes, sub %llu frames %llu bytes, %d clients, "
			    "rss %ld kB\n", streams[0].frames, streams[0].bytes, streams[1].frames,
			    streams[1].bytes, n, rss_kb());
			last_stats = t;
		}
	}
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd >= 0) client_close(&clients[i], "shutdown");
	for (int i = 0; i < TLS_WAITING; i++)
		if (tls_wait[i].on) tls_drop(i, "shutdown");
	close(lfd);
	if (cfd >= 0) { close(cfd); unlink(ctl_path); }
	if (tfd >= 0) { close(tfd); unlink(tls_path); }
	LOG("rtspd: main %llu / sub %llu frames; rss %ld kB\n", streams[0].frames, streams[1].frames,
	    rss_kb());
	mi_ao_stop();
	mi_audio_stop();
	osd_stop();                                     /* detach before the encoders go */
	mi_stop();
	return rc;
}
