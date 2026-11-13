/* SPDX-License-Identifier: MIT */
/*
 * Host test for rtspd's RTSP handling and RFC 7798 packetizer (no camera, no network port):
 * a Unix socketpair stands in for the TCP connection and an Annex-B file for the encoder.
 *
 *   cc -std=c11 -Isrc/mi -Isrc/rtspd -o test_rtspd src/rtspd/test_rtspd.c src/rtspd/auth.c \
 *       src/rtspd/daynight.c src/rtspd/motion.c src/rtspd/audio.c src/mi/osd.c -lm
 *   ./test_rtspd clip.h265 out.h265 [clip.h264]
 *
 * Checks: the RTSP replies, that every NAL comes back byte-identical after depacketizing the
 * interleaved RTP stream (single NAL units and FU fragments), one RTP marker per access unit, and
 * that the SDP carries the parameter sets, MD5 against RFC 1321 vectors and the Digest flow (401
 * challenge, wrong password, correct response with and without qop=auth), time.tz (cam.conf,
 * live set/get, a leftover osd.tz_offset), and image.exposure_night / image.isp_gain_*_max with
 * the ae.* lines of get, slots and logins (login deadline, per-address cap, eviction of the
 * oldest connection not logged in, closing grace, pipelined guesses, per-address lockout, the
 * global budget, 16 users), and Gate 3's -U/-G refusals, the control socket's owner and mode and
 * the snapshot's 0640, the PROXY line (proxy.h) and RTSPS clients through the -t socket (uid,
 * deadline, per-address rules on the PROXY address, rtsps:// URLs, SDP/Content-Base, streaming).
 * Writes the reassembled stream to out.h265 so ffprobe can decode it.
 */
static long long mono_adj;                      /* moves rtspd's monotonic clock (mono_ms) */
#define MONO_ADJ_MS mono_adj
/* the uid a socketpair's peer has for tls_take (getpeereid would say our own); -1 = the real one */
static long long fake_peer_uid = -1;
#define PEER_UID(fd, u) (fake_peer_uid >= 0 ? (*(u) = (uid_t)fake_peer_uid, 0) : peer_uid(fd, u))
#define main rtspd_main
#include "rtspd.c"
#undef main

#include <assert.h>
#include <math.h>

/* MI stubs: the test never starts the pipeline */
int mi_verbose;
int mi_start(const struct mi_cfg *c) { (void)c; return -1; }
void mi_fds(int *v, int *f) { *v = *f = -1; }
void mi_fe_ready(void) {}
int mi_read_frame(uint8_t *b, uint32_t cap, uint64_t *pts) { (void)b; (void)cap; (void)pts; return -1; }
int mi_read_stream(int st, uint8_t *b, uint32_t cap, uint64_t *pts) { (void)st; (void)b; (void)cap; (void)pts; return -1; }
int mi_venc_fd(int st) { (void)st; return -1; }
static int img_vals[MI_IMG_COUNT] = { 50, 50, 50, 50, 50 };
int mi_image_set(int w, int v) { if (w < 0 || w >= MI_IMG_COUNT) return -1; img_vals[w] = v; return 0; }
int mi_image_get(int w) { return img_vals[w]; }
static int night_now = -1, nt_on, nt_loaded = 1;
static char dn_log[256];                        /* "night 1;" / "day-groups;" in call order */
int mi_night(int on)
{
	night_now = on;
	snprintf(dn_log + strlen(dn_log), sizeof dn_log - strlen(dn_log), "night %d;", on);
	return 0;
}
int mi_night_day(void) { snprintf(dn_log + strlen(dn_log), sizeof dn_log - strlen(dn_log), "day-groups;"); return 0; }
int mi_night_tuning(int on) { if (on && !nt_loaded) return -1; nt_on = on; return 0; }
int mi_night_tuning_get(void) { return nt_on; }
/* the SNR orientation and AE shutter limits as rtspd hands them to MI (mi.c's own checks are in
 * src/mi/test_mi.c): each call is logged "orient M F;" / "shutter D N;" */
static int or_m, or_f, or_fail;
static uint32_t sh_day, sh_night;
static char mi_log[512];
int mi_orient(int m, int f)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "orient %d %d;", m, f);
	if (or_fail) return -1;
	or_m = m; or_f = f;
	return 0;
}
void mi_orient_get(int *m, int *f) { *m = or_m; *f = or_f; }
int mi_shutter_max(uint32_t d, uint32_t n)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "shutter %u %u;", d, n);
	sh_day = d; sh_night = n;
	return 0;
}
void mi_shutter_max_get(uint32_t *d, uint32_t *n) { *d = sh_day; *n = sh_night; }
static int af_on, af_hz = 60;
int mi_antiflicker(int on, int hz)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "af %d %d;", on, hz);
	af_on = on; af_hz = hz;
	return 0;
}
void mi_antiflicker_get(int *on, int *hz) { *on = af_on; *hz = af_hz; }
static int tune_vals[MI_TUNE_COUNT] = { 128, 128, 0, 0 }, tune_fail;
int mi_tune_set(int w, int v)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "tune %d %d;", w, v);
	if (tune_fail) return -1;
	tune_vals[w] = v;
	return 0;
}
int mi_tune_get(int w) { return tune_vals[w]; }
static double ae_y = 40; static uint32_t ae_sh = 1000, ae_gain = 1024;   /* daylight: score 40000 */
int mi_ae_info(double *y, uint32_t *sh, uint32_t *g) { *y = ae_y; *sh = ae_sh; *g = ae_gain; return 0; }
/* the AE in detail (get's ae.*): ae_valid 0 = before the first step */
static int ae_valid = 1; static uint32_t ae_isp = 1024; static double ae_tgt = 40;
int mi_ae_state(struct mi_ae_state *s)
{
	s->target = ae_tgt;
	s->y = ae_valid ? ae_y : -1;
	s->shutter_us = ae_valid ? ae_sh : 0;
	s->sensor_gain = ae_valid ? ae_gain : 0;
	s->isp_gain = ae_valid ? ae_isp : 0;
	return ae_valid ? 0 : -1;
}
static int exp_night = MI_EXPOSURE_SAME, isp_day = MI_ISP_GAIN_DAY_DEFAULT, isp_night = MI_ISP_GAIN_NIGHT_DEFAULT;
int mi_exposure_night(int v)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "expn %d;", v);
	if (v != MI_EXPOSURE_SAME && (v < 0 || v > 100)) return -1;
	exp_night = v;
	return 0;
}
int mi_exposure_night_get(void) { return exp_night; }
int mi_isp_gain_max(int d, int n)
{
	snprintf(mi_log + strlen(mi_log), sizeof mi_log - strlen(mi_log), "isp %d %d;", d, n);
	if (d < 1 || d > MI_ISP_GAIN_MAX || n < 1 || n > MI_ISP_GAIN_MAX) return -1;
	isp_day = d; isp_night = n;
	return 0;
}
void mi_isp_gain_max_get(int *d, int *n) { *d = isp_day; *n = isp_night; }
static uint8_t grid[1024];
static unsigned grid_seq;
int mi_audio_start(int g) { (void)g; return 0; }
int mi_audio_fd(void) { return -1; }
int mi_audio_read(int16_t *pcm, unsigned cap, uint64_t *pts) { (void)pcm; (void)cap; (void)pts; return 0; }
void mi_audio_stop(void) {}
static unsigned ao_samples;
int mi_ao_start(void) { return 0; }
void mi_ao_write(const int16_t *pcm, unsigned n) { (void)pcm; ao_samples += n; }
void mi_ao_pump(void) {}
void mi_ao_stop(void) {}
static double up_acc; static unsigned up_n;
static void up_sink(const int16_t *pcm, unsigned n) { for (unsigned i = 0; i < n; i++) { up_acc += (double)pcm[i] * pcm[i]; up_n++; } }
static int ulaw_dec(uint8_t u)                  /* G.711 µ-law decode, for checking the encoder */
{
	u = (uint8_t)~u;
	int t = ((u & 0x0f) << 3) + 0x84;
	t <<= (u & 0x70) >> 4;
	return (u & 0x80) ? 0x84 - t : t - 0x84;
}
static double rms_acc;
static long rms_n;
static void rms_emit(const uint8_t *f, uint32_t ts)
{
	(void)ts;
	for (int i = 0; i < AUDIO_FRAME; i++) { double v = ulaw_dec(f[i]); rms_acc += v * v; rms_n++; }
}
/* a 1 s, 10000-peak tone at 16 kHz through the 8 kHz path, decoded: its rms (~7071 if passed) */
static double tone_rms(double hz)
{
	static int16_t pcm[16000];
	for (int i = 0; i < 16000; i++) pcm[i] = (int16_t)(10000 * sin(2 * M_PI * hz * i / 16000));
	rms_acc = 0;
	rms_n = 0;
	audio_reset(0);
	audio_feed(pcm, 16000, rms_emit);
	return rms_n ? sqrt(rms_acc / (double)rms_n) : 0;
}
unsigned mi_ae_grid(uint8_t *y, unsigned cap, unsigned *w, unsigned *h)
{
	if (!grid_seq || cap < 1024) return 0;
	memcpy(y, grid, 1024); *w = 32; *h = 32;
	return grid_seq;
}
/* a scene: textured background at level L; a "person" (6x4 cells) brighter by 60 % at x */
static void scene(int level, int person_x)
{
	for (int i = 0; i < 1024; i++) grid[i] = (uint8_t)(level + (i * 7 % 13));
	if (person_x >= 0)
		for (int r = 10; r < 16; r++)
			for (int c = person_x; c < person_x + 4; c++) grid[r * 32 + c] = (uint8_t)((level + 6) * 16 / 10);
	grid_seq++;
}
void mi_stop(void) {}
/* osd.c is linked in; the pipeline never starts, so its MI_RGN code never runs */
static mi_chn_hook_fn osd_hooked;
void mi_set_chn_hook(mi_chn_hook_fn f) { osd_hooked = f; }
int mi_flushinv(void *va, uint32_t n) { (void)va; (void)n; return -1; }

static int peer;
static uint8_t rx[64 << 20];
static size_t rx_len;

static void drain(struct client *c)
{
	for (;;) {
		ssize_t n = recv(peer, rx + rx_len, sizeof rx - rx_len, MSG_DONTWAIT);
		if (n > 0) { rx_len += (size_t)n; continue; }
		if (c->fd < 0 || c->out_len == c->out_off) return;
		out_flush(c);
	}
}

static void request(struct client *c, const char *req, const char *expect)
{
	rx_len = 0;
	assert(send(peer, req, strlen(req), 0) == (ssize_t)strlen(req));
	client_input(c);
	drain(c);
	rx[rx_len] = 0;
	if (!strstr((char *)rx, expect)) {
		fprintf(stderr, "FAIL: %.*s-> %s\n", (int)strcspn(req, "\r"), req, rx);
		exit(1);
	}
	printf("ok: %.*s -> %.*s\n", (int)strcspn(req, "\r"), req, (int)strcspn((char *)rx, "\r"), rx);
}

/* H.264 sub-stream (RFC 6184): DESCRIBE /sub, SDP, every NAL byte-identical through single NAL
 * units and FU-A, one marker per access unit. */
static void test_h264(struct client *c, const char *path)
{
	static uint8_t in[8 << 20], au[1 << 20];
	FILE *f = fopen(path, "rb");
	assert(f);
	size_t in_n = fread(in, 1, sizeof in, f);
	fclose(f);
	streams[1].on = 1;
	streams[1].codec = MI_H264;
	struct nal all[4096];
	int nall = split_nals(in, in_n, all, 4096), aus = 0, start = 0;
	/* parameter sets come with the first access unit: feed one before DESCRIBE */
	for (int i = 0; i < nall; i++) {
		int type = all[i].p[0] & 0x1f;
		if ((type < 1 || type > 5) && i + 1 < nall) continue;
		size_t from = (size_t)(all[start].p - in), to = (size_t)(all[i].p - in) + all[i].n;
		while (from > 0 && in[from - 1] != 0) from--;
		while (from > 0 && in[from - 1] == 0) from--;
		memcpy(frame_sub, in + from, to - from);
		if (aus == 0) {
			on_frame(1, frame_sub, to - from);              /* nobody playing yet */
			request(c, "DESCRIBE rtsp://cam/sub RTSP/1.0\r\nCSeq: 1\r\n\r\n",
				"a=rtpmap:96 H264/90000");
			assert(strstr((char *)rx, "packetization-mode=1;profile-level-id=") &&
			       strstr((char *)rx, "sprop-parameter-sets="));
			request(c, "SETUP rtsp://cam/sub/track0 RTSP/1.0\r\nCSeq: 2\r\nTransport: "
				"RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", "200 OK");
			char play[256];
			snprintf(play, sizeof play, "PLAY rtsp://cam/sub RTSP/1.0\r\nCSeq: 3\r\nSession: %s\r\n\r\n",
				 c->session);
			request(c, play, "200 OK");
			assert(c->stream == 1);
		}
		rx_len = 0;
		on_frame(1, frame_sub, to - from);
		drain(c);
		size_t au_n = 0, o = 0;
		int markers = 0;
		while (o + 4 <= rx_len) {
			size_t len = ((size_t)rx[o + 2] << 8) | rx[o + 3];
			uint8_t *r = rx + o + 4, *p = r + 12;
			size_t pn = len - 12;
			markers += r[1] >> 7;
			if ((p[0] & 0x1f) == 28) {
				if (p[1] & 0x80) {
					memcpy(au + au_n, "\0\0\0\1", 4); au_n += 4;
					au[au_n++] = (uint8_t)((p[0] & 0xe0) | (p[1] & 0x1f));
				}
				memcpy(au + au_n, p + 2, pn - 2); au_n += pn - 2;
			} else {
				memcpy(au + au_n, "\0\0\0\1", 4); au_n += 4;
				memcpy(au + au_n, p, pn); au_n += pn;
			}
			o += 4 + len;
		}
		assert(o == rx_len && markers == 1);
		struct nal got[MAX_NALS];
		int ng = split_nals(au, au_n, got, MAX_NALS);
		assert(ng == i - start + 1);
		for (int k = 0; k < ng; k++)
			assert(got[k].n == all[start + k].n && !memcmp(got[k].p, all[start + k].p, got[k].n));
		aus++;
		start = i + 1;
	}
	request(c, "DESCRIBE rtsp://cam/main RTSP/1.0\r\nCSeq: 9\r\n\r\n", "H265/90000");
	streams[1].on = 0;
	request(c, "DESCRIBE rtsp://cam/sub RTSP/1.0\r\nCSeq: 10\r\n\r\n", "404 Not Found");
	printf("ok: H.264 /sub: SDP, %d access units round-tripped byte-identical (FU-A), /sub 404 when off\n",
	       aus);
}

/* t in this process's TZ, as osd.c's clock reads it (localtime_r; its text is test_osd.c's) */
static const char *local(time_t t)
{
	static char s[32];
	struct tm l;
	assert(localtime_r(&t, &l));
	strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S", &l);
	return s;
}

/* load_settings with what it LOGs (stderr) caught in log */
static void load_logged(const char *conf, struct mi_cfg *cfg, struct dn_cfg *dn, char *log, size_t cap)
{
	char lp[600];
	snprintf(lp, sizeof lp, "%s.log", conf);
	fflush(stderr);
	int save = dup(2), fd = open(lp, O_CREAT | O_TRUNC | O_RDWR, 0600);
	assert(save >= 0 && fd >= 0);
	dup2(fd, 2);
	load_settings(conf, cfg, dn);
	fflush(stderr);
	dup2(save, 2);
	close(save);
	ssize_t n = pread(fd, log, cap - 1, 0);
	log[n > 0 ? n : 0] = 0;
	close(fd);
	unlink(lp);
}

/* ---- slots and logins (Gate 3) --------------------------------------------------------
 * Connections go through client_admit with a socketpair and a chosen IPv4 address; the other
 * end of each slot's connection is in peers[]. Users: admin:camera:secret (main's htdigest). */
#define TNONCE "0123456789abcdef0123456789abcdef"
static int peers[MAX_CLIENTS] = { -1, -1, -1, -1 };

/* a connection from ip; NULL if refused (then its other end has been closed: EOF) */
static struct client *conn(const char *ip)
{
	int sv[2];
	struct in_addr a;
	assert(inet_pton(AF_INET, ip, &a) == 1);
	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	struct client *c = client_admit(sv[0], a, ip);
	if (!c) {
		char b;
		assert(recv(sv[1], &b, 1, 0) == 0);
		close(sv[1]);
		return NULL;
	}
	int i = (int)(c - clients);
	if (peers[i] >= 0) close(peers[i]);
	peers[i] = sv[1];
	strcpy(c->nonce, TNONCE);
	return c;
}

static void on(const struct client *c) { peer = peers[c - clients]; }

/* the other end of slot i saw the connection closed (after any replies) */
static int gone(int i)
{
	char b[4096];
	ssize_t n;
	while ((n = recv(peers[i], b, sizeof b, MSG_DONTWAIT)) > 0) {}
	return n == 0;
}

static void drop_all(void)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd >= 0) client_close(&clients[i], "test");
		if (peers[i] >= 0) { close(peers[i]); peers[i] = -1; }
	}
}

static void tick_all(void)
{
	for (int i = 0; i < MAX_CLIENTS; i++) client_tick(&clients[i], mono_ms(), time(NULL));
}

/* a DESCRIBE for admin with password pw, compact (no CSeq) so 21 fit in IN_CAP */
static int digest_req(char *out, size_t cap, const char *pw)
{
	char ha1[33], ha2[33], resp[33], t[128];
	snprintf(t, sizeof t, "admin:camera:%s", pw);
	md5_hex(t, strlen(t), ha1);
	md5_hex("DESCRIBE:rtsp://c/", 18, ha2);
	snprintf(t, sizeof t, "%s:" TNONCE ":%s", ha1, ha2);
	md5_hex(t, strlen(t), resp);
	return snprintf(out, cap, "DESCRIBE rtsp://c/ RTSP/1.0\r\nAuthorization: Digest username=\"admin\","
			"realm=\"camera\",nonce=\"" TNONCE "\",uri=\"rtsp://c/\",response=\"%s\"\r\n\r\n", resp);
}

/* c tries password pw: 1 if it got 200 OK (and is logged in) */
static int login(struct client *c, const char *pw)
{
	char r[512];
	digest_req(r, sizeof r, pw);
	on(c);
	rx_len = 0;
	assert(send(peer, r, strlen(r), 0) == (ssize_t)strlen(r));
	client_input(c);
	drain(c);
	rx[rx_len] = 0;
	int ok = strstr((char *)rx, "RTSP/1.0 200 OK") != NULL;
	assert(ok == (c->fd >= 0 && c->authed));
	return ok;
}

static int occurrences(const char *s, const char *what)
{
	int n = 0;
	for (const char *p = s; (p = strstr(p, what)); p++) n++;
	return n;
}

static void lockout_reset(void)
{
	memset(fails, 0, sizeof fails);
	memset(&gfail, 0, sizeof gfail);
	memset(good, 0, sizeof good);
}

static void test_slots_and_logins(void)
{
	struct client *a, *b, *c, *d, *e;
	drop_all();
	lockout_reset();

	/* login deadline: LOGIN_MS after connecting, however busy the connection is (the margins
	 * leave room for the real time the test takes) */
	a = conn("10.0.0.1");
	b = conn("10.0.0.2");
	assert(login(b, "secret"));
	for (int s = 0; s < 9; s++) {
		mono_adj += 1000;
		on(a);
		request(a, "OPTIONS rtsp://c/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", "200 OK");
		tick_all();
		assert(a->fd >= 0);
	}
	mono_adj += 1001;
	tick_all();
	assert(a->fd < 0 && gone((int)(a - clients)) && b->fd >= 0);   /* b logged in: stays */
	drop_all();
	printf("ok: slots: a connection not logged in after %d ms is closed, whatever it sends; a logged-in one stays\n",
	       LOGIN_MS);

	/* per address: PER_IP_UNAUTHED waiting to log in; one logging in makes room */
	a = conn("10.0.1.1");
	b = conn("10.0.1.1");
	assert(a && b && !conn("10.0.1.1"));
	c = conn("10.0.1.2");
	assert(c);
	assert(login(a, "secret"));
	d = conn("10.0.1.1");
	assert(d);
	drop_all();
	printf("ok: slots: at most %d connections per address not logged in; logging in frees the place\n",
	       PER_IP_UNAUTHED);

	/* every slot taken: the oldest not logged in is evicted, never a logged-in one; the slot is
	 * fresh (nothing of the last client's tracks or talk carries over) */
	a = conn("10.0.2.1");
	assert(login(a, "secret"));
	a->video = a->audio = a->talk = 1;
	a->ch = 7; a->ach = 8; a->tch = 9;
	mono_adj += 10;
	b = conn("10.0.2.2");
	mono_adj += 10;
	c = conn("10.0.2.3");
	mono_adj += 10;
	d = conn("10.0.2.4");
	int bi = (int)(b - clients), bp = peers[bi];
	peers[bi] = -1;                                 /* keep b's end to see it closed */
	e = conn("10.0.2.5");
	char eof;
	assert(e == b && recv(bp, &eof, 1, MSG_DONTWAIT) == 0);    /* b (the oldest) evicted */
	close(bp);
	assert(a->fd >= 0 && c->fd >= 0 && d->fd >= 0 && e->fd >= 0 && !e->authed);
	assert(login(c, "secret") && login(d, "secret") && login(e, "secret"));
	assert(!conn("10.0.2.6"));                      /* all logged in: the newcomer is refused */
	assert(a->fd >= 0 && c->fd >= 0 && d->fd >= 0 && e->fd >= 0);
	int ai = (int)(a - clients);
	client_close(a, "test");
	a = conn("10.0.2.7");
	assert(a == &clients[ai] && !a->video && !a->audio && !a->talk && !a->ch && !a->ach && !a->tch &&
	       !a->authed && !a->auth_fails && !a->ready && !a->playing && !a->closing && a->out_len == 0);
	drop_all();
	printf("ok: slots: full, a newcomer evicts the oldest connection not logged in, never a logged-in one; "
	       "an accepted slot starts clean\n");

	/* closing: CLOSING_MS to read the last reply, however much the client sends */
	a = conn("10.0.3.1");
	assert(login(a, "secret"));
	on(a);
	char junk[4096];
	memset(junk, 'x', sizeof junk);
	while (send(a->fd, junk, sizeof junk, MSG_DONTWAIT) > 0) {}     /* it never reads: full */
	static const char td[] = "TEARDOWN rtsp://c/ RTSP/1.0\r\nCSeq: 2\r\n\r\n",
			  op[] = "OPTIONS rtsp://c/ RTSP/1.0\r\nCSeq: 3\r\n\r\n";
	assert(send(peer, td, sizeof td - 1, 0) == (ssize_t)sizeof td - 1);
	client_input(a);                                /* (no drain: that would read for it) */
	tick_all();
	assert(a->fd >= 0 && a->closing && a->out_len > a->out_off);
	size_t pending = a->out_len - a->out_off;
	for (int k = 0; k < 3; k++) {
		mono_adj += 600;
		assert(send(peer, op, sizeof op - 1, 0) == (ssize_t)sizeof op - 1);
		client_input(a);
		tick_all();
		assert(a->fd >= 0 && a->out_len - a->out_off == pending);  /* read, not answered */
	}
	mono_adj += 201;
	tick_all();
	assert(a->fd < 0);
	drop_all();
	printf("ok: slots: a closing client that doesn't read is closed after %d ms whatever it sends\n", CLOSING_MS);

	/* pipelining: 20 wrong passwords and the right one in one buffer: no 200, 4 challenges */
	static char buf[IN_CAP + 1];
	size_t n = 0;
	for (int k = 0; k < 20; k++) n += (size_t)digest_req(buf + n, sizeof buf - n, "wrong");
	n += (size_t)digest_req(buf + n, sizeof buf - n, "secret");
	assert(n <= IN_CAP);
	a = conn("10.0.4.1");
	on(a);
	rx_len = 0;
	assert(send(peer, buf, n, 0) == (ssize_t)n);
	client_input(a);
	drain(a);
	rx[rx_len] = 0;
	assert(!strstr((char *)rx, "200 OK") && occurrences((char *)rx, "RTSP/1.0 401") == 4 && a->fd < 0);
	/* and nothing after the closing one is handled at all, not even OPTIONS (always open) */
	lockout_reset();
	n = 0;
	for (int k = 0; k < 5; k++) n += (size_t)digest_req(buf + n, sizeof buf - n, "wrong");
	n += (size_t)snprintf(buf + n, sizeof buf - n, "OPTIONS rtsp://c/ RTSP/1.0\r\nCSeq: 9\r\n\r\n");
	b = conn("10.0.4.2");
	on(b);
	rx_len = 0;
	assert(send(peer, buf, n, 0) == (ssize_t)n);
	client_input(b);
	drain(b);
	rx[rx_len] = 0;
	assert(occurrences((char *)rx, "RTSP/1.0 401") == 4 && !strstr((char *)rx, "Public:") && b->fd < 0);
	drop_all();
	printf("ok: logins: 20 wrong + the right password pipelined get 4 challenges and no 200; nothing after "
	       "the 5th wrong one is answered\n");

	/* per address: FAIL_MAX wrong in FAIL_WINDOW lock it (not checked: 401) until the window ends */
	lockout_reset();
	a = conn("10.0.5.1");
	for (int k = 0; k < 4; k++) assert(!login(a, "wrong"));
	assert(a->fd >= 0);
	assert(!login(a, "wrong") && a->fd < 0);       /* the 5th: closed, no reply */
	a = conn("10.0.5.1");
	assert(!login(a, "secret") && strstr((char *)rx, "401") && a->fd >= 0);   /* locked */
	b = conn("10.0.5.2");
	assert(login(b, "secret"));                     /* another address isn't */
	mono_adj += (FAIL_WINDOW + 1) * 1000LL;
	assert(login(a, "secret"));                     /* the window is over */
	drop_all();
	/* a locked address stays locked through a flood of new ones (its entry isn't evicted). It
	 * logged in before, so the global budget the flood also spends doesn't block it: only its
	 * own entry can. */
	lockout_reset();
	struct in_addr l, x;
	inet_pton(AF_INET, "10.0.6.1", &l);
	time_t now = mono_s();
	auth_good(l, now);
	for (int k = 0; k < FAIL_MAX; k++) auth_failed(l, now);
	for (int k = 0; k < 3 * FAIL_SLOTS; k++) {
		x.s_addr = htonl(0x0b000000u + (uint32_t)k);
		auth_failed(x, now);
	}
	assert(gfail.n >= FAIL_GLOBAL && auth_blocked(l, now));
	printf("ok: logins: %d wrong from an address lock it for the window (not checked); others unaffected; "
	       "a locked entry survives a flood of new addresses\n", FAIL_MAX);

	/* the global budget: FAIL_GLOBAL wrong from any addresses stop the checks, except for an
	 * address that logged in within GOOD_KEEP s */
	lockout_reset();
	a = conn("10.0.7.1");
	assert(login(a, "secret"));                     /* the NVR */
	drop_all();
	for (int ip = 0; ip < FAIL_GLOBAL / 4; ip++) {  /* 4 each: no address locked */
		char s[32];
		snprintf(s, sizeof s, "10.0.8.%d", ip + 1);
		a = conn(s);
		for (int k = 0; k < 4; k++) assert(!login(a, "wrong"));
		drop_all();
	}
	assert(gfail.n == FAIL_GLOBAL);
	b = conn("10.0.7.9");
	assert(!login(b, "secret"));                    /* a newcomer: not checked */
	a = conn("10.0.7.1");
	assert(login(a, "secret"));                     /* the NVR: exempt */
	mono_adj += (FAIL_WINDOW + 1) * 1000LL;
	assert(login(b, "secret"));                     /* the window is over */
	drop_all();
	/* the exemption lasts GOOD_KEEP s */
	mono_adj += (GOOD_KEEP + 1) * 1000LL;
	now = mono_s();
	inet_pton(AF_INET, "10.0.7.1", &l);
	for (int k = 0; k < FAIL_GLOBAL; k++) { x.s_addr = htonl(0x0c000000u + (uint32_t)k); auth_failed(x, now); }
	assert(auth_blocked(l, now));
	lockout_reset();
	printf("ok: logins: %d wrong from all addresses stop the checks except for addresses logged in within %d s\n",
	       FAIL_GLOBAL, GOOD_KEEP);
}

/* 18 users: the first 16 load (as camcfg/camhttpd allow), 2 are counted as left out */
static void test_max_users(const char *path)
{
	char p[600], t[128], ha1[33], ha2[33], resp[33], az[512], who[64];
	snprintf(p, sizeof p, "%s.many", path);
	FILE *f = fopen(p, "w");
	assert(f);
	for (int i = 1; i <= AUTH_MAX_USERS + 2; i++) {
		snprintf(t, sizeof t, "u%d:camera:pw%d", i, i);
		md5_hex(t, strlen(t), ha1);
		fprintf(f, "u%d:camera:%s\n", i, ha1);
	}
	fclose(f);
	assert(!users_load(p) && auth_skipped() == 2);
	md5_hex("DESCRIBE:rtsp://c/", 18, ha2);
	for (int i = AUTH_MAX_USERS; i <= AUTH_MAX_USERS + 1; i++) {
		snprintf(t, sizeof t, "u%d:camera:pw%d", i, i);
		md5_hex(t, strlen(t), ha1);
		snprintf(t, sizeof t, "%s:" TNONCE ":%s", ha1, ha2);
		md5_hex(t, strlen(t), resp);
		snprintf(az, sizeof az, "Digest username=\"u%d\", realm=\"camera\", nonce=\"" TNONCE "\", "
			 "uri=\"rtsp://c/\", response=\"%s\"", i, resp);
		assert(auth_check(az, "DESCRIBE", TNONCE, who, sizeof who) == (i == AUTH_MAX_USERS));
	}
	unlink(p);
	assert(!users_load(path) && auth_skipped() == 0);
	printf("ok: users: %d load, more are counted and logged, not loaded\n", AUTH_MAX_USERS);
}

/* ---- RTSPS through camtls (-t, proxy.h) ------------------------------------------------ */

static struct in_addr px_src, px_dst;
static uint16_t px_sp, px_dp;
static size_t px_used;

static int px(const char *s, size_t n) { return proxy_parse(s, n, &px_src, &px_dst, &px_sp, &px_dp, &px_used); }

/* an accepted line is exactly what camtls's snprintf makes of its fields (so nothing looser got in) */
static void px_same(const char *buf)
{
	char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], l[80];
	inet_ntop(AF_INET, &px_src, a, sizeof a);
	inet_ntop(AF_INET, &px_dst, b, sizeof b);
	int n = snprintf(l, sizeof l, "PROXY TCP4 %s %s %u %u\r\n", a, b, px_sp, px_dp);
	assert((size_t)n == px_used && px_used <= PROXY_MAX && !memcmp(l, buf, px_used));
}

static void test_proxy_parse(void)
{
	static const char longest[] = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
	static const struct { const char *s; int r; } t[] = {
		{ "PROXY TCP4 192.0.2.20 192.0.2.5 51234 322\r\n", 1 }, { longest, 1 },
		{ "PROXY TCP4 0.0.0.0 1.2.3.4 1 1\r\n", 1 },
		{ "PROXY TCP4 192.0.2.20 192.0.2.5 51234 322\r\nOPTIONS rtsps://c/ RTSP/1.0\r\n", 1 },
		{ "", 0 }, { "P", 0 }, { "PROXY TCP", 0 }, { "PROXY TCP4 ", 0 }, { "PROXY TCP4 1.2.3.4 5.6", 0 },
		{ "PROXY TCP4 192.0.2.20 192.0.2.5 51234 322\r", 0 },
		{ "G", -1 }, { "GET / HTTP/1.1\r\n", -1 }, { "OPTIONS rtsp://c/ RTSP/1.0\r\n", -1 },
		{ "PROXY TCP6 ::1 ::1 1 2\r\n", -1 }, { "PROXY UNKNOWN\r\n", -1 },
		{ "proxy TCP4 1.2.3.4 5.6.7.8 1 2\r\n", -1 }, { "PROXY  TCP4 1.2.3.4 5.6.7.8 1 2\r\n", -1 },
		{ "PROXY TCP4  1.2.3.4 5.6.7.8 1 2\r\n", -1 }, { "PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 \r\n", -1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\r\n", -1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n", -1 }, { "PROXY TCP4 1.2.3 5.6.7.8 1 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4.5 5.6.7.8 1 2\r\n", -1 }, { "PROXY TCP4 01.2.3.4 5.6.7.8 1 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.256 5.6.7.8 1 2\r\n", -1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 0 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 65536\r\n", -1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n", -1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 1 0x2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 99999\r\n", -1 }, { "PROXY TCP4 1.2.3.4\t5.6.7.8 1 2\r\n", -1 },
		{ "PROXY TCP4 ::ffff:1.2.3.4 5.6.7.8 1 2\r\n", -1 }, { "PROXY TCP4 \r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n\r\n", 1 }, { "PROXY TCP4 1.2.3.4 5.6.7.8 -1 2\r\n", -1 },
		{ "PROXY TCP4 1.2.3.4 5.6.7.8 1 2  \r\n", -1 }, { "PROXY TCP4 1.2.3.4 0x5.6.7.8 1 2\r\n", -1 },
	};
	for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
		size_t n = strlen(t[i].s);
		int r = px(t[i].s, n);
		if (r != t[i].r) { fprintf(stderr, "FAIL proxy_parse \"%s\" -> %d\n", t[i].s, r); exit(1); }
		if (r == 1) {
			px_same(t[i].s);
			assert(px_used == strcspn(t[i].s, "\n") + 1);
			for (size_t k = 0; k < px_used; k++) assert(px(t[i].s, k) == 0);     /* every prefix: wait */
		}
	}
	assert(px(t[0].s, strlen(t[0].s)) == 1 && px_src.s_addr == inet_addr("192.0.2.20") &&
	       px_dst.s_addr == inet_addr("192.0.2.5") && px_sp == 51234 && px_dp == 322 && px_used == 43);
	char b[80];
	memcpy(b, longest, sizeof longest);
	assert(sizeof longest - 1 == PROXY_MAX && px(b, PROXY_MAX) == 1);
	b[PROXY_MAX - 1] = 'x';                         /* 56 bytes and no line end: never */
	assert(px(b, PROXY_MAX) == -1 && px(b, PROXY_MAX - 1) == 0);
	memcpy(b, "PROXY TCP4 1.2.3.4\0 5.6.7.8 1 2\r\n", 33);     /* a NUL inside */
	assert(px(b, 33) == -1);
	/* fuzz: random bytes, and valid lines with bytes changed, cut short or run on; whatever comes
	 * back is consistent, and an accepted line is exactly camtls's format */
	int got[3] = { 0, 0, 0 };
	srand(7);
	for (int k = 0; k < 300000; k++) {
		size_t n;
		if (k % 3) {
			n = (size_t)snprintf(b, sizeof b, "PROXY TCP4 %d.%d.%d.%d %d.%d.%d.%d %d %d\r\n", rand() % 300,
					     rand() % 256, rand() % 256, rand() % 256, rand() % 256, rand() % 256,
					     rand() % 256, rand() % 256, rand() % 70000, rand() % 70000);
			static const char alpha[] = "0123456789. \r\n\tPROXYTCP:x-+";
			for (int m = rand() % 3; m > 0; m--)
				b[rand() % (int)n] = rand() % 4 ? alpha[rand() % (int)(sizeof alpha - 1)] : (char)rand();
			if (rand() % 4 == 0) n = (size_t)rand() % (n + 1);
			else if (rand() % 4 == 0) { memcpy(b + n, "OPTIONS", 7); n += 7; }
		} else {
			n = (size_t)rand() % 70;
			for (size_t j = 0; j < n; j++) b[j] = (char)rand();
			if (rand() % 2 && n >= 11) memcpy(b, "PROXY TCP4 ", 11);
		}
		int r = px(b, n);
		assert(r >= -1 && r <= 1);
		got[r + 1]++;
		if (r == 1) { assert(px_used <= n); px_same(b); }
		if (r == 0) assert(n < PROXY_MAX && !memchr(b, '\n', n) && !memcmp(b, "PROXY TCP4 ", n < 11 ? n : 11));
	}
	assert(got[0] > 1000 && got[1] > 1000 && got[2] > 1000);
	printf("ok: proxy_parse: %u table lines, every prefix of a good line waits, 56 bytes without a line end "
	       "refused; fuzz %d/%d/%d (bad/wait/good), every good one exactly camtls's format\n",
	       (unsigned)(sizeof t / sizeof t[0]), got[0], got[1], got[2]);
}

/* the waiting slot holding fd, or -1 */
static int waiting(int fd)
{
	for (int i = 0; i < TLS_WAITING; i++)
		if (tls_wait[i].on && tls_wait[i].fd == fd) return i;
	return -1;
}

/* a connection to the TLS socket from a peer with uid: rtspd's end (in tls_take), camtls's in *cam */
static int tls_open(long long uid, int *cam)
{
	int sv[2];
	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	fake_peer_uid = uid;
	tls_take(sv[0]);
	fake_peer_uid = -1;
	*cam = sv[1];
	return sv[0];
}

/* camtls's end saw the connection closed */
static int cam_gone(int cam)
{
	char b[4096];
	ssize_t n;
	while ((n = recv(cam, b, sizeof b, MSG_DONTWAIT)) > 0) {}
	return n == 0;
}

/* a client at ip:port through camtls, reaching the camera at 192.0.2.5:322: its slot, or NULL if
 * refused (camtls's end saw EOF). Like conn(), its other end is in peers[] and its nonce TNONCE. */
static struct client *tconn(const char *ip, unsigned port)
{
	int cam, fd = tls_open((long long)tls_uid, &cam), w = waiting(fd);
	char l[80];
	assert(w >= 0);
	int n = snprintf(l, sizeof l, "PROXY TCP4 %s 192.0.2.5 %u 322\r\n", ip, port);
	assert(send(cam, l, (size_t)n, 0) == n);
	tls_proxy_in(w);
	assert(!tls_wait[w].on);
	struct client *c = NULL;
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd == fd) c = &clients[i];
	if (!c) {
		assert(cam_gone(cam));
		close(cam);
		return NULL;
	}
	int i = (int)(c - clients);
	if (peers[i] >= 0) close(peers[i]);
	peers[i] = cam;
	strcpy(c->nonce, TNONCE);
	return c;
}

/* "Authorization: Digest ..." for admin with password pw on method and uri (no qop) */
static void digest_hdr(char *out, size_t cap, const char *method, const char *uri, const char *pw)
{
	char ha1[33], ha2[33], resp[33], t[512];
	snprintf(t, sizeof t, "admin:camera:%s", pw);
	md5_hex(t, strlen(t), ha1);
	snprintf(t, sizeof t, "%s:%s", method, uri);
	md5_hex(t, strlen(t), ha2);
	snprintf(t, sizeof t, "%s:" TNONCE ":%s", ha1, ha2);
	md5_hex(t, strlen(t), resp);
	snprintf(out, cap, "Authorization: Digest username=\"admin\", realm=\"camera\", nonce=\"" TNONCE "\", "
		 "uri=\"%s\", response=\"%s\"\r\n", uri, resp);
}

/* H.265 interleaved RTP on channel 0 (rx, n bytes) back to Annex B in au; the number of markers */
static int depack_h265(const uint8_t *r0, size_t n, uint8_t *au, size_t *au_n)
{
	size_t o = 0;
	int markers = 0;
	*au_n = 0;
	while (o + 4 <= n) {
		assert(r0[o] == '$' && r0[o + 1] == 0);
		size_t len = ((size_t)r0[o + 2] << 8) | r0[o + 3];
		const uint8_t *r = r0 + o + 4, *p = r + 12;
		size_t pn = len - 12;
		assert((r[0] & 0xc0) == 0x80 && (r[1] & 0x7f) == 96);
		markers += r[1] >> 7;
		if (((p[0] >> 1) & 0x3f) == 49) {
			if (p[2] & 0x80) {
				memcpy(au + *au_n, "\0\0\0\1", 4); *au_n += 4;
				au[(*au_n)++] = (uint8_t)((p[0] & 0x81) | ((p[2] & 0x3f) << 1));
				au[(*au_n)++] = p[1];
			}
			memcpy(au + *au_n, p + 3, pn - 3); *au_n += pn - 3;
		} else {
			memcpy(au + *au_n, "\0\0\0\1", 4); *au_n += 4;
			memcpy(au + *au_n, p, pn); *au_n += pn;
		}
		o += 4 + len;
	}
	assert(o == n);
	return markers;
}

static void test_tls(const uint8_t *in, size_t in_n)
{
	struct client *a, *b, *c, *d, *e;
	int cam, fd, w;
	char l[1024], az[512];
	drop_all();
	lockout_reset();
	tls_uid = 4242;                                 /* camtls */

	/* the uid: a peer that isn't camtls is closed at once; the real lookup on a socketpair */
	fd = tls_open(4243, &cam);
	assert(waiting(fd) < 0 && cam_gone(cam));
	close(cam);
	{
		int sv[2];
		uid_t u = (uid_t)-1;
		assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
		assert(!peer_uid(sv[0], &u) && u == geteuid());
		close(sv[0]);
		close(sv[1]);
	}
	/* SO_SNDBUF: modest, so a slow viewer still fills rtspd's own buffer (send_frame drops) */
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	int sb = 0;
	socklen_t sl = sizeof sb;
	assert(w >= 0 && !getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, &sl) && sb >= TLS_SNDBUF && sb <= 2 * TLS_SNDBUF);
	/* PROXY_MS from the accept, a partial line doesn't extend it */
	mono_adj += PROXY_MS - 100;
	tls_tick(mono_ms());
	assert(tls_wait[w].on);
	assert(send(cam, "PROXY TCP4 10.", 14, 0) == 14);
	tls_proxy_in(w);
	assert(tls_wait[w].on && tls_wait[w].len == 14);
	mono_adj += 101;
	tls_tick(mono_ms());
	assert(!tls_wait[w].on && cam_gone(cam));
	close(cam);
	/* a bad line, or the client closing first: closed */
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	assert(send(cam, "OPTIONS rtsp://c/ RTSP/1.0\r\n\r\n", 30, 0) == 30);
	tls_proxy_in(w);
	assert(!tls_wait[w].on && cam_gone(cam));
	close(cam);
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	assert(send(cam, "PROXY TCP4 10.1.0.1 192.0.2.5 1 322\n", 36, 0) == 36);     /* LF without CR */
	tls_proxy_in(w);
	assert(!tls_wait[w].on && cam_gone(cam));
	close(cam);
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	close(cam);
	tls_proxy_in(w);
	assert(!tls_wait[w].on);
	/* at most TLS_WAITING wait; another is closed */
	int cams[TLS_WAITING];
	for (int i = 0; i < TLS_WAITING; i++) assert(waiting(tls_open(4242, &cams[i])) >= 0);
	fd = tls_open(4242, &cam);
	assert(waiting(fd) < 0 && cam_gone(cam));
	close(cam);
	for (int i = 0; i < TLS_WAITING; i++) { tls_drop(i, "test"); close(cams[i]); }
	printf("ok: tls socket: other uids closed, SO_SNDBUF %d, PROXY line within %d ms (a partial one too), bad "
	       "lines closed, at most %d waiting\n", sb, PROXY_MS, TLS_WAITING);

	/* the line and the first request in one write: only the line is read; the request is the
	 * client's first, under its address */
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	static const char both[] = "PROXY TCP4 10.1.9.9 192.0.2.5 40001 322\r\nOPTIONS rtsps://192.0.2.5:322/ RTSP/1.0\r\nCSeq: 1\r\n\r\n";
	assert(send(cam, both, sizeof both - 1, 0) == (ssize_t)sizeof both - 1);
	tls_proxy_in(w);
	a = NULL;
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd == fd) a = &clients[i];
	assert(a && a->tls && a->ip.s_addr == inet_addr("10.1.9.9") && a->local.s_addr == inet_addr("192.0.2.5") &&
	       a->lport == 322 && !strcmp(a->peer, "10.1.9.9:40001 (TLS)"));
	peers[a - clients] = cam;
	on(a);
	rx_len = 0;
	client_input(a);
	drain(a);
	rx[rx_len] = 0;
	assert(strstr((char *)rx, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n") && strstr((char *)rx, "Public:"));
	drop_all();

	/* per address, on the PROXY line's address: two clients through the one socket are two
	 * addresses; the TCP port and camtls count together */
	a = tconn("10.1.0.1", 1000);
	mono_adj += 10;
	b = tconn("10.1.0.1", 1001);
	assert(a && b && a->tls && b->tls && a->ip.s_addr == inet_addr("10.1.0.1"));
	assert(!tconn("10.1.0.1", 1002));
	assert(!conn("10.1.0.1"));
	c = tconn("10.1.0.2", 1000);
	assert(c && c->ip.s_addr == inet_addr("10.1.0.2"));
	mono_adj += 10;
	d = conn("10.1.0.3");
	assert(d && !d->tls);
	int ai = (int)(a - clients), ap = peers[ai];
	peers[ai] = -1;                                 /* keep a's end to see it evicted */
	mono_adj += 10;
	e = tconn("10.1.0.4", 7);                       /* every slot taken: the oldest goes */
	assert(e == &clients[ai] && e->tls && cam_gone(ap));
	close(ap);
	assert(login(b, "secret") && login(c, "secret") && login(d, "secret") && login(e, "secret"));
	assert(!tconn("10.1.0.5", 1));                  /* 4 logged in: refused, TLS or not */
	drop_all();
	printf("ok: tls clients: per-address limit on the PROXY address (two addresses through one socket), shared "
	       "with the port; the %d slots shared, eviction of the oldest not logged in\n", MAX_CLIENTS);

	/* LOGIN_MS counts from the accept, not from the PROXY line */
	fd = tls_open(4242, &cam);
	w = waiting(fd);
	mono_adj += 900;
	assert(send(cam, "PROXY TCP4 10.1.4.1 192.0.2.5 2 322\r\n", 37, 0) == 37);
	tls_proxy_in(w);
	a = NULL;
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (clients[i].fd == fd) a = &clients[i];
	assert(a);
	peers[a - clients] = cam;
	mono_adj += LOGIN_MS - 900 - 20;
	tick_all();
	assert(a->fd >= 0);
	mono_adj += 21;
	tick_all();
	assert(a->fd < 0 && cam_gone(cam));
	drop_all();

	/* lockout on the PROXY address: shared with the port, not with camtls's other clients */
	lockout_reset();
	a = tconn("10.1.1.1", 5000);
	for (int k = 0; k < 4; k++) assert(!login(a, "wrong"));
	assert(!login(a, "wrong") && a->fd < 0);       /* the 5th: closed */
	a = tconn("10.1.1.1", 5001);
	assert(!login(a, "secret") && a->fd >= 0);     /* locked */
	b = conn("10.1.1.1");
	assert(!login(b, "secret"));                    /* on the port too */
	c = tconn("10.1.1.2", 5000);
	assert(login(c, "secret"));                     /* another client through camtls isn't */
	mono_adj += (FAIL_WINDOW + 1) * 1000LL;
	assert(login(a, "secret"));
	drop_all();
	lockout_reset();
	printf("ok: tls clients: login deadline from the accept; the lockout keyed by the PROXY address (shared "
	       "with the port, not with other clients of camtls)\n");

	/* a PROXY line on the port is just a bad request: 401, then 501; the address stays */
	a = conn("10.1.2.1");
	on(a);
	request(a, "PROXY TCP4 1.2.3.4 192.0.2.5 1234 322\r\nCSeq: 1\r\n\r\n", "RTSP/1.0 401");
	assert(login(a, "secret"));
	on(a);
	request(a, "PROXY TCP4 1.2.3.4 192.0.2.5 1234 322\r\nCSeq: 2\r\n\r\n", "501 Not Implemented");
	assert(!a->tls && a->ip.s_addr == inet_addr("10.1.2.1"));
	drop_all();

	/* Digest, DESCRIBE/SETUP/PLAY with rtsps:// URLs, the SDP and Content-Base on the PROXY line's
	 * camera address, then interleaved RTP like the port's */
	a = tconn("10.1.3.1", 40000);
	on(a);
	request(a, "DESCRIBE rtsps://cam.example:322/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", "401 Unauthorized");
	digest_hdr(az, sizeof az, "DESCRIBE", "rtsps://cam.example:322/", "secret");
	snprintf(l, sizeof l, "DESCRIBE rtsps://cam.example:322/ RTSP/1.0\r\nCSeq: 2\r\n%s\r\n", az);
	request(a, l, "200 OK");
	assert(a->authed && strstr((char *)rx, "\r\no=- 1 1 IN IP4 192.0.2.5\r\n") &&
	       strstr((char *)rx, "Content-Base: rtsps://192.0.2.5:322//\r\n") && strstr((char *)rx, "H265/90000"));
	request(a, "DESCRIBE rtsp://other/x RTSP/1.0\r\nCSeq: 3\r\n\r\n", "Content-Base: rtsps://192.0.2.5:322/x/\r\n");
	request(a, "DESCRIBE * RTSP/1.0\r\nCSeq: 4\r\n\r\n", "Content-Base: rtsps://192.0.2.5:322/\r\n");
	streams[1].on = 1;
	request(a, "DESCRIBE rtsps://cam.example:322/sub RTSP/1.0\r\nCSeq: 5\r\n\r\n",
		"Content-Base: rtsps://192.0.2.5:322/sub/\r\n");
	assert(a->stream == 1);
	streams[1].on = 0;
	request(a, "DESCRIBE rtsps://cam.example:322/sub RTSP/1.0\r\nCSeq: 6\r\n\r\n", "404 Not Found");
	request(a, "SETUP rtsps://192.0.2.5:322//track0 RTSP/1.0\r\nCSeq: 7\r\nTransport: RTP/AVP/TCP;unicast;"
		"interleaved=0-1\r\n\r\n", "interleaved=0-1");
	assert(a->stream == 0 && a->video);
	snprintf(l, sizeof l, "PLAY rtsps://192.0.2.5:322// RTSP/1.0\r\nCSeq: 8\r\nSession: %s\r\n\r\n", a->session);
	request(a, l, "Range: npt=0.000-");
	/* and a port client for comparison: the same o= line only through camtls */
	b = conn("10.1.3.2");
	assert(login(b, "secret") && !strstr((char *)rx, "IN IP4 192.0.2.5") && !strstr((char *)rx, "rtsps://"));
	struct nal all[4096];
	static uint8_t au[1 << 20];
	int nall = split_nals(in, in_n, all, 4096), aus = 0, start = 0;
	for (int i = 0; i < nall && aus < 30; i++) {
		int type = (all[i].p[0] >> 1) & 0x3f;
		if (type >= 32 && i + 1 < nall) continue;
		size_t from = (size_t)(all[start].p - in), to = (size_t)(all[i].p - in) + all[i].n, au_n;
		while (from > 0 && in[from - 1] != 0) from--;
		while (from > 0 && in[from - 1] == 0) from--;
		memcpy(frame, in + from, to - from);
		on(a);
		rx_len = 0;
		on_frame(0, frame, to - from);
		drain(a);
		assert(depack_h265(rx, rx_len, au, &au_n) == 1);
		struct nal got[MAX_NALS];
		int ng = split_nals(au, au_n, got, MAX_NALS);
		assert(ng == i - start + 1);
		for (int k = 0; k < ng; k++)
			assert(got[k].n == all[start + k].n && !memcmp(got[k].p, all[start + k].p, got[k].n));
		aus++;
		start = i + 1;
	}
	assert(aus == 30 && a->sent > 0 && !a->drops);
	on(a);
	request(a, "TEARDOWN rtsps://192.0.2.5:322// RTSP/1.0\r\nCSeq: 9\r\n\r\n", "200 OK");
	assert(a->fd < 0);
	drop_all();
	printf("ok: tls client: Digest on rtsps:// URLs, SDP o= and Content-Base rtsps://<PROXY dst>:322, /sub, "
	       "%d access units of interleaved H.265 byte-identical, TEARDOWN\n", aus);

	/* -t PATH:USER: a user from passwd or UID:GID, its uid and primary group; bad ones refused
	 * (main logs them and goes on without the socket) */
	char pw[600], gr[600];
	const char *why = "";
	snprintf(pw, sizeof pw, "%s/test_tls_passwd", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	snprintf(gr, sizeof gr, "%s/test_tls_group", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	FILE *f = fopen(pw, "w");
	fputs("root:x:0:0:root:/:/bin/sh\nrtspd:x:100:100:rtspd:/:/bin/false\ncamtls:x:103:103:camtls:/:/bin/false\n", f);
	fclose(f);
	f = fopen(gr, "w");
	fputs("root:x:0:\ncamtls:x:103:\n", f);
	fclose(f);
	tls_path = NULL;
	assert(!tls_option("/run/rtspd/tls.sock:camtls", pw, gr, &why) && !strcmp(tls_path, "/run/rtspd/tls.sock") &&
	       tls_uid == 103 && tls_gid == 103);
	assert(!tls_option("/tmp/t.sock:104:105", pw, gr, &why) && !strcmp(tls_path, "/tmp/t.sock") &&
	       tls_uid == 104 && tls_gid == 105);
	char longp[200];
	memset(longp, 'a', sizeof longp);
	memcpy(longp + 150, ":camtls", 8);
	static const char *const t_bad[] = { "/run/rtspd/tls.sock", ":camtls", "/x:", "/x:nosuch", "/x:root",
		"/x:0:0", "/x:103:x" };
	tls_path = NULL;
	for (unsigned i = 0; i < sizeof t_bad / sizeof t_bad[0]; i++)
		assert(tls_option(t_bad[i], pw, gr, &why) < 0 && !tls_path);
	assert(tls_option(longp, pw, gr, &why) < 0 && !tls_path);
	assert(tls_listen(longp, getgid()) < 0);
	unlink(pw);
	unlink(gr);
	/* the socket file: 0660, the group given; its accept goes through the uid check */
	char sp[512];
	snprintf(sp, sizeof sp, "%s/test_tls.sock", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	int tfd = strlen(sp) < sizeof ((struct sockaddr_un *)0)->sun_path ? tls_listen(sp, getgid()) : -1;
	if (tfd < 0) {
		printf("ok: -t PATH:USER parsed, bad ones refused (tls socket file SKIPPED: bind not permitted here)\n");
		return;
	}
	struct stat st;
	assert(!stat(sp, &st) && (st.st_mode & 0777) == 0660 && st.st_gid == getgid());
	int cl = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, sp);
	assert(!connect(cl, (struct sockaddr *)&sa, sizeof sa));
	tls_uid = geteuid();                            /* the real peer_uid: ours */
	tls_accept(tfd);
	int k = 0;
	while (k < TLS_WAITING && !tls_wait[k].on) k++;
	assert(k < TLS_WAITING);
	tls_drop(k, "test");
	close(cl);
	close(tfd);
	unlink(sp);
	printf("ok: -t PATH:USER parsed, bad ones refused; tls socket file 0660 with the group, accept checks the uid\n");
}

int main(int argc, char **argv)
{
	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: %s in.h265 out.h265 [in.h264]\n", argv[0]);
		return 2;
	}
	streams[0].on = 1;
	streams[0].codec = MI_H265;
	FILE *f = fopen(argv[1], "rb");
	static uint8_t in[16 << 20];
	size_t in_n = fread(in, 1, sizeof in, f);
	fclose(f);

	int sv[2];
	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	peer = sv[1];
	for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;
	struct client *c = &clients[0];
	c->fd = sv[0];
	c->last = time(NULL);
	strcpy(c->peer, "test");

	/* parameter sets arrive with the first frame, so DESCRIBE after one frame */
	struct nal all[4096];
	int nall = split_nals(in, in_n, all, 4096);
	printf("input: %zu bytes, %d NALs\n", in_n, nall);

	request(c, "OPTIONS rtsp://cam/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", "RTSP/1.0 200 OK");
	request(c, "SETUP rtsp://cam/track0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP;unicast;client_port=5000-5001\r\n\r\n",
		"461 Unsupported Transport");
	request(c, "PLAY rtsp://cam/ RTSP/1.0\r\nCSeq: 3\r\nSession: X\r\n\r\n", "455");
	request(c, "SETUP rtsp://cam/track0 RTSP/1.0\r\nCSeq: 4\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n",
		"interleaved=0-1");
	char play[256];
	snprintf(play, sizeof play, "PLAY rtsp://cam/ RTSP/1.0\r\nCSeq: 5\r\nSession: %s\r\n\r\n", c->session);
	request(c, play, "Range: npt=0.000-");

	/* group NALs into access units: a VCL NAL (type < 32) ends one (single-slice encoder) */
	int aus = 0, start = 0;
	for (int i = 0; i < nall; i++) {
		int type = (all[i].p[0] >> 1) & 0x3f;
		if (type >= 32 && i + 1 < nall) continue;
		size_t from = (size_t)(all[start].p - in), to = (size_t)(all[i].p - in) + all[i].n;
		/* hand on_frame the AU with its start codes, like the encoder does */
		while (from > 0 && in[from - 1] != 0) from--;
		while (from > 0 && in[from - 1] == 0) from--;
		memcpy(frame, in + from, to - from);
		rx_len = 0;
		on_frame(0, frame, to - from);
		drain(c);
		/* depacketize what this AU produced */
		static uint8_t au[1 << 20];
		size_t au_n = 0, o = 0;
		int markers = 0;
		while (o + 4 <= rx_len) {
			assert(rx[o] == '$' && rx[o + 1] == 0);
			size_t len = ((size_t)rx[o + 2] << 8) | rx[o + 3];
			uint8_t *r = rx + o + 4, *p = r + 12;
			size_t pn = len - 12;
			assert((r[0] & 0xc0) == 0x80 && (r[1] & 0x7f) == 96);
			markers += r[1] >> 7;
			int t = (p[0] >> 1) & 0x3f;
			if (t == 49) {
				if (p[2] & 0x80) {
					memcpy(au + au_n, "\0\0\0\1", 4); au_n += 4;
					au[au_n++] = (uint8_t)((p[0] & 0x81) | ((p[2] & 0x3f) << 1));
					au[au_n++] = p[1];
				}
				memcpy(au + au_n, p + 3, pn - 3); au_n += pn - 3;
			} else {
				memcpy(au + au_n, "\0\0\0\1", 4); au_n += 4;
				memcpy(au + au_n, p, pn); au_n += pn;
			}
			o += 4 + len;
		}
		assert(o == rx_len);
		assert(markers == 1);
		struct nal got[MAX_NALS];
		int ng = split_nals(au, au_n, got, MAX_NALS);
		assert(ng == i - start + 1);
		for (int k = 0; k < ng; k++)
			assert(got[k].n == all[start + k].n && !memcmp(got[k].p, all[start + k].p, got[k].n));
		FILE *o2 = fopen(argv[2], aus ? "ab" : "wb");
		fwrite(au, 1, au_n, o2);
		fclose(o2);
		aus++;
		start = i + 1;
	}
	printf("ok: %d access units round-tripped byte-identical, one marker each\n", aus);

	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 6\r\nAccept: application/sdp\r\n\r\n", "sprop-vps=");
	request(c, "GET_PARAMETER rtsp://cam/ RTSP/1.0\r\nCSeq: 7\r\n\r\n", "200 OK");
	/* a client that never reads: frames must be dropped, memory must stay bounded */
	c->want_key = 0;
	unsigned before = c->drops;
	for (int k = 0; k < 2000 && c->drops == before; k++) {
		memcpy(frame, in, in_n > sizeof frame ? sizeof frame : in_n);
		on_frame(0, frame, in_n > sizeof frame ? sizeof frame : in_n);
	}
	assert(c->drops > before && c->want_key == 1);
	assert(c->out_len - c->out_off <= OUT_CAP);
	printf("ok: stalled client drops frames (%u) and waits for a keyframe; buffer bounded\n", c->drops);
	rx_len = 0;
	while (recv(peer, rx, sizeof rx, MSG_DONTWAIT) > 0) {}
	c->out_off = c->out_len = 0;
	/* audio (#110): µ-law values, the 16 -> 8 kHz low-pass, SDP + SETUP track1 + a PCMU packet */
	assert(audio_ulaw(0) == 0xff && audio_ulaw(-1) == 0x7f && audio_ulaw(32767) == 0x80 &&
	       audio_ulaw(-32768) == 0x00);
	for (int v = -32768; v < 32768; v += 97) {
		int d = ulaw_dec(audio_ulaw((int16_t)v)), err = d - v;
		assert(err <= 1100 && err >= -1100);            /* within one µ-law step */
	}
	double pass = tone_rms(1000), stop = tone_rms(6000);
	assert(pass > 6000 && pass < 8000 && stop < pass / 10);    /* 10000-peak tone: rms ~7071 */
	printf("ok: audio: µ-law within a step, 1 kHz passes (rms %.0f), 6 kHz stopped (rms %.0f)\n", pass, stop);
	audio_on = 1;
	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 9\r\n\r\n", "a=rtpmap:0 PCMU/8000");
	request(c, "SETUP rtsp://cam/track1 RTSP/1.0\r\nCSeq: 10\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n",
		"interleaved=2-3");
	assert(c->audio && c->ach == 2);
	c->playing = 1;
	rx_len = 0;
	audio_reset(1000);
	static int16_t sil[640];
	audio_feed(sil, 640, audio_emit);                        /* 640 @16k -> 320 @8k: one frame */
	drain(c);
	assert(rx_len == 4 + 12 + AUDIO_FRAME && rx[0] == '$' && rx[1] == 2 && rx[5] == 0x80 &&
	       rx[8] == 0 && rx[9] == 0 && rx[10] == 0x03 && rx[11] == 0xe8 && rx[16] == 0xff);
	audio_on = 0;
	request(c, "SETUP rtsp://cam/track1 RTSP/1.0\r\nCSeq: 11\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n",
		"404");
	printf("ok: audio: SDP PCMU/8000 track1, SETUP interleaved 2-3, one 40 ms PT 0 packet (marker, ts)\n");
	/* backchannel (#117): decoders, 8 -> 16 kHz level, RTP parsing, DESCRIBE/SETUP, routing */
	for (int v = -32000; v <= 32000; v += 101) {
		int d = audio_ulaw_dec(audio_ulaw((int16_t)v));
		assert(d - v <= 1100 && v - d <= 1100);
	}
	assert(audio_alaw_dec(0xd5) == 8 && audio_alaw_dec(0x55) == -8 && audio_alaw_dec(0xaa) == 32256);
	uint8_t pk[12 + 160];                                    /* 20 ms of a 1 kHz tone, µ-law */
	memset(pk, 0, 12);
	pk[0] = 0x80;
	for (int i = 0; i < 160; i++) pk[12 + i] = audio_ulaw((int16_t)(10000 * sin(2 * M_PI * 1000 * i / 8000)));
	up_acc = 0; up_n = 0;
	for (int r = 0; r < 20; r++) assert(audio_rtp_in(pk, sizeof pk, up_sink) > 9000);   /* peak ~10000 */
	double up_rms = sqrt(up_acc / up_n);
	assert(up_n == 20 * 320 && up_rms > 6000 && up_rms < 8000);   /* level kept: ~7071 */
	pk[1] = 96; assert(audio_rtp_in(pk, sizeof pk, up_sink) < 0); pk[1] = 0;       /* not G.711 */
	pk[0] = 0x40; assert(audio_rtp_in(pk, sizeof pk, up_sink) < 0); pk[0] = 0x80;  /* version 1 */
	pk[0] = 0xa0; pk[sizeof pk - 1] = 200; assert(audio_rtp_in(pk, sizeof pk, up_sink) < 0); /* bad padding */
	pk[0] = 0x8f; assert(audio_rtp_in(pk, 20, up_sink) < 0); pk[0] = 0x80;          /* CSRCs past end */
	assert(audio_rtp_in(pk, 11, up_sink) < 0);
	for (int i = 0; i < 20000; i++) {                       /* garbage: no crash */
		uint8_t g[300];
		random_bytes(g, sizeof g);
		(void)audio_rtp_in(g, (unsigned)(g[0] % 300), up_sink);
	}
	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 12\r\nRequire: www.onvif.org/ver20/backchannel\r\n\r\n",
		"200 OK");
	assert(!strstr((char *)rx, "track2"));                   /* no speaker: not offered */
	speaker_on = 1;
	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 13\r\nRequire: www.onvif.org/ver20/backchannel\r\n\r\n",
		"a=control:track2\r\na=sendonly");
	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 14\r\n\r\n", "200 OK");
	assert(!strstr((char *)rx, "track2"));                   /* only when asked for */
	request(c, "SETUP rtsp://cam/track2 RTSP/1.0\r\nCSeq: 15\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n\r\n",
		"interleaved=4-5");
	assert(c->talk && c->tch == 4 && !talker);                  /* the speaker goes to audio */
	c->playing = 1;
	ao_samples = 0;
	uint8_t il[4 + sizeof pk];
	il[0] = '$'; il[1] = 4; il[2] = 0; il[3] = sizeof pk;
	memcpy(il + 4, pk, sizeof pk);
	assert(send(peer, il, sizeof il, 0) == (ssize_t)sizeof il);
	client_input(c);
	assert(ao_samples == 320 && talker == c);                /* 160 @8k -> 320 @16k to the speaker */
	{       /* a second connection (SSS opens several): its SETUP succeeds; its silence and, while c
		 * talks, its audio don't take the speaker; after TALK_IDLE_MS quiet, its audio does */
		int sv2[2], p1 = peer;
		assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv2));
		fcntl(sv2[0], F_SETFL, O_NONBLOCK);
		fcntl(sv2[1], F_SETFL, O_NONBLOCK);
		struct client *c2 = &clients[1];
		memset(c2, 0, offsetof(struct client, out));
		c2->fd = sv2[0];
		c2->last = time(NULL);
		strcpy(c2->peer, "test2");
		peer = sv2[1];
		request(c2, "SETUP rtsp://cam/track2 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n\r\n",
			"200 OK");
		c2->playing = 1;
		uint8_t q[4 + sizeof pk];
		memcpy(q, il, sizeof q);
		for (int i = 0; i < 160; i++) q[16 + i] = 0xff;     /* µ-law silence */
		ao_samples = 0;
		assert(send(peer, q, sizeof q, 0) == (ssize_t)sizeof q);
		client_input(c2);
		assert(talker == c && ao_samples == 0);
		assert(send(peer, il, sizeof il, 0) == (ssize_t)sizeof il);   /* audible, c just talked */
		client_input(c2);
		assert(talker == c && ao_samples == 0);
		talk_loud_ms -= TALK_IDLE_MS + 1;                   /* c quiet for longer */
		assert(send(peer, il, sizeof il, 0) == (ssize_t)sizeof il);
		client_input(c2);
		assert(talker == c2 && ao_samples == 320);
		client_close(c2, "test");
		assert(!talker);
		close(sv2[1]);
		peer = p1;
	}
	{                                                       /* talk-only: no video sent */
		static const uint8_t au[] = { 0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00 };
		uint8_t junk[4096];
		int had = c->video;
		while (recv(peer, junk, sizeof junk, MSG_DONTWAIT) > 0) {}
		c->video = 0;
		on_frame(0, au, sizeof au);
		assert(recv(peer, junk, sizeof junk, MSG_DONTWAIT) < 0);
		c->video = had;
	}
	speaker_on = 0;
	printf("ok: backchannel: G.711 decode, 8->16 kHz level kept (rms %.0f), RTP checks, track2 offered on "
	       "Require only, SETUP for every client, audible packets take the speaker, talk-only gets no video\n", up_rms);
	request(c, "TEARDOWN rtsp://cam/ RTSP/1.0\r\nCSeq: 8\r\nSession: x\r\n\r\n", "200 OK");
	assert(c->fd < 0);
	printf("ok: teardown closes the session\n");

	if (argc == 4) {
		assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
		fcntl(sv[0], F_SETFL, O_NONBLOCK);
		fcntl(sv[1], F_SETFL, O_NONBLOCK);
		peer = sv[1];
		memset(c, 0, offsetof(struct client, out));
		c->fd = sv[0];
		c->out_off = c->out_len = 0;
		c->ready = c->playing = c->closing = c->want_key = c->stream = 0;
		c->last = time(NULL);
		strcpy(c->peer, "h264");
		test_h264(c, argv[3]);
		close(c->fd);
		c->fd = -1;
	}

	/* MD5 (RFC 1321 appendix A.5) */
	static const char *mv[][2] = {
		{ "", "d41d8cd98f00b204e9800998ecf8427e" },
		{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
		{ "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		  "57edf4a22be3c955ac49da2e2107b67a" },
	};
	for (unsigned i = 0; i < sizeof mv / sizeof mv[0]; i++) {
		char h[33];
		md5_hex(mv[i][0], strlen(mv[i][0]), h);
		assert(!strcmp(h, mv[i][1]));
	}
	printf("ok: MD5 matches RFC 1321 vectors\n");

	/* Digest: htdigest "admin:camera:HA1", HA1 = MD5(admin:camera:secret) */
	char ha1[33], path[512], line[128];
	snprintf(path, sizeof path, "%s/test_rtspd_htdigest", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	md5_hex("admin:camera:secret", 19, ha1);
	FILE *hf = fopen(path, "w");
	assert(hf);
	fprintf(hf, "admin:camera:%s\n", ha1);
	fclose(hf);
	assert(!auth_load(path) && auth_enabled() && !strcmp(auth_realm(), "camera"));
	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	peer = sv[1];
	memset(c, 0, offsetof(struct client, out));
	c->fd = sv[0];
	c->out_off = c->out_len = 0;
	c->ready = c->playing = c->closing = c->authed = c->auth_fails = 0;
	strcpy(c->peer, "auth");
	strcpy(c->nonce, "0123456789abcdef0123456789abcdef");
	request(c, "OPTIONS rtsp://cam/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", "200 OK");
	request(c, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 2\r\n\r\n",
		"WWW-Authenticate: Digest realm=\"camera\", nonce=\"0123456789abcdef0123456789abcdef\"");
	char ha2[33], resp[33], req2[1024];
	/* wrong password */
	char bad1[33];
	md5_hex("admin:camera:wrong", 18, bad1);
	snprintf(line, sizeof line, "%s:%s:", bad1, c->nonce);
	md5_hex("DESCRIBE:rtsp://cam/", 20, ha2);
	char tmp[128];
	snprintf(tmp, sizeof tmp, "%s:%s:%s", bad1, c->nonce, ha2);
	md5_hex(tmp, strlen(tmp), resp);
	snprintf(req2, sizeof req2, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 3\r\nAuthorization: Digest "
		 "username=\"admin\", realm=\"camera\", nonce=\"%s\", uri=\"rtsp://cam/\", "
		 "response=\"%s\"\r\n\r\n", c->nonce, resp);
	request(c, req2, "401 Unauthorized");
	assert(!c->authed && c->auth_fails == 1);
	/* correct, no qop */
	snprintf(tmp, sizeof tmp, "%s:%s:%s", ha1, c->nonce, ha2);
	md5_hex(tmp, strlen(tmp), resp);
	snprintf(req2, sizeof req2, "DESCRIBE rtsp://cam/ RTSP/1.0\r\nCSeq: 4\r\nAuthorization: Digest "
		 "username=\"admin\", realm=\"camera\", nonce=\"%s\", uri=\"rtsp://cam/\", "
		 "response=\"%s\"\r\n\r\n", c->nonce, resp);
	request(c, req2, "200 OK");
	assert(c->authed);
	printf("ok: Digest 401 challenge, wrong password refused, correct response accepted\n");
	/* qop=auth, checked directly */
	snprintf(tmp, sizeof tmp, "%s:%s:00000001:abcdef:auth:%s", ha1, c->nonce, ha2);
	md5_hex(tmp, strlen(tmp), resp);
	snprintf(req2, sizeof req2, "Digest username=\"admin\", realm=\"camera\", nonce=\"%s\", "
		 "uri=\"rtsp://cam/\", qop=auth, nc=00000001, cnonce=\"abcdef\", response=\"%s\"",
		 c->nonce, resp);
	char who[64];
	assert(auth_check(req2, "DESCRIBE", c->nonce, who, sizeof who) && !strcmp(who, "admin"));
	assert(!auth_check(req2, "DESCRIBE", "ffffffffffffffffffffffffffffffff", who, sizeof who));
	printf("ok: Digest qop=auth accepted; stale nonce refused\n");
	test_slots_and_logins();
	test_proxy_parse();
	test_tls(in, in_n);
	test_max_users(path);
	mono_adj = 0;

	/* control socket (#73): parser, then the real unix socket path */
	char out[4096], l1[128];
	strcpy(l1, "set image.saturation 40\n"); ctl_line(l1, out, sizeof out);
	assert(!strcmp(out, "ok\n") && mi_image_get(MI_IMG_SATURATION) == 40);
	strcpy(l1, "set image.bogus 40"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err unknown key"));
	strcpy(l1, "set image.contrast 101"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err value"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "image.saturation=40\n") && strstr(out, "image.exposure=50\n") && strstr(out, "ok\n"));
	strcpy(l1, "frobnicate"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err unknown command"));
	htdigest_path = path;
	strcpy(l1, "auth-reload"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.contrast 40 x"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err value"));
	char bad[512];                       /* a reload from an unusable file keeps the old users */
	snprintf(bad, sizeof bad, "%s.bad", path);
	FILE *bf = fopen(bad, "w");
	fputs("garbage\nadmin:camera:nothex\n", bf);
	fclose(bf);
	htdigest_path = bad;
	strcpy(l1, "auth-reload"); ctl_line(l1, out, sizeof out); assert(strstr(out, "kept old users"));
	assert(auth_enabled() && !strcmp(auth_realm(), "camera"));
	unlink(bad);
	htdigest_path = path;
	/* stream settings from cam.conf (owner: H.264 default; values out of range are ignored) */
	struct mi_cfg sc = { .codec = MI_H264, .kbps = 4000, .fps = 25, .gop = 100, .sub_w = 640,
			     .sub_h = 360, .sub_codec = MI_H264, .sub_kbps = 500, .sub_fps = 25 };
	struct dn_cfg sdn = DN_CFG_DEFAULT;
	char conf[512];
	snprintf(conf, sizeof conf, "%s.conf", path);
	FILE *cf = fopen(conf, "w");
	fputs("stream.main.codec=h265\nstream.main.kbps=6000\nstream.main.gop=50\nstream.sub.fps=99\n"
	      "stream.sub.kbps=300\nstream.main.codec=mjpeg\nimage.contrast=60\nother=1\n"
	      "daynight.mode=night\ndaynight.irled=150\nstream.main.rc=cbr\nstream.sub.profile=main\n"
	      "stream.main.profile=ultra\n", cf);
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	assert(sc.codec == MI_H265 && sc.kbps == 6000 && sc.gop == 50);
	assert(sc.sub_fps == 25 && sc.sub_kbps == 300 && mi_image_get(MI_IMG_CONTRAST) == 60);
	assert(sdn.mode == DN_NIGHT && sdn.irled == 96);    /* 150 out of range: ignored */
	assert(sc.rc == MI_RC_CBR && sc.sub_profile == MI_PROFILE_MAIN && sc.profile == 0);
	cf = fopen(conf, "w");
	fputs("stream.sub.enabled=0\n", cf);
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	assert(sc.sub_w == 0);
	/* sizes (streamcfg.h's only, cam.conf over -w/-h/-s), fps 1..30, kbps by size when unset, the
	 * sub-stream at most the main's fps and inside the main picture */
	{
		char slog[2048];
		struct mi_cfg z = { .w = 2560, .h = 1440, .fps = 30, .sub_w = 320, .sub_h = 180, .sub_fps = 30 };
		cf = fopen(conf, "w");                  /* as if -s 320x180 */
		fputs("stream.main.size=1920x1080\nstream.sub.size=1280x720\nstream.main.fps=30\nstream.sub.fps=31\n"
		      "stream.main.size=640x360\nstream.sub.size=2560x1440\nstream.sub.size=1280X720\n"
		      "stream.sub.size=1280x720 \nstream.main.size=2560x1080\n", cf);
		fclose(cf);
		load_logged(conf, &z, &sdn, slog, sizeof slog);
		assert(z.w == 1920 && z.h == 1080 && z.sub_w == 1280 && z.sub_h == 720 && z.fps == 30 && z.sub_fps == 30);
		assert(strstr(slog, "ignored stream.sub.fps=31") && strstr(slog, "ignored stream.main.size=640x360") &&
		       strstr(slog, "ignored stream.sub.size=2560x1440") && strstr(slog, "ignored stream.sub.size=1280X720") &&
		       strstr(slog, "ignored stream.sub.size=1280x720 \n") && strstr(slog, "ignored stream.main.size=2560x1080"));
		stream_resolve(&z);
		assert(z.kbps == 3000 && z.sub_kbps == 1500);
		static const struct { const char *size; int sub, w, h, kbps; } sz[] = {
			{ "2560x1440", 0, 2560, 1440, 4000 }, { "2304x1296", 0, 2304, 1296, 3500 },
			{ "1920x1080", 0, 1920, 1080, 3000 }, { "1280x720", 0, 1280, 720, 1500 },
			{ "640x360", 1, 640, 360, 500 }, { "960x540", 1, 960, 540, 900 }, { "1280x720", 1, 1280, 720, 1500 } };
		for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
			struct mi_cfg y = { .w = 2560, .h = 1440, .fps = 30, .sub_w = 640, .sub_h = 360, .sub_fps = 30 };
			assert(!stream_setting(&y, sz[i].sub ? "stream.sub.size" : "stream.main.size", sz[i].size));
			stream_resolve(&y);
			assert(sz[i].sub ? y.sub_w == sz[i].w && y.sub_h == sz[i].h && y.sub_kbps == sz[i].kbps
					 : y.w == sz[i].w && y.h == sz[i].h && y.kbps == sz[i].kbps && y.sub_kbps == 500);
		}
		/* set kbps kept whatever the size; -s 0 or stream.sub.enabled=0 (either order) keep the sub off */
		struct mi_cfg y = { .w = 2560, .h = 1440, .fps = 30, .kbps = 6000, .sub_w = 640, .sub_h = 360, .sub_fps = 30,
				    .sub_kbps = 700 };
		assert(!stream_setting(&y, "stream.main.size", "1280x720") && !stream_setting(&y, "stream.sub.size", "960x540"));
		stream_resolve(&y);
		assert(y.kbps == 6000 && y.sub_kbps == 700 && y.w == 1280 && y.sub_w == 960);
		y.sub_w = y.sub_h = 0;                  /* -s 0 */
		assert(!stream_setting(&y, "stream.sub.size", "1280x720") && y.sub_w == 0 && y.sub_h == 0);
		y.sub_w = 640; y.sub_h = 360;
		assert(!stream_setting(&y, "stream.sub.enabled", "0") && !stream_setting(&y, "stream.sub.size", "1280x720"));
		assert(y.sub_w == 0 && y.sub_h == 0);
		/* fps: 30 now in range; the sub clamped to the main's; a sub bigger than the main (bench -w/-h) off */
		y = (struct mi_cfg){ .w = 2560, .h = 1440, .fps = 30, .sub_w = 640, .sub_h = 360, .sub_fps = 30 };
		assert(!stream_setting(&y, "stream.main.fps", "15") && !stream_setting(&y, "stream.sub.fps", "30"));
		assert(stream_setting(&y, "stream.main.fps", "0") < 0 && y.fps == 15);
		stream_resolve(&y);
		assert(y.fps == 15 && y.sub_fps == 15);
		y = (struct mi_cfg){ .w = 1280, .h = 720, .fps = 30, .sub_w = 1280, .sub_h = 720, .sub_fps = 10 };
		stream_resolve(&y);
		assert(y.sub_w == 1280 && y.sub_fps == 10);
		y = (struct mi_cfg){ .w = 960, .h = 540, .fps = 30, .sub_w = 1280, .sub_h = 720, .sub_fps = 30 };
		stream_resolve(&y);
		assert(y.sub_w == 0 && y.sub_h == 0 && y.kbps == 1500);  /* not a listed main size: the smallest's */
		printf("ok: stream.*.size (listed sizes only, cam.conf over -s, sub off stays off), fps 1..30, "
		       "kbps by size when unset, sub fps <= main fps, sub inside main\n");
	}
	/* orientation and shutter limits go into the MI config for mi_start (not applied by hand);
	 * the day/night thresholds are a pair, checked after the whole file, in any line order */
	*mi_log = 0;
	cf = fopen(conf, "w");
	fputs("image.mirror=1\nimage.flip=1\nimage.shutter_day_max=1000\nimage.shutter_night_max=20000\n"
	      "daynight.night_below=2000\ndaynight.day_above=5000\n", cf);
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	assert(sc.mirror == 1 && sc.flip == 1 && sc.shutter_day_max == 1000 && sc.shutter_night_max == 20000);
	assert(sdn.night_below == 2000 && sdn.day_above == 5000 && !*mi_log);
	cf = fopen(conf, "w");
	fputs("image.mirror=2\nimage.flip=x\nimage.shutter_day_max=99\nimage.shutter_night_max=50001\n"
	      "daynight.day_above=9\ndaynight.night_below=10\n", cf);      /* all bad: kept as they were */
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	assert(sc.mirror == 1 && sc.flip == 1 && sc.shutter_day_max == 1000 && sc.shutter_night_max == 20000);
	assert(sdn.night_below == 2000 && sdn.day_above == 5000);
	cf = fopen(conf, "w");
	fputs("image.mirror=0\nimage.shutter_day_max=0\nimage.shutter_night_max=50000\n"
	      "daynight.day_above=10\ndaynight.night_below=5\n", cf);      /* day_above first: fine */
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	assert(sc.mirror == 0 && sc.flip == 1 && sc.shutter_day_max == 0 && sc.shutter_night_max == 50000);
	assert(sdn.night_below == 5 && sdn.day_above == 10);
	/* OSD (osd.c): cam.conf keys taken or ignored one by one; the title may hold spaces and '=' */
	cf = fopen(conf, "w");
	fputs("osd.time.pos=lr\nosd.time.format=MM/dd/yyyy\nosd.title.enabled=1\nosd.title.text= Gate 2 = east\n"
	      "osd.size=huge\nosd.title.pos=nowhere\nosd.bogus=1\n", cf);
	fclose(cf);
	load_settings(conf, &sc, &sdn);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "osd.time.enabled=1\nosd.time.pos=lr\n") && strstr(out, "osd.time.format=MM/dd/yyyy\n"));
	assert(strstr(out, "osd.title.enabled=1\nosd.title.pos=ll\n") && strstr(out, "osd.title.text= Gate 2 = east\n"));
	assert(strstr(out, "osd.size=small\n") && strstr(out, "osd.status=off\n") && !strstr(out, "tz_offset"));
	assert(strstr(out, "\nok\n") && strlen(out) < 2048);
	/* live */
	strcpy(l1, "set osd.style white-on-black"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set osd.time.x 100"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	static const char *const osd_bad[] = { "set osd.time.x 101", "set osd.time.pos middle", "set osd.size 1",
		"set osd.time.enabled", "set osd.time.enabled 1 x", "set osd.nope 1", "set osd.title.textx a",
		"set osd.time.format yyyy-MM-dd-and-more", "set osd.tz_offset -720" };
	for (unsigned i = 0; i < sizeof osd_bad / sizeof osd_bad[0]; i++) {
		strcpy(l1, osd_bad[i]); ctl_line(l1, out, sizeof out);
		if (strncmp(out, "err", 3)) { fprintf(stderr, "FAIL '%s' -> %s", osd_bad[i], out); return 1; }
	}
	strcpy(l1, "set osd.title.text Front door: 1 & 2\r\n"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "osd.title.text=Front door: 1 & 2\n") && strstr(out, "osd.style=white-on-black\n") &&
	       strstr(out, "osd.time.x=100\n"));
	strcpy(l1, "set osd.title.text 1234567890123456789012345678901234567890123456789");
	ctl_line(l1, out, sizeof out);
	assert(strstr(out, "err osd.title.text"));
	strcpy(l1, "set osd.title.text caf\xc3\xa9"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	strcpy(l1, "set osd.title.text"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "osd.title.text=\nosd.size"));
	printf("ok: osd.* from cam.conf (bad lines ignored) and live set/get; titles with spaces, '=' and empty\n");
	/* time.tz: TZ from cam.conf (the OSD clock's local time), live set/get; a leftover osd.tz_offset
	 * skipped without "ignored", with a hint only while there is no time.tz */
	char log[2048];
	time_t oct = 1792318567, dec = 1797502567;   /* 2026-10-18 10:16:07 and 2026-12-17 10:16:07 UTC */
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\ntime.tz=UTC0\nok\n"));
	cf = fopen(conf, "w");
	fputs("osd.tz_offset=-300\ntime.tz=CST6CDT,M3.2.0,M11.1.0\n", cf);
	fclose(cf);
	load_logged(conf, &sc, &sdn, log, sizeof log);
	assert(!strstr(log, "ignored") && !strstr(log, "tz_offset") && !strcmp(cur_tz, "CST6CDT,M3.2.0,M11.1.0"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\ntime.tz=CST6CDT,M3.2.0,M11.1.0\nok\n"));
	assert(!strcmp(local(oct), "2026-10-18 05:16:07"));    /* CDT, UTC-5 */
	assert(!strcmp(local(dec), "2026-12-17 04:16:07"));    /* CST, UTC-6 */
	cf = fopen(conf, "w");
	fputs("osd.tz_offset=60\n", cf);
	fclose(cf);
	load_logged(conf, &sc, &sdn, log, sizeof log);
	assert(!strstr(log, "ignored") && strstr(log, "osd.tz_offset is no longer used") &&
	       strstr(log, "camcfg unset osd.tz_offset"));
	cf = fopen(conf, "w");
	fputs("time.tz=EST5EDT;reboot\ntime.tz=:/etc/localtime\n", cf);
	fclose(cf);
	load_logged(conf, &sc, &sdn, log, sizeof log);
	assert(strstr(log, "ignored time.tz=EST5EDT;reboot") && strstr(log, "ignored time.tz=:/etc/localtime") &&
	       !strcmp(cur_tz, "CST6CDT,M3.2.0,M11.1.0"));               /* the last good one stays */
	strcpy(l1, "set time.tz <+0530>-5:30\r\n"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(local(oct), "2026-10-18 15:46:07"));
	strcpy(l1, "set time.tz NZST-12NZDT,M9.5.0,M4.1.0/3"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(local(oct), "2026-10-18 23:16:07"));     /* NZDT, UTC+13 */
	static const char *const tz_bad[] = { "set time.tz", "set time.tz ", "set time.tz CST6CDT x",
		"set time.tz CST6CDT,M3.2.0", "set time.tz $(reboot)", "set time.tz UTC25",
		"set time.tz <+0530>-05:30:00<+0630>-06:30:00,M3.2.0/02:00:00,M11.1.0/02:00:00",   /* 65 */
		"set time.tzx UTC0" };
	for (unsigned i = 0; i < sizeof tz_bad / sizeof tz_bad[0]; i++) {
		strcpy(l1, tz_bad[i]); ctl_line(l1, out, sizeof out);
		if (strncmp(out, "err", 3)) { fprintf(stderr, "FAIL '%s' -> %s", tz_bad[i], out); return 1; }
	}
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\ntime.tz=NZST-12NZDT,M9.5.0,M4.1.0/3\nok\n"));
	strcpy(l1, "set time.tz UTC0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(local(oct), "2026-10-18 10:16:07"));
	printf("ok: time.tz from cam.conf and live (OSD clock CDT in October, CST in December, +5:30, NZDT); "
	       "bad values refused, a leftover osd.tz_offset skipped with a hint\n");
	unlink(conf);
	/* live: set image.mirror/flip -> mi_orient with the other kept; shutter limits likewise */
	*mi_log = 0;
	or_m = 0; or_f = 1; sh_day = 0; sh_night = 0;
	strcpy(l1, "set image.mirror 1"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.flip 0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.shutter_day_max 500"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.shutter_night_max 40000"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(mi_log, "orient 1 1;orient 1 0;shutter 500 0;shutter 500 40000;"));
	static const char *const ix_bad[] = { "set image.mirror 2", "set image.flip -1", "set image.flip",
		"set image.mirror 1 x", "set image.shutter_day_max 99", "set image.shutter_day_max 1000001",
		"set image.shutter_night_max 50001", "set image.shutter_night_max 1/25", "set image.shutter_day_max 12345678" };
	*mi_log = 0;
	for (unsigned i = 0; i < sizeof ix_bad / sizeof ix_bad[0]; i++) {
		strcpy(l1, ix_bad[i]); ctl_line(l1, out, sizeof out);
		assert(!strncmp(out, "err image.mirror|flip 0|1", 25));
	}
	assert(!*mi_log);
	or_fail = 1;
	strcpy(l1, "set image.flip 1"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "err apply failed\n"));
	or_fail = 0;
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "image.mirror=1\nimage.flip=0\nimage.shutter_day_max=500\nimage.shutter_night_max=40000\n"));
	/* the thresholds live: night_below < day_above is kept, so the order of two sets matters */
	strcpy(l1, "set daynight.night_below 20"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set daynight.day_above 20"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	strcpy(l1, "set daynight.day_above 3000"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "daynight.night_below=20\ndaynight.day_above=3000\n") && strlen(out) < 1500);
	strcpy(l1, "set daynight.night_below 15"); ctl_line(l1, out, sizeof out);
	strcpy(l1, "set daynight.day_above 1500"); ctl_line(l1, out, sizeof out);
	printf("ok: image.mirror/flip and shutter limits: cam.conf into the MI config, live set/get, bad values refused;\n"
	       "    day/night thresholds as a pair from cam.conf in any order, and live\n");
	/* anti-flicker and ISP tuning: cam.conf (anti-flicker into the MI config, tuning queued in MI),
	 * live set/get, bad values refused */
	cf = fopen(conf, "w");
	fputs("image.antiflicker=1\nimage.mains_hz=50\nimage.nr2d=64\nimage.nr3d=255\nimage.wdr=0\nimage.blc=90\n"
	      "image.nr2d=256\nimage.nr3d=-1\nimage.wdr=12a\nimage.blc=\nimage.antiflicker=2\nimage.mains_hz=55\n", cf);
	fclose(cf);
	memset(&sc, 0, sizeof sc);
	*mi_log = 0;
	load_settings(conf, &sc, &sdn);
	assert(sc.antiflicker == 1 && sc.mains_hz == 50);
	assert(!strcmp(mi_log, "tune 0 64;tune 1 255;tune 2 0;tune 3 90;"));
	unlink(conf);
	*mi_log = 0;
	af_on = 0; af_hz = 60;
	strcpy(l1, "set image.antiflicker 1"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.mains_hz 50"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.nr3d 200"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.wdr 0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(mi_log, "af 1 60;af 1 50;tune 1 200;tune 2 0;"));
	static const char *const tk_bad[] = { "set image.nr2d 256", "set image.nr3d -1", "set image.wdr", "set image.blc 1 x",
		"set image.blc 0x10", "set image.nr2d 1000" };
	*mi_log = 0;
	for (unsigned i = 0; i < sizeof tk_bad / sizeof tk_bad[0]; i++) {
		strcpy(l1, tk_bad[i]); ctl_line(l1, out, sizeof out);
		assert(!strcmp(out, "err image.nr2d|nr3d|wdr|blc 0..255\n"));
	}
	static const char *const af_bad[] = { "set image.antiflicker 2", "set image.mains_hz 55", "set image.mains_hz" };
	for (unsigned i = 0; i < sizeof af_bad / sizeof af_bad[0]; i++) {
		strcpy(l1, af_bad[i]); ctl_line(l1, out, sizeof out);
		assert(strstr(out, "image.antiflicker 0|1, image.mains_hz 50|60"));
	}
	assert(!*mi_log);
	tune_fail = 1;
	strcpy(l1, "set image.blc 10"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "err apply failed\n"));
	tune_fail = 0;
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "image.antiflicker=1\nimage.mains_hz=50\nimage.nr2d=64\nimage.nr3d=200\nimage.wdr=0\n"
		      "image.blc=90\n") && strlen(out) < 1700);
	printf("ok: anti-flicker and NR/WDR/BLC: cam.conf (bad values ignored), live set/get, bad values refused\n");
	/* stock night tuning: image.night_tuning 0|1 from cam.conf into the MI config, live set/get */
	cf = fopen(conf, "w");
	fputs("image.night_tuning=1\nimage.night_tuning=2\n", cf);
	fclose(cf);
	memset(&sc, 0, sizeof sc);
	load_settings(conf, &sc, &sdn);
	assert(sc.night_tuning == 1);
	unlink(conf);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out); assert(strstr(out, "image.blc=90\nimage.night_tuning=0\n"));
	strcpy(l1, "set image.night_tuning 1"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && nt_on == 1);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out); assert(strstr(out, "\nimage.night_tuning=1\n"));
	strcpy(l1, "set image.night_tuning 0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && nt_on == 0);
	static const char *const nt_bad[] = { "set image.night_tuning 2", "set image.night_tuning on", "set image.night_tuning" };
	for (unsigned i = 0; i < sizeof nt_bad / sizeof nt_bad[0]; i++) {
		strcpy(l1, nt_bad[i]); ctl_line(l1, out, sizeof out);
		assert(strstr(out, "err ") && strstr(out, "image.night_tuning 0|1") && !nt_on);
	}
	nt_loaded = 0;                                  /* an image without the night files */
	strcpy(l1, "set image.night_tuning 1"); ctl_line(l1, out, sizeof out);
	assert(!strcmp(out, "err image.night_tuning: no usable night tuning files in this image\n") && !nt_on);
	nt_loaded = 1;
	printf("ok: image.night_tuning: cam.conf into the MI config (bad values ignored), live set/get, bad values and "
	       "missing files refused\n");
	/* night exposure and the AE's ISP gain limits: cam.conf, live set/get */
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "image.exposure=50\nimage.exposure_night=day\nimage.mirror=") &&
	       strstr(out, "\nimage.night_tuning=0\nimage.isp_gain_day_max=4\nimage.isp_gain_night_max=2\n"));
	cf = fopen(conf, "w");
	fputs("image.exposure_night=30\nimage.exposure_night=101\nimage.exposure_night=night\nimage.exposure_night=\n"
	      "image.isp_gain_day_max=3\nimage.isp_gain_night_max=1\nimage.isp_gain_day_max=5\n"
	      "image.isp_gain_night_max=0\nimage.isp_gain_day_max=x\n", cf);
	fclose(cf);
	memset(&sc, 0, sizeof sc);
	*mi_log = 0;
	load_settings(conf, &sc, &sdn);
	assert(sc.isp_gain_day_max == 3 && sc.isp_gain_night_max == 1 && exp_night == 30 && !strcmp(mi_log, "expn 30;"));
	unlink(conf);
	*mi_log = 0;
	strcpy(l1, "set image.exposure_night 25"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && exp_night == 25);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out); assert(strstr(out, "\nimage.exposure_night=25\n"));
	strcpy(l1, "set image.exposure_night day"); ctl_line(l1, out, sizeof out);
	assert(!strcmp(out, "ok\n") && exp_night == MI_EXPOSURE_SAME);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out); assert(strstr(out, "\nimage.exposure_night=day\n"));
	strcpy(l1, "set image.exposure_night 0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && exp_night == 0);
	strcpy(l1, "set image.exposure_night 100"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && exp_night == 100);
	assert(!strcmp(mi_log, "expn 25;expn -1;expn 0;expn 100;"));
	static const char *const en_bad[] = { "set image.exposure_night 101", "set image.exposure_night -1",
		"set image.exposure_night Day", "set image.exposure_night", "set image.exposure_night 30 x",
		"set image.exposure_night 1000" };
	for (unsigned i = 0; i < sizeof en_bad / sizeof en_bad[0]; i++) {
		strcpy(l1, en_bad[i]); ctl_line(l1, out, sizeof out);
		assert(!strcmp(out, "err image.exposure_night day (as image.exposure) or 0..100\n") && exp_night == 100);
	}
	strcpy(l1, "set image.exposure_night day"); ctl_line(l1, out, sizeof out);
	*mi_log = 0;
	strcpy(l1, "set image.isp_gain_day_max 1"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set image.isp_gain_night_max 4"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	assert(!strcmp(mi_log, "isp 1 2;isp 1 4;") && isp_day == 1 && isp_night == 4);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\nimage.isp_gain_day_max=1\nimage.isp_gain_night_max=4\n"));
	static const char *const isp_bad[] = { "set image.isp_gain_day_max 0", "set image.isp_gain_day_max 5",
		"set image.isp_gain_night_max x", "set image.isp_gain_night_max", "set image.isp_gain_day_max 2 2" };
	for (unsigned i = 0; i < sizeof isp_bad / sizeof isp_bad[0]; i++) {
		strcpy(l1, isp_bad[i]); ctl_line(l1, out, sizeof out);
		assert(!strcmp(out, "err image.isp_gain_day_max|isp_gain_night_max 1..4 (x)\n") && isp_day == 1 && isp_night == 4);
	}
	strcpy(l1, "set image.isp_gain_day_max 4"); ctl_line(l1, out, sizeof out);
	strcpy(l1, "set image.isp_gain_night_max 2"); ctl_line(l1, out, sizeof out);
	/* the AE in get: Y and target with one decimal, shutter, gains 1024 = 1x; before the first step */
	ae_y = 37.24; ae_sh = 40000; ae_gain = 32768; ae_isp = 2048; ae_tgt = 22.97;
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\nae.y=37.2\nae.target=23.0\nae.shutter_us=40000\nae.sensor_gain=32768\nae.isp_gain=2048\n"));
	ae_valid = 0;
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "\nae.y=-1.0\nae.target=23.0\nae.shutter_us=0\nae.sensor_gain=0\nae.isp_gain=0\n"));
	assert(strlen(out) < 2000 && !strstr(out, "err") && !strcmp(out + strlen(out) - 3, "ok\n"));
	ae_valid = 1; ae_y = 40; ae_sh = 1000; ae_gain = 1024; ae_isp = 1024; ae_tgt = 40;
	printf("ok: image.exposure_night (day|0..100) and image.isp_gain_day/night_max (1..4): cam.conf (bad values "
	       "ignored), live set/get, bad values refused; ae.* in get\n");
	strcpy(l1, "restart"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n") && stop);
	stop = 0;
	printf("ok: cam.conf stream settings (bad values ignored), restart command\n");

	/* snapshot (#75): latest JPEG kept, written atomically on "snapshot" */
	char snp[512];
	snprintf(snp, sizeof snp, "%s/test_snapshot.jpg", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	snap_path = snp;
	strcpy(l1, "snapshot"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err no recent"));
	static const uint8_t notjpeg[] = { 0, 0, 0, 1, 0x67 }, jpg[] = { 0xff, 0xd8, 0xff, 0xe0, 1, 2, 0xff, 0xd9 };
	snap_frame(notjpeg, sizeof notjpeg);
	strcpy(l1, "snapshot"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err no recent"));
	snap_frame(jpg, sizeof jpg);
	strcpy(l1, "snapshot"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok 8\n"));
	FILE *sf = fopen(snp, "rb"); uint8_t sb[16]; assert(sf && fread(sb, 1, 16, sf) == 8 && !memcmp(sb, jpg, 8)); fclose(sf);
	mode_t um = umask(022); umask(um);
	struct stat sst;                                     /* 0640: camctl reads it (Gate 3) */
	assert(!stat(snp, &sst) && (sst.st_mode & 0777) == (0640 & ~um));
	snap_time -= 10;                                     /* stale: refused */
	strcpy(l1, "snapshot"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err no recent"));
	unlink(snp);
	printf("ok: snapshot: non-JPEG ignored, file written atomically, stale refused\n");

	/* motion (#77): learn, still scene quiet, AE/lighting change quiet, person -> start, hold, end */
	long long t = 1000000;
	unsigned mseq;
	for (int i = 0; i < 15; i++) { scene(80, -1); motion_tick(t += 200); }
	assert(motion_state(&mseq, NULL) == 0 && mseq == 0);
	for (int i = 0; i < 10; i++) { scene(80 + (i & 1), -1); motion_tick(t += 200); }      /* noise */
	assert(motion_state(NULL, NULL) == 0);
	for (int i = 0; i < 6; i++) { scene(120, -1); motion_tick(t += 200); }               /* +50 %: relearn */
	for (int i = 0; i < 6; i++) { scene(80, -1); motion_tick(t += 200); }
	assert(motion_state(NULL, NULL) == 0);
	for (int i = 0; i < 3; i++) { scene(80, 5 + 2 * i); motion_tick(t += 200); }         /* someone walks */
	assert(motion_state(&mseq, NULL) == 1 && mseq == 1 && motion_cells() >= 2);
	for (int i = 0; i < 20; i++) { scene(80, -1); motion_tick(t += 200); }               /* 4 s: held */
	assert(motion_state(NULL, NULL) == 1);
	for (int i = 0; i < 10; i++) { scene(80, -1); motion_tick(t += 200); }               /* > 5 s: end */
	assert(motion_state(NULL, NULL) == 0);
	motion_tick(t += 50);                                                               /* rate limit */
	strcpy(l1, "motion"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "motion.state=0\n") && strstr(out, "motion.seq=1\n") && strstr(out, "ok\n"));
	strcpy(l1, "set motion.sensitivity 101"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	strcpy(l1, "set motion.enabled 0"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	for (int i = 0; i < 3; i++) { scene(80, 20 - 2 * i); motion_tick(t += 200); }
	assert(motion_state(NULL, NULL) == 0);                                               /* disabled */
	strcpy(l1, "set motion.enabled 1"); ctl_line(l1, out, sizeof out);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "motion.enabled=1\n") && strstr(out, "motion.sensitivity=50\n"));
	/* mask: only the left half counts; movement on the right is ignored, on the left it isn't */
	char mk[300] = "set motion.mask ";
	for (int r = 0; r < 32; r++) strcat(mk, "ffff0000");                /* cols 0..15 on */
	strcpy(l1, "x"); char big[600]; strcpy(big, mk); ctl_line(big, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(big, "set motion.mask zz"); ctl_line(big, out, sizeof out); assert(strstr(out, "err"));
	for (int i = 0; i < 15; i++) { scene(80, -1); motion_tick(t += 200); }
	for (int i = 0; i < 4; i++) { scene(80, 20 + i); motion_tick(t += 200); }           /* right side */
	assert(motion_state(NULL, NULL) == 0);
	for (int i = 0; i < 3; i++) { scene(80, 4 + i); motion_tick(t += 200); }            /* left side */
	assert(motion_state(NULL, NULL) == 1);
	strcpy(l1, "motion map"); ctl_line(l1, out, sizeof out);             /* one char per cell */
	{
		char *row = strchr(out, '\n') + 1;
		assert(!strncmp(out, "motion.map=change/10% 32x32 ", 28));
		for (int r = 0; r < 32; r++, row += 33) {
			assert(row[32] == '\n');
			for (int c = 0; c < 32; c++)
				assert(c >= 16 ? row[c] == '-' : (row[c] == '#') == (r >= 10 && r < 16 && c >= 6 && c < 10));
		}
		assert(!strcmp(row, "ok\n"));
	}
	strcpy(l1, "motion luma"); ctl_line(l1, out, sizeof out);
	assert(!strncmp(out, "motion.map=luma/16 32x32 ", 25) && strchr(out, '\n')[1 + 10 * 33 + 6] == '8');
	strcpy(l1, "motion"); ctl_line(l1, out, sizeof out); assert(strstr(out, "motion.peak=24\n"));
	strcpy(l1, "motion"); ctl_line(l1, out, sizeof out); assert(strstr(out, "motion.peak=24\n")); /* kept */
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "motion.grid=32x32\n") && strstr(out, "motion.mask=ffff0000ffff0000") &&
	       strstr(out, "audio.on=0\n"));
	strcpy(big, "set motion.mask 80"); for (int i = 2; i < 256; i++) strcat(big, "0");   /* one cell */
	ctl_line(big, out, sizeof out); assert(!strcmp(out, "ok\n"));
	for (int i = 0; i < 30; i++) { scene(80, -1); motion_tick(t += 200); }             /* 6 s quiet */
	assert(motion_state(NULL, NULL) == 0 && motion_need() == 1);  /* capped at the active cells */
	for (int i = 0; i < 3; i++) { scene(80, -1); grid[0] = 200; motion_tick(t += 200); }
	assert(motion_state(NULL, NULL) == 1);
	strcpy(big, "set motion.mask "); for (int i = 0; i < 256; i++) strcat(big, "f");
	ctl_line(big, out, sizeof out);
	/* background learned while AE was still bright (rtspd start), then AE settles 5x darker:
	 * the jump clears within ~1 s and a person is seen */
	for (int i = 0; i < 30; i++) { scene(80, -1); motion_tick(t += 200); }             /* hold ends */
	strcpy(l1, "set motion.enabled 0"); ctl_line(l1, out, sizeof out);
	scene(80, -1); motion_tick(t += 200);
	strcpy(l1, "set motion.enabled 1"); ctl_line(l1, out, sizeof out);
	for (int i = 0; i < 12; i++) { scene(220, -1); motion_tick(t += 200); }
	for (int i = 0; i < 10; i++) { scene(40, -1); motion_tick(t += 200); }
	strcpy(l1, "motion map"); ctl_line(l1, out, sizeof out);
	assert(motion_state(NULL, NULL) == 0 && strstr(out, " jump=0 "));
	for (int i = 0; i < 3; i++) { scene(40, 8 + i); motion_tick(t += 200); }
	assert(motion_state(NULL, NULL) == 1);
	/* wind in bushes: a block of cells flickers +-40 % every evaluation. Once learned (20 s), it
	 * no longer holds motion on; a person in a still area is still seen. */
	for (int e = 0; e < 100; e++) {
		scene(40, -1);
		for (int r = 20; r < 28; r++)
			for (int col = 20; col < 28; col++)
				grid[r * 32 + col] = (uint8_t)(40 + ((r * 31 + col * 7 + e * 17) % 33) - 16);
		motion_tick(t += 200);
	}
	assert(motion_state(NULL, NULL) == 0);
	strcpy(l1, "motion noise"); ctl_line(l1, out, sizeof out);
	assert(!strncmp(out, "motion.map=noise/10% 32x32 ", 27) && strchr(out, '\n')[1 + 24 * 33 + 24] >= '1');
	for (int i = 0; i < 3; i++) {
		scene(40, 4 + i);                                        /* rows 10..15: still area */
		for (int r = 20; r < 28; r++)
			for (int col = 20; col < 28; col++)
				grid[r * 32 + col] = (uint8_t)(40 + ((r * 31 + col * 7 + i * 17) % 33) - 16);
		motion_tick(t += 200);
	}
	assert(motion_state(NULL, NULL) == 1);
	printf("ok: motion: quiet on noise and lighting change, start on movement, 5 s hold, disable, mask, "
	       "one-cell area, map, peak kept across reads, relearn after AE settles, flickering cells learned\n");
	/* day/night (#30): fake /dev/irled (a file) and PWM dir; MCA40E status is inverted */
	char dnd[512], irf[600], pwmd[600], dnp[700];
	snprintf(dnd, sizeof dnd, "%s/dn-test", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	snprintf(irf, sizeof irf, "%s/irled", dnd);
	snprintf(pwmd, sizeof pwmd, "%s/pwmchip4", dnd);
	mkdir(dnd, 0700);
	mkdir(pwmd, 0700);
	snprintf(dnp, sizeof dnp, "%s/pwm0", pwmd);
	mkdir(dnp, 0700);
	for (int i = 0; i < 3; i++) {                      /* sysfs attributes exist; a plain dir needs them */
		static const char *a[] = { "period", "duty_cycle", "enable" };
		char f[800];
		snprintf(f, sizeof f, "%s/%s", dnp, a[i]);
		fclose(fopen(f, "w"));
	}
	unsigned char irs[4] = { 2, 0, 0, 0 };              /* raw 2 = day on MCA40E */
	FILE *irw = fopen(irf, "wb"); fwrite(irs, 1, 4, irw); fclose(irw);
	struct dn_cfg dc = { DN_AUTO, 96, 1, DN_SRC_SENSOR, 15, 1500 };
	dn_init(irf, pwmd, &dc);
	irs[0] = 1;                                         /* night reading at start: */
	irw = fopen(irf, "r+b"); fwrite(irs, 1, 4, irw); fclose(irw);
	dn_tick();                                          /* starts in day like stock */
	assert(dn_state() == DN_DAY && night_now == 0);
	irs[0] = 2;                                         /* back to a day reading */
	irw = fopen(irf, "r+b"); fwrite(irs, 1, 4, irw); fclose(irw);
	for (int i = 0; i < 5; i++) dn_tick();
	assert(dn_state() == DN_DAY);
	irs[0] = 1;                                          /* raw 1 = night */
	irw = fopen(irf, "r+b"); fwrite(irs, 1, 4, irw); fclose(irw);
	for (int i = 0; i < 4; i++) { dn_tick(); assert(dn_state() == DN_DAY); }   /* debounce */
	dn_tick();
	assert(dn_state() == DN_NIGHT && night_now == 1);
	char duty[32] = "";
	snprintf(dnp, sizeof dnp, "%s/pwm0/duty_cycle", pwmd);
	FILE *df = fopen(dnp, "r"); assert(df && fgets(duty, sizeof duty, df)); fclose(df);
	assert(!strcmp(duty, "48000"));                     /* stock night duty */
	irw = fopen(irf, "rb"); unsigned char irb[8] = { 0 }; size_t got = fread(irb, 1, 8, irw); fclose(irw);
	assert(got >= 5 && irb[got - 1] == 0);              /* IR-cut: 0 = night written */
	strcpy(l1, "set daynight.irled 10"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	df = fopen(dnp, "r"); assert(df && fgets(duty, sizeof duty, df)); fclose(df);
	assert(!strcmp(duty, "5000"));                      /* live at night, not at the next switch */
	strcpy(l1, "set daynight.irled 96"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	df = fopen(dnp, "r"); assert(df && fgets(duty, sizeof duty, df)); fclose(df);
	assert(!strcmp(duty, "48000"));
	strcpy(l1, "set daynight.mode day"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	dn_tick();
	assert(dn_state() == DN_DAY && night_now == 0);
	df = fopen(dnp, "r"); assert(df && fgets(duty, sizeof duty, df)); fclose(df);
	assert(!strcmp(duty, "0"));
	strcpy(l1, "set daynight.irled 50"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	df = fopen(dnp, "r"); assert(df && fgets(duty, sizeof duty, df)); fclose(df);
	assert(!strcmp(duty, "0"));                         /* by day the LEDs stay off */
	strcpy(l1, "set daynight.irled 96"); ctl_line(l1, out, sizeof out);
	strcpy(l1, "set daynight.mode dusk"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	strcpy(l1, "set daynight.irled 101"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "daynight.mode=day\n") && strstr(out, "daynight.state=day\n"));
	/* image source (default; MCA40E): score = Y / (shutter s x gain), night < 15, day > 1500 */
	strcpy(l1, "set daynight.mode auto"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set daynight.source image"); ctl_line(l1, out, sizeof out); assert(!strcmp(out, "ok\n"));
	strcpy(l1, "set daynight.night_below 2000"); ctl_line(l1, out, sizeof out); assert(strstr(out, "err"));
	for (int i = 0; i < 6; i++) dn_tick();
	assert(dn_state() == DN_DAY && dn_score() == 40000);
	ae_y = 10; ae_sh = 40000; ae_gain = 32 * 1024;      /* dawn without IR: score ~7 */
	for (int i = 0; i < 4; i++) { dn_tick(); assert(dn_state() == DN_DAY); }
	dn_tick();
	assert(dn_state() == DN_NIGHT && night_now == 1 && dn_score() == 7);
	ae_y = 36; ae_sh = 50000; ae_gain = 4300;           /* IR on, like stock at night: ~170 */
	for (int i = 0; i < 20; i++) dn_tick();
	assert(dn_state() == DN_NIGHT);                     /* the IR alone doesn't make it day */
	ae_y = 40; ae_sh = 5000; ae_gain = 1024;            /* morning: 8000 */
	for (int i = 0; i < 5; i++) dn_tick();
	assert(dn_state() == DN_DAY && night_now == 0);
	/* flapping (a light the IR itself trips): the 3rd switch in 10 min holds for 10 min */
	ae_y = 2; ae_sh = 40000; ae_gain = 32 * 1024;       /* dark again: ~1.5 */
	for (int i = 0; i < 5; i++) dn_tick();
	assert(dn_state() == DN_NIGHT);                     /* switch 3 (night, day, night) */
	ae_y = 40; ae_sh = 5000; ae_gain = 1024;            /* bright: 8000, but held */
	for (int i = 0; i < 30; i++) dn_tick();
	assert(dn_state() == DN_NIGHT);                     /* held */
	for (int i = 0; i < 600; i++) dn_tick();
	assert(dn_state() == DN_DAY);
	strcpy(l1, "get"); ctl_line(l1, out, sizeof out);
	assert(strstr(out, "daynight.source=image\n") && strstr(out, "daynight.score=8000\n"));
	printf("ok: day/night: inverted status, 5 s debounce, IR-cut byte, IR LED duty 48000 (live at night), forced mode;\n"
	       "    image source: night/day thresholds with hysteresis, IR doesn't flip it, flap hold\n");
	/* the order around the IR-cut. Without night tuning: IR-cut, IR LEDs and B/W in one tick (above).
	 * With it, stock's: night = IR LEDs, night groups + B/W, IR-cut out a tick later; day = IR LEDs off,
	 * colour, IR-cut in, the day groups a tick later. */
#define IRCUT() (irw = fopen(irf, "rb"), got = fread(irb, 1, 8, irw), fclose(irw), irb[got - 1])
#define DUTY() (df = fopen(dnp, "r"), assert(df && fgets(duty, sizeof duty, df)), fclose(df), atoi(duty))
	strcpy(l1, "set daynight.mode day"); ctl_line(l1, out, sizeof out);
	dn_tick();
	assert(dn_state() == DN_DAY && IRCUT() == 1);
	nt_on = 1;
	*dn_log = 0;
	strcpy(l1, "set daynight.mode night"); ctl_line(l1, out, sizeof out);
	dn_tick();
	assert(dn_state() == DN_NIGHT && !strcmp(dn_log, "night 1;") && DUTY() == 48000 && IRCUT() == 1);
	dn_tick();
	assert(IRCUT() == 0 && !strcmp(dn_log, "night 1;"));               /* IR-cut out a second later */
	dn_tick();
	assert(IRCUT() == 0 && !strcmp(dn_log, "night 1;"));               /* nothing more */
	strcpy(l1, "set daynight.mode day"); ctl_line(l1, out, sizeof out);
	dn_tick();
	assert(dn_state() == DN_DAY && !strcmp(dn_log, "night 1;night 0;") && DUTY() == 0 && IRCUT() == 1);
	dn_tick();
	assert(!strcmp(dn_log, "night 1;night 0;day-groups;"));            /* the day groups a second later */
	dn_tick();
	assert(!strcmp(dn_log, "night 1;night 0;day-groups;"));
	/* switched again before the second half: it still runs first */
	strcpy(l1, "set daynight.mode night"); ctl_line(l1, out, sizeof out);
	dn_tick();
	strcpy(l1, "set daynight.mode day"); ctl_line(l1, out, sizeof out);
	*dn_log = 0;
	dn_tick();
	assert(IRCUT() == 1 && dn_state() == DN_DAY && !strcmp(dn_log, "night 0;"));
	dn_tick();
	assert(!strcmp(dn_log, "night 0;day-groups;"));
	nt_on = 0;
	*dn_log = 0;
	strcpy(l1, "set daynight.mode night"); ctl_line(l1, out, sizeof out);
	dn_tick();
	assert(IRCUT() == 0 && !strcmp(dn_log, "night 1;"));               /* off: all in one tick again */
	strcpy(l1, "set daynight.mode day"); ctl_line(l1, out, sizeof out);
	dn_tick();
	dn_tick();
	assert(IRCUT() == 1 && !strcmp(dn_log, "night 1;night 0;"));       /* and no day-groups call */
	strcpy(l1, "set daynight.mode auto"); ctl_line(l1, out, sizeof out);
#undef IRCUT
#undef DUTY
	printf("ok: day/night with stock night tuning: night groups before the IR-cut moves out (a tick later), "
	       "day groups a tick after it moves in; off = as before\n");
	/* Gate 3: -U / -G are looked up before anything starts (a bad one stops rtspd with 2); the
	 * control socket's owner, group and mode (ctl_perm, on a plain file here); /dev/urandom kept */
	{
		static const char *const bad[][4] = { { "-N", "-U", "no-such-user-gate3", NULL },
			{ "-N", "-U", "0:0", NULL }, { "-N", "-U", "100:x", NULL }, { "-N", "-U", "root", NULL },
			{ "-N", "-G", "no-such-group-gate3", NULL }, { "-N", "-G", "0", NULL } };
		for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
			char *av[5] = { "rtspd", (char *)bad[i][0], (char *)bad[i][1], (char *)bad[i][2], NULL };
			optind = 1;
#ifdef __APPLE__
			optreset = 1;
#endif
			assert(rtspd_main(4, av) == 2 && !stop);
		}
		char pf[512];
		struct stat pst;
		snprintf(pf, sizeof pf, "%s/test_ctl_perm", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
		fclose(fopen(pf, "w"));
		chmod(pf, 0700);
		assert(!ctl_perm(pf, (uid_t)-1, (gid_t)-1) && !stat(pf, &pst) && (pst.st_mode & 0777) == 0700);
		assert(!ctl_perm(pf, getuid(), (gid_t)-1) && !stat(pf, &pst) && (pst.st_mode & 0777) == 0600);
		assert(!ctl_perm(pf, getuid(), getgid()) && !stat(pf, &pst) && (pst.st_mode & 0777) == 0660 &&
		       pst.st_gid == getgid());
		assert(!ctl_perm(pf, (uid_t)-1, getgid()) && !stat(pf, &pst) && (pst.st_mode & 0777) == 0660);
		if (geteuid()) assert(ctl_perm(pf, 0, (gid_t)-1) < 0);    /* not root: can't give it away */
		unlink(pf);
		uint8_t rb[2];
		random_bytes(rb, 2);
		int ufd = urandom_fd;
		random_bytes(rb, 2);
		assert(ufd >= 0 && urandom_fd == ufd);
		printf("ok: -U/-G: unknown user or group, root, junk refused before anything starts; control "
		       "socket owner/group/mode (0600 with -U, 0660 with -G); /dev/urandom stays open\n");
	}
	char sock[512];
	snprintf(sock, sizeof sock, "%s/test_camd.sock", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	int cfd = ctl_listen(sock);
	if (cfd < 0 && errno == EPERM) {        /* sandboxed build hosts may forbid unix-socket bind */
		printf("ok: control socket: get/set/auth-reload, bad input refused (socket part SKIPPED: bind not permitted here)\nALL OK\n");
		return 0;
	}
	assert(cfd >= 0);
	struct stat st;
	assert(!stat(sock, &st) && (st.st_mode & 077) == 0);          /* root-only socket file */
	int cl = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, sock);
	assert(!connect(cl, (struct sockaddr *)&sa, sizeof sa));
	assert(send(cl, "set image.sharpness 70\n", 23, 0) == 23);
	ctl_serve(cfd);
	char rep[64] = "";
	assert(recv(cl, rep, sizeof rep - 1, 0) > 0 && !strcmp(rep, "ok\n"));
	assert(mi_image_get(MI_IMG_SHARPNESS) == 70);
	close(cl); close(cfd); unlink(sock);
	printf("ok: control socket: get/set/auth-reload, bad input refused, socket file 0600\nALL OK\n");
	remove(path);
	return 0;
}
