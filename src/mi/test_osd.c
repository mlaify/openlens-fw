/* SPDX-License-Identifier: MIT */
/*
 * Host test for osd.c (no camera): mi.c and osd.c are compiled in with ioctl() replaced by fake
 * /dev/mi_sys, /dev/mi_venc and /dev/mi_rgn devices that log every call.
 *
 *   clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/mi \
 *       -o $TMPDIR/test_osd src/mi/test_osd.c -lm
 *   $TMPDIR/test_osd
 *
 * Checks: the MI_RGN request codes and argument sizes (Init 0x44006900 with the palette, Create
 * 0x40186902, Attach 0x40606906, Detach 0x40186907, SetDisplayAttr 0x40606908, GetCanvasInfo
 * 0xc028690a, UpdateCanvas 0xc00c690b + 0x4004690c, Destroy 0x40046903); Init once, and Create ->
 * Attach -> first draw between each encoder's CreateChn and StartRecvPic (the JPEG channel gets the
 * sub-stream's regions, no canvas of its own); every redraw GetCanvasInfo -> flush -> nr11 -> flush
 * -> nr12; the clock redrawn once a second and the title only on change; moves by SetDisplayAttr,
 * a size change by detach + destroy + create (never a resize); 8-aligned widths, 4-aligned
 * heights and positions, clipped to the picture; corners, custom places and a shared corner; the
 * text scale and corners at every stream.main.size / stream.sub.size;
 * glyph bits into I2 pixels for the three styles, '?' for unknown bytes, clipping; the first
 * failure turning the OSD off (all regions detached and destroyed, nothing after it) while the
 * encoders still start; a JPEG attach failure only costing the snapshots; settings parsing; the
 * date and time formats; the clock in local time from TZ (fixed offsets, US Central CDT/CST and its
 * switches, +5:30, a southern summer); teardown order; $OSD_TARGETS.
 */
#define ioctl test_ioctl               /* mi.c's and osd.c's ioctl calls */
#include "mi.c"
#include "osd.c"
#undef ioctl

#include <assert.h>

enum { FAKE_SYS = 1001, FAKE_VENC = 1002, FAKE_RGN = 1003 };

struct call { int fd; unsigned long req; uint32_t len; uint8_t a[1024]; };
static struct call calls[4096];
static int ncalls, fail_req_n;         /* fail_req_n: fail the Nth call (1-based) of fail_req */
static unsigned long fail_req;
static int fail_seen;
static uint32_t fail_dev = 0xffffffff;  /* ... only for this target dev (Attach), if set */

/* canvases by handle (0x20..0x23): the size Create asked for, the buffer GetCanvasInfo gives */
static struct { uint32_t w, h, stride; uint8_t buf[4096 * 160]; } cv[4];

int test_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	va_start(ap, req);
	struct mi_hdr *h = va_arg(ap, struct mi_hdr *);
	va_end(ap);
	struct call *c = &calls[ncalls < 4095 ? ncalls++ : 4095];
	c->fd = fd;
	c->req = req;
	c->len = h->len;
	assert(h->dev == 0 && h->pad == 0);
	assert(h->len == ((req >> 16) & 0x3fff));             /* the header's size is the request's */
	assert(h->len <= sizeof c->a);
	uint8_t *a = (uint8_t *)(uintptr_t)h->ptr;
	memcpy(c->a, a, h->len);
	if (req == fail_req) {
		uint32_t dev = 0;
		if (h->len >= 12) memcpy(&dev, a + 8, 4);          /* Attach: ChnPort.dev */
		if ((fail_dev == 0xffffffff || dev == fail_dev) && ++fail_seen == fail_req_n) {
			errno = EINVAL;
			return -1;
		}
	}
	if (fd == FAKE_RGN) {
		uint32_t handle;
		memcpy(&handle, a, 4);
		if (req == 0x40186902UL) {                         /* Create */
			uint32_t w, hh;
			memcpy(&w, a + 12, 4);
			memcpy(&hh, a + 16, 4);
			assert(handle >= 0x20 && handle < 0x24 && w * hh / 4 + 8 * hh <= sizeof cv[0].buf);
			cv[handle - 0x20].w = w;
			cv[handle - 0x20].h = hh;
			cv[handle - 0x20].stride = w / 4 + 8;             /* the driver may pad rows */
			memset(cv[handle - 0x20].buf, 0xee, sizeof cv[0].buf);
		} else if (req == 0xc028690aUL) {                  /* GetCanvasInfo */
			struct { uint32_t handle, pad; uint64_t phy, virt; uint32_t w, h, stride, fmt; } ci;
			memcpy(&ci, a, sizeof ci);
			assert(handle >= 0x20 && handle < 0x24 && cv[handle - 0x20].w);
			ci.phy = 0x20000000;
			ci.virt = (uint64_t)(uintptr_t)cv[handle - 0x20].buf;
			ci.w = cv[handle - 0x20].w;
			ci.h = cv[handle - 0x20].h;
			ci.stride = cv[handle - 0x20].stride;
			ci.fmt = 2;
			memcpy(a, &ci, sizeof ci);
		} else if (req == 0xc00c690bUL) {                  /* UpdateCanvas: the range to flush */
			uint32_t r[3] = { handle, 0x10000000u + handle * 0x10000u, cv[handle - 0x20].stride * cv[handle - 0x20].h };
			memcpy(a, r, sizeof r);
		}
	}
	return 0;
}

static void ok(const char *what) { printf("ok: %s\n", what); }

static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* The calls since `from` as short names, one per call: e.g. "Init Create Attach Info Flush ..." */
static const char *names(int from, int to)
{
	static char s[16384];
	size_t n = 0;
	s[0] = 0;
	for (int i = from; i < to && n < sizeof s - 64; i++) {
		const struct call *c = &calls[i];
		const char *x = "?";
		char b[48];
		if (c->fd == FAKE_SYS) x = c->req == 0x4010691bUL ? "Flush" : "Sys";
		else if (c->fd == FAKE_VENC) {
			if (c->req == 0x40586900UL) { snprintf(b, sizeof b, "VCreate%u/%u", u32(c->a), u32(c->a + 4)); x = b; }
			else if (c->req == 0x40086904UL) { snprintf(b, sizeof b, "VStart%u/%u", u32(c->a), u32(c->a + 4)); x = b; }
			else continue;
		} else if (c->fd == FAKE_RGN) {
			unsigned long r = c->req;
			x = r == 0x44006900UL ? "Init" : r == 0x40186902UL ? "Create" : r == 0x40046903UL ? "Destroy" :
			    r == 0x40606906UL ? "Attach" : r == 0x40186907UL ? "Detach" : r == 0x40606908UL ? "Disp" :
			    r == 0xc028690aUL ? "Info" : r == 0xc00c690bUL ? "Upd" : r == 0x4004690cUL ? "Commit" : "RGN?";
			if (r == 0x40186902UL || r == 0x40606906UL || r == 0x40186907UL || r == 0x40606908UL ||
			    r == 0x40046903UL) {
				if (r == 0x40606906UL || r == 0x40186907UL || r == 0x40606908UL)
					snprintf(b, sizeof b, "%s%x@%u/%u", x, u32(c->a), u32(c->a + 8), u32(c->a + 12));
				else
					snprintf(b, sizeof b, "%s%x", x, u32(c->a));
				x = b;
			}
		}
		n += (size_t)snprintf(s + n, sizeof s - n, "%s%s", n ? " " : "", x);
	}
	return s;
}

static void want_seq(const char *what, int from, const char *want)
{
	const char *got = names(from, ncalls);
	if (strcmp(got, want)) {
		fprintf(stderr, "FAIL %s:\n  got  %s\n  want %s\n", what, got, want);
		exit(1);
	}
	ok(what);
}

static int count_req(int from, unsigned long req)
{
	int n = 0;
	for (int i = from; i < ncalls; i++) n += calls[i].req == req;
	return n;
}

/* index of the first call with request req since from, or -1 */
static int idx_of(int from, unsigned long req)
{
	for (int i = from; i < ncalls; i++)
		if (calls[i].req == req) return i;
	return -1;
}

/* the SetDisplayAttr / Attach (req) of `handle` on VENC dev/chn since from, or NULL */
static const struct call *place_of(int from, unsigned long req, uint32_t handle, uint32_t dev, uint32_t chn)
{
	for (int i = from; i < ncalls; i++)
		if (calls[i].req == req && u32(calls[i].a) == handle && u32(calls[i].a + 8) == dev &&
		    u32(calls[i].a + 12) == chn)
			return &calls[i];
	return NULL;
}

/* the last call with request req (since from), or NULL */
static const struct call *last_of(int from, unsigned long req)
{
	const struct call *r = NULL;
	for (int i = from; i < ncalls; i++)
		if (calls[i].req == req) r = &calls[i];
	return r;
}

/* the stream sizes start() gives mi.c (stream.main.size / stream.sub.size) */
static int pic_mw = 2560, pic_mh = 1440, pic_sw = 640, pic_sh = 360;

/* Every Create: width 8-aligned, height 4-aligned; every Attach/SetDisplayAttr: x/y 4-aligned and
 * the box inside its picture (main pic_mw x pic_mh, sub/JPEG pic_sw x pic_sh). */
static void check_geometry(int from)
{
	for (int i = from; i < ncalls; i++) {
		const struct call *c = &calls[i];
		if (c->fd != FAKE_RGN) continue;
		if (c->req == 0x40186902UL) {
			assert(u32(c->a + 4) == 0 && u32(c->a + 8) == 2);            /* OSD, I2 */
			assert(u32(c->a + 12) % 8 == 0 && u32(c->a + 16) % 4 == 0);
			assert(c->a[20] == 1 && c->a[21] == 0 && c->a[22] == 0 && c->a[23] == 0);
		}
		if (c->req == 0x40606906UL || c->req == 0x40606908UL) {
			uint32_t h = u32(c->a), mod = u32(c->a + 4), dev = u32(c->a + 8), chn = u32(c->a + 12);
			uint32_t x = u32(c->a + 24 + 8), y = u32(c->a + 24 + 12);
			assert(mod == 2 && u32(c->a + 16) == 0 && c->a[20] == 0);        /* VENC, port 0 */
			assert((dev == 0 && chn <= 1) || (dev == 8 && chn == 3));
			assert(u32(c->a + 24 + 4) == h && c->a[24 + 0x15] == 0xaa);      /* layer, alpha byte */
			int fw = dev == 0 && chn == 0 ? pic_mw : pic_sw, fh = dev == 0 && chn == 0 ? pic_mh : pic_sh;
			assert(x % 4 == 0 && y % 4 == 0);
			assert(h >= 0x20 && h < 0x24);
			assert((int)(x + cv[h - 0x20].w) <= fw && (int)(y + cv[h - 0x20].h) <= fh);
		}
	}
}

/* ---- rendering: an independent reference of the I2 picture ---------------------------------- */

static int ref_text(const char *s, int scale, int x, int y)
{
	int n = (int)strlen(s);
	for (int i = 0; i < n; i++)
		for (int r = 0; r < 16; r++)
			for (int b = 0; b < 8; b++) {
				if (!(glyph_row((unsigned char)s[i], r) & (0x80 >> b))) continue;
				int x0 = scale + (i * 8 + b) * scale, y0 = scale + r * scale;
				if (x >= x0 && x < x0 + scale && y >= y0 && y < y0 + scale) return 1;
			}
	return 0;
}

static int px(const uint8_t *buf, uint32_t stride, int x, int y)
{
	return buf[(size_t)y * stride + (size_t)(x >> 2)] >> ((x & 3) * 2) & 3;   /* LSB first */
}

static void check_render(const char *what, const char *s, int scale, int style, int w, int h)
{
	static uint8_t buf[200 * 64];
	uint32_t stride = (uint32_t)w / 4 + 3;
	int bg = style == STYLE_BOW ? 2 : style == STYLE_WOB ? 1 : 0, fg = style == STYLE_BOW ? 1 : 2;
	memset(buf, 0xee, sizeof buf);
	render(buf, stride, w, h, s, scale, style);
	int text = 0, border = 0;
	for (int y = 0; y < h; y++) {
		for (int x = 0; x < w; x++) {
			int t = ref_text(s, scale, x, y), want = t ? fg : bg;
			if (!t && style == STYLE_BORDER)
				for (int dy = -1; dy <= 1; dy++)
					for (int dx = -1; dx <= 1; dx++)
						if (x + dx >= 0 && x + dx < w && y + dy >= 0 && y + dy < h &&
						    ref_text(s, scale, x + dx, y + dy))
							want = 1;
			if (px(buf, stride, x, y) != want) {
				fprintf(stderr, "FAIL %s: pixel %d,%d is %d, want %d\n", what, x, y, px(buf, stride, x, y), want);
				exit(1);
			}
			text += t;
			border += !t && want == 1 && style == STYLE_BORDER;
		}
		for (uint32_t b = ((uint32_t)w + 3) / 4; b < stride; b++)       /* row padding: background */
			assert(buf[(size_t)y * stride + b] == bg * 0x55);
	}
	assert(buf[(size_t)h * stride] == 0xee);                         /* nothing past the canvas */
	assert(text > 0 && (style != STYLE_BORDER || border > 0));
	ok(what);
}

static void reset(void)
{
	osd_stop();
	failed = 0;
	fd_rgn = FAKE_RGN;
	now_s = 0;
	dirty = 1;
	fail_req = 0;
	fail_req_n = fail_seen = 0;
	fail_dev = 0xffffffff;
	memset(cv, 0, sizeof cv);
	osd_set("osd.time.enabled", "1");
	osd_set("osd.time.pos", "ul");
	osd_set("osd.title.enabled", "0");
	osd_set("osd.title.pos", "ll");
	osd_set("osd.title.text", "");
	osd_set("osd.size", "small");
	osd_set("osd.style", "border");
	osd_set("osd.time.format", "yyyy-MM-dd");
	osd_set("osd.time.12h", "0");
	osd_set("osd.time.weekday", "0");
	jpeg_on = 0;
	ncalls = 0;
}

/* mi.c's encoder setup with the stock-like streams (main 2560x1440, sub 640x360 unless pic_* say
 * otherwise), JPEG on */
static int start(void)
{
	memset(&cfg, 0, sizeof cfg);
	cfg = (struct mi_cfg){ .w = pic_mw, .h = pic_mh, .kbps = 4000, .fps = 25, .gop = 100, .ring = 1, .codec = MI_H264,
			       .sub_w = pic_sw, .sub_h = pic_sh, .sub_kbps = 500, .sub_fps = 25, .sub_gop = 100,
			       .sub_codec = MI_H264, .snapshot = 1, .snapshot_q = 80 };
	fd_sys = FAKE_SYS;
	fd_venc = FAKE_VENC;
	osd_enable();
	return setup_venc();
}

#define T0 1792318567                  /* 2026-10-18 10:16:07 UTC, a Sunday */

static void test_settings(void)
{
	static const struct { const char *k, *v; int ok; } s[] = {
		{ "osd.time.enabled", "1", 1 }, { "osd.time.enabled", "2", 0 }, { "osd.time.enabled", "", 0 },
		{ "osd.time.pos", "lr", 1 }, { "osd.time.pos", "custom", 1 }, { "osd.time.pos", "center", 0 },
		{ "osd.time.x", "0", 1 }, { "osd.time.x", "100", 1 }, { "osd.time.x", "101", 0 }, { "osd.time.x", "05", 0 },
		{ "osd.time.y", "-1", 0 }, { "osd.time.format", "dd/MM/yyyy", 1 }, { "osd.time.format", "yy-MM-dd", 0 },
		{ "osd.time.12h", "1", 1 }, { "osd.time.weekday", "1", 1 }, { "osd.time.text", "x", 0 },
		{ "osd.title.text", "Front door: 1 & 2 <ok>", 1 }, { "osd.title.text", "", 1 },
		{ "osd.title.text", "caf\xc3\xa9", 0 }, { "osd.title.text", "tab\there", 0 },
		{ "osd.title.text", "123456789012345678901234567890123456789012345678", 1 },
		{ "osd.title.text", "1234567890123456789012345678901234567890123456789", 0 },
		{ "osd.title.format", "yyyy-MM-dd", 0 }, { "osd.title.12h", "1", 0 }, { "osd.title.pos", "ur", 1 },
		{ "osd.size", "large", 1 }, { "osd.size", "huge", 0 }, { "osd.style", "white-on-black", 1 },
		{ "osd.style", "red", 0 }, { "osd.tz_offset", "0", 0 }, { "osd.tz_offset", "-300", 0 },
		{ "osd.bogus", "1", 0 }, { "image.flip", "1", 0 },
	};
	for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
		if ((osd_set(s[i].k, s[i].v) == 0) != s[i].ok) {
			fprintf(stderr, "FAIL osd_set %s=%s should be %s\n", s[i].k, s[i].v, s[i].ok ? "taken" : "refused");
			exit(1);
		}
	}
	char out[1024];
	size_t n = osd_get(out, sizeof out);
	assert(n == strlen(out));
	assert(strstr(out, "osd.time.enabled=1\nosd.time.pos=custom\nosd.time.x=100\nosd.time.y=0\n"));
	assert(strstr(out, "osd.title.pos=ur\n") && strstr(out, "osd.time.format=dd/MM/yyyy\nosd.time.12h=1\n"
	       "osd.time.weekday=1\nosd.title.text=123456789012345678901234567890123456789012345678\nosd.size=large\n"
	       "osd.style=white-on-black\nosd.status=off\n"));
	assert(!strstr(out, "tz_offset"));
	assert(osd_get(out, 20) == 19 && strlen(out) == 19);              /* cut, terminated */
	ok("settings: each key's values taken or refused (osd.tz_offset is gone); osd_get lists them");
}

/* The process's time zone, as rtspd sets it from time.tz */
static void set_tz(const char *tz)
{
	setenv("TZ", tz, 1);
	tzset();
}

static void test_time(void)
{
	char t[64];
	static const struct { const char *fmt; int h12, wd; const char *tz; time_t at; const char *want; } v[] = {
		{ "yyyy-MM-dd", 0, 0, "UTC0", T0, "2026-10-18 10:16:07" },
		{ "yyyy/MM/dd", 0, 0, "UTC0", T0, "2026/10/18 10:16:07" },
		{ "dd/MM/yyyy", 0, 0, "UTC0", T0, "18/10/2026 10:16:07" },
		{ "MM/dd/yyyy", 0, 0, "UTC0", T0, "10/18/2026 10:16:07" },
		{ "dd-MM-yyyy", 0, 0, "UTC0", T0, "18-10-2026 10:16:07" },
		{ "MM-dd-yyyy", 0, 1, "UTC0", T0, "10-18-2026 10:16:07 Sun" },
		{ "yyyy-MM-dd", 1, 0, "UTC0", T0, "2026-10-18 10:16:07 AM" },
		{ "yyyy-MM-dd", 1, 1, "<+03>-3", T0, "2026-10-18 01:16:07 PM Sun" },
		{ "yyyy-MM-dd", 1, 0, "UTC0", T0 - 10 * 3600, "2026-10-18 12:16:07 AM" },
		{ "yyyy-MM-dd", 1, 0, "UTC0", T0 + 2 * 3600, "2026-10-18 12:16:07 PM" },
		{ "yyyy-MM-dd", 0, 1, "<+14>-14", T0, "2026-10-19 00:16:07 Mon" },
		{ "yyyy-MM-dd", 0, 1, "<-12>12", T0, "2026-10-17 22:16:07 Sat" },
		/* US Central: CDT (UTC-5) in October, CST (UTC-6) in December */
		{ "yyyy-MM-dd", 0, 1, "CST6CDT,M3.2.0,M11.1.0", T0, "2026-10-18 05:16:07 Sun" },
		{ "MM/dd/yyyy", 1, 1, "CST6CDT,M3.2.0,M11.1.0", 1797502567, "12/17/2026 04:16:07 AM Thu" },
		/* ... and its switches: 2026-11-01 02:00 CDT -> 01:00 CST, 2026-03-08 02:00 CST -> 03:00 CDT */
		{ "yyyy-MM-dd", 0, 0, "CST6CDT,M3.2.0,M11.1.0", 1793516399, "2026-11-01 01:59:59" },
		{ "yyyy-MM-dd", 0, 0, "CST6CDT,M3.2.0,M11.1.0", 1793516400, "2026-11-01 01:00:00" },
		{ "yyyy-MM-dd", 0, 0, "CST6CDT,M3.2.0,M11.1.0", 1772956799, "2026-03-08 01:59:59" },
		{ "yyyy-MM-dd", 0, 0, "CST6CDT,M3.2.0,M11.1.0", 1772956800, "2026-03-08 03:00:00" },
		{ "yyyy-MM-dd", 0, 0, "IST-5:30", T0, "2026-10-18 15:46:07" },
		{ "yyyy-MM-dd", 0, 0, "AEST-10AEDT,M10.1.0,M4.1.0/3", T0, "2026-10-18 21:16:07" },   /* AEDT, UTC+11 */
	};
	for (unsigned i = 0; i < sizeof v / sizeof v[0]; i++) {
		assert(!osd_set("osd.time.format", v[i].fmt) && !osd_set("osd.time.12h", v[i].h12 ? "1" : "0") &&
		       !osd_set("osd.time.weekday", v[i].wd ? "1" : "0"));
		set_tz(v[i].tz);
		time_text(v[i].at, t, sizeof t);
		if (strcmp(t, v[i].want)) { fprintf(stderr, "FAIL time %u: %s, want %s\n", i, t, v[i].want); exit(1); }
	}
	set_tz("UTC0");
	ok("date formats, 12 h (12 AM / 12 PM), weekday; local time from TZ: fixed offsets -12..+14 h, US Central "
	   "CDT in October and CST in December with both switches, India +5:30, Sydney's summer");
}

static void test_render(void)
{
	check_render("render: border style, scale 1", "Ag?", 1, STYLE_BORDER, 40, 20);
	check_render("render: border style, scale 3", "Hi", 3, STYLE_BORDER, 64, 56);
	check_render("render: black on white", "12:59", 2, STYLE_BOW, 96, 36);
	check_render("render: white on black", "Wed", 1, STYLE_WOB, 32, 20);
	check_render("render: clipped to a canvas narrower than the text", "a long title", 2, STYLE_BORDER, 24, 12);
	static uint8_t a[64 * 20], b[64 * 20];
	render(a, 16, 64, 20, "x\x01\xff~", 1, STYLE_BORDER);
	render(b, 16, 64, 20, "x??~", 1, STYLE_BORDER);
	assert(!memcmp(a, b, sizeof a));
	ok("render: bytes without a glyph drawn as '?'");
	/* one known pixel: the first set bit of 'A' row 1 at scale 2 is white (2) in the low bits */
	int r = 1, bit = 0;
	while (!(glyph_row('A', r) & (0x80 >> bit))) if (++bit == 8) { bit = 0; r++; }
	memset(a, 0, sizeof a);
	render(a, 16, 64, 20, "A", 2, STYLE_BOW);
	int x = 2 + bit * 2, y = 2 + r * 2;
	assert((a[y * 16 + x / 4] >> ((x & 3) * 2) & 3) == 1);                   /* black text on white */
	assert(a[0] == 0xaa);                                                     /* white: 2 in each pixel */
	ok("render: I2 packing, pixel 0 in the low bits (OSD_I2_MSB_FIRST=0)");
}

static void test_pipeline(void)
{
	reset();
	osd_tick(T0);
	assert(ncalls == 0);
	assert(!start());
	check_geometry(0);
	/* main: CreateChn, then our Init/Create/Attach/draw, then StartRecvPic; sub likewise; JPEG gets
	 * the sub-stream's region attached */
	want_seq("Init -> Create -> Attach -> draw between each encoder's CreateChn and StartRecvPic",
		 0, "VCreate0/0 Sys Init Create20 Attach20@0/0 Info Flush Upd Flush Commit VStart0/0 "
		    "VCreate0/1 Sys Create22 Attach22@0/1 Info Flush Upd Flush Commit VStart0/1 "
		    "VCreate8/3 Sys Attach22@8/3 VStart8/3");
	const struct call *c = &calls[idx_of(0, 0x44006900UL)];
	assert(c->req == 0x44006900UL && c->len == 0x400);
	assert(!memcmp(c->a, "\0\0\0\0", 4) && !memcmp(c->a + 4, "\xff\0\0\0", 4) &&
	       !memcmp(c->a + 8, "\xff\xff\xff\xff", 4) && !memcmp(c->a + 12, "\xff\x80\x80\x80", 4));
	assert(count_req(0, 0x44006900UL) == 1);
	ok("Init once, palette 0 transparent, 1 black, 2 white, 3 grey");
	/* sizes: main ×4 "2026-10-18 10:16:07" 19 chars -> 608 + 8 = 616 x 72; sub ×1 -> 160 x 20 */
	assert(cv[0].w == 616 && cv[0].h == 72 && cv[2].w == 160 && cv[2].h == 20);
	const struct call *at = &calls[idx_of(0, 0x40606906UL)];
	assert(u32(at->a + 24 + 8) == 32 && u32(at->a + 24 + 12) == 32 && at->a[24] == 1);
	ok("main time box 616x72 at 32,32 (x4); sub 160x20 at 8,8 (x1)");
	/* the update sequence: flush covers the canvas, then nr11's range, then nr12 */
	int ii = idx_of(0, 0xc028690aUL);
	const struct call *f1 = &calls[ii + 1], *up = &calls[ii + 2], *f2 = &calls[ii + 3];
	uint64_t st, len;
	memcpy(&st, f1->a, 8);
	memcpy(&len, f1->a + 8, 8);
	uintptr_t va = (uintptr_t)cv[0].buf;
	assert(st <= va && st + len >= va + cv[0].stride * cv[0].h);
	assert(u32(up->a) == 0x20);
	memcpy(&st, f2->a, 8);
	assert(st == ((0x10000000u + 0x20 * 0x10000u) & ~63u));
	ok("update: GetCanvasInfo -> FlushInvCache(canvas) -> UpdateCanvas -> FlushInvCache(its range) -> nr12");
	/* what was drawn is the reference picture of the time string */
	char tt[64];
	time_text(T0, tt, sizeof tt);
	assert(!strcmp(tt, "2026-10-18 10:16:07"));
	for (int y = 0; y < 72; y += 7)
		for (int x = 0; x < 616; x += 3) {
			int t = ref_text(tt, 4, x, y), p = px(cv[0].buf, cv[0].stride, x, y);
			assert(t ? p == 2 : p != 2);
		}
	ok("the main canvas holds the time in white at x4");

	/* the clock: nothing within the second, then one redraw per region and no other call */
	int n0 = ncalls;
	osd_tick(T0);
	assert(ncalls == n0);
	osd_tick(T0 + 1);
	want_seq("next second: the two clocks redrawn, nothing else", n0,
		 "Info Flush Upd Flush Commit Info Flush Upd Flush Commit");

	/* the title: made on the main and sub sizes, attached to sub and JPEG; the clock not redrawn */
	n0 = ncalls;
	assert(!osd_set("osd.title.text", "Front door") && !osd_set("osd.title.enabled", "1"));
	osd_tick(T0 + 1);
	want_seq("title on: created, attached (sub also to JPEG), drawn once", n0,
		 "Create21 Attach21@0/0 Info Flush Upd Flush Commit Create23 Attach23@0/1 Attach23@8/3 Info Flush Upd Flush Commit");
	check_geometry(n0);
	const struct call *ta = last_of(n0, 0x40606906UL);
	assert(cv[1].w == 10 * 32 + 8 && u32(ta->a + 24 + 8) == 8 && u32(ta->a + 24 + 12) == 360 - 20 - 8);
	n0 = ncalls;
	osd_tick(T0 + 2);
	assert(count_req(n0, 0xc028690aUL) == 2 && count_req(n0, 0x40186902UL) == 0);
	ok("title lower left; then only the clocks redraw each second");

	/* move the title to the clock's corner: stacked under it, by SetDisplayAttr on every target */
	n0 = ncalls;
	assert(!osd_set("osd.title.pos", "ul"));
	osd_tick(T0 + 2);
	want_seq("title to the clock's corner: moved, not remade", n0, "Disp21@0/0 Disp23@0/1 Disp23@8/3");
	assert(u32(calls[n0].a + 24 + 12) == 32 + 72 && u32(calls[n0 + 1].a + 24 + 12) == 8 + 20);
	ok("... stacked under the clock (main y 104, sub y 28)");

	/* a longer title: detach everywhere, destroy, create, attach, draw (never a resize) */
	n0 = ncalls;
	assert(!osd_set("osd.title.text", "Front door, north side"));
	osd_tick(T0 + 2);
	want_seq("longer title: detached, destroyed, made again", n0,
		 "Detach21@0/0 Destroy21 Create21 Attach21@0/0 Info Flush Upd Flush Commit "
		 "Detach23@0/1 Detach23@8/3 Destroy23 Create23 Attach23@0/1 Attach23@8/3 Info Flush Upd Flush Commit");
	/* same length, other text: drawn again only */
	n0 = ncalls;
	assert(!osd_set("osd.title.text", "Front door, south side"));
	osd_tick(T0 + 2);
	want_seq("same-length title: redrawn only", n0, "Info Flush Upd Flush Commit Info Flush Upd Flush Commit");
	/* style: the canvases redrawn, nothing remade */
	n0 = ncalls;
	assert(!osd_set("osd.style", "black-on-white"));
	osd_tick(T0 + 2);
	assert(count_req(n0, 0xc028690aUL) == 4 && count_req(n0, 0x40186902UL) == 0);
	assert(px(cv[0].buf, cv[0].stride, 0, 0) == 2);
	ok("style change: all four redrawn, white boxes");

	/* custom place 100/100: flush with the bottom-right corner; large: wider boxes, clipped on sub */
	n0 = ncalls;
	assert(!osd_set("osd.time.pos", "custom") && !osd_set("osd.time.x", "100") && !osd_set("osd.time.y", "100"));
	osd_tick(T0 + 2);
	const struct call *d = place_of(n0, 0x40606908UL, 0x22, 8, 3);
	assert(d && u32(d->a + 24 + 8) == 640 - 160 && u32(d->a + 24 + 12) == 360 - 20);
	d = place_of(n0, 0x40606908UL, 0x20, 0, 0);
	assert(d && u32(d->a + 24 + 8) == 2560 - 616 && u32(d->a + 24 + 12) == 1440 - 72);
	check_geometry(n0);
	n0 = ncalls;
	assert(!osd_set("osd.size", "large") && !osd_set("osd.title.text", "A title too long for the sub-stream at large"));
	osd_tick(T0 + 3);
	check_geometry(n0);
	assert(cv[1].w == 2560 && cv[3].w == 640 && cv[0].w == 19 * 64 + 16 && cv[2].w == 464 && cv[2].h == 56);
	ok("custom 100/100 at the bottom-right edge; large size clipped to the 640 picture");

	/* hide the title: SetDisplayAttr show 0 on each target, region kept */
	n0 = ncalls;
	assert(!osd_set("osd.title.enabled", "0"));
	osd_tick(T0 + 3);
	want_seq("title off: hidden on every target", n0, "Disp21@0/0 Disp23@0/1 Disp23@8/3");
	assert(calls[n0].a[24] == 0);
	char out[1024];
	osd_get(out, sizeof out);
	assert(strstr(out, "osd.status=on\n"));

	/* teardown: every attachment detached, then the region destroyed; nothing afterwards */
	n0 = ncalls;
	osd_stop();
	want_seq("osd_stop: detach each target, then destroy", n0,
		 "Detach20@0/0 Destroy20 Detach21@0/0 Destroy21 Detach22@0/1 Detach22@8/3 Destroy22 "
		 "Detach23@0/1 Detach23@8/3 Destroy23");
	n0 = ncalls;
	osd_tick(T0 + 10);
	assert(ncalls == n0);
}

static void test_failures(void)
{
	/* Create failing at start: OSD off, no further RGN call, every encoder still started */
	reset();
	osd_tick(T0);
	fail_req = 0x40186902UL;
	fail_req_n = 1;
	assert(!start());
	want_seq("Create failing: OSD off, encoders start", 0,
		 "VCreate0/0 Sys Init Create20 VStart0/0 VCreate0/1 Sys VStart0/1 VCreate8/3 Sys VStart8/3");
	int n0 = ncalls;
	osd_tick(T0 + 1);
	assert(!osd_set("osd.title.enabled", "1") && !osd_set("osd.title.text", "x"));
	osd_tick(T0 + 2);
	assert(ncalls == n0);
	char out[1024];
	osd_get(out, sizeof out);
	assert(strstr(out, "osd.status=failed\n"));
	osd_stop();
	assert(ncalls == n0);
	ok("... nothing after it, osd.status=failed, nothing to tear down");

	/* JPEG attach failing: snapshots without the OSD, streams keep it */
	reset();
	osd_tick(T0);
	fail_req = 0x40606906UL;
	fail_req_n = 1;
	fail_dev = 8;
	assert(!start());
	want_seq("JPEG attach failing: logged, skipped", 0,
		 "VCreate0/0 Sys Init Create20 Attach20@0/0 Info Flush Upd Flush Commit VStart0/0 "
		 "VCreate0/1 Sys Create22 Attach22@0/1 Info Flush Upd Flush Commit VStart0/1 "
		 "VCreate8/3 Sys Attach22@8/3 VStart8/3");
	n0 = ncalls;
	assert(!osd_set("osd.title.enabled", "1") && !osd_set("osd.title.text", "Gate"));
	osd_tick(T0);
	assert(!strstr(names(n0, ncalls), "@8/3"));
	assert(count_req(n0, 0x40186902UL) == 2 && !failed);
	ok("... the title isn't attached to JPEG either; the OSD stays on");

	/* drawing failing later (GetCanvasInfo): every region detached and destroyed, then silence */
	fail_req = 0xc028690aUL;
	fail_dev = 0xffffffff;
	fail_seen = 0;
	fail_req_n = 1;
	n0 = ncalls;
	osd_tick(T0 + 1);
	want_seq("redraw failing: all regions detached and destroyed", n0,
		 "Info Detach20@0/0 Destroy20 Detach21@0/0 Destroy21 Detach22@0/1 Destroy22 Detach23@0/1 Destroy23");
	n0 = ncalls;
	osd_tick(T0 + 2);
	assert(!osd_set("osd.style", "white-on-black"));
	osd_tick(T0 + 3);
	osd_stop();
	assert(ncalls == n0);
	ok("... and nothing after the failure, not even at osd_stop");

	/* everything off: no RGN call at all, not even open/Init */
	reset();
	assert(!osd_set("osd.time.enabled", "0"));
	osd_tick(T0);
	assert(!start());
	assert(count_req(0, 0x44006900UL) == 0 && count_req(0, 0x40186902UL) == 0);
	n0 = ncalls;
	osd_tick(T0 + 1);
	assert(ncalls == n0);
	ok("OSD off in the settings: no MI_RGN call at all");
	/* switched on live: Init, then made and attached while the encoders run */
	assert(!osd_set("osd.time.enabled", "1"));
	osd_tick(T0 + 1);
	want_seq("switched on while streaming: Init, made and attached to all three", n0,
		 "Init Create20 Attach20@0/0 Info Flush Upd Flush Commit Create22 Attach22@0/1 Attach22@8/3 Info Flush Upd Flush Commit");
	osd_stop();
}

/* stream.main.size / stream.sub.size (2026-10-25): the text scales with each picture's width
 * (x4 at 2560, x3 at 2304 and 1920, x2 at 1280; the sub x1 at 640 and 960, x2 at 1280), corners
 * a character width in, every box inside its picture; the JPEG channel shares the sub's regions */
static void test_sizes(void)
{
	static const struct { int mw, mh, sw, sh, ms, ss; } z[] = {
		{ 1920, 1080, 1280, 720, 3, 2 }, { 2304, 1296, 960, 540, 3, 1 }, { 1280, 720, 1280, 720, 2, 2 },
		{ 2560, 1440, 1280, 720, 4, 2 } };
	for (unsigned i = 0; i < sizeof z / sizeof z[0]; i++) {
		reset();
		pic_mw = z[i].mw; pic_mh = z[i].mh; pic_sw = z[i].sw; pic_sh = z[i].sh;
		assert(!osd_set("osd.title.text", "Front door") && !osd_set("osd.title.enabled", "1") &&
		       !osd_set("osd.title.pos", "lr"));
		osd_tick(T0);
		assert(!start());
		check_geometry(0);
		for (int k = 0; k < 2; k++) {               /* k 0 main (0x20/0x21), 1 sub (0x22/0x23) */
			int s = k ? z[i].ss : z[i].ms, fw = k ? z[i].sw : z[i].mw, fh = k ? z[i].sh : z[i].mh;
			int tw = (19 * 8 * s + 2 * s + 7) / 8 * 8, th = (18 * s + 3) / 4 * 4;   /* "2026-10-18 10:16:07" */
			int lw = (10 * 8 * s + 2 * s + 7) / 8 * 8;                                 /* "Front door" */
			const struct call *t = place_of(0, 0x40606906UL, 0x20 + 2 * k, 0, (uint32_t)k);
			const struct call *l = place_of(0, 0x40606906UL, 0x21 + 2 * k, 0, (uint32_t)k);
			assert(t && l && cv[2 * k].w == (uint32_t)tw && cv[2 * k].h == (uint32_t)th && cv[2 * k + 1].w == (uint32_t)lw);
			assert(u32(t->a + 24 + 8) == (uint32_t)(8 * s) && u32(t->a + 24 + 12) == (uint32_t)(8 * s));
			assert(u32(l->a + 24 + 8) == (uint32_t)((fw - lw - 8 * s) & ~3) &&
			       u32(l->a + 24 + 12) == (uint32_t)((fh - th - 8 * s) & ~3));
		}
		assert(place_of(0, 0x40606906UL, 0x22, 8, 3) && place_of(0, 0x40606906UL, 0x23, 8, 3));
		osd_stop();
	}
	pic_mw = 2560; pic_mh = 1440; pic_sw = 640; pic_sh = 360;
	reset();
	ok("main 1920x1080 / 2304x1296 / 1280x720 and sub 960x540 / 1280x720: text x3 / x3 / x2 and x1 / x2, "
	   "corners a character in, inside the picture; JPEG shares the sub's regions");
}

/* $OSD_TARGETS (a staged first test on a camera): only the named channels get regions */
static void test_targets(void)
{
	reset();
	setenv("OSD_TARGETS", "sub", 1);
	osd_tick(T0);
	assert(!start());
	want_seq("OSD_TARGETS=sub: Init, Create, Attach on the sub-stream only", 0,
		 "VCreate0/0 Sys VStart0/0 VCreate0/1 Sys Init Create22 Attach22@0/1 Info Flush Upd Flush Commit VStart0/1 "
		 "VCreate8/3 Sys VStart8/3");
	reset();
	setenv("OSD_TARGETS", "jpeg,sub", 1);
	osd_tick(T0);
	assert(!start());
	assert(!strstr(names(0, ncalls), "@0/0") && strstr(names(0, ncalls), "Attach22@8/3"));
	reset();
	setenv("OSD_TARGETS", "main,subway", 1);
	osd_tick(T0);
	assert(!start());
	assert(strstr(names(0, ncalls), "Attach20@0/0") && !strstr(names(0, ncalls), "Create22"));
	unsetenv("OSD_TARGETS");
	reset();
	ok("OSD_TARGETS: sub only, sub and JPEG, main only (names matched whole)");
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	set_tz("UTC0");                    /* the clock text is local time: the same on any host */
	test_settings();
	test_time();
	test_render();
	test_pipeline();
	test_failures();
	test_sizes();
	test_targets();
	printf("ALL OK\n");
	return 0;
}
