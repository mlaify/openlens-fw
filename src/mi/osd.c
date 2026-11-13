/* SPDX-License-Identifier: MIT */
/*
 * osd.c: on-screen display for rtspd. A date/time line and a title line are drawn into small
 * MI_RGN regions (2-bit palette canvases) that the encoders blend into the video, one region per
 * visible line and picture size:
 *   main stream (VENC 0/0)             its own regions, sized for its width
 *   sub stream (VENC 0/1) + JPEG (8/3) the same regions on both (same size; the web preview)
 * The interface is decoded from stock media_server (docs/STOCK-OSD.md); this is our own code. Stock
 * redraws a full-frame canvas on every stream every 100 ms; we redraw the clock once a second
 * and the title only when it changes.
 *
 * /dev/mi_rgn, the MI convention of mi.c: ioctl(fd, _IOC(dir,'i',nr,size), {u16 dev 0; u16; u32
 * size; u64 &args}). Init (palette) happens once, at the first region; Create -> Attach before
 * the encoder's StartRecvPic (mi.c's hook), then GetCanvasInfo -> draw -> FlushInvCache ->
 * UpdateCanvas (nr11) -> FlushInvCache -> nr12 for every redraw. A line whose size changes is
 * detached, destroyed and made again (an attached canvas is never resized); a move or hide is
 * SetDisplayAttr. The first failure is logged, every region is detached and destroyed, and the
 * OSD stays off (the video keeps going). osd_stop detaches and destroys before mi_stop.
 *
 * The font is 8x16, printable ASCII: build.sh generates it (OSD_FONT_H) from a console font in an
 * Ubuntu package (THIRD-PARTY-NOTICES.md). Without it (host tests) a made-up test font is used.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE                    /* localtime_r under -std=c11 (glibc) */
#endif
#include "osd.h"
#include "mi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#ifdef OSD_FONT_H
#include OSD_FONT_H                    /* static const uint8_t osd_font[95][16]; OSD_FONT_NAME */
#else
#define OSD_FONT_NAME "test font (host build; not for the camera)"
#endif

/* I2 pixel order in a canvas byte: 0 = pixel 0 in the low two bits [G: SigmaStar's samples pack
 * index formats LSB first; unconfirmed on this SoC, see docs/STOCK-OSD.md]. */
#ifndef OSD_I2_MSB_FIRST
#define OSD_I2_MSB_FIRST 0
#endif

static void osd_log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "osd: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* ---- settings --------------------------------------------------------------------------- */

enum { OSD_TIME, OSD_TITLE, OSD_LINES };
enum { POS_UL, POS_UR, POS_LL, POS_LR, POS_CUSTOM, POS_N };
enum { SIZE_SMALL, SIZE_MEDIUM, SIZE_LARGE, SIZE_N };
enum { STYLE_BORDER, STYLE_BOW, STYLE_WOB, STYLE_N };

static const char *const pos_names[POS_N] = { "ul", "ur", "ll", "lr", "custom" };
static const char *const size_names[SIZE_N] = { "small", "medium", "large" };
static const char *const style_names[STYLE_N] = { "border", "black-on-white", "white-on-black" };
static const char *const date_formats[] = { "yyyy-MM-dd", "yyyy/MM/dd", "dd/MM/yyyy", "MM/dd/yyyy",
					    "dd-MM-yyyy", "MM-dd-yyyy" };
#define NFORMATS (int)(sizeof date_formats / sizeof date_formats[0])
static const char *const line_names[OSD_LINES] = { "time", "title" };

static struct {
	struct { int enabled, pos, x, y; } line[OSD_LINES];
	int format, h12, weekday, size, style;
	char title[OSD_TITLE_MAX + 1];
} oc = { { { 1, POS_UL, 0, 0 }, { 0, POS_LL, 0, 0 } }, 0, 0, 0, SIZE_SMALL, STYLE_BORDER, "" };

/* A whole number lo..hi: an optional '-', no leading zeros, at most 4 digits. */
static int osd_num(const char *v, int lo, int hi, int *out)
{
	const char *d = v + (*v == '-');
	size_t n = strlen(d);
	if (n < 1 || n > 4 || strspn(d, "0123456789") != n || (n > 1 && d[0] == '0') || (*v == '-' && d[0] == '0'))
		return -1;
	int x = atoi(v);
	if (x < lo || x > hi) return -1;
	*out = x;
	return 0;
}

static int osd_pick(const char *v, const char *const *names, int n)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(v, names[i])) return i;
	return -1;
}

static int osd_text_ok(const char *v)
{
	size_t n = strlen(v);
	if (n > OSD_TITLE_MAX) return 0;
	for (size_t i = 0; i < n; i++)
		if ((unsigned char)v[i] < 0x20 || (unsigned char)v[i] > 0x7e) return 0;
	return 1;
}

static int dirty = 1;                  /* settings changed: compare everything at the next tick */

int osd_set(const char *key, const char *v)
{
	int x;
	if (strncmp(key, "osd.", 4)) return -1;
	const char *k = key + 4;
	int l = !strncmp(k, "time.", 5) ? OSD_TIME : !strncmp(k, "title.", 6) ? OSD_TITLE : -1;
	if (l >= 0) {
		const char *f = k + strlen(line_names[l]) + 1;
		if (!strcmp(f, "enabled") || (l == OSD_TIME && (!strcmp(f, "12h") || !strcmp(f, "weekday")))) {
			if (strcmp(v, "0") && strcmp(v, "1")) return -1;
			*(!strcmp(f, "enabled") ? &oc.line[l].enabled : !strcmp(f, "12h") ? &oc.h12 : &oc.weekday) = *v == '1';
		} else if (!strcmp(f, "pos")) {
			if ((x = osd_pick(v, pos_names, POS_N)) < 0) return -1;
			oc.line[l].pos = x;
		} else if (!strcmp(f, "x") || !strcmp(f, "y")) {
			if (osd_num(v, 0, 100, &x)) return -1;
			*(f[0] == 'x' ? &oc.line[l].x : &oc.line[l].y) = x;
		} else if (l == OSD_TIME && !strcmp(f, "format")) {
			if ((x = osd_pick(v, date_formats, NFORMATS)) < 0) return -1;
			oc.format = x;
		} else if (l == OSD_TITLE && !strcmp(f, "text")) {
			if (!osd_text_ok(v)) return -1;
			snprintf(oc.title, sizeof oc.title, "%s", v);
		} else {
			return -1;
		}
	} else if (!strcmp(k, "size")) {
		if ((x = osd_pick(v, size_names, SIZE_N)) < 0) return -1;
		oc.size = x;
	} else if (!strcmp(k, "style")) {
		if ((x = osd_pick(v, style_names, STYLE_N)) < 0) return -1;
		oc.style = x;
	} else {
		return -1;
	}
	dirty = 1;
	return 0;
}

/* ---- MI_RGN (/dev/mi_rgn) ----------------------------------------------------------------- */

enum { RGN_W = 1, RGN_RW = 3 };
enum { RGN_MOD_VENC = 2, RGN_OSD = 0, RGN_I2 = 2 };
#define RGN_IOC(dir, nr, size) \
	((unsigned long)(((unsigned)(dir) << 30) | ((unsigned)(size) << 16) | ('i' << 8) | (nr)))
#define RGN_HANDLE0 0x20u              /* our handles: 0x20..0x23 (the driver takes < 0x400) */
#define OSD_MAX_W 4096                 /* a canvas wider than this is refused */

struct rgn_hdr { uint16_t dev, pad; uint32_t len; uint64_t ptr; };
_Static_assert(sizeof(struct rgn_hdr) == 16, "rgn_hdr");

struct rgn_port { uint32_t mod, dev, chn, port; uint8_t z, pad[3]; };   /* Ifado ChnPort: 20 B */
_Static_assert(sizeof(struct rgn_port) == 20, "rgn_port");

static int fd_rgn = -1, rgn_inited, failed;

static int rgn_call(const char *what, int dir, int nr, void *args, uint32_t size)
{
	struct rgn_hdr h = { 0, 0, size, (uint64_t)(uintptr_t)args };
	unsigned long req = RGN_IOC(dir, nr, size);
	int r = ioctl(fd_rgn, req, &h);
	if (mi_verbose) osd_log("%-26s nr%-3d %3uB req=%#lx -> %d\n", what, nr, size, req, r);
	if (r) osd_log("%s failed: ret %d errno %d (%s)\n", what, r, errno, strerror(errno));
	return r;
}

int osd_open(void)
{
	if (fd_rgn < 0 && (fd_rgn = open("/dev/mi_rgn", O_RDWR)) < 0) {
		osd_log("open /dev/mi_rgn: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Palette: 0 transparent, 1 black, 2 white, 3 grey; entries {alpha, r, g, b}. */
static int rgn_init(void)
{
	static uint8_t pal[256][4];
	if (rgn_inited) return 0;
	if (osd_open()) return -1;
	memset(pal, 0, sizeof pal);
	memcpy(pal[1], (uint8_t[4]){ 0xff, 0, 0, 0 }, 4);
	memcpy(pal[2], (uint8_t[4]){ 0xff, 0xff, 0xff, 0xff }, 4);
	memcpy(pal[3], (uint8_t[4]){ 0xff, 0x80, 0x80, 0x80 }, 4);
	_Static_assert(sizeof pal == 0x400, "palette");
	/* A process before us may have left it initialised (no DeInit: stock never calls it): then
	 * Create tells whether the driver works. */
	if (rgn_call("MI_RGN_Init", RGN_W, 0, pal, sizeof pal))
		osd_log("continuing: an earlier process may have initialised MI_RGN\n");
	rgn_inited = 1;
	osd_log("MI_RGN up, font: %s\n", OSD_FONT_NAME);
	return 0;
}

/* ---- targets and regions ------------------------------------------------------------------ */

enum { T_MAIN, T_SUB, T_JPEG, NTARGETS };     /* = mi.c's stream index */
enum { C_MAIN, C_SUB, NCLASSES };             /* a picture size: its regions */

static struct osd_target { int present, bad; uint32_t dev, chn; int w, h; } tgt[NTARGETS];

static struct osd_region {
	int made, w, h, x, y, shown;
	uint32_t handle;
	int on[NTARGETS];              /* attached to that target */
	int drawn, style, scale;       /* what the canvas holds */
	char text[64];
} reg[NCLASSES][OSD_LINES];

static int class_of(int t) { return t == T_MAIN ? C_MAIN : C_SUB; }
static int class_target(int c) { return c == C_MAIN ? T_MAIN : T_SUB; }   /* gives the size */

static struct rgn_port port_of(int t)
{
	return (struct rgn_port){ RGN_MOD_VENC, tgt[t].dev, tgt[t].chn, 0, 0, { 0 } };
}

/* AttachToChn (nr6) and SetDisplayAttr (nr8): {handle; ChnPort; ChnPortParam 72 B: +0 show,
 * +4 layer (stock: the handle), +8 x, +0xc y, +0x15 0xAA [G: alpha]} */
static int rgn_place(int nr, const struct osd_region *g, int t, int show, int x, int y)
{
	struct { uint32_t handle; struct rgn_port p; uint8_t param[72]; } a;
	uint32_t u[3] = { g->handle, (uint32_t)x, (uint32_t)y };
	_Static_assert(sizeof a == 96, "attach");
	memset(&a, 0, sizeof a);
	a.handle = g->handle;
	a.p = port_of(t);
	a.param[0] = (uint8_t)show;
	memcpy(a.param + 4, u, sizeof u);
	a.param[0x15] = 0xaa;
	return rgn_call(nr == 6 ? "MI_RGN_AttachToChn" : "MI_RGN_SetDisplayAttr", RGN_W, nr, &a, sizeof a);
}

static void rgn_drop(struct osd_region *g)
{
	for (int t = 0; t < NTARGETS; t++) {
		if (!g->on[t]) continue;
		struct { uint32_t handle; struct rgn_port p; } d = { g->handle, port_of(t) };
		_Static_assert(sizeof d == 24, "detach");
		rgn_call("MI_RGN_DetachFromChn", RGN_W, 7, &d, sizeof d);
		g->on[t] = 0;
	}
	if (g->made) {
		uint32_t h = g->handle;
		rgn_call("MI_RGN_Destroy", RGN_W, 3, &h, sizeof h);
	}
	memset(g, 0, sizeof *g);
}

static void drop_all(void)
{
	for (int c = 0; c < NCLASSES; c++)
		for (int l = 0; l < OSD_LINES; l++) rgn_drop(&reg[c][l]);
}

static void osd_fail(const char *what)
{
	if (failed) return;
	failed = 1;
	osd_log("%s failed: on-screen display off\n", what);
	drop_all();
}

/* ---- text and layout ---------------------------------------------------------------------- */

static uint8_t glyph_row(unsigned char c, int r)
{
	if (c < 0x20 || c > 0x7e) c = '?';
#ifdef OSD_FONT_H
	return osd_font[c - 0x20][r];
#else
	return r == 0 || r == 15 ? 0 : (uint8_t)((c * 7u + (unsigned)r * 13u) & 0x7e);
#endif
}

/* Glyph scale for a picture width: 640 -> 1, 1920 -> 3, 2560 -> 4 (small); bigger for medium
 * and large. */
static int scale_for(int w, int size)
{
	int s = w / 640 < 1 ? 1 : w / 640;
	return size == SIZE_LARGE ? 2 * s + (s == 1) : size == SIZE_MEDIUM ? s + (s + 1) / 2 : s;
}

static const char *const wdays[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/* In the camera's local time: the TZ rtspd sets from time.tz (setenv + tzset; UTC0 by default). */
static void time_text(time_t now, char *out, size_t cap)
{
	struct tm g;
	char date[48];
	if (!localtime_r(&now, &g)) memset(&g, 0, sizeof g);
	int y = g.tm_year + 1900 < 0 ? 0 : g.tm_year + 1900 > 9999 ? 9999 : g.tm_year + 1900;
	int m = g.tm_mon + 1, d = g.tm_mday, hh = g.tm_hour;
	switch (oc.format) {
	case 1: snprintf(date, sizeof date, "%04d/%02d/%02d", y, m, d); break;
	case 2: snprintf(date, sizeof date, "%02d/%02d/%04d", d, m, y); break;
	case 3: snprintf(date, sizeof date, "%02d/%02d/%04d", m, d, y); break;
	case 4: snprintf(date, sizeof date, "%02d-%02d-%04d", d, m, y); break;
	case 5: snprintf(date, sizeof date, "%02d-%02d-%04d", m, d, y); break;
	default: snprintf(date, sizeof date, "%04d-%02d-%02d", y, m, d); break;
	}
	const char *ampm = "";
	if (oc.h12) {
		ampm = hh < 12 ? " AM" : " PM";
		hh = hh % 12 ? hh % 12 : 12;
	}
	snprintf(out, cap, "%s %02d:%02d:%02d%s%s%s", date, hh, g.tm_min, g.tm_sec, ampm, oc.weekday ? " " : "",
		 oc.weekday ? wdays[g.tm_wday % 7] : "");
}

struct osd_want { int on, w, h, x, y, scale; char text[64]; };

static int align_up(int v, int a) { return (v + a - 1) / a * a; }

/* A line's box (8-aligned width, 4-aligned height, one font pixel of padding) and its 4-aligned
 * place in a fw x fh picture: a corner with a margin of a character width, or custom percentages
 * of the room left (0 = left/top, 100 = right/bottom); `off` moves it away from its edge (a line
 * sharing the corner). Clipped to the picture. */
static void layout(struct osd_want *w, int fw, int fh, int nchars, int pos, int px, int py, int off)
{
	int pad = w->scale, m = (8 * w->scale) & ~3;
	w->w = align_up(nchars * 8 * w->scale + 2 * pad, 8);
	w->h = align_up(16 * w->scale + 2 * pad, 4);
	if (w->w > (fw & ~7)) w->w = fw & ~7;
	if (w->h > (fh & ~3)) w->h = fh & ~3;
	int xr = fw - w->w, yr = fh - w->h;
	w->x = pos == POS_UR || pos == POS_LR ? xr - m : pos == POS_CUSTOM ? xr * px / 100 : m;
	w->y = pos == POS_LL || pos == POS_LR ? yr - m - off : pos == POS_CUSTOM ? yr * py / 100 : m + off;
	if (w->x > xr) w->x = xr;
	if (w->y > yr) w->y = yr;
	if (w->x < 0) w->x = 0;
	if (w->y < 0) w->y = 0;
	w->x &= ~3;
	w->y &= ~3;
	w->on = w->w >= 8 && w->h >= 4;
}

static time_t now_s;                   /* the time shown */

static void want_of(int c, int l, struct osd_want *w)
{
	const struct osd_target *ft = &tgt[class_target(c)];
	char tt[64];
	memset(w, 0, sizeof *w);
	if (!ft->present || ft->bad) return;
	w->scale = scale_for(ft->w, oc.size);
	time_text(now_s, tt, sizeof tt);
	int time_on = oc.line[OSD_TIME].enabled, title_on = oc.line[OSD_TITLE].enabled && *oc.title;
	if (l == OSD_TIME ? !time_on : !title_on) return;
	snprintf(w->text, sizeof w->text, "%s", l == OSD_TIME ? tt : oc.title);
	int off = 0, pos = oc.line[l].pos;
	if (l == OSD_TITLE && time_on && pos == oc.line[OSD_TIME].pos && pos != POS_CUSTOM) {
		struct osd_want t = { .scale = w->scale };           /* stacked next to the clock */
		layout(&t, ft->w, ft->h, (int)strlen(tt), POS_UL, 0, 0, 0);
		off = t.h;
	}
	layout(w, ft->w, ft->h, (int)strlen(w->text), pos, oc.line[l].x, oc.line[l].y, off);
}

/* ---- drawing ------------------------------------------------------------------------------ */

static int text_px(const char *s, int n, int scale, int x, int y)
{
	int fx = x - scale, fy = y - scale;                        /* padding: one font pixel */
	if (fx < 0 || fy < 0) return 0;
	int col = fx / scale, row = fy / scale, ci = col / 8;
	if (row >= 16 || ci >= n) return 0;
	return glyph_row((unsigned char)s[ci], row) >> (7 - col % 8) & 1;
}

static void put_px(uint8_t *row, int x, int idx)
{
	int sh = OSD_I2_MSB_FIRST ? 6 - (x & 3) * 2 : (x & 3) * 2;
	row[x >> 2] = (uint8_t)((row[x >> 2] & ~(3 << sh)) | idx << sh);
}

/* Text into a w x h I2 canvas (stride bytes a row), clipped to it. border: white text with a
 * one-pixel black outline on transparent; black-on-white and white-on-black fill the box. */
static void render(uint8_t *buf, uint32_t stride, int w, int h, const char *s, int scale, int style)
{
	static uint8_t m[3][OSD_MAX_W + 2];                         /* text mask: rows y-1, y, y+1 */
	int n = (int)strlen(s);
	int bg = style == STYLE_BOW ? 2 : style == STYLE_WOB ? 1 : 0, fg = style == STYLE_BOW ? 1 : 2;
	if (w > OSD_MAX_W) w = OSD_MAX_W;
	memset(m, 0, sizeof m);
	for (int x = 0; x < w; x++) m[2][x + 1] = (uint8_t)text_px(s, n, scale, x, 0);
	for (int y = 0; y < h; y++) {
		memmove(m[0], m[1], sizeof m[0]);
		memmove(m[1], m[2], sizeof m[1]);
		for (int x = 0; x < w; x++) m[2][x + 1] = y + 1 < h ? (uint8_t)text_px(s, n, scale, x, y + 1) : 0;
		uint8_t *row = buf + (size_t)y * stride;
		memset(row, bg * 0x55, stride);
		for (int x = 0; x < w; x++) {
			int idx = bg;
			if (m[1][x + 1]) idx = fg;
			else if (style == STYLE_BORDER && (m[0][x] | m[0][x + 1] | m[0][x + 2] | m[1][x] | m[1][x + 2] |
							 m[2][x] | m[2][x + 1] | m[2][x + 2]))
				idx = 1;
			if (idx != bg) put_px(row, x, idx);
		}
	}
}

/* GetCanvasInfo -> draw -> flush -> UpdateCanvas (nr11) -> flush its range -> nr12. */
static int rgn_draw(struct osd_region *g, const struct osd_want *w)
{
	struct { uint32_t handle, pad; uint64_t phy, virt; uint32_t w, h, stride, fmt; } ci;
	_Static_assert(sizeof ci == 40, "canvas info");
	memset(&ci, 0, sizeof ci);
	ci.handle = g->handle;
	if (rgn_call("MI_RGN_GetCanvasInfo", RGN_RW, 10, &ci, sizeof ci)) return -1;
	if (!ci.virt || ci.w < (uint32_t)g->w || ci.h < (uint32_t)g->h || ci.w > OSD_MAX_W || ci.h > OSD_MAX_W ||
	    ci.stride < (ci.w + 3) / 4 || ci.stride > OSD_MAX_W) {
		osd_log("canvas %u: %ux%u stride %u at %#llx, wanted %dx%d\n", ci.handle, ci.w, ci.h, ci.stride,
			(unsigned long long)ci.virt, g->w, g->h);
		return -1;
	}
	uint8_t *buf = (uint8_t *)(uintptr_t)ci.virt;
	render(buf, ci.stride, (int)ci.w, (int)ci.h, w->text, w->scale, oc.style);
	if (mi_flushinv(buf, ci.h * ci.stride)) return -1;
	struct { uint32_t handle, va, size; } up = { g->handle, 0, 0 };
	if (rgn_call("MI_RGN_UpdateCanvas", RGN_RW, 11, &up, sizeof up)) return -1;
	if (up.va && up.size && mi_flushinv((void *)(uintptr_t)up.va, up.size)) return -1;
	uint32_t hd = g->handle;
	if (rgn_call("MI_RGN_UpdateCanvas (commit)", RGN_W, 12, &hd, sizeof hd)) return -1;
	g->drawn = 1;
	g->style = oc.style;
	g->scale = w->scale;
	snprintf(g->text, sizeof g->text, "%s", w->text);
	return 0;
}

/* ---- bringing a line to its wanted state -------------------------------------------------- */

#define FAIL(what) do { osd_fail(what); return; } while (0)

static void sync_line(int c, int l)
{
	struct osd_region *g = &reg[c][l];
	struct osd_want w;
	want_of(c, l, &w);
	if (!w.on) {
		for (int t = 0; t < NTARGETS && g->shown; t++)
			if (g->on[t] && rgn_place(8, g, t, 0, g->x, g->y)) FAIL("hiding a line");
		g->shown = 0;
		return;
	}
	if (g->made && (g->w != w.w || g->h != w.h)) rgn_drop(g);       /* never resize an attached canvas */
	if (!g->made) {
		struct { uint32_t handle, type, fmt, w, h; uint16_t one, z; } a = {
			RGN_HANDLE0 + (uint32_t)(c * OSD_LINES + l), RGN_OSD, RGN_I2, (uint32_t)w.w, (uint32_t)w.h, 1, 0 };
		_Static_assert(sizeof a == 24, "create");
		if (rgn_init()) FAIL("opening MI_RGN");
		if (rgn_call("MI_RGN_Create", RGN_W, 2, &a, sizeof a)) FAIL("MI_RGN_Create");
		memset(g, 0, sizeof *g);
		g->made = 1;
		g->handle = a.handle;
		g->w = w.w;
		g->h = w.h;
	}
	if (g->x != w.x || g->y != w.y || !g->shown)
		for (int t = 0; t < NTARGETS; t++)
			if (g->on[t] && rgn_place(8, g, t, 1, w.x, w.y)) FAIL("MI_RGN_SetDisplayAttr");
	g->x = w.x;
	g->y = w.y;
	g->shown = 1;
	for (int t = 0; t < NTARGETS; t++) {
		if (class_of(t) != c || !tgt[t].present || tgt[t].bad || g->on[t]) continue;
		if (!rgn_place(6, g, t, 1, w.x, w.y)) { g->on[t] = 1; continue; }
		if (t != T_JPEG) FAIL("MI_RGN_AttachToChn");
		osd_log("snapshots (JPEG 8/3) go without the OSD\n");
		tgt[t].bad = 1;
	}
	if ((!g->drawn || strcmp(g->text, w.text) || g->style != oc.style || g->scale != w.scale) && rgn_draw(g, &w))
		FAIL("drawing");
}

static void sync_class(int c)
{
	for (int l = 0; l < OSD_LINES && !failed; l++) sync_line(c, l);
}

static unsigned skip;                  /* targets left out (bench: $OSD_TARGETS) */

/* mi.c's hook: an encoder channel exists and isn't started yet. */
static void osd_hook(int stream, uint32_t dev, uint32_t chn, int w, int h)
{
	if (stream < 0 || stream >= NTARGETS || w < 8 || h < 4 || skip >> stream & 1) return;
	tgt[stream] = (struct osd_target){ 1, 0, dev, chn, w, h };
	if (failed) return;
	if (!now_s) now_s = time(NULL);
	sync_class(class_of(stream));
}

/* For a staged first test on a camera, $OSD_TARGETS limits the OSD to some of "main", "sub" and
 * "jpeg" (comma-separated; the JPEG channel needs "sub", whose regions it shares). Unset: all. */
void osd_enable(void)
{
	static const char *const names[NTARGETS] = { "main", "sub", "jpeg" };
	const char *t = getenv("OSD_TARGETS");
	skip = 0;
	for (int i = 0; t && i < NTARGETS; i++) {
		size_t n = strlen(names[i]);
		int found = 0;
		for (const char *p = t; *p; p += strcspn(p, ",") + (p[strcspn(p, ",")] == ','))
			found |= strcspn(p, ",") == n && !strncmp(p, names[i], n);
		if (!found) skip |= 1u << i;
	}
	if (skip) osd_log("only on: %s (OSD_TARGETS)\n", t);
	mi_set_chn_hook(osd_hook);
}

void osd_tick(time_t now)
{
	if (failed || (now == now_s && !dirty)) return;
	now_s = now;
	dirty = 0;
	for (int c = 0; c < NCLASSES && !failed; c++)
		if (tgt[class_target(c)].present) sync_class(c);
}

void osd_stop(void)
{
	drop_all();
	if (fd_rgn >= 0) close(fd_rgn);
	fd_rgn = -1;
	rgn_inited = 0;
	memset(tgt, 0, sizeof tgt);
	mi_set_chn_hook(NULL);
}

size_t osd_get(char *out, size_t cap)
{
	int on = 0;
	size_t n = 0;
	if (!cap) return 0;
	*out = 0;
	for (int c = 0; c < NCLASSES; c++)
		for (int l = 0; l < OSD_LINES; l++) on |= reg[c][l].made && reg[c][l].shown;
	for (int l = 0; l < OSD_LINES && n < cap; l++)
		n += (size_t)snprintf(out + n, cap - n, "osd.%s.enabled=%d\nosd.%s.pos=%s\nosd.%s.x=%d\nosd.%s.y=%d\n",
				      line_names[l], oc.line[l].enabled, line_names[l], pos_names[oc.line[l].pos],
				      line_names[l], oc.line[l].x, line_names[l], oc.line[l].y);
	if (n < cap)
		n += (size_t)snprintf(out + n, cap - n, "osd.time.format=%s\nosd.time.12h=%d\nosd.time.weekday=%d\n"
				      "osd.title.text=%s\nosd.size=%s\nosd.style=%s\nosd.status=%s\n",
				      date_formats[oc.format], oc.h12, oc.weekday, oc.title, size_names[oc.size],
				      style_names[oc.style], failed ? "failed" : on ? "on" : "off");
	return n < cap ? n : cap - 1;
}
