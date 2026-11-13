/* SPDX-License-Identifier: MIT */
/*
 * Host test for parts of mi.c that need no camera: mi.c is compiled in with ioctl() replaced by a
 * fake /dev/mi_sensor that records MI_SNR_SetOrien and answers MI_SNR_GetOrien.
 *
 *   clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/mi \
 *       -o $TMPDIR/test_mi src/mi/test_mi.c -lm
 *   $TMPDIR/test_mi
 *
 * Checks: the orientation ioctls (request codes 0x4008690c / 0xc008690d, the 8-byte argument, the
 * header), that nothing is sent before mi_start, the non-blocking read-back (as stock's 10 tries),
 * range checks; MI_SNR_SetFps (0x40086905, {pad 0, fps}, once, up to 5 tries as stock); and the AE's shutter/gain split under the day and night limits (auto and user),
 * with anti-flicker at 50 and 60 Hz (whole half cycles, the minimum, a limit too short for it), all
 * with ISP gain 1x giving the results from before it; ISP gain after the sensor's 32x up to the
 * mode's limit (4x / 2x, others; unset in mi_cfg = 1x), IspGain in the AE result (BV unchanged),
 * the total gain for the day/night score; image.exposure_night's night target and the switch.
 * ISP tuning (NR 2D/3D, WDR, BLC) against a fake IQ API (MI_TEST_IQ) holding the three groups as
 * the stock profile has them: exact sizes, a read before every write, no write when nothing
 * changes, only the 16 strength fields ever change, the clamps, BLC only with WDR off and back to
 * the baseline, and a group that can't be read or looks wrong is never written.
 * Stock night tuning (synthetic iq-night.bin / iq-day-switch.bin in $TMPDIR): file checks, the
 * per-mode baselines, key off = ColorToGray only, the night and day writes (only differing groups,
 * exact sizes, file order), sliders and NR against the active mode's baseline, live on/off at
 * night, write failures, start-up at night.
 */
#define MI_TEST_IQ                     /* iq_xfer below instead of the ioctl transport */
#define ioctl test_ioctl              /* mi.c's ioctl calls (and <sys/ioctl.h>'s prototype) */
#include "mi.c"
#undef ioctl

#include <assert.h>

enum { FAKE_SNR = 1000 };
static int calls, set_calls, sensor_m, sensor_f, lag;   /* lag: GetOrien reads stale this many times */
static int pend_m, pend_f;
static int fps_calls, fps_fail;                 /* MI_SNR_SetFps calls; failures still to give */
static uint32_t fps_pad, fps_set;
static unsigned long last_req;
static uint8_t last_arg[8];

int test_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	va_start(ap, req);
	struct mi_hdr *h = va_arg(ap, struct mi_hdr *);
	va_end(ap);
	calls++;
	last_req = req;
	if (fd != FAKE_SNR || h->len != 8) { errno = ENOTTY; return -1; }
	uint8_t *a = (uint8_t *)(uintptr_t)h->ptr;
	memcpy(last_arg, a, 8);
	if (req == 0x4008690cUL) {                      /* SetOrien */
		set_calls++;
		pend_m = a[4];
		pend_f = a[5];
		if (!lag) { sensor_m = pend_m; sensor_f = pend_f; }
		return 0;
	}
	if (req == 0x40086905UL) {                      /* SetFps {pad, fps}: fails fps_fail times first */
		fps_calls++;
		memcpy(&fps_pad, a, 4);
		memcpy(&fps_set, a + 4, 4);
		if (fps_fail) { fps_fail--; errno = EBUSY; return -1; }
		return 0;
	}
	if (req == 0xc008690dUL) {                      /* GetOrien: applied after `lag` reads */
		if (lag && !--lag) { sensor_m = pend_m; sensor_f = pend_f; }
		a[4] = (uint8_t)sensor_m;
		a[5] = (uint8_t)sensor_f;
		return 0;
	}
	errno = ENOTTY;
	return -1;
}

static void ok(const char *what) { printf("ok: %s\n", what); }

/* ---- fake IQ API: the three tuning groups as iq-profile-stock (gc4023_day.bin) has them, and
 * (night tuning) ColorToGray, the image controls' four groups and DynamicBlackLevel ---- */
enum { NFG = 10 };
static struct fake_group {
	uint32_t id, size;
	uint8_t data[6200], orig[6200];
	int fail_get, fail_set;
} fg[NFG] = { { 4111, 1476, { 0 }, { 0 }, 0, 0 }, { 4110, 2632, { 0 }, { 0 }, 0, 0 },
	      { 4118, 1036, { 0 }, { 0 }, 0, 0 }, { 4100, 4, { 0 }, { 0 }, 0, 0 },
	      { 4102, 76, { 0 }, { 0 }, 0, 0 }, { 4101, 76, { 0 }, { 0 }, 0, 0 },
	      { 4106, 416, { 0 }, { 0 }, 0, 0 }, { 4114, 6200, { 0 }, { 0 }, 0, 0 },
	      { 4167, 1436, { 0 }, { 0 }, 0, 0 }, { 0x2e06, 58, { 0 }, { 0 }, 0, 0 } };
enum { F_NR2D, F_NR3D, F_WDR, F_CTG, F_BRI, F_CON, F_SAT, F_SHP, F_DBL, F_AESET };
static char iq_log[4096];                       /* "g4111/1476;s4111/1476;" */
static int iq_bad_size;

static int iq_xfer(int set, uint32_t cmd, void *data, uint32_t size)
{
	snprintf(iq_log + strlen(iq_log), sizeof iq_log - strlen(iq_log), "%c%u/%u;", set ? 's' : 'g', cmd, size);
	for (int k = 0; k < NFG; k++) {
		if (fg[k].id != cmd) continue;
		if (fg[k].size != size) { iq_bad_size++; return -1; }
		if (set ? fg[k].fail_set : fg[k].fail_get) return -1;
		if (set) memcpy(fg[k].data, data, size);
		else memcpy(data, fg[k].data, size);
		return 0;
	}
	return -1;
}

static const uint8_t blend0[16] = { 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
static const uint16_t mdgain0[16] = { 200, 220, 240, 260, 260, 280, 280, 200, 160, 140, 120, 120, 120, 120,
				      120, 120 };
static const uint8_t wdr0[16] = { 200, 200, 190, 180, 170, 170, 170, 170, 160, 150, 150, 150, 150, 150, 150, 150 };

static void fake_groups(void)
{
	for (int k = 0; k < NFG; k++) {
		uint8_t *g = fg[k].data;
		for (uint32_t i = 0; i < fg[k].size; i++) g[i] = (uint8_t)(i * 7 + 3);   /* the other fields */
		uint32_t en = 1, z = 0;
		memcpy(g, &en, 4);                      /* bEnable 1 */
		memcpy(g + 4, &z, 4);                   /* dbg 0 (+pad) */
		memcpy(g + 8, &z, 4);                   /* opType 0 = auto */
		fg[k].fail_get = fg[k].fail_set = 0;
	}
	fg[2].data[12] = 4;                             /* WDR BoxNum */
	for (int i = 0; i < 16; i++) {
		fg[0].data[0x0c + i * 0x56] = blend0[i];
		memcpy(fg[1].data + 0x0c + i * 0x9a + 4, &mdgain0[i], 2);
		fg[2].data[0x10 + i * 60] = wdr0[i];
	}
	memset(fg[F_CTG].data, 0, 4);                   /* colour */
	for (int k = F_BRI; k <= F_CON; k++)            /* levels: {bEnable, opType, 16 auto, manual} */
		for (int i = 0; i < 17; i++) {
			uint32_t v = (uint32_t)(40 + i);
			memcpy(fg[k].data + 8 + 4 * i, &v, 4);
		}
	for (int k = 0; k < NFG; k++) memcpy(fg[k].orig, fg[k].data, fg[k].size);
}

/* Group k differs from its original only in the 16 strength fields */
static int only_fields(int k)
{
	static const unsigned first[3] = { 0x0c, 0x0c, 0x10 }, stride[3] = { 0x56, 0x9a, 60 }, field[3] = { 0, 4, 0 },
			      width[3] = { 1, 2, 1 };
	for (uint32_t o = 0; o < fg[k].size; o++) {
		int in_field = 0;
		for (unsigned i = 0; i < 16; i++) {
			unsigned at = first[k] + i * stride[k] + field[k];
			in_field |= o >= at && o < at + width[k];
		}
		if (!in_field && fg[k].data[o] != fg[k].orig[o]) {
			fprintf(stderr, "group %u byte %u changed\n", fg[k].id, o);
			return 0;
		}
	}
	return 1;
}

static unsigned blend(int i) { return fg[0].data[0x0c + i * 0x56]; }
static unsigned mdgain(int i) { uint16_t v; memcpy(&v, fg[1].data + 0x0c + i * 0x9a + 4, 2); return v; }
static unsigned wdr(int i) { return fg[2].data[0x10 + i * 60]; }

static void tune_reset(void)
{
	memset(&tune, 0, sizeof tune);
	tune.value[MI_TUNE_NR2D] = tune.value[MI_TUNE_NR3D] = 128;
	fake_groups();
	*iq_log = 0;
}

static void test_tune(void)
{
	tune_reset();
	/* before the IQ profile: kept, nothing sent; range */
	assert(mi_tune_get(MI_TUNE_NR2D) == 128 && mi_tune_get(MI_TUNE_NR3D) == 128 && mi_tune_get(MI_TUNE_WDR) == 0 &&
	       mi_tune_get(MI_TUNE_BLC) == 0);
	assert(!mi_tune_set(MI_TUNE_NR2D, 64) && !*iq_log);
	assert(mi_tune_set(MI_TUNE_NR2D, 256) && mi_tune_set(MI_TUNE_NR3D, -1) && mi_tune_set(MI_TUNE_COUNT, 1));
	assert(mi_tune_get(MI_TUNE_NR2D) == 64 && mi_tune_get(-1) == -1);
	ok("tuning before the IQ profile: kept, nothing sent; 0..255 only");

	/* capture: each group read at its exact size; the pending NR2D written, the others only read */
	tune_capture();
	assert(!strcmp(iq_log, "g4111/1476;g4110/2632;g4118/1036;g4111/1476;s4111/1476;g4110/2632;g4118/1036;"));
	assert(tune.ok[0][0] && tune.ok[0][1] && tune.ok[0][2] && !iq_bad_size);
	for (int i = 0; i < 16; i++) assert(blend(i) == blend0[i] * 64u / 128 && mdgain(i) == mdgain0[i] && wdr(i) == wdr0[i]);
	assert(only_fields(0) && !memcmp(fg[1].data, fg[1].orig, 2632) && !memcmp(fg[2].data, fg[2].orig, 1036));
	ok("capture: exact sizes (1476/2632/1036), the pending 2D NR written, unchanged groups only read");

	/* the same value again: read, compared, not written */
	*iq_log = 0;
	assert(!mi_tune_set(MI_TUNE_NR2D, 64) && !strcmp(iq_log, "g4111/1476;"));
	/* clamps: BlendRatio at most 16 (XML), MdGain at most 10230 */
	*iq_log = 0;
	assert(!mi_tune_set(MI_TUNE_NR2D, 255) && !strcmp(iq_log, "g4111/1476;s4111/1476;"));
	for (int i = 0; i < 16; i++) assert(blend(i) == (blend0[i] * 255u / 128 > 16 ? 16 : blend0[i] * 255u / 128));
	assert(blend(15) == 16 && blend(7) == 5 && only_fields(0));
	assert(!mi_tune_set(MI_TUNE_NR2D, 128));
	assert(!memcmp(fg[0].data, fg[0].orig, 1476));
	assert(!mi_tune_set(MI_TUNE_NR3D, 255));
	for (int i = 0; i < 16; i++) assert(mdgain(i) == mdgain0[i] * 255u / 128);
	assert(only_fields(1) && !mi_tune_set(MI_TUNE_NR3D, 0) && mdgain(5) == 0 && only_fields(1));
	assert(!mi_tune_set(MI_TUNE_NR3D, 128) && !memcmp(fg[1].data, fg[1].orig, 2632));
	ok("NR: read-compare-write; 2D NR clamped to 16, 3D NR scaled; 128 restores the profile exactly");

	/* WDR scale (clamped to 255), BLC only with WDR off, 0/0 back to the profile */
	*iq_log = 0;
	assert(!mi_tune_set(MI_TUNE_WDR, 200) && !strcmp(iq_log, "g4118/1036;s4118/1036;"));
	for (int i = 0; i < 16; i++) assert(wdr(i) == (wdr0[i] * 200u / 128 > 255 ? 255 : wdr0[i] * 200u / 128));
	assert(wdr(0) == 255 && wdr(9) == 234 && only_fields(2));
	*iq_log = 0;
	assert(!mi_tune_set(MI_TUNE_BLC, 100) && !strcmp(iq_log, "g4118/1036;"));      /* WDR on: BLC waits */
	assert(!mi_tune_set(MI_TUNE_WDR, 0));
	for (int i = 0; i < 16; i++) assert(wdr(i) == 100);
	assert(only_fields(2) && fg[2].data[12] == 4);
	assert(!mi_tune_set(MI_TUNE_BLC, 0) && !memcmp(fg[2].data, fg[2].orig, 1036));
	assert(!mi_tune_set(MI_TUNE_WDR, 128) && !memcmp(fg[2].data, fg[2].orig, 1036));
	assert(!mi_tune_set(MI_TUNE_WDR, 0));
	ok("WDR: Strength scaled (clamped to 255); BLC only with WDR off; BLC 0 restores the profile");

	/* clamp of MdGain at 10230: a profile with a large gain */
	tune_reset();
	uint16_t big = 9000;
	memcpy(fg[1].data + 0x0c + 3 * 0x9a + 4, &big, 2);
	memcpy(fg[1].orig, fg[1].data, 2632);
	tune.value[MI_TUNE_NR3D] = 255;
	tune_capture();
	assert(mdgain(3) == 10230 && mdgain(0) == 200u * 255 / 128 && only_fields(1));
	ok("3D NR MdGain clamped to 10230");

	/* a group that can't be read, or doesn't look like the layout, is never written */
	tune_reset();
	fg[1].fail_get = 1;                             /* NR3D unreadable */
	fg[2].data[8] = 7;                              /* WDR opType 7: not this layout */
	memcpy(fg[2].orig, fg[2].data, 1036);
	fg[0].data[0x0c + 2 * 0x56] = 40;               /* BlendRatio 40 > 16: not this layout */
	memcpy(fg[0].orig, fg[0].data, 1476);
	tune.value[MI_TUNE_NR3D] = 10;
	tune.value[MI_TUNE_WDR] = 50;
	tune.value[MI_TUNE_NR2D] = 10;
	tune_capture();
	assert(!tune.ok[0][0] && !tune.ok[0][1] && !tune.ok[0][2] && !strchr(iq_log, 's'));
	*iq_log = 0;
	assert(mi_tune_set(MI_TUNE_NR3D, 20) == -1 && mi_tune_set(MI_TUNE_WDR, 60) == -1 && mi_tune_set(MI_TUNE_NR2D, 1) == -1);
	assert(!*iq_log && !memcmp(fg[2].data, fg[2].orig, 1036) && !memcmp(fg[0].data, fg[0].orig, 1476));
	ok("an unreadable group or an unknown layout: left alone, never written, setting it fails");

	/* a failing read or write later is reported */
	tune_reset();
	tune_capture();
	fg[0].fail_get = 1;
	*iq_log = 0;
	assert(mi_tune_set(MI_TUNE_NR2D, 0) == -1 && !strcmp(iq_log, "g4111/1476;"));
	fg[0].fail_get = 0;
	fg[0].fail_set = 1;
	assert(mi_tune_set(MI_TUNE_NR2D, 0) == -1);
	assert(!iq_bad_size);
	ok("a failing read (nothing written) or write is reported");
}

/* AE split with anti-flicker */
static void test_antiflicker(void)
{
	int on, hz;
	assert(mi_antiflicker(2, 50) && mi_antiflicker(1, 55) && mi_antiflicker(0, 0));
	assert(!mi_antiflicker(1, 50));
	mi_antiflicker_get(&on, &hz);
	assert(on == 1 && hz == 50);
	cfg.fps = 25;
	struct { int night, hz; uint32_t day_max, night_max; double exp, sh, gain, exp_after; } t[] = {
		{ 0, 50, 0, 0, 1e9, 40000, 32 * 1024, 1280000 },      /* 4 half cycles = a 25 fps frame */
		{ 0, 50, 0, 0, 5000, 10000, 1024, 10000 },            /* bright: at least 1/100 s */
		{ 0, 50, 0, 0, 25000, 20000, 1280, 25000 },           /* 2 half cycles, gain the rest */
		{ 0, 50, 0, 0, 39999, 30000, 1365, 39999 },
		{ 0, 60, 0, 0, 5000, 8333, 1024, 1e6 / 120 },         /* 1/120 s */
		{ 0, 60, 0, 0, 20000, 16667, 1228, 20000 },
		{ 0, 60, 0, 0, 1e9, 33333, 32768, 1e6 / 120 * 4 * 32 },   /* 4 half cycles fit in 40 ms */
		{ 0, 60, 8333, 0, 1e9, 8333, 32769, 1e6 / 120 * 32 }, /* stock's 8333 us is one */
		{ 0, 50, 15000, 0, 14000, 10000, 1433, 14000 },       /* a limit between 1 and 2 */
		{ 1, 50, 0, 0, 45000, 40000, 1152, 45000 },           /* night: 50 ms is 5 half cycles */
		{ 1, 50, 0, 0, 1e9, 50000, 32768, 1600000 },
		{ 1, 60, 0, 20000, 1e9, 16667, 32767, 1e6 / 120 * 2 * 32 },
	};
	assert(!mi_isp_gain_max(1, 1));                 /* ISP gain 1x: the AE as before it */
	for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
		uint32_t sh, gain, isp;
		double e = t[i].exp;
		night = t[i].night;
		assert(!mi_shutter_max(t[i].day_max, t[i].night_max) && !mi_antiflicker(1, t[i].hz));
		ae_split(&e, &sh, &gain, &isp);
		if (sh != (uint32_t)t[i].sh || gain != (uint32_t)t[i].gain || fabs(e - t[i].exp_after) > 0.01 || af_unusable ||
		    isp != 1024) {
			fprintf(stderr, "FAIL anti-flicker %u: sh %u gain %u exp %.2f\n", i, sh, gain, e);
			exit(1);
		}
	}
	ok("anti-flicker: whole half cycles (10000 / 8333 us), at least one, gain the rest, day and night");

	/* a limit under half a cycle: not applied (logged once), the AE as without it */
	uint32_t sh, gain, isp;
	double e = 4000;
	night = 0;
	assert(!mi_shutter_max(1000, 0) && !mi_antiflicker(1, 50));
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 1000 && gain == 4096 && e == 4000 && af_unusable == 1);
	e = 500;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 500 && gain == 1024 && af_unusable == 1);
	assert(!mi_shutter_max(0, 0));
	e = 500;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 10000 && e == 10000 && !af_unusable);
	/* off: as before */
	assert(!mi_antiflicker(0, 60));
	e = 25000;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 25000 && gain == 1024);
	ok("anti-flicker: a shutter limit under half a cycle can't apply (AE as without); off = as before");
}

static uint32_t u32_at(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* AE split with ISP gain: shutter, then sensor gain to 32x, then ISP gain to the mode's limit */
static void test_isp_gain(void)
{
	int d, n;
	cfg.isp_gain_day_max = cfg.isp_gain_night_max = 0;     /* unset in mi_cfg: 1x (rtspd sets 4 / 2) */
	mi_isp_gain_max_get(&d, &n);
	assert(d == 1 && n == 1);
	uint32_t sh0, gain0, isp0;
	double e0 = 1e9;
	cfg.fps = 25;
	night = 0;
	assert(!mi_shutter_max(0, 0) && !mi_antiflicker(0, 60));
	ae_split(&e0, &sh0, &gain0, &isp0);
	assert(sh0 == 40000 && gain0 == 32768 && isp0 == 1024 && e0 == 40000.0 * 32);
	assert(mi_isp_gain_max(0, 2) && mi_isp_gain_max(5, 2) && mi_isp_gain_max(4, 0) && mi_isp_gain_max(4, 5) &&
	       mi_isp_gain_max(-1, 2));
	assert(!mi_isp_gain_max(3, 1));
	mi_isp_gain_max_get(&d, &n);
	assert(d == 3 && n == 1);
	ok("ISP gain limits: 1..4 by day and at night, others refused; unset in mi_cfg = 1x (the AE as before)");

	cfg.fps = 25;
	assert(!mi_shutter_max(0, 0) && !mi_antiflicker(0, 60));
	struct { int night, day_x, night_x; double exp, sh, gain, isp, exp_after; } t[] = {
		{ 0, 4, 2, 1e9, 40000, 32768, 4096, 40000.0 * 32 * 4 },     /* day: up to 4x */
		{ 0, 4, 2, 40000.0 * 32 * 2, 40000, 32768, 2048, 40000.0 * 32 * 2 },
		{ 0, 4, 2, 40000.0 * 32 * 1.5, 40000, 32768, 1536, 40000.0 * 32 * 1.5 },
		{ 0, 4, 2, 40000.0 * 16, 40000, 16384, 1024, 40000.0 * 16 },   /* sensor gain first */
		{ 0, 4, 2, 40000.0 * 32, 40000, 32768, 1024, 40000.0 * 32 },   /* 32x: not yet ISP */
		{ 0, 4, 2, 30000, 30000, 1024, 1024, 30000 },                  /* shutter first */
		{ 1, 4, 2, 1e9, 50000, 32768, 2048, 50000.0 * 32 * 2 },        /* night: up to 2x */
		{ 1, 4, 2, 50000.0 * 32 * 1.25, 50000, 32768, 1280, 50000.0 * 32 * 1.25 },
		{ 0, 3, 4, 1e9, 40000, 32768, 3072, 40000.0 * 32 * 3 },        /* other limits */
		{ 1, 3, 4, 1e9, 50000, 32768, 4096, 50000.0 * 32 * 4 },
		{ 0, 1, 2, 1e9, 40000, 32768, 1024, 40000.0 * 32 },            /* 1x: as before */
		{ 1, 4, 1, 1e9, 50000, 32768, 1024, 50000.0 * 32 },
	};
	for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
		uint32_t sh, gain, isp;
		double e = t[i].exp;
		night = t[i].night;
		assert(!mi_isp_gain_max(t[i].day_x, t[i].night_x));
		ae_split(&e, &sh, &gain, &isp);
		if (sh != (uint32_t)t[i].sh || gain != (uint32_t)t[i].gain || isp != (uint32_t)t[i].isp ||
		    fabs(e - t[i].exp_after) > 0.01) {
			fprintf(stderr, "FAIL ISP gain %u: sh %u gain %u isp %u exp %.2f\n", i, sh, gain, isp, e);
			exit(1);
		}
	}
	ok("AE split with ISP gain: shutter, then sensor gain to 32x, then ISP gain to the mode's limit "
	   "(day 4x, night 2x, others; 1x = none)");

	/* with anti-flicker (60 Hz, a 1/120 s limit): ISP gain never past the limit despite the rounding */
	uint32_t sh, gain, isp;
	double e = 1e9;
	night = 0;
	assert(!mi_isp_gain_max(4, 2) && !mi_shutter_max(8333, 0) && !mi_antiflicker(1, 60));
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 8333 && gain == 32768 && isp == 4096);
	night = 1;                                      /* the same exposure at night: 2x */
	e = 1e9;
	assert(!mi_shutter_max(0, 20000));
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 16667 && gain == 32768 && isp == 2047);      /* 2 half cycles rounded up 0.3 us */
	assert(!mi_shutter_max(0, 0) && !mi_antiflicker(0, 60));
	night = 0;
	ok("ISP gain with anti-flicker: whole half cycles kept, ISP gain at most the limit");

	/* set_ae: IspGain at +0x10; the BV from the sensor gain as before (not the ISP gain) */
	memset(fg[F_AESET].data, 0, 58);
	assert(!set_ae(40000, 32768, 2048, 40));
	assert(u32_at(fg[F_AESET].data + 0x08) == 40000 && u32_at(fg[F_AESET].data + 0x0c) == 32768 &&
	       u32_at(fg[F_AESET].data + 0x10) == 2048);
	int32_t bv_isp, bv_1x;
	memcpy(&bv_isp, fg[F_AESET].data + 0x20, 4);
	assert(!set_ae(40000, 32768, 1024, 40));
	memcpy(&bv_1x, fg[F_AESET].data + 0x20, 4);
	assert(u32_at(fg[F_AESET].data + 0x10) == 1024 && bv_isp == bv_1x && bv_isp < 0);
	ok("set_ae: IspGain written at +0x10 (1024 = 1x); the BV as before (sensor gain only)");

	/* mi_ae_info: the total gain, so the day/night score (daynight.c: Y / (shutter s x gain / 1024))
	 * counts the ISP gain as exposure; with ISP 1x it is the sensor gain as before */
	double y;
	uint32_t s, g;
	struct mi_ae_state st;
	ae_last.valid = 0;
	assert(mi_ae_info(&y, &s, &g) == -1);
	cfg.ae_target = 40;
	assert(mi_ae_state(&st) == -1 && st.y == -1 && !st.shutter_us && !st.sensor_gain && !st.isp_gain && st.target == 40);
	ae_last.y = 40; ae_last.shutter_us = 40000; ae_last.gain = 32768; ae_last.isp = 1024; ae_last.valid = 1;
	assert(!mi_ae_info(&y, &s, &g) && y == 40 && s == 40000 && g == 32768);
	assert((int)(y / (s / 1e6 * (g / 1024.0))) == 31);
	ae_last.isp = 2048;
	assert(!mi_ae_info(&y, &s, &g) && g == 65536 && (int)(y / (s / 1e6 * (g / 1024.0))) == 15);
	assert(!mi_ae_state(&st) && st.y == 40 && st.shutter_us == 40000 && st.sensor_gain == 32768 &&
	       st.isp_gain == 2048 && st.target == 40);
	ae_last.valid = 0;
	ok("mi_ae_info: total gain (sensor x ISP), so the day/night score counts it; ISP 1x = as before; "
	   "mi_ae_state: sensor and ISP apart, the target");
}

/* image.exposure_night: the night AE target */
static void test_exposure_night(void)
{
	assert(mi_exposure_night_get() == MI_EXPOSURE_SAME);
	assert(mi_exposure_night(101) == -1 && mi_exposure_night(-2) == -1 && mi_exposure_night_get() == MI_EXPOSURE_SAME);
	assert(!mi_exposure_night(0) && !mi_exposure_night(100) && mi_exposure_night_get() == 100);
	/* before the IQ baselines: the base target, day and night (as image.exposure waits) */
	cfg.ae_target = 40;
	night = 1;
	assert(!mi_exposure_night(30) && ae_target() == 40);
	/* baselines in: by day image.exposure, at night image.exposure_night */
	img.ready = 1;
	img.ae_base = 40;
	night = 0;
	assert(ae_target() == 40);
	assert(!mi_night(1) && night);
	assert(fabs(ae_target() - 40 * pow(2.0, -20 / 25.0)) < 1e-9);          /* 30: ~23 */
	assert(!mi_image_set(MI_IMG_EXPOSURE, 75) && cfg.ae_target == 80);
	assert(fabs(ae_target() - 40 * pow(2.0, -20 / 25.0)) < 1e-9);          /* night unchanged */
	assert(!mi_night(0) && ae_target() == 80);                              /* day: image.exposure */
	assert(!mi_night(1) && !mi_exposure_night(MI_EXPOSURE_SAME) && ae_target() == 80);
	assert(!mi_exposure_night(0) && ae_target() == 10 && !mi_exposure_night(100) && ae_target() == 160);
	img.ae_base = 150;
	assert(ae_target() == 200);                                             /* clamped 4..200 */
	img.ae_base = 1;
	assert(!mi_exposure_night(0) && ae_target() == 4);
	img.ae_base = 40;
	assert(!mi_image_set(MI_IMG_EXPOSURE, 50) && !mi_night(0) && ae_target() == 40);
	/* the AE target follows a switch on its next step: mi_ae_state reports it */
	struct mi_ae_state st;
	assert(!mi_exposure_night(30) && !mi_night(1));
	mi_ae_state(&st);
	assert(fabs(st.target - 22.97) < 0.01);
	assert(!mi_night(0));
	mi_ae_state(&st);
	assert(st.target == 40);
	assert(!mi_exposure_night(MI_EXPOSURE_SAME));
	img.ready = 0;
	img.value[MI_IMG_EXPOSURE] = 50;
	ok("image.exposure_night: 0..100 or same as day; night target from it, day from image.exposure, "
	   "switching day/night switches the target; base before the IQ is in; clamped 4..200");
}

/* ---- stock night tuning ---- */
static char nt_dir[512];

/* An iq-dump-format file of n records {id, size, ret} with the data of the given fake groups (or
 * buf when the id has no fake group) */
static void nt_file(const char *name, char *path, size_t cap, const uint32_t (*rec)[3], int n, const uint8_t *const *data)
{
	snprintf(path, cap, "%s/%s", nt_dir, name);
	FILE *f = fopen(path, "wb");
	assert(f);
	for (int i = 0; i < n; i++) {
		assert(fwrite(rec[i], 4, 3, f) == 3);
		assert(fwrite(data[i], 1, rec[i][1], f) == rec[i][1]);
	}
	fclose(f);
}

/* the night versions: ColorToGray 1, a stronger 2D NR, darker brightness, softer sharpening, another
 * black level; Contrast the same as day (a group that's in the files but needs no write) */
static uint8_t nt_night[NFG][6200];
static const uint8_t blendn[16] = { 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 12 };
static const int nt_ids[] = { F_CTG, F_NR2D, F_BRI, F_CON, F_SHP, F_DBL };
enum { NT_N = sizeof nt_ids / sizeof nt_ids[0] };

static void nt_make_night(void)
{
	for (int k = 0; k < NFG; k++) memcpy(nt_night[k], fg[k].orig, fg[k].size);
	nt_night[F_CTG][0] = 1;
	for (int i = 0; i < 16; i++) nt_night[F_NR2D][0x0c + i * 0x56] = blendn[i];
	for (int i = 0; i < 17; i++) {
		uint32_t v = (uint32_t)(30 + i);
		memcpy(nt_night[F_BRI] + 8 + 4 * i, &v, 4);
	}
	for (int i = 0; i < 16; i++) nt_night[F_SHP][5708 + i] = (uint8_t)(100 + i);
	nt_night[F_SHP][6192] = 90;
	nt_night[F_DBL][100] ^= 0x55;
}

/* writes the good pair (night, day) and loads it */
static void nt_good(char *np, char *dp, size_t cap)
{
	uint32_t rec[NT_N][3];
	const uint8_t *nd[NT_N], *dd[NT_N];
	for (int i = 0; i < NT_N; i++) {
		int k = nt_ids[i];
		rec[i][0] = fg[k].id; rec[i][1] = fg[k].size; rec[i][2] = 0;
		nd[i] = nt_night[k];
		dd[i] = fg[k].orig;
	}
	nt_file("iq-night.bin", np, cap, (const uint32_t (*)[3])rec, NT_N, nd);
	nt_file("iq-day-switch.bin", dp, cap, (const uint32_t (*)[3])rec, NT_N, dd);
	nt_load(np, dp);
}

static void nt_reset(void)
{
	nt_free();
	memset(&tune, 0, sizeof tune);
	tune.value[MI_TUNE_NR2D] = tune.value[MI_TUNE_NR3D] = 128;
	memset(&img, 0, sizeof img);
	for (int w = 0; w < MI_IMG_COUNT; w++) img.value[w] = 50;
	night = 0;
	fake_groups();
	nt_make_night();
	iq_bad_size = 0;
	*iq_log = 0;
}

static int fake_is(int k, const uint8_t *want) { return !memcmp(fg[k].data, want, fg[k].size); }

/* group k as day or night data with sharpness value v applied to BranchStrength (as image_build) */
static void shp_want(uint8_t *g, const uint8_t *base, int v)
{
	memcpy(g, base, 6200);
	for (int i = 0; i < 16; i++) g[5708 + i] = (uint8_t)clampi(base[5708 + i] * v / 50, 0, 255);
	g[6192] = (uint8_t)clampi(base[6192] * v / 50, 0, 255);
}

static void test_night(void)
{
	char np[700], dp[700], bp[700];
	snprintf(nt_dir, sizeof nt_dir, "%s", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	cfg.ae_target = 40;

	/* file checks: every record against iq_groups.h; both files the same ids in the same order */
	nt_reset();
	nt_good(np, dp, sizeof np);
	assert(nt.loaded && nt.n == NT_N && nt.id[0] == 4100 && nt.size[4] == 6200);
	static uint8_t zero[32768];
	struct { const char *what; uint32_t rec[2][3]; int day_same; } bad[] = {
		{ "an AE group (AETarget 5127)", { { 4100, 4, 0 }, { 5127, 132, 0 } }, 1 },
		{ "AdaptiveGamma 4150 (AE page)", { { 4100, 4, 0 }, { 4150, 1028, 0 } }, 1 },
		{ "a size iq_groups.h doesn't give", { { 4100, 4, 0 }, { 4110, 2631, 0 } }, 1 },
		{ "an info group (CCMInfo 4140)", { { 4100, 4, 0 }, { 4140, 28, 0 } }, 1 },
		{ "Temperature 4152", { { 4100, 4, 0 }, { 4152, 264, 0 } }, 1 },
		{ "Dummy 4147", { { 4100, 4, 0 }, { 4147, 26192, 0 } }, 1 },
		{ "an id iq_groups.h doesn't list", { { 4100, 4, 0 }, { 4099, 4, 0 } }, 1 },
		{ "a record with ret != 0", { { 4100, 4, 0 }, { 4110, 2632, (uint32_t)-1 } }, 1 },
		{ "an id twice", { { 4100, 4, 0 }, { 4100, 4, 0 } }, 1 },
		{ "day ids in another order", { { 4100, 4, 0 }, { 4110, 2632, 0 } }, 0 },
	};
	const uint8_t *zd[2] = { zero, zero };
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		nt_reset();
		nt_file("bad-night.bin", np, sizeof np, (const uint32_t (*)[3])bad[i].rec, 2, zd);
		uint32_t swapped[2][3] = { { bad[i].rec[1][0], bad[i].rec[1][1], 0 }, { bad[i].rec[0][0], bad[i].rec[0][1], 0 } };
		nt_file("bad-day.bin", dp, sizeof dp, bad[i].day_same ? (const uint32_t (*)[3])bad[i].rec :
			(const uint32_t (*)[3])swapped, 2, zd);
		nt_load(np, dp);
		if (nt.loaded) { fprintf(stderr, "FAIL night file with %s loaded\n", bad[i].what); exit(1); }
		assert(!nt.file[0] && !nt.file[1] && mi_night_tuning(1) == -1 && !mi_night_tuning_get());
	}
	/* truncated: the last record cut short; and a day file with a record less */
	nt_reset();
	nt_good(np, dp, sizeof np);
	FILE *f = fopen(np, "r+b");
	assert(f && !ftruncate(fileno(f), 12 + 4 + 12 + 1476 + 5));
	fclose(f);
	nt_load(np, dp);
	assert(!nt.loaded);
	nt_reset();
	uint32_t one[1][3] = { { 4100, 4, 0 } }, two[2][3] = { { 4100, 4, 0 }, { 4111, 1476, 0 } };
	nt_file("short-night.bin", np, sizeof np, (const uint32_t (*)[3])two, 2, zd);
	nt_file("short-day.bin", dp, sizeof dp, (const uint32_t (*)[3])one, 1, zd);
	nt_load(np, dp);
	assert(!nt.loaded);
	snprintf(bp, sizeof bp, "%s/does-not-exist.bin", nt_dir);
	nt_load(bp, dp);
	assert(!nt.loaded);
	ok("night tuning files: AE/info/Temperature/Dummy/unknown ids, wrong sizes, errors, duplicates, "
	   "another day order, truncated, a record less, missing: refused (night tuning unavailable)");

	/* baselines per mode: day from the ISP, night from the night file (else the day one) */
	nt_reset();
	nt_good(np, dp, sizeof np);
	image_ready();
	assert(img.ready && tune.ready && !nt.live);
	assert(!memcmp(img.bri[0], fg[F_BRI].orig, 76) && !memcmp(img.bri[1], nt_night[F_BRI], 76));
	assert(!memcmp(img.shp[1], nt_night[F_SHP], 6200) && !memcmp(img.sat[1], img.sat[0], 416));
	for (int i = 0; i < 16; i++)
		assert(tune.base[0][TG_NR2D][i] == blend0[i] && tune.base[1][TG_NR2D][i] == blendn[i] &&
		       tune.base[1][TG_NR3D][i] == mdgain0[i] && tune.ok[1][TG_NR2D] && tune.ok[1][TG_NR3D]);
	ok("baselines: day read from the ISP; night from iq-night.bin, the day one where it has no group");

	/* night tuning off (the default): exactly as before, only ColorToGray */
	*iq_log = 0;
	assert(!mi_night(1) && !strcmp(iq_log, "s4100/4;") && fg[F_CTG].data[0] == 1);
	*iq_log = 0;
	assert(!mi_night(0) && !strcmp(iq_log, "s4100/4;") && !mi_night_day() && !strcmp(iq_log, "s4100/4;"));
	for (int k = 0; k < NFG; k++) assert(fake_is(k, fg[k].orig));
	assert(!mi_night_tuning_get());
	ok("night tuning off: a switch writes ColorToGray only, as before");

	/* on by day: nothing yet. Night: each group read, the differing ones written, file order, exact sizes */
	*iq_log = 0;
	assert(!mi_night_tuning(1) && mi_night_tuning_get() == 1 && !*iq_log);
	assert(mi_night_tuning(2) == -1);
	assert(!mi_night(1) && nt.live && night);
	assert(!strcmp(iq_log, "g4100/4;s4100/4;g4111/1476;s4111/1476;g4102/76;s4102/76;g4101/76;"
		       "g4114/6200;s4114/6200;g4167/1436;s4167/1436;"));
	for (int i = 0; i < NT_N; i++) assert(fake_is(nt_ids[i], nt_night[nt_ids[i]]));
	assert(fake_is(F_NR3D, fg[F_NR3D].orig) && fake_is(F_WDR, fg[F_WDR].orig) && fake_is(F_SAT, fg[F_SAT].orig));
	assert(!iq_bad_size);
	ok("night: ColorToGray with the night groups; each read, only the differing written (Contrast not), "
	   "file order, exact sizes; the others untouched");

	/* at night a slider scales the night baseline, the ISP tuning too */
	static uint8_t want[6200];
	*iq_log = 0;
	assert(!mi_image_set(MI_IMG_SHARPNESS, 100) && !strcmp(iq_log, "s4114/6200;"));
	shp_want(want, nt_night[F_SHP], 100);
	assert(fake_is(F_SHP, want) && fg[F_SHP].data[5708] == 200 && fg[F_SHP].data[6192] == 180);
	assert(!mi_tune_set(MI_TUNE_NR2D, 255));
	for (int i = 0; i < 16; i++)
		assert(fg[F_NR2D].data[0x0c + i * 0x56] == (blendn[i] * 255u / 128 > 16 ? 16 : blendn[i] * 255u / 128));
	assert(fg[F_NR2D].data[0x0c + 15 * 0x56] == 16 && fg[F_NR2D].data[0x0c + 3 * 0x56] == 1 && only_fields(F_NR2D));
	assert(!mi_tune_set(MI_TUNE_NR3D, 64));         /* not in the night set: the day baseline */
	for (int i = 0; i < 16; i++) assert(mdgain(i) == mdgain0[i] * 64u / 128);
	ok("at night: sharpness scales the night baseline; 2D NR the night BlendRatio; 3D NR (no night "
	   "group) the day one");

	/* to day: ColorToGray only; the night groups stay (and a slider still scales night) until
	 * mi_night_day, which writes the day versions with the user's values applied to day baselines */
	*iq_log = 0;
	assert(!mi_night(0) && !strcmp(iq_log, "s4100/4;") && nt.live && !night);
	assert(!mi_image_set(MI_IMG_SHARPNESS, 90));
	shp_want(want, nt_night[F_SHP], 90);
	assert(fake_is(F_SHP, want));
	*iq_log = 0;
	assert(!mi_night_day() && !nt.live);
	assert(!strcmp(iq_log, "g4100/4;g4111/1476;s4111/1476;g4102/76;s4102/76;g4101/76;g4114/6200;s4114/6200;"
		       "g4167/1436;s4167/1436;"));
	shp_want(want, fg[F_SHP].orig, 90);
	assert(fake_is(F_SHP, want) && fake_is(F_BRI, fg[F_BRI].orig) && fake_is(F_DBL, fg[F_DBL].orig) &&
	       fg[F_CTG].data[0] == 0);
	for (int i = 0; i < 16; i++)
		assert(fg[F_NR2D].data[0x0c + i * 0x56] == (blend0[i] * 255u / 128 > 16 ? 16 : blend0[i] * 255u / 128));
	assert(only_fields(F_NR2D));
	*iq_log = 0;
	assert(!mi_night_day() && !*iq_log);            /* nothing left to restore */
	assert(!mi_image_set(MI_IMG_SHARPNESS, 50));
	assert(fake_is(F_SHP, fg[F_SHP].orig));
	assert(!mi_tune_set(MI_TUNE_NR2D, 128) && !mi_tune_set(MI_TUNE_NR3D, 128));
	for (int k = 0; k < NFG; k++) assert(fake_is(k, fg[k].orig));
	ok("to day: ColorToGray 0 first, night groups kept until mi_night_day; then the day versions "
	   "(only the differing), sliders and NR against the day baselines; all back to the profile");

	/* live switch of the setting at night: off restores day groups at once (B/W stays), on writes night */
	assert(!mi_night(1) && nt.live);
	*iq_log = 0;
	assert(!mi_night_tuning(0) && !nt.live && !mi_night_tuning_get() && fg[F_CTG].data[0] == 1);
	for (int k = 0; k < NFG; k++) assert(k == F_CTG || fake_is(k, fg[k].orig));
	assert(strstr(iq_log, "g4100/4;g4111") == iq_log);          /* ColorToGray read, kept at 1 */
	assert(!mi_night_tuning(1) && nt.live);
	for (int i = 0; i < NT_N; i++) assert(fake_is(nt_ids[i], nt_night[nt_ids[i]]));
	*iq_log = 0;
	assert(!mi_night(1) && !strcmp(iq_log, "g4100/4;g4111/1476;g4102/76;g4101/76;g4114/6200;g4167/1436;"));
	ok("image.night_tuning live at night: off writes the day groups back at once (B/W kept), on the "
	   "night ones; again: read, nothing written");

	/* a failing write is reported; a group that can't be read is written (it can't be compared) */
	assert(!mi_night(0) && !mi_night_day());
	fg[F_DBL].fail_set = 1;
	assert(mi_night(1) == -1);
	fg[F_DBL].fail_set = 0;
	fg[F_SHP].fail_get = 1;
	*iq_log = 0;
	assert(!mi_night(0) && !mi_night_day() && strstr(iq_log, "g4114/6200;s4114/6200;"));
	fg[F_SHP].fail_get = 0;
	ok("a failing write reported; an unreadable group written");

	/* start-up at night: ColorToGray when the image controls are in, the night groups only after the
	 * ISP tuning's day baselines were read (never from night groups) */
	nt_reset();
	nt_good(np, dp, sizeof np);
	assert(!mi_night_tuning(1) && !mi_night(1) && !*iq_log);
	image_ready();
	assert(nt.live && strstr(iq_log, "g4114/6200;s4100/4;g4111/1476;g4110/2632;g4118/1036;g4111/1476;g4110/2632;"
				 "g4118/1036;g4100/4;g4111/1476;s4111/1476;"));
	for (int i = 0; i < 16; i++) assert(tune.base[0][TG_NR2D][i] == blend0[i]);
	for (int i = 0; i < NT_N; i++) assert(fake_is(nt_ids[i], nt_night[nt_ids[i]]));
	ok("start-up at night: day baselines first, then the night groups");

	/* a set without ColorToGray: mi_night still writes it */
	nt_reset();
	uint32_t r1[1][3] = { { 4167, 1436, 0 } };
	const uint8_t *n1[1] = { nt_night[F_DBL] }, *d1[1] = { fg[F_DBL].orig };
	nt_file("n1.bin", np, sizeof np, (const uint32_t (*)[3])r1, 1, n1);
	nt_file("d1.bin", dp, sizeof dp, (const uint32_t (*)[3])r1, 1, d1);
	nt_load(np, dp);
	image_ready();
	assert(!mi_night_tuning(1));
	*iq_log = 0;
	assert(!mi_night(1) && !strcmp(iq_log, "g4167/1436;s4167/1436;s4100/4;"));
	nt_free();
	ok("a night set without ColorToGray: written as before after the night groups");
}

int main(void)
{
	int m, f;
	/* before mi_start: remembered, no ioctl */
	assert(fd_snr < 0 && !mi_orient(1, 1) && calls == 0);
	mi_orient_get(&m, &f);
	assert(m == 1 && f == 1);
	assert(mi_orient(2, 0) && mi_orient(0, -1));
	ok("orientation before start: remembered, nothing sent; 0/1 only");

	/* started: SetOrien {pad 0, mirror, flip, 0, 0} with request 0x4008690c */
	fd_snr = FAKE_SNR;
	assert(!mi_orient(1, 0) && set_calls == 1 && last_req == 0x4008690cUL);
	static const uint8_t want[8] = { 0, 0, 0, 0, 1, 0, 0, 0 };
	assert(!memcmp(last_arg, want, 8) && sensor_m == 1 && sensor_f == 0);
	assert(orient_checks == ORIENT_CHECKS);
	orient_poll();                                  /* reads back at once: done */
	assert(last_req == 0xc008690dUL && orient_checks == 0);
	ok("SetOrien 0x4008690c {pad 0, mirror 1, flip 0}; GetOrien 0xc008690d read back");

	/* the sensor takes a few frames: read-back retried, never blocking, then stops */
	lag = 3;
	int before = calls;
	assert(!mi_orient(0, 1) && set_calls == 2);
	for (int i = 0; i < 2; i++) { orient_poll(); assert(orient_checks == ORIENT_CHECKS - 1 - i); }
	orient_poll();
	assert(orient_checks == 0 && sensor_m == 0 && sensor_f == 1 && calls == before + 4);
	lag = 100;                                      /* never applied: 10 reads, then gives up */
	assert(!mi_orient(1, 1));
	for (int i = 0; i < 15; i++) orient_poll();
	assert(orient_checks == 0 && calls == before + 4 + 1 + ORIENT_CHECKS);
	lag = 0;
	fd_snr = 7;                                     /* SetOrien failing (not the sensor fd here) */
	assert(mi_orient(0, 0) == -1);
	fd_snr = -1;
	ok("read-back retried up to 10 times without blocking; a failing SetOrien reported");

	/* MI_SNR_SetFps (stock Vif::Init step 10): request 0x40086905, {pad 0, cfg.fps}, once when it
	 * works; retried up to 5 times; giving up isn't fatal to the caller (mi_start goes on) */
	fd_snr = FAKE_SNR;
	cfg.fps = 25;
	int c0 = calls;
	assert(!snr_set_fps() && fps_calls == 1 && calls == c0 + 1 && last_req == 0x40086905UL);
	assert(fps_pad == 0 && fps_set == 25);
	cfg.fps = 30;
	fps_calls = 0;
	fps_fail = 3;
	assert(!snr_set_fps() && fps_calls == 4 && fps_set == 30);
	fps_calls = 0;
	fps_fail = 100;
	assert(snr_set_fps() == -1 && fps_calls == SNR_FPS_TRIES && SNR_FPS_TRIES == 5);
	fps_fail = 0;
	fd_snr = -1;
	ok("SetFps 0x40086905 {pad 0, fps} once; 3 failures -> 4 tries; at most 5 tries, then -1");

	/* shutter limits: ranges */
	uint32_t d, n;
	assert(!mi_shutter_max(0, 0) && !mi_shutter_max(100, 100) && !mi_shutter_max(1000000, 50000));
	assert(mi_shutter_max(99, 0) && mi_shutter_max(0, 99) && mi_shutter_max(1000001, 0) && mi_shutter_max(0, 50001));
	mi_shutter_max_get(&d, &n);
	assert(d == 1000000 && n == 50000);
	ok("shutter limits: 0 or 100..1000000 (day), 0 or 100..50000 (night)");

	/* AE split at 25 fps: shutter up to the limit, then gain up to 32x (ISP gain 1x: as before it) */
	uint32_t sh, gain, isp;
	double e;
	cfg.fps = 25;
	assert(!mi_isp_gain_max(1, 1));
	struct { int night; uint32_t day_max, night_max; double exp, sh, gain_x, exp_after; } t[] = {
		{ 0, 0, 0, 1e9, 40000, 32, 1280000 },           /* day auto: one frame time */
		{ 0, 0, 0, 10000, 10000, 1, 10000 },            /* bright: shutter only */
		{ 0, 1000, 0, 1e9, 1000, 32, 32000 },           /* day 1/1000 s */
		{ 0, 1000, 0, 4000, 1000, 4, 4000 },            /* ... the rest is gain */
		{ 0, 100, 0, 50, 50, 1, 50 },                   /* below the limit: as wanted */
		{ 0, 1000000, 0, 1e9, 40000, 32, 1280000 },     /* longer than a frame: a frame */
		{ 1, 0, 0, 1e9, 50000, 32, 1600000 },           /* night auto: stock's 50 ms */
		{ 1, 1000, 20000, 1e9, 20000, 32, 640000 },     /* night 1/50 s */
		{ 1, 0, 40000, 30000, 30000, 1, 30000 },        /* night 1/25 s, not reached */
		{ 0, 0, 0, 5, 20, 1, 20 },                      /* floor 20 us */
	};
	for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
		night = t[i].night;
		assert(!mi_shutter_max(t[i].day_max, t[i].night_max));
		e = t[i].exp;
		ae_split(&e, &sh, &gain, &isp);
		if (sh != (uint32_t)t[i].sh || gain != (uint32_t)(t[i].gain_x * 1024) || e != t[i].exp_after || isp != 1024) {
			fprintf(stderr, "FAIL ae_split %u: sh %u gain %u exp %.0f\n", i, sh, gain, e);
			return 1;
		}
	}
	cfg.fps = 10;                                   /* 100 ms frames: day auto 1/10 s */
	night = 0;
	mi_shutter_max(0, 0);
	e = 1e9;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 100000);
	night = 1;                                      /* night stays at 50 ms */
	e = 1e9;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 50000);
	cfg.fps = 30;                                   /* the default since 2026-10-25: 1/30 s by day */
	night = 0;
	e = 1e9;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 33333 && gain == 32 * 1024);
	night = 1;                                      /* night: still stock's 50 ms */
	e = 1e9;
	ae_split(&e, &sh, &gain, &isp);
	assert(sh == 50000);
	ok("AE split: shutter capped at the day/night limit (auto: a frame / 50 ms; 33333 us at 30 fps), then gain to 32x");
	test_antiflicker();
	test_isp_gain();
	test_exposure_night();
	test_tune();
	test_night();
	printf("ALL OK\n");
	return 0;
}
