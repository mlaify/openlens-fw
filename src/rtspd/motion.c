/* SPDX-License-Identifier: MIT */
/*
 * motion.c: motion detection (#77) from the ISP's 32x32 AE luma grid, which our AE already reads
 * (mi_ae_grid). No extra hardware work: one 1 KiB grid at most 5 times a second.
 *
 * Each cell keeps a slow background (EMA). A grid is first scaled to the background's overall
 * brightness, so the AE stepping, a cloud or the day/night switch doesn't look like motion; a
 * frame whose overall brightness jumps by more than 25 % only re-learns the background. A cell
 * counts as changed when it differs from its background by more than a sensitivity-scaled share
 * of it (with a floor for dark cells). Motion starts when enough cells changed in 2 of the last 3
 * evaluations, and ends after 5 s without. Each cell also learns how much it usually changes
 * (wind in bushes, water): it counts only when the change is also 3x that, so a swaying bush
 * stops holding motion on while a still area stays as sensitive. Each cell is ~80x45 px of the 2560x1440 picture, so a
 * person a few metres away covers several cells.
 */
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mi.h"
#include "motion.h"

#ifndef LOG
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#endif

#define CELLS_MAX 1024
#define EVAL_MS 200                     /* at most 5 evaluations a second */
#define HOLD_MS 5000                    /* motion ends after this long without */
#define LEARN_EVALS 10                  /* evaluations to settle a fresh background */

static struct motion_cfg cfg = MOTION_CFG_DEFAULT;
static uint8_t mask[CELLS_MAX / 8];
static int mask_set;                    /* 0: every cell counts (the default) */

static int mask_on(unsigned i) { return !mask_set || (mask[i / 8] >> (7 - i % 8) & 1); }

int motion_set_mask(const char *hex)
{
	uint8_t m[CELLS_MAX / 8];
	if (strlen(hex) != MOTION_MASK_HEX) return -1;
	for (unsigned i = 0; i < sizeof m; i++) {
		unsigned v;
		if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1]) ||
		    sscanf(hex + 2 * i, "%2x", &v) != 1)
			return -1;
		m[i] = (uint8_t)v;
	}
	memcpy(mask, m, sizeof mask);
	mask_set = 1;
	return 0;
}

void motion_get_mask(char out[MOTION_MASK_HEX + 1])
{
	for (unsigned i = 0; i < sizeof mask; i++) snprintf(out + 2 * i, 3, "%02x", mask_set ? mask[i] : 0xff);
}
static float bg[CELLS_MAX];
static float dev[CELLS_MAX];            /* each cell's usual change: an EMA of |grid - background| */
#define DEV_K 3                         /* a cell counts above DEV_K x its usual change */
#define DEV_RATE 0.03                   /* ~7 s at 5 evaluations a second (0.2 while learning) */
static unsigned ncells, last_seq, seq_rise;
static int state, have_bg, learn, hist, cells_last, need;
static long long last_eval, last_hit, since;
#define RECENT 10                       /* evaluations kept for the peak: 2 s */
static int recent[RECENT];
static unsigned recent_i;
/* the last evaluation, for motion_map(): each cell's luma and change against its background */
static uint8_t ylast[CELLS_MAX], pct[CELLS_MAX], hit[CELLS_MAX];
static unsigned last_w, last_h;
static double last_mean, last_bmean, last_share;
static int last_jump;

void motion_set(const struct motion_cfg *c) { cfg = *c; if (!cfg.enabled) state = 0; }
const struct motion_cfg *motion_get(void) { return &cfg; }
int motion_cells(void) { return cells_last; }
int motion_need(void) { return need; }
int motion_peak(void)
{
	int p = 0;
	for (unsigned i = 0; i < RECENT; i++) if (recent[i] > p) p = recent[i];
	return p;
}

int motion_map(char *out, size_t cap, int mode)
{
	int n = snprintf(out, cap, "motion.map=%s %ux%u mean=%.1f bg=%.1f jump=%d learn=%d share=%.0f%%\n",
			 mode == 1 ? "luma/16" : mode == 2 ? "noise/10%" : "change/10%", last_w, last_h, last_mean,
			 last_bmean, last_jump, learn, last_share * 100);
	for (unsigned r = 0; r < last_h && n > 0 && (size_t)n < cap; r++) {
		for (unsigned c = 0; c < last_w && (size_t)n + 1 < cap; c++) {
			unsigned i = r * last_w + c;
			unsigned q = mode == 2 ? (bg[i] > 0.5 ? (unsigned)(100 * dev[i] / bg[i]) : 0) : pct[i];
			out[n++] = !mask_on(i) ? '-' : mode == 1 ? "0123456789abcdef"[ylast[i] >> 4] :
				   mode == 0 && hit[i] ? '#' : q >= 100 ? '+' : (char)('0' + q / 10);
		}
		if ((size_t)n + 1 < cap) out[n++] = '\n';
	}
	if (n < 0 || (size_t)n + 4 > cap) return -1;
	memcpy(out + n, "ok\n", 4);
	return 0;
}

int motion_state(unsigned *seq, long long *since_ms)
{
	if (seq) *seq = seq_rise;
	if (since_ms) *since_ms = since;
	return state;
}

static void set_state(int s, long long now, int cells)
{
	if (s == state) return;
	state = s;
	since = now;
	if (s) {
		seq_rise++;
		LOG("motion: start (%d cells changed)\n", cells);
	} else {
		LOG("motion: end\n");
	}
}

void motion_tick(long long now)
{
	static uint8_t y[CELLS_MAX];
	unsigned w, h;
	if (!since) since = now;
	if (now - last_eval < EVAL_MS) return;
	unsigned g = mi_ae_grid(y, sizeof y, &w, &h);
	if (!g || g == last_seq) return;
	last_seq = g;
	last_eval = now;
	if (!cfg.enabled) { set_state(0, now, 0); have_bg = 0; return; }
	unsigned n = w * h;
	double mean = 0, bmean = 0;
	for (unsigned i = 0; i < n; i++) mean += y[i];
	mean /= n;
	if (!have_bg || n != ncells) {                          /* first grid: start learning */
		for (unsigned i = 0; i < n; i++) { bg[i] = y[i]; dev[i] = 0; }
		ncells = n;
		have_bg = 1;
		learn = LEARN_EVALS;
		return;
	}
	for (unsigned i = 0; i < n; i++) bmean += bg[i];
	bmean /= n;
	double scale = mean > 0.5 ? bmean / mean : 1;
	int jump = scale > 1.25 || scale < 0.8;                 /* global change: relearn only */
	/* sensitivity 0..100 -> per-cell change 25 %..3 %, area 0.6 %..0.1 % of the active cells (at 50:
	 * 14 % in ~4 of 1024 cells; the first tuning, 26 % in 9, missed a person walking past on
	 * cam #2, 2026-10-23) */
	unsigned active = 0;
	for (unsigned i = 0; i < n; i++) active += mask_on(i);
	double share = 0.25 - 0.0022 * cfg.sensitivity;
	unsigned area = (unsigned)lround(active * (0.006 - 0.00005 * cfg.sensitivity));
	if (area < 2) area = 2;
	if (area > active && active) area = active;            /* a small area can still trigger */
	need = (int)area;
	int changed = 0;
	for (unsigned i = 0; i < n; i++) {
		double v = y[i] * scale, d = fabs(v - bg[i]), lim = bg[i] * share;
		if (lim < 3) lim = 3;
		if (lim < DEV_K * dev[i]) lim = DEV_K * dev[i];
		int c = !jump && d > lim && mask_on(i);           /* masked-out cells never count */
		if (!jump) dev[i] += (float)((d - dev[i]) * (learn ? 0.2 : DEV_RATE));
		changed += c;
		ylast[i] = y[i];
		double p = bg[i] > 0.5 ? 100 * d / bg[i] : d ? 255 : 0;
		pct[i] = (uint8_t)(p > 255 ? 255 : p);
		hit[i] = (uint8_t)c;
		/* a jump relearns from the grid as it is: the scaled grid has the background's mean by
		 * construction, so relearning from it kept a background learned before AE settled
		 * (cam #2: bg 220 vs picture 40, jump forever, 2026-10-23) */
		bg[i] += (float)(c ? (v - bg[i]) * 0.01 : jump ? (y[i] - bg[i]) * 0.5 : (v - bg[i]) * 0.05);
	}
	cells_last = changed;
	recent[recent_i++ % RECENT] = changed;
	last_w = w; last_h = h; last_mean = mean; last_bmean = bmean; last_jump = jump; last_share = share;
	if (learn) { learn--; return; }
	if (!active) return;                                    /* everything masked out */
	hist = (hist << 1 | ((unsigned)changed >= area)) & 7;
	int votes = (hist & 1) + (hist >> 1 & 1) + (hist >> 2 & 1);
	if (votes >= 2) { last_hit = now; set_state(1, now, changed); }
	else if (state && now - last_hit > HOLD_MS) set_state(0, now, 0);
}
