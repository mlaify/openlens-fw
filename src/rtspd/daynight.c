/* SPDX-License-Identifier: MIT */
/*
 * daynight.c: day/night switching (#30), the way stock media_server does it (static analysis of
 * FUN_0003ff58 / FUN_0003ffd8 / FUN_0003feb4 and the 2026-10-23 night watch on cam #2):
 *   - light: read 4 bytes from /dev/irled, 1 = day, 2 = night; inverted on some product types,
 *     and on MCA40E (cam #2 read 1 while stock was in night mode);
 *   - IR-cut: write one byte to /dev/irled, 1 = day, 0 = night. The kernel driver drives the
 *     H-bridge (GPIO 11/80); we never touch GPIOs (GPIO 30 is the core-voltage control);
 *   - IR LEDs: PWM4 at 20 kHz (period 50000 ns), stock night duty 48000 (96 %);
 *   - picture: black and white and a longer shutter limit (mi_night); with stock night tuning on
 *     (image.night_tuning), also the night IQ groups, in stock's order around the IR-cut (apply).
 * The status is debounced (DN_HOLD seconds the same) so a passing light doesn't flip it.
 *
 * On MCA40E the /dev/irled status isn't a light reading (it read 0 in daylight and under a cover,
 * 2026-10-23), so auto follows the picture by default, like stock's "by image" path
 * (ircut_active_by_image: exposure LV, night < 0.6, day >= 2.7, a 600 s hold-off after 3
 * switches). The score is mean Y / (shutter s x gain): stock's night picture with IR on scored
 * ~170 (cam #2: 50 ms, 4.2x, Y 36), ours at dawn without IR ~8 (40 ms, 32x, Y 10), daylight
 * ~10^4..10^5. Night below night_below (15), day above day_above (1500): far above what the IR
 * LEDs alone give, so switching the IR doesn't switch back. The gain is the AE's total gain,
 * sensor x ISP (mi_ae_info): the scores above were taken with ISP gain 1x, and our AE only raises
 * the ISP gain once the shutter is at its limit and the sensor gain at 32x, so the thresholds keep
 * their meaning; in such a dark scene the score goes on falling with the exposure instead of
 * stopping at the sensor's limit.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daynight.h"
#include "mi.h"

#ifndef LOG
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#endif

#define DN_HOLD 5                       /* seconds of the same reading before switching */
#define PWM_PERIOD 50000                /* ns: 20 kHz, as stock */

#define DN_FLAP_N 3                     /* this many switches ... */
#define DN_FLAP_WINDOW 600              /* ... within this many seconds ... */
#define DN_FLAP_HOLD 600                /* ... hold the state this long (stock: 600 s) */

static struct dn_cfg cfg = DN_CFG_DEFAULT;
static const char *pwm_dir;
static int fd = -1, state, cand, streak, raw = -1, score = -1;
static long ticks, switched[DN_FLAP_N], hold_until;     /* in dn_tick calls (seconds) */

static void ir_leds(int pct);

void dn_set(const struct dn_cfg *c)
{
	int irled_changed = c->irled != cfg.irled;
	if (c->mode != cfg.mode) {                      /* a manual change starts the history afresh */
		memset(switched, 0, sizeof switched);
		hold_until = 0;
	}
	cfg = *c;
	/* the IR LED level applies live at night, not only at the next switch (cam #2, 2026-10-24:
	 * "set daynight.irled 10" left the duty at 48000) */
	if (irled_changed && state == DN_NIGHT && pwm_dir) ir_leds(cfg.irled);
}
const struct dn_cfg *dn_get(void) { return &cfg; }
int dn_state(void) { return state; }
int dn_raw(void) { return raw; }
int dn_score(void) { return score; }

/* The picture's brightness: DN_DAY / DN_NIGHT once a threshold is crossed, the current state in
 * between (hysteresis), 0 before the AE has run. */
static int image(void)
{
	double y;
	uint32_t sh, gain;
	if (mi_ae_info(&y, &sh, &gain) || !sh || !gain) return 0;
	double s = y / (sh / 1e6 * (gain / 1024.0));
	score = s > 1e6 ? 1000000 : (int)s;
	if (s < cfg.night_below) return DN_NIGHT;
	if (s > cfg.day_above) return DN_DAY;
	return state ? state : DN_DAY;
}

static int put(const char *name, long v)
{
	char path[160], buf[24];
	snprintf(path, sizeof path, "%s/%s", pwm_dir, name);
	int f = open(path, O_WRONLY | O_TRUNC);       /* sysfs ignores O_TRUNC; the host test needs it */
	if (f < 0) return -1;
	int n = snprintf(buf, sizeof buf, "%ld", v);
	int r = write(f, buf, (size_t)n) == n ? 0 : -1;
	close(f);
	return r;
}

/* IR LEDs: duty % of the 20 kHz period on pwm0 of the chip (exported if it isn't yet). */
static void ir_leds(int pct)
{
	char path[160];
	struct stat st;
	snprintf(path, sizeof path, "%s/pwm0", pwm_dir);
	if (stat(path, &st)) {
		int f;
		snprintf(path, sizeof path, "%s/export", pwm_dir);
		if ((f = open(path, O_WRONLY)) >= 0) {
			if (write(f, "0", 1) != 1) LOG("daynight: pwm export: %s\n", strerror(errno));
			close(f);
		}
	}
	if (put("pwm0/period", PWM_PERIOD) || put("pwm0/duty_cycle", (long)PWM_PERIOD * pct / 100) ||
	    put("pwm0/enable", 1))
		LOG("daynight: IR LED pwm (%s) not set\n", pwm_dir);
}

static void ircut(int night)
{
	if (fd >= 0) {
		unsigned char b = night ? 0 : 1;
		/* stock ignores the return value; the driver doesn't report 1 for its byte (first chroot
		 * run, 2026-10-23), so only a real error is worth a line */
		if (write(fd, &b, 1) < 0) LOG("daynight: IR-cut write: %s\n", strerror(errno));
	} else {
		/* no device: the picture and the IR LEDs switch, the filter doesn't (cam #2's dark IR
		 * nights before rcS made /dev/irled, 2026-10-24) */
		LOG("daynight: IR-cut NOT moved: no IR-cut device\n");
	}
}

/* With stock night tuning on (mi_night_tuning_get), a switch runs in stock's order, its second half
 * on the next dn_tick (a second later; stock sleeps 1 s there):
 *   to night: IR LEDs on, night groups + B/W (mi_night 1) | IR-cut out;
 *   to day:   IR LEDs off, colour (mi_night 0), IR-cut in  | day groups (mi_night_day).
 * Without it, everything at once as before: IR-cut, IR LEDs, B/W. */
enum { PEND_NONE, PEND_IRCUT_NIGHT, PEND_DAY_GROUPS };
static int pending;

static void finish_pending(void)
{
	if (pending == PEND_IRCUT_NIGHT) {
		ircut(1);
		if (fd >= 0) LOG("daynight: IR-cut out\n");
	} else if (pending == PEND_DAY_GROUPS && mi_night_day()) {
		LOG("daynight: day tuning not fully restored\n");
	}
	pending = PEND_NONE;
}

static void apply(int night)
{
	int staged = mi_night_tuning_get();
	if (!staged) {
		ircut(night);
		ir_leds(night ? cfg.irled : 0);
		if (mi_night(night)) LOG("daynight: B/W switch failed\n");
	} else if (night) {
		ir_leds(cfg.irled);
		if (mi_night(1)) LOG("daynight: B/W / night tuning switch failed\n");
		pending = PEND_IRCUT_NIGHT;
	} else {
		ir_leds(0);
		if (mi_night(0)) LOG("daynight: B/W switch failed\n");
		ircut(0);
		pending = PEND_DAY_GROUPS;
	}
	state = night ? DN_NIGHT : DN_DAY;
	LOG("daynight: %s (%s)\n", !staged ? (night ? "NIGHT: IR-cut out, IR LEDs on, B/W" : "DAY: IR-cut in, IR LEDs off, colour") :
	    night ? "NIGHT: IR LEDs on, B/W, stock night tuning; IR-cut out next second" :
	    "DAY: IR LEDs off, colour, IR-cut in; day tuning next second", cfg.mode == DN_AUTO ? "auto" : "forced");
}

/* The driver's light status: DN_DAY, DN_NIGHT, or 0 if unreadable. */
static int light(void)
{
	unsigned char b[4] = { 0 };
	if (fd < 0) return 0;
	(void)lseek(fd, 0, SEEK_SET);           /* the host test's file needs it; a device says ESPIPE */
	if (read(fd, b, 4) != 4) return 0;
	unsigned v = b[0] | (unsigned)b[1] << 8 | (unsigned)b[2] << 16 | (unsigned)b[3] << 24;
	raw = (int)(v > 1000 ? 1000 : v);              /* the driver's word, for `camcfg ctl get` */
	if (v != 1 && v != 2) return 0;
	if (cfg.invert) v = 3 - v;
	return v == 2 ? DN_NIGHT : DN_DAY;
}

void dn_init(const char *irled, const char *pwm, const struct dn_cfg *c)
{
	if (c) cfg = *c;
	pwm_dir = pwm;
	fd = open(irled, O_RDWR | O_NONBLOCK);
	if (fd < 0) LOG("daynight: %s: %s (the IR-cut can't move; a light-sensor auto stays in day)\n", irled,
			strerror(errno));
	state = cand = streak = pending = 0;
}

void dn_tick(void)
{
	int want, l;
	ticks++;
	if (pending) finish_pending();          /* a staged switch's second half, before anything new */
	if (cfg.mode != DN_AUTO) {
		want = cfg.mode;
		light();                                /* keep daynight.raw current */
	} else {
		l = cfg.source == DN_SRC_SENSOR ? light() : (light(), image());
		if (!l) l = state ? state : DN_DAY;
		if (l != cand) { cand = l; streak = 0; }
		/* start in day like stock (it sets day as soon as it opens /dev/irled), then follow the
		 * reading once it has held for DN_HOLD seconds; after DN_FLAP_N switches in
		 * DN_FLAP_WINDOW s hold still for DN_FLAP_HOLD s (a light that the IR itself trips) */
		if (++streak < DN_HOLD || ticks < hold_until) want = state ? state : DN_DAY;
		else want = cand;
	}
	if (want == state) return;
	int first = !state;
	apply(want == DN_NIGHT);
	if (cfg.mode != DN_AUTO || first) return;       /* the start-up decision isn't a switch */
	memmove(switched + 1, switched, sizeof switched - sizeof switched[0]);
	switched[0] = ticks;
	if (switched[DN_FLAP_N - 1] && ticks - switched[DN_FLAP_N - 1] <= DN_FLAP_WINDOW) {
		hold_until = ticks + DN_FLAP_HOLD;
		LOG("daynight: %d switches in %d s: holding %s for %d s\n", DN_FLAP_N, DN_FLAP_WINDOW,
		    want == DN_NIGHT ? "night" : "day", DN_FLAP_HOLD);
	}
}
