/* SPDX-License-Identifier: MIT */
/* daynight.h: day/night switching (#30): IR-cut, IR LEDs and B/W, as the stock firmware does. */
#ifndef DAYNIGHT_H
#define DAYNIGHT_H

enum { DN_AUTO, DN_DAY, DN_NIGHT };

enum { DN_SRC_IMAGE, DN_SRC_SENSOR };

/* Settings (cam.conf daynight.*). mode DN_*; irled = IR LED duty % at night (stock "100%" =
 * 96 % duty); source = what auto follows: the picture's brightness (DN_SRC_IMAGE, default: the
 * MCA40E's /dev/irled status reads 0 in daylight and under a cover, 2026-10-23) or the driver's
 * status word (DN_SRC_SENSOR, inverted if invert); night_below / day_above = the brightness score
 * thresholds (score = mean Y / (shutter s x gain), see daynight.c). */
struct dn_cfg { int mode, irled, invert, source, night_below, day_above; };
#define DN_CFG_DEFAULT { DN_AUTO, 96, 1, DN_SRC_IMAGE, 15, 1500 }

/* irled: the vendor kernel driver (/dev/irled); pwm: the IR LED PWM chip (/sys/class/pwm/pwmchip4).
 * Opens the driver; without it, auto mode stays in day. */
void dn_init(const char *irled, const char *pwm, const struct dn_cfg *c);
/* Once a second: read the light status, debounce, switch. */
void dn_tick(void);
/* Live changes (control socket); the next dn_tick applies them. */
void dn_set(const struct dn_cfg *c);
const struct dn_cfg *dn_get(void);
/* 0 not decided yet, DN_DAY or DN_NIGHT */
int dn_state(void);
/* last raw status word read from the driver (1/2; -1 none yet), before inversion */
int dn_raw(void);
/* last brightness score (-1 none yet) */
int dn_score(void);

#endif
