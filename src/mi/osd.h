/* SPDX-License-Identifier: MIT */
/*
 * osd.h: the on-screen display (date/time line and a title line burned into the video) through
 * SigmaStar's MI_RGN driver, decoded from stock (docs/STOCK-OSD.md). See osd.c.
 *
 * Use from rtspd: osd_set() for each osd.* line of cam.conf, osd_enable() before mi_start() (it
 * registers the hook mi_start calls between each encoder's CreateChn and StartRecvPic),
 * osd_tick(time(NULL)) from the main loop, osd_set() / osd_get() for the control socket, and
 * osd_stop() before mi_stop() (regions must be detached before the encoders go).
 * Any MI_RGN failure is logged once and turns the OSD off; the video is never stopped for it.
 */
#ifndef OSD_H
#define OSD_H

#include <stddef.h>
#include <time.h>

#define OSD_TITLE_MAX 48               /* osd.title.text: printable ASCII, at most this long */

/* One osd.* setting ("osd.time.pos", "ul"): 0 if the key and value are valid (taken, applied
 * from the next osd_tick), -1 if not (nothing changes). Keys and values: docs in src/README.md. */
int osd_set(const char *key, const char *val);

/* The settings as "osd.KEY=VALUE\n" lines, then osd.status=off|on|failed. Bytes written. */
size_t osd_get(char *out, size_t cap);

void osd_enable(void);                 /* before mi_start */
/* Open /dev/mi_rgn now if it isn't yet (no MI_RGN call): rtspd -U does this before it leaves
 * root, so an OSD first enabled later still finds the device. 0, or -1 (logged). */
int osd_open(void);
void osd_tick(time_t now);             /* main loop: redraws the clock when the second changes */
void osd_stop(void);                   /* before mi_stop: detach and destroy the regions */

#endif
