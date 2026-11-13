/* SPDX-License-Identifier: MIT */
/* motion.h: motion detection from the ISP's AE luma grid (#77). */
#ifndef MOTION_H
#define MOTION_H

#include <stddef.h>

/* cam.conf motion.enabled (0/1, default 1), motion.sensitivity (0..100, default 50),
 * motion.mask: which cells of the grid count (ONVIF CellMotionDetector ActiveCells, #77). */
#define MOTION_GRID_W 32
#define MOTION_GRID_H 32
#define MOTION_MASK_HEX (MOTION_GRID_W * MOTION_GRID_H / 4)
struct motion_cfg { int enabled, sensitivity; };
#define MOTION_CFG_DEFAULT { 1, 50 }

/* The cell mask as 256 hex digits: 1024 bits, row-major from the top-left cell, the first cell in
 * the high bit of the first byte; 1 = the cell counts. All cells count by default. 0 or -1. */
int motion_set_mask(const char *hex);
void motion_get_mask(char out[MOTION_MASK_HEX + 1]);

void motion_set(const struct motion_cfg *c);
const struct motion_cfg *motion_get(void);
/* Call often (every loop pass is fine): evaluates each new grid at most 5 times a second.
 * now_ms: a monotonic clock in ms. */
void motion_tick(long long now_ms);
/* state 0/1; seq: rising edges since start; since_ms: when the state last changed */
int motion_state(unsigned *seq, long long *since_ms);
/* last evaluation: cells that differ from the background (for the log and tests) */
int motion_cells(void);
/* cells needed to count as motion at the current sensitivity and mask */
int motion_need(void);
/* the most cells changed in one evaluation over the last 2 s (reading doesn't reset it: camhttpd
 * polls the same command): for tuning */
int motion_peak(void);
/* The last evaluation as a grid, one character per cell, row-major from the top-left, ending in
 * "ok": mode 0: the change against the background in tens of % ('+' 100 % or more, '#' counted
 * as changed); 1: the luma / 16 (hex digit); 2: the cell's usual change (its noise) in tens of
 * %. '-' is a masked-out cell. 0, or -1 if cap is too small. */
int motion_map(char *out, size_t cap, int mode);

#endif
