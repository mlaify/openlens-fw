/* SPDX-License-Identifier: MIT */
/*
 * streamcfg.h: the sizes, frame rates and default bit rates cam.conf's stream.* keys may hold,
 * shared by rtspd (which runs them), camcfg (which saves them) and camhttpd (web UI, ONVIF), so the
 * three can't drift apart.
 *
 *   stream.main.size  2560x1440 (default), 2304x1296, 1920x1080, 1280x720
 *   stream.sub.size   640x360 (default), 960x540, 1280x720
 *
 * All 16:9 with even sizes: the SCL scales the whole 2560x1440 sensor picture down to each. Every
 * sub size fits inside every main size, so "sub <= main" holds for any pair of listed values.
 * stream.*.fps is 1..STREAM_FPS_MAX (the SC4336P's 30 at 2560x1440), default 30 for both; the
 * sub-stream is fed from the main's frames, so it runs at most at the main's rate (a higher
 * stream.sub.fps runs at the main's: rtspd clamps, camhttpd shows and saves the clamped value).
 * An unset stream.<main|sub>.kbps follows the size: the kbps column below.
 * Header-only, so the build lines stay as they are.
 */
#ifndef STREAMCFG_H
#define STREAMCFG_H

#include <string.h>

#define SENSOR_W 2560                  /* the sensor picture: ONVIF's video source, its bounds */
#define SENSOR_H 1440
#define STREAM_FPS_MAX 30
#define STREAM_FPS_DEFAULT 30

struct stream_size { int w, h, kbps; const char *name; };

/* Size i (0 = the default) of the main (sub 0) or sub-stream (sub 1), or NULL past the last. */
static inline const struct stream_size *stream_size_at(int sub, int i)
{
	static const struct stream_size main_sizes[] = {
		{ 2560, 1440, 4000, "2560x1440" }, { 2304, 1296, 3500, "2304x1296" },
		{ 1920, 1080, 3000, "1920x1080" }, { 1280, 720, 1500, "1280x720" } };
	static const struct stream_size sub_sizes[] = {
		{ 640, 360, 500, "640x360" }, { 960, 540, 900, "960x540" }, { 1280, 720, 1500, "1280x720" } };
	int n = sub ? (int)(sizeof sub_sizes / sizeof sub_sizes[0]) : (int)(sizeof main_sizes / sizeof main_sizes[0]);
	return i >= 0 && i < n ? (sub ? &sub_sizes[i] : &main_sizes[i]) : NULL;
}

/* The listed size v ("1920x1080", exactly as above) of that stream, or NULL. */
static inline const struct stream_size *stream_size_find(int sub, const char *v)
{
	const struct stream_size *s;
	for (int i = 0; (s = stream_size_at(sub, i)); i++)
		if (!strcmp(v, s->name)) return s;
	return NULL;
}

/* The bit rate (kbps) for an unset stream.<main|sub>.kbps at w x h: the listed size's; a size
 * that isn't listed (rtspd's -w/-h/-s, bench only) gets the largest listed one not bigger than
 * it, or the smallest. */
static inline int stream_kbps_default(int sub, int w, int h)
{
	const struct stream_size *s, *best = NULL, *least = NULL;
	for (int i = 0; (s = stream_size_at(sub, i)); i++) {
		if (s->w == w && s->h == h) return s->kbps;
		if ((long)s->w * s->h <= (long)w * h && (!best || s->w > best->w)) best = s;
		if (!least || s->w < least->w) least = s;
	}
	return best ? best->kbps : least->kbps;
}

#endif
