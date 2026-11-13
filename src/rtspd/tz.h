/* SPDX-License-Identifier: MIT */
/*
 * tz.h: the check for cam.conf's time.tz, the camera's time zone as a POSIX TZ string, shared by
 * camcfg (which saves it), rtspd (the OSD clock) and camhttpd (web UI, ONVIF). glibc (static, no
 * zoneinfo files on the camera) and BusyBox read this form without any file. Nothing reaches
 * setenv("TZ") without passing tz_valid(), and it takes only this subset of POSIX, so a file name
 * (":/etc/...", a path), a space, a shell metacharacter or a control byte never gets through:
 *
 *   std offset [dst [offset] [,start[/time],end[/time]]]       at most TZ_LEN (64) characters
 *   std, dst    3 or more letters (CST), or '<' 3 or more of A-Z a-z 0-9 + - '>' (<+0530>)
 *   offset      [+-]hh[:mm[:ss]], at most 24:00:00. POSIX counts west of Greenwich as positive:
 *               CST6 is UTC-6, CET-1 is UTC+1. dst's offset defaults to one hour less than std's.
 *   start, end  Mm.w.d (month 1..12, week 1..5 with 5 = the last, weekday 0..6 with 0 = Sunday),
 *               Jn (day 1..365, Feb 29 never counted) or n (day 0..365, counting Feb 29)
 *   time        [+-]hhh[:mm[:ss]], hours 0..167 (POSIX.1-2024); 02:00 when left out
 *
 * A dst without rules is accepted (glibc then uses the US rules, M3.2.0,M11.1.0), but every
 * preset gives its rules. Header-only, so the build lines stay as they are.
 */
#ifndef TZ_H
#define TZ_H

#include <string.h>

#define TZ_LEN 64                      /* longest time.tz */
#define TZ_BUF (TZ_LEN + 2)            /* a buffer one longer than any valid value (a longer
					  one reads as too long, not cut to a valid one) */
#define TZ_DEFAULT "UTC0"

/* 1..maxd digits at *p with a value <= hi (advancing *p), else -1. */
static inline long tz_num(const char **p, int maxd, long hi)
{
	long v = 0;
	int n = 0;
	while (**p >= '0' && **p <= '9') {
		if (++n > maxd) return -1;
		v = v * 10 + (**p - '0');
		(*p)++;
	}
	return n && v <= hi ? v : -1;
}

/* [+-]h[:mm[:ss]] with 1..hd hour digits, hours <= maxh: the seconds (without the sign), or -1.
 * Minutes and seconds are two digits, 00..59. */
static inline long tz_hms(const char **p, int hd, long maxh)
{
	if (**p == '+' || **p == '-') (*p)++;
	long s = tz_num(p, hd, maxh);
	if (s < 0) return -1;
	s *= 3600;
	for (int i = 0; i < 2 && **p == ':'; i++) {
		const char *q = ++*p;
		long x = tz_num(p, 2, 59);
		if (x < 0 || *p - q != 2) return -1;
		s += i ? x : x * 60;
	}
	return s;
}

/* A zone name: 3+ letters, or <...> with 3+ of [A-Za-z0-9+-]. 0 (advancing *p), else -1. */
static inline int tz_name(const char **p)
{
	static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static const char quoted[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
	const char *s = *p;
	size_t n;
	if (*s == '<') {
		n = strspn(++s, quoted);
		if (n < 3 || s[n] != '>') return -1;
		*p = s + n + 1;
		return 0;
	}
	if ((n = strspn(s, alpha)) < 3) return -1;
	*p = s + n;
	return 0;
}

/* An offset from UTC: [+-]hh[:mm[:ss]] up to 24:00:00. 0 (advancing *p), else -1. */
static inline int tz_offset(const char **p)
{
	long s = tz_hms(p, 2, 24);
	return s >= 0 && s <= 24 * 3600 ? 0 : -1;
}

/* A transition: Mm.w.d, Jn or n, then optionally /time. 0 (advancing *p), else -1. */
static inline int tz_rule(const char **p)
{
	const char *s = *p;
	if (*s == 'M') {
		s++;
		if (tz_num(&s, 2, 12) < 1 || *s != '.') return -1;
		s++;
		if (tz_num(&s, 1, 5) < 1 || *s != '.') return -1;
		s++;
		if (tz_num(&s, 1, 6) < 0) return -1;
	} else if (*s == 'J') {
		s++;
		if (tz_num(&s, 3, 365) < 1) return -1;
	} else if (tz_num(&s, 3, 365) < 0) {
		return -1;
	}
	if (*s == '/') {
		s++;
		if (tz_hms(&s, 3, 167) < 0) return -1;
	}
	*p = s;
	return 0;
}

/* 0 if tz isn't a TZ string of the form above; 1 if it is, without daylight saving; 2 if it is,
 * with daylight saving. */
static inline int tz_valid(const char *tz)
{
	if (!tz) return 0;
	size_t n = strlen(tz);
	if (n < 4 || n > TZ_LEN) return 0;
	for (size_t i = 0; i < n; i++)
		if ((unsigned char)tz[i] < 0x21 || (unsigned char)tz[i] > 0x7e) return 0;
	const char *p = tz;
	if (tz_name(&p) || tz_offset(&p)) return 0;
	if (!*p) return 1;
	if (tz_name(&p)) return 0;
	if (*p && *p != ',' && tz_offset(&p)) return 0;
	if (!*p) return 2;
	if (*p != ',') return 0;
	p++;
	if (tz_rule(&p) || *p != ',') return 0;
	p++;
	if (tz_rule(&p)) return 0;
	return *p ? 0 : 2;
}

#endif
