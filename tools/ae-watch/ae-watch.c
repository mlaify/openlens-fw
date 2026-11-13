/* SPDX-License-Identifier: MIT */
/*
 * ae-watch: print the running pipeline's exposure once a second, READ-ONLY (MI_ISP
 * GetIQApiData only, like iq-dump), so it can run next to the stock media_server and show what
 * stock's AE does in a given scene (owner 2026-10-23: our night image is far darker than stock).
 *
 *   ae-watch SECONDS
 *
 * Per line: shutter (us), sensor gain, ISP gain (x, 1024 = 1x), total gain, mean Y of the 32x32
 * AE grid (0..255), AWB R/B gains. The first line also dumps the raw 95-byte AE status.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "mi.h"

static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static double mean_y(const uint8_t *s, size_t cap)
{
	uint32_t w = u32(s), h = u32(s + 4);
	if (!w || !h || 8 + (size_t)w * h * 4 > cap) return -1;
	double sum = 0;
	for (size_t i = 0; i < (size_t)w * h; i++) sum += s[8 + i * 4 + 3];
	return sum / ((double)w * h);
}

int main(int argc, char **argv)
{
	int secs = argc > 1 ? atoi(argv[1]) : 60;
	if (secs < 1 || secs > 3600) { fprintf(stderr, "usage: %s SECONDS (1..3600)\n", argv[0]); return 2; }
	if (mi_iq_open()) { fprintf(stderr, "mi_iq_open failed\n"); return 1; }
	static uint8_t st[95], stats[46088], wst[59];
	for (int i = 0; i < secs; i++) {
		memset(st, 0, sizeof st);
		int r1 = mi_iq_get(0x2e05, st, sizeof st);          /* AE status */
		int r2 = mi_iq_get(0x2e01, stats, sizeof stats);    /* AE stats */
		int r3 = mi_iq_get(0x2e09, wst, sizeof wst);        /* AWB status */
		if (i == 0 && !r1) {
			printf("AE status raw:");
			for (size_t k = 0; k < sizeof st; k++) printf("%s%02x", k % 16 ? " " : "\n  ", st[k]);
			printf("\n");
		}
		time_t t = time(NULL);
		char ts[16];
		strftime(ts, sizeof ts, "%H:%M:%S", localtime(&t));
		if (r1) { printf("%s AE status read failed (%d)\n", ts, r1); sleep(1); continue; }
		double sg = u32(st + 0x1c) / 1024.0, ig = u32(st + 0x20) / 1024.0;
		printf("%s shutter %6u us  sensor %6.2fx  isp %5.2fx  total %7.2fx  meanY %6.1f", ts,
		       u32(st + 0x18), sg, ig, sg * ig, r2 ? -1.0 : mean_y(stats, sizeof stats));
		if (!r3) printf("  awb r %.2f b %.2f", u32(wst + 0xc) / 1024.0, u32(wst + 0x14) / 1024.0);
		printf("\n");
		fflush(stdout);
		sleep(1);
	}
	return 0;
}
