/* SPDX-License-Identifier: MIT */
/*
 * iq-dump: read every IQ API group of ISP dev 0 / chn 0 (MI_ISP GetIQApiData, read-only) and write
 * them to a binary file, so the stock pipeline's ISP parameters can be diffed against ours
 * (issue #36). It never sets anything, so it can run next to the stock media_server.
 *
 *   iq-dump /tmp/iq-stock.bin
 *
 * File: repeated records {u32 id, u32 size, s32 ret, u8 data[size]} (little-endian); data is
 * zeros when ret != 0. Decode and diff on the host with scripts/iq-diff.py and the camera's
 * /config/iqfile/isp_api.xml. Group table: iq_groups.h (scripts/gen-iq-groups.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mi.h"
#include "iq_groups.h"

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s out.bin\n", argv[0]);
		return 2;
	}
	FILE *out = fopen(argv[1], "wb");
	if (!out) { perror(argv[1]); return 1; }
	if (mi_iq_open()) { fprintf(stderr, "mi_iq_open failed\n"); return 1; }
	unsigned ok = 0, n = sizeof iq_groups / sizeof iq_groups[0];
	static uint8_t buf[32768];
	for (unsigned i = 0; i < n; i++) {
		uint32_t id = iq_groups[i].id, size = iq_groups[i].size;
		if (size > sizeof buf) continue;
		memset(buf, 0, size);
		int32_t ret = mi_iq_get(id, buf, size);
		if (ret) memset(buf, 0, size);
		else ok++;
		fwrite(&id, 4, 1, out);
		fwrite(&size, 4, 1, out);
		fwrite(&ret, 4, 1, out);
		fwrite(buf, 1, size, out);
		if (ret) fprintf(stderr, "  %5u %-40s %6u B: ret %d\n", id, iq_groups[i].name, size, ret);
	}
	fclose(out);
	fprintf(stderr, "iq-dump: %u/%u groups read -> %s\n", ok, n, argv[1]);
	return 0;
}
