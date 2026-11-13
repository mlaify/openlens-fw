/* SPDX-License-Identifier: MIT */
/*
 * mi-probe: run the Ifado MI pipeline (src/mi) for N seconds and write the H.265 stream to a file.
 * Bench tool for cam #1 (issues #28/#43): run from /tmp with the vendor media_server stopped. It
 * never touches flash.
 *
 *   mi-probe [-o out.h265] [-t seconds] [-w W -h H] [-b kbps] [-f fps] [-r] [-v] [-A] [-T y]
 *            [-e us:gain] [-W r:g:b] [-X ae-fields] [-Q iq-profile] [-C ae:awb:af] [-P isp-outfmt]
 *     -r  bind SCL->VENC as HW_RING (stock main stream) instead of FRAME_BASE
 *     -A  our simple AE (mean-Y) + grey-world AWB, clocked by /dev/isp_fe frame events
 *     -T  AE target, stats mean Y (default 110)
 *     -e  fixed exposure: shutter in us, sensor gain (1x = 1024)
 *     -W  fixed white-balance gains r:g:b (1x = 1024)
 *     -X  AE result field overrides (legacy, gm=, hdr=, fn=, deband=, bv=)
 *     -Q  apply the image-pipeline groups of an iq-dump file (e.g. one taken under stock), #36
 *     -C  userspace-3A enables ae:awb:af sent as IQ 0x2e08 (default 1:1:0; stock sends 1:1:1)
 *     -P  ISP output pixel format: 0 YUV422 YUYV (default), 11 NV12
 */
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>

#include "mi.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static uint8_t frame[1 << 20];

int main(int argc, char **argv)
{
	struct mi_cfg cfg = { .w = 2560, .h = 1440, .kbps = 2048, .fps = 25 };
	const char *path = "/tmp/mi-probe.h265";
	int seconds = 10, c;
	while ((c = getopt(argc, argv, "o:t:w:h:b:f:rvAT:e:W:X:Q:C:P:")) != -1) {
		switch (c) {
		case 'o': path = optarg; break;
		case 't': seconds = atoi(optarg); break;
		case 'w': cfg.w = atoi(optarg); break;
		case 'h': cfg.h = atoi(optarg); break;
		case 'b': cfg.kbps = atoi(optarg); break;
		case 'f': cfg.fps = atoi(optarg); break;
		case 'r': cfg.ring = 1; break;
		case 'v': mi_verbose++; break;
		case 'A': cfg.auto3a = 1; break;
		case 'T': cfg.ae_target = atof(optarg); break;
		case 'e': sscanf(optarg, "%u:%u", &cfg.shutter_us, &cfg.gain); break;
		case 'W': sscanf(optarg, "%u:%u:%u", &cfg.wb_r, &cfg.wb_g, &cfg.wb_b); break;
		case 'X': cfg.ae_extra = optarg; break;
		case 'Q': cfg.iq_profile = optarg; break;
		case 'C': cfg.cus3a = optarg; break;
		case 'P': cfg.isp_outfmt = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-o out.h265] [-t sec] [-w W -h H] [-b kbps] [-f fps] [-r] [-v] "
				"[-A] [-T y] [-e us:gain] [-W r:g:b] [-X ae-fields] [-Q iq-profile] [-C ae:awb:af]\n", argv[0]);
			return 2;
		}
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	FILE *out = fopen(path, "wb");
	if (!out) { perror(path); return 1; }

	int rc = 1;
	if (mi_start(&cfg) == 0) {
		int vfd, ffd;
		mi_fds(&vfd, &ffd);
		time_t end = time(NULL) + seconds;
		unsigned frames = 0;
		unsigned long long bytes = 0;
		rc = 0;
		while (!stop && time(NULL) < end) {
			fd_set rf;
			FD_ZERO(&rf);
			FD_SET(vfd, &rf);
			if (ffd >= 0) FD_SET(ffd, &rf);
			struct timeval tv = { 0, 200000 };
			select((ffd > vfd ? ffd : vfd) + 1, &rf, NULL, NULL, &tv);
			if (ffd >= 0 && FD_ISSET(ffd, &rf)) mi_fe_ready();
			int n = mi_read_frame(frame, sizeof frame, NULL);
			if (n < 0) { rc = 1; break; }
			if (n == 0) continue;
			fwrite(frame, 1, (size_t)n, out);
			frames++;
			bytes += (unsigned)n;
		}
		fprintf(stderr, "done: %u frames, %llu bytes -> %s\n", frames, bytes, path);
		if (!frames) rc = 1;
	}
	fclose(out);
	mi_stop();
	return rc;
}
