/* SPDX-License-Identifier: MIT */
/*
 * mi.c: the SigmaStar Ifado MI video pipeline, driven by raw ioctls (no vendor userland).
 *
 *   SNR pad 0 -> VIF 0/0/0 -(realtime)-> ISP 0/0/0 -(realtime)-> SCL 0/0/0 -(frame|ring)-> VENC 0/0
 *
 * Every call is ioctl(fd, _IOC(dir,'i',nr,sizeof(args)), &hdr) on /dev/mi_*, as decoded from the
 * stock media_server (docs/IFADO-MI-PIPELINE.md, analysis/ifado-mi-api-table.tsv) and verified
 * live on cam #1 (runs 1-4, issues #28/#43). 3A: our AE + grey-world AWB over the ISP IQ API,
 * clocked by /dev/isp_fe like the stock CUS3A thread. Used by tools/mi-probe and src/rtspd.
 */
#define _GNU_SOURCE                    /* clock_gettime under -std=c11 (glibc) */
#include "mi.h"

#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "../../tools/iq-dump/iq_groups.h"     /* IQ API group ids and sizes (night tuning) */

/* ---- ioctl convention ---------------------------------------------------------------- */

enum { DIR_W = 1, DIR_R = 2, DIR_RW = 3 };
enum { JPEG_DEV = 8, JPEG_CHN = 3 };            /* stock CJpg: VENC device 8, channel index + 3 */
#define MI_IOC(dir, nr, size) \
	((unsigned long)(((unsigned)(dir) << 30) | ((unsigned)(size) << 16) | ('i' << 8) | (nr)))

struct mi_hdr {
	uint16_t dev;   /* SoC / device id, 0 */
	uint16_t pad;
	uint32_t len;   /* sizeof(args) */
	uint64_t ptr;   /* &args */
};
_Static_assert(sizeof(struct mi_hdr) == 16, "mi_hdr");

int mi_verbose;

static void logf_(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#define LOG(...) logf_(__VA_ARGS__)
#define DBG(...) do { if (mi_verbose) logf_(__VA_ARGS__); } while (0)

static int mi_call_q(int fd, const char *what, int dir, int nr, void *args, uint32_t size,
		     int quiet)
{
	struct mi_hdr h = { 0, 0, size, (uint64_t)(uintptr_t)args };
	unsigned long req = MI_IOC(dir, nr, size);
	int r = ioctl(fd, req, &h);
	if (!quiet || r == 0)
		DBG("  %-28s nr%-3d %3uB req=%#lx -> %d\n", what, nr, size, req, r);
	if (r != 0 && !quiet)
		LOG("%s failed: ret %d errno %d (%s)\n", what, r, errno, strerror(errno));
	return r;
}

static int mi_call(int fd, const char *what, int dir, int nr, void *args, uint32_t size)
{
	return mi_call_q(fd, what, dir, nr, args, size, 0);
}

/* ---- device fds ---------------------------------------------------------------------- */

static int fd_sys = -1, fd_snr = -1, fd_vif = -1, fd_isp = -1, fd_scl = -1, fd_venc = -1;

static int open_dev(const char *path)
{
	int fd = open(path, O_RDWR);
	if (fd < 0)
		LOG("open %s: %s\n", path, strerror(errno));
	return fd;
}

/* ---- shared types (I6C public layouts; Ifado differences noted) ----------------------- */

struct chnport { uint32_t module, dev, chn, port; };            /* MI_SYS_ChnPort_t */
enum { MOD_VENC = 2, MOD_VIF = 6, MOD_ISP = 0x21, MOD_SCL = 0x22 };
enum { BIND_FRAME = 1, BIND_REALTIME = 4, BIND_HW_RING = 0x10 };

/* ---- SYS (/dev/mi_sys) ---------------------------------------------------------------- */

static int sys_init(void)
{
	uint32_t a = 0;
	return mi_call(fd_sys, "MI_SYS_Init", DIR_R, 0, &a, sizeof a);
}

static int sys_bind(struct chnport src, struct chnport dst, uint32_t sfps, uint32_t dfps,
		    uint32_t type, uint32_t param)
{
	struct { struct chnport s, d; uint32_t bind_param, bind_type, z, one, sfps, dfps; } a = {
		src, dst, param, type, 0, 1, sfps, dfps };
	_Static_assert(sizeof a == 56, "bind");
	return mi_call(fd_sys, "MI_SYS_BindChnPort", DIR_W, 3, &a, sizeof a);
}

static int sys_unbind(struct chnport src, struct chnport dst)
{
	/* nr4, 56 B (libmi_sys inventory): same args block as Bind, tail left zero. */
	struct { struct chnport s, d; uint32_t tail[6]; } a = { src, dst, { 0 } };
	_Static_assert(sizeof a == 56, "unbind");
	return mi_call(fd_sys, "MI_SYS_UnBindChnPort", DIR_W, 4, &a, sizeof a);
}

static int sys_set_depth(struct chnport p, uint32_t user, uint32_t buf)
{
	struct { struct chnport p; uint32_t user, buf; } a = { p, user, buf };
	_Static_assert(sizeof a == 24, "depth");
	return mi_call(fd_sys, "MI_SYS_SetChnOutputPortDepth", DIR_W, 21, &a, sizeof a);
}

/* Per-device private ring pool (kernel layout of MI_SYS_ConfigPrivateMMAPool type 4). */
static int sys_ring_pool(uint32_t module, uint32_t dev, uint16_t w, uint16_t h, uint16_t lines)
{
	uint8_t a[60];
	memset(a, 0, sizeof a);
	uint32_t type = 4, maxwh = (uint32_t)w | ((uint32_t)h << 16);
	memcpy(a + 0x00, &type, 4);
	memcpy(a + 0x04, &module, 4);
	a[0x08] = 1;                    /* bCreate */
	a[0x09] = (uint8_t)dev;
	memcpy(a + 0x14, &maxwh, 4);
	memcpy(a + 0x18, &lines, 2);
	return mi_call(fd_sys, "MI_SYS_ConfigPrivateMMAPool", DIR_W, 29, a, sizeof a);
}

static int sys_mmap(uint64_t phys, uint32_t size, void **virt)
{
	struct { uint8_t cached, pad[3]; uint32_t size; uint64_t virt; uint64_t phys; } a = {
		0, { 0 }, size, 0, phys };
	_Static_assert(sizeof a == 24, "mmap");
	int r = mi_call(fd_sys, "MI_SYS_Mmap", DIR_RW, 10, &a, sizeof a);
	*virt = r ? NULL : (void *)(uintptr_t)a.virt;
	return r;
}

static int sys_munmap(void *virt, uint32_t size)
{
	struct { uint64_t virt; uint32_t size, pad; } a = { (uint64_t)(uintptr_t)virt, size, 0 };
	return mi_call(fd_sys, "MI_SYS_Munmap", DIR_W, 11, &a, sizeof a);
}

/* ---- SNR (/dev/mi_sensor) -------------------------------------------------------------- */

struct snr_res {                                             /* MI_SNR_Res_t, 52 B */
	uint16_t cx, cy, cw, ch, ow, oh;
	uint32_t max_fps, min_fps;
	char desc[32];
};
_Static_assert(sizeof(struct snr_res) == 52, "snr_res");

struct snr_plane {                                           /* MI_SNR_PlaneInfo_t, 72 B */
	uint32_t plane_id;
	char name[32];
	uint16_t cx, cy, cw, ch;                             /* @0x24 */
	uint32_t bayer, precision, hdr_src, shutter_us, gain, comp_gain, pixel;   /* @0x2c..0x44 */
};
_Static_assert(sizeof(struct snr_plane) == 72, "snr_plane");

static int snr_u32(const char *what, int nr, uint32_t pad, uint32_t v)
{
	struct { uint32_t pad, v; } a = { pad, v };
	return mi_call(fd_snr, what, DIR_W, nr, &a, sizeof a);
}

/* ---- pipeline parameters -------------------------------------------------------------- */

static struct mi_cfg cfg;

static uint8_t padinfo[56];
static struct snr_plane plane;
static uint32_t bayer_fmt;

static int setup_snr(void)
{
	uint32_t pad = 0;
	struct { uint32_t pad, count; } qc = { pad, 0 };
	struct { uint32_t pad, idx; struct snr_res r; } gr;
	struct { uint32_t pad; uint8_t info[56]; } gp;
	struct { uint32_t pad, plane; struct snr_plane p; } gpl;

	if (snr_u32("MI_SNR_SetPlaneMode", 14, pad, 0)) return -1;
	if (mi_call(fd_snr, "MI_SNR_QueryResCount", DIR_RW, 8, &qc, sizeof qc)) return -1;
	for (uint32_t i = 0; i < qc.count; i++) {
		memset(&gr, 0, sizeof gr); gr.pad = pad; gr.idx = i;
		if (!mi_call(fd_snr, "MI_SNR_GetRes", DIR_RW, 9, &gr, sizeof gr))
			LOG("sensor res %u: %.32s crop %ux%u out %ux%u fps %u..%u\n", i, gr.r.desc,
			    gr.r.cw, gr.r.ch, gr.r.ow, gr.r.oh, gr.r.min_fps, gr.r.max_fps);
	}
	if (snr_u32("MI_SNR_SetRes", 11, pad, 0)) return -1;
	{ uint32_t p = pad; if (mi_call(fd_snr, "MI_SNR_Enable", DIR_W, 0, &p, sizeof p)) return -1; }

	memset(&gp, 0, sizeof gp); gp.pad = pad;
	if (mi_call(fd_snr, "MI_SNR_GetPadInfo", DIR_RW, 2, &gp, sizeof gp)) return -1;
	memcpy(padinfo, gp.info, sizeof padinfo);
	memset(&gpl, 0, sizeof gpl); gpl.pad = pad; gpl.plane = 0;
	if (mi_call(fd_snr, "MI_SNR_GetPlaneInfo", DIR_RW, 3, &gpl, sizeof gpl)) return -1;
	plane = gpl.p;
	/* SigmaStar RGB_BAYER_PIXEL(precision, bayerId); stock: pixel 34 for BG 10BPP. */
	bayer_fmt = plane.bayer < 0xc ? plane.precision * 12 + plane.bayer + 0x14 : plane.pixel;
	LOG("sensor plane: cap %u,%u %ux%u bayer %u prec %u -> pixfmt %u\n", plane.cx, plane.cy,
	    plane.cw, plane.ch, plane.bayer, plane.precision, bayer_fmt);
	return 0;
}

static int setup_vif(void)
{
	uint32_t intf, pad2c;
	memcpy(&intf, padinfo + 4, 4);
	memcpy(&pad2c, padinfo + 0x2c, 4);

	/* VIF group 0: {intf, work 0 (1MULTIPLEX), hdr 0, 0, 0, +0x14 = intf ? 2 : pad+0x2c, ...} */
	struct { uint32_t group; uint32_t a[12]; } g;
	memset(&g, 0, sizeof g);
	g.a[0] = intf;
	g.a[5] = intf ? 2 : pad2c;
	if (mi_call(fd_vif, "MI_VIF_CreateDevGroup", DIR_W, 0, &g, sizeof g)) return -1;

	/* Ifado DevAttr: {pixfmt; u32 0; u16 x,y,w,h @0x08; 0; 0} */
	struct { uint32_t dev, pix, z; uint16_t x, y, w, h; uint32_t z2, z3; } d = {
		0, bayer_fmt, 0, plane.cx, plane.cy, plane.cw, plane.ch, 0, 0 };
	_Static_assert(sizeof d == 28, "vif devattr");
	if (mi_call(fd_vif, "MI_VIF_SetDevAttr", DIR_W, 4, &d, sizeof d)) return -1;
	{ uint32_t dev = 0; if (mi_call(fd_vif, "MI_VIF_EnableDev", DIR_W, 6, &dev, sizeof dev)) return -1; }

	struct { uint32_t dev, port; uint16_t x, y, w, h, dw, dh; uint32_t pix, frc, comp; } o = {
		0, 0, plane.cx, plane.cy, plane.cw, plane.ch, plane.cw, plane.ch, bayer_fmt, 0, 0 };
	_Static_assert(sizeof o == 32, "vif port");
	return mi_call(fd_vif, "MI_VIF_SetOutputPortAttr", DIR_W, 9, &o, sizeof o);
}

static int vif_enable_port(void)
{
	struct { uint32_t dev, port; } a = { 0, 0 };
	return mi_call(fd_vif, "MI_VIF_EnableOutputPort", DIR_W, 11, &a, sizeof a);
}

/* Stock Vif::Init's last step (docs/IFADO-MI-PIPELINE.md, "Sensor + VIF" 10): MI_SNR_SetFps(pad,
 * fps), nr5 {u32 pad; u32 fps}, up to 5 tries, once the VIF output port is enabled. Without it the
 * SC4336P runs at its native 30 fps whatever the binds and VENC's rate control assume (Frigate
 * counted 1,800 frames a minute with 25 configured, 2026-10-25). Not fatal: the video then runs at
 * the sensor's own rate. */
enum { SNR_FPS_TRIES = 5 };

static int snr_set_fps(void)
{
	for (int i = 1; i <= SNR_FPS_TRIES; i++)
		if (!snr_u32("MI_SNR_SetFps", 5, 0, (uint32_t)cfg.fps)) {
			LOG("sensor: %d fps (MI_SNR_SetFps, try %d)\n", cfg.fps, i);
			return 0;
		}
	LOG("MI_SNR_SetFps(%d) failed %d times: the sensor keeps its own frame rate\n", cfg.fps, SNR_FPS_TRIES);
	return -1;
}

static int want_3a(void);
static void cus3a_config(void);
static void cus3a_chn_query(void);

static int setup_isp(void)
{
	struct { uint32_t dev, mask; } cd = { 0, 1 };
	if (mi_call(fd_isp, "MI_ISP_CreateDevice", DIR_W, 0, &cd, sizeof cd)) return -1;

	if (want_3a())
		cus3a_config();                                  /* stock: before CreateChannel */

	struct { uint32_t dev, chn, bind_sensor; uint8_t rest[76]; } cc;
	memset(&cc, 0, sizeof cc);
	cc.bind_sensor = 1;                                  /* 1 << pad 0 */
	_Static_assert(sizeof cc == 88, "isp chn");
	if (mi_call(fd_isp, "MI_ISP_CreateChannel", DIR_W, 2, &cc, sizeof cc)) return -1;
	if (want_3a())
		cus3a_chn_query();

	struct { uint32_t dev, chn, hdr, dnr3; uint8_t rest[20]; } cp;
	memset(&cp, 0, sizeof cp);
	cp.dnr3 = 1;                                         /* stock 3DNR level 1 */
	_Static_assert(sizeof cp == 36, "isp chnparam");
	if (mi_call(fd_isp, "MI_ISP_SetChnParam", DIR_W, 6, &cp, sizeof cp)) return -1;

	struct { uint32_t dev, chn, port; uint16_t x, y, w, h; uint32_t pix, comp, layout; } op = {
		0, 0, 0, 0, 0, plane.cw, plane.ch, (uint32_t)cfg.isp_outfmt /* 0 YUYV, 11 NV12 */, 0, 0 };
	_Static_assert(sizeof op == 32, "isp port");
	if (mi_call(fd_isp, "MI_ISP_SetOutputPortParam", DIR_W, 11, &op, sizeof op)) return -1;

	struct chnport vif = { MOD_VIF, 0, 0, 0 }, isp = { MOD_ISP, 0, 0, 0 };
	if (sys_bind(vif, isp, cfg.fps, cfg.fps, BIND_REALTIME, 0)) return -1;

	struct { uint32_t dev, chn; } st = { 0, 0 };
	if (mi_call(fd_isp, "MI_ISP_StartChannel", DIR_W, 9, &st, sizeof st)) return -1;
	struct { uint32_t dev, chn, port; } ep = { 0, 0, 0 };
	return mi_call(fd_isp, "MI_ISP_EnableOutputPort", DIR_W, 13, &ep, sizeof ep);
}

static int setup_scl(void)
{
	struct { uint32_t dev, mask; } cd = { 0, 7 };        /* stock UseSclMask 7 */
	if (mi_call(fd_scl, "MI_SCL_CreateDevice", DIR_W, 0, &cd, sizeof cd)) return -1;
	if (cfg.ring && sys_ring_pool(MOD_SCL, 0, (uint16_t)plane.cw, (uint16_t)plane.ch,
				      (uint16_t)(cfg.h / 3)))
		return -1;

	struct { uint32_t dev, chn, z; } cc = { 0, 0, 0 };
	if (mi_call(fd_scl, "MI_SCL_CreateChannel", DIR_W, 2, &cc, sizeof cc)) return -1;
	struct { uint32_t dev, chn, rot; } cp = { 0, 0, 0 };
	if (mi_call(fd_scl, "MI_SCL_SetChnParam", DIR_W, 6, &cp, sizeof cp)) return -1;
	struct { uint32_t dev, chn; } sc = { 0, 0 };
	if (mi_call(fd_scl, "MI_SCL_StartChannel", DIR_W, 8, &sc, sizeof sc)) return -1;

	/* port 0: main stream; port 1: sub-stream (stock ST_SclCreateChn: one channel, a port per
	 * stream, each NV12 with user depth 0 / buffer depth 3) */
	for (uint32_t port = 0; port < (cfg.sub_w ? 2u : 1u); port++) {
		uint16_t ow = (uint16_t)(port ? cfg.sub_w : cfg.w), oh = (uint16_t)(port ? cfg.sub_h : cfg.h);
		struct { uint32_t dev, chn, port; uint16_t x, y, w, h, ow, oh; uint8_t mir, flip, p2[2];
			 uint32_t pix, comp; } op = {
			0, 0, port, 0, 0, 0, 0, ow, oh, 0, 0, { 0, 0 }, 0xb /* NV12 */, 0 };
		_Static_assert(sizeof op == 36, "scl port");
		if (mi_call(fd_scl, "MI_SCL_SetOutputPortParam", DIR_W, 10, &op, sizeof op)) return -1;
		struct { uint32_t dev, chn, port; } ep = { 0, 0, port };
		if (mi_call(fd_scl, "MI_SCL_EnableOutputPort", DIR_W, 12, &ep, sizeof ep)) return -1;
		struct chnport sp = { MOD_SCL, 0, 0, port };
		if (sys_set_depth(sp, 0, 3)) return -1;
	}

	struct chnport isp = { MOD_ISP, 0, 0, 0 }, sp0 = { MOD_SCL, 0, 0, 0 };
	return sys_bind(isp, sp0, cfg.fps, cfg.fps, BIND_REALTIME, 0);
}

/* Channel attr (80 B), layout from the CVideoH265 / CVideoH264 attr builders (FUN_0002610c /
 * FUN_0001ce24): same shape, eType 3 / 2. RC mode: H.264 CBR 1 / VBR 2, H.265 CBR 9 / VBR 10;
 * VBR adds max/min QP at +0x40/+0x44, stock's values for MCA40E (0x730): H.264 48/30, H.265
 * 50/32 (docs/STOCK-ENCODE-IMAGE.md). Profile (H.264 only; H.265 stock writes 0). */
static void venc_attr(uint32_t at[20], int codec, int w, int h, int fps, int kbps, int gop, int rc,
		      int profile)
{
	memset(at, 0, 80);
	at[0] = codec == MI_H264 ? 2 : 3;                    /* eType */
	at[1] = (uint32_t)w; at[2] = (uint32_t)h;            /* max W/H */
	at[3] = (uint32_t)((uint64_t)w * h * 15 / 37);       /* bufSize, stock formula */
	at[4] = codec == MI_H264 ? (uint32_t)profile : 0;    /* profile */
	((uint8_t *)at)[0x14] = 1;                           /* byFrame */
	at[6] = (uint32_t)w; at[7] = (uint32_t)h;            /* pic W/H */
	at[9] = 1;
	if (rc == MI_RC_VBR) {
		at[10] = codec == MI_H264 ? 2 : 10;                  /* RC: VBR */
		at[16] = codec == MI_H264 ? 48 : 50;                 /* max QP */
		at[17] = codec == MI_H264 ? 30 : 32;                 /* min QP */
	} else {
		at[10] = codec == MI_H264 ? 1 : 9;                   /* RC: CBR */
	}
	at[11] = (uint32_t)(gop > 0 ? gop : fps * 2);        /* GOP (keyframe interval, frames) */
	at[13] = (uint32_t)fps; at[14] = 1;                  /* fps num/den */
	at[15] = (uint32_t)kbps << 10;                       /* bitrate, bps (stock kbps<<10) */
}

/* Stock's step right after CreateChn for H.264 (CVideoH264 FUN_0001d068): MI_VENC_GetRcParam
 * (nr43), patch, MI_VENC_SetRcParam (nr42); 60-byte param, values for MCA40E from
 * docs/STOCK-ENCODE-IMAGE.md 1.4 (word names are guesses from the I6C headers). H.265's
 * version isn't decoded, so H.265 keeps the driver defaults. */
static int venc_rc_tune(uint32_t chn, int rc, int fps, int kbps, int gop)
{
	struct { uint32_t dev, chn; int32_t p[15]; } a = { 0, chn, { 0 } };
	_Static_assert(sizeof a == 68, "rc param");
	if (mi_call(fd_venc, "MI_VENC_GetRcParam", DIR_RW, 43, &a, sizeof a)) return -1;
	int ratio = fps > 0 ? (gop > 0 ? gop : fps * 2) / fps : 2;
	double bps = (double)((uint32_t)kbps << 10);
	if (rc == MI_RC_VBR) {
		a.p[5] = ratio >= 3 ? -4 : ratio == 2 ? 6 : 12;          /* IPQPDelta */
		a.p[6] = 80;                                             /* ChangePos */
		a.p[7] = 51;                                             /* MaxIQp */
		a.p[8] = 30;                                             /* MinIQp */
		a.p[9] = 12;                                             /* MaxIPProp */
		if (ratio >= 3) a.p[10] = (int32_t)(bps * 1.2);          /* MaxISize, bits */
		else if (ratio < 2) a.p[10] = (int32_t)(bps * 0.9);
		a.p[11] = (int32_t)(bps * (ratio >= 2 ? 0.2 : 0.1));     /* MaxPSize, bits */
	} else {
		a.p[3] = 48; a.p[4] = 20;                                /* MaxQp, MinQp */
		a.p[5] = -4;                                             /* IPQPDelta */
		a.p[6] = 48; a.p[7] = 20; a.p[8] = 20;                   /* MaxIQp, MinIQp, MaxIPProp */
	}
	return mi_call(fd_venc, "MI_VENC_SetRcParam", DIR_W, 42, &a, sizeof a);
}

/* JPEG snapshots (#75): VENC device 8 channel 3, as stock's (unused on MCA40E) CJpg class
 * (docs/STOCK-SNAPSHOT.md): attr from FUN_000273a0 (eType 4, MJPEG FIXQP rc 8, Qfactor), fed from
 * SCL port 1 (the sub-stream size; stock's own snapshot is 640x360 from port 1 too) with
 * FRAME_BASE at 1 fps, and left running so the latest JPEG is always at hand. Stock creates no
 * ring pool and sets no MaxStreamCnt for device 8. */
static int jpeg_on;
static mi_chn_hook_fn chn_hook;                 /* the OSD's attach point (mi.h) */

static int setup_jpeg(void)
{
	struct { uint32_t dev, maxw, maxh; } cd = { JPEG_DEV, (uint32_t)cfg.sub_w, (uint32_t)cfg.sub_h };
	if (mi_call(fd_venc, "MI_VENC_CreateDev (JPEG)", DIR_W, 76, &cd, sizeof cd)) return -1;
	struct { uint32_t dev, chn; uint32_t attr[20]; } cc;
	memset(&cc, 0, sizeof cc);
	cc.dev = JPEG_DEV; cc.chn = JPEG_CHN;
	cc.attr[0] = 4;                                              /* eType JPEG */
	cc.attr[1] = (uint32_t)cfg.sub_w; cc.attr[2] = (uint32_t)cfg.sub_h;   /* max W/H */
	((uint8_t *)cc.attr)[0x10] = 1;                              /* byFrame */
	cc.attr[5] = (uint32_t)cfg.sub_w; cc.attr[6] = (uint32_t)cfg.sub_h;   /* pic W/H */
	cc.attr[10] = 8;                                             /* RC: MJPEG fixed QP */
	cc.attr[11] = 1; cc.attr[12] = 1;                            /* 1 fps */
	cc.attr[13] = (uint32_t)(cfg.snapshot_q > 0 ? cfg.snapshot_q : 80);   /* Qfactor */
	if (mi_call(fd_venc, "MI_VENC_CreateChn (JPEG)", DIR_W, 0, &cc, sizeof cc)) return -1;
	struct chnport sp = { MOD_SCL, 0, 0, 1 }, vp = { MOD_VENC, JPEG_DEV, JPEG_CHN, 0 };
	if (sys_bind(sp, vp, cfg.sub_fps, 1, BIND_FRAME, 0)) return -1;
	if (chn_hook) chn_hook(2, JPEG_DEV, JPEG_CHN, cfg.sub_w, cfg.sub_h);
	struct { uint32_t dev, chn; } st = { JPEG_DEV, JPEG_CHN };
	if (mi_call(fd_venc, "MI_VENC_StartRecvPic (JPEG)", DIR_W, 4, &st, sizeof st)) return -1;
	jpeg_on = 1;
	return 0;
}

static int setup_venc(void)
{
	struct { uint32_t dev, maxw, maxh; } cd = { 0, (uint32_t)cfg.w, (uint32_t)cfg.h };
	if (mi_call(fd_venc, "MI_VENC_CreateDev", DIR_W, 76, &cd, sizeof cd)) return -1;

	for (uint32_t chn = 0; chn < (cfg.sub_w ? 2u : 1u); chn++) {
		int sub = chn == 1;
		struct { uint32_t dev, chn; uint32_t attr[20]; } cc;
		_Static_assert(sizeof cc == 88, "venc chn");
		cc.dev = 0; cc.chn = chn;
		venc_attr(cc.attr, sub ? cfg.sub_codec : cfg.codec, sub ? cfg.sub_w : cfg.w,
			  sub ? cfg.sub_h : cfg.h, sub ? cfg.sub_fps : cfg.fps, sub ? cfg.sub_kbps : cfg.kbps,
			  sub ? cfg.sub_gop : cfg.gop, sub ? cfg.sub_rc : cfg.rc,
			  sub ? cfg.sub_profile : cfg.profile);
		if (sub) cc.attr[3] = (uint32_t)(cfg.sub_w * cfg.sub_h);     /* stock: chn 1 bufSize = w*h */
		if (mi_call(fd_venc, "MI_VENC_CreateChn", DIR_W, 0, &cc, sizeof cc)) return -1;
		int codec = sub ? cfg.sub_codec : cfg.codec;
		if (codec == MI_H264 && venc_rc_tune(chn, sub ? cfg.sub_rc : cfg.rc, sub ? cfg.sub_fps : cfg.fps,
						      sub ? cfg.sub_kbps : cfg.kbps, sub ? cfg.sub_gop : cfg.gop))
			LOG("venc chn %u: RC param tuning failed; driver defaults\n", chn);
		struct { uint32_t dev, chn, cnt; } ms = { 0, chn, 4 };
		if (mi_call(fd_venc, "MI_VENC_SetMaxStreamCnt", DIR_W, 13, &ms, sizeof ms)) return -1;

		/* main: HW_RING like stock's main stream; sub: FRAME_BASE with frame-rate control */
		struct chnport sp = { MOD_SCL, 0, 0, chn }, vp = { MOD_VENC, 0, chn, 0 };
		if (sys_bind(sp, vp, cfg.fps, sub ? cfg.sub_fps : cfg.fps,
			     !sub && cfg.ring ? BIND_HW_RING : BIND_FRAME, 0))
			return -1;
		if (chn_hook) chn_hook((int)chn, 0, chn, sub ? cfg.sub_w : cfg.w, sub ? cfg.sub_h : cfg.h);
		struct { uint32_t dev, chn; } st = { 0, chn };
		if (mi_call(fd_venc, "MI_VENC_StartRecvPic", DIR_W, 4, &st, sizeof st)) return -1;
	}
	if (cfg.sub_w && cfg.snapshot && setup_jpeg()) {
		LOG("JPEG snapshot channel: setup failed; no snapshots\n");
		jpeg_on = 0;
	}
	return 0;
}

/* ---- 3A over the ISP IQ API (SigmaStar CUS3A; stock does this in media_server, issue #43) ---
 * Transport (FUN_0017a730 / FUN_00179ca8): Alloc_IQDataBuf nr15 -> copy -> FlushInvCache ->
 * GetIQApiData nr18 / SetIQApiData nr17 with a 24-byte header -> copy back -> Free nr16. */

enum {
	CUS3A_AE_STATS = 0x2e01,   /* 46088 B: {u32 w, h} + w x h x {r,g,b,y}; run 3: 32x32 */
	CUS3A_AE_STATUS = 0x2e05,  /* 95 B */
	CUS3A_AE_SET = 0x2e06,     /* 58 B CusAEResult_t */
	CUS3A_AWB_STATS = 0x2e07,  /* 34568 B: {u32 w, h} + w x h x {r,g,b}; run 3: 128x90 */
	CUS3A_AWB_STATUS = 0x2e09, /* 59 B */
	CUS3A_AWB_SET = 0x2e0a,    /* 24 B CusAWBResult_t */
	CUS3A_ENABLE = 0x2e08,     /* 3 B {AE, AWB, AF} */
};

struct iq_hdr { uint32_t hdr_size, data_size, cmd, chn, dev, z; };   /* 24 B */
_Static_assert(sizeof(struct iq_hdr) == 24, "iq_hdr");

static int sys_flushinv(void *va, uint32_t size)
{
	uint64_t start = (uintptr_t)va & ~(uint64_t)63, end = ((uintptr_t)va + size + 63) & ~(uint64_t)63;
	struct { uint64_t start, len; } a = { start, end - start };
	return mi_call(fd_sys, "MI_SYS_FlushInvCache", DIR_W, 27, &a, sizeof a);
}

#ifdef MI_TEST_IQ
/* Host tests (src/mi/test_mi.c) supply the transport: it passes 32-bit user addresses, which a
 * 64-bit host can't fake through ioctl(). */
static int iq_xfer(int set, uint32_t cmd, void *data, uint32_t size);
#else
/* MI_SYS_GetRunEnvOnce (libmi_sys 0x11954): /dev/mi_sys nr46, reads a u32. 0 = the IQ API
 * goes through an MMA bounce buffer; otherwise the kernel takes the caller's buffer directly
 * (FUN_0017a730 / FUN_0016eed8). */
static int run_env = -1;

static int sys_run_env(void)
{
	uint32_t env = 0;
	if (mi_call(fd_sys, "MI_SYS_GetRunEnv", DIR_R, 46, &env, sizeof env)) return -1;
	LOG("MI run env: %u\n", env);
	return (int)env;
}

static int iq_xfer(int set, uint32_t cmd, void *data, uint32_t size)
{
	if (run_env < 0) run_env = sys_run_env();
	if (run_env != 0) {
		struct { struct iq_hdr h; uint32_t data, z; } a =
			{ { 0x18, size, cmd, 0, 0, 0 }, (uint32_t)(uintptr_t)data, 0 };
		return mi_call(fd_isp, set ? "MI_ISP_SetIQApiData" : "MI_ISP_GetIQApiData", DIR_W,
			       set ? 17 : 18, &a, sizeof a);
	}
	uint32_t asize = (size + 63) & ~63u;
	struct { uint32_t size, pad; uint32_t virt, pad2; } al = { asize, 0, 0, 0 };
	if (mi_call(fd_isp, "MI_ISP_Alloc_IQDataBuf", DIR_RW, 15, &al, sizeof al) || !al.virt)
		return -1;
	void *buf = (void *)(uintptr_t)al.virt;
	memcpy(buf, data, size);
	sys_flushinv(buf, asize);
	struct { struct iq_hdr h; uint32_t data, z; } a = { { 0x18, size, cmd, 0, 0, 0 }, al.virt, 0 };
	_Static_assert(sizeof a == 32, "iq args");
	int r = mi_call(fd_isp, set ? "MI_ISP_SetIQApiData" : "MI_ISP_GetIQApiData", DIR_W,
			set ? 17 : 18, &a, sizeof a);
	sys_flushinv(buf, asize);
	if (!r) memcpy(data, buf, size);
	struct { uint32_t virt, pad, z0, z1; } fr = { al.virt, 0, 0, 0 };
	mi_call(fd_isp, "MI_ISP_Free_IQDataBuf", DIR_W, 16, &fr, sizeof fr);
	return r;
}
#endif

/* Don't call ISP nr39-44 (the vendor's MI_ISP_EnableUserspace3A ioctls): on run 2 nr39 sent
 * cold (no 0x2e08 config, no nr35) oopsed the kernel ("bad PC" in MI_DEVICE_Ioctl). */

static int want_3a(void) { return cfg.auto3a || cfg.shutter_us || cfg.wb_r; }

/* Stock MI_ISP_CreateChannel wrapper (FUN_0016e7fc): before nr2 it sets IQ 0x2e08 with 3 bytes
 * {AE, AWB, AF} (stock: 1,1,1; we have no AF lens), and after it, nr35 returns the channels
 * that run userspace 3A. */
static void cus3a_config(void)
{
	unsigned ae = 1, awb = 1, af = 0;
	if (cfg.cus3a) sscanf(cfg.cus3a, "%u:%u:%u", &ae, &awb, &af);
	uint8_t en[3] = { (uint8_t)ae, (uint8_t)awb, (uint8_t)af };
	LOG("CUS3A enables: AE %u AWB %u AF %u\n", ae, awb, af);
	iq_xfer(1, CUS3A_ENABLE, en, sizeof en);
}

static void cus3a_chn_query(void)
{
	struct { uint32_t dev, chn, count, list[2]; } q = { 0, 0, 2, { 0, 0 } };
	_Static_assert(sizeof q == 20, "nr35");
	if (!mi_call(fd_isp, "ISP nr35 CUS3A chn list", DIR_RW, 35, &q, sizeof q))
		LOG("cus3a chn list: count %u [%u %u]\n", q.count, q.list[0], q.list[1]);
}

static void hexdump(const char *tag, const uint8_t *p, unsigned n)
{
	LOG("%s:", tag);
	for (unsigned i = 0; i < n; i++) LOG("%s%02x", i % 16 ? " " : "\n  ", p[i]);
	LOG("\n");
}

static uint8_t ae_stats[46088], awb_stats[34568];
static unsigned ae_grid_seq;            /* AE stats reads by the 3A path: motion (#77) */

/* The rest of CusAEResult_t. The vendor AE (run callback 0x17d2e4 via FUN_0017bc00) fills every
 * field; runs 1-4 and rtspd v0 sent only shutter/gains and left these 0, and the image came out
 * flat, grey and soft (blacks ~85, saturation ~3 vs stock 0 / 18): f-number 0 and BV 0 likely make
 * the ISP interpolate its darkest-scene tuning. As the vendor pre-fills them, the HDR-short fields,
 * f-number and deband fps come from the kernel's own AE status, read once before our first set
 * (status +0x24..+0x2c, +0x35, +0x39); AvgY/WeightY are the measured mean Y and BV is APEX
 * (Av + Tv - Sv + scene offset) x 16384. mi_cfg.ae_extra ("legacy" or "gm=,hdr=,fn=,deband=,bv=")
 * overrides them for A/B runs. */
static struct {
	int ready, legacy, bv_fixed;
	uint32_t hshort[3];                  /* ShutterHdrShort, SensorGainHdrShort, IspGainHdrShort */
	uint32_t fn, deband, hdr, gm;        /* FNx10, DebandFPS, HdrRatio, GMBlendRatio */
	int32_t bv;
} aex = { 0, 0, 0, { 30, 1024, 1024 }, 18, 30, 0, 0, 0 };   /* run 3 kernel status at start */

static void aex_init(void)
{
	uint8_t st[95];
	memset(st, 0, sizeof st);
	if (!iq_xfer(0, CUS3A_AE_STATUS, st, sizeof st)) {
		uint32_t fn, deband;
		memcpy(aex.hshort, st + 0x24, sizeof aex.hshort);
		memcpy(&fn, st + 0x35, 4);
		memcpy(&deband, st + 0x39, 4);
		if (fn) aex.fn = fn;
		if (deband) aex.deband = deband;
	}
	for (const char *p = cfg.ae_extra; p && *p; p += strcspn(p, ",") + (p[strcspn(p, ",")] == ',')) {
		long v = strtol(p + strcspn(p, "=") + 1, NULL, 0);
		if (!strncmp(p, "legacy", 6)) aex.legacy = 1;
		else if (!strncmp(p, "gm=", 3)) aex.gm = (uint32_t)v;
		else if (!strncmp(p, "hdr=", 4)) aex.hdr = (uint32_t)v;
		else if (!strncmp(p, "fn=", 3)) aex.fn = (uint32_t)v;
		else if (!strncmp(p, "deband=", 7)) aex.deband = (uint32_t)v;
		else if (!strncmp(p, "bv=", 3)) { aex.bv_fixed = 1; aex.bv = (int32_t)v; }
	}
	aex.ready = 1;
	LOG("AE result: %s fn %u deband %u hdr %u gm %u hdr-short %u/%u/%u%s\n",
	    aex.legacy ? "LEGACY (extra fields 0)" : "vendor-like", aex.fn, aex.deband, aex.hdr, aex.gm,
	    aex.hshort[0], aex.hshort[1], aex.hshort[2], aex.bv_fixed ? " bv fixed" : "");
}

static int set_ae(uint32_t shutter_us, uint32_t gain, uint32_t isp, double y)
{
	if (!aex.ready) aex_init();
	uint8_t r[58];
	uint32_t v;
	memset(r, 0, sizeof r);
	v = sizeof r;  memcpy(r + 0x00, &v, 4);          /* Size */
	v = 1;         memcpy(r + 0x04, &v, 4);          /* Change */
	memcpy(r + 0x08, &shutter_us, 4);                /* Shutter us */
	memcpy(r + 0x0c, &gain, 4);                      /* SensorGain, 1x = 1024 */
	memcpy(r + 0x10, &isp, 4);                       /* IspGain, 1x = 1024 */
	if (!aex.legacy) {
		double t = shutter_us / 1e6, iso = 100.0 * gain / 1024, n = aex.fn / 10.0;
		double bv = log2(n * n / t) - log2(iso / 3.125) + (y > 0 ? log2(y / 46.0) : 0);
		int32_t bv_q = aex.bv_fixed ? aex.bv : (int32_t)(bv * 16384);
		uint32_t yi = y > 0 ? (uint32_t)(y + 0.5) : 0;
		uint16_t gm = (uint16_t)aex.gm;
		memcpy(r + 0x14, aex.hshort, sizeof aex.hshort);   /* HDR short shutter/gains */
		memcpy(r + 0x20, &bv_q, 4);                       /* BVx16384 */
		memcpy(r + 0x24, &yi, 4);                         /* AvgY */
		memcpy(r + 0x28, &aex.hdr, 4);                    /* HdrRatio */
		memcpy(r + 0x2c, &aex.fn, 4);                     /* FNx10 */
		memcpy(r + 0x30, &aex.deband, 4);                 /* DebandFPS */
		memcpy(r + 0x34, &yi, 4);                         /* WeightY */
		memcpy(r + 0x38, &gm, 2);                         /* GMBlendRatio */
	}
	return iq_xfer(1, CUS3A_AE_SET, r, sizeof r);
}

static int set_awb(uint32_t rg, uint32_t gg, uint32_t bg)
{
	/* Size, Change, R, G, B, ColorTmp. The vendor writes Size 0x3a here, not 24; mirror it. */
	uint32_t r[6] = { 0x3a, 1, rg, gg, bg, 5000 };
	return iq_xfer(1, CUS3A_AWB_SET, r, sizeof r);
}

/* Mean of a byte channel over the stats grid. The buffer starts with {u32 w, u32 h}; the grid
 * isn't always the buffer's full capacity (run 3: AE 32x32 in a 128x90 buffer). */
static double stats_mean(const uint8_t *s, uint32_t size, unsigned stride, unsigned ch)
{
	uint32_t w, h;
	memcpy(&w, s, 4);
	memcpy(&h, s + 4, 4);
	uint64_t n = (uint64_t)w * h;
	if (!n || 8 + n * stride > size) return -1;
	uint64_t sum = 0;
	for (uint64_t i = 0; i < n; i++) sum += s[8 + i * stride + ch];
	return (double)sum / n;
}

static void dump_3a_state(void)
{
	uint8_t st[95], wst[59];
	memset(st, 0, sizeof st); memset(wst, 0, sizeof wst);
	if (!iq_xfer(0, CUS3A_AE_STATUS, st, sizeof st)) hexdump("AE status 0x2e05", st, sizeof st);
	if (!iq_xfer(0, CUS3A_AWB_STATUS, wst, sizeof wst)) hexdump("AWB status 0x2e09", wst, sizeof wst);
	if (!iq_xfer(0, CUS3A_AE_STATS, ae_stats, sizeof ae_stats)) {
		hexdump("AE stats 0x2e01 head", ae_stats, 40);
		LOG("AE stats means r %.1f g %.1f b %.1f y %.1f\n", stats_mean(ae_stats, sizeof ae_stats, 4, 0),
		    stats_mean(ae_stats, sizeof ae_stats, 4, 1), stats_mean(ae_stats, sizeof ae_stats, 4, 2),
		    stats_mean(ae_stats, sizeof ae_stats, 4, 3));
	}
	if (!iq_xfer(0, CUS3A_AWB_STATS, awb_stats, sizeof awb_stats)) {
		hexdump("AWB stats 0x2e07 head", awb_stats, 40);
		LOG("AWB stats means r %.1f g %.1f b %.1f\n", stats_mean(awb_stats, sizeof awb_stats, 3, 0),
		    stats_mean(awb_stats, sizeof awb_stats, 3, 1), stats_mean(awb_stats, sizeof awb_stats, 3, 2));
	}
}

/* Simple AE (mean-Y target, shutter first, then sensor gain, then ISP gain) + grey-world AWB,
 * damped. */
static struct { double exp_us; uint32_t r, b; } a3 = { 10000, 1024, 1024 };
static int night;                       /* mi_night(): B/W and the night shutter limit (#30) */
static struct { double y; uint32_t shutter_us, gain, isp; int valid; } ae_last;   /* for day/night */
/* stock at night: 50 ms (MI_NIGHT_SHUTTER_US), sensor gain 4.2x (cam #2) */
static double ae_target(void);          /* the mean-Y target of the current mode (image controls) */

/* The ISP gain limit of mode m (0 day, 1 night) in x (mi_isp_gain_max; unset = 1x, no ISP gain) */
static int isp_gain_limit(int m)
{
	int x = m ? cfg.isp_gain_night_max : cfg.isp_gain_day_max;
	return x >= 1 && x <= MI_ISP_GAIN_MAX ? x : 1;
}

/* The AE's longest shutter (us): day one frame time, night stock's 50 ms, or the user's shorter
 * limit (image.shutter_day_max / _night_max). Never longer than those: the sensor would have to
 * lower its frame rate (mi.h). */
static double ae_max_shutter(void)
{
	double lim = night ? MI_NIGHT_SHUTTER_US : 1e6 / cfg.fps;
	uint32_t user = night ? cfg.shutter_night_max : cfg.shutter_day_max;
	return user && user < lim ? user : lim;
}

/* Anti-flicker (mi_antiflicker): lights on AC mains flicker at twice the mains frequency, so a
 * shutter of a whole number of half cycles always gathers the same light. Stock (0x42278) only
 * raises the kernel AE's MinShutterUS to 10000 / 8333 us; our AE also rounds the shutter down to
 * whole half cycles, which stock's kernel AE doesn't (docs/STOCK-IMAGE-TUNING.md). */
static int af_unusable;                 /* the longest shutter is under half a cycle (logged once) */

static double af_period(void)
{
	return cfg.antiflicker ? 1e6 / (2.0 * (cfg.mains_hz == 50 ? 50 : 60)) : 0;
}

/* Clamp the wanted exposure (shutter us x gain) to the AE's range and split it: shutter first up to
 * ae_max_shutter(), then sensor gain up to 32x, then ISP gain up to isp_gain_limit() (1024 = 1x).
 * With anti-flicker the shutter is 1..n half mains cycles (0.5 us of slack, so stock's 8333 us
 * counts as one at 60 Hz). With a limit of 1x the ISP gain stays 1x and the rest is exactly as
 * before it existed. */
static void ae_split(double *exp_us, uint32_t *sh, uint32_t *gain, uint32_t *isp)
{
	int ispx = isp_gain_limit(night);
	double max_sh = ae_max_shutter(), min_sh = 20, p = af_period(), s;
	if (p > 0) {
		double k = floor((max_sh + 0.5) / p);
		if (k < 1) {
			if (!af_unusable) LOG("anti-flicker: the longest shutter (%.0f us) is under half a mains "
					      "cycle (%.0f us); not applied\n", max_sh, p);
			af_unusable = 1;
			p = 0;
		} else {
			af_unusable = 0;
			min_sh = p;
			max_sh = k * p;
		}
	}
	double max_exp = max_sh * 32 * ispx;
	if (*exp_us < min_sh) *exp_us = min_sh;
	if (*exp_us > max_exp) *exp_us = max_exp;
	s = *exp_us < max_sh ? *exp_us : max_sh;
	if (p > 0) s = floor((s + 0.5) / p) * p + 0.5;      /* whole half cycles, rounded to us */
	*sh = (uint32_t)s;
	double g = *exp_us / *sh * 1024;                    /* the total gain wanted */
	*isp = 1024;
	if (ispx > 1 && g > 32 * 1024) {                    /* sensor at 32x: the ISP does the rest */
		double i = g / 32;
		*isp = (uint32_t)(i < ispx * 1024 ? i : ispx * 1024);
		g = 32 * 1024;
	}
	*gain = (uint32_t)g;
	if (*gain < 1024) *gain = 1024;
}

static void ae_step(void)
{
	if (cfg.shutter_us) {
		double y = -1;
		if (!iq_xfer(0, CUS3A_AE_STATS, ae_stats, sizeof ae_stats)) {
			y = stats_mean(ae_stats, sizeof ae_stats, 4, 3);
			ae_grid_seq++;
		}
		set_ae(cfg.shutter_us, cfg.gain ? cfg.gain : 1024, 1024, y);
		return;
	}
	if (!cfg.auto3a) return;
	if (!iq_xfer(0, CUS3A_AE_STATS, ae_stats, sizeof ae_stats)) {
		ae_grid_seq++;
		double y = stats_mean(ae_stats, sizeof ae_stats, 4, 3), target = ae_target();
		if (y < 0) return;
		if (y < 2) y = 2;
		double k = target / y;
		if (k > 2) k = 2;
		if (k < 0.5) k = 0.5;
		/* near saturation the mean understates the excess, so take the full step down */
		a3.exp_us *= y > 230 ? k : 1 + (k - 1) * 0.6;
		uint32_t sh, gain, isp;
		ae_split(&a3.exp_us, &sh, &gain, &isp);
		set_ae(sh, gain, isp, y);
		ae_last.y = y; ae_last.shutter_us = sh; ae_last.gain = gain; ae_last.isp = isp; ae_last.valid = 1;
		static unsigned logged;                 /* convergence only; -v logs every step */
		if (mi_verbose || logged++ < 16) {
			if (isp > 1024)
				LOG("AE: meanY %.1f -> shutter %u us gain %.2fx isp %.2fx\n", y, sh, gain / 1024.0,
				    isp / 1024.0);
			else
				LOG("AE: meanY %.1f -> shutter %u us gain %.2fx\n", y, sh, gain / 1024.0);
		}
	}
}

static void awb_step(void)
{
	if (cfg.wb_r) {
		set_awb(cfg.wb_r, cfg.wb_g, cfg.wb_b);
		return;
	}
	if (!cfg.auto3a) return;
	if (!iq_xfer(0, CUS3A_AWB_STATS, awb_stats, sizeof awb_stats)) {
		double r = stats_mean(awb_stats, sizeof awb_stats, 3, 0),
		       g = stats_mean(awb_stats, sizeof awb_stats, 3, 1),
		       b = stats_mean(awb_stats, sizeof awb_stats, 3, 2);
		/* skip clipped stats: grey-world on saturated blocks says nothing */
		if (r > 1 && g > 1 && b > 1 && g < 245) {
			uint32_t tr = (uint32_t)(1024 * g / r), tb = (uint32_t)(1024 * g / b);
			if (tr < 512) tr = 512;
			if (tr > 4096) tr = 4096;
			if (tb < 512) tb = 512;
			if (tb > 4096) tb = 4096;
			a3.r = (a3.r * 3 + tr) / 4;
			a3.b = (a3.b * 3 + tb) / 4;
			set_awb(a3.r, 1024, a3.b);
			static unsigned logged;
			if (mi_verbose || logged++ < 16)
				LOG("AWB: r %.1f g %.1f b %.1f -> gains r %.2f b %.2f\n", r, g, b,
				    a3.r / 1024.0, a3.b / 1024.0);
		}
	}
}

/* /dev/isp_fe: the stock 3A thread (FUN_0017cb68) polls it and reads 48-byte events. Words:
 * 0 frame-done chn mask, 1/2/3 AE/AWB/AF enable-request masks, 4 re-init mask, 5 status mask,
 * 6/7 command, 8/9/10 AE/AWB/AF skip-this-frame masks. It acks an enable or disable with a
 * 20-byte write {0, 0, chn, type 0 AE / 1 AWB / 2 AF, u8 on}. */
static int fd_fe = -1;
static unsigned fe_events, ae_runs, awb_runs;
static uint8_t ae_on, awb_on;

static void fe_ack(uint32_t type, uint8_t on)
{
	struct { uint32_t z0, z1, chn, type; uint8_t on, pad[3]; } a = { 0, 0, 0, type, on, { 0 } };
	_Static_assert(sizeof a == 20, "isp_fe ack");
	ssize_t n = write(fd_fe, &a, sizeof a);
	LOG("isp_fe ack type %u on %u -> %zd%s%s\n", type, on, n, n < 0 ? " " : "",
	    n < 0 ? strerror(errno) : "");
}

static void fe_event(void)
{
	uint32_t ev[12];
	memset(ev, 0, sizeof ev);
	ssize_t n = read(fd_fe, ev, sizeof ev);
	if (n <= 0) return;
	if (fe_events++ < 8 || mi_verbose > 1)
		hexdump("isp_fe event", (uint8_t *)ev, (unsigned)n);
	if ((ev[1] & 1) != ae_on) { ae_on = ev[1] & 1; fe_ack(0, ae_on); }
	if ((ev[2] & 1) != awb_on) { awb_on = ev[2] & 1; fe_ack(1, awb_on); }
	if (!(ev[0] & 1)) return;                        /* no frame done on chn 0 */
	if (ae_on && !(ev[8] & 1) && ae_runs++ % 3 == 0) ae_step();
	if (awb_on && !(ev[9] & 1) && awb_runs++ % 3 == 0) awb_step();
}

static void setup_3a(void)
{
	if (!want_3a())
		return;
	fd_fe = open("/dev/isp_fe", O_RDWR);
	if (fd_fe < 0)
		LOG("open /dev/isp_fe: %s (3A falls back to the encoder loop)\n", strerror(errno));
	dump_3a_state();
}

/* ---- VENC stream: ring-buffer protocol (GetStream FUN_0016c1f4 / ReleaseStream FUN_0016cd8c) */

/* Per encoder stream (0 = main VENC 0/0, 1 = sub 0/1, 2 = JPEG snapshot 8/3): its /dev/mi_poll
 * fd and the mapped output buffer. */
static struct venc_stream {
	uint32_t dev, chn;
	int fd_poll;
	struct { uint64_t buf_id, phys; uint32_t size; void *virt; } ring;
	unsigned frames, empty_reads;
} vst[MI_NSTREAMS] = { { 0, 0, -1, { 0 }, 0, 0 }, { 0, 1, -1, { 0 }, 0, 0 },
		       { JPEG_DEV, JPEG_CHN, -1, { 0 }, 0, 0 } };

static int venc_map_ring(uint32_t idx)
{
	struct venc_stream *v = &vst[idx];
	struct { uint32_t dev, chn; uint64_t buf_id; } q = { v->dev, v->chn, 0 };
	if (mi_call(fd_venc, "VENC nr54 cur buf", DIR_RW, 54, &q, sizeof q)) return -1;
	if (v->ring.virt && q.buf_id == v->ring.buf_id) return 0;
	if (v->ring.virt) { sys_munmap(v->ring.virt, v->ring.size); v->ring.virt = NULL; }
	struct { uint64_t buf_id, phys; uint32_t size, pad; } bi = { q.buf_id, 0, 0, 0 };
	_Static_assert(sizeof bi == 24, "nr55");
	if (mi_call(fd_venc, "VENC nr55 buf info", DIR_RW, 55, &bi, sizeof bi)) return -1;
	v->ring.buf_id = q.buf_id; v->ring.phys = bi.phys; v->ring.size = bi.size;
	LOG("venc %u/%u ring: id %#llx phys %#llx size %u\n", v->dev, v->chn, (unsigned long long)q.buf_id,
	    (unsigned long long)bi.phys, bi.size);
	return sys_mmap(v->ring.phys, v->ring.size, &v->ring.virt);
}

/* nr57 args, 80 B: offsets from the GetStream wrapper's stack layout */
struct slice {
	uint32_t dev, chn;      /* 0x00 */
	uint64_t buf_id;        /* 0x08 in */
	uint32_t flags;         /* 0x10 out: bit0 frame end, bits1-3 codec, bit7 new frame */
	uint32_t pad14;
	uint64_t pts;           /* 0x18 */
	uint32_t seq;           /* 0x20 */
	uint32_t pad24;
	uint32_t spec0, spec1;  /* 0x28, 0x2c */
	uint64_t phys;          /* 0x30 */
	uint32_t len;           /* 0x38 */
	uint32_t timeout_ms;    /* 0x3c in */
	uint8_t  b40, p41[3];   /* 0x40 */
	uint32_t x44, x48, x4c;
};
_Static_assert(sizeof(struct slice) == 80, "slice");

static int venc_release(uint32_t idx, uint32_t nslices)
{
	struct venc_stream *v = &vst[idx];
	struct { uint32_t dev, chn; uint64_t buf_id; } r = { v->dev, v->chn, v->ring.buf_id };
	for (uint32_t i = 0; i < nslices; i++) {
		mi_call(fd_venc, "VENC nr69 release slice", DIR_W, 69, &r, sizeof r);
		mi_call(fd_venc, "VENC nr60 put slice", DIR_W, 60, &r, sizeof r);
	}
	uint8_t fin[88];                                     /* {u32 dev; u32 chn; …} */
	memset(fin, 0, sizeof fin);
	memcpy(fin, &v->dev, 4);
	memcpy(fin + 4, &v->chn, 4);
	return mi_call(fd_venc, "VENC nr11 release stream", DIR_W, 11, fin, sizeof fin);
}


/* ---- IQ profile (#36) ---------------------------------------------------------------------
 * Under our pipeline the kernel's IQ file leaves black level, CCM, saturation and gamma disabled
 * with generic tables (iq-diff 2026-10-22), while stock media_server's ISP runs tuned, enabled
 * modules. An iq-dump taken under stock is a complete copy of that tuning; applying its image-
 * pipeline groups (not AE/AWB/AF, info or dummy groups) reproduces it. File records:
 * {u32 id, u32 size, s32 ret, data[size]} (tools/iq-dump). */
/* Applied: the image-pipeline API groups (isp_api.xml Ids 4098..4999, plus BypassItem 10243),
 * minus APIVer 4097 and the Dummy groups 4147/4148. AE (5xxx), AWB (6xxx), AF (7xxx), calibration
 * and debug groups are left to our 3A. Read-only (info) groups just fail the set. */
static int iq_profile_wanted(uint32_t id)
{
	if (id == 10243) return 1;
	return id > 4097 && id < 5000 && id != 4147 && id != 4148;
}

static void iq_profile_apply(const char *spec)
{
	char path[256];
	snprintf(path, sizeof path, "%s", spec);
	path[strcspn(path, "@")] = 0;
	FILE *f = fopen(path, "rb");
	if (!f) { LOG("IQ profile %s: %s\n", path, strerror(errno)); return; }
	static uint8_t buf[32768];
	unsigned set = 0, failed = 0;
	uint32_t hdr[3];
	while (fread(hdr, 4, 3, f) == 3) {
		uint32_t id = hdr[0], size = hdr[1];
		if (size > sizeof buf || fread(buf, 1, size, f) != size) break;
		if (!iq_profile_wanted(id) || hdr[2] != 0) continue;
		if (iq_xfer(1, id, buf, size)) failed++;
		else set++;
	}
	fclose(f);
	LOG("IQ profile %s: %u groups set, %u failed\n", path, set, failed);
}

/* ---- stock night tuning: state (functions after the ISP tuning) -----------------------------
 * The two files (iq-dump records, same ids in the same order): [1] the night versions of the image
 * groups stock's night bin changes, [0] the day versions of the same ids. live says which of the two
 * the ISP holds, and so which baselines the image controls and the ISP tuning scale (0 = day: with
 * night tuning off it never changes, and everything runs as before). */
enum { NT_MAX = 64, NT_GROUP_MAX = 32768 };
static struct {
	int loaded, on, live;
	unsigned n;
	uint32_t id[NT_MAX], size[NT_MAX];
	const uint8_t *data[2][NT_MAX];
	uint8_t *file[2];
} nt;

static const uint8_t *nt_night_data(uint32_t id, uint32_t size);

/* ---- user image controls (#73) ------------------------------------------------------------
 * The baseline of each group is read once, after the IQ profile is applied, so 50 means "as the
 * profile has it" and other values are offsets or scalings of that, keeping the ISO-dependent
 * shape of the stock tuning. Layouts from isp_api.xml. Baselines per mode: [0] day (read from the
 * ISP), [1] night (the night file's version of the group, else the day one). */
enum { IQ_BRIGHTNESS = 4102, IQ_CONTRAST = 4101, IQ_SATURATION = 4106, IQ_SHARPNESS = 4114,
       IQ_COLOR_TO_GRAY = 4100 };

static struct {
	int value[MI_IMG_COUNT];
	int pending[MI_IMG_COUNT];              /* set before the IQ profile was in */
	int ready;                              /* baselines captured */
	double ae_base;
	uint8_t bri[2][76], con[2][76], sat[2][416], shp[2][6200];
} img = { .value = { 50, 50, 50, 50, 50 } };

static unsigned image_ready_frame(void)
{
	if (!cfg.iq_profile) return 12;
	const char *at = strchr(cfg.iq_profile, '@');
	return (at ? (unsigned)atoi(at + 1) : 10) + 2;
}

static int clampi(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

/* Levels (u32[16] auto at +8, u32 manual at +72, range 0..100) offset by delta, into g. */
static void image_levels(uint8_t *g, const uint8_t *base, int delta)
{
	memcpy(g, base, 76);
	for (int i = 0; i < 17; i++) {
		uint32_t v;
		memcpy(&v, g + 8 + 4 * i, 4);            /* 16 auto + the manual one at +72 */
		v = (uint32_t)clampi((int)v + delta, 0, 100);
		memcpy(g + 8 + 4 * i, &v, 4);
	}
}

/* u8 strengths at the given offsets scaled by num/50, clamped to max, into g. */
static void image_scale(uint8_t *g, const uint8_t *base, size_t size, const int (*spans)[2],
			int nspans, int value, int max)
{
	memcpy(g, base, size);
	for (int k = 0; k < nspans; k++)
		for (int i = 0; i < spans[k][1]; i++)
			g[spans[k][0] + i] = (uint8_t)clampi(base[spans[k][0] + i] * value / 50, 0, max);
}

/* The IQ group of image control w and its size (0 for exposure, which is our AE's target). */
static uint32_t image_group(int w, uint32_t *size)
{
	static const uint32_t id[MI_IMG_COUNT] = { IQ_BRIGHTNESS, IQ_CONTRAST, IQ_SATURATION, IQ_SHARPNESS, 0 };
	static const uint32_t sz[MI_IMG_COUNT] = { 76, 76, 416, 6200, 0 };
	*size = w >= 0 && w < MI_IMG_COUNT ? sz[w] : 0;
	return w >= 0 && w < MI_IMG_COUNT ? id[w] : 0;
}

/* Control w's group for value v from mode m's baseline (m: 0 day, 1 night), into g. */
static void image_build(int w, int m, int v, uint8_t *g)
{
	static const int sat_spans[][2] = { { 8, 16 }, { 392, 1 } };       /* SatAllStr auto, manual */
	static const int shp_spans[][2] = { { 5708, 16 }, { 6192, 1 } };   /* BranchStrength */
	switch (w) {
	case MI_IMG_BRIGHTNESS: image_levels(g, img.bri[m], v - 50); break;
	case MI_IMG_CONTRAST:   image_levels(g, img.con[m], v - 50); break;
	case MI_IMG_SATURATION: image_scale(g, img.sat[m], sizeof img.sat[m], sat_spans, 2, v, 127); break;
	case MI_IMG_SHARPNESS:  image_scale(g, img.shp[m], sizeof img.shp[m], shp_spans, 2, v, 255); break;
	}
}

/* The AE target for exposure value v (0..100): a stop per 25 from the base target, 4..200 */
static double exposure_target(int v)
{
	double t = img.ae_base * pow(2.0, (v - 50) / 25.0);
	return t < 4 ? 4 : t > 200 ? 200 : t;
}

/* image.exposure_night (mi_exposure_night): MI_EXPOSURE_SAME or 0..100 */
static int exp_night = MI_EXPOSURE_SAME;

/* By day (and at night without its own value) cfg.ae_target, which image.exposure sets as before;
 * at night with image.exposure_night, its target. Before the IQ baselines are in, the base target
 * either way (as image.exposure's value waits until then). */
static double ae_target(void)
{
	if (!night || exp_night == MI_EXPOSURE_SAME || !img.ready) return cfg.ae_target;
	return exposure_target(exp_night);
}

int mi_exposure_night(int value)
{
	if (value != MI_EXPOSURE_SAME && (value < 0 || value > 100)) return -1;
	if (value != exp_night) {
		if (value == MI_EXPOSURE_SAME) LOG("AE: night exposure as by day (image.exposure)\n");
		else LOG("AE: night exposure %d\n", value);
	}
	exp_night = value;
	return 0;
}

int mi_exposure_night_get(void)
{
	return exp_night;
}

static int image_apply(int what, int value)
{
	static uint8_t g[6200];
	uint32_t size, id = image_group(what, &size);
	if (what == MI_IMG_EXPOSURE) {
		cfg.ae_target = exposure_target(value);
		return 0;
	}
	if (!id) return -1;
	image_build(what, nt.live, value, g);           /* the baseline of the groups the ISP holds */
	return iq_xfer(1, id, g, size);
}

/* Night baseline: the night file's version of the group, else the day one (the same at night). */
static void image_night_base(uint8_t *nb, const uint8_t *db, uint32_t id, uint32_t size)
{
	const uint8_t *d = nt_night_data(id, size);
	memcpy(nb, d ? d : db, size);
}

static void image_capture(void)
{
	if (iq_xfer(0, IQ_BRIGHTNESS, img.bri[0], sizeof img.bri[0]) ||
	    iq_xfer(0, IQ_CONTRAST, img.con[0], sizeof img.con[0]) ||
	    iq_xfer(0, IQ_SATURATION, img.sat[0], sizeof img.sat[0]) ||
	    iq_xfer(0, IQ_SHARPNESS, img.shp[0], sizeof img.shp[0])) {
		LOG("image controls: baseline read failed; controls disabled\n");
		return;
	}
	image_night_base(img.bri[1], img.bri[0], IQ_BRIGHTNESS, sizeof img.bri[0]);
	image_night_base(img.con[1], img.con[0], IQ_CONTRAST, sizeof img.con[0]);
	image_night_base(img.sat[1], img.sat[0], IQ_SATURATION, sizeof img.sat[0]);
	image_night_base(img.shp[1], img.shp[0], IQ_SHARPNESS, sizeof img.shp[0]);
	img.ae_base = cfg.ae_target;
	img.ready = 1;
	if (night) mi_night(1);                 /* the IQ profile may have reset ColorToGray */
	for (int w = 0; w < MI_IMG_COUNT; w++)
		if (img.pending[w] && image_apply(w, img.value[w]))
			LOG("image control %d: apply failed\n", w);
}

static int nt_can_write(void);
static int nt_write(int m);
static int nt_has(uint32_t id);

/* Night (#30): black and white (IQ ColorToGray, which applies live: 2026-10-22 extreme-IQ run)
 * and a longer AE shutter limit. Before the IQ baselines are in, only remembered. With stock night
 * tuning on, night also writes the night groups (their ColorToGray follows the B/W state); the day
 * groups come back with mi_night_day(). */
int mi_night(int on)
{
	night = on ? 1 : 0;
	if (!img.ready) return 0;
	int r = 0;
	if (night && nt.on && nt_can_write()) {
		r = nt_write(1);
		if (nt_has(IQ_COLOR_TO_GRAY)) return r;
	}
	uint32_t g = (uint32_t)night;
	int x = iq_xfer(1, IQ_COLOR_TO_GRAY, &g, sizeof g);
	return x ? x : r;
}

/* ---- sensor orientation (docs/STOCK-ENCODE-IMAGE.md section 3) ------------------------------
 * Stock's CIsp::SetMirror: MI_SNR_SetOrien (SNR nr12, 8 B {u32 pad; u8 mirror; u8 flip; u8 [2]}),
 * then MI_SNR_GetOrien (nr13, same layout, read back) until it matches, up to 10 times 100 ms apart.
 * Stock calls it at init and again whenever the web flip settings change, while streaming. We read
 * it back without blocking the caller: every 3rd main-stream frame (~120 ms at 25 fps), 10 times. */
enum { ORIENT_CHECKS = 10 };
static int orient_checks;              /* GetOrien read-backs left */

static int snr_orien(int set, int *mirror, int *flip)
{
	struct { uint32_t pad; uint8_t mirror, flip, p[2]; } a = {
		0, (uint8_t)(set && *mirror), (uint8_t)(set && *flip), { 0, 0 } };
	_Static_assert(sizeof a == 8, "snr orien");
	int r = set ? mi_call(fd_snr, "MI_SNR_SetOrien", DIR_W, 12, &a, sizeof a)
		    : mi_call_q(fd_snr, "MI_SNR_GetOrien", DIR_RW, 13, &a, sizeof a, 1);
	if (!r && !set) { *mirror = a.mirror; *flip = a.flip; }
	return r;
}

static void orient_poll(void)
{
	int m = -1, f = -1;
	if (!orient_checks) return;
	orient_checks--;
	int r = snr_orien(0, &m, &f);
	if (!r && m == cfg.mirror && f == cfg.flip) {
		LOG("sensor orientation: mirror %d flip %d (read back)\n", m, f);
		orient_checks = 0;
	} else if (!orient_checks) {
		if (r) LOG("sensor orientation: MI_SNR_GetOrien failed; wanted mirror %d flip %d\n", cfg.mirror, cfg.flip);
		else LOG("sensor orientation: reads mirror %d flip %d, wanted %d %d\n", m, f, cfg.mirror, cfg.flip);
	}
}

int mi_orient(int mirror, int flip)
{
	if (mirror < 0 || mirror > 1 || flip < 0 || flip > 1) return -1;
	cfg.mirror = mirror;
	cfg.flip = flip;
	if (fd_snr < 0) return 0;               /* not started: mi_start applies cfg */
	orient_checks = ORIENT_CHECKS;
	if (snr_orien(1, &mirror, &flip)) return -1;
	LOG("sensor orientation: set mirror %d flip %d\n", mirror, flip);
	return 0;
}

void mi_orient_get(int *mirror, int *flip)
{
	*mirror = cfg.mirror;
	*flip = cfg.flip;
}

int mi_shutter_max(uint32_t day_us, uint32_t night_us)
{
	if ((day_us && (day_us < MI_SHUTTER_MIN_US || day_us > MI_DAY_SHUTTER_MAX_US)) ||
	    (night_us && (night_us < MI_SHUTTER_MIN_US || night_us > MI_NIGHT_SHUTTER_US)))
		return -1;
	cfg.shutter_day_max = day_us;
	cfg.shutter_night_max = night_us;
	return 0;
}

void mi_shutter_max_get(uint32_t *day_us, uint32_t *night_us)
{
	*day_us = cfg.shutter_day_max;
	*night_us = cfg.shutter_night_max;
}

int mi_isp_gain_max(int day_x, int night_x)
{
	if (day_x < 1 || day_x > MI_ISP_GAIN_MAX || night_x < 1 || night_x > MI_ISP_GAIN_MAX) return -1;
	if (day_x != cfg.isp_gain_day_max || night_x != cfg.isp_gain_night_max)
		LOG("AE: ISP gain up to %dx by day, %dx at night\n", day_x, night_x);
	cfg.isp_gain_day_max = day_x;
	cfg.isp_gain_night_max = night_x;
	return 0;
}

void mi_isp_gain_max_get(int *day_x, int *night_x)
{
	*day_x = isp_gain_limit(0);
	*night_x = isp_gain_limit(1);
}

int mi_antiflicker(int on, int hz)
{
	if ((on != 0 && on != 1) || (hz != 50 && hz != 60)) return -1;
	if (on != cfg.antiflicker || hz != cfg.mains_hz)
		LOG("anti-flicker: %s (%d Hz mains)\n", on ? "on" : "off", hz);
	cfg.antiflicker = on;
	cfg.mains_hz = hz;
	af_unusable = 0;                        /* say it again if it still can't apply */
	return 0;
}

void mi_antiflicker_get(int *on, int *hz)
{
	*on = cfg.antiflicker;
	*hz = cfg.mains_hz == 50 ? 50 : 60;
}

/* ---- ISP tuning: noise reduction, WDR, backlight (docs/STOCK-IMAGE-TUNING.md) ---------------
 * Stock's live apply (day) is read-compare-write on three IQ API groups; we do the same, day and
 * night. Each group is read whole at its exact size, only the 16 per-ISO auto strength fields
 * change (never bEnable, opType or anything else), and it is written back only when one of them
 * differs. The baseline is the IQ profile's value per entry, read when the image controls capture
 * theirs (after the profile is applied). Layouts: isp_api.xml, checked against iq-profile-stock
 * (= gc4023_day.bin): BlendRatio 0,0,0,0,0,1..11; MdGain 200,220,..,120; Strength 200,200,..,150. */
enum { IQ_NR3D = 4110, IQ_NR_DESPIKE = 4111, IQ_WDR = 4118 };
enum { TG_NR2D, TG_NR3D, TG_WDR, TG_N, TUNE_ENTRIES = 16, TUNE_GROUP_MAX = 2632 };
static const struct tune_group {
	uint32_t id, size;              /* IQ API group and its exact size */
	unsigned first, stride, field;  /* auto entry i's field at first + i x stride + field */
	unsigned wide, max;             /* u16 (else u8), the XML maximum */
	unsigned box_max;               /* WDR BoxNum 1..4 (the others have none: 1) */
	const char *name;
} tg[TG_N] = {
	{ IQ_NR_DESPIKE, 1476, 0x0c, 0x56, 0, 0, 16, 1, "NRDeSpike BlendRatio (2D NR)" },
	{ IQ_NR3D, 2632, 0x0c, 0x9a, 4, 1, 10230, 1, "NR3D MdGain (3D NR)" },
	{ IQ_WDR, 1036, 0x10, 60, 0, 0, 255, 4, "WDR Strength" },
};

static struct {
	int value[MI_TUNE_COUNT];
	int ready;                              /* baselines read (or tried) */
	int ok[2][TG_N];                        /* baseline read and plausible: [0] day, [1] night */
	uint16_t base[2][TG_N][TUNE_ENTRIES];
} tune = { { 128, 128, 0, 0 }, 0, { { 0 } }, { { { 0 } } } };

static unsigned tg_get(const uint8_t *g, int k, int i)
{
	const uint8_t *p = g + tg[k].first + (unsigned)i * tg[k].stride + tg[k].field;
	uint16_t v;
	if (!tg[k].wide) return *p;
	memcpy(&v, p, 2);
	return v;
}

static void tg_put(uint8_t *g, int k, int i, unsigned v)
{
	uint8_t *p = g + tg[k].first + (unsigned)i * tg[k].stride + tg[k].field;
	uint16_t w = (uint16_t)v;
	if (tg[k].wide) memcpy(p, &w, 2);
	else *p = (uint8_t)v;
}

/* What entry i of group k should hold for the current values, from mode m's baseline */
static unsigned tune_want(int m, int k, int i)
{
	unsigned b = tune.base[m][k][i], v;
	if (k == TG_NR2D) v = b * (unsigned)tune.value[MI_TUNE_NR2D] / 128;
	else if (k == TG_NR3D) v = b * (unsigned)tune.value[MI_TUNE_NR3D] / 128;
	else if (tune.value[MI_TUNE_WDR]) v = b * (unsigned)tune.value[MI_TUNE_WDR] / 128;
	else v = tune.value[MI_TUNE_BLC] ? (unsigned)tune.value[MI_TUNE_BLC] : b;
	return v > tg[k].max ? tg[k].max : v;
}

/* Group k's 16 strengths in g set for mode m: the number of entries changed */
static int tune_fill(uint8_t *g, int m, int k)
{
	int changed = 0;
	for (int i = 0; i < TUNE_ENTRIES; i++) {
		unsigned want = tune_want(m, k, i);
		if (tg_get(g, k, i) != want) { tg_put(g, k, i, want); changed++; }
	}
	return changed;
}

/* Read group k, set its strengths (against the baseline of the groups the ISP holds: nt.live),
 * write it back if one changed: 0 if done (or nothing to do), -1 if the group is unusable or the
 * read or the write failed. */
static int tune_apply(int k)
{
	static uint8_t g[TUNE_GROUP_MAX];
	int m = nt.live;
	if (!tune.ok[m][k]) return -1;
	memset(g, 0, tg[k].size);
	if (iq_xfer(0, tg[k].id, g, tg[k].size)) {
		LOG("ISP tuning: %s: read failed; left alone\n", tg[k].name);
		return -1;
	}
	int changed = tune_fill(g, m, k);
	if (!changed) return 0;
	if (iq_xfer(1, tg[k].id, g, tg[k].size)) {
		LOG("ISP tuning: %s: write failed\n", tg[k].name);
		return -1;
	}
	LOG("ISP tuning: %s: %d of %d entries changed\n", tg[k].name, changed, TUNE_ENTRIES);
	return 0;
}

/* Group k's baseline for mode m from its contents g: 1 if the header and values are in the XML
 * ranges, else 0 (logged). */
static int tune_base(const uint8_t *g, int m, int k)
{
	uint32_t en, op, box = 1;
	unsigned top = 0;
	memcpy(&en, g, 4);
	memcpy(&op, g + 8, 4);
	if (k == TG_WDR) box = g[12];
	for (int i = 0; i < TUNE_ENTRIES; i++) {
		tune.base[m][k][i] = (uint16_t)tg_get(g, k, i);
		if (tune.base[m][k][i] > top) top = tune.base[m][k][i];
	}
	if (top > tg[k].max || en > 1 || op > 1 || box < 1 || box > tg[k].box_max) {
		LOG("ISP tuning: %s%s: unexpected contents (enable %u, opType %u, BoxNum %u, largest value %u "
		    "of at most %u); left alone\n", tg[k].name, m ? " (night)" : "", en, op, box, top, tg[k].max);
		return 0;
	}
	if (op) LOG("ISP tuning: %s%s is in manual mode; the per-ISO values set here won't show\n", tg[k].name,
		    m ? " (night)" : "");
	return 1;
}

/* After the IQ profile: each group's baseline, then the values set so far. A group that can't be
 * read, or whose header or values are out of the XML ranges (a layout we don't know), is logged
 * once and never written. The night baseline is the night file's version of the group (checked
 * the same way), or the day one where night tuning doesn't change the group. */
static void tune_capture(void)
{
	static uint8_t g[TUNE_GROUP_MAX];
	for (int k = 0; k < TG_N; k++) {
		memset(g, 0, tg[k].size);
		if (iq_xfer(0, tg[k].id, g, tg[k].size)) {
			LOG("ISP tuning: %s (IQ %u, %u B): unreadable; left alone\n", tg[k].name, tg[k].id, tg[k].size);
			continue;
		}
		tune.ok[0][k] = tune_base(g, 0, k);
	}
	for (int k = 0; k < TG_N; k++) {
		const uint8_t *d = nt_night_data(tg[k].id, tg[k].size);
		if (d) {
			tune.ok[1][k] = tune_base(d, 1, k);
		} else {
			memcpy(tune.base[1][k], tune.base[0][k], sizeof tune.base[0][k]);
			tune.ok[1][k] = tune.ok[0][k];
		}
	}
	tune.ready = 1;
	for (int k = 0; k < TG_N; k++)
		if (tune.ok[0][k]) tune_apply(k);
}

int mi_tune_set(int what, int value)
{
	if (what < 0 || what >= MI_TUNE_COUNT || value < 0 || value > 255) return -1;
	tune.value[what] = value;
	if (!tune.ready) return 0;              /* tune_capture applies it */
	return tune_apply(what == MI_TUNE_NR2D ? TG_NR2D : what == MI_TUNE_NR3D ? TG_NR3D : TG_WDR);
}

int mi_tune_get(int what)
{
	return what >= 0 && what < MI_TUNE_COUNT ? tune.value[what] : -1;
}

/* ---- stock night tuning (image.night_tuning; docs/STOCK-IMAGE-TUNING.md section 4) ----------
 * Stock loads gc4023_night.bin at night and gc4023_day.bin by day (MI_ISP_API_CmdLoadBinFile: the
 * same SetIQApiData path as iq_xfer). scripts/iq-bin2profile.py keeps the image groups that differ
 * (iq-night.bin) and the day versions of the same ids (iq-day-switch.bin). Both are checked here
 * again, record by record, before anything is used: the id must be an iq_groups.h group of exactly
 * that size, in the range the IQ profile applies, and not an AE/AWB/AF, info, Temperature or
 * Day/Night Mode group; the files must list the same ids in the same order, each once. A switch
 * reads every group and writes only those whose contents differ. What is written for a group: the
 * file's version, with ColorToGray following the B/W state, the image controls' groups built from
 * that mode's baseline (unless at 50), and the NR/WDR/BLC strengths set from that mode's baseline. */
static void nt_free(void)
{
	free(nt.file[0]);
	free(nt.file[1]);
	memset(&nt, 0, sizeof nt);
}

static int nt_group_ok(uint32_t id, uint32_t size)
{
	static const char *const skip[] = { "AE/", "AEParam/", "AEInfo/", "AWB/", "AWBInfo/", "AWBCTCali/", "AF/",
					    "AFHW/", "APIVer/", "Dummy/", "Temperature/", "Day/Night Mode/" };
	if (!iq_profile_wanted(id) || size > NT_GROUP_MAX) return 0;
	for (unsigned i = 0; i < sizeof iq_groups / sizeof iq_groups[0]; i++) {
		if (iq_groups[i].id != id) continue;
		const char *name = iq_groups[i].name, *slash = strrchr(name, '/');
		size_t nl = slash ? strlen(slash + 1) : 0;
		if (iq_groups[i].size != size || !slash || (nl >= 4 && !strcmp(slash + 1 + nl - 4, "Info")))
			return 0;                       /* another size, or a read-only info group */
		for (unsigned k = 0; k < sizeof skip / sizeof skip[0]; k++)
			if ((size_t)(slash + 1 - name) == strlen(skip[k]) && !strncmp(name, skip[k], strlen(skip[k])))
				return 0;
		return 1;
	}
	return 0;
}

/* Read file m (1 night, 0 day; night first): 0, or -1 with the reason logged. */
static int nt_read(const char *path, int m)
{
	enum { FILE_MAX = 256 * 1024 };
	FILE *f = fopen(path, "rb");
	if (!f) { LOG("night tuning: %s: %s\n", path, strerror(errno)); return -1; }
	uint8_t *b = malloc(FILE_MAX + 1);
	size_t len = b ? fread(b, 1, FILE_MAX + 1, f) : 0;
	fclose(f);
	nt.file[m] = b;
	const char *why = !b ? "out of memory" : len > FILE_MAX ? "too large" : !len ? "empty" : NULL;
	unsigned n = 0;
	for (size_t off = 0; !why && off < len; n++) {
		uint32_t id, size;
		int32_t ret;
		if (len - off < 12) { why = "truncated record"; break; }
		memcpy(&id, b + off, 4);
		memcpy(&size, b + off + 4, 4);
		memcpy(&ret, b + off + 8, 4);
		if (size > len - off - 12) why = "truncated record";
		else if (ret != 0) why = "a record with an error code";
		else if (!nt_group_ok(id, size)) why = "a group that isn't a known image group of that size";
		else if (n == NT_MAX) why = "too many records";
		else if (m == 0 && (n >= nt.n || nt.id[n] != id || nt.size[n] != size)) why = "ids differ from the night file";
		for (unsigned i = 0; !why && m == 1 && i < n; i++)
			if (nt.id[i] == id) why = "an id twice";
		if (why) {
			LOG("night tuning: %s: record %u (id %u, %u B): %s\n", path, n, id, size, why);
			return -1;
		}
		nt.id[n] = id;
		nt.size[n] = size;
		nt.data[m][n] = b + off + 12;
		off += 12 + (size_t)size;
	}
	if (!why && m == 0 && n != nt.n) why = "fewer records than the night file";
	if (why) {
		LOG("night tuning: %s: %s\n", path, why);
		return -1;
	}
	nt.n = n;
	return 0;
}

static void nt_load(const char *night_path, const char *day_path)
{
	nt_free();
	if (nt_read(night_path, 1) || nt_read(day_path, 0)) {
		nt_free();
		LOG("night tuning: unavailable\n");
		return;
	}
	nt.loaded = 1;
	LOG("night tuning: %u groups from %s and %s\n", nt.n, night_path, day_path);
}

static int nt_has(uint32_t id)
{
	for (unsigned i = 0; i < nt.n; i++)
		if (nt.id[i] == id) return 1;
	return 0;
}

/* The night file's version of group id (NULL if night tuning doesn't change it or isn't loaded) */
static const uint8_t *nt_night_data(uint32_t id, uint32_t size)
{
	for (unsigned i = 0; nt.loaded && i < nt.n; i++)
		if (nt.id[i] == id && nt.size[i] == size) return nt.data[1][i];
	return NULL;
}

/* Everything a switch needs: the files, and the image controls' and ISP tuning's baselines */
static int nt_can_write(void)
{
	return nt.loaded && img.ready && tune.ready;
}

/* Group i of mode m (0 day, 1 night) as it should be now, into g */
static void nt_build(unsigned i, int m, uint8_t *g)
{
	uint32_t id = nt.id[i], v = (uint32_t)night;
	memcpy(g, nt.data[m][i], nt.size[i]);
	if (id == IQ_COLOR_TO_GRAY) memcpy(g, &v, 4);
	for (int w = 0; w < MI_IMG_COUNT; w++) {
		uint32_t size;
		if (image_group(w, &size) == id && size == nt.size[i] && img.value[w] != 50)
			image_build(w, m, img.value[w], g);
	}
	for (int k = 0; k < TG_N; k++)
		if (tg[k].id == id && tg[k].size == nt.size[i] && tune.ok[m][k]) tune_fill(g, m, k);
}

/* Switch the ISP to mode m's groups: each read, and written only if it differs. 0, or -1 if a
 * write failed. */
static int nt_write(int m)
{
	static uint8_t want[NT_GROUP_MAX], cur[NT_GROUP_MAX];
	unsigned set = 0, same = 0, failed = 0;
	nt.live = m;
	for (unsigned i = 0; i < nt.n; i++) {
		uint32_t id = nt.id[i], size = nt.size[i];
		nt_build(i, m, want);
		memset(cur, 0, size);
		if (!iq_xfer(0, id, cur, size) && !memcmp(cur, want, size)) { same++; continue; }
		if (iq_xfer(1, id, want, size)) failed++;
		else set++;
	}
	LOG("night tuning: %s groups: %u written, %u unchanged, %u failed\n", m ? "night" : "day", set, same, failed);
	return failed ? -1 : 0;
}

int mi_night_day(void)
{
	if (!nt.live || night || !nt_can_write()) return 0;
	return nt_write(0);
}

int mi_night_tuning(int on)
{
	if ((on != 0 && on != 1) || (on && !nt.loaded)) return -1;
	if (on != nt.on) LOG("night tuning: %s\n", on ? "on" : "off");
	nt.on = on;
	if (!nt_can_write()) return 0;          /* the IQ profile isn't in yet: mi_read_stream applies it */
	if (on && night && !nt.live) return nt_write(1);
	if (!on && nt.live) return nt_write(0);
	return 0;
}

int mi_night_tuning_get(void)
{
	return nt.on;
}

/* Once the IQ profile is in (frame image_ready_frame()): the day baselines and the values set so
 * far, then, if it is night with night tuning on, the night groups (after both captures, so the
 * day baselines are never read from night groups). */
static void image_ready(void)
{
	image_capture();
	tune_capture();
	if (night && nt.on && nt_can_write()) nt_write(1);
}

unsigned mi_ae_grid(uint8_t *y, unsigned cap, unsigned *w, unsigned *h)
{
	uint32_t gw, gh;
	if (!ae_grid_seq) return 0;
	memcpy(&gw, ae_stats, 4);
	memcpy(&gh, ae_stats + 4, 4);
	if (!gw || !gh || (uint64_t)gw * gh > cap || 8 + (uint64_t)gw * gh * 4 > sizeof ae_stats) return 0;
	for (uint32_t i = 0; i < gw * gh; i++) y[i] = ae_stats[8 + i * 4 + 3];
	*w = gw;
	*h = gh;
	return ae_grid_seq;
}

/* The total gain (sensor x ISP), so the day/night score (daynight.c) counts the ISP gain as
 * exposure too: with ISP gain 1x it is the sensor gain, as before. */
int mi_ae_info(double *y, uint32_t *shutter_us, uint32_t *gain)
{
	if (!ae_last.valid) return -1;
	*y = ae_last.y; *shutter_us = ae_last.shutter_us;
	*gain = (uint32_t)((uint64_t)ae_last.gain * ae_last.isp / 1024);
	return 0;
}

int mi_ae_state(struct mi_ae_state *s)
{
	s->target = ae_target();
	if (!ae_last.valid) {
		s->y = -1;
		s->shutter_us = s->sensor_gain = s->isp_gain = 0;
		return -1;
	}
	s->y = ae_last.y;
	s->shutter_us = ae_last.shutter_us;
	s->sensor_gain = ae_last.gain;
	s->isp_gain = ae_last.isp;
	return 0;
}

int mi_image_set(int what, int value)
{
	if (what < 0 || what >= MI_IMG_COUNT || value < 0 || value > 100) return -1;
	img.value[what] = value;
	if (!img.ready) {
		img.pending[what] = 1;
		return 0;
	}
	return image_apply(what, value);
}

int mi_image_get(int what)
{
	return what >= 0 && what < MI_IMG_COUNT ? img.value[what] : -1;
}

/* ---- public API (mi.h) --------------------------------------------------------------- */


int mi_start(const struct mi_cfg *c)
{
	cfg = *c;
	if (cfg.ae_target <= 0) cfg.ae_target = 110;
	fd_sys = open_dev("/dev/mi_sys");
	fd_snr = open_dev("/dev/mi_sensor");
	fd_vif = open_dev("/dev/mi_vif");
	fd_isp = open_dev("/dev/mi_isp");
	fd_scl = open_dev("/dev/mi_scl");
	fd_venc = open_dev("/dev/mi_venc");
	if (fd_sys < 0 || fd_snr < 0 || fd_vif < 0 || fd_isp < 0 || fd_scl < 0 || fd_venc < 0)
		return -1;
	cfg.mirror = cfg.mirror ? 1 : 0;
	cfg.flip = cfg.flip ? 1 : 0;
	cfg.antiflicker = cfg.antiflicker ? 1 : 0;
	cfg.mains_hz = cfg.mains_hz == 50 ? 50 : 60;
	if (cfg.antiflicker) LOG("anti-flicker: on (%d Hz mains)\n", cfg.mains_hz);
	if (mi_shutter_max(cfg.shutter_day_max, cfg.shutter_night_max)) {
		LOG("AE shutter limits %u/%u us out of range: auto\n", cfg.shutter_day_max, cfg.shutter_night_max);
		cfg.shutter_day_max = cfg.shutter_night_max = 0;
	}
	for (int m = 0; m < 2; m++) {                   /* 0 = 1x (no ISP gain), as before it existed */
		int *x = m ? &cfg.isp_gain_night_max : &cfg.isp_gain_day_max;
		if (*x < 0 || *x > MI_ISP_GAIN_MAX) {
			LOG("AE ISP gain limit %d (%s) out of range: 1x\n", *x, m ? "night" : "day");
			*x = 0;
		}
	}
	LOG("AE: ISP gain up to %dx by day, %dx at night\n", isp_gain_limit(0), isp_gain_limit(1));
	if (cfg.iq_night && cfg.iq_day) nt_load(cfg.iq_night, cfg.iq_day);
	if (cfg.night_tuning && mi_night_tuning(1))
		LOG("night tuning: image.night_tuning is 1, but there are no usable night files: off\n");
	if (sys_init() || setup_snr() || setup_vif() || setup_isp() || vif_enable_port())
		return -1;
	snr_set_fps();                                  /* stock: right after the VIF port; not fatal */
	if (setup_scl() || setup_venc())
		return -1;
	/* Orientation once the pipeline runs (stock's live path sets it while streaming); 0/0 is the
	 * sensor's power-on default, so then it is only read back. A failure is logged, not fatal. */
	if (cfg.mirror || cfg.flip) mi_orient(cfg.mirror, cfg.flip);
	else orient_checks = ORIENT_CHECKS;
	setup_3a();

	/* MI_VENC_GetFd: the kernel attaches each channel to its own /dev/mi_poll instance */
	for (uint32_t idx = 0; idx < MI_NSTREAMS; idx++) {
		if ((idx == 1 && !cfg.sub_w) || (idx == 2 && !jpeg_on)) continue;
		struct venc_stream *v = &vst[idx];
		struct { uint32_t dev, chn, poll_fd, poll_id; } gf = { v->dev, v->chn, 0, 0 };
		v->fd_poll = open_dev("/dev/mi_poll");
		if (v->fd_poll < 0) return -1;
		gf.poll_fd = (uint32_t)v->fd_poll;
		if (mi_call(fd_venc, "MI_VENC_GetFd", DIR_RW, 16, &gf, sizeof gf)) return -1;
		if (ioctl(v->fd_poll, 0, (unsigned long)gf.poll_id) != 0)
			LOG("mi_poll bind (venc %u/%u) failed: %s (continuing with polling)\n", v->dev,
			    v->chn, strerror(errno));
	}
	return 0;
}

void mi_fds(int *venc_fd, int *fe_fd)
{
	*venc_fd = vst[0].fd_poll;
	*fe_fd = fd_fe;
}

int mi_venc_fd(int stream)
{
	return stream >= 0 && stream < MI_NSTREAMS ? vst[stream].fd_poll : -1;
}

void mi_fe_ready(void)
{
	fe_event();
}

int mi_read_frame(uint8_t *buf, uint32_t cap, uint64_t *pts)
{
	return mi_read_stream(0, buf, cap, pts);
}

/* ---- audio in (#110; docs/STOCK-AUDIO.md) ----------------------------------------------
 * As stock media_server Start_ai (0x286d0): /dev/mi_ai dev 0, chn group 0, S16 mono 16 kHz,
 * 1280-sample periods (80 ms), interfaces {1 analog mic, 37 echo ref}, the stock gains. Frames are
 * MI_SYS output-port buffers on {AI, 0, 0, 0}: GetBuf (SYS nr19) gives a user VA and the PCM length,
 * PutBuf (nr20) returns it; /dev/mi_poll via SYS GetFd (nr23) says when one is ready. */
enum { MOD_AI = 4 };
static int fd_ai = -1, ai_poll = -1;
static unsigned ai_total = 1, ai_mic = 1;

int mi_audio_start(int gain)
{
	fd_ai = open_dev("/dev/mi_ai");
	if (fd_ai < 0 || fd_sys < 0) return -1;
	struct { uint32_t dev, fmt, mode, rate, period; uint8_t inter, pad[3]; } o = { 0, 0, 1, 16000, 1280, 1, { 0 } };
	_Static_assert(sizeof o == 24, "ai open");
	struct { uint32_t dev, ifs[8]; uint8_t n, pad[3]; } at = { 0, { 1, 37 }, 2, { 0 } };
	_Static_assert(sizeof at == 40, "ai attach");
	struct { uint32_t ifc; int16_t l, r; } g1 = { 1, 15, 0 }, g2 = { 37, 0, 0 };
	_Static_assert(sizeof g1 == 8, "ai ifgain");
	struct { uint16_t dev; uint8_t grp, pad; int16_t gain[16]; uint8_t n, pad2; } sg = { 0, 0, 0, { 10 }, 1, 0 };
	_Static_assert(sizeof sg == 38, "ai gain");
	struct { uint16_t dev; uint8_t grp, z; } en = { 0, 0, 0 };
	if (mi_call(fd_ai, "MI_AI_Open", DIR_W, 0, &o, sizeof o) ||
	    mi_call(fd_ai, "MI_AI_AttachIf", DIR_W, 2, &at, sizeof at) ||
	    mi_call(fd_ai, "MI_AI_SetIfGain", DIR_W, 12, &g1, sizeof g1) ||
	    mi_call(fd_ai, "MI_AI_SetIfGain", DIR_W, 12, &g2, sizeof g2) ||
	    mi_call(fd_ai, "MI_AI_SetGain", DIR_W, 8, &sg, sizeof sg) ||
	    mi_call(fd_ai, "MI_AI_EnableChnGroup", DIR_W, 6, &en, sizeof en))
		return -1;
	struct chnport p = { MOD_AI, 0, 0, 0 };
	if (sys_set_depth(p, 4, 8)) return -1;
	ai_poll = open_dev("/dev/mi_poll");
	struct { struct chnport p; uint32_t poll_id, poll_fd; } gf = { p, 0, (uint32_t)ai_poll };
	_Static_assert(sizeof gf == 24, "sys getfd");
	if (ai_poll < 0 || mi_call(fd_sys, "MI_SYS_GetFd (AI)", DIR_RW, 23, &gf, sizeof gf) ||
	    ioctl(ai_poll, 0, (unsigned long)gf.poll_id) != 0)
		LOG("audio: no poll fd (%s); reading on a timer\n", strerror(errno));
	if (gain < 0) gain = 14;                                /* stock: Volume 75 of max 19 */
	struct { uint32_t ifc; int16_t l, r; } g3 = { 1, (int16_t)gain, 0 };
	struct { uint16_t dev; uint8_t grp, mute[16], n; } mu = { 0, 0, { gain == 0 }, 1 };
	_Static_assert(sizeof mu == 20, "ai mute");
	mi_call(fd_ai, "MI_AI_SetIfGain", DIR_W, 12, &g3, sizeof g3);
	mi_call(fd_ai, "MI_AI_SetMute", DIR_W, 10, &mu, sizeof mu);
	struct { uint16_t dev, z; uint32_t fmt; uint8_t inter, total, mic, echo; } ci = { 0, 0, 0, 0, 0, 0, 0 };
	_Static_assert(sizeof ci == 12, "ai chn info");
	if (!mi_call_q(fd_ai, "MI_AI chn info", DIR_RW, 16, &ci, sizeof ci, 1) && ci.total && ci.mic &&
	    ci.mic <= ci.total) {
		ai_total = ci.total;
		ai_mic = ci.mic;
	}
	LOG("audio: AI 16 kHz mono S16, mic gain %d, channels %u (mic %u)\n", gain, ai_total, ai_mic);
	return 0;
}

int mi_audio_fd(void) { return ai_poll; }

/* One AI buffer of mic PCM (16 kHz mono S16) into pcm[cap]: samples copied, 0 if none ready. */
int mi_audio_read(int16_t *pcm, unsigned cap, uint64_t *pts)
{
	if (fd_ai < 0) return -1;
	uint8_t a[240];
	memset(a, 0, sizeof a);
	struct chnport p = { MOD_AI, 0, 0, 0 };
	memcpy(a, &p, sizeof p);
	a[0xec] = 10;                                           /* as libmi_sys sets it */
	if (mi_call_q(fd_sys, "MI_SYS_ChnOutputPortGetBuf (AI)", DIR_RW, 19, a, sizeof a, 1)) return 0;
	uint64_t pts_v, hbuf;
	uint32_t virt, bsize, content;
	memcpy(&pts_v, a + 0x10, 8);
	memcpy(&virt, a + 0x10 + 0x20, 4);
	memcpy(&bsize, a + 0x10 + 0x30, 4);
	memcpy(&content, a + 0x10 + 0x34, 4);
	memcpy(&hbuf, a + 0xe0, 8);
	unsigned n = 0;
	if (virt && content && content <= bsize) {
		unsigned bytes = content / ai_total * ai_mic;           /* mic first, echo after */
		n = bytes / 2 < cap ? bytes / 2 : cap;
		void *va = (void *)(uintptr_t)virt;
		sys_flushinv(va, bsize);
		memcpy(pcm, va, n * 2u);
	}
	if (pts) *pts = pts_v;
	struct { uint64_t h; } pb = { hbuf };
	mi_call_q(fd_sys, "MI_SYS_ChnOutputPortPutBuf (AI)", DIR_W, 20, &pb, sizeof pb, 1);
	return (int)n;
}

void mi_audio_stop(void)
{
	if (fd_ai < 0) return;
	struct { uint16_t dev; uint8_t grp, z; } en = { 0, 0, 0 };
	uint16_t dev = 0;
	mi_call(fd_ai, "MI_AI_DisableChnGroup", DIR_W, 7, &en, sizeof en);
	mi_call(fd_ai, "MI_AI_Close", DIR_W, 1, &dev, sizeof dev);
	if (ai_poll >= 0) close(ai_poll);
	close(fd_ai);
	fd_ai = ai_poll = -1;
}

/* ---- audio out (#117; docs/STOCK-AUDIO.md section 5) -------------------------------------
 * As stock Start_ao (0x2a57c) on 0x730: /dev/mi_ao dev 0, S16 mono 16 kHz, period 0x400,
 * interface 1, interface volume 0, device volume 20 dB (no_ao_limited: max 20), unmuted. Writes go
 * through the kernel's staging buffer (nr8 -> MI_SYS_Mmap): wait for room (nr7), copy, nr9 len.
 * The speaker amplifier is GPIO 12 (active high), on while playing and off after 200 ms idle, as
 * stock (0x2a664). Never GPIO 30 (core voltage). */
#define AO_FRAME 1280                   /* bytes = 640 samples = 40 ms at 16 kHz, as stock */
#define AO_PENDING (AO_FRAME * 48)      /* ~1.9 s queued in-process; the oldest drops when full */
static int fd_ao = -1, amp_on;
static void *ao_virt;
static uint32_t ao_size;
static uint8_t ao_q[AO_PENDING];
static unsigned ao_qlen;
static long long ao_last_ms;

static long long mono_now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

static void amp(int on)
{
	static const char *gpio = "/sys/class/gpio/gpio12";
	char path[64];
	if (on == amp_on) return;
	snprintf(path, sizeof path, "%s/value", gpio);
	if (access(path, F_OK)) {                               /* export it once (our rootfs) */
		int f = open("/sys/class/gpio/export", O_WRONLY);
		if (f >= 0) { if (write(f, "12", 2) != 2) {} close(f); }
		snprintf(path, sizeof path, "%s/direction", gpio);
		f = open(path, O_WRONLY);
		if (f >= 0) { if (write(f, "out", 3) != 3) {} close(f); }
		snprintf(path, sizeof path, "%s/value", gpio);
	}
	int f = open(path, O_WRONLY);
	if (f >= 0) {
		if (write(f, on ? "1" : "0", 1) == 1) amp_on = on;
		close(f);
	}
}

int mi_ao_start(void)
{
	fd_ao = open_dev("/dev/mi_ao");
	if (fd_ao < 0 || fd_sys < 0) return -1;
	struct { uint16_t dev, z; uint32_t fmt, mode, rate, period, inter, x; } o = { 0, 0, 0, 1, 16000, 0x400, 1, 0 };
	_Static_assert(sizeof o == 28, "ao open");
	struct { uint16_t dev, z; uint32_t ifc, x; } at = { 0, 0, 1, 0 };
	_Static_assert(sizeof at == 12, "ao attach");
	struct { uint32_t ifc; int16_t l, r; } iv = { 1, 0, 0 };
	struct { uint16_t dev; int16_t l, r; uint16_t z; uint32_t fade; } vol = { 0, 20, 20, 0, 0 };
	_Static_assert(sizeof vol == 12, "ao volume");
	struct { uint16_t dev; uint8_t l, r; uint32_t z; } mu = { 0, 0, 0, 0 };
	_Static_assert(sizeof mu == 8, "ao mute");
	struct { uint16_t dev, z; uint32_t x; uint64_t phys; uint32_t size, y; } sb = { 0, 0, 0, 0, 0, 0 };
	_Static_assert(sizeof sb == 24, "ao staging");
	if (mi_call(fd_ao, "MI_AO_Open", DIR_W, 2, &o, sizeof o) ||
	    mi_call(fd_ao, "MI_AO_AttachIf", DIR_W, 4, &at, sizeof at) ||
	    mi_call(fd_ao, "MI_AO_SetIfVolume", DIR_W, 18, &iv, sizeof iv) ||
	    mi_call(fd_ao, "MI_AO_SetVolume", DIR_W, 14, &vol, sizeof vol) ||
	    mi_call(fd_ao, "MI_AO_SetMute", DIR_W, 16, &mu, sizeof mu) ||
	    mi_call(fd_ao, "MI_AO staging buffer", DIR_RW, 8, &sb, sizeof sb) || !sb.phys || !sb.size ||
	    sys_mmap(sb.phys, sb.size, &ao_virt)) {
		mi_ao_stop();
		return -1;
	}
	ao_size = sb.size;
	LOG("audio: AO 16 kHz mono S16, 20 dB, staging %u bytes; amplifier GPIO 12\n", ao_size);
	return 0;
}

void mi_ao_write(const int16_t *pcm, unsigned n)
{
	if (fd_ao < 0) return;
	unsigned bytes = n * 2u;
	if (bytes > AO_PENDING) { pcm += (bytes - AO_PENDING) / 2; bytes = AO_PENDING; }
	if (ao_qlen + bytes > AO_PENDING) {                     /* drop the oldest */
		unsigned drop = ao_qlen + bytes - AO_PENDING;
		memmove(ao_q, ao_q + drop, ao_qlen - drop);
		ao_qlen -= drop;
	}
	memcpy(ao_q + ao_qlen, pcm, bytes);
	ao_qlen += bytes;
}

/* Call from the main loop: hands queued 40 ms frames to the device while it has room, never
 * blocks; switches the amplifier off after 200 ms with nothing queued here or in the device. */
void mi_ao_pump(void)
{
	if (fd_ao < 0) return;
	long long now = mono_now_ms();
	struct { uint16_t dev, z; uint32_t total, queued; } st = { 0, 0, 0, 0 };
	_Static_assert(sizeof st == 12, "ao status");
	while (ao_qlen >= AO_FRAME) {
		if (mi_call_q(fd_ao, "MI_AO status", DIR_RW, 7, &st, sizeof st, 1) ||
		    st.total < st.queued || AO_FRAME > st.total - st.queued || AO_FRAME > ao_size)
			break;
		if (!amp_on) amp(1);
		memcpy(ao_virt, ao_q, AO_FRAME);
		sys_flushinv(ao_virt, AO_FRAME);
		struct { uint16_t dev, z; uint32_t len; } w = { 0, 0, AO_FRAME };
		if (mi_call_q(fd_ao, "MI_AO write", DIR_W, 9, &w, sizeof w, 0)) break;
		memmove(ao_q, ao_q + AO_FRAME, ao_qlen - AO_FRAME);
		ao_qlen -= AO_FRAME;
		ao_last_ms = now;
	}
	if (amp_on && ao_qlen < AO_FRAME && now - ao_last_ms > 200 &&
	    !mi_call_q(fd_ao, "MI_AO status", DIR_RW, 7, &st, sizeof st, 1) && !st.queued)
		amp(0);
}

void mi_ao_stop(void)
{
	if (amp_on) amp(0);
	if (fd_ao < 0) return;
	if (ao_virt) { sys_munmap(ao_virt, ao_size); ao_virt = NULL; }
	uint16_t dev = 0;
	mi_call_q(fd_ao, "MI_AO_Close", DIR_W, 3, &dev, sizeof dev, 1);
	close(fd_ao);
	fd_ao = -1;
	ao_qlen = 0;
}

int mi_read_stream(int stream, uint8_t *buf, uint32_t cap, uint64_t *pts)
{
	if (stream < 0 || stream >= MI_NSTREAMS || vst[stream].fd_poll < 0) return -1;
	uint32_t idx = (uint32_t)stream;
	struct venc_stream *v = &vst[idx];
	if (venc_map_ring(idx)) return -1;
	uint32_t n = 0, total = 0;
	int overflow = 0;
	for (;;) {
		struct slice s;
		memset(&s, 0, sizeof s);
		s.dev = v->dev;
		s.chn = v->chn;
		s.buf_id = v->ring.buf_id;
		s.timeout_ms = n ? 100 : 10;            /* first slice: don't stall the caller */
		if (mi_call_q(fd_venc, "VENC nr57 get slice", DIR_RW, 57, &s, sizeof s, n == 0))
			break;
		if (s.phys < v->ring.phys || s.phys + s.len > v->ring.phys + v->ring.size) {
			LOG("slice outside ring: phys %#llx len %u\n", (unsigned long long)s.phys, s.len);
			break;
		}
		if (!n && pts) *pts = s.pts;
		if (total + s.len <= cap)
			memcpy(buf + total, (uint8_t *)v->ring.virt + (s.phys - v->ring.phys), s.len);
		else
			overflow = 1;
		n++; total += s.len;
		if (s.flags & 1) break;                      /* frame end */
	}
	if (!n) { v->empty_reads++; return 0; }
	uint8_t info[96];                                    /* {u32 dev; u32 chn; …} */
	memset(info, 0, sizeof info);
	memcpy(info, &v->dev, 4);
	memcpy(info + 4, &v->chn, 4);
	memcpy(info + 0x0c, &total, 4);
	mi_call(fd_venc, "VENC nr10 stream info", DIR_RW, 10, info, sizeof info);
	venc_release(idx, n);
	v->frames++;
	if (idx != 0) {                                      /* 3A and IQ ride on the main stream */
		if (overflow) {
			LOG("stream %u frame %u: %u bytes > buffer %u, dropped\n", idx, v->frames, total, cap);
			return 0;
		}
		return (int)total;
	}
	unsigned frames = v->frames;
	if (want_3a() && !fe_events && frames > 10 && frames % 3 == 0) {
		ae_step();                              /* isp_fe silent: drive 3A from here */
		awb_step();
	}
	if (cfg.iq_profile) {
		const char *at = strchr(cfg.iq_profile, '@');
		unsigned when = at ? (unsigned)atoi(at + 1) : 10;   /* earlier sets fail "in early CameraOpen" */
		if (frames == (when ? when : 10))
			iq_profile_apply(cfg.iq_profile);
	}
	if (frames == image_ready_frame())
		image_ready();
	if (frames % 3 == 0)
		orient_poll();
	if (want_3a() && frames == (unsigned)cfg.fps * 3) {
		LOG("3A: %u isp_fe events, AE on %u (%u runs), AWB on %u (%u runs)\n",
		    fe_events, ae_on, ae_runs, awb_on, awb_runs);
		dump_3a_state();
	}
	if (mi_verbose || frames % 250 == 0)
		LOG("frame %u: %u slices %u bytes\n", frames, n, total);
	if (overflow) {
		LOG("frame %u: %u bytes > buffer %u, dropped\n", frames, total, cap);
		return 0;
	}
	return (int)total;
}

void mi_set_chn_hook(mi_chn_hook_fn fn)
{
	chn_hook = fn;
}

int mi_flushinv(void *va, uint32_t size)
{
	return fd_sys < 0 ? -1 : sys_flushinv(va, size);
}

int mi_iq_open(void)
{
	fd_sys = open_dev("/dev/mi_sys");
	fd_isp = open_dev("/dev/mi_isp");
	if (fd_sys < 0 || fd_isp < 0) return -1;
	return sys_init();
}

int mi_iq_get(uint32_t cmd, void *buf, uint32_t size)
{
	return iq_xfer(0, cmd, buf, size);
}

void mi_stop(void)
{
	struct chnport vif = { MOD_VIF, 0, 0, 0 }, isp = { MOD_ISP, 0, 0, 0 },
		       scl = { MOD_SCL, 0, 0, 0 }, venc = { MOD_VENC, 0, 0, 0 };
	LOG("mi: %u/%u frames (main/sub), %u empty reads; 3A: %u isp_fe events, AE %u runs, "
	    "AWB %u runs\n", vst[0].frames, vst[1].frames, vst[0].empty_reads, fe_events, ae_runs,
	    awb_runs);
	if (fd_fe >= 0) { close(fd_fe); fd_fe = -1; }
	for (uint32_t idx = MI_NSTREAMS; idx-- > 0;) {
		struct venc_stream *v = &vst[idx];
		if (v->fd_poll < 0) continue;
		close(v->fd_poll);
		v->fd_poll = -1;
		if (v->ring.virt) { sys_munmap(v->ring.virt, v->ring.size); v->ring.virt = NULL; }
		if (fd_venc >= 0) {
			struct { uint32_t dev, chn; } c = { v->dev, v->chn };
			if (idx == 2) {                 /* stock: nr6 0xc00c6906, {dev, chn, u32} */
				struct { uint32_t dev, chn, z; } sr = { v->dev, v->chn, 0 };
				mi_call(fd_venc, "MI_VENC_StopRecvPic", DIR_RW, 6, &sr, sizeof sr);
			}
			mi_call(fd_venc, "MI_VENC_DestroyChn", DIR_W, 2, &c, sizeof c);
		}
		if (idx >= 1 && fd_sys >= 0) {
			struct chnport sp1 = { MOD_SCL, 0, 0, 1 }, vp1 = { MOD_VENC, v->dev, v->chn, 0 };
			sys_unbind(sp1, vp1);
		}
	}
	if (fd_sys >= 0) {
		sys_unbind(scl, venc);
		sys_unbind(isp, scl);
		sys_unbind(vif, isp);
	}
	nt_free();
	LOG("teardown is best-effort; reboot to restore stock\n");
}
