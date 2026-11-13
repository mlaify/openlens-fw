/* SPDX-License-Identifier: MIT */
/*
 * mi.h: our SigmaStar Ifado MI layer (raw ioctls, no vendor userland). See mi.c and
 * docs/IFADO-MI-PIPELINE.md. One H.265 main stream: SNR -> VIF -> ISP -> SCL port 0 -> VENC 0/0.
 */
#ifndef MI_H
#define MI_H

#include <stdint.h>

enum { MI_H265 = 0, MI_H264 = 1 };
enum { MI_NSTREAMS = 3 };               /* 0 main, 1 sub, 2 JPEG snapshot (mi_read_stream index) */
enum { MI_RC_CBR = 0, MI_RC_VBR = 1 };
/* H.264 attr profile values (stock FUN_0005205c: web High -> 2, Main -> 1, Baseline -> 0) */
enum { MI_PROFILE_BASELINE = 0, MI_PROFILE_MAIN = 1, MI_PROFILE_HIGH = 2 };

struct mi_cfg {
	int w, h, kbps, fps;            /* main stream (SCL port 0); fps is also the sensor's
					   (MI_SNR_SetFps) */
	int codec;                     /* main stream: MI_H264 or MI_H265 */
	int gop, sub_gop;               /* keyframe interval in frames; 0 = 2 s (2 x fps) */
	int rc, sub_rc;                 /* MI_RC_CBR or MI_RC_VBR (stock: VBR, max/min QP 48/30) */
	int profile, sub_profile;       /* H.264: MI_PROFILE_BASELINE/MAIN/HIGH (stock web "High") */
	int sub_w, sub_h, sub_kbps, sub_fps, sub_codec;
					/* sub-stream: SCL port 1 -> VENC chn 1, FRAME_BASE, like stock
					   (640x360 H.264 there); sub_w 0 = no sub-stream */
	int snapshot, snapshot_q;       /* JPEG snapshot channel from the sub port (1 fps), Qfactor */
	int ring;                       /* SCL->VENC HW_RING (stock main stream), else FRAME_BASE */
	int auto3a;                     /* our AE + grey-world AWB */
	double ae_target;               /* AE stats mean-Y target; 0 = 110 */
	uint32_t shutter_us, gain;      /* fixed exposure (gain 1x = 1024), 0 = off */
	uint32_t wb_r, wb_g, wb_b;      /* fixed WB gains (1x = 1024), 0 = off */
	const char *cus3a;              /* "ae:awb:af" userspace-3A enables sent as IQ 0x2e08 before ISP
					   CreateChannel; NULL = 1:1:0 (stock media_server sends 1:1:1) */
	const char *iq_profile;         /* iq-dump-format file whose image-pipeline groups are applied
					   with SetIQApiData once streaming (#36); "path@N" applies it at
					   frame N (default 10); NULL = kernel IQ only */
	const char *iq_night, *iq_day;  /* stock night tuning (mi_night_tuning): iq-night.bin and
					   iq-day-switch.bin (scripts/iq-bin2profile.py), read at start;
					   NULL = none */
	int night_tuning;               /* image.night_tuning at start: 0/1 */
	int isp_outfmt;                 /* ISP output port pixel format: 0 YUV422 YUYV (default), 11
					   NV12 (stock picks one of the two) */
	const char *ae_extra;           /* AE result overrides: "legacy" (old all-zero extra fields) or
					   "gm=N,hdr=N,fn=N,deband=N,bv=N"; NULL = vendor-like defaults */
	int mirror, flip;               /* sensor orientation (MI_SNR_SetOrien), 0/0 = sensor default =
					   stock's picture on MCA40E */
	uint32_t shutter_day_max, shutter_night_max;
					/* AE shutter limits in us, 0 = auto (day: one frame time; night:
					   MI_NIGHT_SHUTTER_US). Day is never longer than a frame time,
					   night never longer than MI_NIGHT_SHUTTER_US */
	int antiflicker, mains_hz;      /* anti-flicker in our AE (mi_antiflicker): 0/1, and the mains
					   frequency 50 or 60 (anything else = 60) */
	int isp_gain_day_max, isp_gain_night_max;
					/* AE ISP gain limits (mi_isp_gain_max), x 1..MI_ISP_GAIN_MAX;
					   0 = 1x, no ISP gain (as before; rtspd's defaults are
					   MI_ISP_GAIN_DAY/NIGHT_DEFAULT, stock's MaxISPGain) */
};

/* Shutter limits (image.shutter_day_max / _night_max): 0 = auto, else MI_SHUTTER_MIN_US.. the max.
 * Stock's night shutter is 50 ms, already longer than a 25 or 30 fps frame (40 / 33 ms): the
 * sensor stretches its frames at night, as stock's does (about 20 fps); a longer one would lower
 * the sensor frame rate further, which the encoder and stream settings don't account for. */
#define MI_SHUTTER_MIN_US 100
#define MI_DAY_SHUTTER_MAX_US 1000000   /* longer than a frame time acts as a frame time */
#define MI_NIGHT_SHUTTER_US 50000

extern int mi_verbose;              /* 1: log every ioctl; 2: also every isp_fe event */

/* Opens /dev/mi_*, builds and starts the pipeline and 3A. 0 on success. */
int mi_start(const struct mi_cfg *cfg);

/* fds to select() for reading: the encoder's /dev/mi_poll and /dev/isp_fe (-1 if 3A is off). */
void mi_fds(int *venc_fd, int *fe_fd);

/* Call when the isp_fe fd is readable: runs AE/AWB on frame-done events. */
void mi_fe_ready(void);

/* Copies the next encoded access unit (Annex-B, all its slices) of the main stream into buf and
 * releases it. Returns its length, 0 if none is ready (or it didn't fit in cap and was dropped),
 * -1 on error. *pts gets the encoder's timestamp of the first slice. */
int mi_read_frame(uint8_t *buf, uint32_t cap, uint64_t *pts);

/* The same for stream 0 (main) or 1 (sub); and the /dev/mi_poll fd to select() for it (-1 if
 * that stream isn't configured). */
int mi_read_stream(int stream, uint8_t *buf, uint32_t cap, uint64_t *pts);
int mi_venc_fd(int stream);

/* User image controls (#73), each 0..100 with 50 = the current IQ (the stock profile):
 * brightness / contrast offset the ISP's per-ISO levels (4102 / 4101) by value-50; saturation /
 * sharpness scale the per-ISO strengths (4106 SatAllStr / 4114 BranchStrength) by value/50;
 * exposure moves our AE target by a stop per 25 (at night too, unless mi_exposure_night has its
 * own value). Before the IQ profile is in (frame < its
 * frame + 2) the value is kept and applied then. 0 on success. */
enum { MI_IMG_BRIGHTNESS, MI_IMG_CONTRAST, MI_IMG_SATURATION, MI_IMG_SHARPNESS, MI_IMG_EXPOSURE,
       MI_IMG_COUNT };
int mi_image_set(int what, int value);
int mi_image_get(int what);                 /* last value set (50 if never) */

/* Night mode (#30): 1 = black and white + stock's 50 ms night shutter limit, 0 = colour. With stock
 * night tuning on (mi_night_tuning), 1 also writes the night groups (ColorToGray among them), and
 * the image controls and ISP tuning then scale the night baselines; 0 only turns the colour back on,
 * and mi_night_day() restores the day groups (stock: after the IR-cut, a second later). */
int mi_night(int on);
int mi_night_day(void);

/* Stock night tuning (image.night_tuning, docs/STOCK-IMAGE-TUNING.md section 4): at night, the
 * image groups of stock's gc4023_night.bin that differ from day (cfg.iq_night; stronger noise
 * reduction, softer sharpening, darker shadows), and the day versions (cfg.iq_day) back by day.
 * Every record is checked against tools/iq-dump/iq_groups.h at start; no AE/AWB/AF group. Each
 * group is read and written only if it differs. Switching it on at night writes the night groups at
 * once, off writes the day ones back. -1 if on and the files weren't loaded (or not 0/1).
 * mi_night_tuning_get: 1 if on (and loaded). */
int mi_night_tuning(int on);
int mi_night_tuning_get(void);

/* Sensor orientation: mirror (left-right) and flip (upside down), each 0/1, with MI_SNR_SetOrien
 * as stock's CIsp::SetMirror (docs/STOCK-ENCODE-IMAGE.md section 3). Before mi_start only
 * remembered (mi_start applies cfg.mirror/flip); after it applied at once, and GetOrien reads it
 * back over the next ~10 main-stream frame groups (logged). The ISP's AE grid (motion) follows the
 * sensor, so it stays aligned with the picture. 0 on success. mi_orient_get: the values set. */
int mi_orient(int mirror, int flip);
void mi_orient_get(int *mirror, int *flip);

/* AE shutter limits in us, 0 = auto (see struct mi_cfg); used from the AE's next step. -1 if a
 * value is outside the ranges above. mi_shutter_max_get: the values set. */
int mi_shutter_max(uint32_t day_us, uint32_t night_us);
void mi_shutter_max_get(uint32_t *day_us, uint32_t *night_us);

/* Anti-flicker (image.antiflicker 0|1, image.mains_hz 50|60), day and night, in our own AE (no ISP
 * write): when on, the shutter is at least half a mains cycle (10000 us at 50 Hz, 8333 at 60 Hz)
 * and a whole number of those half cycles, gain making up the rest; never longer than the longest
 * shutter above. If that limit is shorter than half a cycle, anti-flicker can't apply: logged once,
 * and the AE runs as with it off. Used from the AE's next step. -1 if a value is invalid.
 * mi_antiflicker_get: the values set. docs/STOCK-IMAGE-TUNING.md. */
int mi_antiflicker(int on, int hz);
void mi_antiflicker_get(int *on, int *hz);

/* ISP tuning (docs/STOCK-IMAGE-TUNING.md), each 0..255, scaling the IQ profile's per-ISO values as
 * stock does:
 *   MI_TUNE_NR2D  image.nr2d: NRDeSpike (IQ 4111) BlendRatio x value/128, at most 16; 128 = as tuned
 *   MI_TUNE_NR3D  image.nr3d: NR3D (IQ 4110) MdGain x value/128, at most 10230; 128 = as tuned
 *   MI_TUNE_WDR   image.wdr: WDR (IQ 4118) Strength x value/128, at most 255; 0 = as tuned
 *   MI_TUNE_BLC   image.blc: with image.wdr 0, WDR Strength = value for every ISO; 0 = as tuned
 * Each group is read whole, only those fields change, and it is written back only if one of them
 * differs. Before the IQ profile is in (frame < its frame + 2) the value is kept and applied then;
 * a group that can't be read then is left alone (logged once, and setting it fails). 0 on success. */
enum { MI_TUNE_NR2D, MI_TUNE_NR3D, MI_TUNE_WDR, MI_TUNE_BLC, MI_TUNE_COUNT };
int mi_tune_set(int what, int value);
int mi_tune_get(int what);                  /* last value set (128 / 128 / 0 / 0 if never) */

/* Night exposure (image.exposure_night): at night the AE target comes from this value instead of
 * image.exposure (same scale: 50 = the base target, a stop per 25), MI_EXPOSURE_SAME = follow
 * image.exposure (the default). Used from the AE's next step; a day/night switch switches the
 * target. -1 if the value is neither. mi_exposure_night_get: the value set. */
#define MI_EXPOSURE_SAME (-1)
int mi_exposure_night(int value);
int mi_exposure_night_get(void);

/* ISP gain in our AE (image.isp_gain_day_max / _night_max): once the shutter is at its limit and
 * the sensor gain at 32x, the AE raises the ISP gain (CusAEResult IspGain) up to this many x, by
 * day and at night; 1 = no ISP gain (the AE as before). Whole x 1..MI_ISP_GAIN_MAX: stock's
 * ExposureLimit MaxISPGain is 4096 (4x) in its day bin and 2048 (2x) in its night bin. rtspd's
 * defaults are the same 4x / 2x (the AE statistics see the ISP gain: cam #1, 2026-10-24,
 * docs/STOCK-IMAGE-TUNING.md section 5); mi_cfg 0 = 1x. Used from the AE's next step; IspGain doesn't enter the AE result's
 * BV (sensor gain only, as before). -1 if a value is out of range. mi_isp_gain_max_get: the
 * limits in use. */
#define MI_ISP_GAIN_MAX 4
#define MI_ISP_GAIN_DAY_DEFAULT 4     /* stock's; verified live 2026-10-24: the AE stats see it */
#define MI_ISP_GAIN_NIGHT_DEFAULT 2   /* stock's night bin */
int mi_isp_gain_max(int day_x, int night_x);
void mi_isp_gain_max_get(int *day_x, int *night_x);

/* Our AE's last step: mean Y (0..255), shutter (us), total gain = sensor x ISP (1024 = 1x). -1
 * before the first. */
int mi_ae_info(double *y, uint32_t *shutter_us, uint32_t *gain);

/* The same in detail for `get` (ae.*): sensor and ISP gain apart (1024 = 1x) and the AE's mean-Y
 * target now (day or night). Before the first step: -1, with y -1, shutter and gains 0 and the
 * target filled in. */
struct mi_ae_state { double y, target; uint32_t shutter_us, sensor_gain, isp_gain; };
int mi_ae_state(struct mi_ae_state *s);

/* The latest AE luma grid (32x32 on this ISP) into y[cap]: its read count (changes with every new
 * grid), 0 if none yet. For motion detection (#77). */
unsigned mi_ae_grid(uint8_t *y, unsigned cap, unsigned *w, unsigned *h);

/* Audio in (#110): the microphone as stock captures it (16 kHz mono S16, 80 ms buffers). Start
 * after mi_start; gain 0..19 (stock 14), -1 = stock. mi_audio_fd: select() it for a buffer (-1:
 * poll on a timer). mi_audio_read: samples into pcm[cap], 0 if none ready, -1 if not started. */
int mi_audio_start(int gain);
int mi_audio_fd(void);
int mi_audio_read(int16_t *pcm, unsigned cap, uint64_t *pts);
void mi_audio_stop(void);

/* Audio out (#117): the speaker, 16 kHz mono S16. mi_ao_write queues PCM (drops if not started
 * or the device is full). */
int mi_ao_start(void);
void mi_ao_write(const int16_t *pcm, unsigned n);
void mi_ao_pump(void);                  /* from the main loop: feeds the device, never blocks */
void mi_ao_stop(void);

/* Read-only IQ API access without building a pipeline (tools/iq-dump): opens /dev/mi_sys and
 * /dev/mi_isp and calls MI_SYS_Init. Safe next to a running media_server: it only reads. */
int mi_iq_open(void);

/* MI_ISP GetIQApiData for dev 0 / chn 0: cmd is an isp_api.xml group Id, size its byte size.
 * 0 on success, else the MI error. */
int mi_iq_get(uint32_t cmd, void *buf, uint32_t size);

/* On-screen display (osd.c): mi_start calls the hook for each encoder channel after CreateChn and
 * its bind, before StartRecvPic (where stock attaches its MI_RGN regions): stream 0 main (VENC
 * 0/0), 1 sub (0/1), 2 JPEG snapshots (8/3); w x h is its picture. NULL = none. */
typedef void (*mi_chn_hook_fn)(int stream, uint32_t dev, uint32_t chn, int w, int h);
void mi_set_chn_hook(mi_chn_hook_fn fn);

/* MI_SYS_FlushInvCache over [va, va + size) (SYS nr27), e.g. for an OSD canvas. -1 before
 * mi_start or on error. */
int mi_flushinv(void *va, uint32_t size);

/* Best-effort teardown; reboot to fully restore the stock pipeline. Regions attached to the
 * encoders (osd_stop) must be detached first. */
void mi_stop(void);

#endif
