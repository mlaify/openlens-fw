/* SPDX-License-Identifier: MIT */
/*
 * audio.c: the microphone path's DSP for RTSP (#110), as stock's CAuPcm2G711u (docs/STOCK-AUDIO.md):
 * 16 kHz mono S16 from MI_AI, halved to 8 kHz through a low-pass FIR (so nothing above 4 kHz folds
 * back), G.711 µ-law (ITU-T G.711, the usual bias-and-segment encoder), cut into 320-byte frames
 * (40 ms) for one RTP packet each (PCMU/8000, payload type 0).
 */
#include <stdint.h>
#include <string.h>

#include "audio.h"

/* 31-tap half-band low-pass (cutoff ~3.6 kHz at 16 kHz, Hamming), Q15. Odd taps other than the
 * centre are zero for a half-band filter; the even ones are listed. */
#define TAPS 31
static const int32_t fir[TAPS] = {
	-47, 0, 115, 0, -251, 0, 487, 0, -872, 0, 1508, 0, -2649, 0, 10243, 16384,
	10243, 0, -2649, 0, 1508, 0, -872, 0, 487, 0, -251, 0, 115, 0, -47,
};

static int16_t hist[TAPS];
static unsigned phase;
static uint8_t out[AUDIO_FRAME];
static unsigned fill;
static uint32_t ts;

void audio_reset(uint32_t ts0)
{
	memset(hist, 0, sizeof hist);
	phase = fill = 0;
	ts = ts0;
}

uint8_t audio_ulaw(int16_t s)
{
	int sign = s < 0 ? 0x80 : 0, x = s < 0 ? -(int)s : s;
	if (x > 32635) x = 32635;
	x += 0x84;                                              /* bias */
	int seg = 7;
	for (int m = 0x4000; seg > 0 && !(x & m); m >>= 1) seg--;
	int mant = (x >> (seg + 3)) & 0x0f;
	return (uint8_t)~(sign | seg << 4 | mant);
}

void audio_feed(const int16_t *pcm, unsigned n, void (*emit)(const uint8_t *frame, uint32_t ts))
{
	for (unsigned i = 0; i < n; i++) {
		memmove(hist, hist + 1, (TAPS - 1) * sizeof hist[0]);
		hist[TAPS - 1] = pcm[i];
		if (phase++ & 1) continue;                      /* keep every other output: 8 kHz */
		int64_t acc = 0;
		for (int k = 0; k < TAPS; k++) acc += (int64_t)fir[k] * hist[k];
		int32_t v = (int32_t)(acc >> 15);
		if (v > 32767) v = 32767;
		if (v < -32768) v = -32768;
		out[fill++] = audio_ulaw((int16_t)v);
		if (fill == AUDIO_FRAME) {
			emit(out, ts);
			ts += AUDIO_FRAME;
			fill = 0;
		}
	}
}

/* ---- backchannel: G.711 from the client -> 16 kHz for the speaker ------------------------ */

int16_t audio_ulaw_dec(uint8_t u)
{
	u = (uint8_t)~u;
	int t = ((u & 0x0f) << 3) + 0x84;
	t <<= (u & 0x70) >> 4;
	return (int16_t)((u & 0x80) ? 0x84 - t : t - 0x84);
}

int16_t audio_alaw_dec(uint8_t a)
{
	a ^= 0x55;
	int t = (a & 0x0f) << 4, seg = (a & 0x70) >> 4;
	if (seg == 0) t += 8;
	else t = (t + 0x108) << (seg - 1);
	return (int16_t)((a & 0x80) ? t : -t);
}

/* 2x upsampling: zero-stuff and the same half-band low-pass (gain 2 to keep the level) */
static int16_t uhist[TAPS];

static void up2(const int16_t *in, unsigned n, int16_t *out)
{
	for (unsigned i = 0; i < n; i++)
		for (int z = 0; z < 2; z++) {
			memmove(uhist, uhist + 1, (TAPS - 1) * sizeof uhist[0]);
			uhist[TAPS - 1] = z ? 0 : in[i];
			int64_t acc = 0;
			for (int k = 0; k < TAPS; k++) acc += (int64_t)fir[k] * uhist[k];
			int32_t v = (int32_t)(acc >> 14);
			out[2 * i + (unsigned)z] = (int16_t)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
		}
}

int audio_rtp_in(const uint8_t *p, unsigned n, void (*sink)(const int16_t *pcm, unsigned n))
{
	int peak = 0;
	if (n < 12 || (p[0] >> 6) != 2) return -1;
	unsigned cc = p[0] & 0x0f, pt = p[1] & 0x7f, off = 12 + 4 * cc;
	if (p[0] & 0x10) {                                      /* header extension */
		if (n < off + 4) return -1;
		off += 4 + 4 * ((unsigned)p[off + 2] << 8 | p[off + 3]);
	}
	unsigned end = n;
	if (p[0] & 0x20) {                                      /* padding */
		if (!p[n - 1] || p[n - 1] > n) return -1;
		end -= p[n - 1];
	}
	if (off >= end || (pt != 0 && pt != 8) || end - off > 1024) return -1;
	static int16_t pcm8[1024], pcm16[2048];
	unsigned k = end - off;
	for (unsigned i = 0; i < k; i++) {
		pcm8[i] = pt ? audio_alaw_dec(p[off + i]) : audio_ulaw_dec(p[off + i]);
		int a = pcm8[i] < 0 ? -pcm8[i] : pcm8[i];
		if (a > peak) peak = a;
	}
	if (!sink) return peak;
	up2(pcm8, k, pcm16);
	sink(pcm16, 2 * k);
	return peak;
}
