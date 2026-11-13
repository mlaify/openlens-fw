/* SPDX-License-Identifier: MIT */
/* audio.h: microphone audio for RTSP (#110): 16 kHz PCM -> 8 kHz G.711 µ-law, 40 ms frames. */
#ifndef AUDIO_H
#define AUDIO_H

#include <stdint.h>

#define AUDIO_FRAME 320                 /* bytes = samples at 8 kHz = 40 ms, as stock */

/* Feed 16 kHz mono S16 samples; every complete 320-byte µ-law frame goes to emit(frame, ts),
 * ts in 8 kHz units. */
void audio_feed(const int16_t *pcm, unsigned n, void (*emit)(const uint8_t *frame, uint32_t ts));
uint8_t audio_ulaw(int16_t s);
void audio_reset(uint32_t ts0);

/* Two-way audio (backchannel, #117): G.711 from the client back to 16 kHz PCM for the speaker. */
int16_t audio_ulaw_dec(uint8_t u);
int16_t audio_alaw_dec(uint8_t a);
/* One RTP packet from the client (PT 0 PCMU or 8 PCMA): its samples at 16 kHz go to sink(pcm, n)
 * (sink NULL: only measure). Its peak |sample| (0..32767), or -1 if not a usable RTP audio
 * packet. */
int audio_rtp_in(const uint8_t *p, unsigned n, void (*sink)(const int16_t *pcm, unsigned n));

#endif
