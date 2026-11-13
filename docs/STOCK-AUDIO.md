# Stock audio: microphone capture, G.711 encode, RTSP audio (static analysis)

Goal: capture the microphone with raw MI ioctls (no vendor libs) and stream G.711 µ-law the same
way stock does. **Static analysis only** of V3.5.2.1 `/opt/ch/media_server` (ET_EXEC: Ghidra
address = ELF vaddr), `/opt/ch/hik_server` (ET_EXEC, the RTSP/ONVIF server), `/opt/ch/libtools.so`
and `/config/lib/libmi_sys.so` (both .so: Ghidra address = vaddr + 0x10000). Nothing vendor was
executed. Vendor files stay outside the repo.

Confidence: **[C]** = read from decompiled code or constants; **[L]** = also matches the live
read-only probe of stock on cam #2 (`/proc/mi_modules/mi_ai/mi_ai0`, 2026-10-23); **[G]** = guess
(names from SigmaStar's public I6C "new" MI_AI headers, semantics). Product = MCA40E = 0x730
(see STOCK-ENCODE-IMAGE.md §0).

## 0. Summary for our firmware
| Item | Stock value (0x730) |
|---|---|
| Capture enabled | Yes: `CAudioManage` is created at media_server init and starts AI unconditionally [C, L] |
| Device | `/dev/mi_ai`, AI dev 0, chn group 0 [C, L] |
| Interfaces | `AttachIf(0, {1, 37}, 2)`: 1 = ADC_AB (analog mic) [G name], 37 = echo reference [G] [C values, L: MiChnGrpCnt 2, MhalChnCnt 4] |
| Format | S16_LE, **mono**, **16000 Hz**, interleaved, **period 1280 samples = 80 ms** [C, L] |
| Gains | `SetIfGain(1, 15, 0)`, `SetIfGain(37, 0, 0)`, `SetGain(0, 0, {10}, 1)`, then `SetIfGain(1, 14, 0)` for Volume 75 [C] |
| Frame read | `MI_SYS_ChnOutputPortGetBuf` on `{AI=4, 0, 0, 0}` (SYS nr19), wait with `MI_SYS_GetFd` + `select`; depth (4, 8) [C, L] |
| Processing | SigmaStar IaaAnr/IaaAgc/IaaEq (closed lib, statically linked) in place on the PCM [C]; optional for us |
| Encode | Resample 16 k → **8 kHz**, **G.711 µ-law** (`CAuPcm2G711u`), **320-byte frames = 40 ms** [C] |
| RTSP | `m=audio 0 RTP/AVP 0` + `a=rtpmap:0 PCMU/8000`, `a=control:trackID=2`; one 320-byte frame per RTP packet [C] |
| AO | `/dev/mi_ao` dev 0 opened at init (16 kHz mono); fed by ONVIF backchannel / Hik talk / prompts [C, L] |

## 1. Is audio on, and with what parameters
**Config** (`config.default.mca40e.xml`):
`<Audio><Capture Volume="75" VolumePlay="100" amplify="1"/><Encode Enable="1" SampleRate="8000"
EncodeType="G.711" BitRate="64000"/></Audio>`. libtools serialises Capture (0x1c B) + Encode
(0x2c B: `{Enable; SampleRate; char EncodeType[32]; BitRate}`) into one 0x48-byte block that
`CAudioManage` copies to `+0x14` (ctor `0x29bd4`). The `SetAudioCfg` log (`0x29f50`) names the
fields: block[7] = enable, [8] = samplerate, +0x24 = type string, s16 +0xc = Volume,
s16 +0xe = VolumePlay, [4] = amplify, s16 +0x16 = AEC [C].

**Creation** (`FUN_000504a4`, media init): `new CAudioManage(0x2326b4 cfg, cb 0x50249,
0x50271, 0x50141, 0x50189)` → `CAudioManage::Init` (`0x29c6c`) when global `*0x2342b8 == 0`
(unresolved; live shows AI running, so it is 0) [C, L]. Init:
- `type = GetAudioEncoderType(cfg.EncodeType)`; `outRate = cfg.SampleRate` (8000);
  `outChn = (type == AAC) ? 2 : 1`.
- **Device rate:** `/etc/flag.customize` contains `"_FHAI"` ? cfg.SampleRate : **16000**. The
  rootfs file holds `_SMW`, so **16000** [C, L: SampleRate 16000].
- Creates `CAudioDecode` (`0x2a12c`, AO), `CAudioRecv` (`0x29498`), `CAudioFilePlay`
  (`0x2b0f4`), then `CAudioEncode` (`0x28394`, AI) and calls each one's start (vtable +0xc).
- No product-type branch decides whether audio exists; product checks only tweak gains (below).

**`CAudioEncode` fields** (ctor `0x28394`, base `0x29270`) [C]: +0x10 codec type, +0x14 out chn,
+0x18 = 16 bits, +0x1c out rate (8000), +0x24 dev rate (16000), +0x28 = 1 (dev chn), +0x2c = 1
(AI sound mode), **+0x20 period = dev rate × 2 / 25** (magic `0x51eb851f`), rounded down to a
multiple of 128 if needed → **1280** at 16 kHz (0x280 for product 0xb210 only), +0x31 encode
enable, +0x34 AI dev = 0, +0x38 chn group = 0, +0xcc Volume, +0xd0 amplify, +0xd4 AEC (bool),
+0xd8 encoded-frame callback, +0xdc raw-PCM callback.

**AEC:** only when `/opt/ch/enable_aec.flag` exists (`0x2905c`); not on the rootfs, so off [C].
The echo interface (37) is attached anyway, and `MI_AI_Read` is called with a NULL echo frame.

**ANR / AGC / EQ** (`AudioIaaAnr_Init`, `0x288e0`) [C]: for mono/stereo at 8/16/48 kHz it sets up
SigmaStar's IaaAnr (128-sample blocks, `0x28d90`), IaaAgc and IaaEq from tables at
`0x1a2bf8`/`0x1a2c2c`. In the AI thread ANR runs in place when global `*0x23445c == 0` [C;
the global's value is not resolved]. Our firmware can skip this (closed library) and send the raw
mic, or add our own high-pass/AGC later.

## 2. MI_AI call sequence (stock `Start_ai` = `FUN_000286d0`)
Same kernel convention as video (IFADO-MI-PIPELINE.md): `fd = open("/dev/mi_ai")`,
`hdr = {u16 devId = 0; u16 pad; u32 len; u64 ptr}`, `ioctl(fd, _IOC(dir, 'i', nr, len), &hdr)`.
The user lib (`ai_api.c`) first calls nr3 `0xc0016903` (1 B out: device count) and nr4
`0xc0046904` (4 B: channel-group count of a device) to size its tables (`0x15cd08`); we can skip
both [C].

| # | Call (wrapper) | ioctl | args (bytes) | Stock values |
|---|---|---|---|---|
| 1 | `MI_AI_Open(dev, &attr)` (`0x15d950`) | nr0 `0x40186900` W | 24: `{u32 dev; u32 eFormat; u32 eSoundMode; u32 eSampleRate; u32 periodSize; u8 bInterleaved; pad[3]}` | `{0, 0 (S16_LE), 1 (mono), 16000, 1280, 1}` [C, L] |
| 2 | `MI_AI_AttachIf(dev, if[], n)` (`0x15da68`) | nr2 `0x40286902` W | 40: `{u32 dev; u32 if[8]; u8 n; pad[3]}` (each if < 0x28) | `{0, {1, 37}, 2}` (table at `0x1a2bf0`) [C] |
| 3 | `MI_AI_SetIfGain(if, l, r)` (`0x15f6f4`) | nr12 `0x4008690c` W | 8: `{u32 if; s16 left; s16 right}` | `(1, 15, 0)`, then `(37, 0, 0)` [C] |
| 4 | `MI_AI_SetGain(dev, grp, gain[], n)` (`0x15f274`) | nr8 `0x40266908` W | 38: `{u16 dev; u8 grp; u8 pad; s16 gain[16]; u8 n; u8 pad}` | `(0, 0, {10}, 1)`; `{-1}` only if `*0x2342bc` and product 0x71d / 0x726–0x729 [C] |
| 5 | `MI_AI_EnableChnGroup(dev, grp)` (`0x15dbd0`) | nr6 `0x40046906` W | 4: `{u16 dev; u8 grp; u8 0}` | `(0, 0)` [C] |
| 5b | (inside 5) `MI_SYS_GetFd({4, dev, grp, 0})` | SYS nr23 `0xc0186917` RW | 24: `{chnPort[16]; u32 pollId (out); u32 pollFd (in)}` then `ioctl(pollFd, 0, pollId)`; pollFd = `open("/dev/mi_poll")` | stored per group [C] |
| 6 | `MI_SYS_SetChnOutputPortDepth(0, {4, 0, 0, 0}, 4, 8)` | SYS nr21 | 24 | user 4, buf 8 [C, L: usrDepth 4, BufCntQuota 8] |
| 7 | `MI_AI_SetIfGain(1, g, 0)` + `MI_AI_SetMute(dev, grp, {g == 0}, 1)` (`0x28650`) | nr12 / nr10 `0x4014690a` W | SetMute 20: `{u16 dev; u8 grp; u8 mute[16]; u8 n}` | g = 14 for Volume 75 (below) [C] |
| R | read loop, below | | | |
| 8 | `MI_AI_DisableChnGroup(0)` (`0x15dee8`) | nr7 `0x40046907` W | 4: `{u16 dev; u8 grp; u8 0}` | stop path `0x285a8` [C] |
| 9 | `MI_AI_Close(0)` (`0x15d9ec`) | nr1 `0x40026901` W | 2: `{u16 dev}` | [C] |

Note the stop path passes `0` as the single argument to DisableChnGroup; read as `{dev 0, grp 0}`
[C]. The live `/proc` shows the attr exactly as in row 1 (Format S16_LE, Mono, 16000, Interleaved
1, PeriodSize 1280) [L], which also confirms eSoundMode 1 = mono in this enum.

**Mic gain from the Volume setting** (`FUN_000284b0`) [C]: v = clamp(Volume, 0, 100) (capped
at 80, or 75 for some 0x718.. products, when global `*0x234314 != 0`); max = 19 (0x13) normally,
14 if `/opt/ch/aiot_server` exists (it doesn't), 21 for 0x697, 14 for some 0x716.. products (0x730
is not one); if amplify == 0, max = 10 when `/etc/flag.customize` contains `_FH`, else 4.
`g = min(max, (int)(v × max / 100.0 + 0.5))`. Stock config (75, amplify 1): **g = (int)14.75 = 14**.

### 2.1 Getting a frame (`MI_AI_Read` wrapper `0x15e3c8`, `ReleaseData` `0x15eef0`)
Stock calls `MI_AI_Read(0, 0, &mic, NULL, 128 ms)` in thread `ai_thread` (`0x28dec`) and
`MI_AI_ReleaseData(0, 0, &mic, NULL)` after use. The wrapper does **no AI GetFrame ioctl with a
user buffer**: frames come from **MI_SYS output-port buffers** that the kernel maps into the
process [C]:
1. nr17 `0xc0046911` RW, 4 B `{u16 dev; u8 grp; u8 bEnabled (out)}`; error `0xa0042017` if 0.
2. `MI_SYS_ChnOutputPortGetBuf({4 (AI), dev, grp, 0}, &bufInfo, &hBuf)` = SYS nr19
   `0xc0f06913` RW, 240 B: `{chnPort[16] @0; bufInfo[0xd0] @0x10 (out); u64 hBuf @0xe0 (out);
   u8 @0xec = 10 (libmi_sys always sets 10; meaning unknown [G])}`. If it fails and the timeout
   is non-zero: `select()` on the group's mi_poll fd for the timeout, then GetBuf again; else
   return `0xa004200d` (no data).
3. `bufInfo` fields used for AI (offsets inside the 0xd0 block) [C]: **+0x00 u64 pts**,
   **+0x20 pVirAddr** (low 32 bits; a user VA, used directly without MI_SYS_Mmap), +0x28 u64
   phys [G], **+0x30 u32 bufSize** (passed to FlushInvCache), **+0x34 u32 contentSize** (bytes of
   PCM), **+0x40 u64 seq**. eBufType (+0x10) is a type libmi_sys's ptr64 conversion leaves
   alone (it only rewrites types 1/3/4), so these offsets are the kernel's own [C].
4. nr11 `0xc014690b` RW, 20 B (same layout as SetMute): the per-channel mute flags; muted
   channels are zeroed in place.
5. nr16 `0xc00c6910` RW, 12 B `{u16 dev; u16 0; u32 fmt (0 → 2 bytes/sample); u8 bInterleaved;
   u8 totalChn; u8 micChn; u8 echoChn}`.
6. Layout: `n = contentSize / totalChn` bytes per channel. Interleaved: **mic = virt,
   `n × micChn` bytes**; echo (if fewer than total) starts at `virt + n × micChn`. Planar: channel
   i at `virt + n × i`. `MI_AI_Data_t` (0x90 B): `void *buf[16] @0; u32 bytes[16] @0x40; u64 pts
   @0x80; u64 seq @0x88` [C offsets, G names].
7. Release: `MI_SYS_FlushInvCache(virt, bufSize)` (SYS nr27) then
   `MI_SYS_ChnOutputPortPutBuf(hBuf)` = SYS nr20 `0x40086914` W, 8 B `{u64 hBuf}` [C].

Live: output port 0 GetFrame ≈ 12.5 fps (80 ms per buffer), GetOkCnt growing, no drops [L]. So
each buffer carries 1280 mono samples (2560 bytes of mic) [C + L]. **For our thin layer:** open
`/dev/mi_ai` and `/dev/mi_sys`, do rows 1–7, then loop `select(pollFd)` → nr19 → copy
`contentSize/totalChn × micChn` bytes from +0x20 → nr27 → nr20. Steps 1/4/5 of the read path are
optional (call nr16 once after enable to learn totalChn/micChn).

## 3. Encoding and RTSP
**Codec IDs** (libtools `GetAudioEncoderType` `0x5bf84`) [C]: `PCMU`/`G711`/`G.711`/`G711U`/
`G.711U` → **0 (G.711 µ-law)**; `PCMA`/`G711A`/`G.711A` → 2; `PCM` → 3;
`MPEG4-GENERIC`/`AACG4-GENERIC`/`AAC`/`MP4A` → 1 (AAC); `G.722`/`G.726` → 0; else −1. Names
(`0x5c0bc`): 0 G.711U, 1 AAC, 2 G.711A, 3 PCM. Config `"G.711"` → **µ-law** [C].

**Offered codecs** (`GetAudioEntry` `0x42b74`, entries `{name[16]; chn?; bits; kHz; kbps;
default}`) [C]: G.711U 8 k (**default**), G.711A 8 k, G.711U 16 k, G.711A 16 k, AAC (2, 16 bit,
16 k, 16 kbps). G.726/G.722 are added only if `/etc/filesys.ver` contains `_XZ` (it holds
`_SMW-H5`). No product branch.

**Encode path** [C]:
1. `ai_thread` (`0x28dec`) creates an AudioUtils converter `FUN_000534d8(this, 3 (PCM in), 16000,
   1, type 0, 8000, 1, frame = 0x140, cb 0x288d4)`; frame = 0x400 for AAC.
2. Type 0 builds **`CAuPcm2G711u`** (`0x541cc`, RTTI `12CAuPcm2G711u`, base `8CAuCodec`). Init
   (`0x5429c`) creates a resampler (`0xe5674`) because 16000×1 ≠ 8000×1 (ratio 0.5).
3. Per AI buffer: resample (`0x54030`), µ-law each S16 sample to one byte (`0x55522`), and emit
   **fixed 320-byte frames** (`0x54108`) to the callback. 320 bytes at 8 kHz = **40 ms**, so each
   80 ms AI buffer gives two frames.
4. Callback `0x288d4` stamps the time (`MI_SYS_GetCurPts`) and passes the frame to `+0xd8`
   (`0x50249`), which publishes it to the shared frame manager that `hik_server` reads [G for
   the last hop].

**SDP** (`hik_server` `0x2d688`, audio enabled only when the audio config enable is set) [C]:
```
m=audio 0 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=control:trackID=2
```
The rate is the configured SampleRate (stock 8000). G.711A gives PT 8 / `PCMA`. AAC would give
`m=audio 0 RTP/AVP 0`, `a=rtpmap:0 MPEG4-GENERIC/<rate>/2` and `a=fmtp:0 config=…` (static PT 0
for AAC: non-standard).

**RTP packetisation** (`streamPackRTP_Audio` `0x29e1c` / `0x29fe0`) [C]: one encoded frame per
RTP packet (320 bytes = **40 ms**), V=2, PT 0 (8 for codec id 0x90), **marker bit set on every
audio packet**, timestamp = pts_ms × (rate / 1000), SSRC field 0x88776655 (byte-swapped
constant), sequence per channel. If the payload length isn't a multiple of 4 it adds RTP padding
(P bit plus pad count); 320 never needs it.

**For our streamer:** send PCMU/8000 PT 0, 320-byte (40 ms) packets, timestamp += 320 per packet.
That is what stock clients (incl. SSS) already accept from this camera [C for stock, G for SSS].
Plain G.711 is enough; nothing here suggests SSS needs AAC [G]. The resampler: a 2:1 decimation
of the 16 kHz capture with a low-pass FIR. Alternatively, open AI at 8000 directly: the code
accepts 8/16/32/48 kHz and the `_FHAI` variant does exactly that, but stock on 0x730 uses 16000 [C].

## 4. Audio out (MI_AO), briefly
- `CAudioDecode` is created and started at init (`Start_ao` `0x2a57c`) [C, L: AO chn 0 enabled,
  same pid]:
  `MI_AO_Open(dev, {0 S16, 1 mono, 16000, 0x400 period, 1 interleaved})` (`/dev/mi_ao` nr2
  `0x401c6902`, 28 B) → `MI_AO_AttachIf(dev, 1, 0)` (nr4 `0x400c6904`, 12 B) →
  `MI_AO_SetIfVolume(1, 0, 0)` (nr18 `0x40086912`, 8 B) → `MI_AO_SetVolume(dev, dB, dB, 0)`
  (nr14 `0x400c690e`, 12 B) + `MI_AO_SetMute(dev, VolumePlay == 0)` (nr16 `0x40086910`, 8 B).
  `MI_AO_Write` = nr1/nr7/nr9 (`0x1603b4`).
- AO volume (`0x2a1cc`): `dB = (max + 60) × VolumePlay / 100 − 60`, clamped to [−60, max]. max
  is 7, 12 or 30 depending on `/opt/ch/no_ao_limited.flag` (present on the rootfs) and
  unresolved globals [C formula, G which max applies].
- **Sources:** the ONVIF backchannel (hik_server adds `m=audio 0 RTP/AVP 8 0`,
  `a=control:trackID=5`, `a=rtpmap:8 PCMA/8000`, `a=rtpmap:0 PCMU/8000`, `a=sendonly` when the
  DESCRIBE carries `Require: …backchannel`; `0x2db88`), Hik talk (`audioTalkTask`, 160-byte
  frames), alarm/voice prompts (mp3) [C]. Received A-law/µ-law is converted to the configured
  codec and handed to `talk_playdata` [C].
- Whether the D240W-S has a speaker fitted is not visible statically; stock opens AO
  regardless [open]. Not needed for capture.

## Evidence index (media_server unless noted)
| Address | What |
|---|---|
| `0x504a4` | media init: creates `CAudioManage` (`0x29bd4` ctor, `0x29c6c` Init) |
| `0x29f50` | SetAudioCfg (config change → restart / gain / AEC) |
| `0x28394` / `0x29270` | CAudioEncode ctor / CAudioBase ctor (period = rate × 2 / 25) |
| `0x286d0` | Start_ai: Open, AttachIf, SetIfGain ×2, SetGain, EnableChnGroup, depth, gain |
| `0x28650` / `0x284b0` | volume → SetIfGain + SetMute / gain formula |
| `0x28dec` | ai_thread: Read(128 ms) → ANR → encoder → ReleaseData |
| `0x285a8` | stop_ai: DisableChnGroup, Close |
| `0x288e0` / `0x28d90` | IaaAnr/Agc/Eq init / ANR run |
| `0x15d950` `0x15d9ec` `0x15da68` `0x15dbd0` `0x15dee8` | MI_AI Open / Close / AttachIf / EnableChnGroup / DisableChnGroup |
| `0x15e3c8` / `0x15eef0` | MI_AI_Read / ReleaseData (SYS GetBuf / PutBuf) |
| `0x15f274` `0x15f4c4` `0x15f6f4` | MI_AI SetGain / SetMute / SetIfGain |
| `0x534d8` / `0x541cc` / `0x5429c` / `0x54108` / `0x55522` | AudioUtils factory / CAuPcm2G711u / resampler init / 320-byte framing / µ-law |
| `0x2a57c` / `0x2a50c` / `0x2a1cc` | Start_ao / AO volume + mute / AO dB formula |
| libtools `0x5bf84` / `0x42b74` | GetAudioEncoderType / codec capability list |
| libmi_sys `0x12440` / `0x1266c` / `0x12838` / `0x119d4` | GetBuf nr19 / PutBuf nr20 / GetFd nr23 / BufInfo ptr64 conversion |
| hik_server `0x2d688` / `0x2db88` / `0x29e1c` | audio SDP / backchannel SDP / audio RTP packing |

## 5. Audio out in detail (for our backchannel)
Static only, same binaries as above. Stock path on 0x730:
**RTSP backchannel (hik_server) → UDP 127.0.0.1:9998 → `CAudioRecv` (media_server) → G.711µ
decode + resample 8 k → 16 k → `CAudioDecode` frame queue → `ao_thread` → `MI_AO_Write` at
16 kHz mono**, with the speaker amplifier on **GPIO 12** switched around playback.

### 5.1 MI_AO calls (`/dev/mi_ao`, same 16-byte header as AI; hdr.devId = 0)
| Call (wrapper) | ioctl | args (bytes) | Stock values (0x730) |
|---|---|---|---|
| `MI_AO_Open(dev, &attr)` (`0x15ff9c`) | nr2 `0x401c6902` W | 28: `{u16 dev; u16 0; u32 eFormat; u32 eSoundMode; u32 eSampleRate; u32 periodSize; u32 bInterleaved; u32 ?}` | `{0, 0 (S16_LE), 1 (mono), 16000, 0x400, 1, <uninitialised stack>}` (`Start_ao` `0x2a57c`, disassembly: only 5 words stored) [C]. Use 0 for the 6th word [G] |
| `MI_AO_AttachIf(dev, if, x)` (`0x1602b8`) | nr4 `0x400c6904` W | 12: `{u16 dev; u16 0; u32 if; u32 x}` | `(0, 1, 0)`; if 1 = DAC_AB [G name] [C] |
| `MI_AO_SetIfVolume(if, l, r)` (`0x160b50`) | nr18 `0x40086912` W | 8: `{u32 if; s16 l; s16 r}` (if must be 1, 2, 4, 8, 16 or 32) | `(1, 0, 0)` [C] |
| `MI_AO_SetVolume(dev, l, r, fade)` (`0x160950`) | nr14 `0x400c690e` W | 12: `{u16 dev; s16 l_dB; s16 r_dB; u16 0; u32 fade}` | `(0, 20, 20, 0)` for VolumePlay 100 (below) [C] |
| `MI_AO_SetMute(dev, l, r, x)` (`0x160a54`) | nr16 `0x40086910` W | 8: `{u16 dev; u8 muteL; u8 muteR; u32 x}` | `(0, 0, 0, 0)`; `(0, 1, 1, 0)` only when VolumePlay = 0 (`0x2a50c`) [C] |
| `MI_AO_Write` (`0x1603b4`) | nr8 / nr1 / nr7 / nr9 | below | `(0, pcm, 1280, pts 0, timeout 1000 ms)` (`send_ao` `0x2a480`) [C] |
| `MI_AO_GetTimestamp` (`0x160c44`) | nr7 `0xc00c6907` RW | 12 | idle check in `ao_thread` [C] |
| `MI_AO_Close(dev)` (`0x160114`) | nr3 `0x40026903` W | 2: `{u16 dev}` | stop path `0x2af14` → `0x2a4c0`; the wrapper first `MI_SYS_Munmap`s the staging buffer [C] |

- Order at start (`0x2aba0` → `0x2a57c`): **Open → AttachIf → SetIfVolume → SetVolume → SetMute**,
  then the `ao_thread` starts. There is **no separate Enable/Start ioctl**; the Open wrapper only
  adds the optional dump hook (`0x15faf8`, env `MI_AO_DUMP_ENABLE`). Stop: thread exit (PA off,
  below), then Close. No Disable or ClearBuf call is used [C].
- Other nrs seen: nr0 `0xc0016900` (1 B out: AO device count, lib bookkeeping) [C].

**Write path** (`MI_AO_Write(dev, data, len, u64 pts, s32 timeoutMs)`, `0x1603b4`) [C]:
1. First call per device maps a **staging buffer**: nr8 `0xc0186908` RW, 24 B
   `{u16 dev; pad[6]; u64 phys (out) @8; u32 size (out) @0x10; u32 @0x14}`, then
   `MI_SYS_Mmap(phys, size, &virt, cached = 0)` (`0x15fe10`, disassembly). `len > size` → error.
2. nr1 `0xc01c6901` RW, 28 B (= GetAttr, same layout as Open) gives rate / mode / format to compute
   the write's play time: `us = len × 10⁶ / rate / soundMode`, halved for S16. Poll interval =
   that time / 4 (in ms), at least 1 ms.
3. Wait for room: nr7 `0xc00c6907` RW, 12 B `{u16 dev; u16 0; u32 total (out) @4; u32 queued
   (out) @8}`. Proceed when `len <= total − queued`; error if `total <= len`. timeout −1 = wait
   forever; 0 = one try; N ms = about N / interval tries. Timeout → `0xa005200d`.
4. `memcpy(virt, data, len)` (always at the start of the staging buffer),
   `MI_SYS_FlushInvCache(virt, len rounded up to the cache line)`, then **nr9 `0x40086909` W, 8 B
   `{u16 dev; u16 0; u32 len}`**: the kernel copies it into its DMA ring.
- So PCM goes through a kernel-provided, mmap'ed staging buffer plus a "commit len" ioctl. It is
  **not** MI_SYS input-port GetBuf/PutBuf and not a user pointer.
- **What stock writes:** frames of `CAudioDecode +0x20` = **0x500 bytes = 640 samples = 40 ms at
  16 kHz mono** (0x140 only for the `_KO` customer build; 0x400 for AAC) [C]. The AO period is
  0x400 samples (64 ms). Live: AO chn 0 buffer 20000 bytes [L].
- **Underrun / flush:** none explicit. `ao_thread` (`0x2ad4c`) pops a frame from the queue (max
  40 frames ≈ 1.6 s; when full, the oldest are dropped, "egnore audio packets", `0x2a780`) and
  writes it. With nothing queued it sleeps 10 ms. After more than 20 empty polls it checks every
  10th poll whether `GetTimestamp` reports 0 bytes queued; if so it switches the PA off. For 0x730
  late frames (over 200 ms old) are **not** dropped, and playback ANR (`0x2ac18`) is explicitly
  skipped (`if (product != 0x730)`) [C].

**AO volume** (`0x2a1cc`) [C]: `dB = (int)((max + 60) × VolumePlay / 100.0) − 60`, clamped to
[−60, max]. For 0x730 max is decided by globals that `media_server` sets from
`/etc/flag.customize` (= `_SMW`) and flag files:
- `*0x234314` (`/opt/ch/flag.af.ptz.wtd`, absent) = 0, so base max = **7**.
- `*0x234288` = **1** because the customer string contains `_SMW` (main `0x185fc`, the
  `strstr(..., "_SMW")` → `*puVar = 1` chain). With `/opt/ch/no_ao_limited.flag` present and 0x730
  in none of the exception lists, this sets **max = 20**.
- `*0x234280` is 0 (another customer string), so no override to 12.
- Result: **max 20 dB; VolumePlay 100 → SetVolume(0, 20, 20, 0)**. Without `no_ao_limited.flag`
  it would stay 7 [C, from the rootfs files].

### 5.2 Format path from the backchannel
1. **hik_server** depacketises RTP (5.4) and calls `TalkAudioPackCB` (`0x2cc58`). That converts
   A-law↔µ-law (`alaw2ulaw` / `ulaw2alaw`) so the payload matches the **configured audio codec**
   (G.711U on stock), then calls libtools `talk_playdata` [C].
2. `talk_playdata` (libtools `0x5b924`) sends one UDP datagram per call to **127.0.0.1:9998**:
   a 32-byte header `{u32 0xabcdefdd; u32 sourceId (set by OpenTalk); u32 0; u32 timestampMs;
   u32 len; 0; 0; 0}` + the G.711 bytes [C].
3. **media_server `CAudioRecv`** (thread `audio_udpserver` `0x29b04`, socket `0x29508`,
   epoll loop `0x29a04`, recv ≤ 0x1400 B): accepts datagrams with magic 0xabcdefdd.
   `recv_data_handle` (`0x2989c`) arbitrates sources by priority (ids 6–11 → {4, 10, 10, 3, 1,
   3}, others 10; a source is released after 800 ms of silence, `0x296c0`).
   - Payloads without the inner magic 0xeebbaadd go to the decoder.
   - Inner type 3 = raw PCM with its own rate (`0x296e4`).
   - Inner type 5 = mp3 (prompts) [C].
4. **Decoder** (`0x293a0`): `AudioUtils(type = configured codec 0, 8000 Hz, mono → PCM, 16000 Hz,
   mono, frame 0x500)` = **`CAuG711u2Pcm`** (RTTI `12CAuG711u2Pcm`, `0x543c4`), which **resamples
   8 k → 16 k itself** (same `CAuCodec` resampler as the encoder) [C].
5. Decoded PCM → callback `0x29448` → `PushPcmData(CAudioDecode, pcm, len, now)` (`0x2a780`),
   which re-chunks it into 1280-byte frames on the queue → `ao_thread` → `MI_AO_Write` [C].

So **AO always runs at 16 kHz mono S16** (opened once at init, not reopened for talk), and the
8 k → 16 k up-sampling happens in media_server's decoder. **For our firmware:** decode PCMU/PCMA
(8 kHz) → upsample ×2 → write 1280-byte (40 ms) chunks with the nr7/nr9 protocol. Alternatively,
open AO at 8000: the AI side accepts 8000, and the AO driver probably does too [G], but that is
untested and stock doesn't do it.

### 5.3 Speaker amplifier (PA) enable: **GPIO 12**
- `ao_thread` calls `FUN_0002a664(this, 1)` just before writing the first frame after idle
  (skipped if `/tmp/lowpower.flag` exists), and `FUN_0002a664(this, 0)` when idle (5.1) or on
  thread exit [C].
- `FUN_0002a664`: `on = (arg > 0)`. The level is inverted only for products 0x703 and
  0x708–0x70a, **not 0x730**, so **active high**. `gpio = GetAudioOutGpioPort()`; if ≥ 0,
  `io_out_write(gpio, on)` = write `"1"`/`"0"` to **`/sys/class/gpio/gpio%d/value`** (libtools
  `0x50ee4`). The expander and `set_gpio_value` branches are for other products only [C].
- `GetAudioOutGpioPort` (libtools `0x52538`) returns the pin of the per-product GPIO table entry
  whose type field is 4. For 0x730, `FUN_000517a0` selects **`g_io_mcf43`** (2 entries: the
  0x730 & ~0x10 == 0x720 branch → `LAB_0005182a`). The entries are:
  - `{"PAD_SPI0_DO", pin **12**, dir out, default −1 (none), type **4** = audio out}`
  - `{"PAD_SPI0_CK", pin 10, dir in, type 3}` (not audio)
  
  `gpio_init` exports 12 as output at boot without setting a level [C].
  This matches BOARD.md: only GPIO 10 (in), 12 (out, 0) and 30 are exported on the live unit [L].
- **For our firmware:** set **GPIO 12** to 1 before playback and 0 after the queue drains. **Never
  touch GPIO 30** (SoC core voltage); it is not part of the audio path. GPIO 10 is an input; leave
  it alone.
- The config `amplify` field does **not** touch the speaker: it only lowers the *mic* gain cap
  when 0 (`0x284b0`, §2) [C]. There is no other AO-side mute/PA toggle; SetMute is used only for
  VolumePlay = 0.

### 5.4 hik_server backchannel (RTSP)
- **Request:** if any `Require` header value **contains `backchannel`** (`strstr`, `0x2e44e`;
  e.g. `www.onvif.org/ver20/backchannel`), the session flag `+0x39` is set and DESCRIBE appends
  (`0x2db88`, rate = configured SampleRate):
  ```
  m=audio 0 RTP/AVP 8 0
  a=control:trackID=5
  a=rtpmap:8 PCMA/8000
  a=rtpmap:0 PCMU/8000
  a=sendonly
  ```
  Without the header, there is no backchannel track.
- **SETUP** of a URL containing `trackID=5` (with the flag set) creates the receive transport.
  Both TCP-interleaved and UDP are supported. For UDP there is a "customer NVR udp backchannel"
  path that rebuilds the transport engine with a server port. PLAY's RTP-Info lists the
  backchannel as `url=…trackID=5;seq=0;rtptime=0` [C].
- **TCP interleaved receive** (`0x2cd08`, data read on the RTSP socket): for each `$` frame,
  `{0x24, ch, u16 len}` followed by RTP. **The channel byte is not checked.** The payload is
  taken at offset 4 + 12, size `len − 12` (CSRC/extension not handled). PT 8 → A-law, anything
  else → µ-law. A bare RTP packet (no `$`) is also accepted [C].
- **UDP receive** (`0x2cdf0`): `select` 100 ms, `recvfrom` ≤ 0xa00. It honours CC and the X
  extension. PT 8 = A-law, PT 0 = µ-law; PT 13 (CN) and 101 are ignored, others dropped [C].
- **Packet size:** none required. Each RTP payload is forwarded as-is (one datagram to 9998). SSS
  and ONVIF clients typically send 20 ms (160 B) PCMU [G]. The Hik-private talk channel
  (`audioTalkTask` `0x1b9a8`) uses frames of exactly 160 B, at most 64 per read [C].
- **SSS-specific:** nothing SSS-named was found. The generic ONVIF Require/backchannel path above
  is what SSS uses [G].

### 5.5 Evidence index (audio out)
| Address | What |
|---|---|
| `0x2aba0` / `0x2af14` | CAudioDecode start (Start_ao + thread) / stop (Close) |
| `0x2a57c` / `0x2a50c` / `0x2a1cc` | Start_ao / volume + mute / dB formula |
| `0x2ad4c` / `0x2a480` | ao_thread / send_ao (Write, timeout 1000) |
| `0x2a780` | PushPcmData (1280-B frames, 40-deep queue) |
| `0x2a664` | PA switch → `GetAudioOutGpioPort` → sysfs GPIO |
| `0x29b04` / `0x29508` / `0x29a04` / `0x2989c` / `0x293a0` / `0x29448` | talk UDP server thread / socket :9998 / loop / source arbitration / G.711→PCM decoder setup / decoder → PushPcmData |
| `0x15ff9c` `0x1602b8` `0x160b50` `0x160950` `0x160a54` `0x1603b4` `0x15fe10` `0x160c44` `0x160114` | MI_AO Open / AttachIf / SetIfVolume / SetVolume / SetMute / Write / staging map / GetTimestamp / Close |
| libtools `0x5b924` / `0x52538` / `0x517a0` / `0x50ee4` / `g_io_mcf43` | talk_playdata / GetAudioOutGpioPort / GPIO table select / io_out_write / 0x730 GPIO table |
| hik_server `0x2db88` / `0x2e44e` / `0x2cd08` / `0x2cdf0` / `0x2cc58` | backchannel SDP / Require parse / TCP and UDP RTP receive / codec convert + talk_playdata |
