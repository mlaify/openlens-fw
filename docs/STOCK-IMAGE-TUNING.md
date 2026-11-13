<!-- SPDX-License-Identifier: MIT -->
# Stock image tuning: IQ bins, NR, WDR, BLC, anti-flicker (static analysis of `media_server`)

Goal: reproduce stock's 2D/3D noise reduction, WDR, backlight and anti-flicker settings in our
firmware. **Static analysis only** of V3.5.2.1 `/opt/ch/media_server` (ET_EXEC: Ghidra addresses =
ELF vaddrs; decode by a subagent, 2026-10-23). Nothing vendor was executed or copied into the repo.
Tags: **[C]** read in code, **[L]** matches bench data, **[G]** guess.

## 1. Which IQ file stock tunes with
- Stock loads **`/config/iqfile/gc4023_day.bin`** (night: `gc4023_night.bin`) through
  `MI_ISP_API_CmdLoadBinFile` in `Load_DayBinFile` (`0x3f3f8`) [C]. This corrects the earlier
  reading that stock runs the kernel's IMX307 file (docs/IFADO-MI-PIPELINE.md): the kernel does
  load `iqfile0.bin` → `imx307_iqfile.bin` first, and media_server then loads the gc4023 bin over it.
- Our `bench-logs/iq-profile-stock.bin` (an iq-dump taken under stock, applied with `-Q`) **is
  gc4023_day.bin** [L]: 36 of its 37 image-pipeline groups appear verbatim in the day bin, among them
  the three below at their auto entries: NRDeSpike `0x3c00`, NR3D `0x55d4` (MdGain of entry 0 at
  `0x55d8`), WDR `0x14b2c`. Only 16 of 37 appear in the night bin (2026-10-23 check).
- After a load stock keeps per-ISO baselines from the bin; at night it clears its WDR/BLC/HLC
  handling [C].
- At night stock loads `gc4023_night.bin` (e.g. WDR Strength 170.. instead of 200.., different
  NR3D). We do the same, as an option (`image.night_tuning`, default 0): section 4. Neither bin is
  in `rootfs/vendor-files.tsv` or the image; the build derives the groups from the owner's dump.

## 2. Live apply in stock
- By day, read-compare-write on WDR, HLC, BLC, anti-flicker, TNF (2D NR) and SNF (3D NR); at night
  only anti-flicker [C]. Every write is read-modify-write of the whole group.
- Transport identical to our `iq_xfer` (24-byte header, `MI_ISP_SetIQApiData` / `GetIQApiData`) [C].

| Setting (stock field, addr) | IQ group (isp_api.xml Id, size) | What stock changes |
|---|---|---|
| Anti-flicker (`0x42278`; TVSystem 1 = 50 Hz / 0 = 60 Hz, forct_antiflicker) | 0x1409 ExposureLimit (5129), 32 B `{u32 MinShutterUS, MaxShutterUS, MinFNx10, MaxFNx10, MinSensorGain, MinISPGain, MaxSensorGain, MaxISPGain}` | only MinShutterUS: forced → 10000 (50 Hz) / 8333 (60 Hz), off → 30; no quantisation [C]. Owner's stock: 60 Hz, Disable |
| 2D NR = TNF (UI 0..255, 128 default) | 0x100f NRDeSpike (4111), 1476 B: `{u32 bEnable; u8 DbgMode; pad3; u32 opType}`, 16 auto entries of 0x56 B from +0x0c | entry+0 u8 BlendRatio[i] = TNF × base[i] / 128, base = 0,0,0,0,0,1,2,…,11 [L]; stock never clamps (XML max 16) |
| 3D NR = SNF (0..255, 128) | 0x100e NR3D (4110), 2632 B: `{u32 bEnable, bDbgEn, opType}`, 16 auto entries of 0x9a B from +0x0c | entry+4 u16 MdGain[i] = SNF × base[i] / 128, base = 200,220,240,260,260,280,280,200,160,140,120×6 [L]; XML max 10230 |
| WDR (`0x41f40`; WDRMode 0 Disable / 1 DWDR (/3 HWDR in some UIs), WDRValue 0..255) | 0x1016 WDR (4118), 1036 B: `{u32 bEnable, bDbgEn, opType; u8 BoxNum; pad3}`, 16 auto entries of 60 B from +0x10: `{u8 Strength, LocalStrength, LevelStrength, GDTE; u32 DetailEnh; u16 StrByY[16]; u16 Oft; u8 Sft[15]; u8 Dark, Bright; pad}` | mode ≠ 0: Strength[i] = WDRValue × base[i] / 128 (stock wraps at 256); mode 0: no write, so the bin's enabled, tuned WDR stays ("Disable" = tuned default). Changing WDRMode re-inits video in stock [G]; only the Strength bytes matter here |
| BLC (BackLight 0..255, `0x41ff4`), only when WDRMode == 0 | same 0x1016 | BackLight > 0 → Strength[i] = BackLight for all 16; 0 → restore baseline 200,200,190,180,170,170,170,170,160,150×7 [L] |
| HLC | 0x140f, the kernel AE's strategy | **skipped**: it steers the kernel AE, and we run our own AE (CUS3A), so it would most likely do nothing [G] |
| Shutter mode | 0x1409 MaxShutterUS = 1e6/fps (auto) or 1e6/speed | already in our own AE (`image.shutter_day_max` / `_night_max`) |

Our iq-dump (`tools/iq-dump/iq_groups.h`) has the same Ids and sizes (5129/32, 4111/1476,
4110/2632, 4118/1036), and the baselines above are what `iq-profile-stock.bin` holds at those
offsets (headers there: bEnable 1, opType 0 = auto, WDR BoxNum 4).

## 3. What our firmware does (rtspd / src/mi)
- **Anti-flicker** (`image.antiflicker` 0|1, default 0; `image.mains_hz` 50|60, default 60), day and
  night, in **our own AE**: no ISP write, since our AE sets the shutter itself. When on, the shutter
  is at least half a mains cycle (10000 / 8333 µs) and **a whole number of half cycles**, the gain
  making up the rest; never longer than the longest shutter. That is better than stock, which only
  raises the minimum, so between one and two half cycles its shutter still beats with the light.
  If the longest shutter is under half a cycle (e.g. 1/1000 s by day), anti-flicker can't apply:
  logged once, and the AE runs as with it off.
- **NR / WDR / BLC** (`image.nr2d`, `image.nr3d` 0..255, default 128 = the profile as tuned;
  `image.wdr` 0..255, 0 = as tuned, else Strength × value / 128; `image.blc` 0..255, used only with
  `image.wdr` 0, 0 = as tuned): the baseline is read per entry after the IQ profile is applied
  (frame N+2, with the image controls), so the values scale the profile's own per-ISO shape.
  Clamps: BlendRatio 16, MdGain 10230, Strength 255 (stock wraps; we clamp).
- **Applied day and night.** Stock applies them by day only, because at night its night bin
  replaces the tuning. We apply them at night too: against the day profile with
  `image.night_tuning` 0, against the night groups (section 4) with 1.
- **Rules kept from stock, and the risks it avoids:** exact group sizes; always read the group, then
  write it back whole; only the 16 strength fields change (never bEnable, opType, BoxNum or the other
  fields); compare first, no write if nothing differs (no per-frame writes); nothing written before
  the profile is in (the values wait). A group that can't be read, or whose header or values are out
  of the XML ranges (bEnable/opType > 1, BoxNum not 1..4, a value over the max), is logged once and
  never written; setting it then fails. Never MinShutter > MaxShutter: we don't write 0x1409 at all.
- The kernel oops seen earlier came from the 3A ioctls ISP nr39–44; none of this uses them.

## 4. Stock night tuning (`image.night_tuning`)
Static decode of `media_server` (subagent, 2026-10-23) plus the two bins from the owner's dump,
parsed on the host (nothing vendor executed; only derived groups enter the image).

### 4.1 The bins
- Day `/config/iqfile/gc4023_day.bin` (SHA-256 `631beab1…aaf538e`, 136508 B, 85 records), night
  `gc4023_night.bin` (`f221c7b5…0ca7f227d`, 136792 B, 86 records: the day ids plus Temperature
  4152) [L].
- `MI_ISP_API_CmdLoadBinFile` is user space: it reads the file and sends each record with
  `MI_ISP_SetIQApiData` (nr17), the same path as our `iq_xfer` [C]. Its parser trusts the lengths.
- **Format** [C]+[L]: a 32-byte header `{u32 magic 0x6d65032c; u16 minor 0; u16 major 1; u32
  payload length = file size − 32; u32 checksum = byte sum of the payload; u32 key 1234; u32 0;
  u32 1 (checksum checked when nonzero); u32 0}`, then records `{u32 key 1234; u32 type 5; u32 len;
  u16 api_id; u16 nbuf; u32 off[nbuf]; data}`, `len` counting from `api_id`, so data is
  `len − 4 − 4·nbuf` bytes. In both bins every record is type 5 with key 1234; 165 have one buffer
  (offset 0), the multi-buffer ones are EVComp 5123 (2), ManualExposure 5125 (4) and APIVer 4097
  (2). The image groups' data sizes equal `tools/iq-dump/iq_groups.h` (e.g. NR3D 2632, WDR 1036).
- 25 groups differ between the bins [L]: 4 AE (AETarget 5127, AEWinWeight 5133, AEPlainLongTbl
  5130, ExposureLimit 5129: MaxShutter 250 ms, MaxISPGain 2048) and 21 image groups:
  DynamicDP 4119, Crosstalk 4115, DeMosaic 4124, DynamicBlackLevel 4167 (auto → manual, black
  level 4080), NRDeSpike 4111, NRLuma_Adv 4141, NRChroma_Adv 4142, NR3D 4110, CCM 4108 (auto →
  manual, near identity), HSV 4120, HSVBYISO 4178, Gamma 4104 and YUVGamma 4105 (darker shadows),
  Brightness 4102, Contrast 4101, ColorToGray 4100 (0 → 1), Sharpness 4114, Sharpness_EX 4145,
  Saturation 4106, WDR 4118, WDR_NR 4158.
- Night values of the groups our controls scale [L]: NRDeSpike BlendRatio 0,0,0,1,2,…,12,12 (day
  0,0,0,0,0,1,…,11); NR3D MdGain 220,240,260,280,300,320,300,240,160,120… (day 200,220,…);
  WDR Strength 170,170,170,180,180,180,180,170,160,150… (day 200,200,190,180,170…), LocalStrength
  168,168,168,168,160,152,… (day 128 at low ISO; the first decode's "LocalStrength 160 → 40"
  doesn't match this layout, an open doubt), BoxNum 4 both; Sharpness BranchStrength at ISO 4..6 80 (day
  96); Contrast 48.. at low ISO (day 40..); Brightness ±1.

### 4.2 Stock's switch [C]
- Day → night: IR LEDs on → load the night bin (its ColorToGray 1 turns the picture grey) → sleep
  1 s → IR-cut to night → frame rate reset.
- Night → day: IR LEDs off → ColorToGray 0 → IR-cut to day → sleep 1 s → load the day bin
  (+500 ms settle) → frame rate.
- Before a load it polls `MI_ISP_IQ_GetParaInitStatus` (0x1002) until 1; after it re-reads its
  baselines (day: Saturation, Sharpness, WDR, AETarget, NR3D, NRDeSpike; night: Sharpness,
  AETarget, NR3D, NRDeSpike, HLC) and re-applies the user's scalings.

### 4.3 What we do
- **Build** (`scripts/iq-bin2profile.py`, in `scripts/build-rootfs.sh`): both bins must match the
  pinned SHA-256 and pass every check above (magic, version, payload length, checksum, header and
  record keys, type, per-record bounds, buffer offsets, each id once). It takes the groups that
  differ and that iq_groups.h lists, in the range our IQ profile applies (4098..4999 and 10243,
  not Dummy 4147/4148), not on an AE/AEParam/AEInfo/AWB/AWBInfo/AWBCTCali/AF/AFHW page (our own
  AE/AWB runs; stock's AE groups would fight it, and AdaptiveGamma 4150 sits on the AE page), not
  an `…Info` group, not Temperature (night-only, nothing to switch back to) and not Day/Night Mode
  (the kernel's own detection). A taken group must have one buffer of exactly iq_groups.h's size,
  else the build stops. Output: `/etc/cam/iq-night.bin` (night versions) and
  `/etc/cam/iq-day-switch.bin` (day versions of the same ids, so the switch back doesn't depend on
  what the ISP holds), in our iq-dump record format; the 21 groups above, about 75 KB each.
  Without the bins in `/vendor` the build warns and the image has no night tuning.
- **rtspd** (`-q NIGHT,DAY`, src/mi/mi.c): reads both at start and checks every record again
  (iq_groups.h id and size, the same exclusions, same ids in the same order, each once); a file
  that fails leaves night tuning unavailable. `image.night_tuning` 0|1, **default 0**.
- **Switch**, in stock's order around the IR-cut, the second half on the next day/night tick (1 s,
  never a blocking sleep): night = IR LEDs, night groups, IR-cut out; day = IR LEDs off,
  ColorToGray 0, IR-cut in, day groups. With the key at 0 nothing changes: IR-cut, IR LEDs and
  ColorToGray at once, as before.
- **Writes:** every group read whole and written only if it differs. ColorToGray follows the B/W
  state (so the day groups written at night keep it grey). No init-status poll: we are long past
  init (the IQ profile is in before anything here runs).
- **Baselines per mode:** the image controls (Brightness, Contrast, Saturation, Sharpness) and the
  ISP tuning (NRDeSpike, NR3D, WDR) keep a day baseline (read from the ISP after the IQ profile,
  as before) and a night one (the night file's group, checked like the day one; the day one where
  the night set doesn't have the group). A change at night scales the night baseline; after each
  switch the current values are applied to the new mode's baseline as part of the group write
  (a control at 50 writes the file's group unchanged). Day values never go into night groups.
- **Kept as ours:** the night shutter cap of 50 ms (`MI_NIGHT_SHUTTER_US`). Stock's night bin
  raises ExposureLimit MaxShutter to 250 ms, but that is the kernel AE's limit, which we don't run
  (CUS3A: our own AE); 250 ms would also drop the frame rate. The AE target and exposure tables of
  the night bin are skipped with the other AE groups.

## 5. Exposure limits: ours vs stock, ISP gain, night exposure
Stock runs the kernel AE, limited by ExposureLimit (5129, layout in section 2); we run our own AE
(CUS3A) and set shutter, sensor gain and ISP gain ourselves in `CusAEResult_t` (0x2e06:
Shutter +0x08, SensorGain +0x0c, IspGain +0x10, 1024 = 1x; docs/IFADO-MI-PIPELINE.md).

| Limit | Stock (kernel AE) | Ours before 2026-10-24 | Ours now (defaults) |
|---|---|---|---|
| Longest shutter, day | ExposureLimit MaxShutterUS (1e6/fps in "auto" shutter mode) | one frame time (40 ms at 25 fps), `image.shutter_day_max` | unchanged |
| Longest shutter, night | night bin: 250 ms | 50 ms (`MI_NIGHT_SHUTTER_US`), `image.shutter_night_max` | unchanged |
| Sensor gain | MaxSensorGain (not decoded here) | 32x | unchanged |
| ISP gain, day | day bin MaxISPGain 4096 = 4x (owner's 2026-10-24 reading) | fixed 1x | up to 4x, `image.isp_gain_day_max` 1..4 |
| ISP gain, night | night bin MaxISPGain 2048 = 2x [L] | fixed 1x | up to 2x, `image.isp_gain_night_max` 1..4 |
| Minimum shutter | MinShutterUS 30, 10000 / 8333 with anti-flicker | 20 us; anti-flicker whole half cycles | unchanged |

- **Order:** shutter up to its limit, then sensor gain to 32x, then ISP gain up to the mode's limit
  (src/mi/mi.c `ae_split`). ISP gain is a digital gain: it brightens the picture and its noise
  alike, so it comes last, as stock's limits imply. With a limit of 1 the AE is exactly the old one
  (host test). Anti-flicker and the shutter limits work as before (the shutter part of the split
  is unchanged); with anti-flicker the ISP gain is still never above the limit.
- **Values:** 1..4 for both keys (4 = stock's highest, the day bin's). Stock uses 4 by day and 2
  at night, and so do our defaults. A night limit above 2 goes beyond
  stock's night bin.
- **BV:** the AE result's BV (APEX, section "Run 4" of IFADO-MI-PIPELINE) still takes its ISO
  from the sensor gain alone, as before. Whether it should count the ISP gain depends on the same
  open question as the score (below): if the AE statistics see the ISP gain, the total would be
  right. Left for the owner to decide after the live check.
- **Defaults:** rtspd starts with 4 / 2 (stock's). Verified live on cam #1 under a street light (2026-10-24): with the day limit at 4 the AE settled at ISP gain 3481 (3.4x) with mean Y 40.1 on a target of 40, so the AE statistics see the ISP gain; the day/night score stayed 46 (colour); in `mi_cfg` an unset limit (0) means 1x, so tools that
  start the pipeline themselves (`tools/mi-probe`) keep the AE as it was.
- **Why (cam #1, 2026-10-23 night):** in colour under a street light our AE topped out at one
  frame of shutter and 32x sensor gain and the picture stayed too dark, where stock adds up to 4x
  ISP gain by day. The owner prefers colour while the street light is on; its colour score there
  is ~58, above `daynight.night_below` 15, so it stays in colour. (A score of 58 at one frame and
  32x means a mean Y of ~74, above the default target 40, where the AE would not be at its limits;
  the lamp itself may lift the mean. The new `ae.*` values show which limit the AE is at.)
- **The day/night score** (src/rtspd/daynight.c: mean Y / (shutter s x gain)) now uses the total
  gain (`mi_ae_info`: sensor x ISP / 1024). Its thresholds (15 / 1500) and reference scores were
  taken with ISP gain 1x. ISP gain only appears once the shutter is at its limit and the sensor at
  32x and Y is still under the target, that is in a scene scoring under about 31 by day (target
  40 / (0.04 s x 32), at 25 fps) or 25 at night (50 ms), so daylight and IR-lit night scores
  (~170) don't change, and neither does the day threshold (1500).
  - **Open, to check live:** whether the AE statistics (0x2e01) are taken after the ISP gain. If
    they are, Y rises with the ISP gain and the score stays what it was at the sensor's limit
    (the street-lit colour picture keeps ~58 and gets brighter). If they are taken before it, Y
    doesn't respond: the AE drives the ISP gain to its limit whenever the sensor is maxed and Y is
    below target, and the score falls by up to that factor (58 / 4 = 14.5, under night_below 15:
    cam #1 would switch to night). Check on cam #1 in colour after dark: `camcfg ctl get | grep
    '^ae\.'` with `image.isp_gain_day_max` 4, then 1: `ae.y` should follow `ae.isp_gain`. If it
    doesn't, set `image.isp_gain_day_max 1` (the old behaviour) until the AE accounts for it.
- **Night exposure** (`image.exposure_night`, `day` or 0..100, default `day` = as
  `image.exposure`): at night the AE target comes from it, on the same scale (2^((v-50)/25) x the
  base target). Stock's night bin has its own AETarget too (section 4.1; skipped there with the
  other AE groups). **30 is the recommended value for a street-lit or mostly dark scene:** cam #1's
  IR picture was overexposed, washed-out grey at the default 50 and right at 30. An IR-lit scene
  without other light (cam #2) looks right with the default. Lowering the night target lowers the
  exposure in proportion, so the day/night score doesn't move with it.
- **Visible live:** `camcfg ctl get` reports `ae.y`, `ae.target`, `ae.shutter_us`,
  `ae.sensor_gain` and `ae.isp_gain` (1024 = 1x); the chroot test's `--overnight` sampler logs them
  each minute.
