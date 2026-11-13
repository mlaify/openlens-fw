# Stock encoder and image settings (static analysis of `media_server`)

Goal: let our firmware reproduce the stock encoder rate control, H.264 profile, flip/mirror and
image options. **Static analysis only** of V3.5.2.1 `/opt/ch/media_server` (ET_EXEC, so Ghidra
addresses = ELF vaddrs) and `/opt/ch/libtools.so` (Ghidra address = vaddr + 0x10000). Nothing
vendor was executed. Vendor files stay outside the repo.

Confidence: **[C]** = read directly from decompiled code or constants; **[L]** = consistent with
live probe data as well; **[G]** = guess or inference (field names, semantics). Field names
follow SigmaStar's public I6C headers wherever the offsets agree, and those names are [G].

## 0. Product type: the switch behind most per-model branches
- `media_server` branches on a global product type (`*0x2344ac`; also `VideoManage +0x50`). It
  comes from libtools `product_type_read()` (`0x42b44`): `/tmp/product_type.txt` →
  `GetDeviceTypeFromStr()` (`0x5307c`), a table of 0x90 entries `{int id; char name[0x48]}`.
- The owner's camera writes **`MCA40E`** to `/tmp/product_type.txt` (bench-logs
  `probe5-irled-cam2.txt`, `night-watch-…-060550.txt`). In the libtools table (file offset
  0xc8c00), `MCA40E` has **id 0x730** [C]. Neighbours: MCA50E = 0x72a, MCA50P2 = 0x72d.
- Assuming `*0x2344ac` holds this libtools id (same value range, same function names) [G, high],
  every per-model branch below is evaluated for **0x730**. That assumption predicts the
  flip result in §3, and live probe 3 confirms it.

## 1. Rate control (CBR / VBR) and the 80-byte channel attr

### 1.1 How the mode is chosen
- The encoder object carries the per-stream config: `+0xac` EncodeFormat string, `+0xcc`
  BitRateControl string, `+0xec` GOP (XML `Initquant`; the web GOP field writes it), `+0xf0`
  kbps, `+0xf4` fps, `+0x100` qp_enable, `+0x104` qp_min, `+0x108` qp_max, `+0x10c`
  EncodeProfile, `+0x5c` channel (0 main, 1 sub) [C]. The qp_* offsets match libtools'
  EncodeConfig parser (`0x78090`): stream struct `+0x7c/+0x80/+0x84` = qp_enable/min/max, and
  the "set custom qp" log [C].
- `FUN_00052048(str)` returns `strcmp(str, "CBR") != 0`: **0 = CBR, 1 = anything else (VBR)**
  [C]. A third mode (2) exists only for H.265 when EncodeFormat is `"H265+"` and
  `/opt/ch/enable_avbr.flag` exists (`FUN_0002610c`). That flag isn't on the rootfs.
- Web "Quality" (`BitRateQuality`: 0 = Customize, 1–5 = worse…best) is **not read by either attr
  builder** [C: no access to that field]. Most likely it only preselects the bitrate in the web
  page [G].

### 1.2 RC mode numbers (`attr +0x28`, at[10])
| Codec | CBR | VBR | AVBR (H265+ + flag only) | Source |
|---|---|---|---|---|
| H.264 (`FUN_0001ce24`) | **1** | **2** | 4 (dead code: rate type is never 2 for H.264) | [C] |
| H.265 (`FUN_0002610c`) | **9** | **10** | 12 | [C] |

### 1.3 Attr words that depend on RC mode (H.264 builder `FUN_0001ce24`) [C]
| at[] | Offset | CBR | VBR |
|---|---|---|---|
| 10 | 0x28 | 1 | 2 |
| 11 | 0x2c | gop (`+0xec`) | gop |
| 12 | 0x30 | 0 (statTime) | 0 |
| 13 / 14 | 0x34 / 0x38 | fps / 1 | fps / 1 |
| 15 | 0x3c | kbps << 10 (bitrate, or **max** bitrate for VBR) | kbps << 10 |
| 16 | 0x40 | 0 | **maxQp = 48 (0x30)** |
| 17 | 0x44 | 0 | **minQp = 30 (0x1e)** for 0x730 (0x20 for products 0x194/0x1a0; 0x22 for 0x503–0x505, 0x14 on their sub stream) |
| 18, 19 | 0x48, 0x4c | 0 | 0 |

Custom QP (`qp_enable > 0`): minQp = `qp_min`, maxQp = `max(qp_min, qp_max)` (log
`"channel %d set custom qp %d-%d"`). The stock XML has `qp_enable="0"` (only stream 3 even lists
it), so the defaults apply [C].

The layout matches I6C `MI_VENC_AttrH264Vbr_t {gop, statTime, fpsNum, fpsDen, maxBitRate, maxQp,
minQp}` versus `…Cbr_t {gop, statTime, fpsNum, fpsDen, bitRate, fluctuateLevel}` [G names, C
offsets].

**H.265 VBR (for completeness, `FUN_0002610c`, plain "H265", product 0x730)** [C]: at[10] = 10,
at[16] maxQp = **50 (0x32)** if `*0x2345c4 == 0`, else 48. at[17] minQp = **32 (0x20)**; **20
(0x14)** on the sub stream (chn 1 or 4) when bitrate < 1,024,000 bps (1000 kbps). The custom-QP
override is the same. The global `0x2345c4` isn't resolved [G: likely a smart-encode flag]. The
smart-P call (`FUN_0016d9dc`/`FUN_0016d90c` = VENC nr45 Get / nr44 Set, 20-byte
`{1, gop - 1, u8 1}`) only runs for H265+ or when global `0x234284 != 0`, main stream only.

### 1.4 Stock also sets RC params after CreateChn (`MI_VENC_Get/SetRcParam`)
- The base init `FUN_00027368` (vtable slot +0x10) does `VencBase::Init` (`FUN_00027f48`:
  build attr, CreateChn, …), then `GetDefaultBitrate`, then **vtable slot +0x34 = SetRcParam**
  [C]. For CVideoH264 (vtable `0x19ece4`) that slot is **`FUN_0001d068`**; for H.265 it's
  `0x26560` (not decoded).
- `FUN_0001d068`: `MI_VENC_GetRcParam(dev 0, chn, &p)` (`FUN_0016d830`, nr43 `0xc044692b`),
  modifies words, then `MI_VENC_SetRcParam` (`FUN_0016d754`, nr42 `0x4044692a`, args =
  `{u32 dev, chn; u32 p[15]}` = 68 B; the **param struct is 60 bytes**) [C].
- Words written (index into the 15-word param; values [C], names [G], following I6C
  `MI_VENC_RcParam_t {u32 ThrdI[1]; u32 ThrdP[1]; u32 RowQpDelta; union …}`):

| Word | Offset | CBR | VBR (owner's main stream) | Name [G] |
|---|---|---|---|---|
| 0–2 | 0x00–0x08 | (as read) | (as read) | ThrdI, ThrdP, RowQpDelta |
| 3 | 0x0c | 48 | (as read: = attr maxQp) | MaxQp |
| 4 | 0x10 | 20 | (as read: = attr minQp) | MinQp |
| 5 | 0x14 | −4 | **−4** if gop/fps ≥ 3; **6** if gop/fps == 2; **12** if gop/fps < 2 | IPQPDelta |
| 6 | 0x18 | 48 | **80** | CBR: MaxIQp / VBR: ChangePos |
| 7 | 0x1c | 20 | **51**, or qp_max if qp_enable and qp_max ≥ qp_min | CBR: MinIQp / VBR: MaxIQp |
| 8 | 0x20 | 20 | **30**, or qp_min (same condition) | CBR: MaxIPProp / VBR: MinIQp |
| 9 | 0x24 | (as read) | **12** | VBR: MaxIPProp |
| 10 | 0x28 | (as read) | **1.2 × bps** if gop/fps ≥ 3 (unchanged if == 2); **0.9 × bps** if < 2 | VBR: MaxISize (bits) |
| 11 | 0x2c | (as read) | **0.2 × bps** if gop/fps ≥ 2; **0.1 × bps** if < 2 | VBR: MaxPSize (bits) |
| 12–14 | 0x30–0x38 | (as read) | (as read) | (AVBR adds 25 at word 12) |

  `bps = kbps << 10`, and gop/fps is integer division. The multipliers are the doubles at
  `0x1d210` = 0.9, `0x1d218` = 0.1, `0x1d220` = 0.2, `0x1d228` = 1.2 [C].

### 1.5 What stock builds for the owner's settings
Main stream: H.264 High, VBR, 4000 kbps, GOP 100. fps is assumed 25 (the XML default; the
owner didn't state it). [C values, assuming product 0x730 and qp_enable = 0]:
```
attr: at[0]=2  at[1..2]=2560,1440  at[3]=2560*1440*15/37  at[4]=2 (High, see §2)
      byte 0x14=1  at[6..7]=2560,1440  at[8]=0  at[9]=1
      at[10]=2 (H264 VBR)  at[11]=100  at[12]=0  at[13]=25  at[14]=1
      at[15]=4096000  at[16]=48  at[17]=30
rcparam (Get → modify → Set, right after CreateChn):
      w5=-4  w6=80  w7=51  w8=30  w9=12  w10=4915200  w11=819200
```
Sub stream: H.264 VBR 500 kbps: the same, with at[3] = w·h (sub-stream bufSize rule for chn 1),
at[15] = 512000, minQp 30, w10/w11 = 1.2 / 0.2 × 512000 when gop/fps ≥ 3.

**For `venc_attr()`:** VBR = set at[10] = 2 (H.264) / 10 (H.265), at[16] = 48 (H.265: 50),
at[17] = 30 (H.265: 32), and keep at[15] = kbps << 10 as the max bitrate. To match stock
exactly, also do the `GetRcParam` → patch → `SetRcParam` step (nr43 / nr42, 68-byte args)
before `StartRecvPic`.

## 2. H.264 profile [C]
- The web "Profile" select (`camera_AdvanceBaseProfile`) writes XML `EncodeProfile`:
  **0 = "High Profile", 1 = "Main Profile", 2 = "Base(line)"** (`var/www/js/encodeConfig.js`
  labels the option ids `AdvanceBaseProfile_Disable/Enable/Base` with
  `w_HighProfile/w_MainProfile/w_BaseProfile`).
- `CVideoH264` builder: `at[4] = FUN_0005205c(EncodeProfile)`, where `FUN_0005205c(x)` = `x == 0
  ? 2 : (x != 2 ? 1 : 0)`. So **XML 0 (High) → at[4] = 2, 1 (Main) → 1, 2 (Baseline) → 0**.
  This is the MI convention 0 = Baseline, 1 = Main, 2 = High [G names, C mapping].
- **Our `at[4] = 0` therefore requests Baseline.** The owner's High Profile is **at[4] = 2**.
  The H.265 builder always writes at[4] = 0.

## 3. Flip / mirror [C + L]
- **Mechanism: sensor orientation only.** `CIsp::SetMirror` (`FUN_0001cae8`, log string
  "SetMirror") calls **`MI_SNR_SetOrien(pad, bMirror, bFlip)`** (`FUN_0016aef0`, SNR nr12
  `0x4008690c`, args 8, `{u32 pad; u8 mirror; u8 flip; pad}` [G layout], then reads it back with
  `MI_SNR_GetOrien` (`FUN_0016af70`, nr13 `0xc008690d`), retrying up to 10 times 100 ms apart.
  - It's called from the `CIsp` constructor (`FUN_0001cd20`) at init, and from
    `SetVideoCapture` (`FUN_00021cc8`) when HFlip/VFlip change.
  - The ISP ChnParam mirror/flip (`Isp::Init` `FUN_0001c540`) are **0** except in stitch mode on
    product 0x68b. The SCL output-port mir/flip are **0**: `ST_SclCreateChn` (`FUN_000fad34`)
    memsets the 24-byte port param and sets only the size and pixfmt; SCL rotation is 0.
- **Value computation** (`InitmIsp` `FUN_0001d9c8`; the same logic is in `SetVideoCapture`):
  `mirror = (HFlip > 0)`, `flip = (VFlip > 0)` (Capture struct `+0x18` / `+0x1c`; the debug log
  prints them as "bHFlip, bVFlip"), then XORs:
  1. **Per product:** for 0x730 the code reaches the `0x720 + n` bitmask `0x13433` (at `0x1dd20`
     and `0x21cc0`). Bit 16 (0x730) is set, so **both mirror and flip are inverted** [C].
  2. `/mnt/nand/imageflip` `ImageFlip=(n)` (read by `FUN_0001fccc` into `VideoManage +0x23f4`):
     n = 1 or 3 inverts mirror; n = 2 or 3 inverts flip.
  3. `/opt/ch/force_image_flip.flag` inverts both (not on the rootfs).
- **Result for MCA40E (no imageflip file):** `SetOrien(mirror = !HFlip, flip = !VFlip)`. The
  owner's "Enable / Enable" gives **`SetOrien(0, 0)`** = no mirror, no flip.
  - [L] Probe 3 (stock streaming) dumped sensor pad 0 with **bmirror 0, bflip 0**.
  - The SC4336P driver (`cus_sc4336p_mipi_20251225.ko`) has `pCus_SetOrien`/`GetOrien`. Its
    only data-table write of the orientation register is `{0x3221, 0x00}`, so the power-on
    default is also normal orientation [C, the register meaning is SmartSens convention [G]].
  - This is why our stream (no SetOrien call) already looks like stock.
- **For our firmware:** web "Enable" = sensor default. To support the setting, call
  `MI_SNR_SetOrien(0, !hflip, !vflip)`. "Disable/Disable" gives `SetOrien(1, 1)` (rotated
  180°).

## 4. Defog ("Defogging", DfrogFlag / DfrogValue)
**Finding: stock `media_server` never applies it** [C, high confidence].
- The web page (`cameraConfig.js`) writes `<Capture DfrogFlag DfrogValue>`. libtools
  parses/serializes them as Capture struct words `[0x14]` / `[0x15]` (`+0x50` / `+0x54`;
  serializer `0x73918`). Next to them are WDRMode `+0x40` and WDRValue `+0x4c`.
- `media_server` has **no** "Dfrog"/"defog" string except the linked library's
  `MI_ISP_IQ_SetDefogCall` name, and nothing references that string.
- The ISP controller copies the config to `this + 0x2c` (`FUN_00041e08`), so DfrogFlag/Value
  would be at `+0x7c` / `+0x80` (VideoManage's copy: `+0x58` base → `+0xa8` / `+0xac`). I
  decompiled all 1626 functions in 0x14000–0x6a000: none of the 27 ISP-channel functions
  touches `+0x7c`/`+0x80`, and no VideoManage function touches `+0xa8`/`+0xac`.
- The IQ-set wrappers that the app calls are only these cmd IDs (callers in parentheses):
  - 0x1004 (`0x3fd80`/`0x3fdd4`, day/night)
  - 0x1005 (`0x409b8`), 0x1006 (`0x40a40`), 0x100a (`0x41d5c`): Contrast / Brightness /
    Saturation [G]
  - 0x100e (`0x42398`), 0x100f (`0x422e8`): NR [G]
  - 0x1012 (`0x41b68`): Sharpness [G]
  - **0x1016 WDR** (`0x41f40` ISP_SetWDR, `0x41ff4`/`0x420b8` backlight)
  - 0x14xx AE, 0x1802 AWB [G], and the CUS3A 0x2e.. set
  None is fed from the defog fields.
- So the "Defogging Enable, level 128" setting has **no image effect on stock**. Our firmware
  can ignore it. If we wanted defog anyway, SigmaStar's `MI_ISP_IQ_SetDefog` cmd ID isn't
  identifiable from this binary (no caller) [open].
- Related, in case WDR is ever needed: `ISP_SetWDR` (`FUN_00041f40`) does `MI_ISP_IQ_GetWDR`
  (`0x170758`, 1036 B = 16 × 0x3c-byte entries + header) and, when WDRMode ≠ 0, sets each
  entry's byte `+0x10` = `WDRValue × table[i] / 128` (table at `this + 0x94c`). It then calls
  `MI_ISP_IQ_SetWDR` (cmd 0x1016, `0x1706c0`) [C]. WDR, backlight, the two NR groups and
  anti-flicker are decoded in full, and implemented, in docs/STOCK-IMAGE-TUNING.md.

## 5. Day/night thresholds (optional item)
The ircut thread handler `FUN_00042c4c` switches on IrcutMode (`this + 0x920`, from Capture
`IrcutMode`; the XML default is 0) [C]:

| IrcutMode | Behaviour |
|---|---|
| **0 Auto** | Three sub-paths, chosen by flags (below) |
| 1 | Time schedule (IrcutNightStartTime / EndTime) |
| **2** | **Passive:** `/dev/irled` status alone (`FUN_0003feb4`: 1 = day, 2 = night, >2 → 1; inverted only for products 0x199/0x19d/0x19e). No AE gating |
| 3 | Manual |
| 5 | ADC |
| 6 / 7 | Forced variants |
| −1 | Aging test |

**Auto (mode 0) sub-paths:**
- **ADC** (two globals `DAT_000406a8/ac` set; `FUN_000403b4`): reads `/dev/adclp0`.
  - Thresholds: day→night = `IrcutSensitivity × 3`, night→day = `light_off_sensitivity × 3`.
    An `adc.xml` config (path built with `/tmp`) can override them.
  - Night if ADC ≤ day→night on two reads (a `usleep` apart); day if ADC ≥ night→day on two reads.
- **Image/AE** (`FUN_00040168` "ircut_active_by_image"): `MI_ISP_QueryExposureInfo` (IQ get cmd
  0x1402, `FUN_00172ef0`).
  - **Night when LVx10 < 6. Day when LVx10 ≥ 35 − IrcutSensitivity / 10** (e.g. 30 at
    sensitivity 50).
  - Hold-off: it won't return to day within 600 s of a night switch once there have been ≥ 3
    switches. The gain is only logged.
- If flag `this + 0x1568` is set, Auto only records the `/dev/irled` status into
  `this + 0x156c`, and switching happens elsewhere [G].

**Which sub-path MCA40E takes in Auto is unresolved.** The globals and `+0x1564/+0x1568` are set
outside the decompiled code; the bench notes show `/dev/irled` in use [open].

`light_off_sensitivity` is also used by the smart-light BV calibration (`FUN_0004c378`), but only
when a `light.debug.xml` exists [C]. Mapping of the web labels: "Light On Illumination" =
`IrcutSensitivity` and "Light Off Sensitivity" = `light_off_sensitivity` [G].

## Evidence index (media_server unless noted)
| Address | What |
|---|---|
| `0x1ce24` / `0x2610c` | CVideoH264 / CVideoH265 channel-attr builders (vtable slot +8) |
| `0x52048` | BitRateControl string → 0 CBR / 1 other |
| `0x5205c` | EncodeProfile → MI profile (0→2, 1→1, 2→0) |
| `0x27368` | Venc init: `0x27f48` (CreateChn) → GetDefaultBitrate → vtable+0x34 |
| `0x1d068` | CVideoH264 SetRcParam logic (vtable +0x34) |
| `0x16d754` / `0x16d830` | MI_VENC_SetRcParam / GetRcParam wrappers (nr42 / nr43, 68 B) |
| `0x1cae8` | CIsp::SetMirror → MI_SNR_SetOrien / GetOrien (`0x16aef0` / `0x16af70`) |
| `0x1cd20` | CIsp constructor (stores mirror/flip at +0x46/+0x47, calls SetMirror) |
| `0x1d9c8` / `0x21cc8` | InitmIsp / SetVideoCapture flip computation |
| `0x1fccc` | reads `/mnt/nand/imageflip` |
| libtools `0x5307c`, table at file 0xc8c00 | product-name → id (MCA40E = 0x730) |
| libtools `0x771f8` / `0x73918` | Capture XML parse / serialize (field offsets) |
