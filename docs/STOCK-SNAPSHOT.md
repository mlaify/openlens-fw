# Stock JPEG snapshot path (static analysis of `media_server`)

Goal: find out how the stock V3.5.2.1 `/opt/ch/media_server` makes JPEG snapshots, so our MI
layer can add one. **Static analysis only.** Nothing vendor was executed or copied into the
repo. `media_server` is ET_EXEC, so Ghidra addresses are ELF vaddrs. `libcgibin.so` and
`libtools.so` addresses are Ghidra addresses (vaddr + 0x10000).

Confidence: **[C]** = read from decompiled code or constants; **[L]** = also matches live probe 3
(`bench-logs/cam1-live-probe-3.txt`); **[G]** = guess or inference. Field names follow
SigmaStar's public headers wherever the offsets agree, and those names are [G].

## 0. Summary
- Stock has **two** snapshot implementations, chosen per product at run time [C]:
  - **`CJpgSelf`** (`encode/video/vjpg_self.cpp`) is software. It grabs one NV12 frame from an
    SCL output port with `MI_SYS_ChnOutputPortGetBuf` and encodes it with a statically linked
    libjpeg (`nv12_to_jpgfile`). It never touches VENC.
  - **`CJpg`** (`encode/video/vjpg.cpp`) is hardware: VENC **device 8**, channel 3 or 4,
    JPEG.
- **The owner's MCA40E (product 0x730) uses `CJpgSelf`** [C + L]:
  - The HW path needs `/opt/ch/flag.venc.snapjpg` or a product in a hard-coded list; 0x730 has
    neither (§1).
  - Probe 3 shows no `mi_venc8`, and SCL port 1 has user depth 1 / buffer quota 4, which is
    exactly what `CJpgSelf`'s port grabber sets (§2).
- So **no stock code path on this camera exercises VENC JPEG.** The HW layout below comes from the
  `CJpg` and `CVideoMJPEG` code that sits unused in the same binary. It is real stock code, but
  not proven on this SoC/kernel [G for "works here"].
- **What stock serves** [C]:
  - `snapshot.cgi` and every other `MsgSetSnapJpegFile` client get **one frame from SCL dev 0
    chn 0 port 1 (the sub-stream port).** With the owner's config that is **640×360**.
  - It is libjpeg-encoded at **quality 50**, whatever `stream=` the caller asks for (§4).

## 1. Which implementation runs (VideoManage ctor `FUN_000201e0`, `InitVenc` `FUN_0001e370`)
- `VideoManage +0x2400` ("use VENC JPEG") is set only for products in 0x684..0x6a3 (bitmask
  `0x81f802e3`) or 0x626, or when `/opt/ch/flag.venc.snapjpg` exists (`0x20690`).
  - 0x730 isn't in the list, and the flag isn't on the rootfs, so **+0x2400 = 0** [C].
  - `+0x2404` (0x782/0x783/0x786–0x789) and `+0x23d8` (dual-sensor products) are also 0 for
    0x730 [C].
- `ENABLE_JPG_SNAP = [main, sub]` (`VideoManage +0x23f0/+0x23f1`) is set by the ctor's caller
  `FUN_000504a4`:
  - `sub = !exists("/opt/ch/support.main.jpeg.flag")`
  - `main = exists(that flag)`, or a product in a short list: 0x68b; 0x684..0x6a3 with mask
    `0x81c00001`; 0x698 or 0x68d with a global set
  - For 0x730 with no flag: **[0, 1]**, so only the sub-stream snapshot object exists [C].
- `InitVenc`, third loop (`0x1e86c..`): for each enabled index i (0 = main, 1 = sub), `w,h` =
  the stream size `VideoManage +0x2388 + i*8` (forced to 1280×720 for i = 1 when global
  `*0x234290 == 1`). Then:
  - `+0x2400 == 0 && +0x2404 == 0`: `new CJpgSelf` (`FUN_0001b440`, 0x108 B,
    vtable `0x19df3c`), source = `Scl(VideoManage +0x14) +0x12c` (the SCL "user port" object).
    Stored at `VideoManage +0x38 + i*4`. **This is the MCA40E path.**
  - `+0x2404 != 0`: `CJpgSelf` variant `FUN_0001b324` (takes the Scl object itself).
  - `+0x2400 != 0`: `new CJpg` (`FUN_00027780`, 0xb0 B, vtable `0x1a2170`), §3.
- `StartVenc` (`FUN_0001ebb8`) calls `StartRecvPic` only on the stream encoders `+0x2c..+0x34`,
  not on the JPEG objects. JPEG capture is on demand only [C].

## 2. MCA40E path: `CJpgSelf` (software JPEG from SCL port 1)
**Frame source** [C + L]:
- `Scl::Init` (`FUN_00022b10`, tail) creates the user-port object `FUN_00022558(obj, 0x22, sclDev,
  sclChn, port = 1, 0, 1)` (0xb8 B) and sizes it from the Scl port-1 size (`+0x44/+0x46`).
- Its ctor calls `FUN_000224ec` with r1 = 1, r2 = 4 (disassembly at `0x225c8`):
  `MI_SYS_SetChnOutputPortDepth(0, {0x22, 0, 0, 1}, user 1, buf 4)`.
  - [L] Probe 3: SCL port 1 **usrDepth 1, BufCntQuota 4**, UsrGetFifoQ discarding every frame.
    That matches a grabber that is set up but idle.
  - SCL port 2 (800×480, NV12 0x8ca00 B, user-locked, ~3.4 fps) is **not** the snapshot. It is
    the IVE/motion thread `FUN_000347ec`, which checks for width 800 and height 0x1e0.

**Trigger** [C]:
1. A client sends media message **0x127** with a 0x98-byte payload
   `{u32 stream; u32 quality; char dir[64]; char file[80]}` (crop variant: `file[64]` +
   `x, y, w, h`). Senders are libtools `SetSnapJpegMsg` `0x350c0` and `MsgSetSnapJpegFile` `0x3e2ac`.
2. Handler `FUN_000eb830` case 0x127 → `FUN_00051490` → **`VideoManage::SnapJpeg`
   `FUN_0001fc00`**.
3. `SnapJpeg` picks the object: with `[main, sub] = [0, 1]` it **always uses the sub object
   (index 1); the requested stream is ignored.** It then calls `CJpgSelf::SnapJpeg`
   (`FUN_0001b214`):
   - quality is clamped to **50..99**
   - path = `dir + "/" + file`
   - crop rect stored at `+0xf8..+0x104`
   - `FUN_000224a4(userPort, 1)` sets the port's "get one buffer" flag and starts its thread.

**Grab + encode** [C]:
1. User-port thread `FUN_00022390`:
   - `SetChnOutputPortDepth(port, 1, 4)`
   - while the flag is set: `MI_SYS_ChnOutputPortGetBuf({0x22, 0, 0, 1}, &bufInfo, &h)`
     (libmi_sys, SYS nr19 `0xc0f06913`, 240 B)
   - copy via `FUN_00022258`
   - `PutBuf` (nr20 `0x40086914`, 8 B)
   - clear the flag (one frame)
   - on stop: depth (0, 4).
2. `CJpgSelf` thread `FUN_0001adc4` polls every **100 ms** (`0x186a0` µs). When the port's frame
   counter moves:
   - **`nv12_to_jpgfile(virt, w, h, quality, path)`** (`FUN_000ecdd4`, libjpeg: quality
     clamped 10..100, `raw_data_in`, Y 2×2 / chroma 1×1) for no crop, or the crop variant
     `FUN_000ecdf8`
   - then `FUN_000224a4(port, 0)` to stop the grabber
   - then the callback `snapjpgCallback` (`FUN_00050448`): `touch <path>.ok` and
     `MsgNotifyAlarm(0x17, …)`.
3. The image size is the port-1 frame size, i.e. **the sub-stream resolution (640×360 here)**
   [C for the source, L for the size: port 1 feeds VENC chn 1].
4. Odd detail: the encoder's chroma row pointers address the frame as **planar I420** (`U = base
   + w·h + (w/2)·(y/2)`, `V = U + w·h/4`), not interleaved NV12, unless `FUN_00022258`
   de-interleaves while copying (not checked) [C addressing, G effect].

## 3. Hardware path (unused on MCA40E): `CJpg`, VENC device 8
**Construction** (`InitVenc` → `FUN_00027780` → base `FUN_00027d04`) [C]:
- VENC chn = **i + 3** (3 = main-size snapshot, 4 = sub-size); eType at `+0x50` = **4**.
- Bind source = `{module 0x22 (SCL), dev 0, chn 0 (1 if global *0x234610), port P}`.
  - Normally P = **1**. P = 2 only when `*0x234610 != 0 && *0x234290 == 1`.
  - When the main snapshot is enabled with `+0x2400`, `InitScl` (`FUN_00020c0c`) **swaps the
    port 0 / port 1 sizes** and `InitVenc` swaps the main/sub VENC sources. Port 1 then carries
    the main resolution, and both main H.264 and the JPEG take it from port 1.
  - So stock always gives the JPEG the FRAME_BASE port, never the HW_RING one [C; the reason is
    G].
- srcFps = VIF/sensor fps (`*(VideoManage+4) +0x24`, 25); **dstFps = 1**; initial Qfactor
  `+0x84` = **90** (0x5a).

**Init** = `VencBase::Init` `FUN_00027f48` (vtable +0x10; `CJpg` has no RcParam step) [C]:
1. Attr from the `CJpg` builder **`FUN_000273a0`** (80 B, below).
2. First JPEG channel only: **`MI_VENC_CreateDev(8, {maxW, maxH})`**, nr76 `0x400c694c`,
   args 12 `{u32 dev = 8; u32 maxW; u32 maxH}`.
   - maxW/H = this JPEG channel's w/h, unless a global override is set (0xa00×0x5a0, product
     0x695 only).
   - **No ring pool for dev 8.** The ring pool is only on the H.264/H.265 branch.
3. **`MI_VENC_CreateChn(8, chn, attr)`**, nr0 `0x40586900`, args 88. The wrapper `FUN_0016b7d0`
   keeps the per-channel stream context in slot **16 + chn** for dev ≥ 8. Right after create it
   runs `FUN_0016b430`:
   - `open("/dev/mi_poll")`
   - `MI_VENC_GetFd` nr16 `{dev, chn, pollFd, id}`
   - `ioctl(pollFd, 0, id)`
   (Stock's wrapper does this for every channel; we do it ourselves after setup.)
4. **No `SetMaxStreamCnt`** for dev 8. Stock calls nr13 only on the H.264/H.265 branch.
5. Bind (`FUN_00027df0`):
   `{0x22, 0, 0, P} → {2 (VENC), 8, chn, 0}`, srcFps 25, dstFps 1, bindParam 0.
   - Type = `*0x234620 ? 4 : 1`, and REALTIME (4) when `*0x234610 == 0` and the SCL source chn
     is 1. With the globals at 0 (as for the normal single-SCL-channel build) that is
     **FRAME_BASE (1)**. The globals are set elsewhere (unresolved; `0x234610` also gates the
     `/opt/ch/flag.three_video` dev choice).

**JPEG channel attr (80 B, `FUN_000273a0`)** [C values; names G from I6C `MI_VENC_AttrJpeg_t` +
`MI_VENC_AttrMjpegFixQp_t`]. **The JPEG layout differs from H.264/H.265**: the attr has no profile
word, so bByFrame sits at +0x10, not +0x14.

| Offset | Field | Stock value |
|---|---|---|
| +0x00 | eType | **4** (JPEG) |
| +0x04 / +0x08 | maxW / maxH | w / h |
| +0x0c | bufSize | 0 |
| +0x10 | u8 bByFrame | 1 |
| +0x14 / +0x18 | picW / picH | w / h |
| +0x1c / +0x20 | bSupportDCF / restartMarkerPerRow | 0 / 0 |
| +0x24 | — | 0 |
| +0x28 | eRcMode | **8** = MJPEG FIXQP (matches the Tiramisu enum: H264 1–5, MJPEG CBR 6 / VBR 7 / FIXQP 8, H265 9–12) [value C, name G] |
| +0x2c / +0x30 | srcFrmRateNum / Den | **1 / 1** (`+0x78`) |
| +0x34 | u32Qfactor | **90** (`+0x84`) |
| +0x38..+0x4c | — | 0 |

`CVideoMJPEG` (the MJPEG *stream*, `FUN_00022740`) uses the same layout: eType 4, RC 8, fps =
stream fps, Qfactor **50**. Its SetRcParam (`FUN_0002279c`, vtable +0x34) resets Qfactor to 50
via JpegParam when BitRateControl is "CBR" [C].

**JPEG param: `MI_VENC_Get/SetJpegParam`** [C]:
- Get = nr41 `0xc0906929`, Set = nr40 `0x40906928`; args 144 = `{u32 dev; u32 chn;
  param[136]}`. Wrappers: `FUN_0016d684` / `FUN_0016d5b4`.
- `param` = I6C `MI_VENC_ParamJpeg_t {u32 u32Qfactor; u8 YQt[64]; u8 CbCrQt[64]; u32
  u32McuPerEcs}` (4 + 64 + 64 + 4 = 136) [size C, names G].
- Stock does Get → overwrite word 0 (Qfactor) → Set and leaves the tables as read.
- SigmaStar's `ST_Venc_CreateChannel`-style helper `FUN_000fa7a4` does the same right after
  CreateChn(8, …): Qfactor = attr word 13, or **60** if that is 0.

**Snapshot = `CJpg::SnapJpeg` `FUN_00027578`, one-shot via Start/Stop** [C]:
1. Quality clamp (`+0x48` = width):
   - width < 1920: q ≥ 100 → 99; 16 ≤ q ≤ 34 → 35; else q
   - width ≥ 1920: q ≥ 36 → **35**; 16 ≤ q ≤ 19 → 20; else q
2. `GetJpegParam(8, chn)`, then Qfactor = q, then `SetJpegParam(8, chn)`.
3. Push `dir + "/" + file` onto a pending list.
4. If the list was empty: **`MI_VENC_StartRecvPic(8, chn)`**, nr4 `0x40086904`, args 8.
   - **Not** `StartRecvPicEx`: stock never uses a frame-count receive. The channel runs at its
     1 fps until drained.
5. Read (vtable +0x1c `FUN_000278a0`): `ReadStream` (`FUN_00027cf4`, with **dev = 8 because
   eType == 4**). This is the same protocol as H.264:
   - `Query` nr7
   - `GetStream` wrapper `FUN_0016c1f4` (nr54/55 map, nr57 slices, nr10 info; flags codec
     bits = 4) with a 40 ms timeout
   - `SaveStream` (`FUN_000273f8`): pops one filename; writes pack 0, appends the rest. That
     is the complete JPEG file, with no added headers [C writes, G "complete JFIF"].
   - `ReleaseStream` `FUN_0016cd8c` (nr69/60/11)
6. When the pending list becomes empty: **`MI_VENC_StopRecvPic(8, chn)`**, nr6 `0xc00c6906`,
   args 12 `{dev; chn; u32}`. The wrapper `FUN_0016be00` retries up to 200 × 10 ms while it
   returns busy (`0xa0022012`).

## 4. Who asks for snapshots, and at what size
- **HTTP `snapshot.cgi`** = libcgibin `http_snapshot_request` (`0x3966c`):
  - stream: `strstr(query, "stream=1")` → 0, otherwise 1 (when the two dual-stream globals are
    0). Other variants are parsed but don't change the size.
  - **quality is always 50 (0x32)**
  - file `/tmp/snapshot_stream%d_%x_%x.jpg`, or `MsgSetSnapCropJpegFile` with
    `crop=x,y,w,h`
  - it then polls `/tmp/<f>.ok` every 10 ms, up to 300 times (3 s), and sends the file as
    `image/jpeg` [C].
- **ONVIF `GetSnapshotUri`** (web_server `0x68568` / `0x6cf34`) returns
  `…/cgi-bin/snapshot.cgi?stream=N`, with N = 1 for the first profile and 2 for the second (−1
  with `g_snap_order`). That's the same CGI.
- hik_server (`snap.hik.jpg`), comm_server and alarm snaps (`/tmp/alarm_snap`) use the same
  message 0x127.
- **Size served on MCA40E:** the sub-stream size, **640×360** with the default/owner config
  (`EncodeConfig Stream="2" 640X360`) [C path + L port 1 = sub].
- `JpegConfig Enable/Stream/Quality/Framerate` (XML default `1 / 0 / 80 / 2`): media messages
  0x10d / 0x103 / 0x106 (`MSG_CMD_SET_JPG_ENABLE`, `…JPEG_QUALITY`, `…JPG_FRAMERATE`) are **only
  logged** in `FUN_000eb830`. These settings don't affect stock snapshots [C].

## 5. For our MI layer (recommendation)
Model a HW snapshot on `CJpg`, using our existing raw ioctls:
1. After `setup_venc()`, create the JPEG device:
   - `CreateDev nr76 {8, W, H}`
   - `CreateChn nr0 {8, chn, attr}` with the §3 table: eType 4, RC 8, fps 1/1, Qfactor 90. Use
     chn 0, or 3 like stock [G: the chn number is free].
   - `GetFd nr16` + mi_poll bind for (8, chn).
   - Skip SetMaxStreamCnt and the ring pool.
2. **Source port:**
   - **Sub-size snapshot (what stock serves):** bind SCL port 1 → VENC (8, chn), FRAME_BASE,
     src fps → dst 1. That is the same port our sub-stream already uses with FRAME_BASE, and an
     MI output port can feed several binds [G: stock never does this shared bind on this SoC].
   - **Main-size snapshot:** don't bind to port 0 (it's HW_RING to VENC chn 0). Stock avoids
     that by moving the main stream to the FRAME_BASE port. Enable **SCL port 2** at the main
     size (UseSclMask 7 allows 3 ports; stock uses port 2 only for 800×480 IVE) and bind it
     FRAME_BASE at 1 fps [G].
3. Snapshot:
   - `GetJpegParam nr41` → set Qfactor → `SetJpegParam nr40` (144-byte args)
   - `StartRecvPic nr4 {8, chn}`
   - wait on its mi_poll fd
   - `mi_read_stream`-style nr7 / 54 / 55 / 57 / 10, then release 69 / 60 / 11, **with dev = 8**
   - `StopRecvPic nr6 {8, chn, 0}` (retry on busy)
   - The packs concatenated are the .jpg.
4. **Code change needed:** our ring helpers (`venc_map_ring`, slice loop, `venc_release` in
   `src/mi/mi.c`) hard-code `dev = 0` and index `vst[]` by chn. They need a dev parameter and a
   separate context for (8, chn). The kernel keys the buffer by (dev, chn) [C from the wrapper
   slots].
5. Software fallback (stock-equivalent): `MI_SYS_ChnOutputPortGetBuf` (SYS nr19, 240 B) on SCL
   port 1 with user depth 1, then encode in userspace. It needs a JPEG encoder in our static
   binary, so the HW path is preferred.

## Evidence index (media_server unless noted)
| Address | What |
|---|---|
| `0x201e0` | VideoManage ctor: `+0x2400` (flag.venc.snapjpg / product list), `+0x2404`, `+0x23d8`, `+0x23f0/1` |
| `0x504a4` | ctor caller: ENABLE_JPG_SNAP from `/opt/ch/support.main.jpeg.flag` |
| `0x1e370` | InitVenc: third loop creates CJpgSelf / CJpg per index ("ENABLE_JPG_SNAP = [%d, %d]") |
| `0x20c0c` | InitScl: port sizes, port 0/1 swap when `+0x2400 && main` |
| `0x22b10` / `0x22558` / `0x224ec` | Scl::Init creates the port-1 user-get object; depth (1, 4) |
| `0x22390` / `0x224a4` | user-port grab thread (GetBuf / PutBuf), enable/disable ("SetGetBuffer") |
| `0x1b440` / `0x1b214` / `0x1adc4` | CJpgSelf ctor / SnapJpeg (q 50..99) / encode thread (100 ms) |
| `0xecdd4` / `0xecdf8` | nv12_to_jpgfile (libjpeg) / crop variant |
| `0x1fc00` / `0x51490` / `0xeb830` | VideoManage::SnapJpeg / msg 0x127 glue / media msg handler |
| `0x27780` / `0x27d04` | CJpg ctor (Qfactor 90, fps 1) / VencBase ctor field map |
| `0x273a0` / `0x22740` | CJpg / CVideoMJPEG channel-attr builders |
| `0x27f48` / `0x27df0` | VencBase::Init (dev 8 CreateDev/CreateChn) / SCL→VENC bind |
| `0x27578` / `0x278a0` / `0x273f8` | CJpg SnapJpeg (clamp, JpegParam, StartRecvPic) / read + StopRecvPic / SaveStream |
| `0x16b568` / `0x16b7d0` / `0x16b430` | CreateDev nr76 / CreateChn nr0 (dev ≥ 8 → slot 16+chn) / GetFd + mi_poll |
| `0x16d684` / `0x16d5b4` | GetJpegParam nr41 / SetJpegParam nr40 (144 B) |
| `0x16bd3c` / `0x16be00` | StartRecvPic nr4 (8 B) / StopRecvPic nr6 (12 B, busy retry) |
| `0x000fa7a4` | ST helper: CreateChn(8) + Qfactor (attr word 13 or 60) |
| libcgibin `0x3966c` | `http_snapshot_request` (quality 50, `/tmp/snapshot_stream%d_%x_%x.jpg`, `.ok` wait) |
| libtools `0x350c0` / `0x3e2ac` | SetSnapJpegMsg / MsgSetSnapJpegFile (0x98-byte payload) |
| web_server `0x68568` / `0x6cf34` | ONVIF GetSnapshotUri → `snapshot.cgi?stream=N` |
| vtables | CJpg `0x1a2170`, CVideoMJPEG `0x1a08fc`, CJpgSelf `0x19df3c` |
