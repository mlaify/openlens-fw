# Ifado MI video pipeline: reverse-engineered from stock `media_server`

Working notes for the thin Ifado MI layer (owner's option 2; see IFADO-PLATFORM.md). Everything
below is static analysis of the stock V3.5.2.1 `/opt/ch/media_server`. It is an ET_EXEC, so
Ghidra addresses are the ELF vaddrs. Status: **in progress.** SNR, VIF, ISP, SCL, the binds, VENC
create/attr, the stream/mmap protocol, struct layouts and the IQ load path are done; live
confirmation (probe 3) and then `mi-probe` are next.

## Method / tools
- `tools/ghidra/IoctlInventory.java` + `IoctlDeviceMap.java` give
  `analysis/ifado-mi-api-table.tsv`. Rows whose `name_source` starts with **`verified:`** were
  confirmed from the calling code; the rest are still guesses.
- `tools/ghidra/CommonCallers.java` found `VideoManage::Init` = `FUN_00021040`.
- `scripts/annotate-mi-calls.py` labels decompiled C with module/nr/size/name and resolves
  `DAT_` strings. `scripts/resolve-dat-strings.py` does the strings only.
- The vendor code is SigmaStar's sample framework (`vif/st_vif.c`, `ST_Vif_*`, `ST_Sys_Bind`),
  wrapped in C++ classes (`encode/video/{vif,isp,scl,venc}.cpp`).

## Kernel call convention (all modules)
```
fd  = open("/dev/mi_<module>", O_RDWR)      // cached per process; re-opened after fork
hdr = { u16 devId (SoC id, 0); u16 pad; u32 len = sizeof(args); u64 ptr = &args }   // 16 bytes
ioctl(fd, _IOC(dir, 'i', nr, sizeof(args)), &hdr)
```
`args` packs the call's scalar arguments first, then the struct. For example
`MI_SNR_GetPadInfo(pad, &info)` has args = {u32 pad; info[56]}, so 60 bytes. **Table sizes are
args sizes, not struct sizes.**

## Module IDs (match SigmaStar's I6C enum)
VENC = 2, VIF = 6, SYS = 9, VDISP = 14, SNR = 27, IPU = 29, **ISP = 0x21 (33)**, **SCL = 0x22 (34)**.

## Stage order: `VideoManage::Init` (`FUN_00021040`)
1. `FUN_0001fccc`: reads `/mnt/nand/imageflip` (`ImageFlip=(n)`)
2. `FUN_0001d650`: **InitVif**. Builds the Vif object (`FUN_0001b758`) and calls `Vif::Init`
   (`FUN_0001bc84`)
3. `FUN_0001d9c8`: **InitmIsp**. Builds the Isp object (`FUN_0001cd20`) and calls `Isp::Init`
   (`FUN_0001c540`)
4. `FUN_0001e188`: InitVDisp (optional) · `FUN_0001d414`: InitRgn
5. `FUN_0001e344`: **StartIsp** (`FUN_0001c3c8`), then VIF `EnableOutputPort`
6. `FUN_00020c0c`: **InitScl** (Scl object, `Scl::Init` = `FUN_00022b10`)
7. `FUN_0001e370`: **InitVenc** · `FUN_0001ef04`: InitRegion (OSD) · `FUN_0001f354`: InitIve
   (optional)
8. `FUN_0001ebb8`: **StartVenc** · `FUN_0001ebec`: **StartGetStream** · `FUN_0001f408`:
   InitIsp (IQ/3A)

## Sensor + VIF: `Vif::Init` (`FUN_0001bc84`, `encode/video/vif.cpp`)
1. `MI_SNR_SetPlaneMode(pad, hdr ? 1 : 0)`: nr14, args 8
2. Choose the resolution index and fps (`FUN_0001b7d4`). Factory path `SNR_InitUnInit`:
   `QueryResCount` (nr8) → `GetRes(i)` for each (nr9, 4 + 56) → `SetFps(pad, 15)`
3. `MI_SNR_SetRes(pad, resIdx)`: nr11 · `MI_SNR_Enable(pad)`: nr0
4. `MI_SNR_GetPadInfo(pad, &pad[56])`: nr2 · `MI_SNR_GetPlaneInfo(pad, 0, &plane[72])`: nr3
5. Pixel format: if `plane.bayerId (0x2c) < 0xc` then
   `pixfmt = plane.precision (0x30) * 12 + bayerId + 0x14` (SigmaStar's `RGB_BAYER_PIXEL`
   macro); else `plane.ePixel (0x44)`.
6. `MI_VIF_CreateDevGroup(group, {u32 a; u32 b; u32 hdrType; padInfo…})`: nr0, args 52
   (`ST_Vif_CreateDevGroup`, `FUN_000fa9a0`). The wrapper forces field `+0x10` = 5 and
   `+0x0c` = 1 when field `+0x08` is non-zero.
7. `MI_VIF_SetDevAttr(dev, {pixfmt; …; plane +0x24; plane +0x28; …})`: nr4, args 28, then
   `MI_VIF_EnableDev(dev)`: nr6 (`ST_Vif_EnableDev`, `FUN_000faa14`)
8. `MI_VIF_SetOutputPortAttr(dev, port, {u16 capX, capY, capW, capH, dstW, dstH; u32 frc?;
   u32 pixfmt})`: nr9, args 32 (`FUN_000faafc`). Capture rect comes from the plane info
   (`+0x?`, read `local_44/42`); dst = capture size.
9. `MI_VIF_EnableOutputPort(dev, port)`: nr11 (`FUN_000fab78`). On some products it's deferred
   until after StartIsp.
10. `MI_SNR_SetFps(pad, fps)`: nr5, up to 5 tries.

## ISP: `Isp::Init` (`FUN_0001c540`, `encode/video/isp.cpp`)
1. First instance only: `MI_ISP_CreateDevice(dev, {u32 1})`: nr0, args 8
2. `MI_VIF_GetOutputPortAttr(vifDev, port, &attr[24])` (nr10), to get the capture size;
   `SNR_GetPadInfo` / `GetPlaneInfo`
3. If bayer: `FUN_000facf8(pad, &chn[80])` fills the channel attr; else `chn[0] = 0`
4. `MI_ISP_CreateChannel(dev, chn, &chnAttr[80])`: nr2, args 88
5. `MI_ISP_SetChnParam(dev, chn, {u32 hdr (2 / 1); u32 3dnrLevel = 1; u16 ?; …;
   u32 rotate/mirror?})`: nr6, args 36 (28-byte struct)
6. `FUN_000fac08` computes the output rect, then `MI_ISP_SetOutputPortParam(dev, chn, port,
   {u16 x, y, w, h (crop); u32 ePixelFormat (0, or 0xb)})`: nr11, args 32
7. Optionally `MI_SYS_SetChnOutputPortDepth(0, {0x21, dev, chn, port}, 0, 3)`
8. `Isp::Bind` (`FUN_0001c444`): **VIF → ISP**, below

**Start** (`FUN_0001c3c8`): `MI_ISP_StartChannel(dev, chn)` (nr9), then
`MI_ISP_EnableOutputPort(dev, chn, port)` (nr13).

## Binds (`ST_Sys_Bind`-style helper `FUN_000fa6a0` → `MI_SYS_BindChnPort`)
Helper arg: `{src {module, dev, chn, port}, dst {module, dev, chn, port}, u32 srcFps,
u32 dstFps, u32 bindType, u32 bindParam}` →
`MI_SYS_BindChnPort(0, &src, &dst, srcFps, dstFps, bindType, bindParam)`, provided by the
camera's own `libmi_sys.so`.

| Bind | src | dst | type |
|---|---|---|---|
| `Isp::Bind` `FUN_0001c444` | VIF (6) dev/chn/port | ISP (0x21) dev, chn, port 0 | **4 = REALTIME**; 1 = FRAME_BASE on some products |
| `Scl::Bind` `FUN_00022978` | ISP (0x21) | SCL (0x22) dev, chn, port | **4 = REALTIME** (1 when SCL dev ≠ 0) |
| Venc bind `FUN_00027df0` | SCL (0x22) dev 0/1, chn, port | VENC (2) dev 0 (8 for JPEG), chn | **0x10 = HW_RING** for the main stream; 4 or 1 for others |

Bind type values: 1 FRAME_BASE · 2 SW_LOW_LATENCY · 4 REALTIME · 8 HW_AUTOSYNC · 0x10 HW_RING.

## SCL: `Scl::Init` (`FUN_00022b10`, `encode/video/scl.cpp`)
- `MI_SCL_CreateDevice(dev, {u32 hwSclMask})`: nr0, args 8. The mask is 0xF, 7, 0xE, 5 or 10
  depending on product and stream count; 7 is typical for two streams.
- For dev 0, `MI_SYS_ConfigPrivateMMAPool(0, {u32 type 4; u8 bCreate 1; u32 module 0x22;
  u32 dev; u16 maxW; u16 maxH (scaled ring height)})`: this is the ring pool for HW_RING.
- `ST_SclCreateChn` (`FUN_000fad34`, `scl/st_scl.c`):
  1. `MI_SCL_CreateChannel(dev, chn, {u32 0})`: nr2, args 12
  2. `MI_SCL_SetChnParam(dev, chn, {u32 eRot = 0})`: nr6, args 12
  3. `MI_SCL_StartChannel(dev, chn)`: nr8, args 8
  4. For each output port:
     - `MI_SCL_SetOutputPortParam(dev, chn, port, {crop x, y, w, h = 0; u16 outW, outH
       (swapped for rot 90/270); u32 ePixelFormat = 0xb (NV12); …})`: nr10, args 36
       (24-byte struct)
     - `MI_SCL_EnableOutputPort(dev, chn, port)`: nr12, args 12
     - `MI_SYS_SetChnOutputPortDepth(0, {0x22, dev, chn, port}, 0, 3)`
- Then `Scl::Bind` (ISP → SCL, REALTIME).

## VENC (`encode/video/venc_base.cpp`, codec subclasses `venc_h264/h265/mjpeg.cpp`)
- Classes: CVideoH264 (vtable `0x19ece4`), CVideoH265 (`0x1a1ccc`), CVideoMJPEG (`0x1a08fc`).
  - Slot +0x08 is the channel-attr builder: H.264 `FUN_0001ce24`, **H.265 `FUN_0002610c`**,
    MJPEG `FUN_00022740`.
  - Shared base methods: `0x272dc` (save packs), `0x27368` (init + default bitrate), `0x27cf4`
    (**ReadStream**), `0x27b54`, `0x2796c`, `0x27a54`, `0x26eb4`.
- **`VencBase::Init` (`FUN_00027f48`):**
  1. vtable+8 builds `attr[80]`; then `attr.eType` = codec (2 = H.264, 3 = H.265, 4 = JPEG)
  2. First use of a device: `MI_VENC_CreateDev(dev, {u32 maxW, u32 maxH})`, nr76, args 12.
     dev 0 for H.264/H.265, **dev 8** for JPEG.
  3. Optional ring pool: `MI_SYS_ConfigPrivateMMAPool(0, {type 4, bCreate 1, module 2 (VENC),
     dev 0, maxW, maxH 0x168})`
  4. `MI_VENC_CreateChn(dev, chn, &attr[80])`: nr0, args 88 (wrapper `FUN_0016b7d0`)
  5. `MI_VENC_SetMaxStreamCnt(dev, chn, 4)`: nr13, args 12
  6. Bind SCL → VENC (`FUN_00027df0`, HW_RING for the main stream)
- **H.265 channel attr, 80 bytes**, from `FUN_0002610c`. Same shape as I6C's `MI_VENC_ChnAttr_t`:
  | Offset | Field |
  |---|---|
  | +0x00 | eType |
  | +0x04 / +0x08 | maxW / maxH |
  | +0x0c | bufSize (w·h·15/37) |
  | +0x10 | profile 0 |
  | +0x14 | u8 byFrame 1 |
  | +0x18 / +0x1c | picW / picH |
  | +0x20 | 0 |
  | +0x24 | 1 |
  | +0x28 | **eRcMode: 9 = H.265 CBR, 10 = VBR, 12 = AVBR** |
  | +0x2c | gop |
  | +0x30 | statTime 0 |
  | +0x34 / +0x38 | fpsNum / fpsDen (1) |
  | +0x3c | bitrate in bits/s (kbps << 10) |
  | +0x40 / +0x44 | VBR maxQp / minQp (e.g. 0x30 / 0x19, or 0x32 / 0x20–0x24) |
  - Also `MI_VENC_GetRefParam` / `SetRefParam` (nr45 / 44, args 20) for smart-P.
- **ReadStream (`FUN_00027cf4`):**
  1. `MI_VENC_Query(dev, chn, &stat[40])` (nr7, args 48): `stat +0x10` = pending frames
  2. `MI_VENC_GetStream(dev, chn, &{u32 *pstPack; u32 packCount = 1; …[0x48]})` → save →
     `MI_VENC_ReleaseStream`
  3. **Pack = 184 bytes:** +0x08 data ptr, +0x0c len, +0x10 u64 PTS, +0x18 u8 frameEnd.
- **The `GetStream` wrapper (`FUN_0016c1f4`) is NOT thin.** It manages per-channel output-buffer
  mappings: ioctls `0xc0106936` (nr54, 16 B) and `0xc0186937` (nr55, 24 B), then
  `MI_SYS_Mmap` + `MI_SYS_FlushInvCache` from the camera's `libmi_sys.so`, `0xc0506939`
  (nr57, 80 B), and finally `0xc060690a` (nr10, 96 B) = the GetStream itself, with mapping
  tables per dev/chn. `ReleaseStream` (`FUN_0016cd8c`) issues nr69 / 60 / 11. **Both need a
  careful full decompile before reimplementation.**

## VENC stream protocol (from `GetStream` `FUN_0016c1f4` / `ReleaseStream` `FUN_0016cd8c`)
The newer MI VENC hands out frames from a **ring buffer that the kernel maps into the process**.
A per-(dev, chn) context `{…, +0x08 u64 bufId, +0x18 u64 bufPhys, +0x20 virt, +0x24 size,
+0x28 frameCounter}` is created with the channel; with no context, `GetStream` fails.

**GetStream(dev, chn, &stream, timeoutMs):**
1. `ioctl nr54 0xc0106936` args 16 `{u32 dev; u32 chn; u64 bufId (out)}`: the current output
   buffer.
2. If `bufId` changed:
   - `MI_SYS_Munmap` the old mapping
   - `ioctl nr55 0xc0186937` args 24 `{u64 bufId; u64 phys (out); u32 size (out); pad}`
   - `MI_SYS_Mmap(phys, size, &virt, cached = 1)`
   - `MI_SYS_FlushInvCache(virt, size)` (cache-line aligned)
3. Loop: `ioctl nr57 0xc0506939`, args 80. **Offsets corrected for #37 from the wrapper's stack
   layout:**
   | Offset | Field |
   |---|---|
   | 0x00 | u32 dev |
   | 0x04 | u32 chn |
   | 0x08 | u64 bufId (in) |
   | 0x10 | u32 flags (out) |
   | 0x18 | u64 pts |
   | 0x20 | u32 seq |
   | 0x28 / 0x2c | special-frame words |
   | 0x30 | u64 slicePhys |
   | 0x38 | u32 len |
   | 0x3c | u32 timeoutMs (in, ≤ 100) |
   | 0x40 | u8 |
   | 0x44 / 0x48 | u32 |
   The wrapper polls in ≤100 ms slices up to the caller's timeout. Each slice gives virt =
   ctx.virt + (slicePhys − ctx.bufPhys), bounds-checked against ctx.size, cache-invalidated,
   and stored as one 184-byte pack.
   - **flags**: bit 0 = frame end; bits 1–3 = codec (2 = H.264, 3 = H.265, 4 = JPEG,
     5 = ?); bits 4–6 = ref/slice type; bit 7 = new frame.
   - Slices are collected until frame end.
4. `ioctl nr10 0xc060690a` args 96 `{u32 dev; u32 chn; …}` returns stream info (copied into
   `stream[6..0x13]`).
5. The wrapper then parses NAL start codes in pack 0 to fill pack data-type info.
   - H.264 types: 1/5 slice, 6/7/8 SEI/SPS/PPS, 14.
   - H.265 types: 0–2 slice, 0x13 IDR, 0x20–0x22 VPS/SPS/PPS, 0x27 SEI.
   - **Our streamer can skip this:** an RTSP/file writer only needs the Annex-B bytes.
6. Error path: for each pack, `ioctl nr60 0x4010693c` args 16 `{dev; chn; u64 bufId}`, then
   `ioctl nr11 0x4058690b` args 88 `{dev; chn; …}`.

**Pack (184 bytes, stride 0x2e words):** +0x00 u64 phys · +0x08 virt · +0x0c len ·
+0x10 u64 pts · +0x18 u8 frameEnd (|2 on special) · +0x1c dataType · +0x24 infoCount ·
+0x28 + i·16 per-NAL {…, +0x0c len, +0x10 type, +0x14 offset} · +0x40 frame counter.

**ReleaseStream:** for each pack, cache flush, then `ioctl nr69 0x40106945` args 16
`{dev; chn; u64 bufId}` and `ioctl nr60 0x4010693c` args 16 (same args). Finally
`ioctl nr11 0x4058690b` args 88 `{dev; chn; …}`.

## #37 findings (2026-10-22)
- **StartRecvPic:** `MI_VENC_StartRecvPic(dev, chn)` = nr4, args 8. StartVenc calls each
  encoder's vtable+0x14 method; the JPEG snapshot path calls `(8, 5)`.
- **Waiting for frames:** `MI_VENC_GetFd` (`FUN_0016d2cc`):
  1. `pollFd = open("/dev/mi_poll", O_RDWR)`
  2. `ioctl(vencFd, nr16 0xc0106910, {u32 dev; u32 chn; u32 pollFd; u32 pollId (out)})`
  3. `ioctl(pollFd, 0, pollId)` binds them
  4. Then `select()` on `pollFd` (the snapshot path waits this way; then `Query`, `GetStream`)
- **`MI_VENC_ChnStat_t` (Query, args 8 + 40):** I6C layout. +0x08 leftStreamFrames,
  **+0x10 curPacks** (the pack count to allocate).
- **SYS:**
  - `MI_SYS_Init(0)`
  - `BindChnPort` nr3, 56 B: `{src chnport[16]; dst chnport[16]; u32 bindParam; u32 bindType;
    u32 0; u32 1; u32 srcFps; u32 dstFps}`
  - `UnBindChnPort` nr4, 56 B
  - `SetChnOutputPortDepth` nr21, 24 B: `{chnport; u32 userDepth; u32 bufDepth}` (stock 0, 3)
  - `ConfigPrivateMMAPool` nr29, 60 B, kernel struct for type 4: `{u32 type; u32 module; u8
    bCreate; u8 dev; …; +0x14 u16 maxW, maxH; +0x18 u16 ringLine; +0x1a heapName[32]}`
- **Ring pools:** SCL uses `ringLine = h/3` for generic products (480 at 1440p; some products
  use h·5/8 or h/4). VENC (optional) uses 640×360, 360 lines.
- **`MI_COMMON_Init`** is only a userspace `pthread_once`; there's no kernel registration.
- Still open: the tails of nr10 / nr11, the meaning of VIF nr3 and SNR nr6/7/10, and exact
  teardown numbers (ISP/SCL Destroy*). None of these block `mi-probe`.

## SYS (camera's own `libmi_sys.so`, all via `/dev/mi_sys`)
- `MI_SYS_Init(u16 socId)`: `_IOR('i', 0, 4)` = `0x80046900`. socId goes in **hdr.devId**;
  args = {u32 out}.
- `MI_SYS_Mmap(u64 phys, u32 size, void **virt, bool cached)`: `0xc018690a` (nr10), args 24
  `{u8 cached; pad[3]; u32 size; u64 virt (out); u64 phys}`. **The kernel creates the
  mapping**, so no `/dev/mem` is needed.
- `MI_SYS_Munmap(void *virt, u32 size)`: `0x4010690b` (nr11), args 16 `{u64 virt; u32 size;
  pad}`.
- `MI_SYS_FlushInvCache(void *va, u32 size)`: `0x4010691b` (nr27), args 16.
- `MI_SYS_BindChnPort` and the rest: codes in `analysis/ifado-mi-ioctl-inventory.tsv`
  (`libmi_sys.so` section, all named).
- **Result:** the thin layer can be pure ioctls with no vendor `.so` at all. A static musl
  binary is enough.

## Struct layouts: Ifado mostly = SigmaStar's public I6C layouts (verified offsets)
| Struct | Size | Layout (offsets confirmed from stock code) |
|---|---|---|
| `MI_SNR_Res_t` (GetRes, args 4 pad + 4 idx + 52) | 52 | `{u16 cropX, Y, W, H; u16 outW, outH; u32 maxFps; u32 minFps; char desc[32]}` |
| `MI_SNR_PlaneInfo_t` (GetPlaneInfo, args 4 + 4 + 72) | 72 | `{u32 planeId; char name[32]; u16 capX @0x24, capY, capW, capH; u32 eBayerId @0x2c; u32 ePrecision @0x30; u32 eHdrSrc; u32 shutterUs; u32 gainX1024; u32 compGain; u32 ePixel @0x44}` |
| `MI_SNR_PADInfo_t` (GetPadInfo, args 4 + 56) | 56 | `{u32 planeCount; u32 eIntfMode @4; u32 eHDRMode @8; union intfAttr…; @0x2c used by VIF group}` |
| VIF GroupAttr (CreateDevGroup, args 4 + 48) | 48 | `{eIntfMode = pad.eIntfMode; eWorkMode = 0; eHDRType = 0; 0; 0; +0x14 = (intf == 0 ? pad+0x2c : 2); 0…}`. The wrapper forces +0x0c = 1 / +0x10 = 5 for HDR |
| VIF DevAttr (SetDevAttr, args 4 + 24) | 24 | `{u32 eInputPixel (bayer fmt); u32 0; u16 x, y, w, h (= plane cap rect) @0x08; u32 0; u32 0}`. **Differs from I6C**: the extra u32 at +0x04 moves the rect |
| `MI_VIF_OutputPortAttr_t` (args 4 + 4 + 24) | 24 | `{u16 capX, Y, W, H; u16 dstW, dstH; u32 ePixFormat; u32 eFrameRate = 0; u32 eCompress = 0}` |
| `MI_ISP_ChannelAttr_t` (CreateChannel, args 8 + 80) | 80 | `{u32 sensorBindId = 1 << pad (pad 0 → 1); rest 0}` (`ST_TransMISnrPadToMIIspBindSensorId`) |
| `MI_ISP_ChnParam_t` (args 8 + 28) | 28 | `{u32 eHDRType = 0; u32 e3DNRLevel = 1; u8 bMirror, bFlip; …; u32 @0x0c (rot / ldc flag)}` |
| `MI_ISP_OutPortParam_t` (args 12 + 20) | 20 | `{u16 cropX, Y, W, H; u32 ePixelFormat (0 = YUYV422 default, 0xb = NV12); u32 eCompress; u32 eBufLayout}` |
| `MI_SCL_OutPortParam_t` (args 12 + 24) | 24 | `{u16 cropX, Y, W, H (0 = full); u16 outW, outH; u8 bMirror, bFlip; u32 ePixelFormat = 0xb @0x10; u32 eCompress}` |
| VENC ChnAttr (args 8 + 80) | 80 | see the VENC table above |
- Resolution choice (`FUN_0001b7d4`, `GetSensorParam`) depends on the sensor type. For types it
  doesn't handle, it uses **res index 0 at 25 fps** (0x19). SC4336P's internal type code is not
  identified yet; `GetRes(0)` tells us its mode.

## IQ / 3A (step 2 findings)
- `VideoManage` "InitIsp" (`FUN_0001f408`) is **not** IQ loading. It creates the vendor's
  day/night and LED controller object for the sensor type and starts its thread. Our own
  day/night code replaces it.
- IQ load: `Load_DayBinFile` (`FUN_0003f3f8`) → path from `FUN_0003f2f0`: `/tmp/isp_day.bin`,
  else `/tmp/oem/app/isp_day.bin` → `MI_ISP_API_CmdLoadBinFile(dev, chn, path, key 1234)`
  (`FUN_00179b88`: reads the file, then sends it via `FUN_0017721c`, the ISP IQ-API path).
  Night uses `isp_night.bin` the same way.
- There's no SC4336P IQ bin on the flash. The ISP *kernel driver* loads
  `/config/iqfile/iqfile0.bin` (→ `imx307_iqfile.bin`) itself (probe 3), but that is **not** the
  tuning stock streams with: media_server then loads **`/config/iqfile/gc4023_day.bin`** (night:
  `gc4023_night.bin`) with `MI_ISP_API_CmdLoadBinFile`, and our iq-dump taken under stock matches
  gc4023_day.bin group for group (**corrected 2026-10-23**, docs/STOCK-IMAGE-TUNING.md §1). The
  `/tmp` / `/tmp/oem/app` bins don't exist on the live camera.
- 3A runs in the kernel (`IspDriverThread`). Userspace CUS3A hooks exist in `media_server` but
  are optional.

## Live ground truth: probe 3 (cam #1, 2026-10-22, stock streaming)
Source: `bench-logs/cam1-live-probe-3.txt` (gitignored), `/proc/mi_modules/*` + dmesg. It
**confirms the decoded design:**
| Item | Live value |
|---|---|
| Sensor pad 0 | MIPI, HDR off, PlaneMode 0, **1 resolution: 2560×1440 @ 30 max / 3 min fps**, running **25 fps**; plane BG **10BPP**; crop (0, 0, 2560, 1440) |
| VIF group 0 | MIPI, work mode **1MULTIPLEX**, clkedge **2**, HDR 0 |
| VIF dev 0 | in-crop (0, 0, 2560, 1440), BG_10BPP |
| VIF port 0 | crop (0, 0, 2560, 1440) → dest 2560×1440, **pixel 34** (= 0x14 + 1·12 + 2: 10BPP, BayerId 2), compress 0, 25 fps |
| Bind | **VIF 0/0/0 → ISP (33) 0/0/0, type 4 (REALTIME)** |
| ISP dev 0 chn 0 | Input 3, Hdr 0, **3dnr 1**, PixelFmt 34, BayerId 2, YuvOrder 0, 2560×1440. Chip idx **13**, version **4** |
| Bind | **ISP 0/0/0 → SCL (34) 0/0/0, REALTIME** |
| SCL dev 0 | UseSclMask **7**; chn 0 with 3 output ports |
| Bind | **SCL port 0 → VENC chn 0, type 16 (HW_RING)**, the main stream |
| Bind | **SCL port 1 → VENC chn 1, type 1 (FRAME_BASE)**, the sub-stream |
| SCL port 2 | user-get port (~3.4 fps; probably motion detection) |
| VENC dev 0 | chn 0 + chn 1 enabled, 25 fps each. There's no `mi_venc8`: JPEG dev 8 isn't in use |
| **IQ** | **The kernel loads one itself:** `isp root is /config/iqfile` → `iqfile0.bin` (38410 B) = the symlink to **`imx307_iqfile.bin`**. No `/tmp/isp_*.bin` and no `/tmp/oem` exist. (Probe 3 read this as "stock runs IMX307 tuning"; corrected 2026-10-23: media_server loads `gc4023_day.bin` over it, docs/STOCK-IMAGE-TUNING.md.) |

Implications for `mi-probe` / our firmware:
- Use exactly this topology.
- Keep `/config/iqfile/iqfile0.bin` (vendor file, local only) so the ISP starts the same way.
- IQ quality (risk B-4) is now concrete: the stock camera uses a foreign sensor's tuning, so an
  SC4336P IQ file would be an image-quality improvement, not a requirement.

## Live run 1 of `mi-probe` (cam #1, 2026-10-22 15:10, #28)
`bench-logs/mi-probe-run-20261022-150956/` (gitignored). Binary SHA-256 `36ee9bc1…`.
- **All 40 MI calls returned 0**, so the decoded interface works:
  `SYS_Init` → SNR (res 0 = 2560×1440@30, plane bayer 2 / 10-bit → pixfmt 34) → VIF → ISP →
  bind → start → SCL → bind → VENC create/chn → bind → `StartRecvPic` → `GetFd` → ring
  (`nr54`/`nr55` → 368 KB ring, `MI_SYS_Mmap`) → `nr57` slices → `nr10` → release
  (`nr69`/`nr60`/`nr11`). Teardown freed everything cleanly; dmesg shows each client
  disconnecting.
- **Output:** 720p 125 frames in 5 s (25 fps), full 38 frames in 5 s. Both are valid H.265:
  VPS/SPS/PPS, IDR every 50 frames, TRAIL_R between. But the frames are tiny (IDR 0.7–3.3 KB),
  so the picture is flat.
- **Cause:** dmesg shows `Get Buffer Failed, modId=34 (SCL) dev0 chn0 port0` with `MI_SYS_Pass_AllocBufDefaultPolicy:
  Can't Find Buf Allocation`, so SCL had no output buffers. `ps` showed **`media_server` still
  alive** after `killall` (SIGTERM). It most likely still held the shared MMA heap.
- **Fix for run 2** (`scripts/cam-run-mi-probe.py`): `killall -9` and wait until it's gone;
  dump `mi_sys_mma` heap usage; read `/proc/mi_modules` **mid-run**; and also try the stock
  HW_RING bind (`-r`), which gives SCL its private ring pool.
- `-1610014689` (`0xa0090019`) from the first `nr57` is the normal "no frame yet" return; the
  next poll succeeded.

## Run 1 image analysis + why: userspace 3A (2026-10-22)
- Decoded on the Mac with ffmpeg: 720p 125 frames, 2560×1440 38 frames, yuv420p.
- **The picture is fully overexposed:** mean luma ≈ 236 / 255, Y range 203–239, constant across
  all 5 s, with a few green specks where one channel didn't clip. The same structure shows in
  both runs at different SCL output sizes, so it's a **real optical image**, not stale memory.
  The video path works.
- **Cause: no AE/AWB.** On this camera **3A runs in userspace inside `media_server`** (SigmaStar
  "CUS3A"):
  - `_CUS3A_AlgoInit` (`FUN_0017c7b4` / `FUN_0017cb68`), `CUS3A_RegInterfaceEX`
    (`FUN_0017c638`)
  - AE loop `FUN_0017bc00`, AWB loop `FUN_0017bef8`, each calling a registered algorithm
    callback
  With `media_server` gone, exposure and gain stay at their power-on values.
- **Transport = ISP IQ API** (`FUN_0017a730`): a command header `{u32 ?; u32 size; u32 cmdId;
  u32 chn; u32 dev}`. `MI_ISP_Alloc_IQDataBuf` (nr15) → copy → `MI_ISP_GetIQApiData` (nr18) →
  copy back → `MI_ISP_Free_IQDataBuf` (nr16). Set-type commands go through `FUN_00179ca8`
  (`SetIQApiData` nr17).
  - The camera's `MI_SYS_GetRunEnvOnce` picks a registered direct callback when it's available.
- **CUS3A command IDs:**
  | Use | IDs |
  |---|---|
  | AE inputs | 0x2e01, 0x2e02, 0x2e03, 0x2e2b, 0x2e2c |
  | AE status | 0x2e05 |
  | **set AE result** | **0x2e06** |
  | AWB inputs | 0x2e07, 0x2e19 |
  | AWB status | 0x2e09 |
  | **set AWB result** | **0x2e0a** |

  These roles were corrected by the struct decode below. 0x2e05/0x2e09 are status blocks, and
  the per-block stats are 0x2e01/0x2e07.
- **Next:** decode the CUS3A stats/result structs (from `media_server`'s callers, cross-checked
  with SigmaStar's public CUS3A docs), then add (a) a fixed-exposure option to `mi-probe` for
  the next live run, and (b) a small AE (mean-luma target) + AWB (grey-world) loop for the
  streamer. Tracked in its own issue.

## CUS3A structs decoded (#43 step 1, 2026-10-22)
Static decode from `media_server` (sizes are the `dataSize` the vendor passes; field names
follow SigmaStar's public CUS3A headers where the offsets agree).

**IQ API transport** (all on `/dev/mi_isp`, except the cache flush):
| Call | ioctl | args |
|---|---|---|
| `MI_ISP_Alloc_IQDataBuf` | nr15 `0xc010690f` (RW) | 16 B `{u32 size; u32 pad; out u32 virt @+8; u32 pad}` |
| `MI_ISP_Free_IQDataBuf` | nr16 `0x40106910` (W) | 16 B `{u32 virt; ...}` |
| `MI_ISP_SetIQApiData` | nr17 `0x40206911` (W) | 32 B `{24-byte IQ header; u32 bufVirt @+0x18; u32 0}` |
| `MI_ISP_GetIQApiData` | nr18 `0x40206912` (W) | same |
| `MI_SYS_FlushInvCache` | `/dev/mi_sys` nr27 `0x4010691b` (W) | 16 B `{u64 start (cache-line aligned); u64 length}` |

- IQ header: `{u32 hdrSize = 0x18; u32 dataSize; u32 cmdId; u32 chn; u32 dev; u32 0}`.
  `mi_hdr.devId` = the header's dev field >> 16.
- Flow: alloc(roundup64(dataSize)) → memcpy in → FlushInvCache → Get/Set → memcpy out → Free.

**Commands:**
| Cmd | Size | Contents |
|---|---|---|
| 0x2e01 AE avg stats | 0xb408 = 8 + 128×90×4 | per-block {R, G, B, Y} bytes |
| 0x2e02 / 0x2e03 | 0x100 each | histograms 1 / 2 |
| 0x2e2b / 0x2e2c | 0x100 each | HDR stats |
| 0x2e05 AE status | 95 B | not decoded field by field; dumped by `mi-probe` |
| **0x2e06 set AE** | **58 B** | `CusAEResult_t`, packed (below) |
| 0x2e07 (and 0x2e19) AWB stats | 0x8708 = 8 + 128×90×3 | per-block {R, G, B} bytes |
| 0x2e09 AWB status | 59 B | dumped by `mi-probe` |
| **0x2e0a set AWB** | **24 B** | `{Size; Change; R_gain; G_gain; B_gain; ColorTmp}` (1x = 1024). The vendor writes Size 0x3a |

`CusAEResult_t` (0x3a, packed u32 unless noted): Size, Change, Shutter (µs), SensorGain
(1x = 1024), IspGain (1x = 1024), ShutterHdrShort, SensorGainHdrShort, IspGainHdrShort,
BV×16384, AvgY, HdrRatio, FN×10, DebandFPS, WeightY, u16 GMBlendRatio.

**Enabling userspace 3A** (`MI_ISP_EnableUserspace3A`, `FUN_0017b3c0`). This section is
superseded by "Run 2" below:
- ISP nr39 `0x400c6927` (AE), nr40 `0x400c6928` (AWB), nr41 `0x400c6929` (AF); args 12 B
  `{dev, chn, 1}`.
- Then nr42 `0xc014692a`, nr44 `0xc014692c`, nr43 `0xc014692b`; args 20 B `{dev, chn, type
  0..2, flag 0/1, timeout 1000}`.
- **Calling nr39 cold oopses the kernel** (run 2). See below for the real stock sequence.

**mi-probe v2 (#43 step 2):** `-e shutter:gain` fixed AE, `-W r:g:b` fixed WB, `-A` mean-Y AE +
grey-world AWB. See `tools/mi-probe/README.md`.

## Run 2 (cam #1, 2026-10-22 15:43, #28/#43) and the real CUS3A mechanism
Evidence: `bench-logs/mi-probe-run-20261022-154304/` (gitignored). mi-probe SHA-256
`4c053724…`. The camera was rebooted afterwards; no flash write.

**Baseline (720p, FRAME_BASE, no 3A):**
- 150 frames at 25 fps; all ioctls returned 0.
- **No SCL "Get Buffer Failed"**: `killall -9 media_server` fixed run 1's buffer problem. The
  MMA heap was free before the run (`avail 0x15b4000`).
- The image is still fully overexposed (YAVG 236), as expected without 3A.

**Every 3A variant (all also used `-r`) oopsed the kernel** at our first 3A call:
- The call was `ioctl(/dev/mi_isp, 0x400c6927)` (nr39), straight after `MI_VENC_StartRecvPic`.
- Oops: `Internal error: Oops: 80000007 [#1] PREEMPT THUMB2`, `Code: bad PC value`, stack
  `MI_DEVICE_Ioctl [sstar_mi]` ← `_CamFileOpsUnlocked_ioctl` ← `sys_ioctl`. The kernel jumped
  through an unset function pointer.
- The process was killed and its pipeline freed. The kernel kept running, but later runs saw
  no `/proc/mi_modules` entries and more Oopses.
- HW_RING was **not** tested: the crash happened before GetFd.
- A userspace ioctl on `/dev/mi_isp` crashing the kernel is a vendor driver bug. It is a local
  DoS from any process that can open the node. The owner decides whether it goes into the
  disclosure project; it is not reported from here.

**The stock sequence, decoded after the Oops** (`media_server` 3.5.2.1, static only):
1. `MI_SYS_GetRunEnvOnce` (libmi_sys `0x11954`) is `/dev/mi_sys` nr46 `0x8004692e`, reading a
   u32.
   - env 0: the IQ API uses the MMA bounce buffer (Alloc/Flush/nr17-18/Free).
   - Otherwise it tries an in-process callback table, then nr17/18 with the **caller's
     buffer pointer** directly (`FUN_0016eed8`).
2. The `MI_ISP_CreateChannel` wrapper (`FUN_0016e7fc`) does these steps:
   - **Before nr2:** IQ Set **0x2e08** (3 bytes `{AE, AWB, AF}`; stock constant `{1,1,1}`).
   - **After nr2:** ISP **nr35** `0xc0146923`, 20 B `{dev, chn, count (in 2 / out), list[2]}`.
     For each channel it returns, it runs `FUN_0017b3c0`.
   - That function skips everything when a per-channel "already enabled" flag is set.
   - With env 2 it registers callbacks only (`FUN_00179c5c`, `FUN_0017c71c/c7b4/c87c`), with no
     nr39.
   - Otherwise it calls nr39–41, then nr42/44/43 (3 tries each).
   - We called nr39 with neither 0x2e08 nor nr35 first.
3. **The per-frame driver is `/dev/isp_fe`** (thread `FUN_0017cb68`):
   - It runs `poll(POLLIN, 1000)` and reads **48 bytes**, as u32 words:
     | Word | Meaning |
     |---|---|
     | 0 | frame-done channel mask |
     | 1 / 2 / 3 | AE / AWB / AF enable-request masks (level, not edge) |
     | 4 | algorithm re-init mask |
     | 5 | status-dump mask |
     | 6 / 7 | command (type 3 → `FUN_0017cb28`) |
     | 8 / 9 / 10 | AE / AWB / AF **skip this frame** masks |
   - For each enable change it writes a **20-byte ack** `{0, 0, chn, type 0 AE / 1 AWB / 2 AF,
     u8 on}`.
   - On frame-done (not skipped) it runs AE `FUN_0017bc00`. That reads 0x2e05 status and stats
     0x2e01/02/03 (+0x2e2b/2c for HDR), calls the algorithm, and sets **0x2e06**. AWB is
     `FUN_0017bef8`.

**mi-probe change (run 3):**
- No nr39–44.
- Query the run env.
- 0x2e08 `{1,1,0}` before CreateChannel; log nr35 after.
- Open `/dev/isp_fe`, ack AE/AWB enables, and run AE/AWB every 3rd frame-done event that isn't
  skipped.
- If `isp_fe` stays silent, step from the encoder loop after 10 frames.
- The runner tests HW_RING alone and 3A only on the frame-based path, and stops at the first
  Oops.

## Run 3 (cam #1, 2026-10-22 16:02): first real image from our code (#28/#43)
Evidence: `bench-logs/mi-probe-run-20261022-160201/` (gitignored; the frames show the owner's
street, so keep them local). mi-probe SHA-256 `bf85e830…`. No Oops; rebooted afterwards; no
flash write.

| Variant | Frames (6 s) | YAVG | Result |
|---|---|---|---|
| 720p HW_RING, no 3A | 141 | 236 | **HW_RING works**; overexposed as expected |
| 720p `-e 5000:1024` | 139 | 226 | **Real street image** (547 KB): set AE works; 5 ms is still too long for daylight; green tint (no WB) |
| 720p `-A` | 122 | 236 | AE drove exposure to max: AE stats were misparsed (below) |
| 2560×1440 HW_RING `-A` | 118 | 236 | same |

**Decoded from the live dumps:**
- **Run env = 2.** The IQ API takes the caller's buffer directly (nr17/18), with no MMA
  bounce.
- nr35 after CreateChannel returns `count 1 [0]`.
- **`/dev/isp_fe` works:** about one 48-byte event per frame, `{w0 1, w1 1, w2 1, rest 0}`
  (frame done on chn 0; AE and AWB requested on). Our 20-byte ack `write()` returns -1. AE/AWB
  results apply anyway, and run 4 logs the errno.
- **AE stats 0x2e01 = `{u32 w = 32, u32 h = 32}` + 32×32 × {R, G, B, Y}** (only 4 KB of the
  46 KB buffer is used). **AWB stats 0x2e07 = `{128, 90}` + 128×90 × {R, G, B}.**
- In the `-e 5000` run, AE Y ≈ 247 and AWB ≈ 230/241/207, both near clipping.
- **AE status 0x2e05:** +0x18 = shutter µs (5000 after our set; 199 at start), +0x1c = sensor
  gain (1024), +0x20 = ISP gain (1024), +0x24 = 30 (fps?). This shows the set AE result is
  applied.
- **AWB status 0x2e09:** +4 = 128, +8 = 90 (grid), +0xc/0x10/0x14 = R/G/B gains (1024 each).
- The first stats Gets after start fail with MI error `0xa0207001` (no stats yet). Later ones
  succeed.

**Run 4 changes:**
- AE mean uses the grid size from the stats header.
- A full step down near saturation, and a 20 µs minimum shutter.
- AWB skips clipped stats.
- The ack errno is logged.
- Variants: 720p `-e 300:1024`, 720p `-A`, full `-r -A`, 8 s each.

## Run 4 (cam #1, 2026-10-22 16:09): working AE + AWB from our own code (#43 done)
Evidence: `bench-logs/mi-probe-run-20261022-160859/` (gitignored; owner's street, keep local).
mi-probe SHA-256 `42796416…`. No Oops; rebooted afterwards; no flash write. 8 s per variant.

| Variant | Frames | YAVG (start → settled) | Result |
|---|---|---|---|
| 720p `-e 300:1024` | 207 | 121.5 | Well exposed, **green** (no WB) |
| 720p `-A` | 215 | 225 → 162 in about 1 s | **Correct exposure and natural colour** |
| 2560×1440 HW_RING `-A` | 202 | 225 → 162 | same at full size |

- **AE:** the first step from saturation (stats Y 253) jumps to 5000 µs. It then settles at
  **≈650 µs, 1x gain, stats Y 108–111** (target 110), with about ±1 % dither. The stats Y is
  pre-gamma, so a stats target of 110 gives video YAVG ≈ 162. A lower target (≈80–90) would
  bring the output down.
- **AWB:** with the stats at R 82 / G 114 / B 63, the gains are **R 1.38, B 1.81**. The AWB stats
  don't move when the gains change: they are taken **before** WB, so grey-world converges in
  one step and stays put.
- `isp_fe` ack `write()` → **EINVAL** for the 20-byte ack. AE/AWB results apply anyway (the
  kernel's enable masks stay on). The ack layout is still unresolved and harmless for now.
- The image looks slightly hazy, with low contrast. Under our pipeline only the kernel's imx307 IQ
  file is loaded (gamma/CCM not tuned); stock adds `gc4023_day.bin` on top (docs/STOCK-IMAGE-TUNING.md),
  which our `-Q` IQ profile reproduces. That is IQ work (#36), not 3A.

**Outcome:** #43's goal is met. A usable image now comes from our own pipeline: no vendor
userland, AE + AWB in about 100 lines of our code. Follow-ups: the AE target and contrast (IQ,
#36), the ack layout, and night/IR behaviour (#30).

## Still to do
- VENC: confirm the remaining arg fields of nr57 / nr10 / nr11 by watching a live run, or by
  reading `FUN_0016c1f4`'s stack layout more closely; `StartRecvPic` (nr4) call site; poll via
  `GetFd` (nr16).
- SYS: which `MI_SYS_Init` socId stock passes, and the MMA pool configuration
  (`MI_SYS_ConfigPrivateMMAPool` layouts).
- Remaining unknowns are tracked as GitHub issues (see RESUME.md §5).
