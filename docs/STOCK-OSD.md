<!-- SPDX-License-Identifier: MIT -->
# Stock OSD: MI_RGN as media_server and web_server use it

Static decode of the stock V3.5.2.1 firmware (`media_server`, `web_server`), made for our own OSD
(`src/mi/osd.c`). Nothing here ran on a camera. **[C]** = read from the code, **[G]** = a guess.
No vendor code or data is copied; the stock 16×16 font file is vendor material and isn't used.

## MI_RGN ioctls (`/dev/mi_rgn`, device 0)
The MI convention of `docs/IFADO-MI-PIPELINE.md`: `ioctl(fd, _IOC(dir,'i',nr,size), {u16 dev 0; u16;
u32 size; u64 &args})`. Codes from `analysis/ifado-mi-ioctl-inventory.tsv` [C].

| Call | nr | Request | Args |
|---|---|---|---|
| Init | 0 | `0x44006900` | 1024 B palette: 256 × `{u8 alpha, r, g, b}`; entry 0 transparent |
| DeInit | 1 | `0x00006901` [G, from the I6C library] | none. Stock never calls it, and neither do we |
| Create | 2 | `0x40186902` | 24 B `{u32 handle; u32 type (0 OSD, 1 cover); u32 pixfmt (2 I2, 3 I4, 4 I8); u32 w; u32 h; u16 1 [G meaning, the 0x730 board's value]; u16 0}`; handles < 0x400 |
| Destroy | 3 | `0x40046903` | `{u32 handle}` |
| AttachToChn | 6 | `0x40606906` | 96 B `{u32 handle; ChnPort 20 B; ChnPortParam 72 B}` |
| DetachFromChn | 7 | `0x40186907` | 24 B `{u32 handle; ChnPort}` |
| SetDisplayAttr | 8 | `0x40606908` | the same 96 B as Attach |
| GetCanvasInfo | 10 | `0xc028690a` | 40 B `{u32 handle; u32; u64 phys; u64 virt; u32 w, h, stride, fmt}`; `virt` is usable by the process as is |
| UpdateCanvas | 11 + 12 | `0xc00c690b`, then `0x4004690c` | nr11: 12 B `{u32 handle; out u32 va; out u32 size}`; nr12: `{u32 handle}` |

- **ChnPort** (Ifado, 20 B): `{u32 module; u32 dev; u32 chn; u32 port; u8 0; pad}`. Stock attaches to
  module 2 (VENC), dev 0 (8 for the JPEG channel), chn = the stream, port 0. One region may be
  attached to several channels [C].
- **ChnPortParam** (72 B): `+0 u8 show (1)`, `+4 u32 layer` (stock: the handle [G]), `+8 u32 x`,
  `+0xc u32 y` (4-aligned), `+0x10 u32 0` [G: alpha mode], `+0x14 u8 0`, `+0x15 u8 0xAA` [G:
  foreground/background alpha], `+0x18 u8 0`, the rest 0.
- **Update** [C]: GetCanvasInfo → draw into `virt` → `MI_SYS_FlushInvCache(virt, h × stride)` (SYS
  nr27) → nr11 → `MI_SYS_FlushInvCache(va, size)` → nr12.

## Order and rules
- Init once per process. Create and Attach after the encoder's CreateChn and before its
  StartRecvPic (`VideoManage::Init`: InitVenc, InitRegion, then StartVenc) [C].
- Stock attaches to the main stream in HW_RING mode, so ring + OSD works on this SoC [C].
- Rules we keep [C/G]:
  - detach before an encoder is destroyed or resized;
  - never resize an attached canvas: destroy and create it again;
  - x and y 4-aligned, width 8-aligned;
  - flush between drawing and nr12, and nr12 only after nr10 and nr11;
  - destroy on exit; clip text to the canvas.
- **I2 pixel order** within a byte is not decoded. `osd.c` puts pixel 0 in the low two bits
  (SigmaStar's sample code packs index formats that way [G]); `-DOSD_I2_MSB_FIRST=1` flips it if the
  first live test shows 4-pixel groups mirrored.

## What stock draws
- One **full-frame I2 canvas** per stream (921,600 B on the 2560×1440 main), every stream updated
  every **100 ms**, with its own 16×16 font. Text scale: 640 wide ×1, 1920 ×3, 2560 ×4 for "small";
  medium and large are bigger [C].
- **Settings:**
  - time: enable, position (corner or custom %), format (`yyyy-mm-dd hh:mm:ss`, `mm/dd/yyyy …`,
    `dd/mm/yyyy …`), 24/12 h, weekday;
  - title: enable, position, text;
  - style: black on white, white on black, white or black with a border on transparent;
  - font size small / medium / large.

## ONVIF in stock `web_server`
- Media ver10 and Media2: GetOSDs, GetOSD, GetOSDOptions, SetOSD, CreateOSD, DeleteOSD;
  `<trt:Capabilities … OSD="true">` in GetServiceCapabilities [C].
- Two fixed tokens on the video source configuration [C]:
  - `osd_title`: Type Text, TextString Type Plain + PlainText;
  - `osd_time`: TextString Type DateAndTime, DateFormat `yyyy-MM-dd`, `yyyy/MM/dd`, `dd/MM/yyyy`,
    `MM/dd/yyyy` …, TimeFormat `HH:mm:ss`.
- Position: UpperLeft, UpperRight, LowerLeft, LowerRight, or Custom with `Pos x, y` in −1..1
  (ONVIF's y points up).
- GetOSDOptions: MaximumNumberOfOSDs Total 2 (PlainText 1, DateAndTime 1); Type Text; the corner
  PositionOptions and Custom; TextOption types Plain and DateAndTime, the date formats,
  TimeFormat `HH:mm:ss`.
- SetOSD refuses Type Image; CreateOSD maps onto the two tokens; DeleteOSD hides.
- SSS draws privacy masks itself (owner, 2026-10-23), so covers (`type 1`) aren't needed.

## Ours (`src/mi/osd.c`), compared
- **Regions:** small per-line I2 regions: one per visible line and picture size. The main time
  box is 616×72 at ×4. The sub-stream's regions are also attached to the JPEG channel, so
  snapshots and the web preview carry the overlay.
- **Updates:** the clock is redrawn once a second, on the second; the title only when it changes.
- **Font:** our own data: Terminus 8×16, converted at build time (`scripts/psf2c.sh`,
  THIRD-PARTY-NOTICES.md).
- **ONVIF:** camhttpd answers the same six operations with the same two tokens
  (`src/camhttpd/README.md`).
