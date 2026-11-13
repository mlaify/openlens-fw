# mi-probe: minimal Ifado MI video pipeline test (issue #26)

A static ARMv7 program that drives the SigmaStar Ifado MI kernel interface directly, with no
vendor userland library. It reproduces the stock video pipeline and writes H.265 to a file:

```
SNR pad 0 → VIF 0/0/0 ─realtime→ ISP 0/0/0 (3DNR 1) ─realtime→ SCL 0/0/0 (NV12) ─frame|ring→ VENC 0/0 (H.265 CBR)
```

Everything it does (codes, struct layouts, call order, the stream ring-buffer protocol) comes
from `docs/IFADO-MI-PIPELINE.md` and `analysis/ifado-mi-api-table.tsv`, confirmed against the
live pipeline (probe 3).

## Build (owner's terminal, Docker)
The pipeline code lives in `src/mi/` (shared with `src/rtspd`); this directory holds only the
probe's `main`. One build makes both binaries:
```
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
```
This uses Ubuntu's signed `gcc-arm-linux-gnueabihf` (ARMv7-A, Thumb-2) and produces static
`build/arm/mi-probe` and `build/arm/rtspd`, plus `.sha256` files (gitignored build artifacts).
`scripts/cam-run-mi-probe.py` runs the probe variants on cam #1.

## Run (issue #28: cam #1 only, owner's OK required)
1. The owner opens the root console. Copy `mi-probe` to `/tmp` (`docs/COPY-FILES-TO-CAMERA.md`)
   and check its SHA-256 on the camera.
2. Stop the vendor apps that own the MI pipeline: `killall procman media_server` (and any
   respawn). Kernel modules stay loaded.
3. `cd /tmp && ./mi-probe -v -t 10 -w 1280 -h 720 -b 1024` for a first, smaller frame-based
   run, then the full size: `./mi-probe -t 10`. With `-r` it uses the stock HW_RING bind and a
   private SCL ring pool.
4. Copy `/tmp/mi-probe.h265` to the Mac and play it (`ffplay`, VLC). Save the stdout/stderr and
   `cat /proc/mi_modules/mi_{vif,isp,scl,venc}/*0` to `bench-logs/`.
5. **Reboot** to restore stock. Teardown is best-effort.

It never writes flash.

## Options
`-o file` (default `/tmp/mi-probe.h265`) · `-t seconds` (10) · `-w/-h` (2560×1440) ·
`-b kbps` (2048) · `-f fps` (25) · `-r` HW_RING bind · `-v` log every ioctl (`-vv` also every
`isp_fe` event) · `-T y` AE target (110).

3A (issue #43): the stock AE/AWB is SigmaStar CUS3A running inside `media_server`, so without
it the image is fully overexposed. Any of these options does the following, as stock does:
- Sets IQ 0x2e08 `{AE, AWB, AF}` before ISP CreateChannel.
- Opens `/dev/isp_fe` and acks the kernel's AE/AWB enable requests.
- Runs AE/AWB on frame-done events and dumps the AE/AWB status and stats means.

It never calls ISP nr39–44: on run 2, nr39 oopsed the kernel. The options:
- `-e shutter_us:gain`: a fixed exposure (sensor gain 1x = 1024), e.g. `-e 5000:1024`.
- `-W r:g:b`: fixed white-balance gains (1x = 1024).
- `-A`: our own loop, run on every 3rd frame-done event. It does mean-Y AE (target 110,
  shutter first, then gain up to 32x total) and damped grey-world AWB, and logs `AE:` / `AWB:`
  lines. If `/dev/isp_fe` stays silent, it steps from the encoder loop instead.

The IQ API transport, command IDs and struct layouts are in `docs/IFADO-MI-PIPELINE.md` (IQ / 3A).

## Known uncertainties (issue #37)
- Some nr57 / nr10 / nr11 fields beyond the ones used, and the exact UnBind tail.
- Whether the ISP output pixel format 0 (YUYV) is right for this product, or 0xb.
- Teardown order and DestroyDevice numbers. Rebooting is the reliable reset.
- 3A: why the `isp_fe` ack `write()` returns -1 (results apply anyway), the AWB result `Size`
  field (the vendor writes 0x3a, not 24), and the remaining AE/AWB status fields. Run 3 settled
  the rest: env 2, AE stats 32×32 RGBY, AWB stats 128×90 RGB.
