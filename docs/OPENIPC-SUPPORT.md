# OpenIPC support for this board — I6C (SSC377) + SC4336P (PLAN B-2a)

> **SUPERSEDED 2026-10-22.** The camera is SigmaStar **Ifado** (Cortex-A7, GICv2), not
> Infinity6C. OpenIPC has no Ifado target, and its `ssc377_lite` build (GICv3, Cortex-A35)
> can't boot here. See **`docs/IFADO-PLATFORM.md`**. The text below is kept as history.

Research 2026-10-21 (GitHub API + OpenIPC site). **Verdict: this board is a supported
combination in OpenIPC.** The project outlook improves from "multi-week port, sensor is
the risk" to "likely a buildable target; verify image quality at Gate 2."

## SoC — supported
- OpenIPC lists **SSC377 / SSC377D / SSC377DE / SSC377QE / SSC378DE** as "Done and done!"
  with guided installers (SigmaStar vendor page). SSC377 = **Infinity6C**, mapped to the
  `sigmastar-infinity6c` kernel target in OpenIPC/linux.
- **Kernel load address nuance:** OpenIPC's SSC377 default kernel load is **0x21000000**;
  our STOCK U-Boot relocates per the uImage header to **0x20008000** (DRAM base
  0x20000000). Since we keep stock U-Boot, package the OpenIPC kernel as a **relocatable
  zImage** wrapped in a uImage with load/entry **0x20008000** (see IMAGE-PACKAGING.md), or
  set the uImage addr to match. A zImage self-relocates, so either DRAM addr works.

## Sensor — supported (the key unlock)
- OpenIPC's `sensors` repo contains **`sigmastar/infinity6c/sensor_sc4336p_mipi.c`** —
  an SC4336P MIPI driver for exactly this SoC family, alongside sc401ai/sc430ai/sc450ai/
  gc4653/imx335/imx415/os04a10/etc.
- Driver config: **2560x1440 @30 fps, 2 MIPI lanes, 10-bit Bayer BG, external ISP
  (ISP_EXT), I2C 0x60, 27 MHz MCLK, CSI 216 MHz.** Sensor ID check: reg 0x3107=0x9c,
  0x3108=0x42. Resolution matches the 4 MP IPC-D240W-S.
- The driver does sensor register init + runtime AE; it references **no IQ/calibration
  file** — ISP tuning is handled downstream (majestic/SigmaStar ISP), not in the sensor
  driver.

## B-4 narrowed: frames = supported, TUNING quality = the remaining risk
The earlier B-4 concern ("no SC4336P IQ shipped in the stock dump") is softened: OpenIPC
provides the sensor driver, so the camera will produce frames. What's not guaranteed is
**well-tuned day/night image quality** — OpenIPC's ISP tuning for SC4336P may be generic.
Our vendor `_SMW/cfg_i6c/sc4336p_a50` tuning is a reference but a different format. Plan:
RAM-boot (Gate 2), judge the picture, and only invest in ISP tuning if needed.

## OpenIPC's own caveats (keep honest)
- "A matching sensor driver does not guarantee it works as intended" — hence Gate 2.
- OpenIPC includes binary components (majestic streamer); not wholly auditable source.
- SigmaStar sensor detection is module-based (`/config/auto_detect_sensor/modules/`).

## Updated effort estimate
- Tier A (adapt OpenIPC) is now the clear path: SSC377 target + SC4336P driver both exist.
- Likely bounded to: build the SSC377 image with the SC4336P sensor selected, package to
  fit stock mtd1/mtd2 (IMAGE-PACKAGING.md), RAM-boot to prove video, then flash via
  root-shell/TFTP (DELIVERY.md). ISP tuning is the main variable.

## Sources
- OpenIPC SigmaStar SoCs: https://openipc.org/cameras/vendors/sigmastar
- OpenIPC supported hardware: https://openipc.org/supported-hardware
- OpenIPC kernel targets: https://github.com/OpenIPC/linux
- SC4336P I6C driver: OpenIPC/sensors `sigmastar/infinity6c/sensor_sc4336p_mipi.c`
- Sensor support model (per-SDK, module-based): OpenIPC/wiki firmware-sensors.md
