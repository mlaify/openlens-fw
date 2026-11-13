# BOARD.md — Anpviz IPC-D240W-S hardware map (from the stock V3.5.2.1 image)

Static analysis of the owner's flash dump (2026-10-21): stock kernel decompressed, the
built-in device tree extracted + decompiled, and the stock userland (libtools.so,
media_server, mainctrl) decompiled in Ghidra. Purpose: give the OpenIPC port the
board-specific facts that OpenIPC's generic `ssc377` support won't know.

## Identity
| Item | Value | Source |
|---|---|---|
| Board model (DTB) | **`IFADO SSC032B-S01A`**, `compatible = "sstar,ifado"` | built-in DTB |
| Meaning | **Corrected 2026-10-22:** `ifado` is its own SigmaStar family (live `soc0/family` = IFADO, Cortex-A7, GICv2), **not** Infinity6C. SSC032B-S01A = **SigmaStar reference board**. See `docs/IFADO-PLATFORM.md` | live probe |
| Kernel | **Linux 5.10.117**, `arm-sigmastar-linux-uclibcgnueabihf-9.1.0-gcc` | kernel banner |
| CPU | ARM Cortex-A7 r0p5, single core, 1 GHz (`CPU part 0xc07`, no ARMv8 instructions); GICv2 | DTB + live `/proc/cpuinfo`, `/proc/interrupts` |

Being a near-reference board is good news: OpenIPC's `ssc377` support derives from the
same SigmaStar SDK reference design.

## Kernel partition (mtd1) layout — IMPORTANT for packaging
| mtd1 offset | Size | Content |
|---|---|---|
| 0x000000 | 64 B | uImage header: arch ARM, type kernel, **comp field = LZMA (3)**, load/entry **0x20008000** |
| 0x000040 | 1,683,112 B | kernel payload — **actually XZ** (`FD 37 7A 58 5A`, check=CRC64), not LZMA |
| (inside) | 46,696 B | **board DTB built into the kernel** (decompressed Image @ 0x315c00, v17) |
| 0x1C6C8C | 43,076 B (xz) | blobA — small embedded tool (unknown consumer) |
| 0x1D14D0 | 112,916 B (xz) | blobB — 256 KiB `SGSI` image tagged `L10.0.3_verified_24120513` |
| 0x1ECDE4 | 78,364 B (xz) | blobC — 87,847 B decompressed, high-entropy, no strings (unidentified); missed by binwalk, found by `scripts/extract-kernel-dtb.py`; runs to the exact end of mtd1 |

- The bootloader ignores the header's LZMA label and decompresses **XZ** (the IPL
  registers `ipl_cust_xz_decompress_func_register`). **Package the OpenIPC kernel the same
  way** (see IMAGE-PACKAGING.md) — an LZMA-alone payload would likely fail to boot.
- The IPL references **`PM_RTOS` / `MISC_RTOS`**; blobB may be a power-management RTOS
  image loaded from this partition. Until proven unused, **preserve all three trailing blobs**:
  keep the OpenIPC kernel uImage **≤ 0x1C0000 bytes (1.75 MiB)** so writes never touch the
  64 KiB erase block holding blobA (mtd1 0x1C0000–0x1CFFFF).
- U-Boot env also carries `loados_addr=0x23000000`, `loados_size=0x1ab1ac`.

## Image sensor — SmartSens SC4336P
| Item | Value | Source |
|---|---|---|
| Sensor driver | stock `cus_sc4336p_mipi_20251225.ko` = **same SigmaStar SDK driver as OpenIPC's** `sensor_sc4336p_mipi.c` (identical `pCus_init_mipi2lane_linear_4M30fps`) | .ko strings |
| Mode | 2560×1440 @ 30 fps, 2-lane MIPI, linear | driver |
| **Load params** | stock passes **only `chmap=5`** ("VIF channel mapping"); others default | `/opt/ch/loadko` |
| Other params | `lane_num`, `hdr_lane_num`, `i2c_slave_id`, `mclk` (string), `sensor_rst_pol`, `mipi_user_def` | .ko modinfo |
| Sensor I2C bus | **I2C1** (`snr0_mipi_i2c = 1`; i2c1 @ 0x1f223200) | DTB `sensorif` |
| Sensor reset GPIO | **GPIO 76** (`snr_sr0_rst_gpio = 0x4c`); no PWDN GPIO | DTB `sensorif` |
| CSI ports | sr0 = 4-lane (lane_select 3,1,2,4,5); sr2 = 2-lane (lane_select 0,1,2); no PN swap | DTB `csi` |
| MCLK | DTB flags **37.125 MHz** mode on sr0/1/2; OpenIPC's SC4336P driver uses **27 MHz** | DTB / OpenIPC src |

**Porting action:** load the SC4336P module with **`chmap=5`** under OpenIPC (most likely
cause of the public SSC377+SC4336P "boots, sensor detected, no frames" report — that board
used different routing). If frames still don't come, check MCLK (37.125 vs 27 MHz) next.

## Day/night (IR-cut, IR LEDs, light sensing)
Two code paths exist in the stock firmware, selected by **product type** (derived from the
device serial via `sn_get_product_type` → written to `/tmp/product_type.txt`):

1. **Vendor `/dev/irled` kernel driver** ("IRLED driver v2.1 20240625 for 373", built into
   the stock kernel, not a module). `media_server` writes 1 byte for day/night mode and
   reads day/night status (1=day, 2=night) from it. The driver owns the IR-cut H-bridge and
   the photosensor (pins resolved below). **OpenIPC's kernel does not have this driver** —
   the pins are given to majestic instead.
2. **ADC-threshold path** — reads a light ADC, compares to day/night thresholds from
   config, and drives **GPIO 61** directly (`io_out_write(0x3d, 0=day / 1=night)`).

Pin assignments otherwise come from a **static per-product-type GPIO table inside
libtools.so** (`FUN_000517a0` selects it by product type; entries are 0x34 bytes:
+0x20 pin, +0x24 dir (0 in/1 out), +0x28 default level, +0x2c type ID); `gpio_init`
exports them via sysfs. Some product types use an **I2C GPIO expander** instead
(`init_i2c_expand_gpio`, `set_expand_gpio_value`).

### Resolved for this unit (2026-10-21: bench probe + kernel decompile)
- **Product type `MCA40E`** (`/tmp/product_type.txt`). This unit uses **path 1, `/dev/irled`**
  (char 93,0). Only GPIO 10 (in, 1), 12 (out, 0) and 30 (core VID — see below) are exported;
  none changed between day and night, so the IR pins are held by the kernel driver.
- **IR-cut / light-sensor pins** — read from the IRLED driver's GPIO table in the stock kernel
  (Thumb-2 kernel, virtual base `0xC0008000`; init at `0xC0305C3C`, table at `0xC0367D58`,
  close-timer at `0xC012B902`):

  | Kernel label | GPIO | Dir | Role |
  |---|---|---|---|
  | `IRCUT A` | **11** | out, idles low | IR-cut H-bridge leg A |
  | `IRCUT B` | **80** | out, idles low | IR-cut H-bridge leg B |
  | `IRDET` | **23** | in | day/night light sensor |

  The driver pulses one leg, then a timer drops both low ("IRCUT close"). It is char
  device major 93 (`/dev/irled`). It handles IR-cut + sensor only — **not** the LEDs.
- **`/dev/irled` protocol** (media_server `FUN_0003ff58` / `FUN_0003ffd8` / `FUN_0003feb4`,
  disassembled 2026-10-23):
  - **Write** one byte: `1` = day (IR-cut in), `0` = night (IR-cut out). Night also creates
    `/tmp/ircut_night_mode`.
  - **Read** a u32 light status: 1 = day, 2 = night. Stock swaps it for product codes
    0x199/0x19d/0x19e.
  - **MCA40E reads inverted:** cam #2 read 1 while stock was in night mode (probe 5).
- **Polarity:** stock "IRCut Mode = Manual Normal Open" = **night** (filter out, B/W image).
  Which leg (A or B) is the "open" pulse isn't decoded yet — at OpenIPC RAM-boot set
  `irCutPin1=11`, `irCutPin2=80`, `irSensorPin=23`; if day/night come out inverted, swap 1↔2.
- **IR LEDs and white LED — resolved (darkness test, 2026-10-22, on camera #2, same model):**

  | Light | PWM channel | Pad | Evidence (night forced, LED manual 100%, dark room) |
  |---|---|---|---|
  | **IR LEDs** | **PWM4** (`pwmchip4/pwm0`) | **9** | Pure Infrared: PWM4 duty 50000/50000, PWM0 0 |
  | **White LED** | **PWM0** (`pwmchip0/pwm0`) | **13** | Pure White: PWM0 duty 50000/50000, PWM4 0 |

  Both run at **20 kHz** (period 50000 ns); brightness % maps linearly to duty (100% = full
  period). Driven from userland (`media_server` "pwm duty"), not by `/dev/irled`. In lit
  rooms both duties read 0 (scene above "Light On Illumination"). Pure White mode does **not**
  set `/tmp/ircut_night_mode` — it keeps the IR-cut in the day position for colour night
  video. For OpenIPC: IR LED = PWM4 @ 20 kHz (fallback: mux pad 9 as GPIO 9, drive high = full
  on); white LED = PWM0 / pad 13 (optional; leave off for IR-only night mode).
- **GPIO 30 = SoC core-voltage control** (`core_power`, `sstar,voltage-ctrl`: 980/1030 mV,
  init 1000 mV). **OpenIPC must never drive GPIO 30.**
- Sensor module live parameters: `chmap=5`, `lane_num=2`, `hdr_lane_num=4`, `i2c_slave_id=0`,
  `mclk=default`, `sensor_rst_pol=1`, module `MVX3IFADO…build.202512301714`.
- Flash erase size is **4 KiB** on mtd0–2 (64 KiB on DATA): the hard kernel limit is really
  `0x1C6000`; `0x1C0000` stays the documented budget for margin. Runtime `mma_heap` is
  `0x1600000` (22 MiB), not the env's 0x1800000 — use the runtime value in OpenIPC bootargs.

`scripts/bench-probe.sh` (stock root shell, read-only) reproduces the userland half of this.

## Other peripherals
| Item | Value |
|---|---|
| Ethernet | `sstar-emac` emac0, internal PHY, `phy-mode = "mii"` — standard |
| WiFi | **None** — no WiFi driver in rootfs or kernel (web WiFi pages are generic baggage) |
| UART console | ttyS0 @ 115200 8N1 (pads not yet located) |
| USB | USB2 PHY present (`sstar,u2phy`) |
| NPU | `dla/model/sdy48.img` person-detection model (stock); `ipu_lfw.bin` 0 B |

## Artifacts
Regenerate everything with the versioned script (outputs are vendor-derived — keep them in
`$TMPDIR` or under the gitignored `vendor-blobs/`):

    python3 scripts/extract-kernel-dtb.py vendor-blobs/kernel/mtd1-kernel.bin vendor-blobs/dtb

It parses the uImage header (and flags the XZ-under-LZMA mismatch), writes the raw kernel
`Image`, every valid DTB (`board0.dtb` → `board0.dts` via `dtc`, 2,409 lines), and each
trailing XZ stream (`trailing0..2.bin` = blobA/B/C), and prints the safe kernel budget.

Ghidra decompiles of libtools.so / media_server came from `scripts/ghidra-run.sh` with
`tools/ghidra/DecompileByName.java`, `DecompileStringRefs.java`, and `DecompileAddresses.java`
(see `tools/ghidra/README.md`).
