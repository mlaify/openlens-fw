# Custom secure firmware — build plan (Anpviz IPC-D240W-S, SigmaStar I6C)

> **2026-10-22 correction:** the SoC is SigmaStar **Ifado** (Cortex-A7, GICv2), not I6C, and
> OpenIPC's ssc377 target can't boot it. The current route is stock kernel + new rootfs; see
> `docs/IFADO-PLATFORM.md` and RESUME.md §5. The plan below is kept as history.

Goal: replace the insecure ANJOY888 userland with an open, hardened firmware that
is still fully functional (video, RTSP/ONVIF, motion/person events), by **reusing
the vendor's silicon blobs and the per-sensor ISP tuning** and swapping everything
above them. Based on static recon of the owner's own V3.5.2.1 flash dump
(2026-10-18). This is the owner's hardware; building/flashing it is legitimate.

Related: see `../RESUME.md` (disclosure project) and `../report/HANDOFF.md`. The
vulnerabilities this firmware eliminates are F1–F24 in the disclosure report.

---

## 1. Platform facts (confirmed from the dump)

| Item | Value | Source |
|---|---|---|
| SoC | SigmaStar **Infinity6C (I6C)** (SSC33x family) | `mtd0-BOOT.bin` "I6C"; IPL strings |
| First boot | SigmaStar **IPL** → **U-Boot** → `bootm` (XZ-compressed) | BOOT.bin IPL_* symbols |
| Kernel | Linux **5.10** (uImage, dtb embedded — no separate .dtb in rootfs) | `config/modules/5.10/` |
| libc | **uClibc 1.0.31** | `lib/ld-uClibc-1.0.31.so` |
| Sensor | SmartSens **SC4336P** (MIPI), module variant `sc4336p_a50` | `cus_sc4336p_mipi_20251225.ko`; `isp_source.txt` |
| Ethernet | `sstar_emac` | u-boot env |
| SPI-NOR | PUYA **P25Q128** 16 MiB, **3.3 V** | chip markings / prior note |
| Console | **ttyS0 @ 115200 8N1** (UART EXISTS — find the pads) | u-boot `bootargs` |
| Memory split | `LX_MEM=0x4000000` (64M Linux), `mma_heap=0x1800000` (24M multimedia), `cma=1M` | u-boot env |
| Rootfs | **SquashFS, read-only**, `root=/dev/mtdblock2` | u-boot `bootargs` |
| OEM lineage | `_SMW` default config (`default_config/_SMW/cfg_i6c/sc4336p_a50`) | `isp_source.txt` build path |

### MTD partition map (memorize — this is the flash layout)
```
nor0: 0x40000  (BOOT   = IPL + IPL_CUST + U-Boot)   256 KiB
      0x200000 (kernel = uImage, dtb embedded)        2 MiB
      0xCB0000 (rootfs = SquashFS ro)               ~13 MiB
      0x100000 (DATA   = JFFS2 /mnt/nand, per-unit)   1 MiB
total mapped 0xFF0000 = 16,711,680 B (64 KiB short of the 16 MiB chip; the
unmapped region is the final 0xFF0000-0xFFFFFF tail, not the IPL header;
a full-chip read captures it, but the mapped MTD dump does not)
```

### U-Boot boot flow (reference)
```
bootcmd      = dcache on; run bootargs_run; run bootcmd_nor || run bootcmd_mmc;
bootcmd_nor  = sf probe 0; loados nor 0x23000000 kernel by_header; bootm 0x23000000
bootargs     = console=ttyS0,115200n8r root=/dev/mtdblock2 ro init=/linuxrc
               LX_MEM=0x4000000 mma_heap=mma_heap_name0,miu=0,sz=0x1800000
               mma_memblock_remove=1 cma=1M mtdparts=nor0:...
```

### Video bring-up recipe (from `/opt/ch/loadko` — reuse this order)
```
insmod /config/modules/5.10/sstar_mi.ko common_init.g_ModParamPath=/config/modparam.json
insmod /config/modules/5.10/mi_debug.ko                      # optional
echo 0 up /config/iqfile/fc105G1.00_SWLUT.txt ... > /proc/mi_modules/mi_scl/debug_hal/hvsp   # lens/HVSP LUT
insmod /opt/ch/cus_sc4336p_mipi_20251225.ko chmap=5          # SC4336P sensor, MIPI chmap 5
mdev -s
```

---

## 2. Reusable assets already in hand (the hard-to-get parts)

Extract these from `3.5.2.1/anpviz-live-analysis-2026-10-18/rootfs` — they are what
a from-scratch builder normally can't get:

- **Kernel + embedded DTB:** `mtd1-kernel.bin` (I6C board DTB is inside it).
- **U-Boot + IPL:** `mtd0-BOOT.bin` (keep as-is initially; it already does SPI-NOR + XZ).
- **Kernel modules (5.10):** `sstar_mi.ko` (the combined MI driver), `mi_debug.ko`.
- **Sensor driver:** `cus_sc4336p_mipi_20251225.ko` (SC4336P, `chmap=5`).
- **MI userland blobs:** `config/lib/libmi_sys.so`, `libmi_common.so`, `libcam_os_wrapper.so`
  (NOTE: VENC/ISP/VIF appear statically linked into `media_server`; OpenIPC ships its
  own complete I6C MI libs, so prefer OpenIPC's set and only fall back to these).
- **MI module params:** `/config/modparam.json`.
- **ISP / IQ tuning:** `config/iqfile/` — `isp_api.xml`, `isp_source.txt`, the HVSP LUT
  `fc105G1.00_SWLUT.txt`. ⚠️ The active SC4336P IQ bin is referenced by the `_SMW`
  config path, not the leftover `imx307/gc4023` bins; **confirm/locate the SC4336P
  tuning bin** (may be embedded in media_server or generated) — bring-up item B-4.
- **Per-unit data (DATA partition):** MAC, lens/sensor calibration, keep it intact —
  it is per-device and must be preserved across reflashes.

---

## 3. Recommended approach — tiers

**Tier A (recommended): adapt OpenIPC (or Thingino) for I6C + SC4336P.**
OpenIPC targets exactly these SoCs (ssc33x / Infinity6). You inherit a maintained,
already-hardened Buildroot userland (majestic streamer → RTSP/ONVIF, no telnet, SSH)
and only solve the SoC+sensor bring-up, for which the dump supplies every blob.
- If I6C + SC4336P is already supported → build + flash with the CH341A. ~a weekend.
- If not → port it using the dump's kernel/DTB/sensor.ko/IQ. ~weeks.

**Tier B: custom Buildroot image reusing the blobs.** Keep the vendor kernel + MI
blobs + sensor .ko + IQ; write a minimal hardened userland yourself. More control,
more work than reusing OpenIPC's userland.

**Tier C: full custom app against the MI SDK.** Reimplement the camera app on
`MI_VI/MI_ISP/MI_VENC`. Multi-month; only worth it for a product. Not recommended.

**Do Tier A.** It is the shortest path to "actually secure and functional."
For an assessment of network-only transfer and recovery on the expendable old
camera, see `NETWORK-ONLY-UPDATE.md`; no custom image has yet been installed
through that route.

---

## 4. Bring-up checklist

**Phase 0 — safety net (do first)**
- [ ] B-0a CH341A: take **two full-chip reads** of the 16 MiB P25Q128 (3.3 V — verify
      voltage before clipping). `sha256` both; they must match. This is the golden
      restore image. Store offline. (We already hold the mtd0–3 mapped dump; a
      full-chip read additionally captures the unmapped 64 KiB chip tail.)
- [ ] B-0b Write the golden image back once and confirm the camera still boots — proves
      the read/write loop works before you change anything.

**Phase 1 — serial console (high ROI; find the UART)**
- [ ] B-1 UART exists (`ttyS0`). Hunt 3 test points near the SoC: TX, RX, GND. A USB-TTL
      at 115200 8N1; probe for TX during boot (it spews IPL/u-boot logs). 3.3 V logic.
      Without it you are reflashing blind; with it, bring-up is minutes. Interrupt
      u-boot for an interactive prompt (`sf`, `printenv`, `setenv`, `bootm`).

**Phase 2 — OpenIPC/Thingino target check**
- [ ] B-2a Confirm OpenIPC support for **ssc33x / Infinity6C** and the **SC4336P** sensor
      (check the OpenIPC/Thingino hardware lists + sensor drivers).
- [ ] B-2b If supported: build the OpenIPC image for I6C; set the DTB/sensor to SC4336P.
- [ ] B-2c If not: port — reuse `sstar_mi.ko`, `cus_sc4336p_mipi.ko (chmap=5)`, the IQ
      set, and the embedded DTB from the dump; wire them into OpenIPC's Buildroot.

**Phase 3 — video first boot**
- [ ] B-3 Boot OpenIPC kernel+rootfs from RAM (u-boot `loady`/`tftp` over UART, or flash
      to the kernel/rootfs partitions). Replicate `loadko` order. Get `majestic`
      streaming RTSP. This is the make-or-break step (ISP/sensor).
- [ ] B-4 Resolve the SC4336P IQ: point majestic/MI at the correct tuning so the image
      is usable day+night. (Locate/extract the `_SMW sc4336p_a50` IQ if OpenIPC lacks it.)

**Phase 4 — functionality parity**
- [ ] B-5 RTSP main+sub streams; verify in Surveillance Station ("By Camera" ONVIF).
- [ ] B-6 ONVIF (onvif server in OpenIPC) for discovery + event passthrough.
- [ ] B-7 Motion/person events → ONVIF event → SSS Action Rule (ties into your DS223j
      setup: camera-side detection, NAS just records/notifies).
- [ ] B-8 Audio if needed; IR-cut/day-night switch; LED/PTZ if applicable.

**Phase 5 — flash + finalize**
- [ ] B-9 Keep the vendor **BOOT (IPL+u-boot)** partition unless you have a reason to
      change it; flash only **kernel** + **rootfs**; preserve **DATA** (per-unit cal/MAC).
- [ ] B-10 Full-chip CH341A write of the final image; verify boot; re-image the 2nd camera.

---

## 5. Security design (the whole point — what makes it "secure")

Replace, do not patch, the ANJOY888 stack. Target state:
- **No telnet, no port-9999 debug service, no `console.cgi` debug toggle** (kills F22/F23).
- **SSH key-only** (dropbear/OpenSSH), password login disabled; **unique per-device**
  root credential, not a shared firmware hash (kills F19).
- **No derived/master credential, no cloud/P2P phone-home, no Alibaba FOTA** (kills F1/F15).
- **No unauthenticated control plane**; if ONVIF is on, require auth by default (fixes F12/F17).
- **Signed updates:** sign firmware images with *your* key; verify the signature in the
  updater (and ideally in u-boot) before flashing — no CRC-only updates (fixes F6).
- **Read-only SquashFS rootfs** + small writable overlay (tmpfs/JFFS2) for config only.
- **Network default-deny:** nftables drop-all inbound except RTSP/ONVIF/SSH from the
  camera VLAN; **no outbound** except what you explicitly allow (NTP). Keep the camera
  on the isolated no-internet VLAN regardless.
- **Credentials/keys:** no hard-coded DES key, no reversible EncryptPwd store (fixes F13);
  store secrets hashed/encrypted with a per-device key.
- **Minimal attack surface:** drop Dahua(37777)/Hik(8000)/SADP/UPnP unless needed
  (removes F16/F24 surface and the F20/F21 parsers entirely).

---

## 6. Tools / environment

- **Flashing:** CH341A + SOIC-8 clip (have it). `flashrom -p ch341a_spi` to read/write
  the P25Q128 (3.3 V). Always read→verify before write; keep the golden dump.
- **Build:** OpenIPC/Thingino Buildroot external tree (brings the arm uClibc toolchain).
  Cross: `arm-openipc-linux-musl-` or the uClibc variant matching the vendor ABI if you
  reuse vendor .so's (uClibc 1.0.31). NOTE: mixing musl-built userland with uClibc
  vendor blobs can break — prefer OpenIPC's own MI libs to avoid ABI mismatch.
- **Kernel/rootfs transfer during bring-up:** u-boot over UART (`loady`), or TFTP, or
  just CH341A reflash of the kernel+rootfs partitions.
- **Recovery:** CH341A reflash of the golden full-chip image un-bricks anything short
  of corrupting IPL (and even IPL is in the dump).

## 7. Biggest risks / unknowns
> **Update 2026-10-21:** B-2a RESOLVED — OpenIPC supports SSC377/I6C **and** ships an
> SC4336P I6C sensor driver (`OpenIPC/sensors sigmastar/infinity6c/sensor_sc4336p_mipi.c`).
> B-4 narrows to ISP **tuning quality** only (frames are supported). See `docs/OPENIPC-SUPPORT.md`.
1. **SC4336P IQ tuning** — if OpenIPC lacks SC4336P support and the vendor IQ bin is
   buried in `media_server`, getting good image quality is the main technical risk. (B-4)
2. **UART pads** — if truly absent, bring-up is slow (blind reflash loop). Find them. (B-1)
3. **MI library ABI** — reusing vendor libmi .so's against a non-uClibc userland can
   fail; prefer OpenIPC's I6C MI libs. (§6)
4. **Full-chip vs mapped dump** — get a true CH341A full-chip golden image (captures the
   unmapped 64 KiB chip tail) before writing anything. (B-0a)

## 8. First three concrete actions
1. Find the UART pads and get a boot log (confirms IPL/u-boot versions, DRAM init, sensor probe).
2. Full-chip CH341A read ×2 → golden restore image (offline).
3. Check OpenIPC/Thingino for I6C + SC4336P; if present, build a test image and RAM-boot it over UART before flashing.

---

## 9. Acceptance gates (hard conditions before touching the replacement camera)

Adopted from external review (ChatGPT, 2026-10-20) and agreed. **Develop only on
the recovered spare (camera #1). The replacement (camera #2) stays isolated and
working; it is only reflashed after ALL gates below pass on the spare.** A
successful Linux boot is NOT proof of a working or secure camera.

**Gate 1 — Prove recovery first.**
- **2026-10-22 progress:** two matching 16 MiB software reads of cam #1 now
  include the previously unmapped 64 KiB tail. See
  `docs/SOFTWARE-FULL-CHIP-BACKUP.md`. They do not prove physical restoration;
  the CH341A read/write/boot test below remains open.
- Take a true **full-chip CH341A read** of the 16 MiB P25Q128 (not just the mapped
  MTD dump, which is 64 KiB short at the *end* of the chip). Two reads,
  hashes must match → golden restore image, stored offline.
- Identify and preserve board-specific data (per-unit DATA partition: MAC, cal) and
  U-Boot env. Document and **test** a restore: write golden back, confirm boot.
- A UART/U-Boot+TFTP install route may avoid the clip, but a bad bootloader or
  missing UART can still force the clip — so the clip path must be proven first.

**Gate 2 — Get working video before writing flash.**
- Compare stock `chmap=5`, `modparam.json`, sensor wiring, and the ISP/IQ tuning
  against OpenIPC's Infinity6C build and the known SSC377+SC4336P reports.
- **Boot a candidate from RAM (U-Boot `loady`/TFTP) and demonstrate stable video,
  IR/night switching, and clean reboot on the spare — before any flash write.**
- A public SSC377+SC4336P OpenIPC report shows a similar board booting and detecting
  the sensor but producing **no video frames** (different sensor routing). Treat as a
  warning to test THIS board, not proof of failure.

**Gate 3 — Security acceptance test (on an isolated test link).**
- On first boot of a current OpenIPC build, immediately **claim** the camera with a
  unique password (OpenIPC's "unclaimed" state should refuse streams/shell until a
  password is set — verify this actually holds on the matched build).
- Enumerate **listeners and outbound connections**; test HTTP, RTSP, ONVIF, SSH, and
  reset **before and after** claiming. Record the results.
- Confirm what the **retained bootloader** accepts: does U-Boot take unauthenticated
  network/`ota` updates? Does this SoC enforce boot signatures at all? Until these are
  answered, "OpenIPC installed" is a **functionality** milestone, not proof of a
  trusted boot chain.

**Caveats to keep honest:**
- OpenIPC includes **binary components** (e.g., the Majestic streamer) — it is not
  wholly auditable source. Replacing Anjoy's app removes F1–F24's surface but does not
  by itself establish a verified/trusted boot chain.
- Keep production cameras on the **no-internet VLAN**; allow only the NVR + management
  host; disable unused services. This holds regardless of firmware.

## 10. B-4 update — SC4336P ISP tuning is NOT shipped as data (important)

Recon of the dump: `media_server` references an IQ-file table for other sensors
(gc4023, imx307, imx577, ov12d40, sp4329 …) but **the on-device `config/iqfile/`
contains no `sc4336p_*.bin`**, and the generic `iqfile0-3.bin` slots **symlink to
`imx307_iqfile.bin`**. The only SC4336P tuning reference is the one-line
`isp_source.txt` build path `_SMW/cfg_i6c/sc4336p_a50`; `media_server` has 0
"sc4336" strings (tuning not embedded by that name). So the stock camera runs
SC4336P on tuning that is either compiled elsewhere or falls back to imx307/driver
defaults.

Consequence for the build: **obtaining good SC4336P image quality is the #1
technical risk.** Options, in order: (a) use OpenIPC/Thingino's own SC4336P tuning
if present; (b) extract/convert the `_SMW sc4336p_a50` tuning from the vendor's ISP
tool set if obtainable; (c) accept sensor-driver defaults + hand-tune via the MI ISP
API. Do Gate 2 (RAM-boot, prove video) before committing to flash precisely because
of this.

> **Delivery:** clipless install via root-shell `flashcp` or U-Boot TFTP is planned in `docs/DELIVERY.md` (owner accepts brick risk; never software-write BOOT).
