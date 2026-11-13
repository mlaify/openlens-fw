# The camera is SigmaStar "Ifado", not Infinity6C: what that means for the firmware

Established 2026-10-22 from two read-only live probes of cam #1 (owner-run, logs in the
gitignored `bench-logs/cam1-live-probe-{1,2}.txt`), the stock dumps, and the built OpenIPC
image. **This supersedes the I6C/SSC377 identification in OPENIPC-SUPPORT.md and BUILD.md.**

## Hardware, confirmed live
| Item | Value | Evidence |
|---|---|---|
| SoC family | **SigmaStar IFADO**, revision 4 | `/sys/devices/soc0/family` = `IFADO`, `revision` = 4; MI log "chipidx 13, revision 4" |
| Possible part | maybe an SSC373-class part (unconfirmed) | vendor IRLED driver banner "for 373"; read the chip marking to confirm |
| IPL build | `ifado_nor_defconfig` | mtd0 strings |
| Board | `IFADO SSC032B-S01A` (`compatible = "sstar,ifado"`) | `/proc/device-tree/model`, DTB |
| CPU | **ARM Cortex-A7 r0p5, single core, 1 GHz** (`CPU part 0xc07`); NEON/VFPv4/LPAE/idiv; **no ARMv8 instructions** | `/proc/cpuinfo`, `sstar_cpufreq` |
| Interrupts | **GICv2** (`GIC-0`, `arm,cortex-a7-gic` at `0x16001000`) + SigmaStar `ms_main_intc`/`ms_gpi_intc` | `/proc/interrupts`, dmesg, DTB |
| Timer | ARM arch timer 6 MHz (virt) | dmesg |
| RAM | 64 MiB DDR at `0x20000000`; Linux gets ~38 MB; MMA heap 22 MiB at `0x22a00000`; CMA 2 MiB | dmesg, cmdline |
| PWM | `sstar,pwm` at `0x1F003400` (8 channels; `/dev/pwm0,4-7`) | DTB, `/dev` |
| Ethernet | `Sstar-emac` at `0x1f2a2000`, generic MII PHY | dmesg |
| Flash | 16 MiB SPI-NOR via `sstar-fsp_qspi` / `sstar-norflash` | dmesg |

"I6C" appears only in vendor **labels** (`version_kernel=MSTAR_I6C_LINUX_375`,
`default_config/_SMW/cfg_i6c/...`). The silicon is Ifado. The earlier identification relied on
those labels.

## Why the OpenIPC `ssc377_lite` build can't boot here
Built image (OpenIPC `65ce450`, see BUILD.md), compared with the live hardware:
- **Interrupt controller:** its DTB declares `arm,gic-v3` at `0x16000000` + `0x16040000`. The
  chip has a GICv2. The kernel would get no working interrupts and almost certainly hang early.
- **CPU:** its DTB says `arm,cortex-a35`, and userspace and the toolchain are tuned for the A35
  (`BR2_cortex_a35`). That can emit ARMv8-AArch32 instructions, which crash with SIGILL on this
  Cortex-A7.
- **Peripherals:** `sstar,infinity-pwm` at `0x1F203200`, a different clock and padmux layout,
  and OpenIPC's I6C `mi.ko`, which targets I6C video hardware.
- **No Ifado target in OpenIPC:** OpenIPC has no Ifado family. Its other Cortex-A7 SigmaStar
  family (`ssc30kd`/`ssc30kq` → infinity6e) uses kernel 4.9 and a different chip layout.

The build work isn't wasted: the Docker pipeline, the kernel-size packaging rules and the
review findings all carry over. But **don't RAM-boot or flash the `ssc377_lite` images on
this camera.**

## The route that boots: stock kernel + new rootfs
Keep everything that already boots this exact silicon: mtd0 (IPL/U-Boot), mtd1 (the stock
5.10.117 kernel with its DTB and the trailing blobs), and the vendor kernel modules. Replace
**only the rootfs in mtd2.**

### What a replacement rootfs must provide
| Requirement | Detail / evidence |
|---|---|
| Format | **squashfs, xz**. Stock uses 256 KiB blocks and 7.9 MB; the mtd2 slot is 0xCB0000 (13,303,808 B) |
| Init | the kernel runs `init=/linuxrc` from `root=/dev/mtdblock2 rootfstype=squashfs ro` (U-Boot env bootargs). Provide `/linuxrc` (BusyBox init), `/etc/inittab` and `/etc/init.d/rcS` |
| ISA / ABI | ARMv7 EABI hard-float, **Cortex-A7 only**, Thumb-2 OK. Build with Buildroot targeting `cortex_a7`, not OpenIPC's A35 toolchain |
| Filesystems available | squashfs, jffs2, tmpfs, ramfs, devtmpfs, devpts, sysfs, proc, configfs, cgroup. **No overlayfs, ext4, NFS or vfat** |
| Persistent storage | DATA = mtd3, jffs2, mounted at `/mnt/nand` (1 MiB). Today it holds the vendor config and credentials. Plan its reuse for SSH keys and config (wipe/reformat decision later) |
| Memory | ~38 MB for Linux in total. The stock apps leave ~15 MB available; a lean userland must stay well under that |
| Network | `eth0` is built in. **No netfilter/iptables, no IPv6**: default-deny means *no listeners except the ones we choose* |
| Kernel modules | Same order and parameters as stock `/opt/ch/loadko`: `insmod /config/modules/5.10/sstar_mi.ko common_init.g_ModParamPath=/config/modparam.json`; `insmod mi_debug.ko`; `echo 0 up /config/iqfile/fc105G1.00_SWLUT.txt /config/iqfile/fc105G1.00_SWLUT.txt > /proc/mi_modules/mi_scl/debug_hal/hvsp`; `insmod cus_sc4336p_mipi_20251225.ko chmap=5`; `mdev -s`. `modules_disabled=0` |
| Vendor data the drivers read | `/config/modparam.json`, `/config/iqfile/*` (incl. `isp_api.xml`, `fc105G1.00_SWLUT.txt`), `/config/venc_fw/ven_para.cfg`, `/config/dla/*` |
| Devices | devtmpfs + `mdev -s`: `/dev/mi_*` (major 249), `msys`, `mi_poll`, `irled` (93), `pwm*`, `i2c-*`, `watchdog`, `mtd*` |

The vendor `.ko`/`.so`/IQ files stay **local**. The build copies them from the owner's dump at
image-assembly time and never commits them (hard rule 5).

### Booting it and testing first
- **No kexec, no initramfs path from the running system.** The first real boot of a new rootfs
  means writing mtd2. That requires Gate 1 first: a CH341A read **and a tested restore**. mtd0
  and mtd1 are never written.
- **Before that, test from the live root shell on the stock kernel** (agents may connect per
  RESUME §3 rule 8, read-only by default):
  - run our static Cortex-A7 binaries from `/tmp`
  - `chroot` into a test rootfs unpacked into tmpfs
  - stop vendor apps one at a time to measure what video and network still need

## Video: the real blocker
Stock video runs in `/opt/ch/media_server` (2.1 MB, uClibc), which has the SigmaStar MI
user libraries **compiled in**: 91 `MI_VIF/ISP/SCL/VENC/...` functions. Its dynamic deps are
only `libstdc++`, `libmi_sys.so`, `libtools.so`, `libgcc_s`, `libc.so.0` and `ld-uClibc`. The
camera has **no** `libmi_vif/isp/scl/venc.so`. Only `libmi_sys.so`, `libmi_common.so` and
`libcam_os_wrapper.so` exist, in `/config/lib`. So an open-source streamer has no vendor
video library to call.

Options, cheapest first:
1. **SDK:** find SigmaStar's Ifado SDK (MI headers + libs) or an open project that supports
   Ifado. Web research, authorised 2026-10-22.
2. **Contain the vendor engine:** keep `media_server` with no network role. Drop every
   network-facing vendor service (`hik_server`, `web_server`, `p2p_server`, `h5live_server`,
   `dbg_server`, `comm_server`, `ex_server`, telnet). Add our own RTSP server fed from
   media_server's internal stream, which needs reverse-engineering its IPC.
3. **Talk to the kernel directly:** reimplement the MI calls against `/dev/mi_*`, with the
   ioctl ABI recovered from `media_server` in Ghidra. Most effort; full control.

## Research results (2026-10-22)
- **Public web: nothing on "Ifado" or "I6DC".** The searches came back empty:
  - SigmaStar product pages, OpenIPC (site, ipctool chip table, linux/u-boot branch lists),
    linux-chenxing, and general search.
  - "SSC373" turns up only as a module vendor's part name, with no datasheet.
  - Known codenames (ipctool #21): Infinity6 = Macaron, 6b0 = Ispahan, 6e = Pudding
    (includes the Cortex-A7 SSC30KD/KQ), **6c = Maruko** (SSC377/378, Cortex-A35),
    mercury6 = Tiramisu.
  - Ifado/I6DC is unpublished. Read the chip marking to get the part number.
- **The vendor SDK is "I6DC".** The build paths in the stock `sstar_mi.ko` are
  `/home/shawn.liu/Anj_i6dc_v3.1.0/sdk/.../impl/{sys,scl}/hal_common/ifado/...`.
  `media_server` carries `MVX1##I6DC####…` tags (AGC/APC/NR).
  The kernel module contains both **IFADO** and **MARUKO** strings, so Ifado's MI stack comes
  from the I6C (Maruko) codebase.
- **(Superseded by the exact Ghidra comparison below)** First heuristic: the MI kernel interface *looked* close to OpenIPC's I6C libraries. The OpenIPC I6C user libraries
  (`sigmastar-osdrv-infinity6c/files/lib`) are thin ioctl wrappers: `libmi_vif.so` and
  `libmi_scl.so` are ~9.6 KB each. Ioctl codes are `_IOC` with type `'I'` (0x49), and the
  codes encode struct sizes.
  - A heuristic constant scan found these byte-identical in the stock `media_server` /
    `libmi_sys.so`: **VENC 20/37, VIF 8/10, SYS 4/6**.
  - The non-matching candidates have improbable sizes (4097, 1579, 1146…) and are probably
    data, not ioctls.
  - Tentative conclusion at the time (**wrong**, see below): same API generation, likely
    largely ABI-compatible.
- **Exact Ghidra comparison (2026-10-22): OpenIPC's I6C libraries are NOT compatible.**
  `tools/ghidra/IoctlInventory.java` decodes every `ioctl()` request at its call site. Each MI
  call is `ioctl(fd, _IOC(dir, 'i', nr, sizeof(params)), &{size, u64 ptr})`, so a command code
  pins both the call number and the struct size. Results
  (`analysis/ifado-mi-ioctl-inventory.tsv`, `analysis/i6c-openipc-mi-ioctl-inventory.tsv`):
  | Module | Same function names | Identical codes |
  |---|---|---|
  | SYS (I6C lib vs stock `libmi_sys.so`) | 47 | **14** |
  | VENC (vs names recovered in `media_server`) | 21 | **0** |
  | RGN | 8 | **2** |
  - VIF/ISP/SCL/SENSOR wrappers in `media_server` are unnamed. Only a few of their codes
    collide anywhere.
  - Typical differences: call numbers shift (VENC `CreateChn` is nr 2 / 84 B on I6C and
    nr 0 / 88 B on Ifado). Structs grow, because Ifado widens pointer/handle fields to 8 bytes
    (SYS frame buffers are 648 B on I6C and 376 B on Ifado; RGN attach is 48 → 96 B).
  - **Conclusion:** same MI API design, but a newer, incompatible kernel interface. **Option
    "use OpenIPC's I6C libs" is dead.**
- **What's left for video:**
  - **Contain `media_server`** (option 2): least work, keeps a vendor binary.
  - **Thin Ifado MI shim** (option 3, now better defined): the camera ships its own
    `libmi_sys.so`/`libmi_common.so`. The other modules' wrappers are thin
    (`open /dev/mi_<mod>` + one ioctl). `analysis/ifado-mi-ioctl-inventory.tsv` gives every
    command code (number + struct size) that `media_server` uses. A minimal
    sensor→VIF→ISP→SCL→VENC pipeline needs perhaps 30–40 calls. Struct layouts would come
    from I6C-era headers adjusted to the Ifado sizes, verified against `media_server`'s
    decompiled callers. Medium–high effort, no vendor network code.
- **Superseded plan (kept for the record):**
  1. In Ghidra, recover the exact ioctl command list from OpenIPC's I6C `libmi_*.so` call
     sites. Check each one in `media_server`, including struct sizes.
  2. If they match, test live on cam #1 with the owner's per-action OK: from `/tmp`, run a
     small program that inits MI SYS/VIF/VENC through OpenIPC's I6C libs (with a musl loader)
     against the stock `sstar_mi.ko`, after stopping `media_server`.
  3. If it works, an open streamer (e.g. OpenIPC's divinus/waybeam-style dlopen streamers)
     becomes possible without the vendor engine. If not, fall back to containing
     `media_server` (option 2 above).

## Video route chosen: a thin Ifado MI layer (owner decision 2026-10-22)
Our own static Cortex-A7 code drives `/dev/mi_*` directly with the Ifado command codes. No
vendor userland runs: not `media_server`, and not the vendor network services.

### API table: `analysis/ifado-mi-api-table.tsv`
Every MI call that stock `media_server` makes, by device (`tools/ghidra/IoctlDeviceMap.java`
folds each wrapper's `open("/dev/mi_*")`), with call number, struct size and direction. Names
come from `media_server` log strings where present. Those are only hints: some wrappers log a
shared helper's name, e.g. several VENC rows say `GetStream`. Otherwise names are a guess from
the I6C call with the same (dir,size) or the same nr. **Verify each one by decompiling its
callers before use.**
- SENSOR, ISP and SCL keep I6C call numbering. A few structs grew (ISP chn param 28 → 36 B,
  sensor pad info 56 → 60 B).
- VIF keeps the numbering with larger structs (`CreateDevGroup` 32 → 52 B).
- VENC is renumbered (`CreateDev` at nr 76, `DestroyDev` nr 77; `SetChnAttr`/`GetChnAttr`
  88 B; `SetJpegParam` nr 40 at 144 B).
- SYS: the camera's own `libmi_sys.so` names every call (`analysis/ifado-mi-ioctl-inventory.tsv`).

### Stock pipeline order: `VideoManage::Init` (`encode/video/video_manage.cpp`) at `FUN_00021040`
Found with `tools/ghidra/CommonCallers.java` (the routine reaching the SNR/VIF/ISP/SCL create
wrappers). Stage names come from its log strings (`scripts/resolve-dat-strings.py`):
1. `FUN_0001d650`: first stage (the log prints it only as "exec function"); includes the
   sensor/VIF bring-up (`FUN_0001b5b4` calls SNR wrappers)
2. `FUN_0001d9c8`: InitmIsp
3. `FUN_0001e188`: InitVDisp (optional)
4. `FUN_0001d414`: InitRgn
5. `FUN_0001e344`: StartIsp, then VIF `EnableOutputPort`
6. `FUN_00020c0c`: InitScl
7. `FUN_0001e370`: InitVenc
8. `FUN_0001ef04`: InitRegion (OSD)
9. `FUN_0001f354`: InitIve (optional)
10. `FUN_0001ebb8`: StartVenc
11. `FUN_0001ebec`: StartGetStream
12. `FUN_0001f408`: InitIsp (IQ/3A)

### Plan
1. Decompile each stage and record the exact MI call order and the struct field values. That
   covers: sensor resolution index and plane mode; VIF dev/group/port attrs; ISP channel and
   port params; SCL port size and format; VENC channel attr (codec, size, RC); and the SYS
   binds (SNR→VIF→ISP→SCL→VENC).
2. Define the Ifado structs: I6C-era layouts resized to the sizes in the API table, with each
   field checked against how `media_server` fills it.
3. Build `mi-probe`, a static musl Cortex-A7 test that runs the minimal pipeline and writes
   H.264/H.265 to a file. Toolchain: Buildroot `cortex_a7` in the Docker setup.
4. On cam #1, with the owner's OK for this action: stop `media_server`, run `mi-probe` from
   `/tmp`, and check the stream on the Mac. Kernel modules stay as stock loads them.
5. Then: a small RTSP server around it, day/night (GPIO 11/80/23, PWM4), the hardened rootfs.

## Stock boot chain on the device (for reference)
`/linuxrc` (BusyBox 1.24.1 init) → `/etc/init.d/rcS`:
- mounts, mdev
- `/opt/ch/loadko`
- `/opt/ch/procman`, which starts `mainctrl`, `media_server`, `comm_server`, `record_server`,
  `hik_server`, `h5live_server`, `ex_server`, `p2p_server`, `web_server`, and `dbg_server` /
  `telnetd` when debug is toggled

`inittab` also respawns `getty` on `ttyS0`.
