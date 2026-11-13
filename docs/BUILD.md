# Building OpenIPC for this board (SSC377 / I6C + SC4336P)

> **2026-10-22: the `ssc377_lite` images must not be booted on this camera.** Its SoC is
> SigmaStar Ifado (Cortex-A7, GICv2), and this build targets Infinity6C (Cortex-A35, GICv3).
> See `docs/IFADO-PLATFORM.md`. The Docker pipeline (`docker-openipc.sh`,
> `claude-docker-openipc`) and the packaging notes below remain useful for building a
> Cortex-A7 userland for the stock-kernel route.

Produces the kernel+rootfs to install via `docs/DELIVERY.md`, packaged to fit stock
`mtd1/mtd2` per `docs/IMAGE-PACKAGING.md`. Confirmed buildable combo (see
`docs/OPENIPC-SUPPORT.md`): board defconfig **`ssc377_lite`**, sensor **SC4336P** driver
present in the I6C sensor set.

## Build host — Linux (natively, or in a container)
OpenIPC firmware is a Buildroot tree whose top-level Makefile assumes a **Debian/Ubuntu
Linux host**: `make deps` uses `apt-get`, and it calls GNU `sed -i`, `stat -c`, `date -d`,
`nproc`. It does not build natively on macOS. Use a Linux VM, or Docker on the Mac (below).
Needs ~20–30 GB disk. Deps (Ubuntu): `make deps`, or `automake autotools-dev bc
build-essential cpio curl file fzf git libncurses-dev libtool lzop make rsync unzip wget
libssl-dev python3 python3-pip`.

### What `ssc377_lite_defconfig` pulls in (read 2026-10-22)
- **Prebuilt external toolchain** `arm-openipc-linux-musleabihf` (musl, not the stock uClibc),
  downloaded from OpenIPC's GitHub releases (`toolchain.sigmastar-infinity6c`). OpenIPC builds
  these on x86_64 Linux, so expect an **x86_64-host** toolchain.
- Kernel from OpenIPC's linux tree, config `infinity6c-ssc027a.config`, **uImage with XZ**
  (`BR2_LINUX_KERNEL_XZ=y`) — matches the stock XZ payload.
- Rootfs **squashfs XZ**; `BR2_OPENIPC_FLASH_SIZE="8"` (8 MB layout; our 16 MB flash and
  13 MiB rootfs slot give ample room).
- `BR2_cortex_a35` — the stock DTB says Cortex-A7. Check this at RAM-boot.
- Packages: majestic + webui, dropbear, ipctool, sigmastar-osdrv-infinity6c (OpenIPC's own
  MI libs — use these, not the stock uClibc blobs), wireguard-tools, wpa_supplicant (unneeded:
  no WiFi on this board).

### macOS / Apple Silicon via Docker (`scripts/docker-openipc.sh`, set up 2026-10-22)
The Mac is arm64 and OpenIPC's toolchain is x86_64-host, so the build runs in an
`--platform linux/amd64` Ubuntu 24.04 container (`docker/Dockerfile`) under **Rosetta**: the
same host type as OpenIPC's CI, and much faster than QEMU emulation. The owner runs
`scripts/docker-openipc.sh` from their own terminal; the assistant's sandbox can't reach the Docker
socket and uses `claude-docker-openipc` instead (see "The assistant's builds" below).

**One-time Docker Desktop settings** (Settings, then *Apply & restart*):
- General: *Use Virtualization framework* **on**; *Use Rosetta for x86_64/amd64 emulation on
  Apple Silicon* **on**.
- Resources › Advanced: CPU limit = **all cores**; Memory **16 GB** if the Mac can spare it
  (8 GB minimum; Buildroot runs many compilers at once); Swap 2 GB; disk limit ≥ 64 GB.

**Use:**
```
scripts/docker-openipc.sh check   # Docker up? CPUs/RAM it has; Rosetta detected?
scripts/docker-openipc.sh build   # builds the image if needed, then OpenIPC -> ./out/
scripts/verify-image.sh out/openipc-kernel.bin out/openipc-rootfs.bin
```
`out/` gets `openipc-kernel.bin` (option A), `openipc-kernel-zimage.bin` (option B),
`openipc-rootfs.bin`, `build.log`, and `BUILD-INFO.txt` (OpenIPC commit, build seconds, CPUs,
ccache hits). `out/` is gitignored. `shell` opens a shell in the build tree (`make
BOARD=ssc377_lite br-linux-menuconfig` etc.); `clean` drops the build tree; `purge` drops the
caches too.

**Why it's fast:**
- Three Docker named volumes (ext4 in Docker's VM, case-sensitive): `cam-openipc-work` (OpenIPC
  clone + Buildroot output), `cam-openipc-dl` (`BR2_DL_DIR`: toolchain, kernel and package
  tarballs), and `cam-openipc-ccache` (OpenIPC enables `BR2_CCACHE`). Re-running `build`
  only rebuilds what changed. After `clean`, the rebuild skips the downloads and mostly hits
  ccache.
- OpenIPC turns on `BR2_PER_PACKAGE_DIRECTORIES` and runs `make -j$(nproc)`, so it uses every
  CPU Docker has.
- Only `scripts/` (read-only) and `out/` are shared with macOS. No build I/O crosses that
  share.

**Not done: native arm64.** An arm64 container would skip Rosetta (perhaps 20–30% faster
compiles), but the prebuilt toolchain can't run there. It would mean building the toolchain
with `make toolchain` and pointing the defconfig's `BR2_TOOLCHAIN_EXTERNAL_URL` at the result.
Measure the Rosetta baseline (`BUILD-INFO.txt`) first; ccache already makes rebuilds cheap.

### The assistant's builds: `claude-docker-openipc` (exception E-9, 2026-10-22)
A root-owned wrapper (claude-env kit `macbook-docker/`) that runs the same build for the assistant,
once the owner has installed it. Run each as its own command:
```
claude-docker-openipc check          # Docker up, image, Rosetta, network guard probe (all "ok")
claude-docker-openipc image          # build the image from the root-owned Dockerfile
claude-docker-openipc build [board]  # ssc377_lite (default), ssc377d_lite, ssc377de_lite, ssc377qe_lite
claude-docker-openipc clean          # drop the build tree volume
```
How it differs from `docker-openipc.sh`:
- Only `scripts/build-openipc.sh` goes into the container (plain file, ≤ 64 KiB, read-only). The
  image comes from the kit's Dockerfile, so edits to `docker/Dockerfile` here don't reach it (ask
  the owner to update the kit).
- Results go to `~/Library/Application Support/claude-docker-openipc/out/`, not `./out/`; run
  `scripts/verify-image.sh` on them there. The owner copies images out for flashing.
- Its own volumes (`claude-openipc-work|dl|ccache`), so its first build downloads and compiles
  everything again.
- The container reaches the public internet only: no LAN, no camera, no services on the Mac.
- A first build takes long: run it in the background and read `out/build.log`. Docker Desktop
  must already be running (the owner starts it).

### Camera-specific changes `build-openipc.sh` makes to OpenIPC (2026-10-22)
- **Kernel trim.** The script writes `$WORK/cam-kernel.fragment` and points
  `BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES` at it in the board defconfig of the clone.
  - **Removed:** `KALLSYMS`, `MTD_UBI`, `UBIFS_FS`, `USB_SUPPORT`/`USB` (+ SigmaStar USB PHY),
    `MMC` (+ SigmaStar SD/MMC), `WIRELESS`/`CFG80211`/`RFKILL`, `FAT`/`MSDOS`/`VFAT`. This board
    has no microSD, USB or WiFi, and its NOR flash doesn't use UBI.
  - **Result:** option-A kernel 2,039,172 B → **1,628,780 B**, under the 1,835,008 B budget.
  - **Kept on purpose: `DEBUG_SPINLOCK` / `DEBUG_MUTEXES`.** OpenIPC's prebuilt SigmaStar `mi.ko`
    was built with them. It calls `find_vma`/`do_mmap`/`down_write` and uses wait queues, so it
    reads `mm_struct` and wait-queue layouts inline. Turning lock debugging off would shift
    those layouts under it (checked statically from its imports, 2026-10-22).
  - Changing the list forces `make clean` (ccache-assisted rebuild ≈ 21 min). After the build
    the script warns if anything selected a trimmed option back on.
- **SC4336P `chmap=5`.** OpenIPC's `load_sigmastar` loads `sensor_sc4336p_mipi.ko chmap=1`. The
  script gives sc4336p its own case with `chmap=5` (stock value), marked
  `cam-firmware-dev: chmap=5`, and reinstalls the osdrv package if it's already built.
  - `lane_num` defaults to 2, matching stock.
- **Sensor pinned.** In `load_sigmastar`, `SENSOR=sc4336p` replaces `$(fw_printenv -n sensor)`,
  detection only runs when `SENSOR` is empty, and the `fw_setenv sensor` call is removed
  (marker `cam-firmware-dev: sensor pinned`).
  - Why: OpenIPC's fw_env autosearch (`all-patches/uboot-tools/0011-env-partition-autosearch.patch`)
    only accepts envs of 0x10000, 0x20000 or 0x40000 bytes. Stock's is 0x1000 bytes at
    mtd0+0x3F000. Replaying the search on the stock dumps found no env in mtd0–mtd3, so every
    boot would autodetect and the save would always fail.
  - Pinning removes the runtime detection, and no boot step writes to flash.
  - Other `fw_printenv` reads (profile, hostname, network) return empty. `sysupgrade` and
    `extutils` write only when someone runs them by hand, and with no env found they fail.
  - Stock also passed `sensor_rst_pol=1`; whether OpenIPC's driver accepts it is unchecked.
    Check it at RAM-boot if the sensor doesn't come out of reset.

### Host requirements found in the first builds (2026-10-22)
- **hexdump** (`bsdextrautils` on Ubuntu 24.04). The SigmaStar kernel's `scripts/dtc/dtx_diff`
  needs it. Without it the `uImage` step fails with "dtb … syntax error". Both Dockerfiles must
  include it, and `build-openipc.sh` checks for it first.
- **GNU make ≥ 4.4.** Under make 4.3 in the amd64 container under Rosetta, the parallel build
  stops at busybox's config step with "write jobserver: Bad file descriptor".
  `build-openipc.sh` builds a SHA-256-pinned make 4.4.1 into `$WORK/tools` automatically when
  needed.
- Changing Docker Desktop resources restarts the engine and kills a running build (exit 143).

## Pick the exact SSC377 variant first
SSC377 defconfigs: `ssc377_lite`, `ssc377d_lite`, `ssc377de_lite`, `ssc377qe_lite`.
Confirm your die before building — from the UART boot log (IPL/U-Boot banner) or OpenIPC's
`ipctool`. Start with **`ssc377_lite`** (base I6C) unless the log says DE/QE/D.

## Build
```
git clone --depth=1 https://github.com/OpenIPC/firmware.git
cd firmware
make BOARD=ssc377_lite        # or run `make` for the interactive board menu
```
Outputs land in `output/images/` — a kernel uImage and a `rootfs*.squashfs` for the
board (names are board-suffixed). The `_lite` rootfs is small (fits the 13 MiB mtd2).

## Sensor = SC4336P
The I6C sensor set includes `sensor_sc4336p_mipi` (2560x1440@30, 2-lane, I2C 0x60, ext
ISP). OpenIPC selects/loads the sensor at runtime via its config (majestic + the SigmaStar
sensor module). Ensure the running config targets **sc4336p** (majestic `.isp.sensor` /
the device sensor config), not a default. Confirm at first boot: the sensor ID check reads
reg 0x3107=0x9c / 0x3108=0x42, else init fails.

## Repackage for STOCK U-Boot (keep BOOT, easy recovery)
OpenIPC's own uImage targets OpenIPC U-Boot (load 0x21000000). We keep **stock U-Boot**
(relocates per header to 0x20008000). So:
1. Wrap the OpenIPC kernel to match stock (details + rationale: IMAGE-PACKAGING.md, BOARD.md):
   - **Option A (mirror stock):** XZ (CRC64) of the raw `Image`, header labelled LZMA:
     ```
     xz --check=crc64 --lzma2=preset=9 -c Image > Image.xz
     mkimage -A arm -O linux -T kernel -C lzma -a 0x20008000 -e 0x20008000 \
             -n openipc-i6c -d Image.xz openipc-kernel.bin
     ```
   - **Option B (fallback):** uncompressed self-decompressing `zImage`, `-C none`.
   `scripts/build-openipc.sh` produces both. (The stock payload is XZ despite the LZMA
   label — an LZMA-alone payload, as earlier drafts said, would likely not boot.)
2. Keep the OpenIPC `rootfs.squashfs` as `openipc-rootfs.bin` (must be ≤13 MiB).
3. Verify: `scripts/verify-image.sh openipc-kernel.bin openipc-rootfs.bin` (checks
   load=0x20008000, arch/type, XZ-vs-zImage payload, the **1.75 MiB** kernel budget that
   protects mtd1's trailing blobs, and the 13 MiB rootfs budget).
4. Load the SC4336P module with **`chmap=5`** (stock value; see BOARD.md) — wire this into
   OpenIPC's SigmaStar sensor-load script / majestic config.

## Integration caveat (read before flashing)
Two install models — pick deliberately:
- **Graft onto stock (recommended first):** keep stock U-Boot + stock `mtdparts`
  (`root=/dev/mtdblock2`), replace ONLY mtd1(kernel)+mtd2(rootfs). Lowest risk — U-Boot
  TFTP recovery stays available. BUT OpenIPC's init/overlay must work with the stock
  partition map (kernel mtd1, squashfs-ro rootfs mtd2, data mtd3; no separate overlay
  partition). The `_lite` squashfs + tmpfs overlay generally tolerates this; verify at
  RAM-boot.
- **Full OpenIPC install:** flash OpenIPC's own bootloader + its partition scheme. Cleanest
  OpenIPC experience, but writes BOOT → you lose the keep-stock-U-Boot recovery path, so a
  golden clip backup becomes mandatory.

## Flash + prove (per DELIVERY.md / PLAN gates)
1. **Gate 2 first:** U-Boot `tftpboot 0x22000000 openipc-kernel.bin; bootm 0x22000000`
   (RAM-boot, no write) → confirm **video / IR-night / clean reboot**. A boot ≠ good video.
2. Persist via Method 1 (`flashcp -v ... /dev/mtd1` + `/dev/mtd2` from the root shell) or
   Method 2 (`sf erase`/`sf write`).
3. **Gate 3:** security acceptance test on the isolated link.

## Honest unknowns to resolve at the bench
- Exact SSC377 die (lite/DE/QE/D) → correct defconfig.
- Whether the `_lite` rootfs fits 13 MiB after your config (shrink packages if not).
- Whether OpenIPC init is happy with the stock mtdparts (graft model) or needs the full
  install.
- SC4336P **ISP tuning quality** (B-4) — judge at RAM-boot; the vendor `_SMW sc4336p_a50`
  set is a reference if OpenIPC's default looks poor.

## Sources
- OpenIPC build system: https://github.com/OpenIPC/firmware (README + wiki)
- SigmaStar defconfigs: OpenIPC/firmware `br-ext-chip-sigmastar/configs/` (ssc377_lite…)
- SC4336P I6C driver: OpenIPC/sensors `sigmastar/infinity6c/sensor_sc4336p_mipi.c`
