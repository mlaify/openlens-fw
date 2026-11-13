#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build-openipc.sh — build OpenIPC for SSC377/I6C + SC4336P, then repackage for STOCK U-Boot.
# RUN ON LINUX (a Linux VM / Docker) — NOT the macOS sandbox (Buildroot needs Linux).
# Produces: out/openipc-kernel.bin (uImage, load 0x20008000) and out/openipc-rootfs.bin.
set -euo pipefail

BOARD="${BOARD:-ssc377_lite}"       # override: BOARD=ssc377de_lite ./build-openipc.sh
LOAD="0x20008000"                    # stock U-Boot kernel load/entry (NOT OpenIPC's 0x21000000)
WORK="${WORK:-$PWD/openipc-build}"
OUT="${OUT:-$PWD/out}"

case "$(uname -s)" in Linux) ;; *) echo "ERROR: build on Linux (a Linux VM / Docker), not $(uname -s)."; exit 1;; esac
for t in git make mkimage; do command -v "$t" >/dev/null || { echo "ERROR: missing $t (install u-boot-tools + build deps)"; exit 1; }; done
# The SigmaStar kernel's scripts/dtc/dtx_diff uses hexdump to tell a .dtb from source; without it
# the uImage step fails late with "dtb ... syntax error". Debian/Ubuntu: bsdextrautils.
command -v hexdump >/dev/null || { echo "ERROR: missing hexdump (Debian/Ubuntu: apt-get install bsdextrautils)"; exit 1; }

mkdir -p "$OUT"

# GNU make < 4.4 passes its jobserver to sub-makes as inherited file descriptors. In the amd64
# container on the Mac (Rosetta) OpenIPC's parallel build then stops in busybox's config step
# with "write jobserver: Bad file descriptor" (3 of 3 runs, 2026-10-22). make 4.4 uses a named
# pipe instead, so build it once into $WORK/tools when the host's make is older.
MAKE_VER=4.4.1
MAKE_SHA256=dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3
if ! make --version | head -1 | grep -qE 'Make (4\.([4-9]|[1-9][0-9])|[5-9])'; then
  if [ ! -x "$WORK/tools/bin/make" ]; then
    echo ">> host make is older than 4.4; building GNU make $MAKE_VER into $WORK/tools ..."
    mkdir -p "$WORK/tools/src"
    curl -fsSL -o "$WORK/tools/src/make-$MAKE_VER.tar.gz" "https://ftp.gnu.org/gnu/make/make-$MAKE_VER.tar.gz"
    echo "$MAKE_SHA256  $WORK/tools/src/make-$MAKE_VER.tar.gz" | sha256sum -c -
    tar -xzf "$WORK/tools/src/make-$MAKE_VER.tar.gz" -C "$WORK/tools/src"
    (cd "$WORK/tools/src/make-$MAKE_VER" && ./configure --prefix="$WORK/tools" --disable-nls >/dev/null \
      && make -j"$(nproc)" >/dev/null && make install >/dev/null)
  fi
  export PATH="$WORK/tools/bin:$PATH"
fi
echo ">> using $(make --version | head -1)"
if [ ! -d "$WORK/firmware" ]; then
  echo ">> cloning OpenIPC firmware ..."; git clone --depth=1 https://github.com/OpenIPC/firmware.git "$WORK/firmware"
fi
cd "$WORK/firmware"

# Kernel trim for this camera, to fit the 0x1C0000 mtd1 budget (stock config: 2,039,172 B).
# The camera has no microSD, USB or WiFi, and has NOR flash (no UBI). The kernel symbol table
# is dropped. Lock debugging (DEBUG_SPINLOCK/MUTEXES) STAYS: the prebuilt SigmaStar mi.ko was
# built with it and reads mm_struct and wait queues inline, so turning it off would change
# their layout under mi.ko.
# A change to this list forces `make clean`, so the kernel and its modules are rebuilt
# (ccache keeps that quick).
KFRAG="$WORK/cam-kernel.fragment"
cat > "$KFRAG.new" <<'EOF'
# CONFIG_KALLSYMS is not set
# CONFIG_MTD_UBI is not set
# CONFIG_UBIFS_FS is not set
# CONFIG_USB_SUPPORT is not set
# CONFIG_USB is not set
# CONFIG_SSTAR_USB_SUPPORT is not set
# CONFIG_SS_USB2_PHY is not set
# CONFIG_MMC is not set
# CONFIG_MS_SDMMC is not set
# CONFIG_SS_FAST_MMC is not set
# CONFIG_WIRELESS is not set
# CONFIG_CFG80211 is not set
# CONFIG_RFKILL is not set
# CONFIG_FAT_FS is not set
# CONFIG_MSDOS_FS is not set
# CONFIG_VFAT_FS is not set
EOF
if ! cmp -s "$KFRAG.new" "$KFRAG"; then
  if [ -d output/build ]; then
    echo ">> kernel trim changed: make clean so the kernel and its modules rebuild ..."
    make "BOARD=$BOARD" clean
  fi
  mv "$KFRAG.new" "$KFRAG"
else
  rm -f "$KFRAG.new"
fi
# Same lookup as OpenIPC's Makefile. That file is included both as a defconfig and as a makefile.
BOARD_CFG="$(find br-ext-*/configs/*_defconfig | grep -m1 "$BOARD")"
[ -n "$BOARD_CFG" ] || { echo "ERROR: no defconfig for BOARD=$BOARD"; exit 1; }
sed -i '/^BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=/d' "$BOARD_CFG"
echo "BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=\"$KFRAG\"" >> "$BOARD_CFG"

# The SC4336P on this camera needs chmap=5 (the stock driver's value; docs/BOARD.md). OpenIPC's
# load script loads it with chmap=1, which would give no video here, so give sc4336p its own
# case. If either loader patch below applies to an already-built package, it's reinstalled so the
# patched script reaches the rootfs.
LOADER=general/package/sigmastar-osdrv-infinity6c/files/script/load_sigmastar
CHMAP_MARK="cam-firmware-dev: chmap=5"
if [ -f "$LOADER" ] && ! grep -q "$CHMAP_MARK" "$LOADER"; then
  echo ">> patching $LOADER: sc4336p chmap=5 ..."
  python3 - "$LOADER" "$CHMAP_MARK" <<'PY'
import re, sys
path, mark = sys.argv[1], sys.argv[2]
s = open(path).read()
grp = re.search(r'^(\s*)([\w|]*\bsc4336p\b[\w|]*)\)\n', s, re.M)
if not grp:
    sys.exit("load_sigmastar: no case pattern lists sc4336p; update the chmap patch")
ind, names = grp.group(1), [n for n in grp.group(2).split("|") if n != "sc4336p"]
if not names:
    sys.exit("load_sigmastar: sc4336p already has its own case; update the chmap patch")
own = (f"{ind}sc4336p)\n"
       f"{ind}\t# {mark}: stock value for the Anpviz IPC-D240W-S (docs/BOARD.md)\n"
       f"{ind}\tinsmod $MODULE/sensor_sc4336p_mipi.ko chmap=5\n"
       f"{ind}\t;;\n")
open(path, "w").write(s[:grp.start()] + own + f"{ind}{'|'.join(names)})\n" + s[grp.end():])
PY
  grep -q "$CHMAP_MARK" "$LOADER" || { echo "ERROR: chmap patch didn't apply"; exit 1; }
  LOADER_PATCHED=1
fi

# Pin the sensor. This camera only ever has the SC4336P. Upstream reads it with
# `fw_printenv -n sensor`; when that's empty it autodetects (sensor_config.ko + ipcinfo) and saves
# the result with `fw_setenv`. With stock U-Boot there is no environment fw_env can find. Its
# autosearch only takes 0x10000/0x20000/0x40000 envs, and stock's is 0x1000 at mtd0+0x3F000; a
# replay against the 2026-10-22 dumps found nothing. So the save would fail on every boot. Pinning
# removes the runtime detection, the env read, and any automatic env write.
PIN_MARK="cam-firmware-dev: sensor pinned"
if [ -f "$LOADER" ] && ! grep -q "$PIN_MARK" "$LOADER"; then
  echo ">> patching $LOADER: pin sensor to sc4336p, no fw_printenv/fw_setenv ..."
  python3 - "$LOADER" "$PIN_MARK" <<'PY'
import sys
path, mark = sys.argv[1], sys.argv[2]
s = open(path).read()
edits = [
    ("SENSOR=$(fw_printenv -n sensor)\n",
     f"SENSOR=sc4336p  # {mark}: the only sensor on this camera; stock U-Boot has no OpenIPC env\n"),
    ('fw_setenv sensor "$SENSOR"\n', f": # {mark}: no fw_setenv\n"),
    ('if [ -z "$1" ] || [ -z "$SENSOR" ]; then\n', 'if [ -z "$SENSOR" ]; then\n'),
]
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"load_sigmastar: expected exactly one {old.strip()!r}; update the sensor-pin patch")
    s = s.replace(old, new)
open(path, "w").write(s)
PY
  grep -q "$PIN_MARK" "$LOADER" || { echo "ERROR: sensor-pin patch didn't apply"; exit 1; }
  LOADER_PATCHED=1
fi
if [ "${LOADER_PATCHED:-0}" = 1 ] && [ -d output/per-package/sigmastar-osdrv-infinity6c ]; then
  make "BOARD=$BOARD" br-sigmastar-osdrv-infinity6c-reinstall
fi

echo ">> building BOARD=$BOARD (this pulls a toolchain and takes a while) ..."
make "BOARD=$BOARD"

# Report any trim option that something else selected back on.
KCONF="$(ls output/build/linux-*/.config 2>/dev/null | head -1 || true)"
if [ -n "$KCONF" ]; then
  sed -n 's/^# \(CONFIG_[A-Z0-9_]*\) is not set$/\1/p' "$KFRAG" | while read -r opt; do
    grep -q "^$opt=" "$KCONF" && echo ">> WARNING: kernel trim didn't take: $(grep "^$opt=" "$KCONF")"
  done || true
fi

echo ">> locating build outputs ..."
KSRC="$(ls -S output/images/uImage* 2>/dev/null | head -1 || true)"
RSRC="$(ls -S output/images/rootfs*.squashfs* output/images/*rootfs* 2>/dev/null | grep -i squ | head -1 || true)"
ZIMG="$(ls -S output/images/zImage output/build/linux-*/arch/arm/boot/zImage 2>/dev/null | head -1 || true)"
# raw (uncompressed) kernel Image — needed for option A (mirror stock XZ payload)
IMG="$(ls -S output/images/Image output/build/linux-*/arch/arm/boot/Image 2>/dev/null | head -1 || true)"
[ -n "$RSRC" ] || { echo "ERROR: no squashfs rootfs in output/images/ — check the build"; exit 1; }

# Kernel packaging (see docs/IMAGE-PACKAGING.md + BOARD.md):
#  A) mirror stock: XZ(CRC64) of raw Image, header comp labelled lzma  -> openipc-kernel.bin
#  B) fallback:     uncompressed self-decompressing zImage, comp=none -> openipc-kernel-zimage.bin
# RAM-boot both; keep whichever the stock bootloader boots. Each must be <= 0x1C0000 bytes.
built=0
if [ -n "$IMG" ] && command -v xz >/dev/null; then
  echo ">> option A: XZ(raw Image) under lzma label @ $LOAD ..."
  xz --check=crc64 --lzma2=preset=9 -c "$IMG" > "$OUT/Image.xz"
  mkimage -A arm -O linux -T kernel -C lzma -a "$LOAD" -e "$LOAD" -n openipc-i6c -d "$OUT/Image.xz" "$OUT/openipc-kernel.bin"
  built=1
fi
if [ -n "$ZIMG" ]; then
  echo ">> option B: uncompressed zImage @ $LOAD ..."
  mkimage -A arm -O linux -T kernel -C none -a "$LOAD" -e "$LOAD" -n openipc-i6c-z -d "$ZIMG" "$OUT/openipc-kernel-zimage.bin"
  [ "$built" = 1 ] || cp "$OUT/openipc-kernel-zimage.bin" "$OUT/openipc-kernel.bin"
  built=1
fi
if [ "$built" = 1 ]; then :
elif [ -n "$KSRC" ]; then
  echo ">> NOTE: only a prebuilt uImage found; its load addr may be 0x21000000 (OpenIPC U-Boot)."
  echo "   For stock U-Boot, rebuild from zImage with -a $LOAD, or edit the kernel-image config."
  cp "$KSRC" "$OUT/openipc-kernel.bin"
else
  echo "ERROR: no kernel image found in output/images/"; exit 1
fi
cp "$RSRC" "$OUT/openipc-rootfs.bin"

echo ">> outputs:"; ls -la "$OUT"/openipc-*.bin
echo ">> NEXT: copy out/ to the Mac and run  scripts/verify-image.sh out/openipc-kernel.bin out/openipc-rootfs.bin"
echo "        then flash per docs/DELIVERY.md (RAM-boot Gate 2 first)."
