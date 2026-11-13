# OpenIPC image packaging — fit stock mtd1/mtd2 + satisfy `bootm by_header`

How to build the OpenIPC kernel+rootfs so the **stock U-Boot** boots them unchanged,
so Methods 1/2 (`docs/DELIVERY.md`) have something to flash. Keep stock U-Boot →
keep easy recovery.

## What the stock bootloader expects
Boot flow (U-Boot env):
```
bootcmd_nor = sf probe 0; loados nor 0x23000000 kernel by_header; bootm 0x23000000
bootargs    = console=ttyS0,115200n8r root=/dev/mtdblock2 ro init=/linuxrc
              LX_MEM=0x4000000 mma_heap=...,sz=0x1800000 cma=1M mtdparts=nor0:...
```
- `loados ... kernel by_header` copies the **kernel** partition to RAM 0x23000000 and
  reads the real image size from the **uImage header** (so the partition may hold a
  shorter image + trailing junk — the header carries the length).
- `bootm` then parses the uImage at 0x23000000 and relocates the kernel to its header
  load address.
- `root=/dev/mtdblock2 ro` → rootfs is the **mtd2 (SquashFS, read-only)** partition.

### Exact stock uImage header (match these)
Parsed from `mtd1-kernel.bin`:
| field | value | mkimage flag |
|---|---|---|
| magic | 0x27051956 (legacy uImage) | (mkimage default) |
| arch | ARM | `-A arm` |
| OS | Linux | `-O linux` |
| type | kernel | `-T kernel` |
| compression field | **LZMA (3)** — but see correction below | `-C lzma` |
| **actual payload** | **XZ** (`FD 37 7A 58 5A`, LZMA2, check=CRC64) of the raw `Image` | `xz --check=crc64` |
| **load addr** | **0x20008000** | `-a 0x20008000` |
| **entry point** | **0x20008000** | `-e 0x20008000` |
| data size | ~1.64 MiB | (must stay ≤ **0x1C0000** — see budget) |

DRAM base is 0x20000000 (LX_MEM 64 MiB → 0x20000000–0x24000000); kernel at +0x8000.

> **Correction (2026-10-21, see BOARD.md):** the stock header *labels* the payload LZMA,
> but the bytes are **XZ** — SigmaStar's bootloader registers an XZ decompressor and
> ignores the label. The earlier recipe in this doc (LZMA-alone payload) was wrong and
> would most likely not boot. Mirror stock: XZ payload, header comp field = lzma.

## Partition budget (hard limits)
| part | dev | size | your image must be ≤ |
|---|---|---|---|
| kernel | /dev/mtd1 | 0x200000 | **0x1C0000 = 1.75 MiB** (uImage incl. 64-B header) — the last 256 KiB holds three XZ blobs (blobB is a `SGSI` image, possibly the `PM_RTOS` the IPL loads); never erase mtd1 past 0x1C0000 |
| rootfs | /dev/mtd2 | 0xCB0000 | **13 MiB** (SquashFS) |
| BOOT | /dev/mtd0 | 0x40000 | **do not touch** |
| DATA | /dev/mtd3 | 0x100000 | **preserve** (per-unit MAC/cal) |

If OpenIPC's kernel+rootfs won't fit, options (in order): shrink the OpenIPC rootfs
(drop unused packages) to ≤13 MiB; raise compression; only as a last resort re-layout
`mtdparts` (which means editing U-Boot env in BOOT → you lose the keep-U-Boot recovery
property, so avoid).

## Build steps (OpenIPC/Thingino Buildroot for I6C)
1. **Kernel — option A (mirror stock, try first):** XZ-compress the raw `arch/arm/boot/Image`
   and label it LZMA exactly like stock:
   ```
   xz --check=crc64 --lzma2=preset=9 -c Image > Image.xz
   mkimage -A arm -O linux -T kernel -C lzma -a 0x20008000 -e 0x20008000 \
           -n openipc-i6c -d Image.xz openipc-kernel.bin
   ```
   **Option B (fallback, decompressor-independent):** wrap the self-decompressing `zImage`
   uncompressed — `mkimage … -C none -a 0x20008000 -e 0x20008000 -d zImage …`. The zImage
   decompresses itself, so this avoids depending on the bootloader's XZ path. RAM-boot
   both (DELIVERY.md Method 2) and keep whichever boots. Either must be ≤ 0x1C0000 bytes.
2. **DTB:** the stock board DTB is **built into the kernel Image** (not appended, no .dtb on
   rootfs). The OpenIPC kernel brings its own I6C DTB — make it carry this board's facts
   (BOARD.md: sensor on I2C1, reset GPIO 76, CSI lane maps, emac MII). Reference DTS is
   extracted per BOARD.md "Artifacts".
3. **Rootfs:** build a **SquashFS** image (stock mounts mtd2 as squashfs ro). Keep it
   ≤13 MiB; use xz or gzip squashfs comp. OpenIPC's majestic + overlay model matches the
   read-only-root design.
   ```
   mksquashfs rootfs/ openipc-rootfs.bin -comp xz -noappend -all-root
   ```
4. **Verify before flashing:** `scripts/verify-image.sh openipc-kernel.bin openipc-rootfs.bin`.

## Flash (recap from DELIVERY.md)
- Method 1 (root shell): `flashcp -v openipc-kernel.bin /dev/mtd1` ;
  `flashcp -v openipc-rootfs.bin /dev/mtd2`. (flashcp erases only the blocks the file
  covers, so a kernel ≤ 0x1C0000 leaves the trailing blobs intact; header carries size.)
- Method 2 (U-Boot): `tftpboot 0x22000000 openipc-kernel.bin; sf erase 0x40000 0x1C0000;
  sf write 0x22000000 0x40000 ${filesize}` then rootfs at 0x240000 / 0xCB0000.
  (**Not** `sf erase 0x40000 0x200000` — that wipes the trailing blobs.)
- RAM-boot test first: `tftpboot 0x22000000 openipc-kernel.bin; bootm 0x22000000` (no write).

## Optional — assemble a full 16 MiB image (for clip or region write)
`scripts/assemble-image.sh` builds golden-BOOT + new-kernel@0x40000 + new-rootfs@0x240000
+ preserved-DATA@0xEF0000 into a full-chip image for `flash-restore.sh`/CH341A or
`flash-write-region.sh`.

## Honest caveats
- A valid uImage that boots Linux is NOT proof of working video (sensor/ISP — see B-4).
  RAM-boot (Method 2 test) and check video before persisting.
- If OpenIPC's I6C kernel wants a different load addr than 0x20008000, its own U-Boot
  expects that — but you are keeping STOCK U-Boot, so you must match 0x20008000 here.
- `os` byte / name field in the stock header are non-standard/garbled; U-Boot on these
  boards boots on magic+arch+type+comp+load. Match those five and it works.
