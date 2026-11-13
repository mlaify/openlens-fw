# vendor-blobs/: the stock SigmaStar/Anjoy binaries this firmware runs on

openlens-fw replaces the camera's root filesystem with our own code, but it still runs on parts of
the stock firmware: the boot loader, the kernel, SigmaStar's media (MI) and sensor drivers, and the
ISP tuning files. Those parts are kept here so the firmware can be built, studied and recovered
without each person first dumping their own camera.

**None of these files are ours, and none of them are covered by this repository's MIT license.**
See `../THIRD-PARTY-NOTICES.md` for the license status of each one.

They were extracted from the stock flash of an Anpviz IPC-D240W-S running firmware V3.5.2.1
(SigmaStar Ifado SoC; Anjoy ANJOY888 platform). `SHA256SUMS` lists every file.

| File | What it is | License |
|---|---|---|
| `boot/mtd0-BOOT.bin` | IPL + U-Boot and its saved environment (the 256 KiB BOOT partition). The camera's MAC address in the environment is replaced with `02:00:00:00:00:00` by `scripts/scrub-uboot-env.py` | U-Boot: GPL-2.0-or-later; SigmaStar IPL: proprietary |
| `kernel/mtd1-kernel.bin` | Linux 5.10.117 uImage (Thumb-2, XZ payload, DTB embedded), the 2 MiB kernel partition | GPL-2.0-only |
| `modules/sstar_mi.ko`, `modules/mi_debug.ko` | SigmaStar MI media kernel driver | Proprietary (SigmaStar) |
| `modules/cus_sc4336p_mipi_20251225.ko` | SC4336P sensor driver (load with `chmap=5`) | Proprietary (SigmaStar/Anjoy) |
| `mi-libs/*.so` | SigmaStar MI userland libraries (our firmware doesn't use them; kept for reference) | Proprietary (SigmaStar) |
| `modparam.json` | MI module parameters passed to `sstar_mi.ko` | Proprietary (vendor configuration) |
| `iqfile/` | ISP tuning shipped on the camera (gc4023, imx307, fc105 LUT). There is no SC4336P-specific IQ file: stock uses the imx307 one | Proprietary (SigmaStar/Anjoy) |
| `dla/model/sdy48.img` | NPU model for the stock person detection (unused by our firmware); `dla/ipu_lfw.bin` is empty on the camera | Proprietary (vendor) |
| `scripts/loadko` | The stock module-load order | Vendor script |

## Kernel and U-Boot source

The kernel and U-Boot binaries are GPL. The GPL entitles everyone who receives them to the
corresponding source. Neither Anpviz/Anjoy nor SigmaStar has published the source for these builds,
and we don't have it. What we know of them:
- Linux 5.10.117 with SigmaStar's out-of-tree platform code (`MSTAR_I6C_LINUX_375`);
- U-Boot built with `ifado_nor_defconfig`, environment version strings `MCA40E_*`.

Upstream sources: <https://kernel.org> (5.10.117) and <https://source.denx.de/u-boot/u-boot>.
Anyone who received these binaries from the vendor may request the corresponding source from
Anjoy/Anpviz and from SigmaStar. Replacing both with builds from source is on the roadmap.

## Proprietary files

The proprietary files are redistributed as they were found on the camera, unmodified (except
the MAC address noted above), without any license from their owners, for interoperability with
hardware the user owns. All rights in them belong to their owners. If you are a rights holder
and object, open an issue or use the contact in `../SECURITY.md`.

## Using your own camera's files

Your camera's files should match the hashes in `SHA256SUMS` if it runs the same stock version.
If you extract `mtd0` from your own camera, run `scripts/scrub-uboot-env.py` on it before you
share it.
