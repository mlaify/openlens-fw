# Third-party notices

The source in this repository is ours, under the MIT license (`LICENSE`), unless a file says
otherwise. A built camera image (`scripts/build-rootfs.sh`) also contains the parts below. Anyone
who distributes an image must meet their terms.

| Part | Where it comes from | License | What distributing an image requires |
|---|---|---|---|
| BusyBox | Ubuntu's `busybox-static` (armhf) package | GPL-2.0-only | Offer the exact corresponding source (the Ubuntu source package of that version) |
| GNU C Library (statically linked into our tools) | Ubuntu's cross toolchain | LGPL-2.1-or-later | Let users relink: our source is public under MIT, which covers it. A musl build (#27, MIT) would remove this |
| Dropbear SSH | Built by `scripts/build-dropbear.sh` from Debian's signed source package (`apt-get source dropbear`; the version is in `build/arm/dropbear-VERSION.txt` and BUILD-INFO) | MIT-style (Dropbear's LICENSE; parts public domain, libtomcrypt/libtommath public domain or WTFPL) | Keep its LICENSE text with the image |
| Mbed TLS 3.6 (statically linked into `camtls`) | Built by `scripts/build-camtls.sh` from Debian's signed source package, with our config overlay `src/camtls/mbedtls-user-config.h` (the version is in `build/arm/mbedtls-VERSION.txt` and BUILD-INFO) | Apache-2.0 OR GPL-2.0-or-later (we use it under Apache-2.0) | Keep a copy of the Apache License 2.0 with the image |
| libsodium (statically linked into `camupdate` and `camcfg`) | Ubuntu's `libsodium-dev` (armhf) | ISC | Keep its copyright and license notice |
| Terminus Font, 8×16 glyphs of printable ASCII (compiled into `rtspd` for the OSD) | Ubuntu's `console-setup-linux` package (`Lat15-TerminusBold16.psf.gz`, else the first of `Uni2-TerminusBold16`, `Lat15-Terminus16`, `Uni2-Terminus16`), converted at build time by `scripts/psf2c.sh` into `build/gen/osd_font.h` (never committed). `src/build.sh` stops unless the package's copyright file gives Terminus the SIL Open Font License | SIL OFL 1.1 (© Dimitar Toshkov Zhekov) | Keep the font's copyright notice and the OFL text with the image: `src/build.sh` saves the package's copyright file as `build/arm/osd-font.copyright`. The converted subset is a modified version under the OFL, so it isn't called "Terminus" (its name in the build is "osd 8x16, from Terminus Font") |
| Linux kernel | **Not included in a rootfs image.** The image replaces the root filesystem (mtd2) only; the camera keeps its own kernel. The stock kernel binary is in `vendor-blobs/` (below) | GPL-2.0-only | Nothing for a rootfs image |

License texts: `LICENSES/` (MIT, GPL-2.0, Apache-2.0). The OFL and Dropbear texts come from the
build (above).

## Vendor files in `vendor-blobs/`

This repository carries the stock binaries the firmware runs on (owner decision 2026-11-12),
listed with hashes in `vendor-blobs/SHA256SUMS` and described in `vendor-blobs/README.md`. They are
**not** ours and **not** under the MIT license.

| Part | License | Notes |
|---|---|---|
| Linux 5.10.117 kernel (`vendor-blobs/kernel/`) | GPL-2.0-only (`LICENSES/GPL-2.0.txt`) | Binary as built by the vendor. The vendor has not published the corresponding source and we don't have it; upstream is kernel.org 5.10.117. See vendor-blobs/README.md |
| U-Boot (`vendor-blobs/boot/`) | GPL-2.0-or-later (`LICENSES/GPL-2.0.txt`) | Same: vendor binary, source unpublished; upstream is source.denx.de. The camera's MAC address in its saved environment is replaced with a placeholder |
| SigmaStar IPL (`vendor-blobs/boot/`), MI and sensor drivers (`modules/`), MI libraries (`mi-libs/`), ISP tuning (`iqfile/`), module parameters, NPU model (`dla/`), load script | Proprietary; all rights reserved by SigmaStar / Anjoy / Anpviz | Redistributed unmodified, without a license from their owners, for interoperability with hardware the user owns. Not covered by this repository's MIT license |

`scripts/build-rootfs.sh` copies some of these vendor files into the image
(`rootfs/vendor-files.tsv`): the MI and sensor kernel modules, ISP tuning (IQ) files and encoder
parameters. They keep the status above inside an image too.

## Reverse-engineered interfaces

`src/mi/` drives the SoC's media drivers through ioctl interfaces decoded for interoperability
(docs/IFADO-MI-PIPELINE.md). It is our own code, written from the decoded interfaces. No vendor
code is copied.
