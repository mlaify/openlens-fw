# Building from source

You build every part in Docker containers. The result is one squashfs image for the camera's
`rootfs` partition, which you then sign as an update package.

## What you need

- **Docker.** All build steps run in `ubuntu:24.04` or `debian:trixie` containers and download
  their packages, so the containers need internet access.
- **A clone of the repository.**
- **Files from your own camera.** The image needs a few proprietary vendor files: the SigmaStar
  media and sensor kernel modules, the ISP tuning files and the encoder parameters. Copies are
  in the repository's
  [`vendor-blobs/`](https://github.com/mlaify/openlens-fw/tree/main/vendor-blobs), with their
  licences, for reference. The build still reads them from your own camera's files and checks
  them against known hashes:
  - **The stock root filesystem,** unpacked. It is the squashfs in the `rootfs` partition of your
    flash backup (see [Installing](Installing) for the backup, and
    [`scripts/flash-layout.txt`](https://github.com/mlaify/openlens-fw/blob/main/scripts/flash-layout.txt)
    for the partition offsets). The build copies the files listed in
    [`rootfs/vendor-files.tsv`](https://github.com/mlaify/openlens-fw/blob/main/rootfs/vendor-files.tsv)
    and checks each one's SHA-256. If your stock firmware's files differ, the build stops.
  - **The stock IQ profile** (`bench-logs/iq-profile-stock.bin`, or set `IQ_PROFILE`). It is
    captured from a camera still on stock firmware with
    [`scripts/cam-iq-dump.py`](https://github.com/mlaify/openlens-fw/blob/main/scripts/cam-iq-dump.py),
    which needs root on the stock firmware. Without it the build warns and the picture is flat
    and grey.
  - The stock night-tuning files are read from the same root filesystem, if present. Without
    them the build warns and the "stock night tuning" setting isn't available.
- **Your update key** in `rootfs/update-keys.local` (gitignored). A release build stops without
  one. See
  [Signing and update keys](Signing-and-update-keys).
- **Your camera subnet (CAM_NET).** Steps 2 and 3 stop without it. Write it once to
  `cam-net.local` at the top of your clone (git ignores it), for example
  `echo 192.168.50.0/24 > cam-net.local`, or pass `-e CAM_NET=...` to both `docker run`s. The
  camera's HTTPS certificate authority and its static addresses are limited to it. See
  [HTTPS and the camera CA](HTTPS-and-the-camera-CA).

## Build order

Run these from the top of your clone. Replace `<path-to-stock-rootfs>` with the folder where you
unpacked the stock root filesystem, and `<version>` with the version you want (see below).

### 1. Dropbear (SSH server)

```sh
docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-dropbear.sh
```

It builds Dropbear from Debian's signed source package and writes `build/arm/dropbearmulti`.
The image needs Dropbear 2025.87 or later (post-quantum key exchange). If the container's
version is too old, the script stops; try a newer container such as `debian:testing`.
You only need to run this again to update Dropbear.

### 2. camtls (TLS front end)

```sh
docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-camtls.sh
```

It builds mbedTLS 3.6 from Debian's signed source package, then `build/arm/camtls`. Run it again
after any change to `src/camtls/`. The image build refuses to run without `build/arm/camtls`.

### 3. The camera programs

```sh
docker run --rm -v "$PWD":/src -w /src -e FWVER=<version> ubuntu:24.04 bash src/build.sh
```

It cross-compiles `rtspd`, `camhttpd`, `camcfg`, `ntpc`, `camupdate` and some tools into
`build/arm/`. `FWVER` is only the firmware version the camera reports over ONVIF (default
`dev`). Setting it to the same value as `FW_VERSION` keeps things tidy.

### 4. The image

```sh
docker run --rm -v "$PWD":/src -w /src \
  -v <path-to-stock-rootfs>:/vendor:ro \
  -e FW_VERSION=<version> ubuntu:24.04 bash scripts/build-rootfs.sh
```

This makes a **release image**. It has no accounts, passwords or SSH keys. The build runs
[`scripts/scan-credentials.sh`](https://github.com/mlaify/openlens-fw/blob/main/scripts/scan-credentials.sh)
on the tree and fails if it finds any. It also fails if the image is larger than the `rootfs`
partition (0xCB0000 bytes).

## Release and bench images

- **Release** (the default, no flag): the image you sign and install.
- **`--bench`:** an image for the developers' RAM-only test, which embeds the builder's own
  accounts and keys from a `/secrets` mount. It is marked as a bench image.
  `make-update.sh` refuses to sign it and `camupdate` refuses to install it.
  **Never flash a bench image.**

## Version numbers

- `FW_VERSION` is the image's version, written to `/etc/cam/version`. The format is
  `YYYYMMDD.N`, for example `20261026.0`.
- The default is today's UTC date with `.0`. Two builds on one day get the same default, so set
  it yourself: `.1`, `.2` and so on.
- **A camera only installs a version newer than the one it runs.** You can see the installed
  version on the web UI's Status and System pages, or with `cat /etc/cam/version` over SSH.

## Outputs

All outputs are in `build/`, which git ignores.

| File | What |
|---|---|
| `build/arm/*` | the programs, each with a `.sha256` |
| `build/rootfs/rootfs.sqfs` | the image for the `rootfs` partition |
| `build/rootfs/BUILD-INFO.txt` | the version, `image: release` or `image: BENCH`, the Dropbear and mbedTLS versions packed, and `cam_net:` |
| `build/rootfs/MANIFEST.txt` | the files in the image |
| `build/rootfs/chroot-test.tgz` | our files only; used by the first-install script |

`build/rootfs/` contains vendor files. Don't publish it.

Next: sign the image into a `.camfw` package. See
[Signing and update keys](Signing-and-update-keys).

## Host tests (optional)

The programs have tests that run on a Mac or Linux machine without a camera:

```sh
bash scripts/host-tests.sh
```

They need clang, ffmpeg/ffprobe, libsodium and ssh-keygen, and the mbedTLS source from step 2.
