<!-- SPDX-License-Identifier: MIT -->
# Contributing

Thank you for your interest in contributing to openlens-fw, hardened replacement firmware for the
Anpviz IPC-D240W-S camera. Bug reports, fixes, tests and documentation are welcome. Progress is
steady but slow, so please be patient with reviews.

By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to Contribute

- **Report a bug:** open an issue with the
  [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
- **Suggest a feature:** open an issue with the
  [feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Say which camera and NVR
  you use; the firmware supports one camera model, and features are judged by what they add to
  the attack surface as much as by what they do.
- **Fix something or improve the docs:** open a pull request. For a larger change, open an issue
  first so we can agree on the approach.
- **Report a security vulnerability:** **don't open a public issue.** Follow
  [SECURITY.md](SECURITY.md).

The user documentation is at [docs.mlaify.io/openlens-fw](https://docs.mlaify.io/openlens-fw/).
Its source is the `content/openlens-fw/` folder of [mlaify/docs](https://github.com/mlaify/docs):
send documentation fixes there.

## Before you post anything

Issues, pull requests, logs and screenshots are public. Remove first:
- MAC addresses, serial numbers and device IDs;
- passwords, recovery codes, private keys and RTSP URLs with credentials (`rtsp://user:pass@...`);
- your public IP address, and anything in a picture you wouldn't show strangers.

Never post flash dumps, `DATA` partition images or backups (`.cambak`): they hold your camera's
MAC, calibration, accounts and keys.

## Pull Request Process

1. Fork the repository and create a topic branch from `main`.
2. Keep each pull request to one purpose.
3. Run the host tests. They run every program's tests under ASan and UBSan on macOS or Linux,
   without a camera, and must end with `0 failed`:

   ```sh
   bash scripts/host-tests.sh
   ```

   They need clang, ffmpeg/ffprobe, libsodium and ssh-keygen, and the mbedTLS source that
   `scripts/build-camtls.sh` unpacks. New code comes with tests.
4. Build for the camera. The ARM build is gcc with `-std=c11` and glibc, which catches things the
   host build doesn't (POSIX functions need `_GNU_SOURCE`):

   ```sh
   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
   ```

   Run `scripts/build-camtls.sh` in `debian:trixie` as well when you change `src/camtls/`. Both
   need your camera subnet (`CAM_NET`); see
   [Building from source](https://docs.mlaify.io/openlens-fw/building-from-source/).
5. If you tried the change on a camera, say how: the firmware version, what you checked, and the
   result. Changes to authentication, listeners, privileges or updates need a test on real
   hardware before they ship.
6. Update the READMEs when a program, script or file changes, and send a docs change to
   [mlaify/docs](https://github.com/mlaify/docs) when users would notice (a setting, a page, a port,
   a build step).
7. Open the pull request against `main`. Describe what changed, why, and how you tested it.
8. Pull requests are squash-merged. Be responsive to review feedback.

## Rules the code follows

These keep the firmware's security properties. A change that breaks one won't be merged.

- **No shared credentials.** Never add a default account, password, key or anything derived from
  one. Release images must pass `scripts/scan-credentials.sh`, which the build runs.
- **Network-facing daemons don't run as root.** rtspd, ntpc, camhttpd's worker and camtls each run
  as their own user. Only camhttpd's monitor holds passwords and runs privileged operations,
  behind grants (`docs/CAMHTTPD-PRIVSEP.md`). A new feature that needs root goes through a monitor
  operation.
- **TLS keys never leave the camera,** and only camtls loads the server key. Don't add TLS code or
  keys to camhttpd or rtspd.
- **camcfg is the only writer** of settings, users and keys in `/mnt/nand/cam`, and the only
  password and key validator. Other programs run it and show its message.
- **Updates write only the `rootfs` partition,** through `camupdate`, with a package signed by
  the owner's key. Never write the `BOOT` partition (U-Boot), and never drive GPIO 30 (the SoC
  core voltage).
- **The repository scans clean** with `gitleaks git` and `gitleaks dir` (CI runs it on every pull
  request).
- **No vulnerability details for the stock firmware.** Weaknesses in the vendor's software go to
  the vendor or a coordinator such as CERT/CC, not into this repository.

## Style

- **C:** C11, compiled with `-Wall -Wextra` and no warnings. Check every return value, keep
  buffers bounded, and match the code around your change.
- **Shell:** POSIX `sh` for scripts that run on the camera (BusyBox); `bash` is fine for build and
  host scripts.
- **Python:** standard library only where possible, Python 3.11 or later.
- **New files** start with an SPDX header: `SPDX-License-Identifier: MIT`.
- **Docs:** short sentences, plain words, and the camera's addresses as `<camera-ip>` or from the
  192.0.2.0/24 documentation range.

## Vendor files

`vendor-blobs/` holds the stock binaries the firmware runs on. They aren't ours and they aren't
MIT-licensed (`vendor-blobs/README.md`). Don't send changes to them, and don't add new vendor
files without opening an issue first.

## Licensing

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), the license of this project's own code. Third-party parts keep their own
licenses (`THIRD-PARTY-NOTICES.md`).
