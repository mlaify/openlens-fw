# openlens-fw — open-source, hardened firmware for the Anpviz IPC-D240W-S (SigmaStar Ifado)

Open-source replacement firmware for Anpviz IPC-D240W-S cameras you own, replacing the stock
("ANJOY888") userland and its published vulnerabilities (24 findings, disclosed through CISA and
CERT/CC in 2026). The camera keeps its stock kernel; our own userland goes into the rootfs
partition (mtd2). Our code is MIT-licensed; the stock binaries it runs on are in `vendor-blobs/`
under their own terms (`THIRD-PARTY-NOTICES.md`).

openlens-fw is not affiliated with or endorsed by Anpviz, Anjoy or SigmaStar. "Anpviz" names the
hardware it runs on.

**User documentation:** [docs.mlaify.io/openlens-fw](https://docs.mlaify.io/openlens-fw/) (source
in [mlaify/docs](https://github.com/mlaify/docs), `content/openlens-fw/`). Security reports:
[`SECURITY.md`](SECURITY.md). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Target (confirmed on the owner's cameras; docs/BOARD.md)
- SoC SigmaStar **Ifado** (`soc0/family` = IFADO, Cortex-A7, GICv2), board type MCA40E. Not
  Infinity6C, and not supported by OpenIPC: its `ssc377` images must never be booted here
  (docs/IFADO-PLATFORM.md).
- IPL → U-Boot → Linux **5.10.117** (stock, kept).
- Sensor SmartSens **SC4336P** (MIPI, `chmap=5`).
- SPI-NOR PUYA **P25Q128** 16 MiB, **3.3 V**; UART `ttyS0 @ 115200`.
- MTD: BOOT 256K / kernel 2M / rootfs (squashfs, ro) ~13M / DATA 1M (jffs2).

## Status
Both of the owner's cameras run this firmware from flash (since 2026-10-24), installed over the
network and updated in place with signed packages. Surveillance Station records them over ONVIF.
- **Video:** H.264/H.265 main and sub streams at 30 fps (sizes configurable).
- **Streaming:** RTSP on 554, RTSPS on 322.
- **Web UI and ONVIF:** HTTPS on 443 with a CA on each camera.
- **Other features:** day/night with IR, OSD, motion, SNTP.
- **SSH:** Dropbear, keys only, post-quantum key exchange.
- **No shared credentials:** each camera is claimed after the flash.
- **Network daemons off root.**

Details and the current release: `docs/RESUME.md` §2. What's next: `docs/RESUME.md` §7.

## Layout
- `AGENTS.md` / `CLAUDE.md` / `docs/RESUME.md` — **start here** (complete handoff for agents and
  new sessions).
- `src/` — our programs:
  - `mi/` (the video pipeline over raw MI ioctls);
  - `rtspd/` (RTSP, day/night, image controls);
  - `camhttpd/` (ONVIF, web UI, snapshots, the claim);
  - `camtls/` (TLS front end);
  - `camcfg/` (settings, users, keys);
  - `ntpc/` (SNTP);
  - `camupdate/` (signed updates).

  See `src/README.md`.
- `rootfs/` — the image's skeleton (inittab, rcS, the `*-run` scripts), applets, the update keys,
  the vendor-file list; `scripts/build-rootfs.sh` assembles it (`rootfs/README.md`).
- `wiki/` — the GitHub wiki's pages, which now only point to the docs site
  (`scripts/publish-wiki.sh` publishes them).
- `docs/PLAN.md` — the original build plan: platform facts, MTD map, U-Boot flow, reusable-blob
  inventory, phased checklist, **acceptance gates (§9)**, and the **SC4336P-IQ risk (§10, B-4)**.
  `docs/GATE3-CRITERIA.md` is the security acceptance.
- `vendor-blobs/` — the stock binaries the firmware runs on (kernel/DTB, U-Boot, `sstar_mi.ko`,
  sensor `.ko`, MI libs, IQ files, NPU model, `loadko`), with `SHA256SUMS`. **Not ours and not
  MIT:** GPL (kernel, U-Boot) or proprietary, see `vendor-blobs/README.md`. The BOOT image's MAC
  address is scrubbed (`scripts/scrub-uboot-env.py`).
- `scripts/` — build, signing, install, bench, flashing/recovery and extraction helpers, incl.
  `extract-kernel-dtb.py` (unpack stock mtd1: kernel Image, DTB→DTS, trailing blobs),
  `ghidra-run.sh` (headless decompile), `cam-claim.py` (the first claim, `--backup`/`--restore`)
  and `cam-recover.py` (unlock a camera whose DATA failed: a signed restore or erase,
  docs/PLAN-DATA-LOCK.md).
- `tools/ghidra/` — Ghidra headless scripts used for the static analysis (see its README).
- `docs/DELIVERY.md` / `docs/IMAGE-PACKAGING.md` — clipless install paths and how to package the
  kernel+rootfs to fit stock mtd1/mtd2 (`bootm by_header`, load 0x20008000). Written for the
  OpenIPC route; the install that shipped is `scripts/cam-first-install.py` (docs/RESUME.md §7).
- `docs/OPENIPC-SUPPORT.md`, `docs/BUILD.md` + `scripts/build-openipc.sh` — the OpenIPC route
  (BOARD=ssc377_lite), abandoned once the SoC turned out to be Ifado, kept for reference. On the
  Mac: `scripts/docker-openipc.sh build` (Docker, amd64 under Rosetta; outputs in `out/`).
- `docs/NETWORK-ONLY-UPDATE.md` — evidence and limits for avoiding UART/clip during development
  on the expendable old camera.
- `docs/ROOT-CONSOLE.md` + `scripts/camera-root-console.py` — temporary, interactive root console
  and cleanup for bench work on a camera still running stock.
- `docs/COPY-FILES-TO-CAMERA.md` + `scripts/camera-copy-text.py` — verified transfer of small text
  files into a stock camera's RAM-backed `/tmp`.
- `docs/SOFTWARE-FULL-CHIP-BACKUP.md` — the read-only, network-only full-chip capture of a stock
  camera (two matching 16 MiB images of cam #1, 2026-10-22); the CH341A golden images came after.
- `docs/BOARD.md` — hardware map: reference board, kernel 5.10.117, XZ kernel payload + 1.75 MiB
  kernel budget, SC4336P wiring (`chmap=5`, I2C1, reset GPIO 76), day/night architecture.
  `scripts/bench-probe.sh` resolves pins on a stock unit.

## Golden rules
1. **Develop on cam #1.** Every update goes to cam #1 first; cam #2 (the camera in use) only
   with the owner's OK for that update.
2. **Recovery before anything:** full-chip CH341A golden image (×2, hashes match), tested
   restore, before any flash write (Gate 1: done 2026-10-24).
3. **Never write mtd0 (U-Boot).** Updates write only mtd2, through `camupdate` with a signed
   package.
4. Keep cameras on an **isolated VLAN** (docs/PLAN-TLS.md A); do security acceptance testing on
   an isolated link.
5. Never commit vendor blobs or flash dumps to git (see `.gitignore`).
