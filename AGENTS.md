# AGENTS.md — openlens-fw (formerly cam-firmware-dev)

Open-source secure firmware for Anpviz IPC-D240W-S cameras, developed on the owner's two. **SoC: SigmaStar Ifado (Cortex-A7, GICv2),
not Infinity6C.** Don't boot the OpenIPC `ssc377_lite` images; see `docs/IFADO-PLATFORM.md`.

**Read first:** `docs/RESUME.md`. It is the complete handoff:
- status: as of 2026-10-26, **both cameras run our release firmware from flash (20261025.2)**:
  - installed over the network (#148), claimed (no shared credentials, #128), verified by the
    owner, and updated in place with signed packages (#104);
  - the web UI is HTTPS through `camtls` with a CA on each camera (#165); ONVIF over HTTPS and
    RTSPS on 322 are on too, but Synology Surveillance Station (SSS) can't use TLS, so it records
    over plain ONVIF/RTSP (80/554);
  - 30 fps with configurable main/sub sizes; both cameras run a 1280x720 sub (#166);
  - merged since, for cam #1 as 20261026.3 (RESUME §7 "Right now"): the settings backup, lock
    mode and signed recovery (#171–#178), the CA download (#183), the camtls relay fix (#192).
    Then the #179 bench.

  **Gate 3 (#38) is mostly done**: review fixes, every network daemon off root, post-quantum SSH,
  gate3-live all PASS. **The upgrade roadmap** (the residuals: TLS, NTP, DATA failing, U-Boot,
  with their state) and the next steps are in RESUME §7;
- hard rules and hardware facts;
- **how to build, sign and install a release** (§6.3, §6.5). The chroot test (§6.4) only
  applies to a camera still on stock;
- **the next order of development** (§7);
- the git workflow. Then `docs/BOARD.md` for hardware detail. The dated history (DEVLOG) and the
copy of the assistant's memory are kept outside the repository, in the owner's notes folder.

## Non-negotiables (full list in RESUME.md §3)
- No flash write without a verified golden CH341A backup and a tested restore (Gate 1: done by
  the owner on 2026-10-24; the golden stays the recovery, and no rollback package is planned).
- Never write mtd0 (U-Boot). Updates write only mtd2 (rootfs), through `camupdate` with a package
  signed by the owner's key, and keep the stock kernel.
- Every build needs a version newer than the installed one: `-e FW_VERSION=YYYYMMDD.N` for
  `build-rootfs.sh` and `-e FWVER=` for `src/build.sh`. The default `<date>.0` repeats within a day.
- Never drive GPIO 30 (SoC core voltage).
- Vendor blobs are tracked in `vendor-blobs/` (owner decision 2026-11-12) with their licenses in
  `vendor-blobs/README.md`; a BOOT image goes in only after `scripts/scrub-uboot-env.py`. Never
  commit flash dumps, DATA partitions, `bench-logs/`, `bench-conf/` or anything with credentials,
  serials or a camera's MAC. The repo must scan clean with `gitleaks git` and `gitleaks dir`.
- Develop on cam #1. cam #2 is the owner's working camera. (Their addresses are in the owner's
  notes, not in the repo: use `<cam1>`/`<cam2>` or the 192.0.2.0/24 documentation range in docs.)
  - Both cameras run our release firmware from flash since 2026-10-24: the owner installed and
    verified them.
  - Try every update and rollback on cam #1 first.
  - Install on cam #2 only when the owner says so for that update.
- Findings in vendor code are unreported vulnerabilities: keep them out of this repo.
- No shared credentials, ever (#128): never add a default account, password, key or derived
  secret. Release images must pass `scripts/scan-credentials.sh`. Bench credentials only go into
  `build-rootfs.sh --bench` images, which are never flashed.
- Daemons that parse the network don't run as root (Gate 3): rtspd (`rtspd`), ntpc (`ntpc`,
  `CAP_SYS_TIME`), camhttpd's worker (`camhttpd`), camtls (`camtls`). Only camhttpd's monitor holds passwords and
  runs privileged operations, behind grants (docs/CAMHTTPD-PRIVSEP.md). Don't move a password,
  HA1 or secret into the worker or rtspd. A new feature that needs root goes through a monitor
  op.
- TLS keys never leave the camera: each camera makes its own CA (name constraints CAM_NET, the
  camera subnet compiled in from `scripts/cam-net.sh`/`src/camnet.h`; no DNS, no IPv6) and its IP-only server certificate on DATA, through `camcfg tls`. Only camtls
  loads the server key; camhttpd and rtspd stay plain behind UNIX sockets and trust the PROXY
  line only from camtls's uid (SO_PEERCRED, `src/rtspd/proxy.h`). Don't add TLS code or keys to
  them.
- camcfg is the only writer of settings, users and keys in `/mnt/nand/cam` and the only
  password/key validator. Other programs exec it and show its message. The one exception is
  camhttpd's own state there (`time-floor`, `epr-secret`; Gate 3), which it writes itself.
- Raw bench/serial logs live in gitignored `bench-logs/`. Summarise hardware facts only, and never
  copy serial numbers, MACs or credentials into the repo.
- Both cameras run our firmware, so the stock root console is gone. Live work goes over SSH with
  the owner's key, from the owner's terminal: the assistant's sandbox can't reach the cameras.
  - Never handle the cameras' passwords or recovery codes.
  - An install, or anything persistent, needs the owner's OK for that action.
  - If the sandbox or a classifier blocks something, stop and hand the command to the owner.

## Workflow
The repository lives on **GitHub** (2026-11-13): the public `mlaify/openlens-fw`, and the owner's
private development copy `mlaify/openlens-fw-dev` (renamed from `mlaify/cam-firmware-dev`), whose
histories are separate; work on whichever the owner names. The user documentation is at
docs.mlaify.io/openlens-fw, source `content/openlens-fw/` in `mlaify/docs`. Open work is tracked as **GitHub issues** (index in RESUME.md §8).
Reference the issue in commits/PRs (`Fixes #N` when done).

Branch **in a worktree** (`.claude/worktrees/<branch>`; the main checkout is the owner's working
tree) → signed commit (`claude-git-sign`) → push → PR (`claude-gh pr create`), all as bare single
commands. If `claude-gh` refuses an issue command, give the owner the `gh` command. **The owner
merges**, as a squash (main allows no merge commits; an agent's `pr merge` is denied as
merge-without-review). Details: `docs/RESUME.md` §10.

**Before you open a PR:**
- Run `bash scripts/host-tests.sh` (every host test under ASan/UBSan; it must say "0 failed"),
  plus `-O2 -Wall -Wextra` with no warnings (RESUME §6.3).
- Remember the ARM build is gcc `-std=c11` with glibc; ask the owner to run `src/build.sh` on the
  branch (and `scripts/build-camtls.sh` in `debian:trixie` when `src/camtls/` changes; the
  host test of camtls needs its `build/mbedtls-src`).
- Write a dated log entry in the PR description (the owner keeps the DEVLOG outside the repo),
  and update the READMEs. A change users see (a
  setting, a page, a port, a build step) also needs a PR to the user docs in `mlaify/docs`
  (`content/openlens-fw/`; no owner addresses, keys or vendor weaknesses there; the owner merges
  and approves the deploy). `wiki/` only holds pages that point to the docs site.
- Put an SPDX MIT header on any new file.
- Bring the branch up to date with main.
- For PRs that build on one another, tell the owner the merge order; after each squash, rebase
  the next branch onto main.

**Live work:**
- **To try a change on a camera:** build a release with a new version, sign it, and install it
  on cam #1 (web UI or SSH, RESUME §6.5). Then cam #2, only with the owner's OK.
- Read live values over SSH: `camcfg ctl get`, `logread`, `camcfg tls show`.
- **Security evidence:** `python3 scripts/gate3-live.py <cam> --admin NAME [--viewer N --operator N
  --camfw PKG... --lockout --skip-nmap]`, run by the owner. A change that touches auth, listeners,
  privileges or updates needs a passing run on cam #1.
- Something only the camera can judge (driver permissions, a privilege drop) ships **off**,
  behind an image file, and is bench-tested by hand on cam #1 first (rootfs/README.md has the
  examples).
- Write sanitized findings into the PR's log entry; raw logs never go in the repo.
- **Backups:** the owner runs `scripts/backup-projects.sh <encrypted drive> <repo> <notes>` after
  milestones.
