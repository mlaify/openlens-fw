# RESUME — cam-firmware-dev (start here; complete handoff for any agent or session)

Last updated: **2026-10-26** (both cameras on 20261025.2: HTTPS web UI, 30 fps, a 720p sub-stream;
Gate 3 mostly done; the upgrade roadmap and what's next are in §7).
- **2026-10-25/26:**
  - **TLS (#165, docs/PLAN-TLS.md B and D):** `camtls` (uid 103, mbedTLS 3.6.6) terminates HTTPS
    on 443 for the web UI and RTSPS on 322. Each camera makes its own CA, limited to
    CAM_NET (the camera subnet, a build setting since 2026-11-12), which issues the camera's IP-only certificate and re-issues it when DHCP
    changes the address. Port 80 redirects browsers. On in the image (`/etc/cam/tls.on`).
    Surveillance Station can't do TLS to a generic ONVIF camera, so it stays on plain 80/554
    behind the router isolation.
  - **Streams (#166):** we never set the sensor's frame rate, so it ran at 30 fps while
    everything assumed 25. Now 30 fps by default (1..30) and the main and sub sizes are
    settings. Both cameras: main 2560x1440 at 30 fps and 4000 kbps, sub 1280x720 at 30 fps and
    1500 kbps.
  - **IR nights (#164):** `/dev/irled` never existed on flash; rcS now creates it.
  - **Plan only:** settings backup, a lock page and signed recovery when DATA fails
    (docs/PLAN-DATA-LOCK.md, #167 and this update).
- **Gate 3 (#38), 2026-10-24:** docs/GATE3-CRITERIA.md §7 has the details and the owner's
  decisions.
  - Three code reviews, with every finding fixed.
  - Every network daemon is off root: rtspd 100, ntpc 101 (`CAP_SYS_TIME` only), and camhttpd
    split into a root monitor plus a worker as 102.
  - Post-quantum SSH: Dropbear 2025.89.
  - `scripts/gate3-live.py` passes everything on .6 on both cameras.
- **Both cameras run our firmware from flash (2026-10-24).**
  - Release 20261024.0 was installed over the network with `scripts/cam-first-install.py` (no
    CH341A).
  - The owner claimed both cameras and verified video, IR, SSH, NTP, SSS, the web UI and
    persistence across a power cycle.
- Since then both cameras are updated in place with signed packages, over SSH or from the web UI
  (§6.5).
- **Milestones:** Synology Surveillance Station (SSS) records our streams over ONVIF; the camera
  has its own web UI; and a release image carries **no shared credentials** (each camera is
  claimed, #128).
- **First full night:** cam #2 ran overnight in the RAM chroot with SSS recording, auto day/night
  and motion. It was stable all night: no leak, no SSS drop, no day/night flapping.

Self-contained: everything needed to resume is in this file or linked from it.
- Dated history (newest first): the DEVLOG is kept outside the repository since 2026-11-12, in the
  owner's notes folder (it names the owner's network and cameras). Its history up to then is in
  git (`docs/DEVLOG.md` before the move).
- Hardware evidence: `docs/BOARD.md`.
- The MI layer: `docs/IFADO-MI-PIPELINE.md`.
- Stock behaviour we copied: `docs/STOCK-ENCODE-IMAGE.md`, `docs/STOCK-SNAPSHOT.md`,
  `docs/STOCK-IMAGE-TUNING.md` (anti-flicker, NR, WDR/BLC, the night bin), `docs/STOCK-OSD.md`,
  `docs/STOCK-ONVIF-ORIENTATION.md`, `docs/STOCK-AUDIO.md`.
- First-boot claim and recovery: `docs/CLAIM.md`.
- Per-component detail: `src/README.md`, `src/camhttpd/README.md`, `rootfs/README.md`.

## 1. What this project is
Replace the insecure stock firmware ("ANJOY888", Anpviz/Anjoy) on the owner's **Anpviz
IPC-D240W-S** cameras with our own hardened userland.
- **Route:** the stock kernel (mtd1) and vendor kernel modules stay. A new squashfs rootfs
  replaces mtd2 only.
- **Not OpenIPC:** the SoC is SigmaStar **Ifado** (Cortex-A7, GICv2), which OpenIPC doesn't
  support. Its `ssc377` images must never be booted here.
- **Video:** our own code drives the hardware through raw MI ioctls (`src/mi`). There is no
  vendor userland.
- **First target:** Synology Surveillance Station (SSS) as the NVR.
- **Sibling project:** the owner's research-notes folder (not a git repo, not public) holds the
  flash dumps and the coordinated-disclosure work.
  - Findings F1–F24; CISA Case #116607, CERT/CC VRF #26-10-FZTVG.
  - **Vendor findings never go into this repo.**

**Cameras:**
- **cam #1** = <cam1>, the expendable dev unit. A street light keeps it bright at night.
- **cam #2** = <cam2>, the unit in use. It runs our firmware too. Updates go to cam #1
  first, and to cam #2 only with the owner's OK for that update.
- **NAS** (SSS) = <nas>, on a different subnet, so ONVIF discovery can't reach the cameras:
  add them by IP.
- The owner's Mac is on another subnet.

## 2. Status (2026-10-26)
**Both cameras run release 20261025.2 from mtd2** (TLS, streams, IR fix; §7). The owner
verified everything below on real flash. **Merged since, not yet on a camera:** the settings
backup, lock mode and signed recovery (#171–#178, docs/PLAN-DATA-LOCK.md), the System page's CA
download (#183), and the camtls relay fix (#192). They go to cam #1 together as **20261026.3**
(§7, "Right now"). It was developed in the RAM **chroot test** (§6.4).
- The chroot test and `cam-first-install.py` need the **stock** root console, which a flashed
  camera no longer has. They only matter for a camera that is still on stock.
- Work on a flashed camera goes over SSH (the owner's key, set at the claim). New builds go on
  as signed `camupdate` packages, over SSH or from the web UI's System page (§6.5,
  docs/UPDATE-PATH.md).

| Area | State |
|---|---|
| Video | **H.264 High VBR**, GOP 100, stock's RC tuning. **30 fps** by default (`stream.*.fps` 1..30; the sensor's rate is set with `MI_SNR_SetFps`, #166). Sizes: `stream.main.size` 2560x1440 (default) / 2304x1296 / 1920x1080 / 1280x720, `stream.sub.size` 640x360 (default) / 960x540 / 1280x720; an unset kbps follows the size. **Both cameras run a 1280x720 sub** (1500 kbps). Stock IQ profile + NV12 → "looks like stock" (its "42 set, 5 failed" at start is old and unexplained) |
| RTSP | `rtspd` on **554**, Digest auth, RTP over TCP only (461 for UDP); **RTSPS on 322** through camtls |
| TLS | `camtls` (uid 103, mbedTLS 3.6.6 from Debian, `scripts/build-camtls.sh`): 443 → camhttpd and 322 → rtspd over UNIX sockets with a PROXY line trusted by SO_PEERCRED. TLS 1.2/1.3, ECDHE-ECDSA, ChaCha20-Poly1305 first. A per-camera CA (nameConstraints CAM_NET, no DNS, no IPv6) issues a 397-day IP-only certificate; `camcfg tls init|renew|show`, `/run/camtls/{ready,info,ca.crt}`. The owner trusts each camera's CA on the Mac (docs/PLAN-TLS.md) |
| ONVIF | `camhttpd` on 80 (and 443 over TLS; SSS uses plain 80): Device + Media ver10, WS-UsernameToken + HTTP Digest, roles, WS-Discovery. Independent security review: 12 findings fixed. **SSS adds the camera, applies its encoder settings (rtspd restarts) and plays live view** |
| Snapshot | Hardware JPEG (VENC dev 8, the sub-stream's size, 1 fps) → `/snapshot.jpg` |
| Image controls | brightness/contrast/saturation/sharpness/exposure (0..100, 50 = stock), mirror/flip (sensor), shutter limits, **anti-flicker 50/60 Hz, 2D/3D NR, WDR, BLC** (scaling the tuning profile, #134), all live via `camcfg` and the web UI. **SSS has no image controls for this camera**, so the web UI is the place |
| Night tuning | Stock's night ISP tuning: 21 groups derived at build time from the owner's `gc4023_night.bin` and applied at the day/night switch, with per-mode baselines for the sliders. `image.night_tuning`, **default off**. About 18 live switches overnight on cam #1 with 0 failures; not yet judged by eye on cam #2 |
| OSD | Date/time (on by default, top left) and a title, through MI_RGN (#136); ONVIF OSD operations exist, but SSS doesn't show OSD controls. Font: Terminus 8×16 (OFL), fetched at build |
| Web UI | `/ui/` on **443** (HTTPS; port 80 redirects browsers before any login, #165) (#79): status, image with a live preview, streams, motion & audio, OSD, time (NTP + time zone), users, SSH keys, system. Digest login, CSRF tokens, CSP; one small script `/ui.js` |
| Claim | Release images have no accounts or keys. An unclaimed camera serves only `/setup` for 30 min after power-on, then shows a recovery code once; `/recover` works in the same window (#128, docs/CLAIM.md). Both are HTTPS-only while camtls runs. The bench uses `--bench` images |
| Time zone | `time.tz` (POSIX TZ, presets with automatic DST, e.g. US Central CST/CDT), on the Time page and over ONVIF. Logs stay UTC (#137) |
| Day/night | Auto from the picture's exposure score (night < 15, day > 1500, 5 s, flap hold); IR-cut via `/dev/irled` (rcS creates the node, #164), IR LEDs PWM4 96 %, B/W. **A real night on cam #2 is verified:** it switched at dusk, held a night score of 118–175 and didn't flap. Thresholds are on the web UI |
| Time | `ntpc` SNTP → `time.cloudflare.com` (verified, +0.016 s); SSS can set NTP/time over ONVIF |
| SSH | Dropbear 2025.89 (Debian trixie source), keys only, no forwarding, post-quantum kex mlkem768x25519 (negotiated live) |
| Privileges | rtspd as `rtspd` (100), ntpc as `ntpc` (101, `CAP_SYS_TIME`), camhttpd: root monitor + worker as `camhttpd` (102), camtls as `camtls` (103); group `camctl` (110). Switches: `/etc/cam/rtspd.user`, `/etc/cam/camhttpd.user` (docs/CAMHTTPD-PRIVSEP.md) |
| Config | `/mnt/nand/cam` on DATA (jffs2): `cam.conf`, `users`, SSH keys; `camcfg` CLI |
| Audio | Mic → G.711 µ-law on RTSP track1 (SSS plays it). The two-way code exists (RTSP backchannel → MI_AO, ONVIF AudioOutput), but **the owner says these cameras don't support talk** (verified earlier); don't test it |
| Motion | AE 32×32 grid, background EMA, per-cell noise EMA (wind), mask = SSS area grid (ONVIF Analytics). Works live (cells/seq on walking; `camcfg ctl motion map|luma|noise`). ONVIF Events PullPoint as stock sends them; SSS pulls them but **ignores "by camera" → owner keeps "by SSS" detection** (2026-10-23) |
| Orientation | Mirror/flip on the web UI. SSS's "Video Orientation" panel never calls ONVIF for this camera (vendor database only), so it stays disabled; standard ONVIF Rotate 180 is kept for other clients (#135). A true 90° rotation is #123 |
| rootfs | squashfs-xz ≈ 3 MB of 13 MB mtd2; BusyBox init; listeners 554, 322, 80, 443, 3702/udp, 22 |

## 3. Hard rules (do not break)
1. **Recovery before any flash write:** a full-chip CH341A golden image ×2 with matching
   hashes, plus a tested restore (Gate 1, #33). Done by the owner on 2026-10-24; the golden
   images live on the owner's offline disk, and they stay the recovery (no rollback package).
2. **Never software-write mtd0 (U-Boot).** Only mtd2 (rootfs ≤ 0xCB0000), and mtd1 only if ever
   needed. Keep DATA (mtd3): the vendor's files stay, ours go in `/mnt/nand/cam`.
3. **Never drive GPIO 30** (SoC core voltage). Day/night uses only `/dev/irled` and PWM4.
4. **Never commit vendor blobs, dumps or bench logs.** `bench-logs/` and `build/` are
   gitignored and may hold the serial number, MAC or credentials. Never copy those into
   chat or the repo.
5. **Vendor vulnerabilities stay local** (coordinated disclosure). If analysis finds one, keep
   it out of this repo and note it in the disclosure memory.
6. **Static analysis only on the Mac** (Ghidra headless in the sandbox). Never execute vendor
   binaries on the workstation. Running our own code on the cameras is owner-approved, through
   the bench scripts.
7. **Cameras:**
   - Develop on cam #1. Every update goes to cam #1 first, and to cam #2 only with the owner's
     OK for that update.
   - Both run our firmware, so there is no stock root console any more. Live work goes over SSH
     with the owner's key.
   - Agents never handle the cameras' passwords or recovery codes.
   - The owner runs live commands in their terminal; the assistant's sandbox can't reach the
     cameras.
8. **Denied actions:** if the sandbox, a permission rule or the auto-mode classifier denies
   something, stop. Don't reroute; hand the owner the exact command.
   - Example: an agent's `pr merge` is denied as "merge without review", so the owner merges.
9. Never paste or repeat the owner's passwords. They have pasted RTSP URLs with credentials
   before.

## 4. Hardware facts (confirmed; evidence in BOARD.md)
| Area | Fact |
|---|---|
| SoC / board | SigmaStar **Ifado** (`soc0/family` = IFADO), Cortex-A7 r0p5 1 core, GICv2; DTB `IFADO SSC032B-S01A`. Product type **MCA40E** (stock id 0x730) |
| Kernel | Linux 5.10.117, Thumb-2, built-in IRLED driver (a bare char major in `/proc/devices`, no sysfs, so rcS mknods `/dev/irled`, minor 0); vendor modules loaded by our rcS like stock `loadko` |
| Flash / MTD | PUYA P25Q128 16 MiB 3.3 V; BOOT 0x40000 · kernel 0x200000 · rootfs 0xCB0000 · DATA 0x100000 (jffs2) |
| Sensor | SmartSens SC4336P 2560×1440, MIPI 2-lane, `chmap=5` |
| Day/night | `/dev/irled`: **write 1 = day (IR-cut in), 0 = night**. Its read status is **not a light reading on MCA40E** (it reads 0). The kernel drives the IR-cut pins (GPIO 11/80) |
| LEDs | IR LEDs = **PWM4** (`/sys/class/pwm/pwmchip4/pwm0`), 20 kHz, stock night duty 48000/50000; white LED = PWM0 |
| Never | **GPIO 30** = core voltage |
| eth0 MAC | from U-Boot env `ethaddr` (mtd0 +0x3F000), set by our rcS |
| Stock at night | IR on, 50 ms shutter, sensor gain 4.2×, mean Y 36 (cam #2 night watch) |

## 5. Architecture
```
 sensor -> VIF -> ISP (stock IQ profile, our AE/AWB) -> SCL port0 -> VENC 0/0 H.264 main (HW_RING)
                                                    \-> SCL port1 -> VENC 0/1 H.264 sub
                                                                  \-> VENC 8/3 JPEG 1 fps (snapshot)
 rtspd  (owns the hardware; RTSP 554; day/night; image controls; control socket /run/camd.sock)
   ^ control socket: get / set image.* / set daynight.* / snapshot / restart / auth-reload
 camhttpd (80/tcp ONVIF + /snapshot.jpg + web UI, 3702/udp WS-Discovery)  -> camcfg (writes cam.conf)
 camtls (443 -> camhttpd, 322 -> rtspd; UNIX sockets /run/camhttpd/tls.sock, /run/rtspd/tls.sock)
 sshd-run (Dropbear 22, keys only)     ntpc (SNTP client)     camcfg (CLI for config + users)
 config: /mnt/nand/cam/{cam.conf, users, ssh/}   runtime: /run/cam/{rtspd.htdigest, snapshot.jpg}
```
| Binary (static ARMv7) | Source | Started by |
|---|---|---|
| `rtspd` | `src/rtspd` + `src/mi` | inittab → `rtspd-run` (respawn) |
| `camhttpd` | `src/camhttpd` | `camhttpd-run` |
| `ntpc` | `src/ntpc` | `ntpc-run` |
| `camtls` | `src/camtls` + Debian's mbedTLS 3.6, via `scripts/build-camtls.sh` | `camtls-run` (only with `/etc/cam/tls.on`) |
| `camcfg` | `src/camcfg` | CLI; camhttpd execs it |
| `dropbearmulti` | Debian source (2025.87+, post-quantum kex) via `scripts/build-dropbear.sh` | `sshd-run` |
| BusyBox | Ubuntu `busybox-static` armhf | init |

**`cam.conf` keys** (`camcfg set KEY VALUE`; details in the READMEs):
- `image.brightness|contrast|saturation|sharpness|exposure`: 0..100, 50 = stock. Live.
- `stream.main|sub.codec|kbps|fps|gop|rc|profile|size`, `stream.sub.enabled`: applied with
  `camcfg ctl restart`. fps 1..30 (default 30; the sub runs at most at the main's fps).
- `net.plain`: 1 (default) keeps plain ONVIF and snapshots on port 80, which SSS needs; 0 closes
  them.
- `snapshot.quality`, `snapshot.enabled`.
- `daynight.mode` (auto|day|night), `irled`, `source` (image|sensor), `night_below`,
  `day_above`, `invert`. Live.
- `time.ntp`: up to 3 servers; default time.cloudflare.com; empty = off.
- `time.tz`: a POSIX TZ string (default `UTC0`; presets in the web UI). Live.
- `image.mirror|flip`, `image.shutter_day_max|shutter_night_max` (µs, 0 = auto),
  `image.antiflicker`, `image.mains_hz`, `image.nr2d|nr3d|wdr|blc` (0..255),
  `image.night_tuning` (0/1, default 0). Live.
- `osd.time.*`, `osd.title.*`, `osd.size`, `osd.style`. Live.
- `motion.enabled|sensitivity|mask`, `audio.enabled|gain`.
- Recovery code hash: `/mnt/nand/cam/recovery`, written by camcfg only (#128).

**Users:** `camcfg user add|passwd|role|del|list` (roles admin/operator/viewer; the password is
read from stdin). rtspd's Digest file is derived from them, and both RTSP and ONVIF use the same
accounts.

## 6. Reproduce the setup (owner's Mac terminal; Docker Desktop running)
### 6.1 One-time bench secrets: `~/.config/cam-firmware-dev/` (never committed)
**Release images carry no credentials (#128, docs/CLAIM.md):** each camera is claimed at
`http://<camera>/setup` in the 30 minutes after power-on, or with `python3 scripts/cam-claim.py
HOST`, which saves its recovery code as `recovery-<HOST>.txt` here. The files below go only into
**bench** images (`build-rootfs.sh --bench`) for the RAM chroot test; make-update.sh and camupdate
refuse a bench image.
- **`users.seed` and `rtspd.htdigest`:** `python3 scripts/rtsp-passwd.py admin --role admin`
  (prompts for a password: camcfg's rules, 8–64 printable ASCII, never shortened).
- **`authorized_keys`:** your SSH public key or keys, one per line. The owner uses
  `~/.ssh/<your-camera-key>.pub`.
- **`root.hash`** (optional, bench only): a crypt hash that enables a serial root login. Without
  it, root has no password.

### 6.2 One-time inputs
- **Stock rootfs dump** at `<path-to-stock-rootfs>` (unpacked from your own flash backup).
  `rootfs/vendor-files.tsv` lists the vendor files copied from it, with SHA-256s.
- **Stock IQ profile** at `bench-logs/iq-profile-stock.bin`:
  - capture it with `scripts/cam-iq-dump.py` on a camera running stock firmware;
  - then `cp bench-logs/iq-run-*/iq-stock.bin bench-logs/iq-profile-stock.bin`.
- **Dropbear:**
  `docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-dropbear.sh`
  (it fails on a missing Terrapin fix or a bad option name).
- **camtls (mbedTLS):**
  `docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-camtls.sh`
  (writes `build/arm/camtls`, `build/mbedtls-src` for the host tests). `build-rootfs.sh` refuses
  to build without it. Rebuild it after a change to `src/camtls/`.

### 6.3 Build
```
cd openlens-fw && git switch main && git pull     # CAM_NET in cam-net.local (scripts/cam-net.sh)
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
# the bench image for the chroot test (§6.4): the builder's accounts and keys, never flashed
docker run --rm -v "$PWD":/src -w /src \
  -v <path-to-stock-rootfs>:/vendor:ro \
  -v "$HOME/.config/cam-firmware-dev":/secrets:ro ubuntu:24.04 bash scripts/build-rootfs.sh --bench
```
**`--bench` is new (#128):** without it the build makes a release image (no `/secrets` mount
needed; it is ignored if present), with no accounts or keys, checked by
`scripts/scan-credentials.sh`; that is the image for `make-update.sh` and a flash. A release image
in the chroot test comes up unclaimed: claim it at `http://<camera>/setup` within 30 minutes of
the camera's last boot (the window counts from the stock kernel's boot).
**Outputs:**
- `build/arm/*` (+ `.sha256`);
- `build/rootfs/rootfs.sqfs` (the mtd2 image);
- `build/rootfs/chroot-test.tgz`;
- `MANIFEST.txt`, `BUILD-INFO.txt` (`image: release` or `image: BENCH`).

**Host tests** (no camera): see `src/README.md` (test_rtspd, test_camcfg), `src/camhttpd/README.md`
(test_camhttpd) and `src/ntpc/test_ntpc.c`. All run under `-fsanitize=address,undefined` with
clang. Use `$TMPDIR` for temporary files. Also `bash src/camupdate/test.sh` (signed updates, bench
refusal), `bash scripts/test-scan-credentials.sh` (the release scan) and
`python3 scripts/test_cam_claim.py` (cam-claim.py's helpers).

### 6.4 Live test on a stock camera: the chroot test (RAM only)
**Neither camera is on stock any more**, so this section only applies to a camera that is.
Run it with the **bench** build from §6.3 (`build-rootfs.sh --bench`), so the chroot has your
accounts and SSH key at once. With a release build it comes up unclaimed (#128): rtspd and SSH
wait, ONVIF refuses, and `/setup` is open until 30 minutes after the camera's last boot.
```
python3 scripts/camera-root-console.py open --host <cam2> --user WEBUSER --keep-open
python3 scripts/cam-chroot-test.py --host <cam2> --minutes 30   # options: --daynight-check --image-check --no-reboot
# per-camera settings that survive from run to run (gitignored): --conf bench-conf/cam2.conf
# (key=value lines, each set with camcfg before rtspd starts); --overnight for tuning runs
# cam #1: daynight.mode=day, image.exposure_night=30, time.tz; cam #2: image.exposure_night=85,
# image.night_tuning=1, time.tz (2026-10-24, DEVLOG)
```
**What it does:**
- Uploads `chroot-test.tgz`, about 30 s with the streamed upload.
- Stops the vendor userland, and BusyBox feeds the watchdog.
- Bind-mounts `/config /dev /proc /sys`.
- Runs cam-config on a tmpfs stand-in for DATA.
- Respawns `rtspd-run`, `sshd-run` and `camhttpd-run` the way init would.
- Takes a snapshot and restart-tests rtspd.
- Polls NTP once.
- Samples the logs every 60 s.
- Saves everything to `bench-logs/chroot-run-*/` (`session.txt`, `logread.txt`,
  `snapshot.jpg`), then reboots back to stock.

The root console closes at that reboot, so `open` it again before every run.

**While it runs:**
- **Play the streams:**
  `ffplay -rtsp_transport tcp rtsp://USER:PASS@<cam2>/` (and `/sub`).
- **Snapshot:**
  `curl --digest -u USER:PASS -o snap.jpg http://<cam2>/snapshot.jpg`.
- **SSH:** the chroot gets a new host key every run, so clear the old one first.
  ```
  ssh-keygen -R <cam2> -f ~/.ssh/known_hosts_cam
  ssh -o IdentitiesOnly=yes -o IdentityAgent=none -i ~/.ssh/<your-camera-key> -o UserKnownHostsFile=~/.ssh/known_hosts_cam root@<cam2>
  ```
- **On the camera:**
  - `camcfg ctl get` shows the live image and day/night values (including `daynight.score`);
  - `logread | grep -E 'camhttpd|rtspd|daynight'`;
  - `echo -v > /etc/cam/camhttpd.args; killall camhttpd` turns on ONVIF call logging.
- **Surveillance Station:**
  - Add a camera: brand ONVIF, IP `<cam2>`, port 80, a camera user. Search won't find it
    across subnets.
  - SSS applies its encoder settings, rtspd restarts once (about 3 s), then live view plays.
  - If the test reboots the camera, SSS shows "Updates are required". After the next run, reload
    the camera's capacity in SSS.
- **Day/night test:**
  - cover the whole camera loosely (a box or towel);
  - it switches to night after 5 s and back 5 s after you uncover it;
  - 3 switches in 10 min hold the state for 10 min, and
    `camcfg set daynight.mode day; camcfg unset daynight.mode` clears that.

**Other bench tools:**
- `scripts/cam-night-watch.py`: stock's exposure and IR state, read-only.
- `scripts/cam-ro-probe.py` with `scripts/probes/*.txt` (`CAM_HOST=` picks the camera).
- `scripts/cam-iq-dump.py`, `scripts/cam-run-rtspd.py` (port 8554, next to the vendor
  userland).

### 6.5 Release and update a flashed camera (both cameras since 2026-10-24)
1. **Version:** every build needs one newer than the installed version (System page, or
   `/etc/cam/version`): `YYYYMMDD.N`. The default is `<UTC date>.0`, which repeats within a day,
   so set it:
   ```
   docker run --rm -v "$PWD":/src -w /src -e FWVER=20261026.0 ubuntu:24.04 bash src/build.sh
   docker run --rm -v "$PWD":/src -w /src \
     -v <path-to-stock-rootfs>:/vendor:ro \
     -e FW_VERSION=20261026.0 ubuntu:24.04 bash scripts/build-rootfs.sh
   ```
   This is a release build: no `--bench`, and `BUILD-INFO.txt` says `image: release`.
   - **Dropbear isn't rebuilt here:** `build-rootfs.sh` packs `build/arm/dropbearmulti`
     (checked against its `.sha256`). Rebuild it only to update Dropbear, with
     `scripts/build-dropbear.sh` in `debian:trixie` (§6.2). The `dropbear:` line in
     `build/rootfs/BUILD-INFO.txt` shows what a build packed (2025.89 since 2026-10-24).
   - **camtls isn't rebuilt here either:** run `scripts/build-camtls.sh` (§6.2) when
     `src/camtls/` changes. BUILD-INFO's `mbedtls:` line shows what was packed.
2. **Sign** (YubiKey PIN and touch): `scripts/make-update.sh ~/.ssh/<your-key>` writes
   `build/update/<version>.camfw`. It refuses a bench image.
3. **Install on cam #1:**
   - **Web UI:** System, then Firmware update. Upload, check the verdict (version, device,
     signer, size), tick the box, Install. The page refuses downgrade packages.
   - **SSH:** `ssh root@<cam1> camupdate --check < build/update/<v>.camfw`, then the same
     without `--check`.
   - The camera reboots in about 1–2 minutes. Settings, users and keys are kept.
4. **Then cam #2,** with the owner's OK.
5. **A camera's first start with TLS** makes its CA and certificate. Trust the CA on the Mac once:
   download it from the System page (#183, from the next image on) or
   `ssh root@<camera> cat /run/camtls/ca.crt`, check the fingerprint against `camcfg tls show`
   and the name constraints, add it to Keychain Access and set "Always Trust" for SSL.

## 7. Where we are, the upgrade roadmap, and what's next
**Done (details in DEVLOG):**
- Exposure tuning (#143/#144): ISP gain 4x day / 2x night, `image.exposure_night`, `ae.*` in `get`.
  cam #2 runs `image.night_tuning 1` (the owner's pick, 2026-10-24).
- The first real flash of both cameras (2026-10-24, `scripts/cam-first-install.py`, Gate 1 by the
  owner), then signed updates over SSH and from the web UI (#104). No rollback-to-stock package
  (the owner's decision): the CH341A golden stays the recovery. Packages signed to allow a
  downgrade are refused by the web UI; SSH still installs them.
- Gate 3 (#38) hardening: review fixes (#154), post-quantum SSH and rtspd/ntpc off root
  (#155–#157), camhttpd's monitor/worker split (#158/#159), gate3-live all PASS.
- IR nights (#164), TLS (#165), streams at 30 fps with configurable sizes (#166). Both cameras
  run 20261025.2.

**The upgrade roadmap: the Gate 3 residuals and their state** (docs/GATE3-CRITERIA.md §7):

| Residual | Options | State |
|---|---|---|
| **No TLS** (docs/PLAN-TLS.md) | A: router isolation of the camera VLAN (NAS → 80/554; admin Mac → 22/80/443; cameras → DNS and NTP only). B: HTTPS for the web UI. C: UI only through `ssh -L`. D: ONVIF over HTTPS and RTSPS | **A:** the owner's router job, still to do. **B: done and on** (#165). **D: built and on** (443/322), but SSS can't use TLS for a generic ONVIF camera, so SSS stays on plain 80/554 behind A. C not chosen |
| **NTP on the path** | A: NAS as time source plus the VLAN isolation. B: Roughtime bounds (Ed25519, libsodium). C: NTS (RFC 8915, TLS 1.3 + AES-SIV) | **A accepted** (segmented VLAN; ntpc already refuses pre-build times and holds steps over 1000 s). C optional later, reusing camtls's mbedTLS; B if C is too heavy |
| **DATA failing to mount** (docs/PLAN-DATA-LOCK.md) | An encrypted settings backup (also offered at the claim); a lock page when DATA fails or loses the users file; recovery signed with the image's update keys, on the page or the command line | **Built and merged 2026-10-26** (#171–#178, host-tested); the bench test #179 on cam #1 is left. Owner decisions 2026-10-26 in the plan. Open: whether lock mode also stops rtspd and WS-Discovery; System-page backups HTTPS-only; the 48 KiB cap on a restore from the web |
| **Stock U-Boot** | A: physical protection. B: quiet U-Boot (an mtd0 write, CH341A only). C: our own verifying U-Boot. D: C plus the flash's boot-region lock (irreversible). E: SoC secure boot (eFuses) | **A accepted** (mount out of reach, tamper seals). E: optional static look at whether the IPL checks a signature, before ever considering D. B, C, D not pursued |

**Right now (evening 2026-10-26):**
- **camtls relay fix (#192, merged):** the openviz RTSPS probe got no frames on either camera.
  camtls stopped a pass after 16 rounds holding a chunk from rtspd and then waited for the
  client's next packet (64 KB per RTCP report), and a reused connection slot sent the next client
  up to 4 KiB left over from the previous one, before any login. Both fixed with tests (DEVLOG).
  20261026.1 and .2 were built **without** it: `build/arm/camtls` is rebuilt only by
  `scripts/build-camtls.sh` (§6.5).
- **The owner's steps for 20261026.3** (given 2026-10-26): `git pull`; `build-camtls.sh` in
  `debian:trixie`; `build-rootfs.sh` with `-e FW_VERSION=20261026.3`; `make-update.sh`; the CH341A
  copy (`scripts/flash-backup.sh cam1-pre-20261026.3`) and `cat /dev/mtd3` into `bench-logs/`;
  `camupdate --check`, then install, on cam #1; then
  `cat /etc/cam/version; ls -l /mnt/nand/cam/claimed; pidof camtls; logread | grep -E "camtls|data-check|locked"`.
- **Then:** the openviz probe on cam #1 only, main and sub, with no client traffic after PLAY (a
  steady stream expected), and once right after a streamed session (no stray first byte). Then
  the #179 bench on the same image. cam #2 stays on 20261025.2 until the owner's OK.

**Suggested order (owner to confirm):**
1. The owner's router rules (TLS A) and the NAS as NTP server (NTP A): no firmware change.
2. The remaining Gate 3 tests: the full nmap scan from a wired machine, WS-Discovery from a host
   in CAM_NET, network fuzzing, slowloris, a 24 h soak.
3. **Network config (#80)** in the web UI.
4. Small follow-ups: camhttpd should use the shared `src/rtspd/proxy.h` parser; find out why 5
   of the IQ profile's 42 groups fail at every start (errno 22/29, old); try the 2304x1296 and
   1920x1080 main sizes live.
5. When the owner schedules them: the DATA-lock plan (backup first, it's useful alone), then NTS.
6. Later: a true 90° rotation (#123), RTP over UDP, musl/minimal BusyBox (#27), and whether
   camhttpd should ignore SSS's encoder push (it set 10 fps / GOP 10 once).

## 8. Issues (GitHub: `mlaify/openlens-fw`; anything opened on the owner's mirror 2026-11-03..11-12 stays there)
| # | Item | State |
|---|---|---|
| #29 | RTSP streamer | Done: H.264 main/sub, Digest, 554, leak-tested; overnight stable |
| #30 | Day/night | Done: a real night verified on cam #2; thresholds in the UI |
| #31 | Hardened rootfs (mtd2) | Done: on both cameras from flash since 2026-10-24 (now 20261025.2) |
| #36 | IQ fine-tuning vs stock | Mostly done: #133/#134 parity, night tuning #141, exposure tuning #143/#144; 5 IQ groups fail at every start (unexplained) |
| #72 | Config + users on DATA | Done (`camcfg`, cam-config) |
| #73 | User image controls | Done (web UI; SSS has no image controls) |
| #74 | ONVIF Profile S | Done: SSS records |
| #75 | JPEG snapshot | Done |
| #76 | SSH | Done (keys only; keys added at claim or in the web UI) |
| #77 | Motion + ONVIF Events | Done (camera-side works; SSS uses its own detection) |
| #78 | Time / NTP | Done (ntpc; time zone #137) |
| #79 | Web UI | Done (#129–#132 and follow-ups) |
| #80 | Network config | Part 1 built (2026-10-28, PR net-config): `camcfg net`, boot-time `net-up` (ARP checks, DHCP fallback, 10-minute confirm), ONVIF reports static. Part 2: the web UI's Network page. Bench on cam #1 left |
| #104 | Signed updates | Done: camupdate over SSH and from the web UI, verified on cam #1 (20261024.1, .2) |
| #117 | Two-way audio | Code done; the owner says these cameras don't support talk |
| #123 | 90° rotation | Open (mirror/flip done) |
| #128 | No shared credentials / claim | Done (#140) |
| #183 | CA download on the System page | Merged (#187); bench on cam #1 with 20261026.3 left |
| #27 | musl toolchain + minimal BusyBox | Later |
| #33 / #39 | Gate 1 / flash | Done 2026-10-24 (Gate 1 by the owner; flash with cam-first-install.py) |
| #38 | Gate 3 (security acceptance) | Mostly done (§7; GATE3-CRITERIA §7): TLS B and D done (#165); live tests left |
| #180 | DATA lock, settings backup, signed recovery (tracking) | Built, host-tested and merged (2026-10-26): #171 (#186), #172/#173, #174/#178 and #175/#176/#177 (all through #191: lock page, `camcfg unlock`, `cam-recover.py`). Next: #179 bench test on cam #1 (Argon2id timing, browser download/restore, Digest re-POST of the claim's form, cam #2 refusal, lock mode, signed restore and erase, lock-mode SSH) |

## 9. Repo map (main paths)
| Path | What |
|---|---|
| `src/mi/` | MI pipeline over raw ioctls, 3A, IQ profile, image controls, night mode, JPEG channel |
| `src/rtspd/` | RTSP server, Digest (`auth.c`), day/night (`daynight.c`), control socket, host test |
| `src/camhttpd/` | ONVIF + snapshot + WS-Discovery; host test; README (operations, auth, SSS notes) |
| `src/camcfg/`, `src/ntpc/` | config/user CLI (incl. `camcfg tls`); SNTP client (+ host test) |
| `src/camtls/` | the TLS front end (443, 322), its helpers `gen-ca|issue|check`, our mbedTLS config overlay, host test |
| `src/rtspd/proxy.h`, `src/rtspd/streamcfg.h` | the strict PROXY-line parser; the stream sizes and fps rules shared by rtspd, camcfg and camhttpd |
| `src/build.sh` | cross-builds all binaries in Docker → `build/arm/` |
| `rootfs/` | `skel/` (inittab, rcS, cam-config, *-run scripts), `applets.txt`, `vendor-files.tsv`, `dropbear/localoptions.h`, README |
| `scripts/build-rootfs.sh`, `build-dropbear.sh`, `build-camtls.sh` | image assembly; Dropbear build; mbedTLS + camtls build |
| `scripts/cam-chroot-test.py` | the live test (§6.4; `--overnight` for tuning runs); helpers in `cam-run-mi-probe.py` (upload, stop_vendor) |
| `scripts/iq-bin2profile.py` | build step: derives the night-tuning groups from the owner's stock day/night bins (pinned hashes) |
| `scripts/psf2c.sh` | build step: the OSD font from Ubuntu's console-setup-linux |
| `scripts/camera-root-console.py` | owner opens/closes the stock root console (telnet) |
| `scripts/rtsp-passwd.py` | creates the bench `users.seed` / `rtspd.htdigest` (camcfg's password rules) |
| `scripts/cam-first-install.py` | first install on a **stock** camera over the network: root console, RAM chroot, signed camupdate (#148) |
| `scripts/make-update.sh` | signs `build/rootfs/rootfs.sqfs` into `build/update/<version>.camfw` (YubiKey) |
| `scripts/backup-projects.sh` | the owner's backup: one verified `.tar.zst` of both project folders, with git bundles and a SHA-256 manifest (not encrypted; it goes on encrypted drives) |
| `scripts/cam-claim.py` | claims a flashed camera over HTTPS (`--pin` the CA fingerprint, `--http` without TLS): first admin, SSH key, recovery code saved locally (#128) |
| `scripts/scan-credentials.sh` | fails a release image that carries credential material (#128) |
| `scripts/host-tests.sh` | every host test under ASan/UBSan (Gate 3 §3); run it before every PR |
| `scripts/gate3-live.py` | Gate 3 live evidence against a camera (`--skip-nmap`, `--only ssh,nmap,rtsp,onvif,wsd,camupdate,lockout,tls`, `--lockout`); `bench-logs/gate3-<date>/<host>/<run>/` |
| `src/rtspd/drop.h` | leaving root (own passwd/group read, capset), used by rtspd, ntpc and camhttpd |
| `tools/` | `mi-probe`, `iq-dump`, `ae-watch`, `ghidra/` headless scripts (incl. `DisassembleAt.java`) |
| `docs/` | this file, ROADMAP, BOARD, IFADO-*, STOCK-*, PLAN, PLAN-TLS, PLAN-DATA-LOCK, GATE3-CRITERIA |
| `vendor-blobs/`, `scripts/scrub-uboot-env.py` | the stock binaries (tracked since 2026-11-12, licenses in `vendor-blobs/README.md`); the MAC scrubber for a BOOT image |
| `wiki/`, `scripts/publish-wiki.sh` | the user-facing wiki's source (the GitHub wiki; reviewed in PRs); the owner publishes it with the script |
| `SECURITY.md`, `.github/ISSUE_TEMPLATE/` | how to report vulnerabilities privately; the bug report template |

## 10. Environment and git workflow
- **Mac:** Apple Silicon.
  - Docker Desktop (the owner starts it).
  - Ghidra `analyzeHeadless`, wrapped by `scripts/ghidra-run.sh`.
  - Host builds: clang. macOS lacks `SOCK_CLOEXEC`, so test code avoids it.
- **The assistant's sandbox:**
  - It can't reach the cameras, local ports or the Docker socket, and it can't bind unix
    sockets; host tests skip those parts.
  - The owner runs Docker and the bench scripts.
  - Use `$TMPDIR` (not `/tmp`). zsh `noclobber` blocks `>` onto existing files: use `>|` or
    Python.
- **Git:**
  - **Forge (since 2026-11-12):** GitHub, private `mlaify/openlens-fw` (renamed from
    `mlaify/cam-firmware-dev`), for code, PRs, issues and the wiki. The owner's other remote is
    a mirror. A public copy is planned as a
    fresh single-commit repository, so this history stays private.
  - **Signing:** commits are signed with `claude-git-sign`; the owner touches the YubiKey on
    commit, push and fetch.
  - **Single commands only:** `claude-git-sign` and `claude-gh` must be bare commands — no
    pipes, redirects, `&&` or `>/dev/null`. `cd` separately first.
  - **The main checkout is the owner's working tree too:** they pull, build and run scripts
    from it. Do branch work in a worktree (`git worktree add -b <branch>
    .claude/worktrees/<branch> main`), never by switching branches there, and check
    `git branch --show-current` before every commit.
  - **Per change:** in that worktree: edit, `git add <files>`,
    `claude-git-sign commit -m "…"` (or `-F file`), then `claude-git-sign push -u origin <branch>`
    and `claude-gh pr create`.
  - **Merging:** **the owner merges**, on GitHub or in their terminal (an agent's merge is denied).
    GitHub's rules on main allow no merge commits, so PRs are squashed: for stacked PRs, rebase
    the upper branch onto main after the lower one merges. Then: `claude-git-sign fetch origin`,
    `git merge --ff-only origin/main`, and `claude-git-sign branch -d <branch>`.
  - **Dated log:** the DEVLOG lives in the owner's notes folder, not the repo. Write the entry in
    the PR description; the owner (or an agent with access to that folder) adds it there.
  - **Commit trailer:** `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. PR bodies end
    with the Claude Code line.
- **Subagents** worked well for:
  - static RE of stock (`docs/STOCK-*`);
  - feature implementation in a git worktree under `.claude/worktrees/` (untracked), with a
    precise brief that includes the decoded facts;
  - an independent security review.

  Review their diffs and run every host test yourself before committing. Possible vendor
  findings they report go to the disclosure memory, never the repo.
- **Lessons (2026-10-23/24):**
  - **Stacked PRs:**
    - GitHub main takes squashes only (no merge commits, 2026-11-12). After the lower PR is
      squashed, rebase the upper branch onto the new main (`git rebase --onto origin/main
      <old-lower-tip> <upper>`) and push it before the owner merges.
    - If main's tree already equals the branch's base, `git checkout --ours` resolves the
      conflicts.
  - **The ARM build is gcc `-std=c11` with glibc:** any POSIX function in an ISO header
    (`clock_gettime`, `localtime_r`, `setenv`) needs `_GNU_SOURCE` before the includes. The host
    tests stub mi.c, so only `src/build.sh` catches this; ask the owner to build a branch
    (detached: `git switch --detach origin/<branch>`) before merging.
  - **A second checkout for building:** `git worktree add --detach ../<dir>
    origin/<branch>`. It also needs the gitignored inputs: `build/arm/dropbearmulti*`,
    `build/arm/dropbear-VERSION.txt`, `build/arm/camtls*`, `build/arm/mbedtls-VERSION.txt` and
    `bench-logs/iq-profile-stock.bin` (and `build/mbedtls-src` for the camtls host test).
  - **`git add` and `claude-git-sign` are separate commands.** Chained after `&&`, the signer runs
    sandboxed and fails ("Operation not permitted").
  - **zsh doesn't split `$VAR` into words:** run multi-flag compiles through `bash -c`.
  - **`claude-git-sign commit -F` runs outside the sandbox, where `$TMPDIR` is different:**
    write message files to the session scratchpad, not `$TMPDIR`.
  - **Issues:** `claude-gh` may not reach issues (it allows day-to-day PR commands); if it
    refuses one, give the owner the `gh` command.
  - **Gate 3 lessons (2026-10-24):**
    - Run `scripts/host-tests.sh` (all suites, ASan/UBSan) before each PR. On macOS `head -c 0`
      fails, so don't generate zero-length test inputs.
    - Features that need the camera to judge (a privilege drop, the vendor MI driver) go in
      **off**, behind a file in the image (`/etc/cam/*.user`), and are bench-tested on cam #1
      by hand before a release turns them on.
    - A live test script must time-limit external tools and stream their progress: nmap over
      Wi-Fi takes about 25 min, and a held pipe once hung it. It must also never overwrite
      earlier evidence (one folder per run).
  - **Lessons (2026-10-24/25):**
    - Check boot-time device setup on flash, not only in the chroot: the chroot inherited stock's
      `/dev/irled`, and flash had none (#164).
    - Measure what the hardware does, not what the config says: the sensor ran at 30 fps while
      every log said 25 (#166).
    - The image's BusyBox has only the applets in `rootfs/applets.txt` (no `nice`): check before
      calling one from a script.
    - noclobber with `>|` only replaces a file you meant to: a reused scratch name once gave a PR
      a stale body. Use a new name per PR body.
