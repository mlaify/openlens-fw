# rootfs: hardened userland for mtd2 (#31)

The stock kernel (mtd1) and its vendor modules stay. This tree replaces only the rootfs in mtd2:
squashfs-xz, booted with `root=/dev/mtdblock2 rootfstype=squashfs init=/linuxrc`.

| Path | What |
|---|---|
| `skel/` | Our files, copied verbatim. `etc/inittab`, `etc/init.d/rcS` (mounts, stock module load, watchdog, DHCP), `usr/sbin/rtspd-run` (starts rtspd with `/etc/cam/*`, logs to syslog), `usr/sbin/sshd-run` (Dropbear, #76), `etc/init.d/data-check` and `usr/sbin/sshd-lock` (lock mode, #174/#178), `usr/sbin/camtls-run` (HTTPS, off until its bench test), configs |
| `dropbear/localoptions.h` | Dropbear build options: server only, public keys only, no forwarding, no SHA-1/CBC/3DES (#76) |
| `applets.txt` | BusyBox applets linked as commands. The build fails if one is missing |
| `vendor-files.tsv` | Vendor files copied from the owner's stock-rootfs dump at assembly time, each SHA-256 checked. **Never committed** |
| `SOURCE_DATE_EPOCH` | Fixed timestamp for reproducible squashfs/tar output |

## Boot sequence
1. The kernel runs `/linuxrc` (BusyBox init). The image carries `/dev/console` and `/dev/null`.
2. `rcS` mounts proc/sys/tmpfs `/dev`/devpts/tmpfs `/tmp` and `/run`, plus `/run/fw` (a 0700
   tmpfs of 6 MiB for the web UI's firmware uploads, #104), makes `/run/camtls` and
   `/run/camhttpd` for HTTPS ("Users" below), then runs `mdev -s`,
   `sysctl` (stock buffer sizes plus hardening), hostname, `syslogd -C64` (RAM ring, read with
   `logread`) and `klogd`. Mount options (Gate 3): `/dev` nosuid,noexec; `/tmp` nosuid,nodev
   (exec stays: camupdate copies itself there and execs the copy); `/run`, `/run/fw` and DATA
   (or its tmpfs stand-in) nosuid,nodev,noexec. Nothing in the image executes from those.
   Hardening in `sysctl.conf`: no ICMP redirects accepted or sent (also `secure_redirects`), no
   source routes, strict reverse-path filter (`rp_filter=1`), for `all` and `default`; rcS sets
   the same on `eth0` itself before bringing it up (the kernel ORs `all` and the interface for
   redirects, and `default` misses an interface that already exists). No IPv6 settings: the
   stock kernel has no IPv6.
3. Kernel modules load exactly as stock `/opt/ch/loadko`: `sstar_mi.ko` with
   `/config/modparam.json`, `mi_debug.ko`, the HVSP LUT echo, then the sensor
   `cus_sc4336p_mipi_20251225.ko chmap=5`. Then `/etc/init.d/rtspd-prep` (Gate 3, "Users"
   below): `/run/cam` becomes `rtspd:camctl` 2750, the IR LED PWM (pwmchip4/pwm0) and the
   amplifier GPIO 12 are exported and their attributes given to `rtspd`.
4. DATA (mtd3, jffs2) mounts at `/mnt/nand`, and `/etc/init.d/data-check` (#174) checks it: a
   camera that was claimed keeps `/mnt/nand/cam/claimed`, and if that marker is there but the
   users file is missing or has no admin, jffs2 lost it. **Lock mode** (docs/PLAN-DATA-LOCK.md
   Part 2): when DATA doesn't mount or data-check finds that, rcS writes the reason to
   `/run/data-failed` (0644), leaves DATA unmounted and puts an empty tmpfs on `/mnt/nand`.
   camcfg then refuses `claim` and `backup import`, and `sshd-run` hands over to `sshd-lock`
   (below). A fresh or erased DATA mounts empty and stays claimable; a claimed camera without the
   marker (its first boot of this firmware) gets one. `/etc/init.d/cam-config` then:
   - makes `/mnt/nand` root-only (0700) and creates `/mnt/nand/cam` (ours; the stock firmware's leftovers were removed by hand, Gate 3);
   - **a release image has no account** (#128, docs/CLAIM.md): the owner claims the camera at
     `http://<camera>/setup` in the first 30 minutes after power-on (or with
     `scripts/cam-claim.py`). Only a bench image (`/etc/cam/bench`, `build-rootfs.sh --bench`,
     never flashed) seeds accounts and SSH keys from `/etc/cam/users.seed` and
     `authorized_keys.seed`;
   - derives `/run/cam/rtspd.htdigest` from the users (`camcfg`, #72; the file belongs to
     `/run/cam`'s owner, rtspd, 0600).
5. `watchdog -T 30 -t 5 /dev/watchdog` takes over from the vendor's `mainctrl`.
6. Network: `lo`, then the MAC from U-Boot's `ethaddr`, then `/etc/init.d/net-up` (#80):
   - **dhcp** (the default, and in lock mode): udhcpc on `eth0`. A `net.dns` replaces the lease's
     servers (`/run/net-dns`, read by `udhcpc.script`).
   - **static** (cam.conf's `net.*`, from `camcfg net set`): `arping -D` first, then the address
     and route, then up to 60 s for the gateway to answer ARP. If a check fails, this boot uses
     DHCP.
   - **A change waiting for confirmation** (`net-pending` on DATA):
     - if its static check fails, the confirmed settings come back at once;
     - otherwise `net-up wait` reverts and reboots after 10 minutes unless `camcfg net confirm`
       runs first.
   - `/run/net-status` (0644) records the outcome: configured, mode, state, reason and pending.
     camhttpd's ONVIF GetNetworkInterfaces reads it, to say Manual or DHCP.
7. `inittab` respawns the services below. These are the **only listeners**; the stock kernel has no
   netfilter, so that is the firewall.
   - `rtspd-run`, on 554 (RTSP default, as stock; Surveillance Station assumes it): `rtspd -a /run/cam/rtspd.htdigest` (it waits until the camera is claimed; there is no image fallback)
     `-Q /etc/cam/iq-profile.bin -i /mnt/nand/cam/cam.conf` (image settings, #73),
     `-q /etc/cam/iq-night.bin,/etc/cam/iq-day-switch.bin` when the build derived them (stock
     night tuning, `image.night_tuning`), `-G camctl`, `-U` with `/etc/cam/rtspd.user`'s user
     (in the image since its bench test passed; see "Users"), plus `/etc/cam/rtspd.args`.
   - `sshd-run`, on 22: Dropbear, public keys only (#76); it waits until the camera is claimed
     and has a key. In lock mode it runs `sshd-lock` instead (#178): root's keys are the image's
     update keys (`/etc/cam/update-keys`, copied to `/run/lockssh`, the sk keys with
     `verify-required`, Dropbear's `-D`), with a throwaway host key in `/run/lockssh`; DATA's keys
     are never used.
   - `ntpc-run`: the NTP client (#78). It doesn't listen; it sends DNS (53/udp) and NTP
     (123/udp) to the configured servers. It runs as user `ntpc` with `CAP_SYS_TIME` only.
   - `camhttpd-run`, on 80/tcp and 3702/udp: ONVIF Device + Media, `/snapshot.jpg` and
     WS-Discovery (#74, #75). See src/camhttpd/README.md. While unclaimed it serves only `/setup`.
     `-Z` with `/etc/cam/camhttpd.user`'s user (in the image since the bench test passed):
     a root monitor and a worker running as that user.
   - `camtls-run`, on 443/tcp and 322/tcp (docs/PLAN-TLS.md §B, D): **on** since the bench test
     below passed (2026-10-25): the image has `/etc/cam/tls.on` (`/run/tls.on` also works, for
     an image without it). Without either it waits, checking every 10 s. It doesn't wait for the claim
     (`/setup` is HTTPS-only once camtls is ready). Each start:
     - waits for eth0's IPv4 address;
     - `camcfg tls init IP`: on the first start, the camera's own CA and a server certificate for
       that address in `/mnt/nand/cam/tls` (0600; camcfg runs `camtls gen-ca` and `issue`);
     - `camtls check /mnt/nand/cam/tls IP`: on `renew` (another address, or within 30 days of the
       end) `camcfg tls renew IP`, the key kept; on `bad`, a log line, a minute's wait and a retry;
     - publishes `/run/camtls/ca.crt` and `/run/camtls/info` (the check line), 0644 (the System
       page shows them and offers the CA for download, #183);
     - runs `camtls -k … -c … -U camtls -L 443:/run/camhttpd/tls.sock -L 322:/run/rtspd/tls.sock -r /run/camtls/ready` (camtls sets its own priority to nice 5).
       camtls reads the key as root, runs as `camtls`, and passes plain HTTP to camhttpd over the
       UNIX socket. It exits (3) when eth0's address changes or the end nears; the next start renews.
       While `/run/camtls/ready` exists, camhttpd sends browsers on port 80 to `https://`.
8. `ttyS0` getty. **Root has no password** (`*`), so there is no serial login (owner decision
   2026-10-23). Access is SSH with keys.

Not in the image: telnetd, any vendor daemon (procman, mainctrl, media_server, hik/h5live/comm/
ex/p2p/web/dbg servers), vendor libraries, `dla/` (AI model), other sensors' IQ files.

## Build (owner's terminal)
src/build.sh and build-camtls.sh need CAM_NET, the camera subnet: `cam-net.local` at the
repository root (gitignored) or `-e CAM_NET=A.B.C.D/PREFIX` (scripts/cam-net.sh).
```
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-dropbear.sh
docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-camtls.sh
docker run --rm -v "$PWD":/src -w /src \
  -v <path-to-stock-rootfs>:/vendor:ro \
  ubuntu:24.04 bash scripts/build-rootfs.sh
```
That is a **release image**: no credentials, checked by `scripts/scan-credentials.sh` (the build
fails if the tree holds any). For the chroot test, a **bench image** with the builder's accounts
and keys: add `-v "$HOME/.config/cam-firmware-dev":/secrets:ro` and `--bench` (docs/CLAIM.md;
make-update.sh and camupdate refuse it).
Output in `build/rootfs/` (gitignored; it holds vendor files, and in a bench build the builder's
credentials): `rootfs.sqfs` (+ `.sha256`), `chroot-test.tgz`, `MANIFEST.txt`, `BUILD-INFO.txt`
(`image: release` or `image: BENCH`; `mbedtls:` names the mbedTLS source package and camtls's
SHA-256). The build fails if the image exceeds mtd2 (0xCB0000), or without `build/arm/camtls`.

## Test: chroot on cam #1, in RAM (nothing flashed)
```
python3 scripts/cam-chroot-test.py --minutes 10      # root console open --keep-open
ffplay -rtsp_transport tcp rtsp://admin:PASSWORD@<cam1>/      # and /sub
```
The chroot runs our BusyBox, rcS syntax check, `syslogd` and `rtspd-run` against the live
`/config` and `/dev`. Module loading is only exercised at a real boot. Flashing mtd2 waits for
Gate 1 (a CH341A read **and** a tested restore).

## Settings and accounts (#72)
`camcfg` manages `/mnt/nand/cam/cam.conf` (key=value) and `/mnt/nand/cam/users`
(`name:role:password`, roles admin/operator/viewer). Both are 0600, and every write is atomic
under a lock. Examples: `camcfg user list`, `echo 'new password' | camcfg user passwd admin`,
`camcfg set image.brightness 55`.
- **Image settings** (`image.brightness|contrast|saturation|sharpness|exposure`, 0..100, 50 =
  stock) apply live through rtspd's control socket `/run/camd.sock` and persist (#73).
- **Day/night** (`daynight.mode auto|day|night`, `daynight.irled`, `daynight.invert`) applies
  live. See src/README.md.
- **Stream settings** (`stream.main.*`, `stream.sub.*`: codec, kbps, fps, gop, size; H.264 at 30 fps by default)
  take effect after `camcfg ctl restart`. See src/README.md.
- **User changes** regenerate `/run/cam/rtspd.htdigest`, and rtspd reloads it without a restart.

## Users (Gate 3)
System users, no password (`*` in shadow, which `scan-credentials.sh` accepts), shell
`/bin/false` (not in `/etc/shells`, so Dropbear refuses them too), home `/`:

| User / group | uid / gid | For |
|---|---|---|
| `rtspd` | 100 / 100 | rtspd with `-U rtspd` (when the image has `/etc/cam/rtspd.user`) |
| `ntpc` | 101 / 101 | ntpc (always), keeping `CAP_SYS_TIME` |
| `camhttpd` | 102 / 102 | camhttpd's worker with `-Z camhttpd` (when the image has `/etc/cam/camhttpd.user`); its monitor stays root |
| `camtls` | 103 / 103 | camtls with `-U camtls` (HTTPS, when camtls-run runs it): it reads the key as root, then holds no file on DATA |
| group `camctl` | 110, members rtspd, camhttpd | `/run/camd.sock` (0660 `rtspd:camctl` with `-U`, `root:camctl` without) and `/run/cam` (read) |

What runs as whom and in what order: src/README.md, "Users". The runtime directories:

| Path | Owner, mode | Made by | Why |
|---|---|---|---|
| `/run/cam` | `rtspd:camctl` 2750 | rtspd-prep (rcS) | rtspd writes `snapshot.jpg` (0640, group camctl by the setgid bit) and re-reads `rtspd.htdigest`; camctl reads the snapshot |
| `/run/cam/rtspd.htdigest` | `rtspd` 0600 | camcfg (root) | camcfg gives the file to the directory's owner, writing its temp file with `O_EXCL`/`O_NOFOLLOW` (the directory isn't root's) |
| `/run/camd.sock` | see above | rtspd (as root, before the drop) | root's clients connect regardless (`CAP_DAC_OVERRIDE`) |
| `/sys/class/pwm/pwmchip4/pwm0/{period,duty_cycle,enable}`, `/sys/class/gpio/gpio12/value` | `rtspd` | rtspd-prep | IR LEDs and the speaker amplifier after rtspd's drop |
| `/run/ntp.conf` | root 0644 | ntpc-run, camcfg | ntpc's copy of `time.ntp` (DATA is root-only) |
| `/run/ntpc` | `ntpc` 0700 | ntpc-run | ntpc's marker `synced` |
| `/run/fw` | `camhttpd` 0700 (a 6 MiB tmpfs) | rcS | firmware uploads: camhttpd's worker writes `upload.camfw`, its monitor opens it (`O_NOFOLLOW`) for camupdate and writes `install.log` (given to `camhttpd`); root (no `-Z`) uses it as well |
| `/run/camtls` | `camtls` 0755 | rcS | camtls makes `ready` there once it listens (camhttpd checks for it); camtls-run (root) renames `ca.crt` and `info` (0644) in from `/run`, so nothing planted there makes root write through a link |
| `/run/camhttpd` | `root:camtls` 0750 | rcS | camhttpd binds `tls.sock` there as root; only camtls (and root) reach it |
| `/mnt/nand/cam/tls` | root 0700, files 0600 | camcfg (`tls init`/`renew`) | the camera's CA (`ca.key`, `ca.crt`; 10 years) and server certificate (`server.key`, `server.crt`; at most 397 days, SAN = eth0's address) |

No device node changes: mdev leaves `/dev/*` root's 0660, and rtspd opens every device it uses
(`/dev/mi_*`, `/dev/isp_fe`, `/dev/irled`, `/dev/mi_rgn`, `/dev/urandom`) before it leaves root;
ntpc opens `/dev/urandom` before. No `video` group is needed for that reason.

**rtspd's drop is on** (`skel/etc/cam/rtspd.user`, the line `rtspd`) since the bench test below
passed on cam #1 (2026-10-24). To turn it off again, build without that file: nothing on DATA can
turn it off, because the file is in the image.

### Bench test: rtspd as its own user (passed on cam #1, 2026-10-24)
Cam #1 runs our release; SSH as root works; `/tmp` is an exec tmpfs. The running image has no
`rtspd`/`camctl` entries, so the test uses numbers (`100:100`, group `110`). From the owner's
terminal, after `src/build.sh` (the ARM build), with the SSH options of the login line below:
```
CAM=<cam1>
S="ssh -o IdentitiesOnly=yes -o IdentityAgent=none -i $HOME/.ssh/<your-camera-key> -o UserKnownHostsFile=$HOME/.ssh/known_hosts_cam root@$CAM"
$S 'cat > /tmp/rtspd && chmod 700 /tmp/rtspd' < build/arm/rtspd
$S 'cat > /tmp/rtspd-prep' < rootfs/skel/etc/init.d/rtspd-prep
$S 'tr "\0" " " < /proc/$(pidof rtspd)/cmdline; echo; cat /proc/$(pidof rtspd)/environ | tr "\0" "\n" | grep OSD_TARGETS'
```
1. **Note the production arguments** printed by the last line (`-a /run/cam/rtspd.htdigest -Q …
   -i /mnt/nand/cam/cam.conf …`); they are ARGS below. Don't change users during the test: the
   running image's camcfg would write `rtspd.htdigest` as root's 0600 and `auth-reload` would
   keep the old users (the new camcfg gives it to rtspd).
2. **Pause the image's rtspd.** On the running release: stop its rtspd-run shell, then rtspd, so
   init doesn't start another: `$S 'kill -STOP $(pidof rtspd-run) && kill $(pidof rtspd); sleep 3; pidof rtspd || echo stopped'`.
   (An image with this change has a supported way: `touch /run/rtspd.hold`, then kill rtspd;
   rtspd-run waits until the file is gone.)
3. **Permissions as rtspd-prep makes them at boot:** `$S 'sh /tmp/rtspd-prep 100 110; ls -ld /run/cam; ls -l /run/cam /sys/class/pwm/pwmchip4/pwm0/duty_cycle /sys/class/gpio/gpio12/value'`
   (expect `/run/cam` `drwxr-s--- 100 110`, the htdigest, pwm and gpio files owned by 100).
4. **Run the test build** with ARGS plus the drop: `$S '/tmp/rtspd ARGS -G 110 -U 100:100 < /dev/null > /tmp/rtspd.log 2>&1 &'`
   (prefix `OSD_TARGETS=…` if step 1 showed one). Then:
   `$S 'grep -E "running as|leave root|failed|errno" /tmp/rtspd.log; grep -E "^(Uid|Gid|Groups|CapPrm|CapEff)" /proc/$(pidof rtspd)/status; ls -l /run/camd.sock'`.
   Pass: `rtspd: running as 100:100 (uid 100, gid 100, 1 groups); setuid(0) refused`; Uid/Gid all
   100; CapPrm and CapEff 0; the socket `srw-rw---- 100 110`. **Any `failed: ret … errno 1
   (Operation not permitted)` or `errno 13` after the "running as" line means the MI module wants
   root for that call: stop, note the call, the drop stays off.**
5. **Exercise everything that runs after the drop** (watch `$S 'tail -f /tmp/rtspd.log'`):
   - streams: `ffplay -rtsp_transport tcp rtsp://admin:PASSWORD@$CAM/` and `/sub`, 10+ minutes,
     and SSS reconnects and records; the IQ profile line at frame 10 shows no error;
   - control socket as root: `$S 'camcfg ctl get | tail -3'` ends `ok`; `$S 'camcfg ctl auth-reload'` says ok;
   - day/night: `$S 'camcfg ctl set daynight.mode night'` (B/W, IR LEDs on, `cat
     /sys/class/pwm/pwmchip4/pwm0/duty_cycle` 48000, no "IR LED pwm … not set"), then `day`, then `auto`;
   - OSD: `$S 'camcfg ctl set osd.title.enabled 1; camcfg ctl set osd.title.text Bench; camcfg ctl get | grep osd.status'` (`on`, visible);
   - snapshot through camhttpd (root): `curl --digest -u admin:PASSWORD -o s.jpg http://$CAM/snapshot.jpg`
     is a JPEG; `$S 'ls -l /run/cam/snapshot.jpg'` is `-rw-r----- 100 110`;
   - microphone (the audio track in ffplay) and two-way audio (`python3 scripts/cam-talk.py` or
     SSS talk): audible, "talks to the speaker" in the log, `gpio12/value` 1 while talking.
6. **Restore:** `$S reboot` (cleanest: the image's rtspd starts as root with the image's
   permissions). Without a reboot: `$S 'kill $(pidof rtspd); sleep 2; chown -R 0:0 /run/cam; chmod 700 /run/cam; kill -CONT $(pidof rtspd-run)'`
   (the old rtspd-run's pipeline ends, init starts it again).

### Bench test: camhttpd as its own user (passed on cam #1, 2026-10-24)
camhttpd -Z (docs/CAMHTTPD-PRIVSEP.md): a root monitor and a worker as user `camhttpd`. Like
rtspd's test, from the owner's terminal after `src/build.sh`, with `$CAM` and `$S` as above; the
running image has no `camhttpd` entries, so numbers again: `-Z 102:110` (uid 102, group 110 =
camctl as its only group). On an image that has the users, use the name instead
(`-Z camhttpd`); the image's own `/usr/sbin/camhttpd` will do. **It is on** since this passed:
`skel/etc/cam/camhttpd.user` holds `camhttpd`. To turn it off, build without that file.
```
$S 'cat > /tmp/camhttpd && chmod 700 /tmp/camhttpd' < build/arm/camhttpd
$S 'tr "\0" " " < /proc/$(pidof camhttpd)/cmdline; echo'
```
1. **Prerequisite:** rtspd's test above, steps 1 to 4 (`/run/cam` `100:110` 2750 and an rtspd with
   `-G 110`, with or without `-U`), so the worker's group reaches the control socket and the
   snapshot. Note camhttpd's production arguments from the last line (ARGS below; usually none).
2. **Pause the image's camhttpd** and give it the upload area: `$S 'kill -STOP $(pidof camhttpd-run) && kill $(pidof camhttpd); sleep 2; pidof camhttpd || echo stopped; chown 102 /run/fw; ls -ld /run/fw'`
   (`drwx------ 102 root`).
3. **Run the test build:** `$S '/tmp/camhttpd ARGS -Z 102:110 < /dev/null > /tmp/camhttpd.log 2>&1 &'`, then
   `$S 'grep -E "worker:|monitor:" /tmp/camhttpd.log; for p in $(pidof camhttpd); do echo $p; grep -E "^(PPid|Uid|Gid|Groups|CapEff)" /proc/$p/status; done'`.
   Pass: `worker: running as 102:110 (uid 102, gid 110, 1 groups); setuid(0) refused` and
   `monitor: root, pid M; the worker is pid W`; the monitor's Uid all 0, the worker's (PPid M) all
   102, Groups 110, CapEff 0.
4. **Exercise everything** (watch `$S 'tail -f /tmp/camhttpd.log'`). **Stop at any `monitor: … refused`
   line in normal use, a page saying "camcfg failed" or "couldn't run camupdate", a grey preview or
   a missing snapshot: note it, the split stays off.**
   - SSS: the camera stays connected and records; a motion event arrives; its snapshot works;
     edit the stream settings in SSS once (SetVideoEncoderConfiguration, rtspd restarts);
   - ONVIF as admin: `python3 scripts/gate3-live.py $CAM --admin NAME --only onvif,lockout --lockout`
     passes as on the release (the lockout lives in the monitor now);
   - web UI as admin: Status, Image (move a slider, Save), OSD, Streams, Motion, Time (save the NTP
     servers unchanged; change the zone and back), Users (add `bench` as viewer, log in as it,
     change its password, delete it), SSH keys (the list shows; add and delete a throwaway key),
     System: upload the current release's `.camfw` (the check's verdict shows: refused as not
     newer, or OK), Discard;
   - `/recover` with a wrong code (403, and it counts: 5 lock the address for a minute);
   - optional, last: an Install of a newer `.camfw`, or Reboot from the System page (both end the
     test).
5. **Evidence:** `python3 scripts/gate3-live.py $CAM --admin NAME --only ssh` (the camera-side part:
   the `§7 runs as:` INFO lines show the monitor as root and the worker as uid 102). Claim on a
   reset DATA is the chroot test's (`scripts/cam-chroot-test.py`), not this one.
6. **Restore:** `$S reboot`, or `$S 'kill $(pidof camhttpd); sleep 1; chown 0 /run/fw; kill -CONT $(pidof camhttpd-run)'`
   (killing the monitor ends the worker; init starts the image's camhttpd-run again).

### Bench test: HTTPS (camtls) on cam #1 (passed 2026-10-25; on in the image since)
Needs a release on cam #1 with camtls (`scripts/build-camtls.sh`, then `src/build.sh` and
`build-rootfs.sh` with a new `FW_VERSION`, signed and installed, RESUME §6.5) and camhttpd's
`-t` side (docs/PLAN-TLS.md §B). That image has no `tls.on`, so HTTPS is off: `logread | grep
camtls` shows "no /etc/cam/tls.on or /run/tls.on: not starting". `$CAM` and `$S` as above.
1. **Start:** `$S 'touch /run/tls.on'`, wait 15 s, then
   `$S 'logread | grep camtls | tail -5; camcfg tls show; ls -l /run/camtls /mnt/nand/cam/tls; netstat -ltn | grep :443; grep -E "^(Uid|Gid|Groups|CapEff)" /proc/$(pidof camtls)/status'`.
   Pass: "first start: made: CA and server certificate for <cam1>", `ok san=<cam1> …`,
   `ready`, `ca.crt` and `info` 0644, the four DATA files 0600 root, 443 listening, Uid/Gid 103,
   CapEff 0. Any "failed" or "not starting" line: stop, note it; HTTPS stays off.
2. **Trust the camera's CA on the Mac:** fetch it with
   `$S 'cat /run/camtls/ca.crt' > cam1-ca.crt` (or the System page's download, #183), compare `openssl x509 -in cam1-ca.crt -noout
   -fingerprint -sha256` with `ca_fp` from `camcfg tls show`, then Keychain Access → File → Import
   Items (login keychain) → double-click the certificate → Trust → "When using this certificate:
   Always Trust" → close (asks for your password).
3. **Browser:** `http://$CAM/ui/` goes to `https://$CAM/ui/` without asking for a login there;
   HTTPS has no warning (padlock, issued by the camera's CA), then the login. Every page works
   (Status, Image, OSD, Streams, Motion, Time, Users, SSH keys, System).
4. **Preview** over HTTPS for 5+ minutes: smooth, no growing delay
   (`$S 'top -b -n 1 | grep -E "camtls|camhttpd"'` for the CPU).
5. **Upload:** System page, the current `.camfw`: the check's verdict shows; Discard.
6. **SSS on 80:** still connected, recording, a motion event with its snapshot (ONVIF and
   `/snapshot.jpg` stay on port 80 until D).
7. **Evidence:** `python3 scripts/gate3-live.py $CAM --admin NAME --only tls` all PASS (TLS 1.0
   and 1.1 INFO if this Mac's OpenSSL can't offer them), then `--only onvif` (its web UI checks run
   over HTTPS now) and the listeners (`22, 80, 443, 554`).
8. **An address change:** give cam #1 another address in CAM_NET in the router's DHCP
   reservation, then `$S 'kill -USR2 $(pidof udhcpc); kill -USR1 $(pidof udhcpc)'` (the session
   drops; a reboot would forget `/run/tls.on`). On the new address: `logread | grep camtls` shows
   "renewing" and `camcfg tls show NEWIP` is `ok san=NEWIP`; `https://NEWIP/ui/` has no warning
   (same CA). Put the reservation back the same way and check SSS again.
9. **Stop:** `$S 'rm /run/tls.on; kill $(pidof camtls)'`: `ready` is gone, camtls-run waits again,
   and port 80 serves the web UI and `/setup` itself (the claim fallback). A reboot does the same.
Pass → `skel/etc/cam/tls.on` goes into the image (cam #1, then cam #2 with the owner's OK).

**ntpc on the running image (optional):** `$S 'cat > /tmp/ntpc && chmod 700 /tmp/ntpc' < build/arm/ntpc`,
then `$S 'grep "^time.ntp=" /mnt/nand/cam/cam.conf > /tmp/ntp.conf; chmod 644 /tmp/ntp.conf; /tmp/ntpc -1 -v -c /tmp/ntp.conf -U 101:101; echo exit $?'`:
`running as 101:101 (uid 101) with CAP_SYS_TIME only`, an offset, `exit 0` (the slew or step
went through with `CAP_SYS_TIME` alone).

## SSH (#76)
- **Server:** Dropbear 2025.87 or later from Debian's signed source package, static ARMv7
  (`scripts/build-dropbear.sh`; 2022.83 from Ubuntu 24.04 until Gate 3). It is built without
  password or PAM auth, without forwarding (agent, X11, TCP) and without SHA-1, CBC or 3DES, and
  with the post-quantum hybrid key exchanges mlkem768x25519-sha256 and sntrup761x25519-sha512.
  `localoptions.h` gives the full list.
- **Client keys:** ed25519, ecdsa, rsa (SHA-2 signatures only) and FIDO `-sk` keys.
- **Limits:** 3 auth tries, the fixed 300 s auth timeout, and at most 3 unauthenticated connections per
  IP.
- **Keys:** `/root/.ssh` links to `/mnt/nand/cam/ssh` on DATA. A release image ships none: they
  are added at the claim (`/setup` or `scripts/cam-claim.py`) or on the web UI's SSH keys page
  (#128). A bench image seeds `authorized_keys` from `/etc/cam/authorized_keys.seed`, which the
  build takes from `/secrets/authorized_keys` (public keys only; the build refuses anything else).
  Lines with key options (`from="…" ssh-ed25519 …`) are refused by that check for now.
- **Host key:** `sshd-run` makes the ed25519 host key on first start (DATA) and logs its
  fingerprint. With no `authorized_keys`, sshd doesn't start.
- **Login** (bench, your camera key; check the fingerprint against the
  `sshd: Fingerprint` line):
  `ssh -o IdentitiesOnly=yes -o IdentityAgent=none -i ~/.ssh/<your-camera-key> -o UserKnownHostsFile=~/.ssh/known_hosts_cam root@<cam1>`.
  The chroot test makes a new host key each run (DATA is a tmpfs there):
  `ssh-keygen -R <cam1> -f ~/.ssh/known_hosts_cam`.
- **No sftp/scp server.** Copy with `ssh root@cam 'cat > /tmp/f' < f`.
- **Build (owner's terminal, before `build-rootfs.sh`):**
  `docker run --rm -v "$PWD":/src -w /src debian:trixie bash scripts/build-dropbear.sh`

## Decisions (owner, 2026-10-23)
- **Serial console:** root locked; SSH only.
- **DATA:** keep the vendor's files and add ours under `/mnt/nand/cam`. Wiping can come after the
  golden backup.
- **ONVIF auth:** both HTTP Digest and WS-UsernameToken, so passwords are stored recoverably
  (root-only files).
- **eth0 MAC:** from U-Boot's `ethaddr` (rcS); probe 4 confirms it live.

## Open decisions
- **BusyBox** is Ubuntu's signed `busybox-static` (full applet set, glibc static) for now. A
  minimal hardened config is #27.
- **`mi_debug.ko`** is loaded for parity with stock (it adds `/proc` debug entries). Drop it later?
