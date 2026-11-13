# Plan: settings backup, and a camera whose DATA fails stays locked (not scheduled)

**Status:** built (2026-10-26), bench test (#179) pending. Part 1: the `.cambak` format and
`camcfg backup export|import` (#171), the System page's download and restore (#172), and the
claim's backup offer, the restore at `/setup/restore` and `cam-claim.py --backup|--restore` (#173).
A backup restored from the web UI is at most 48 KiB (larger: SSH); the System page needs HTTPS for
both. Part 2: lock detection (#174: `/etc/init.d/data-check`, the `claimed` marker; claim and
import refused in lock mode; DATA stays unmounted, a tmpfs on `/mnt/nand`) and the lock page
(#175). Part 3: `camcfg unlock` and the shared verifier (#176), `scripts/cam-recover.py` (#177),
lock-mode SSH (#178, `/usr/sbin/sshd-lock`). Owner decisions 2026-10-24 (write it up, don't build it; it's a lot of work
for a rare event) and 2026-10-26 (this design, the lock page, and a backup at the claim). Until then it's an accepted Gate 3 residual
(docs/GATE3-CRITERIA.md §7, docs/CLAIM.md "DATA not mounted"). Part 1 is useful on its own and
can ship first.

## The problem
- "Claimed" means only that the users file on DATA (mtd3, jffs2) has an admin line.
- If the jffs2 mount fails (corruption, an MTD error), rcS mounts an empty tmpfs instead. The
  camera then looks new, and `/setup` is open for 30 minutes after that boot.
- The same happens if DATA mounts but jffs2 has dropped the users file (a bad-CRC node).
- Whoever claims it gets admin and root over SSH. As root they can:
  - read raw mtd3, which holds the owner's passwords in clear for ONVIF and the recovery hash;
  - write any partition, including a rootfs that never went through camupdate's signature check.

  That rootfs persists across reboots even though the claim itself doesn't.
- The owner's own way back today is the serial console or the CH341A.

## What makes a fix possible
- A factory-fresh or erased mtd3 (all 0xFF) **mounts** as an empty jffs2. Only a damaged one
  fails. So "mount failed" can lock the camera without stopping the first claim of a new camera.
- Every image already carries its builder's public keys in `/etc/cam/update-keys` (camupdate,
  docs/UPDATE-PATH.md). Whoever builds the image signs its updates, so those keys are the owner's,
  and they survive a DATA failure. Whoever can sign a recovery can already sign a whole firmware,
  so recovery adds no new authority, and the image needs no new key (no #128 exception).

## Owner decisions (2026-10-26)
- Recovery is authorized by a signature from an update key (the owner signs their own firmware).
  A YubiKey isn't required: camupdate accepts `ssh-ed25519` as well as `sk-ssh-ed25519`.
- A backup **includes the TLS CA key**, so a restored camera keeps the CA the owner's Mac trusts.
- A backup **can't be restored on another camera**, not even a replacement.
- A backup is **encrypted with a passphrase**.
- **The lock page** looks like the web UI, is the only page, shows an alert that DATA is corrupt,
  and gives the restore steps, on the page and from the command line (Part 2).
- **The claim prompts for a first backup** (Part 1).

## Part 1: settings backup and restore
- **Export:** System page, admin only, HTTPS only: "Download backup", asking for a passphrase
  twice. Also `camcfg backup export` over SSH (reads the passphrase on stdin).
- **Contents:** everything under `/mnt/nand/cam`: users and the recovery hash, settings, SSH host
  keys and authorized_keys, `tls/` (CA key and certificate, server key and certificate). A
  file-level archive, not a raw mtd3 image: a raw image can't be checked on restore.
- **Format** (`.cambak`):
  - a text header: magic `cam-backup 1`, the device ID (below), the firmware version, the creation
    time, the Argon2id salt and parameters;
  - then one XChaCha20-Poly1305 box over a simple archive (name, size, bytes; regular files only;
    no mode, as every file is 0600), with the whole header as associated data, so the device ID
    can't be edited. The exact format is in camcfg.c's top comment.
  - Key: Argon2id from the passphrase (libsodium, already linked by camupdate). Built with 8
    passes over 4 MiB (the camera has about 11 MiB free while streaming); to be measured on cam #1
    (target about 2 s). Import takes a file's own values within 1..32 passes and 1..8 MiB.
  - DATA is 1 MiB, so the whole thing fits in RAM; no streaming.
- **Device ID:** a SHA-256 of a fixed label and eth0's MAC from the U-Boot env (mtd0, read only,
  as rcS already does), shortened. It survives a DATA failure and doesn't show the MAC. A camera
  without a valid `ethaddr` refuses backup and restore.
- **Restore** takes the file plus the passphrase, and refuses a device ID that isn't this camera's
  (no override):
  - from the System page when logged in as admin (asks for the admin password again);
  - in place of `/setup` on an unclaimed camera, HTTPS only, inside the claim window. That's no
    more power than a claim. A camera's own backup restores it claimed.
- **Restore checks before writing anything:** header, device ID, decryption, every name against an
  allow-list of our files (no `..`, no links, sizes bounded), a valid users file with an admin.
  Then camcfg writes the files atomically under its lock and the camera reboots.
- **Writer:** camcfg (`camcfg backup export|import`), per AGENTS.md's writer rule. camhttpd's
  monitor runs it with a fixed argv and pipes, as it does for the claim; the worker never writes
  DATA.
- **At the claim (owner decision 2026-10-26):** once `/setup` has made the first admin, the page
  that shows the recovery code also asks the owner to download a backup of these first settings
  right away, so a copy exists before DATA can ever fail. It asks for the passphrase there and
  can be skipped. The page says a backup is a snapshot, and to download a new one after changing
  settings. `scripts/cam-claim.py` does the same (`--backup FILE`, asking for the passphrase).
- **The file is password-equivalent:** it holds the ONVIF passwords in clear and the CA key. The
  page says so and asks for a long passphrase (at least 12 characters).

## Part 2: lock mode
1. **rcS records the failure** in `/run/data-failed`, with the reason, and logs it:
   - the jffs2 mount fails (before the tmpfs fallback); or
   - DATA mounts and `/mnt/nand/cam/claimed` exists, but the users file is missing or has no admin.
     camcfg writes that marker at claim, as its own file (its own jffs2 inode). On the first boot
     of this firmware, a camera with a valid users file and no marker gets one.
2. **While `/run/data-failed` exists:**
   - camhttpd's monitor refuses `claim` and `recover`. The worker serves a lock page instead of
     `/setup`: "storage failed", the reason, and the signed recovery below;
   - rtspd and dropbear's normal path wait, as on an unclaimed camera;
   - camtls runs with a throwaway CA in tmpfs (the real one was on DATA), so the browser warns.
3. **The lock page (owner decision 2026-10-26).** It looks like the rest of the web UI (the same
   `ui.css`, header and layout) but is a single page with no navigation and no login: every
   path of the web UI answers with it, and port 80 redirects to it.
   - At the top, an alert symbol and "This camera is locked: its data partition (DATA) is
     corrupt", with the reason in one line (the mount failed, or the users file is missing).
   - **Restore from this page:** the steps of Part 3 in order, with the form on the page: the
     challenge to copy, the action (restore a backup, or erase and claim fresh), the backup file,
     its passphrase and the signature.
   - **Restore from the command line:** `scripts/cam-recover.py <camera> --backup FILE` (it reads
     the challenge, signs it with the owner's key and uploads), or over SSH with an update key
     (`ssh root@<camera>`, then `camcfg unlock restore -` or `camcfg unlock erase`).
   - **No backup?** Erase and claim fresh, then set the camera up again.
   - A note to do this on the isolated camera network or a direct cable (Part 3).

## Part 3: signed recovery
**On the lock page:**
1. The camera shows a one-time challenge: 32 random bytes, the device ID and the firmware version.
   It lives in the monitor's memory, expires after 10 minutes, and is replaced after each attempt.
2. The owner picks the action: **restore** a backup (upload it), or **erase** DATA and claim fresh.
3. On the Mac, a new `scripts/cam-recover.py` builds the message to sign: the namespace's version,
   the challenge, the device ID, the action and, for restore, the backup's SHA-256. It runs
   `ssh-keygen -Y sign -n cam-recover` with the owner's key (a touch and PIN for a YubiKey) and
   prints the signature to paste.
4. The camera checks the signature against `/etc/cam/update-keys` with camupdate's sshsig code (the
   same rules: user presence and verification flags on sk keys, empty reserved field), then the
   challenge, the device ID and the backup's hash.
5. **Restore:** decrypt and check the backup completely in RAM (Part 1), then erase mtd3, mount it,
   write the files and reboot. The camera comes back claimed, with no open claim window. Nothing
   is erased if any check fails.
6. **Erase:** erase mtd3 and reboot into a fresh, claimable camera. The owner claims it at once
   and can then restore a backup through `/setup`.

**Why each part is there:**
- The challenge stops a captured signature being replayed later to wipe a camera.
- Signing the backup's hash stops someone on the path swapping in a backup of their own.
- The signature doesn't protect the passphrase: in lock mode the camera has lost its keys, so its
  certificate is new and unverified. Recover on the isolated camera network or a direct cable, as
  for the first claim (docs/CLAIM.md). The page says so.
- Failed signatures count toward camhttpd's lockout.

**Over SSH:** in lock mode only, sshd-run uses `/etc/cam/update-keys` as root's authorized keys
(never next to DATA's own keys), with a throwaway host key. The owner can read `dmesg`, try a
remount, or run `camcfg backup import` / `flash_erase /dev/mtd3 0 0` by hand. To check: whether
dropbear enforces the sk keys' verify-required (PIN) flag.

**Code layout:**
- the sshsig verifier moves out of camupdate into a shared file used by both;
- a root helper does the checks, the erase and the writes. camhttpd's monitor calls it with a
  fixed argv and pipes. Built as `camcfg unlock restore|erase|info` (`camcfg recover` is the
  recovery code's, #128); the verifier is `src/camupdate/sshsig.h`. The upload is exactly camcfg
  unlock's stdin (passphrase line, signature, backup), so the monitor pipes it in unchanged.

## Tests
- **Host:**
  - backup format: round trip, a wrong passphrase, an edited header or device ID, a truncated
    file, bad names (`..`, links, unknown files), a fuzzed archive parser;
  - rcS's decision, with a fake mount that fails, mounts empty, or mounts with the marker but no
    users file;
  - the monitor refusing claim and recover in lock mode; the lock page served for every path;
  - the claim's backup prompt and `cam-claim.py --backup`;
  - the recovery message: a valid signature, a wrong key, a wrong namespace, an expired or reused
    challenge, a wrong device ID, a swapped backup;
  - sshd-run choosing the update keys only in lock mode.
- **Chroot or bench:** a mount failure in the chroot's rcS copy. Check that `/setup` is refused,
  the signed restore and erase work, the update keys work over SSH, and DATA's keys aren't used.
- **Cam #1:** take a CH341A backup of DATA first.
  - Export a backup and restore it on the same camera.
  - Restoring cam #1's backup on cam #2 is refused (the device ID check, without writing).
  - Corrupt one jffs2 erase block on purpose, reboot, check lock mode, restore with a signed
    challenge, check the camera comes back claimed with its CA. Then the same with erase.
  - Delete the users file only (marker kept), reboot, check lock mode.
  - Restore the owner's DATA from the CH341A backup at the end.

## Open decisions (owner)
- Should lock mode also stop rtspd and WS-Discovery, or leave them waiting as on a new camera?

## Issues
Filed 2026-10-26: tracking #180; work #171 (backup format and camcfg), #172 (System page),
#173 (claim prompt, restore at /setup, cam-claim.py --backup), #174 (rcS detection), #175 (lock
page), #176 (signed recovery), #177 (cam-recover.py), #178 (lock-mode SSH), #179 (bench test).

## Issue text (as filed for the tracking issue)
**Title:** Settings backup, and lock a camera whose DATA fails (plan only; Gate 3 residual)

**Body:** see docs/PLAN-DATA-LOCK.md. Today a jffs2 mount failure, or a lost users file, makes the
camera claimable by anyone on the LAN for 30 minutes after that boot, and the claimer gets root,
so they could flash an unsigned rootfs. The plan:
1. an encrypted, per-camera settings backup (passphrase, includes the TLS CA);
2. lock mode when DATA fails (a fresh, erased DATA still mounts empty and stays claimable);
3. recovery authorized by a signature from the image's own update keys over a one-time
   challenge: restore a backup or erase, and SSH with those keys in lock mode only.

No new key in the image, no #128 exception. Not scheduled: accepted residual, owner decisions
2026-10-24 and 2026-10-26.
