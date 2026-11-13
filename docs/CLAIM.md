<!-- SPDX-License-Identifier: MIT -->
# First-boot claim and admin recovery (#128)

The stock firmware's root problem was a credential that every camera shared: a master password
computable from the serial, one root hash in every image, and a password silently cut to 16
characters. Our image carries **no credential at all**. Every account, password, SSH key and
recovery secret is made per camera, by its owner, after the camera is flashed.

## What ships in an image
- **Release image** (`scripts/build-rootfs.sh`, the default):
  - no users file, `users.seed`, `rtspd.htdigest`, `authorized_keys`, SSH host key or root hash;
  - `/etc/shadow` has `root:*` (locked), so the serial getty can't log in;
  - the build runs `scripts/scan-credentials.sh` on the tree and fails if it finds any of those
    by name, a password hash in `shadow`/`passwd`, or, in any text file, a private key, a crypt(3)
    hash, an htdigest line, an account line (`name:admin|operator|viewer:…`) or an SSH public key
    (outside `/etc/cam/update-keys`, which holds the update signing keys: public verification keys);
  - **per-start secrets** stay as before: the Digest nonce key, the web form key, the nonce offset
    (all from `/dev/urandom` at each camhttpd start). The Digest realm (`camera`) is fixed. Nothing
    is derived from the serial number or the MAC. The SSH host key is made on each camera at its
    first SSH start (`sshd-run`).
- **Bench image** (`build-rootfs.sh --bench`, for the RAM chroot test only):
  - embeds the builder's `users.seed`, `authorized_keys` and optional `root.hash` from `/secrets`;
  - is marked `/etc/cam/bench` (build time + "never flash"); `cam-config` seeds from the image
    only when that marker is there;
  - its `rootfs.sqfs` ends with a trailer after the squashfs (`CAM-FIRMWARE-DEV BENCH IMAGE …`),
    and `BUILD-INFO.txt` says `image: BENCH`;
  - **`make-update.sh` refuses to package it** (the marker in `build/rootfs/root`, the BUILD-INFO
    line, or any bytes after the squashfs's 4 KiB-padded end), and **`camupdate` refuses to
    install it**: the payload must end at the superblock's `bytes_used` rounded up to 4 KiB (as
    mksquashfs pads it), and the trailer's text names the reason. camupdate can't cheaply look for
    `/etc/cam/bench` inside the xz-compressed squashfs (no xz or squashfs reader on the camera
    side), so it checks the bytes after the filesystem instead. This works for a bench image
    packaged by an older make-update too, because the check is on the signed payload itself.
  - A bench image written with the CH341A or U-Boot isn't checked by anything: don't.
- The image's old `rtspd.htdigest` fallback is gone: rtspd's Digest file is always derived from
  DATA's users (`/run/cam/rtspd.htdigest`).

## The unclaimed camera
A camera is **claimed** when its users file (`/mnt/nand/cam/users`) has an admin
(`camcfg claimed` exits 0). Until then:

| Service | Unclaimed |
|---|---|
| RTSP (rtspd, 554) | not started: `rtspd-run` waits, checking every 5 s, until claimed and `/run/cam/rtspd.htdigest` is non-empty |
| SSH (Dropbear, 22) | not started: `sshd-run` waits until claimed and a key exists |
| ONVIF (`/onvif/*`) | every operation, PRE_AUTH ones too, answers `ter:NotAuthorized` "The camera is not set up yet: claim it in a browser at /setup" |
| `/snapshot.jpg`, `/preview.mjpg` | 503 |
| HTTP, **within 30 min of power-on** | `/setup` (and `/ui.css`); every other path redirects (302) to `/setup` |
| HTTP, **after 30 min** | one page on every path (503): "setup is closed: power-cycle the camera and claim it within 30 minutes" |
| WS-Discovery (3702/udp) | unchanged: answers Probes with the camera's XAddr (it holds no secret and helps the owner find the camera) |

**The window** is measured from power-on with `/proc/uptime` (`CLOCK_BOOTTIME`): NTP and
`SetSystemDateAndTime` don't move it, and a camhttpd restart doesn't reopen it. If `/proc/uptime`
can't be read, the window counts as closed. A power cycle reopens it as long as no admin exists.

## Claiming (`/setup`)
- **Form:** admin name (default `admin`), password twice, optional SSH public key (one line). The
  page warns to claim on a network only you use and shows the minutes left.
- **Checks in camhttpd:** the request's `Host` must be the address it came in on (optionally with
  the port), else 421 with a link to that address: a name that resolves to the camera (DNS
  rebinding: another site's script in the owner's browser) can't reach the form. A POST also
  needs an `Origin` (or `Referer`) of that host, a form body, and a `csrf` token: HMAC-SHA1 under
  the per-start key of "/setup" and the 15-minute bucket (there is no user yet, so the path stands
  in for one; a user's or `/recover`'s token doesn't work here). The two passwords must match, and
  the password and key must be one line of printable ASCII (a newline would start another stdin
  line for camcfg). Setup and recovery POSTs share a limit of **10 a minute**, from all
  addresses together (429 after that).
- **camcfg does the rest** (`camcfg claim NAME`, password and key on stdin), under its lock: it
  refuses if an admin already exists (so `/setup` can only ever make the first admin), checks the
  name, the password (8..64 printable ASCII, never shortened, no outer spaces, not the name) and
  the key, then writes in this order: the recovery file, the users file with the admin, and **the
  SSH key last** (a key already there is left alone). The key is written only once the admin is
  stored (Gate 3), so a claim that fails never leaves a root key behind for whoever claims next:
  if the users file can't be written, the recovery file is removed; if the key can't be added,
  the admin line and the recovery file are taken back out and the camera stays unclaimed ("claim
  undone"). A power cut before the users file leaves the camera unclaimed (claiming again just
  works); one between the users file and the key leaves it claimed without the key (add it from
  the web UI's SSH keys page). It regenerates `/run/cam/rtspd.htdigest`; rtspd-run then starts
  rtspd within 5 s, sshd-run starts Dropbear if a key was given.
- **The page then shows the recovery code once** (`Cache-Control: no-store`, never logged, never
  stored) with a note to save it, and a link to `/ui/`, where the browser asks for the new login.
- **A first backup (#173, docs/PLAN-DATA-LOCK.md):** over HTTPS the same page offers to download a
  settings backup right away (a passphrase, twice; the browser asks for the new admin's login as
  the form posts to the System page). It can be skipped, and says a backup is a snapshot. Over
  plain HTTP it only points to the System page (which needs HTTPS for backups) or SSH.
- **Or restore instead of claiming (#173):** `/setup` also takes this camera's own backup and its
  passphrase (`/setup/restore`, a multipart form, the same Host, Origin, token and rate checks as the
  claim, and a locked-out address refused first). The monitor checks again that no admin exists and
  the window is open; camcfg checks the file is this camera's and decrypts it before writing
  anything. A wrong passphrase counts as a failed login. The camera reboots, claimed with the
  backup's accounts, keys and HTTPS CA. Another camera's backup is refused.
- **Logged** (syslog, camhttpd): `ADDRESS: camera claimed: admin NAME[, SSH key added]`, and every
  refused POST with its address and reason. Never the password or the code.
- **After the claim** `/setup` is a 404 until the users file has no admin again. The claim also
  writes `/mnt/nand/cam/claimed`, so a users file lost later (or DATA failing to mount) locks the
  camera instead of reopening the claim: see "DATA failing: lock mode" below. To claim a camera
  afresh on purpose, remove both files over SSH (or erase DATA). Neither the web UI nor camcfg deletes or demotes the last admin (`camcfg user del` /
  `user role` refuse it: "NAME is the last admin: make another user admin first", Gate 3).
- **From a terminal:** `python3 scripts/cam-claim.py HOST` does the same over HTTP right after a
  flash: it prompts for the name and the password (twice, never echoed; checked against the same
  rules first), lets you pick one of `~/.ssh/*.pub` (never anything but a `.pub` file holding one
  public key line), posts to the camera's IPv4 address, prints the code and saves it to
  `~/.config/cam-firmware-dev/recovery-<HOST>.txt` (0600, folder 0700). `--backup FILE` then logs
  in as the new admin and downloads a first backup into FILE (0600, never over an existing file;
  HTTPS only; the passphrase asked twice before the claim). `--restore FILE` restores this
  camera's backup at `/setup/restore` instead of claiming (the passphrase asked once).

## The recovery code
- **Made at claim** (and on every use) by camcfg: 26 characters of base32 (`A-Z2-7`), 130 random
  bits from `/dev/urandom`, shown in groups of 4 (`ABCD-EFGH-…-YZ`). Case, spaces and dashes don't
  matter when it is typed.
- **Stored** only as a slow hash in `/mnt/nand/cam/recovery` (0600, written atomically under
  camcfg's lock): PBKDF2-HMAC-SHA256 with a 16-byte random salt per camera (and per code) and
  100 000 iterations (a check takes the file's own count, 1 000..10 000 000), plus the name of the
  admin it was made for. The SHA-256, HMAC and PBKDF2 are camcfg's own (no library; tested against
  FIPS 180, RFC 4231 and the published PBKDF2-HMAC-SHA256 vectors). The compare is constant time.
  - The cost (~0.3–0.6 s a check on the Cortex-A7, an estimate, not measured) matters little
    against 130 random bits; it is there so a copied DATA partition doesn't hand over the code.
    The users file next to it holds the passwords in the clear anyway (ONVIF's digest needs them,
    owner decision 2026-10-23): DATA is root-only and is the camera's secret.
- **Used at `/recover`**, open only in the **30 minutes after power-on** (403 "power-cycle"
  otherwise), with the same Host, Origin, token (`/recover`'s own) and rate limit as setup. The
  form takes the admin name (empty = the admin the code was made for), the code and the new
  password twice. camcfg (`camcfg recover [NAME]`) verifies the code **before** it looks at the
  name, so a guess learns nothing about the accounts; then it checks that NAME is an admin and the
  password policy (a refusal there doesn't use the code up), sets the password, regenerates rtspd's
  Digest file, makes a **new code** for that admin, and the page shows it once. The old code no
  longer works.
- **Wrong codes count as failed logins** (camhttpd's `auth_failed`): 5 from one address in a
  minute lock it, for the code and for every login, until the minute is up; 20 from all
  addresses in a minute stop checks for addresses that haven't logged in lately. A locked address
  is answered without running camcfg. At most 10 recovery or setup POSTs a minute get through in
  all, so guessing 130 bits is out of reach.
- **Which admin:** the code is made for the admin who claimed (or last recovered). If that user is
  gone (deleted by another admin), the code resets any admin named in the form; with the name left
  empty, the page asks for one. It never resets an operator or viewer.
- **Logged:** `ADDRESS: admin NAME's password reset with the recovery code; a new code was
  issued`, `ADDRESS: wrong recovery code[, blocked]`. Never the code or the password.
- **Lost the code?** An admin with an SSH key can store a new one: `camcfg recovery set` reads a
  code (26 characters of A-Z and 2-7) on stdin and keeps only its hash; `camcfg recovery check`
  reads one and exits 0 if it matches.

## Other ways back in
- **SSH key holder:** `echo 'new password' | camcfg user passwd NAME` (or `camcfg user add`).
- **Lost both the code and every admin key:** reflash with the CH341A (Gate 1). DATA keeps the
  vendor's files and ours; wiping `/mnt/nand/cam` makes the camera unclaimed again.
- **Not implemented, a possible future option (owner decision 2026-10-23, off by default):** a
  power-cycle pattern (for example 5 cycles of under 10 s each) that wipes the accounts and
  reopens setup. Anyone with access to the camera's power could use it, so it would be the owner's
  choice to enable it. This camera has no reset button.

## Threat model
- **The LAN race in the window.** Until it is claimed, anyone who can reach port 80 in the first
  30 minutes after power-on can claim the camera. Mitigations: the window (a camera left
  unclaimed shows nothing after 30 minutes), claiming on an isolated network or a direct cable
  (the page and cam-claim.py say so), `/setup` vanishing once an admin exists (a second claimant
  gets a 404, and the owner who finds the camera claimed by someone else knows it), and the log
  line with the claimant's address. Claim right after the flash.
- **Cross-site requests from the owner's browser** (a page on the internet posting to
  `http://192.168.x.y/setup` while the camera is unclaimed): refused by the Origin check and the
  token, which another site can't read. **DNS rebinding** (a name the attacker controls resolving
  to the camera, so Origin and Host agree): refused because Host must be the camera's own
  address. Use the IP, not a name, for setup and recovery.
- **Someone on the LAN after the claim** can try `/recover` only in the 30 minutes after a power
  cycle, at most 5 codes a minute per address and 10 POSTs a minute in all, against 130 random
  bits. A power cut they can cause reopens that window, but not setup.
- **Holding off the owner:** the shared limit of 10 setup/recovery POSTs a minute lets someone on
  the LAN keep the owner's claim or recovery from getting through while they keep sending (in the
  claim window they could claim the camera themselves anyway). Cut them off and power-cycle.
- **Someone with the code** (a photo of the paper, the owner's laptop) can reset an admin password
  in the window after a power-on. Using it replaces it, so the owner's old code then fails: a sign
  to look at the log. Keep the code like a password.
- **A copied DATA partition** gives the passwords (stored for ONVIF) and the code's hash; the code
  itself is not on the camera.
- **The first HTTPS visit can't be verified:** while camtls runs, `/setup` and `/recover` are
  HTTPS-only (docs/PLAN-TLS.md B), but at the claim the camera's CA is brand new and not yet
  trusted, so the browser can't tell the camera from someone on the path. `cam-claim.py` prints
  the certificate's fingerprint (`--pin` to require one). If camtls isn't running, the claim falls
  back to plain HTTP and is logged. Another reason to claim on an isolated network.
- **Shared secrets across cameras:** none. Two cameras flashed from one release image differ in
  every credential, host key, salt and per-start key.

## DATA failing: lock mode (#174, #178; docs/PLAN-DATA-LOCK.md)
**Since 2026-10-26** a claimed camera whose DATA fails is locked instead of claimable:
- **Detection (rcS and `/etc/init.d/data-check`):** the jffs2 mount fails, or DATA mounts with
  `/mnt/nand/cam/claimed` but without a users file that has an admin. rcS writes the reason to
  `/run/data-failed`, leaves DATA unmounted and puts an empty tmpfs on `/mnt/nand`.
- **Then:** `camcfg claim` and `camcfg backup import` refuse ("the camera is locked"), so `/setup`
  can't claim it; rtspd and the normal SSH wait as on an unclaimed camera; camtls makes a
  throwaway CA on the tmpfs (the browser warns); SSH accepts only the image's update keys
  (`sshd-lock`, a throwaway host key).
- **Still claimable:** a fresh or erased DATA (it mounts empty, no marker).
- **Not covered:** jffs2 losing both the users file and the marker (the camera looks new).
- **Recovery (#175-#177):** the lock page (every path; the reason, a one-time challenge, the form),
  `scripts/cam-recover.py`, or SSH with an update key: `camcfg unlock restore` (a backup) or
  `camcfg unlock erase`, signed with an update key over the challenge (the web and the script)
  and checked before mtd3 is erased. Or the CH341A.

The section below is how it was before, and the options weighed then.

### Before lock mode: the camera was claimable again (Gate 3 finding)
"Claimed" meant only "the users file on DATA has an admin line"; nothing else on the camera
remembered a claim. So a claimed camera whose DATA didn't mount was unclaimed for that boot.
What happened (`rootfs/skel/etc/init.d/rcS`, the DATA block after the module load):
1. `mount -t jffs2 … /dev/mtdblock3 /mnt/nand` fails (a corrupt or erased-looking jffs2, an MTD
   error). rcS logs `DATA (mtd3) not mounted: running on image defaults, nothing persists` and
   mounts an empty 256 KiB tmpfs (0700) on `/mnt/nand` instead.
2. `cam-config` runs on that tmpfs: it makes `/mnt/nand/cam` and `ssh/`, finds no users (a release
   image seeds none), logs "not claimed yet", and writes an empty `/run/cam/rtspd.htdigest`.
3. camhttpd finds no admin (it reads the users file on every request), so for the first 30 minutes
   after power-on `/setup` is open and every other path redirects to it; rtspd and Dropbear wait.
4. **Anyone on the LAN can claim it** in that window: their admin, password, recovery code and
   SSH key go to the tmpfs, rtspd starts with their account, and Dropbear starts with their key,
   which is **root**. As root they can read `/dev/mtd3` raw (the owner's users file holds the
   passwords in the clear for ONVIF, plus the recovery hash) and write any flash partition.
5. Nothing of that claim persists: at the next boot, if DATA mounts, the owner's accounts are back.
   If DATA keeps failing, every boot reopens the window.
**Owner decision (2026-10-24): (b), keep today's behaviour**, recorded as an accepted residual of
Gate 3 (#38); then (2026-10-26) the fix in docs/PLAN-DATA-LOCK.md, built as above: an encrypted per-camera settings backup, lock mode when DATA fails or loses the users
file, and recovery signed with the image's own update keys. The options considered on 2026-10-24:
- **(a) Don't open `/setup` when DATA failed to mount.** rcS would leave a marker (for example
  `/run/data-missing`) and camhttpd would serve the "setup is closed" page instead. Safe against
  the race, but a camera with a broken DATA can then only be recovered over the serial console or
  with the CH341A (reflash or rewrite mtd3), and a factory-new or wiped camera whose DATA really
  is unformatted would need the same: rcS would have to tell "mount failed" from "empty jffs2"
  (an erased mtd3 normally mounts as an empty jffs2, which stays claimable as today).
- **(b) Keep today's behaviour.** The window and the log line are the only guards; a DATA failure
  is rare and needs the attacker on the LAN in the 30 minutes after that boot.
- **(c) A "claimed" marker outside DATA**, checked as well as the users file: claimed if either
  says so, and with the marker set but no users file, setup stays closed. Where to keep it is the
  hard part: mtd0 (U-Boot and its env) is only ever read by this firmware, and mtd2 (the rootfs)
  is rewritten by every update, so it would need a spare flash area or a policy change for the
  U-Boot env; and it needs its own way to be cleared for a deliberate re-claim.

## Bench workflow (owner)
The RAM chroot test needs a camera that streams at once, so it uses a bench image:
```
docker run --rm -v "$PWD":/src -w /src \
  -v <path-to-stock-rootfs>:/vendor:ro \
  -v "$HOME/.config/cam-firmware-dev":/secrets:ro ubuntu:24.04 bash scripts/build-rootfs.sh --bench
```
The image seeds `users.seed` and `authorized_keys` into the chroot's tmpfs DATA as before. To try
the claim in the chroot instead, build a release image (no `--bench`, no `/secrets`): the chroot
comes up unclaimed, and since the chroot runs on the stock kernel, the window counts from the
camera's last power-on, so run it within 30 minutes of booting the camera.
