# UPDATE-PATH: signed firmware updates for a flashed camera (#104)

Goal: once our rootfs is in mtd2, a new version must go on the camera without a SOIC clip,
and only versions the owner signed may go on it.

## Constraints
- **The kernel and bootloader stay stock.** U-Boot boots `root=/dev/mtdblock2` (squashfs), and
  its env and bootargs live in mtd0, which we never write. So there is **one slot**: no A/B, no
  bootcount.
- **mtd2 is 0xCB0000 (13 MB), erase size 4 KiB.** Our image is about 3 MB, so a write takes
  seconds.
- **The running system is mounted from mtd2.** Pages of running binaries can be re-read from
  flash while mtd2 is being rewritten, so the writer must run from RAM.
- **RAM:** 64 MiB, about 11 MiB free while streaming. The update is staged in tmpfs (3 MB) and
  streaming stops before the write.
- **DATA (mtd3) is never touched** by an update; settings, users and keys survive.

## Package (`.camfw`): one file = header, then the signature of the header, then the payload
```
header (text, 1 line per key, ends with a blank line):
  magic=camfw1
  device=MCA40E-IFADO          # refuses a package for another board
  part=rootfs                  # only rootfs for now (kernel stays stock)
  version=YYYYMMDD.N           # monotonic
  size=<bytes of payload>
  sha256=<hex of payload>
  allow-downgrade=0|1
signature: the armored OpenSSH sshsig of exactly the header bytes, namespace "cam-firmware"
payload: the squashfs image (rootfs.sqfs), `size` bytes
```
- Signing (owner's Mac): `ssh-keygen -Y sign -f <key> -n cam-firmware header.txt`. With an
  `ed25519-sk` key that's a YubiKey touch.
- `scripts/make-update.sh KEY` reads `build/rootfs/rootfs.sqfs` and the image's
  `/etc/cam/version` and `/etc/cam/device`, asks for the signature, and writes
  `build/update/<version>.camfw`.
  - `build-rootfs.sh` sets the version from `FW_VERSION` (default: today, `.0`). Use
    `FW_VERSION=YYYYMMDD.N` for a second build on the same day.
- **Owner's keys (decision 2026-10-23):** a resident `ed25519-sk` key on each of three YubiKeys
  (nano, sif, nfc), created with `-O verify-required`. Their public keys go in
  `rootfs/update-keys`, which the build bakes into `/etc/cam/update-keys`. camupdate requires the
  user-presence **and** user-verified (PIN) flags on sk signatures.

## Verification on the camera (`camupdate`, static, our code)
1. **Read the package** from stdin or a file into tmpfs, with a size cap of mtd2's size.
2. **Parse the header** strictly: magic, device, part, version and size; reject unknown keys.
3. **Verify the sshsig signature over the header** against the trusted public keys in
   `/etc/cam/update-keys`, which are baked into the image.
   - Supported: `ssh-ed25519` and `sk-ssh-ed25519@openssh.com`.
   - For sk keys, check that the user-presence and user-verified flags are set.
   - The SSHSIG reserved field must be empty (OpenSSH always writes it empty), and the signed
     data is built with bounds checks.
4. **Check the payload:** its SHA-256 must equal the header's, and it must be a squashfs that
   fits mtd2.
5. **Check the version:** it must be greater than the running one (`/etc/cam/version`), unless
   the signed header says `allow-downgrade=1`. A missing or malformed `/etc/cam/version` (not
   `YYYYMMDD.N`) is refused too unless the header says `allow-downgrade=1`: no installed version,
   no downgrade rule (Gate 3 review).
6. **`--check`** stops here and prints the verdict (no write). The web UI and SSH use this first.
7. **Write:**
   - re-exec `camupdate` from a tmpfs copy: `/tmp/camupdate.XXXXXX/camupdate.run`, in a fresh
     0700 directory (`mkdtemp`, then `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0700), so nothing planted
     in the world-writable `/tmp` is followed or truncated. Once running, the copy deletes itself
     and its directory (the kernel keeps the running image), so a refused install leaves nothing in
     RAM;
   - **SIGSTOP** every other process except init and its own ancestors (the SSH session, so
     progress shows). Nothing exits, so init respawns nothing from the flash being rewritten;
   - kill BusyBox's watchdog feeder (`/dev/watchdog` is single-open) and take the device. rcS
     starts the feeder once (`watchdog -T 30 -t 5 /dev/watchdog`); inittab has no entry for it,
     so init never respawns it. If the device can't be taken within about 2 s, camupdate starts
     the feeder again (its `/proc/<pid>/exe` with its old command line), SIGCONTs the stopped
     processes, and exits 1 with nothing written;
   - erase and write mtd2 with MTD ioctls (`MEMERASE` and `write`) in 64 KiB chunks, feeding the
     watchdog after every block and logging progress;
   - read it back and compare;
   - `sync` and reboot.
8. **On any failure before the erase,** nothing changes. **After the erase has begun,** camupdate
   never just exits (everything else is stopped and only it feeds the watchdog): a failed erase,
   write or read-back starts the erase, write and read-back again from the payload in RAM, up to 3
   passes. If none verifies, it logs `INSTALL FAILED`, syncs and reboots. That leaves a broken
   rootfs, as a power cut during the write does: recover with the CH341A (Gate 1) or U-Boot TFTP
   over UART.

**Crypto:** Ed25519 verification and SHA-512 come from **libsodium**.
- On the camera: Ubuntu's signed `libsodium-dev:armhf`, linked statically.
- On the Mac: Homebrew, for the host test.
- Monocypher isn't packaged in Ubuntu 24.04. We don't write our own curve code; SHA-256 is small
  and ours.

## Delivery
- **Over SSH:** `ssh root@cam camupdate --check < 20261023.1.camfw` (with the `.sig` sent in
  the same stream, or as a second file), then `camupdate` to install.
- **From the web UI (System page, admin; details in `src/camhttpd/README.md`, "Firmware update"):**
  1. **Upload:** `/ui.js` sends the `.camfw` as the raw body of `POST /ui/firmware`
     (octet-stream, the page's form token in `X-CSRF-Token`). camhttpd checks admin, Origin,
     token, type, `Content-Length` (at most 5 MiB), that nothing else is uploading or installing,
     and `MemAvailable` (twice the file plus 2 MiB) before it reads a byte. It streams the body
     into `/run/fw/upload.camfw`: a tmpfs of its own (rcS, 0700, 6 MiB), so `/tmp` keeps room for
     `camupdate.run`.
  2. **Check:** `camupdate --check /run/fw/upload.camfw` (fork/exec, no shell, `PATH` only),
     beside camhttpd's loop. REFUSED deletes the file and shows camupdate's reason. A package
     signed with `allow-downgrade=1` is refused too (the owner's decision, 2026-10-24): downgrades
     go over SSH only.
  3. **Show:** the installed version beside the new version, device, signer and size.
  4. **Confirm:** a tick box and a form bound to that upload (a random id, the uploading admin,
     the SHA-1 taken while it streamed in).
  5. **Install:** the reply goes out first ("about 1 to 2 minutes; settings, users and keys are
     kept"), then `camupdate /run/fw/upload.camfw` runs detached (double fork + setsid, stdio to
     `/run/fw/install.log`), so camhttpd isn't one of the ancestors camupdate spares: it is
     SIGSTOPped with everything else.
  - Packages over 5 MiB, such as the stock rollback (about 13 MB), go over SSH.

## Rollback to stock
Sign the stock mtd2 image (from the golden dump) as a package with `allow-downgrade=1`. That
installs like any update and brings stock back without the clip. Stock mtd2 is about 13 MB,
which fits the tmpfs stage only with streaming stopped. Test it on cam #1.

## Tests
- **Host:**
  - header parser (malformed, oversized, unknown keys);
  - sshsig parsing with OpenSSH-generated test vectors, for ed25519 and sk-ed25519 (signatures
    made with `ssh-keygen -Y sign` and committed as test data, public keys only);
  - tampered header or payload, wrong namespace, wrong device, a downgrade without the flag, a
    missing or malformed installed version, a forged signature block with a 2000-byte reserved
    field;
  - the install path on a test build's stand-ins (`CAMUPDATE_TEST`: a file for mtd2 and one for
    the watchdog, a fake `/proc`, `CU_TMP` for `/tmp`; "reboot" is exit status 3): the 0700 RAM
    copy, retried passes, `INSTALL FAILED` then a reboot, and a watchdog that can't be taken
    (feeder restarted, processes resumed, nothing written);
  - fuzz.
- **Camera (cam #1, after Gate 1):**
  - `--check` on valid and invalid packages;
  - an install of version N+1, then a reboot into it;
  - the stock rollback package.
