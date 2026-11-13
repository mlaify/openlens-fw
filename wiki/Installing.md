# Installing

Installing replaces only the camera's `rootfs` flash partition. The bootloader, the kernel and
the data partition stay as they are.

## Before anything: a full flash backup

Do not skip this. A failed install, or a lost update key, can leave a camera that only a flash
programmer can bring back.

You need:

- a **CH341A** USB programmer and a **SOIC-8 clip**;
- `flashrom` on your computer;
- the camera opened so you can reach the flash chip (PUYA P25Q128). **It runs at 3.3 V.** Check
  your programmer's voltage before you clip on.

Then:

1. **Read the whole chip twice** and compare.
   [`scripts/flash-backup.sh`](https://github.com/mlaify/openlens-fw/blob/main/scripts/flash-backup.sh)
   does both reads and the compare. Two identical reads give you a trustworthy "golden" image.
2. **Keep copies offline.** The backup holds your camera's own data (its MAC address and
   calibration) and the stock firmware.
3. **Test a restore** before you write anything else.
   [`scripts/flash-restore.sh`](https://github.com/mlaify/openlens-fw/blob/main/scripts/flash-restore.sh)
   writes a full golden image back; flashrom verifies it after writing.

Rules that keep a camera recoverable:

- **Never write the `BOOT` partition** (the bootloader). Only `rootfs` is ever written.
- Keep the `DATA` partition. It holds the camera's own files, and our settings live there too.

The partition layout is in
[`scripts/flash-layout.txt`](https://github.com/mlaify/openlens-fw/blob/main/scripts/flash-layout.txt).

## Before you install

- [Build a release image](Building-from-source) with your own keys in `rootfs/update-keys.local`.
- [Sign it](Signing-and-update-keys) into a `.camfw` package.
- Put the camera on a **network only you use**: a separate VLAN or a direct cable. After the
  install the camera is unclaimed, and anyone who reaches it first can claim it.
- Give it a **DHCP reservation**. The camera only uses DHCP. For HTTPS, the address must be
  in the subnet the image was built for, CAM_NET (see
  [HTTPS and the camera CA](HTTPS-and-the-camera-CA)).

## First install from stock firmware

[`scripts/cam-first-install.py`](https://github.com/mlaify/openlens-fw/blob/main/scripts/cam-first-install.py)
installs over the network, without the programmer. It needs a root shell on the stock firmware.
This wiki doesn't describe how to get one; read the script and the repository's docs.

What the script does, at a high level:

1. Checks the camera's flash layout (read-only).
2. Uploads the release build's tools and your signed package into RAM, and checks their
   SHA-256.
3. Stops the stock software and runs `camupdate --check` on the package: your signature, the
   device, the image and its size.
4. Asks you to type `FLASH <camera-ip>` to confirm.
5. Writes the `rootfs` partition only, reads it back, compares, and reboots.
6. Waits for the camera to come back with our firmware, unclaimed.

```sh
python3 scripts/cam-first-install.py --host <camera-ip> --package build/update/<version>.camfw
```

Add `--check-only` for a dry run: everything up to the check, then the camera reboots back to
stock.

## After the install

- The camera comes up **unclaimed**. Claim it **within 30 minutes** of that boot. See
  [Claiming the camera](Claiming-the-camera).
- **DATA is kept.** The stock firmware's files on the data partition stay. Our settings,
  accounts, keys and certificates go in their own folder there (`/mnt/nand/cam`).
- Later updates don't need the script or the programmer. See
  [Updating firmware](Updating-firmware).

## If it doesn't come back

Write the `rootfs` partition back from your golden image with the programmer:

```sh
scripts/flash-write-region.sh rootfs <golden-image>
```

That brings the stock firmware back. The script writes only the region you name.

There is no "go back to stock" update package. The flash backup is the way back.
