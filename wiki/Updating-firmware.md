# Updating firmware

Once a camera runs this firmware, you update it with a signed `.camfw` package. No programmer or
cable is needed.

First [build](Building-from-source) a release image with a **newer version** than the camera
runs, and [sign it](Signing-and-update-keys).

## What is kept

An update rewrites only the `rootfs` partition. **The DATA partition is never touched,** so
these stay:

- settings (`cam.conf`);
- users and passwords, and the recovery code;
- SSH keys and the SSH host key;
- the camera's CA and certificate, so your browser keeps trusting it.

The camera reboots at the end. Video stops for about 1 to 2 minutes.

## From the web UI

You need an admin account.

1. Open **System** (`https://<camera-ip>/ui/system`).
2. Under **Firmware update**, choose the `.camfw` file and click **Upload and check**.
3. The camera checks the package and shows the result: the installed version beside the new
   version, the device, the signer and the size. Nothing is installed yet.
4. Tick **Yes, install this firmware and reboot the camera**, then **Install**. Only the admin
   who uploaded it can install it. **Discard** throws it away.
5. Reload the page after about 2 minutes.

Limits:

- The page needs its script (`/ui.js`). Without scripts, use SSH.
- Packages up to 5 MiB. Larger ones go over SSH.
- The web UI refuses packages signed with `--allow-downgrade`.
- An upload not installed within 15 minutes is discarded.

## Over SSH

You need an SSH key on the camera.

Check first. This changes nothing:

```sh
ssh root@<camera-ip> camupdate --check < build/update/<version>.camfw
```

A good package prints a line like:

```text
camupdate: OK: version <version> for MCA40E-IFADO, <bytes> bytes, signed by <key>
```

Then install:

```sh
ssh root@<camera-ip> camupdate < build/update/<version>.camfw
```

The SSH session shows the progress while the camera writes. Then the camera reboots and the
connection drops.

## What camupdate checks

Before it writes anything, `camupdate` refuses a package unless:

- the header's signature is from a key in the image's `/etc/cam/update-keys` (security-key
  signatures must carry the touch and PIN flags);
- the device is `MCA40E-IFADO` and the partition is `rootfs`;
- the image's SHA-256 matches the signed header, and it is a squashfs that fits the partition;
- it is not a bench image;
- the version is **newer** than `/etc/cam/version`.

### Downgrades

An older version is refused unless the package was signed with `--allow-downgrade` (see
[Signing and update keys](Signing-and-update-keys)). Install those over SSH only.

## If an install fails

- **Any failure before the write starts** changes nothing. The camera keeps running.
- **During the write** camupdate stops every other program and feeds the hardware watchdog
  itself. If the write or the read-back fails, it tries again, up to 3 times. If none succeeds it
  logs `INSTALL FAILED` and reboots. A power cut during the write has the same result.
- In that case the camera won't boot our firmware. Write the `rootfs` partition back from your
  flash backup with the CH341A programmer (see [Installing](Installing)), then install again.

## Check the result

After the reboot, the web UI's **Status** or **System** page shows the new version. Over SSH:

```sh
ssh root@<camera-ip> cat /etc/cam/version
```

A camera that reboots gets a new SSH session but keeps its host key, so `ssh` doesn't warn.
