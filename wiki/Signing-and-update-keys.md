# Signing and update keys

A camera running this firmware installs only update packages signed by one of the keys built
into its image. You make those keys yourself, so only you can update your cameras.

## Why your own keys

- Every image carries a list of public keys in `/etc/cam/update-keys`. The build copies it from
  your own `rootfs/update-keys.local`. That file is gitignored, so your keys never end up in a
  commit.
- `camupdate`, the camera's installer, checks every package's signature against that list. A
  package signed by any other key is refused.
- So the keys in the image you install decide who can update that camera from then on.
- **Put your own keys in `rootfs/update-keys.local` before you build.** The repository ships no
  keys: [`rootfs/update-keys`](https://github.com/mlaify/openlens-fw/blob/main/rootfs/update-keys)
  is a template with comments only, and the build uses it only when `update-keys.local` doesn't
  exist.
- **A release build with no key stops.** A bench build only warns. A camera running an image
  with no keys would refuse every package.

## Make a key

Use OpenSSH's `ssh-keygen`. Two kinds of key are accepted.

**A plain Ed25519 key** in a file:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/<your-key> -C cam-firmware
```

Give it a passphrase. Anyone with this file and its passphrase can sign firmware for your
cameras.

**An Ed25519 key on a FIDO2 security key** (recommended if you have one):

```sh
ssh-keygen -t ed25519-sk -O verify-required -O resident -f ~/.ssh/<your-key> -C cam-firmware
```

- `-O verify-required` is required. The camera only accepts a security-key signature that
  carries both "user present" (touch) and "user verified" (PIN). A signature without the
  "user verified" flag is refused at install time.
- `-O resident` is optional. It stores the key on the security key, so you can load it on
  another computer with `ssh-keygen -K`.

## Put the public key in the image

Add each public key's line (the contents of `~/.ssh/<your-key>.pub`) to
`rootfs/update-keys.local` (create it; copying `rootfs/update-keys` gives you its comments), one
per line. Lines starting with `#` are comments.

```text
# my update keys
ssh-ed25519 AAAA... cam-firmware
sk-ssh-ed25519@openssh.com AAAA... cam-firmware-backup
```

Only `ssh-ed25519` and `sk-ssh-ed25519@openssh.com` lines are allowed. Anything else stops the
build.

**Add a second key and keep it somewhere safe.** If you lose every key in the image, the camera
can't be updated over the network any more. The only way back is to rewrite the flash with a
CH341A programmer (see [Installing](Installing)).

## Sign a package

After [building](Building-from-source) a release image, run this on your computer (not in
Docker):

```sh
scripts/make-update.sh ~/.ssh/<your-key>
```

It reads `build/rootfs/rootfs.sqfs` and the image's version and device, asks `ssh-keygen` to
sign (enter the passphrase, or the PIN and a touch for a security key), and writes
`build/update/<version>.camfw`.

It refuses a bench image.

### Downgrades

A camera only installs a version newer than the one it runs. To allow an older version, sign
the package with:

```sh
scripts/make-update.sh ~/.ssh/<your-key> --allow-downgrade
```

The web UI refuses such packages. Install them over SSH. See
[Updating firmware](Updating-firmware).

## What is in a package

A `.camfw` file has three parts:

1. A short text header: the format, the device (`MCA40E-IFADO`), the partition (`rootfs`), the
   version, the payload size, its SHA-256 and the downgrade flag.
2. An OpenSSH signature (`ssh-keygen -Y sign`, namespace `cam-firmware`) over the header.
3. The squashfs image.

The camera checks the signature over the header, then that the image's SHA-256 matches the
header, that the device is right, that it is a squashfs that fits the partition, and the version
rule.

## Changing keys later

The camera trusts the keys in the image it runs. To move to a new key:

1. Put the new public key in `rootfs/update-keys.local` (keep the old one there for now, if you
   like).
2. Build a new image with a newer version.
3. Sign it with a key the camera already trusts, and install it.

From then on the camera trusts the keys in the new image.
