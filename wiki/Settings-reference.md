# Settings reference

Most settings are on the web UI. Everything is also available over SSH with `camcfg`, which
stores the settings in `/mnt/nand/cam/cam.conf` on the DATA partition. Settings survive reboots
and firmware updates.

## camcfg

Run these on the camera (`ssh root@<camera-ip>`).

### Settings

```sh
camcfg list                     # every setting that is set
camcfg get <key>                # one setting (exit 1 if it isn't set)
camcfg set <key> <value>        # save, and apply live where possible
camcfg unset <key>              # back to the default
```

`camcfg` checks every value and refuses a bad one with a reason.

- **Live** settings apply at once.
- **Stream, audio and snapshot** settings apply when the video service restarts:

  ```sh
  camcfg ctl restart
  ```

  The video stops for about 3 seconds. NVRs reconnect.

### Live values

```sh
camcfg ctl get                  # live image, day/night, motion, OSD and exposure values
camcfg ctl motion map           # the last motion evaluation as a 32x32 grid
```

`camcfg ctl get` includes `daynight.state` and `daynight.score` (see Day/night below).

### Users

```sh
camcfg user list
echo '<password>' | camcfg user add <name> <role>
echo '<password>' | camcfg user passwd <name>
camcfg user role <name> <role>
camcfg user del <name>
```

- Roles: `admin`, `operator`, `viewer`. They match ONVIF's Administrator, Operator and User.
- The password is read from stdin, never from the command line. Rules: 8 to 64 printable ASCII
  characters, never shortened, no space at the start or end, not the user name.
- The same accounts log in to the web UI, ONVIF and RTSP.
- At most 16 users. The last admin can't be deleted or demoted.

| Role | Can |
|---|---|
| viewer | watch streams and snapshots, see the Status page |
| operator | also change image, OSD, stream and motion settings |
| admin | also time, users, SSH keys, firmware update and reboot |

### SSH keys

```sh
camcfg sshkey list                          # numbered, with fingerprints
echo '<public key line>' | camcfg sshkey add  # one key line on stdin
camcfg sshkey del <number>
```

The SSH keys log in as root. Accepted types: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
`ecdsa-sha2-nistp256`, `sk-ecdsa-sha2-nistp256@openssh.com`, `ssh-rsa`. At most 16 keys. Key
options (`from="..."`) aren't accepted. The web UI's **SSH keys** page does the same.

Run `sshkey add` from your computer like this:

```sh
ssh root@<camera-ip> camcfg sshkey add < ~/.ssh/<your-key>.pub
```

### Settings backup

A backup is one encrypted file holding everything in `/mnt/nand/cam`: settings, users and their
passwords, the recovery code's hash, SSH keys and host key, and the HTTPS CA with its key. It
restores only on the camera that made it, and only with its passphrase (at least 12
characters).

**In the web UI** (admin, over HTTPS): the **System** page's **Settings backup** part.

- **Download backup:** enter a passphrase twice; the file downloads as
  `camera-<camera-ip>-<date>.cambak`.
- **Restore and reboot:** choose the file, enter its passphrase and your own password. The camera
  restores it and reboots; log in with the backup's accounts. The web UI takes backups up to
  48 KiB; a larger one restores over SSH.
- Over plain HTTP the page only says to use HTTPS or SSH.
- Right after a claim, the setup page offers the same download, and the setup page can restore a
  backup instead of a claim (see [Claiming the camera](Claiming-the-camera)).

**Over SSH**, from your computer, without the passphrase showing or being saved in your shell
history:

```sh
read -rs PASS                   # type the passphrase, then Enter
printf '%s\n' "$PASS" | ssh root@<camera-ip> camcfg backup export > camera.cambak
unset PASS
```

To restore it (the camera then needs a reboot):

```sh
read -rs PASS
{ printf '%s\n' "$PASS"; cat camera.cambak; } | ssh root@<camera-ip> camcfg backup import
unset PASS
ssh root@<camera-ip> reboot
```

On the camera itself, `camcfg backup export > FILE` asks for the passphrase twice, and
`camcfg backup import FILE` asks once.

- **Keep the file safe.** Anyone with the file and the passphrase has your passwords (ONVIF needs
  them stored in clear) and the CA key your computer trusts.
- **A backup is a snapshot.** Make a new one after changing settings, users or keys. Restoring
  puts the camera back exactly as the backup was: files added since are removed.
- **Restore checks everything first.** A wrong passphrase, another camera's backup or a damaged
  file changes nothing.

### Other commands

```sh
camcfg tls show                 # the HTTPS certificate: ok/renew/bad, address, end date, fingerprints
camcfg claimed                  # exit 0 if the camera has an admin
camcfg recovery set             # store a new recovery code (read from stdin)
```

## Image (live)

| Key | Values | Default |
|---|---|---|
| `image.brightness`, `contrast`, `saturation`, `sharpness`, `exposure` | 0..100 | 50 (= stock) |
| `image.exposure_night` | `day` or 0..100 | `day` (follow `image.exposure`). Try 30 for a street-lit scene that looks washed out at night |
| `image.mirror`, `image.flip` | 0 or 1 | 0 |
| `image.shutter_day_max` | 0 (automatic) or 100..1000000 µs | 0 |
| `image.shutter_night_max` | 0 (automatic, 50 ms) or 100..50000 µs | 0 |
| `image.antiflicker` | 0 or 1 | 0 |
| `image.mains_hz` | 50 or 60 | 60 |
| `image.nr2d`, `image.nr3d` | 0..255 (128 = as tuned) | 128 |
| `image.wdr` | 0..255 (0 = as tuned) | 0 |
| `image.blc` | 0..255, only with `image.wdr` 0 (0 = as tuned) | 0 |
| `image.night_tuning` | 0 or 1: the stock firmware's night tuning (stronger noise reduction, softer sharpening) | 0 |
| `image.isp_gain_day_max`, `image.isp_gain_night_max` | 1..4 (×) | 4, 2 |

A shorter shutter limit gives a noisier, and in poor light darker, picture.
`image.night_tuning` is only available if the image was built with the stock night-tuning files.

## Day/night (live)

| Key | Values | Default |
|---|---|---|
| `daynight.mode` | `auto`, `day`, `night` | `auto` |
| `daynight.irled` | IR LED power, 0..100 % | 96 |
| `daynight.night_below` | 1..1000000 | 15 |
| `daynight.day_above` | 1..1000000 | 1500 |
| `daynight.source` | `image` or `sensor` | `image` |

- In `auto`, the camera computes a brightness score from the picture (`daynight.score` in
  `camcfg ctl get`). It switches to night when the score stays below `night_below` for 5
  seconds, and back to day when it stays above `day_above`.
- `night_below` must stay below `day_above`. The web UI's Image page sets them in a safe order.
- After 3 switches in 10 minutes the camera holds its state for 10 minutes. Setting the mode to
  `day` and back to `auto` clears that.
- Leave `daynight.source` at `image`: on this camera the light sensor's status isn't a light
  reading.

## Streams (after `camcfg ctl restart`)

Keys exist for `stream.main.*` and `stream.sub.*`.

| Key | Values | Default |
|---|---|---|
| `stream.main.size` | `2560x1440`, `2304x1296`, `1920x1080`, `1280x720` | `2560x1440` |
| `stream.sub.size` | `640x360`, `960x540`, `1280x720` | `640x360` |
| `stream.*.codec` | `h264`, `h265` | `h264` |
| `stream.*.kbps` | 64..16384 | follows the size (below) |
| `stream.*.fps` | 1..30 | 30 |
| `stream.*.gop` | 1..1000 (frames between keyframes) | 100 |
| `stream.*.rc` | `vbr`, `cbr` | `vbr` |
| `stream.*.profile` | `high`, `main`, `baseline` (H.264 only) | `high` |
| `stream.sub.enabled` | 0 or 1 | 1 |

An unset `kbps` follows the size:

| Main size | kbps | Sub size | kbps |
|---|---|---|---|
| 2560x1440 | 4000 | 640x360 | 500 |
| 2304x1296 | 3500 | 960x540 | 900 |
| 1920x1080 | 3000 | 1280x720 | 1500 |
| 1280x720 | 1500 | | |

- The sub-stream runs at most at the main stream's fps.
- A set `kbps` stays as set when you change the size.
- The web UI's **Streams** page restarts the video for you, at most once every 10 seconds.
- Keep H.264 if you use Synology Surveillance Station.

## Snapshots (after `camcfg ctl restart`)

| Key | Values | Default |
|---|---|---|
| `snapshot.quality` | 10..99 | 80 |
| `snapshot.enabled` | 0 or 1 | 1 |

Snapshots are the sub-stream's size and need the sub-stream on.

## Time

| Key | Values | Default |
|---|---|---|
| `time.ntp` | up to 3 host names or IPv4 addresses, comma-separated | `time.cloudflare.com` |
| `time.tz` | a POSIX TZ string, live | `UTC0` |

- The camera has no battery clock. Its time comes from NTP (or from an admin over ONVIF).
- An empty server list on the web UI's **Time** page turns NTP off. `camcfg unset time.ntp`
  goes back to the default.
- On an isolated network, point `time.ntp` at a local time server, such as your router or NAS.
- `time.tz` is used for the on-screen clock and for local time on the web UI. Logs stay in UTC.
- The Time page has a list of zones with daylight saving rules. With `camcfg`, for example US
  Central time:

  ```sh
  camcfg set time.tz CST6CDT,M3.2.0,M11.1.0
  ```

  POSIX counts west of UTC as positive: `CST6` is UTC−6, `CET-1` is UTC+1.

## On-screen display (live)

| Key | Values | Default |
|---|---|---|
| `osd.time.enabled` | 0 or 1 | 1 |
| `osd.title.enabled` | 0 or 1 | 0 |
| `osd.title.text` | up to 48 printable ASCII characters | empty |
| `osd.time.pos`, `osd.title.pos` | `ul`, `ur`, `ll`, `lr` (corners) or `custom` | `ul`, `ll` |
| `osd.time.x`, `osd.time.y`, `osd.title.x`, `osd.title.y` | 0..100, for `custom` | 0 |
| `osd.time.format` | `yyyy-MM-dd`, `yyyy/MM/dd`, `dd/MM/yyyy`, `MM/dd/yyyy`, `dd-MM-yyyy`, `MM-dd-yyyy` | `yyyy-MM-dd` |
| `osd.time.12h` | 0 or 1 | 0 |
| `osd.time.weekday` | 0 or 1 | 0 |
| `osd.size` | `small`, `medium`, `large` | `small` |
| `osd.style` | `border`, `black-on-white`, `white-on-black` | `border` |

The overlay is in the main stream, the sub-stream and the snapshots.

## Motion (live) and audio (after restart)

| Key | Values | Default |
|---|---|---|
| `motion.enabled` | 0 or 1 | 1 |
| `motion.sensitivity` | 0..100 | 50 |
| `motion.mask` | 256 hex digits, one bit per cell of a 32x32 grid (1 = counts) | every cell |
| `audio.enabled` | 0 or 1: the microphone on the RTSP streams | 1 |
| `audio.gain` | 0..19 | 14 |

The motion area is easiest to draw in your NVR (ONVIF), which sets `motion.mask`.

## Network

| Key | Values | Default |
|---|---|---|
| `net.plain` | 1 or 0 | 1 |

- `1`: port 80 serves ONVIF and `/snapshot.jpg` in plain HTTP, and ONVIF offers `rtsp://`
  stream addresses. Synology Surveillance Station needs this.
- `0` (only while HTTPS is up): port 80 refuses ONVIF and snapshots and only redirects browsers.
  ONVIF offers only `rtsps://`, and discovery lists only `https://`. Port 554 still serves
  plain RTSP.
- Set `0` only once every NVR and client uses HTTPS and RTSPS.

### Address, DNS and hostname (after a reboot)

By default the camera takes its address from DHCP. These settings change only with
`camcfg net set`, which checks them as a whole (`camcfg set net.mode …` is refused):

| Key | Values | Default |
|---|---|---|
| `mode` | `dhcp` or `static` | `dhcp` |
| `address` | static only: `A.B.C.D/PREFIX`, prefix 8..30, inside CAM_NET (the image's camera subnet) | none |
| `gateway` | static only, required: a host in the address's subnet | none |
| `dns` | 1 to 3 IPv4 servers, comma-separated. With DHCP, they replace the lease's servers | the lease's |
| `hostname` | 1-63 of `a-z 0-9 -`, not starting or ending with `-` | the image's |

The hostname isn't private: the camera sends it in its DHCP requests, and ONVIF's GetHostname
answers without a login (the ONVIF standard requires it).

```
camcfg net set mode=static address=192.0.2.10/24 gateway=192.0.2.1 dns=192.0.2.1 hostname=porch
camcfg net show
reboot
```

`net set` replaces all five: a key you leave out goes back to its default.

The address must be in CAM_NET, the subnet the image was built for, because the camera's HTTPS certificate can only name an
address there. Without `dns`, a static camera can't resolve NTP server names (`time.ntp` takes
addresses too).

**A change only takes effect at the next reboot, and you must confirm it.** After that reboot, the
camera keeps the new settings only if you run `camcfg net confirm` (over SSH, at the new address)
within 10 minutes. Otherwise it puts the previous settings back and reboots. `camcfg net revert`
does the same at once. Setting the previous values again also cancels the change.

**A static address is checked at every boot.** First the camera checks that no other device
answers for the address. Then, once the address is set, it waits up to 60 seconds for the gateway
to answer. If either check fails:
- if the change is still waiting for confirmation: the previous settings come back immediately;
- otherwise: the camera uses DHCP for that boot and keeps your settings.

`/run/net-status` says which of these happened and why.
