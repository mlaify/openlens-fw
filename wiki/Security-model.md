# Security model

What the firmware protects, how, and what it leaves to you.

## No shared credentials

- A release image contains **no account, password, password hash, SSH key or SSH host key.** The
  build scans the image and fails if it finds any.
- Every secret is made on the camera, after you flash it: your accounts at the claim, the SSH
  host key at the first SSH start, the CA at the first HTTPS start, and random keys at every
  start.
- Nothing is derived from the serial number or the MAC address. Two cameras flashed from the
  same image share no secret.
- The serial console has no root login.

## The claim

See [Claiming the camera](Claiming-the-camera).

- Until a camera has an admin, it serves only `/setup`, and only for 30 minutes after power-on.
  RTSP and SSH don't start.
- `/setup` and `/recover` check that the request's `Host` is the camera's own address (against
  DNS rebinding), that the `Origin` is the camera, and a per-form token (against other web pages
  posting to the camera). Setup and recovery together allow 10 attempts a minute.
- The recovery code has 130 random bits. The camera stores only a PBKDF2-HMAC-SHA256 hash of it.
- **Passwords are stored in the clear** in a root-only file on the DATA partition. ONVIF's
  WS-UsernameToken login needs them. Treat the DATA partition, and any copy of it, as secret.

## Logins

- Web UI, snapshots and RTSP use HTTP Digest; ONVIF uses Digest or WS-UsernameToken. The same
  accounts and three roles (admin, operator, viewer) apply everywhere.
- 5 wrong passwords from one address in a minute lock that address for the rest of the minute.
  20 in a minute from all addresses stop checks for everyone except clients that logged in
  recently as operator or admin, such as your NVR.
- Web UI forms need a matching `Origin` and a per-user token. Pages are only served by IP
  address, with a strict Content Security Policy and no framing.
- SSH (Dropbear 2025.89) takes **keys only**: no passwords, no forwarding, no SFTP or SCP. It
  offers post-quantum hybrid key exchange (`mlkem768x25519`). SSH keys log in as root.

## Programs off root

Every network-facing program drops root after it has opened what it needs:

| Program | Runs as | What it does |
|---|---|---|
| `rtspd` | `rtspd` (uid 100) | video, RTSP, day/night |
| `ntpc` | `ntpc` (uid 101), keeping only the right to set the clock | NTP client |
| `camhttpd` worker | `camhttpd` (uid 102) | HTTP, ONVIF, web UI, discovery |
| `camtls` | `camtls` (uid 103) | TLS for ports 443 and 322 |
| `camhttpd` monitor | root | logins and privileged actions only |

Group `camctl` (gid 110) lets the worker reach the video service's control socket.

### The monitor and worker split

`camhttpd` is split in two:

- The **worker** parses everything from the network, but **never holds a password**, a recovery
  hash or the login secrets.
- The **monitor** (root) checks every login and runs the few privileged actions: saving a
  setting, changing users or keys, setting the time, rebooting and installing firmware.
- The worker can ask for a privileged action only inside a real, verified request from a user
  with the right role, and only for 30 seconds after it.

So a bug in the HTTP or ONVIF parsers doesn't hand over passwords or root.

## TLS

See [HTTPS and the camera CA](HTTPS-and-the-camera-CA).

- Each camera makes its own CA. Its name constraints limit it to one IPv4 network and no DNS
  names, so it can't vouch for any website.
- TLS 1.2 and 1.3 only, ECDHE-ECDSA, no RSA or CBC.
- `camtls` runs as its own user and holds no passwords. It passes connections to `camhttpd` and
  `rtspd` over local UNIX sockets that only its user can reach.
- With HTTPS up, the web UI, `/setup` and `/recover` are HTTPS-only.

## Signed updates

See [Signing and update keys](Signing-and-update-keys) and
[Updating firmware](Updating-firmware).

- The camera installs only packages signed by a key baked into its image: Ed25519, or Ed25519 on
  a FIDO2 security key with touch and PIN.
- It checks the signature, the device, the image's hash and size, and that the version is newer,
  before it writes anything.
- An update writes only the `rootfs` partition. The bootloader and DATA are never written.

## Network exposure

| Port | Service |
|---|---|
| 22/tcp | SSH (after the claim, with a key) |
| 80/tcp | ONVIF, snapshots; redirects browsers to HTTPS |
| 443/tcp | HTTPS: web UI, ONVIF |
| 554/tcp | RTSP |
| 322/tcp | RTSPS |
| 3702/udp | WS-Discovery |

The stock kernel has no packet filter, so this list is the whole attack surface on the camera.
Outbound, the camera needs only DHCP, DNS and NTP.

## Known limits and what to do

### Plain ONVIF and RTSP for NVRs (use router isolation)

Synology Surveillance Station can't use HTTPS or RTSPS with this camera, so it talks to ports 80
and 554 in plain text. Logins there are Digest (no password on the wire), but the traffic isn't
encrypted.

**Recommended:** put the cameras on their own VLAN and let your router allow only:

- from the NVR: TCP 80 and 554 (or 443 and 322 if it can use TLS);
- from your admin computer: TCP 22, 80 and 443;
- from the cameras: DHCP, DNS and NTP. Nothing else to the internet or to other networks.

Keep WS-Discovery inside the camera VLAN and add cameras to the NVR by address.

### NTP can be spoofed on the network

Plain NTP isn't authenticated. Someone on the path can move the camera's clock. The NTP client
refuses times before the firmware was built, and holds a step of more than 1000 seconds until a
second, fresh reply agrees. **Recommended:** use a local time server inside the isolated camera
network. Authenticated time (NTS) is a possible later option; it isn't planned in detail.

### DATA failing: the camera locks itself

The DATA partition holds the settings, accounts and keys. If it fails to mount (flash
corruption), or loses the users file of a claimed camera, the camera **locks**: every page is a
lock page, nobody can claim it, nothing streams, and SSH accepts only your update keys (the keys
that sign your firmware). A fresh or erased DATA stays claimable as usual. (Before lock mode, a
camera whose DATA failed looked unclaimed for 30 minutes, and whoever claimed it got root.)

**Getting it back** needs one of your update keys, which can already install any firmware, so it
adds no new way in: restore a settings backup or erase DATA, signed over a one-time challenge,
from the lock page, `scripts/cam-recover.py`, or SSH. See
[Troubleshooting](Troubleshooting). Do it on your isolated camera network: in lock mode the
camera's certificate is a throwaway one, so the connection can't be verified. The design is in
[`docs/PLAN-DATA-LOCK.md`](https://github.com/mlaify/openlens-fw/blob/main/docs/PLAN-DATA-LOCK.md).

**Not covered:** jffs2 losing both the users file and the claimed marker; the camera then looks
new.

### The bootloader needs physical protection

The camera keeps its stock bootloader, which doesn't check signatures. Anyone with physical
access (a serial console or a flash clip) can run or write any firmware. **Recommended:** mount
cameras out of reach and use tamper seals.

## Reporting a security issue

Don't open a public issue. See
[SECURITY.md](https://github.com/mlaify/openlens-fw/blob/main/SECURITY.md).
