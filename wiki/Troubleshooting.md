# Troubleshooting

## Where to look

Most checks need SSH (`ssh root@<camera-ip>`).

**The log** is kept in RAM and lost at a reboot. Times are UTC.

```sh
logread                                          # everything
logread | grep -E 'camhttpd|rtspd|daynight'      # web, ONVIF, video, day/night
logread | grep camtls                            # HTTPS
logread | grep -i data                           # the DATA partition
```

**Live values** from the video service:

```sh
camcfg ctl get
```

It shows the image settings, `daynight.state` and `daynight.score`, motion, the OSD status and
the exposure (`ae.*`). It ends with `ok`. No `ok` means the video service isn't running.

**Other quick checks:**

```sh
cat /etc/cam/version             # installed firmware
camcfg tls show                  # the HTTPS certificate
camcfg claimed && echo claimed   # does the camera have an admin?
```

The web UI's **Status** page shows the firmware version, uptime, time, day/night, motion,
streams, memory and network.

## The camera looks unclaimed

It shows `/setup`, or "setup is closed".

- **"Setup is closed: power-cycle the camera":** the 30-minute window after power-on has passed.
  Power-cycle it and claim it within 30 minutes. See [Claiming the camera](Claiming-the-camera).
- **You had claimed it, and now it says it's locked, or a claim fails with "the camera is
  locked":** the DATA partition failed (it didn't mount, or it lost the users file). The camera
  refuses a new claim, so nobody else can take it over.
  - Keep it on an isolated network or a direct cable while you recover it.
  - SSH still works for whoever holds one of the image's **update keys** (the keys that sign your
    firmware), with a new host key, so your SSH client warns that the key changed. That's
    expected here.
  - Power-cycle it once: if DATA mounts again, your accounts and settings come back.
  - Otherwise open the camera's address in a browser: the lock page says why, and walks you
    through a **restore** of your settings backup (`.cambak`) or an **erase** (no backup: claim the
    camera afresh after). Either is signed with an update key over a one-time challenge:

    ```sh
    python3 scripts/cam-recover.py <camera-ip> --backup camera.cambak --key ~/.ssh/<update-key>
    python3 scripts/cam-recover.py <camera-ip> --erase --key ~/.ssh/<update-key>
    ```

    Signing elsewhere: `--print-message` prints what to sign
    (`ssh-keygen -Y sign -n cam-recover -f <key> msg`), and `--signature msg.sig` sends it.
    The camera checks the signature and the whole backup before it erases anything, then reboots.
  - Over SSH with an update key instead:
    `{ printf '%s\n' "$PASS"; cat camera.cambak; } | ssh root@<camera-ip> camcfg unlock restore -`
    or `ssh root@<camera-ip> camcfg unlock erase`, then `reboot`.
  - No backup and no update key: your flash backup and the CH341A programmer (see
    [Installing](Installing)).
- **A camera you had claimed shows `/setup` again** on firmware from before lock mode: the DATA
  partition didn't mount. Don't let anyone else reach it (whoever claims it gets root), and
  update the firmware.
  - See "DATA failing" in the [Security model](Security-model).

## Browser certificate warnings

- **First visit to a new camera:** expected. The camera made its own CA, which your computer
  doesn't trust yet. Trust it after the claim: [HTTPS and the camera CA](HTTPS-and-the-camera-CA).
- **Using a host name:** the certificate names only the IP address. Use
  `https://<camera-ip>/`. The web UI also refuses requests made by name (HTTP 421).
- **Another computer or browser:** trust the CA there too.
- **The camera's address changed:**
  - Inside the CA's range (CAM_NET, the subnet the image was built for), the camera issues a new
    certificate within about a minute, with no warning.
  - **Outside the range,** the camera can't issue a certificate for the new address. HTTPS stops,
    and `logread | grep camtls` shows `camcfg tls renew failed` (or `init failed`), retried every
    minute. The web UI then works only on plain `http://<camera-ip>/`. Give the camera an address
    in the range again (a DHCP reservation), or rebuild with your network's range.
- **The CA files on DATA are gone:** the camera makes a new CA at its next start, and you trust
  that one instead.
- **The System page says "HTTPS is off":** camtls hasn't published the CA (`/run/camtls/ca.crt`).
  It runs only in an image built with HTTPS on; `logread | grep camtls` says why it isn't
  starting. **"camtls's status can't be read":** the CA can still be downloaded; `camcfg tls show`
  over SSH gives the status.
- **The downloaded CA's fingerprint doesn't match `camcfg tls show`:** don't trust it. Something
  between you and the camera replaced it. Fetch it over SSH instead, from a network you control.
- **"Download the camera's CA certificate" gives 403:** only an admin can download it.

## HTTPS isn't running

`https://<camera-ip>/` doesn't connect, and port 80 serves the pages in plain HTTP.

```sh
logread | grep camtls
camcfg tls show
```

- `eth0 has no IPv4 address yet: waiting`: the network isn't up.
- `camcfg tls init failed` or `renew failed`, mentioning "not an address in" your CAM_NET: the
  address is outside the CA's range. See above.
- `no /etc/cam/tls.on`: the image was built without HTTPS.

## Synology Surveillance Station says "HTTPS: Not Supported"

That is SSS's own verdict for a generic ONVIF camera, whatever the camera offers. Add the camera
on port **80** with plain RTSP, and protect those ports with your router. See
[NVR setup](NVR-setup).

## SSS can't connect or shows "Updates are required"

- Load the camera's capacity again in SSS.
- Check SSS's account on the camera has the **operator** or admin role. Encoder settings need it.
- Check SSS uses the camera's IP address and port 80.
- `logread | grep camhttpd` shows refused logins and refused requests, with the address.

## No picture at night, or no IR

- In night mode the IR-cut filter must move out and the IR LEDs come on. The filter is driven
  through the device `/dev/irled`, which the start-up script creates.
- Check it exists:

  ```sh
  ls -l /dev/irled
  logread | grep -E 'daynight|irled|IRLED'
  ```

- `daynight: IR-cut NOT moved: no IR-cut device`, or `no IRLED driver in /proc/devices`: the
  filter can't move, so night mode is black and white with the IR light blocked. Firmware
  built before this was fixed (October 2026) lacked the device node; update to a newer build.
- `daynight: IR LED pwm ... not set`: the IR LEDs can't be switched.
- If the picture is washed out at night, try `image.exposure_night` 30 (see
  [Settings reference](Settings-reference)).
- To test, force night mode, then go back:

  ```sh
  camcfg ctl set daynight.mode night
  camcfg ctl set daynight.mode auto
  ```

## Video stopped

```sh
logread | grep rtspd | tail -20
camcfg ctl get | tail -3
```

- A stream setting change restarts the video service (about 3 seconds). NVRs reconnect.
- RTSP clients must use **TCP**. A client that asks for UDP is refused.
- At most 4 RTSP clients at once, ports 554 and 322 together.

## Wrong time

- Check the Status page, or `date -u` over SSH.
- The camera has no battery clock. Until NTP answers after a boot, its clock is wrong, and ONVIF
  logins with WS-UsernameToken fail (Digest still works).
- Check `time.ntp` points at a server the camera can reach. On an isolated network use a local
  one.

## Reporting a bug

Open an issue in the [repository](https://github.com/mlaify/openlens-fw/issues). Include:

- the firmware version (`cat /etc/cam/version`);
- what you did, what you expected and what happened;
- the relevant `logread` lines.

**Remove private details first.** Logs, pages and settings can contain:

- **MAC addresses** (the Status page, network output);
- **serial numbers**;
- **passwords** and **recovery codes**;
- **RTSP or other URLs with credentials** in them (`rtsp://user:password@...`);
- private keys (never share these; public keys and fingerprints are fine).

Replace them with placeholders such as `<mac>` or `<password>`. Also consider replacing your
addresses with `<camera-ip>`.

**Security issues don't go in public issues.** See
[SECURITY.md](https://github.com/mlaify/openlens-fw/blob/main/SECURITY.md).
