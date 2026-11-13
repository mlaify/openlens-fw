# openlens-fw

Hardened replacement firmware for the **Anpviz IPC-D240W-S** IP camera.

It keeps the camera's stock kernel and replaces the root filesystem (the `rootfs` flash
partition) with our own small userland. You build the image yourself, sign it with your own
key, and install it on a camera you own.

## Supported hardware

| | |
|---|---|
| Camera | Anpviz IPC-D240W-S (board type MCA40E) |
| SoC | SigmaStar Ifado (one Cortex-A7 core) |
| Sensor | SmartSens SC4336P, 2560x1440 |
| Flash | 16 MiB SPI NOR (PUYA P25Q128, 3.3 V) |
| RAM | 64 MiB |

No other camera is supported. This is not OpenIPC: OpenIPC doesn't support this SoC, and its
images for other SigmaStar chips must never be booted on this camera.

## What works

- **Video:** H.264 (or H.265) main stream up to 2560x1440 and a sub-stream up to 1280x720,
  30 fps by default.
- **RTSP** on port 554 (Digest login, RTP over TCP) and **RTSPS** on port 322.
- **ONVIF Profile S** on port 80 (and 443): device, media, imaging, events and motion area.
  Tested with Synology Surveillance Station.
- **Web UI over HTTPS** on port 443. Port 80 redirects browsers there. Each camera makes its
  own certificate authority.
- **Day/night:** automatic switching, IR-cut filter and IR LEDs.
- **Image controls:** brightness, contrast, saturation, sharpness, exposure, mirror and flip,
  shutter limits, anti-flicker, noise reduction, WDR and backlight compensation.
- **On-screen display:** date and time, and a title.
- **Motion detection,** sent as ONVIF events.
- **Microphone:** G.711 audio on the RTSP streams.
- **JPEG snapshots** at `/snapshot.jpg`.
- **Time:** NTP and a time zone with daylight saving rules.
- **Signed firmware updates** from the web UI or over SSH.
- **SSH** (Dropbear, keys only, post-quantum key exchange).
- **No shared credentials:** an image has no accounts or keys. You claim each camera after
  you flash it.

## What doesn't

- **Two-way talk.** This camera doesn't support it.
- **Network settings.** The camera gets its address by DHCP. Setting a static address is
  planned, not built. Use a DHCP reservation on your router.
- **90° rotation.** Mirror and flip (180°) work; 90° is planned.
- **RTP over UDP.** RTSP clients must use TCP.
- **HTTPS on one subnet.** The camera's certificate authority is limited to the subnet the image
  was built for (CAM_NET, a required build setting). See
  [HTTPS and the camera CA](HTTPS-and-the-camera-CA).

## Status

The firmware runs from flash on the developer's cameras every day and records to Surveillance
Station. Three code reviews and most of the planned security acceptance tests are done. Some
live tests (a full port scan, network fuzzing and a 24-hour soak) are still to run. Known
limits are listed in the [Security model](Security-model).

Installing replacement firmware can leave a camera unusable. Take a full flash backup first and
make sure you can restore it. Use this at your own risk.

## Pages

1. [Building from source](Building-from-source)
2. [Signing and update keys](Signing-and-update-keys)
3. [Installing](Installing)
4. [Claiming the camera](Claiming-the-camera)
5. [HTTPS and the camera CA](HTTPS-and-the-camera-CA)
6. [Updating firmware](Updating-firmware)
7. [NVR setup](NVR-setup)
8. [Settings reference](Settings-reference)
9. [Security model](Security-model)
10. [Troubleshooting](Troubleshooting)

## License

The source is under the [MIT license](https://github.com/mlaify/openlens-fw/blob/main/LICENSE).
A built image also contains third-party parts and proprietary vendor files from your own
camera. Read [THIRD-PARTY-NOTICES.md](https://github.com/mlaify/openlens-fw/blob/main/THIRD-PARTY-NOTICES.md)
before you share an image. In short: don't share images that contain vendor files.
