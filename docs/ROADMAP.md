# Roadmap: a full-feature hardened camera (first target: Synology Surveillance Station)

Where we are (2026-10-23):
- **Surveillance Station adds the camera over ONVIF and plays both H.264 streams.** This runs on
  cam #2 in the RAM chroot test; nothing is flashed.
- Also working: snapshots, SSH (keys), NTP, day/night, image controls, config/users on DATA.
- The next order is in docs/RESUME.md §7. Flashing waits for Gate 1.

## What Surveillance Station needs from a camera
SSS adds a camera by brand/model, as **ONVIF** (generic) or as **"User define"** (raw RTSP). We
can already be added as "User define" with our two RTSP URLs. ONVIF (Profile S) is what makes it
a first-class camera:
- discovery on the LAN (WS-Discovery);
- automatic main/sub stream setup (`GetProfiles`, `GetStreamUri`);
- snapshots (`GetSnapshotUri`);
- time sync (`SetSystemDateAndTime`);
- image settings (Imaging service);
- camera-side motion events (Events service).

## Architecture
```
              +-------------------- camd (rtspd grows into it) ----------------------+
 sensor/ISP-> | MI pipeline, 3A, IQ | RTSP main/sub | JPEG snapshot | motion (AE grid) |
              +----------------- control socket /run/camd.sock -----------------------+
                         ^                                  ^
  camhttpd (one small HTTP server)                 sshd (Dropbear, keys only)
    /onvif/* SOAP: Device, Media, Imaging, Events
    WS-Discovery (UDP 3702)
    /snapshot.jpg, minimal web UI
  config + users: /mnt/nand/cam (DATA, jffs2), defaults in /etc/cam
```
- **One process owns the hardware** (camd). Everything else changes settings through its control
  socket (root-only unix socket), so there's no second MI client.
- **Listeners:** RTSP 554 (as stock; Surveillance Station assumes it), HTTP 80 (ONVIF + UI), SSH 22, WS-Discovery 3702/udp.
  Each one authenticated, except discovery. Nothing else.
- **No netfilter** in the stock kernel, so the listener list is the firewall.

## Work items (GitHub issues)
| # | Item | Notes |
|---|---|---|
| A (#72) | **Persistent config + users** on DATA (mtd3, jffs2, 1 MiB) | Foundation for auth, image settings and SSH keys. **Decided:** keep the vendor's files, ours in `/mnt/nand/cam` |
| B (#73) | **Runtime image settings** ("user color tuning"): brightness, contrast, saturation, sharpness, AE target, mirror/flip | IQ API groups 4102/4101/4106/4114, our AE target; persisted; via control socket, ONVIF Imaging and the UI |
| C (#74) | **ONVIF Profile S**: Device + Media + Imaging, WS-Discovery, auth | So SSS can add the camera as ONVIF. **Decided:** HTTP Digest and WS-UsernameToken (passwords stored recoverably, root-only) |
| D (#75) | **JPEG snapshot** (VENC JPEG device 8) | `GetSnapshotUri`, `/snapshot.jpg` |
| E (#76) | **SSH**: static Dropbear, public keys only | Host keys in DATA; `authorized_keys` from config |
| F (#77) | **Motion detection** from the ISP's 32×32 AE luma grid + ONVIF Events | Cheap: the stats are already read every frame |
| G (#78) | **Time**: ONVIF `SetSystemDateAndTime` + NTP client | NTP needs a BusyBox with `ntpd` (#27) |
| H (#79) | **Minimal web UI** (status, network, users, streams, image) | Same HTTP server as ONVIF |
| I (#80) | **Network config**: DHCP (default) or static, hostname, DNS | From config |
| — | Day/night: IR-cut, IR LEDs, light sensor, ISP night mode | Existing #30. Needed for real deployment |
| — | Image quality fine-tuning | Existing #36, parked (low priority, owner) |
| — | Toolchain: musl + minimal BusyBox | Existing #27 |
| — | Gates: backup/restore (#33), security review (#38), flash (#39) | Existing |

**Proposed order:** A (#72) → B (#73) → C (#74, with D #75) → E (#76) → F (#77) → #30 → H/I (#79/#80) → G (#78). SSS can use the camera as
"User define" RTSP today; after C it's a proper ONVIF camera.

## eth0 MAC (checked 2026-10-23)
- U-Boot's env holds `ethaddr`, but `bootargs_run` doesn't pass it to the kernel.
- The vendor's `mainctrl` applied it from userspace (`ifconfig eth0 hw ether`, `ModifyMac`).
- Our `rcS` now reads `ethaddr` from the env (mtd0 +0x3F000, read only), validates it and sets
  it before DHCP.
- Probe `scripts/probes/4-eth0-mac-origin.txt` confirms it on the live camera (values redacted on
  the camera).
