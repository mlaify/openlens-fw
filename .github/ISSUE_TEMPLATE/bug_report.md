---
name: Bug report
about: Something in the camera firmware doesn't work as it should
title: ''
labels: ''
assignees: ''

---

<!--
Security problems: please don't report them here: issues are visible to everyone who can see this
repository. See SECURITY.md:
https://github.com/mlaify/openlens-fw/blob/main/SECURITY.md

Before you paste anything, remove MAC addresses, serial numbers, passwords, recovery codes and
RTSP URLs that contain a user name or password (rtsp://user:pass@...).
-->

**Firmware version**
The version on the System page, or `cat /etc/cam/version` over SSH (e.g. 20261025.2).

**Camera**
Model, and which of your cameras if you have more than one.

**What broke**
Pick one: video/RTSP, ONVIF/NVR, web UI, HTTPS/certificates, day/night, firmware update, SSH, the
claim (`/setup`, `/recover`), something else.

**Describe the bug**
What happened, and what you expected to happen.

**To reproduce**
1.
2.
3.

**NVR and client**
Surveillance Station version, or the player (VLC, ffplay, ...) or browser and its version.

**Log excerpt**
Over SSH, for example `logread | grep -E 'rtspd|camhttpd|camtls|daynight'` around the time it
happened. Remove MACs, serial numbers, passwords, recovery codes and RTSP URLs with credentials
first.

```
paste here
```

**Screenshots**
If they help. Crop out anything private.

**Additional context**
Settings you changed (`camcfg list`), network setup, anything else.
