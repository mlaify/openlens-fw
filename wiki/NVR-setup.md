# NVR setup

The camera speaks ONVIF and RTSP. It has been tested with **Synology Surveillance Station**
(SSS). Other NVRs may work through ONVIF or plain RTSP, but haven't been tested.

## Make an account for the NVR

Don't give the NVR your admin account. On the web UI's **Users** page (admin), add a user with
the **operator** role for the NVR.

Why operator:

- SSS sets the stream's encoder settings when it connects, which needs operator or admin.
- While someone is guessing passwords, an NVR that recently logged in as operator or admin keeps
  working. A viewer account doesn't get that.

## Synology Surveillance Station

1. In SSS, add a camera **by IP address**. Its search (ONVIF discovery) only finds cameras on
   the NAS's own subnet.
2. Brand: **ONVIF** (generic).
3. IP: `<camera-ip>`. Port: **80**.
4. User name and password: the NVR account above.
5. Save. SSS reads the camera's capabilities and pushes its encoder settings. The video restarts
   once (about 3 seconds), then live view plays.

Notes:

- **Keep SSS on plain HTTP (80) and RTSP (554).** SSS shows "HTTPS: Not Supported" for a generic
  ONVIF camera. Given port 443, or an `rtsps://` address, it still sends plain text and fails.
  Protect these ports with your router instead (see [Security model](Security-model)).
- **Image settings:** SSS has no image controls for this camera. Use the web UI's **Image**
  page.
- **Motion:** SSS receives the camera's motion events but uses its own detection. Set SSS's
  motion detection source to SSS. You can draw the detection area in SSS.
- **Video orientation:** SSS's orientation panel doesn't work for this camera. Use mirror and
  flip on the web UI's Image page.
- **Stream settings:** SSS may push its own values back after you change them on the web UI.
- **"Updates are required":** load the camera's capacity again in SSS.
- **Time:** setting the camera's clock from SSS needs an admin account. With an operator
  account, let the camera use NTP (see [Settings reference](Settings-reference)).
- Keep the codec at H.264. SSS's event detection can't use H.265.

## Generic RTSP

| Stream | URL |
|---|---|
| Main | `rtsp://<camera-ip>/` |
| Sub | `rtsp://<camera-ip>/sub` |
| Main over TLS | `rtsps://<camera-ip>:322/` |
| Sub over TLS | `rtsps://<camera-ip>:322/sub` |

- **TCP only.** RTP goes over the RTSP connection. A client that asks for UDP is refused. Set your
  client to "RTSP over TCP".
- **Login:** HTTP Digest, with any camera account (viewer is enough to watch).
- **Audio:** G.711 µ-law, 8 kHz mono, on both streams.
- **RTSPS:** the client must trust the camera's CA (see
  [HTTPS and the camera CA](HTTPS-and-the-camera-CA)).
- **At most 4 RTSP clients** at once, ports 554 and 322 together. An NVR recording main and sub
  uses 2.

For a quick test with ffplay:

```sh
ffplay -rtsp_transport tcp 'rtsp://<user>:<password>@<camera-ip>/'
```

A password in a URL ends up in your shell history and in process lists. Don't paste such URLs
into bug reports.

## Snapshots

`/snapshot.jpg` gives a JPEG at the sub-stream's size (Digest login, viewer or above):

```sh
curl --digest -u <user> -o snap.jpg http://<camera-ip>/snapshot.jpg
```

It is on port 80 for NVRs, and on `https://<camera-ip>/snapshot.jpg` too.

## ONVIF details

- ONVIF on `http://<camera-ip>/onvif/device_service` (and `https://` on port 443).
- WS-UsernameToken and HTTP Digest logins. UsernameToken needs the camera's clock to be right.
- Two profiles: `Profile_1` (main) and `Profile_2` (sub, while the sub-stream is on).
- Roles map to ONVIF levels: admin = Administrator, operator = Operator, viewer = User.
