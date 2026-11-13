# camhttpd: ONVIF Profile S (+ two-way audio, Imaging, Events, Analytics, OSD), WS-Discovery and snapshots (#74, #75, #77, #103, #110, #117)

`camhttpd` lets Synology Surveillance Station (SSS) add the camera as a generic ONVIF camera.
rtspd still owns the video hardware. camhttpd reads the config files and gets JPEGs from rtspd
over the control socket, as it does image settings and motion state. It runs one thread and one
`select()` loop: the HTTP listener, at most 6 connections (4 per address) and the WS-Discovery socket. It
allocates no memory of its own.

| File | What |
|---|---|
| `camhttpd.c` | The server: HTTP/1.1, SOAP 1.2 Device + Media (ver10), Imaging (ver20), Events (ver10 PullPoint), auth, SHA-1/Base64, WS-Discovery, the web UI and its preview stream (#79) |
| `test_camhttpd.c` | Host test: runs the request handler and the Probe matcher on canned input, without a socket |

It links `src/rtspd/auth.c` for MD5 only.

## Usage
```
camhttpd [-p port] [-l addr] [-r rtsp-port] [-u ctl-socket] [-U users] [-c cam.conf]
         [-S snapshot.jpg] [-i ifname] [-w skew-s] [-Z user|uid:gid] [-t path:user]
         [-T ready-file] [-D] [-v]
```
| Option | Default | Meaning |
|---|---|---|
| `-p` / `-l` | 80 / 0.0.0.0 | HTTP port and bind address |
| `-r` | 554 | RTSP port written into `GetStreamUri` |
| `-u` | `/run/camd.sock` | rtspd's control socket |
| `-U` / `-c` | `/mnt/nand/cam/users` / `cam.conf` | accounts (`name:role:password`) and settings |
| `-S` | `/run/cam/snapshot.jpg` | the file rtspd writes for `snapshot` |
| `-i` | eth0 | interface for WS-Discovery, `GetNetworkInterfaces` and the EndpointReference |
| `-w` | 300 | allowed UsernameToken `Created` skew in seconds (±) |
| `-Z` | | privilege separation: the worker runs as this user ("Privilege separation" below) |
| `-t` | | HTTPS through camtls: its UNIX socket and the one user that may connect (name or `UID:GID`); see [HTTPS](#https-through-camtls-docsplan-tlsmd-b). camhttpd-run passes `-t /run/camhttpd/tls.sock:camtls` while `/etc/cam/tls.on` or `/run/tls.on` exists |
| `-T` | `/run/camtls/ready` | the file camtls makes while it serves 443 (only with `-t`) |
| `-D` | | no WS-Discovery |
| `-v` | | log every operation |

`FirmwareVersion` comes from `-DFW_VERSION` (`FWVER=… src/build.sh`). Both files are read again on
every request, so `camcfg user …` and `camcfg set stream.…` show up at once. The stream values
are what rtspd will use at its next start.

Settings changed over ONVIF are saved by running `/usr/sbin/camcfg -d <cam.conf's directory> set
KEY VALUE`. That is a fork/exec with a fixed argv, no shell and an environment of `PATH` only
(`execve`, as for camupdate), and camhttpd validates the values first. The loop blocks while camcfg
writes, at most 10 s (`CAMCFG_MS`): a camcfg still running then is killed (SIGKILL, logged) and the
change counts as failed. The web UI's `camcfg user`/`sshkey`/`claim`/`recover` runs work the same.
The monitor runs every one of them ("Privilege separation").

## HTTP
- Routes:
  - `POST /onvif/device_service`, `media_service`, `imaging_service`, `event_service`
    (subscriptions: `event_service?sub=<id>`), `analytics_service` and `deviceio_service`;
  - any `POST /onvif/*`. A path containing "media", "imaging", "event", "analytics" or
    "deviceio" counts as that service (`/onvif/Media`, `/onvif/Imaging`, `/onvif/Events`,
    `/onvif/Analytics`, `/onvif/DeviceIO`). This matters for `GetServiceCapabilities`, and for
    the DeviceIO forms of GetVideoSources, GetAudioSources, GetAudioOutputs and
    GetRelayOutputs, which return token lists;
  - `GET /snapshot.jpg`;
  - the web UI (#79): `GET /` and `/ui` (302 to `/ui/`), `GET /ui.css`, `GET`/`POST /ui/…` and
    `GET /preview.mjpg` (see [Web UI](#web-ui-79));
  - `GET`/`POST /ui/firmware`: the System page's firmware upload (admin; see
    [Firmware update](#firmware-update-from-the-web-ui-104));
  - `GET /ui/ca.crt`: the camera's CA certificate, to trust in a browser (admin; see
    [HTTPS](#https-through-camtls-docsplan-tlsmd-b));
  - `POST /ui/backup-restore`: the System page's backup restore, a multipart form (admin; see
    [Settings backup](#settings-backup-172-173)); the download is the System page's own
    `POST /ui/system` with `do=backup`;
  - `GET`/`POST /recover`: admin recovery with the recovery code, in the 30 minutes after
    power-on (see [First-boot claim](#first-boot-claim-and-admin-recovery-128));
  - while the camera is **unclaimed** (no admin) all of the above is replaced: `/setup`,
    `POST /setup/restore` (its own backup instead of a claim) and `/ui.css` only, in the 30
    minutes after power-on; see
    [First-boot claim](#first-boot-claim-and-admin-recovery-128);
  - 404 or 405 for anything else (`/setup` once claimed).
  - With `-t`, the same routes also come from camtls (HTTPS, ONVIF included), port 80 redirects
    the pages while HTTPS is up, and `net.plain=0` closes port 80's ONVIF and snapshot; see
    [HTTPS](#https-through-camtls-docsplan-tlsmd-b).
- **ONVIF and browsers** (Gate 3 #1): a browser keeps the Digest login it used for the web UI
  (same realm `camera`) and sends it with requests another site's page makes to the camera. So an
  `/onvif/` POST is refused before any credential is looked at when it
  - carries an `Origin` that isn't `http://<its own Host>` (the web UI's check: `null`, another
    host, scheme or port, or two of them), or a `Sec-Fetch-Site` other than `same-origin` or
    `none`: 403;
  - has a `Content-Type` other than `application/soap+xml`, `text/xml` or `application/xml`
    (parameters such as `charset` and `action` allowed, case ignored), none, or two: 415. That stops
    the form and `text/plain` POSTs a page may send without a CORS preflight.

  Both are logged with the address (the 415 with the type that was sent). NVRs send neither header,
  and SOAP's type: SOAP 1.2 says `application/soap+xml`, SOAP 1.1 clients `text/xml`. **SSS's own
  type isn't in a bench log yet**: check `logread | grep 'refused: Content-Type'` after an install.
- **The web UI and the images by name** (Gate 3 #4, DNS rebinding): `/ui/…` (`/ui/firmware`
  too, its upload at the headers), `/snapshot.jpg` and `/preview.mjpg` answer only when `Host` is
  the address the request came in on (`:port` optional on 80), as `/setup` and `/recover` already
  did; any other Host gets 421 with a link to the address, before any login. `/ui.css`, `/ui.js`
  and the `/` redirect hold nothing and stay open. ONVIF takes any Host: NVRs send what they were
  given, and the checks above cover a browser there. Open the pages by the camera's IP address.
- One request per connection (`Connection: close`).
- Size limits: headers over 8 KiB get 431, a whole request over 64 KiB gets 413. The search for
  the end of the headers picks up where the last `recv` left it. The one exception is an admin's
  firmware upload (`POST /ui/firmware`, up to 5 MiB), which is streamed to a file, never buffered.
- Chunked bodies get 501. A missing, malformed or repeated `Content-Length` gets 400, and so does
  a NUL in the headers. `Expect: 100-continue` is answered.
- Connections: at most 6, and 4 from one address (a held PullMessages keeps its connection).
  The security review set 4; the web UI needed more: a browser opens the page's CSS, script and
  preview at once while SSS holds a pull, and the preview stayed grey (2026-10-23).
  When all 6 are taken, a new connection takes the slot of a stalled one: one still waiting for
  its headers after 1 s (`HDR_GRACE_MS`, so a browser's parallel requests can't push each other
  out), or one in its body that has had no byte for 2 s (`BODY_IDLE_MS`, Gate 3 #2: a POST that
  announces 60 000 bytes and stops); of those, the one stalled longest. Only connections whose
  request isn't complete qualify, so nothing authenticated is ever taken: credentials are checked
  once the whole request is in, and a held pull, a preview, a firmware upload (an admin, checked at
  its headers) or its check, and a reply being sent are never chosen. If no slot can be had, new
  connections wait in the listen backlog (camhttpd stops accepting until one frees) instead of
  being accepted and closed. A connection over the per-address limit is still closed, and one
  address may have at most 2 requests in their body at once (`BODY_PER_PEER`; a third gets 429).
  Only one pull is held per subscription, so held pulls use at most 2 of the slots (sized from SSS
  against stock: 1 HTTP + 1 RTSP connection at a time).
- Timeouts: 5 s for the headers; then 5 s plus one second per 4 KiB of body; 30 s to send the
  reply.
- Parsing cost: every XML name scan stops at `<` and at the end of the body, so a hostile body
  costs linear time.
- Every reply carries `Cache-Control: no-store`.

## HTTPS through camtls (docs/PLAN-TLS.md B)
camtls (its own process and user) terminates TLS on 443 and hands each connection to camhttpd as
plain HTTP over a UNIX socket. camhttpd's side:
- **The socket** (`-t PATH:USER`): made by root before the privilege split, at PATH (a stale socket
  there is replaced; anything else there, or no parent directory, and there is none), owner root,
  group USER's primary group, mode 0660 (set by the umask at `bind`; the group with `lchown`),
  non-blocking. The monitor closes it after the fork; the worker accepts on it beside port 80,
  under the same `can_accept`/backlog rule. If USER isn't in `/etc/passwd` (or is root) or the
  socket can't be made, camhttpd logs `-t …: <why>; running without HTTPS` and serves port 80 as
  before: unlike `-Z`, whose failure stops camhttpd (it must never keep root by accident), a
  missing `-t` only leaves things as they were, and stopping would also stop ONVIF for SSS. A
  malformed `-t` (no `:`, a relative path) is a usage error (exit 2).
- **Who may connect:** the peer's uid (`SO_PEERCRED`; `getpeereid` in the Mac host test) must be
  USER's, else the connection is closed and logged before it takes a slot.
- **The PROXY line:** a connection from camtls must start with exactly
  `PROXY TCP4 <client> <camera> <client port> <camera port>\r\n`: dotted quads (`inet_pton`, no
  leading zeros), ports 1..65535 without leading zeros, single spaces, at most 56 bytes; no `TCP6`,
  no `UNKNOWN`, nothing else. Anything else is closed and logged; the bytes after it are the HTTP
  request. Until it is in (at most 1 s, `PROXY_MS`, else closed and logged), the connection has the
  address 0.0.0.0 (so at most 4 such at once) and can be evicted like one waiting for its headers.
  Then the client's address is the peer for everything (`PER_PEER`: over 4, closed and logged;
  `BODY_PER_PEER`, the lockout, the logs, the monitor's `auth`), and the camera's address is the
  local one (Host checks, links). Port 80 never takes a PROXY line: there it is a bad request (400).
- **The send buffer** of each camtls connection is set to about 32 KiB (`SO_SNDBUF`), so the
  preview's back-pressure (a frame only when the last is out) still works through a UNIX socket.
- **Scheme by connection:** from camtls, `Origin`/`Referer` must be `https://<Host>` (an
  `http://` one is refused there, and an `https://` one on port 80), `Host` the address or
  `address:443`, and generated links (the 421 page, the closed-setup page) are `https://`.
  On port 80 everything stays `http://`.
- **ONVIF over HTTPS** (stage D; SSS supports it): `/onvif/*` from camtls is served as on port 80,
  and every address camhttpd gives follows the connection: `GetCapabilities` and `GetServices`
  XAddrs, `GetSnapshotUri` and the PullPoint subscription address are `https://<address>/…` (no
  port) over HTTPS, `http://` on port 80. `GetStreamUri` gives `rtsps://<address>:322/` (or
  `/sub`; camtls relays 322 to rtspd) for a request over HTTPS while HTTPS is up, and
  `rtsp://<address>:554/` otherwise. camtls writes one ready file for all its listeners, so the
  `-T` file stands for RTSPS too (camtls must make it only once both 443 and 322 listen): a second
  marker would only add a state, 443 without 322, that camtls has no reason to run in. `GetNetworkProtocols` adds HTTPS 443 (HTTP 80 and
  RTSP 554 stay) while HTTPS is up; ONVIF has no RTSPS entry. WS-Discovery XAddrs list
  `http://<address>/onvif/device_service https://<address>/onvif/device_service` (space-separated,
  `http://` first so a client that takes the first one sees no change) while HTTPS is up.
- **`net.plain`** (cam.conf, `camcfg set net.plain 0|1`, default 1): the owner sets 0 once SSS uses
  HTTPS and RTSPS (edit the camera in SSS first). While it is 0 **and** HTTPS is up, port 80's
  `/onvif/*` gets 403 with a SOAP fault ("Plain HTTP is off on this camera (net.plain=0): use
  https://") and `/snapshot.jpg` a 403, both before any login and logged at most once a minute;
  `GetStreamUri` gives only `rtsps://`; discovery lists only the `https://` XAddr. The browser
  paths keep redirecting. While HTTPS is down, port 80 serves everything as before whatever
  `net.plain` says (the same fallback as the claim's). Read from cam.conf per request, only when
  HTTPS is up and only for those paths. Closing RTSP 554 is rtspd's, not camhttpd's.
- **Port 80 while HTTPS is up** ("up": the socket was made and the `-T` file exists; one `stat`
  per request for these paths): `/`, `/ui`, `/ui/…`, `/setup`, `/recover` and `/preview.mjpg` are
  answered before any login and before the unclaimed redirect. GET and HEAD get `302 Location:
  https://<the address the connection came in on><the target as sent>` (a target that isn't
  printable ASCII: 400), with no `WWW-Authenticate`. A POST gets 403 and a short page linking to
  the https URL, logged (`POST … over plain HTTP refused: HTTPS is up`); the firmware upload's POST
  gets it at its headers, before its login. `/ui.css`, `/ui.js`, `/onvif/*` and `/snapshot.jpg`
  are unchanged (SSS uses the last two) until `net.plain=0`.
- **Fallback** (owner's default): without the ready file, port 80 works as before, `/setup` and
  `/recover` included, and the log says `TLS not running: /setup over plain HTTP` (or `/recover`)
  at most once a minute.
- **The System page's HTTPS part** (#183; admin): camtls-run's public files, read by the worker as
  they are (no X.509 code here). `/run/camtls/info` (camtls check's `ok san=… not_after=… ca_fp=…
  fp=…`) gives the certificate's address, its end (UTC) and the CA's and the certificate's SHA-256
  fingerprints (shown as `AB:CD:…`, as Keychain Access and Firefox show them); a line that isn't
  that, or a field that doesn't look right, shows "can't be read" instead. Over HTTPS, a
  certificate for another address than the page's gets a warning (camtls renews at its next
  start). Then a link to `GET /ui/ca.crt` and the steps to trust it: check its fingerprint against
  `camcfg tls show` over SSH first (the download itself came over an unverified connection), then
  macOS Keychain Access (Always Trust for SSL) or Firefox (Authorities, Import). Without
  `/run/camtls/ca.crt` the page says HTTPS is off and offers nothing.
- **`GET /ui/ca.crt`** (admin; an operator or viewer gets 403, logged; Host must be the address, as
  for every `/ui/` path; GET only): `/run/camtls/ca.crt` as `application/x-x509-ca-cert`, with
  `Content-Disposition: attachment; filename="camera-ca-<address>.crt"`. The path is fixed;
  nothing in the request names a file. `/run/camtls` is camtls's directory, so the file is opened
  without following a link and served only if it is a regular file under 8 KiB holding exactly one
  PEM certificate; anything else is 404 ("HTTPS is off"), as is a missing file. On port 80 while
  HTTPS is up it redirects like every `/ui/` path.
- **Not camhttpd's:** the `camtls` user, `/run/camhttpd` (camtls needs search permission on it)
  and `/run/camtls` (the worker, user `camhttpd`, needs search permission to `stat` the ready file;
  without it HTTPS counts as down; it reads `ca.crt` and `info` there too) come with camtls.

## Operations and access classes
| Class | Who | Operations |
|---|---|---|
| PRE_AUTH | anyone | GetSystemDateAndTime, GetCapabilities, GetServices, GetServiceCapabilities, GetHostname, GetWsdlUrl, GetEndpointReference |
| READ_SYSTEM | viewer+ | GetDeviceInformation, GetScopes, GetNetworkInterfaces, GetNetworkProtocols, GetDiscoveryMode, GetNTP, GetRelayOutputs (none); DeviceIO GetVideoSources, GetAudioSources, GetAudioOutputs, GetRelayOutputs |
| READ_MEDIA | viewer+ | GetProfiles, GetProfile, GetStreamUri, GetSnapshotUri, GetVideoSources, GetVideoSourceConfiguration(s), GetCompatibleVideoSourceConfigurations, GetVideoSourceConfigurationOptions, GetVideoEncoderConfiguration(s), GetCompatibleVideoEncoderConfigurations, GetVideoEncoderConfigurationOptions, GetGuaranteedNumberOfVideoEncoderInstances, GetAudioSources, GetAudioSourceConfiguration(s), GetCompatibleAudioSourceConfigurations, GetAudioSourceConfigurationOptions, GetAudioEncoderConfiguration(s), GetCompatibleAudioEncoderConfigurations, GetAudioEncoderConfigurationOptions, GetAudioOutputs, GetAudioOutputConfiguration(s), GetCompatibleAudioOutputConfigurations, GetAudioOutputConfigurationOptions, GetAudioDecoderConfiguration(s), GetCompatibleAudioDecoderConfigurations, GetAudioDecoderConfigurationOptions, GetVideoAnalyticsConfiguration(s), GetCompatibleVideoAnalyticsConfigurations, GetOSDs, GetOSD, GetOSDOptions; Analytics GetSupportedAnalyticsModules, GetAnalyticsModules, GetSupportedRules, GetRules; Imaging GetImagingSettings, GetOptions, GetStatus, GetMoveOptions; Events GetEventProperties, CreatePullPointSubscription, PullMessages, Renew, Unsubscribe, SetSynchronizationPoint; `/snapshot.jpg` |
| ACTUATE | operator+ | SetVideoEncoderConfiguration, Add/Remove/SetAudioSourceConfiguration, Add/Remove/SetAudioEncoderConfiguration, Add/Remove/SetAudioOutputConfiguration, Add/Remove/SetAudioDecoderConfiguration (all no-ops), SetImagingSettings, SetVideoAnalyticsConfiguration, AddVideoAnalyticsConfiguration, ModifyAnalyticsModules, ModifyRules, CreateRules, SetOSD, CreateOSD, DeleteOSD |
| READ_SYSTEM_SECRET | admin | GetUsers (names and levels, never passwords) |
| WRITE_SYSTEM | admin | SetSystemDateAndTime, SetNTP |

**Media:**
- Two profiles:
  - `Profile_1`, `stream.main.size` (2560×1440 by default; 2304×1296, 1920×1080, 1280×720);
  - `Profile_2`, `stream.sub.size` (640×360 by default; 960×540, 1280×720), present only while
    `stream.sub.enabled` is not 0.
- Codec, fps, kbps, gop, profile and size come from `cam.conf` `stream.*`, with rtspd's defaults
  and ranges (`src/rtspd/streamcfg.h`): 30 fps by default, an unset kbps the size's default
  (src/README.md, "Stream settings"), the sub's fps at most the main's.
- The video source (`VideoSource_1`, `VideoSourceConfig_1` Bounds, GetVideoSources'
  Resolution, GetVideoSourceConfigurationOptions) stays the sensor's 2560×1440 whatever the stream
  sizes: both streams scale the whole picture. GetVideoSources' Framerate is the main's fps.
- `GetStreamUri` gives `rtsp://<address the request came in on>:554/` (or `/sub`); over HTTPS
  `rtsps://<that address>:322/` (see [HTTPS](#https-through-camtls-docsplan-tlsmd-b)).
- `GetSnapshotUri` gives `http://<that address>/snapshot.jpg` (`https://` over HTTPS).
- `SetVideoEncoderConfiguration` (`VideoEncoder_1` main, `VideoEncoder_2` sub) accepts exactly
  what `GetVideoEncoderConfigurationOptions` offers:
  - one of the stream's sizes, listed as `ResolutionsAvailable` per encoder (with no token, both
    encoders' sizes, 1280×720 once); a new one is saved as `stream.<main|sub>.size`;
  - `FrameRateLimit` 1..30, `EncodingInterval` 1, `BitrateLimit` 64..16384 kbps. A sub-stream
    FrameRateLimit above the main's is taken as the main's; a main lowered below the sub's fps
    saves the sub's too (`stream.sub.fps`), as rtspd would run it anyway;
  - `GovLength` 1..1000, `H264Profile` Baseline/Main/High;
  - `Encoding` H264, or `H265` as we report it.

  Anything else gets `ter:InvalidArgVal`/`ter:ConfigModify` and nothing is saved.
  - **Ignored:** `Quality`, `Multicast`, `SessionTimeout`, `ForcePersistence`, and the rate
    control mode (`stream.*.rc` stays).
  - **Saving:** each value that changed is saved (`camcfg set stream.<main|sub>.<codec|kbps|fps|gop|profile|size>`).
    A `BitrateLimit` equal to the shown size default of an unset kbps isn't saved, so after a size
    change the bit rate follows the new size (SSS then reads the new default back).
    Only then camhttpd sends `restart` to rtspd, which exits; init starts it again with the new
    settings in about 3 s, and SSS reconnects.
  - **At most one restart per 10 s** (`RESTART_GAP_MS`, Gate 3 #11; with the web UI's streams and
    audio changes): a change saved within 10 s of the last restart is saved and answered as usual,
    and its restart is put off to the end of those 10 s; anything saved meanwhile joins that one
    restart (also at a clean exit). So SSS setting both encoders back to back costs two restarts
    10 s apart, not a refusal, and nothing an operator sends can restart rtspd more often.
  - **Same values:** saves nothing and restarts nothing, so SSS repeating its settings costs
    nothing.
  - **camcfg failure:** gets `env:Receiver ter:Action`.
- `GetGuaranteedNumberOfVideoEncoderInstances`: TotalNumber 2 (1 with the sub-stream off); H264
  counts the H.264 streams; JPEG 0.
- `GetVideoSourceConfigurationOptions`: bounds 0,0,2560×1440 (the sensor) and `VideoSource_1`.
- **Audio (#110):** rtspd sends the microphone in both RTSP streams (`a=control:track1`, G.711
  µ-law, 8 kHz mono, 64 kbit/s), so the same `GetStreamUri` URL carries it.
  - **What clients see:** `AudioSource_1` (1 channel), `AudioSourceConfig_1` and
    `AudioEncoderConfig_1` (G711, Bitrate 64, SampleRate 8, a Multicast block, SessionTimeout).
    Both profiles carry the two configurations, in tt:Profile's order: VideoSource, AudioSource,
    VideoEncoder, AudioEncoder, VideoAnalytics.
  - **Gets:** GetAudioSources; GetAudioSourceConfiguration(s) and
    GetCompatibleAudioSourceConfigurations; GetAudioSourceConfigurationOptions
    (`InputTokensAvailable`); GetAudioEncoderConfiguration(s) and
    GetCompatibleAudioEncoderConfigurations; GetAudioEncoderConfigurationOptions (G711,
    BitrateList 64, SampleRateList 8).
  - **Changes are no-ops:**
    - `Add*` with our tokens succeeds, since both profiles already carry them;
    - `Remove*` is acknowledged and **ignored**, so a client can't silently switch the
      microphone off; use `camcfg set audio.enabled 0`;
    - `SetAudioEncoderConfiguration` accepts only G711/64/8 and `SetAudioSourceConfiguration`
      only `AudioSource_1`; anything else gets `ter:ConfigModify`.
  - **`audio.enabled=0` in cam.conf:** no audio in the profiles, `ter:AudioNotSupported` for the
    audio operations, and an empty GetAudioEncoderConfigurationOptions, as before audio existed.
    rtspd applies the setting at its next start, so between a change and a restart camhttpd
    follows cam.conf, not the running stream.
- **Two-way audio (#117):** rtspd plays a client's RTSP backchannel on the speaker. A DESCRIBE
  with `Require: www.onvif.org/ver20/backchannel` gets a sendonly PCMU/PCMA `track2`, and SETUP
  of it makes that client the talker. camhttpd shows the speaker the way ONVIF ver10 clients
  look for it:
  - **Media:** `AudioOutput_1`; `AudioOutputConfig_1` (OutputToken `AudioOutput_1`, SendPrimacy
    `www.onvif.org/ver20/HalfDuplex/Auto`, OutputLevel 100); `AudioDecoderConfig_1`.
  - **Profiles:** both carry the two configurations in their `tt:Extension` (tt:ProfileExtension:
    AudioOutputConfiguration, then AudioDecoderConfiguration), after the VideoAnalyticsConfiguration.
  - **Gets:** GetAudioOutputs; GetAudioOutputConfiguration(s) and
    GetCompatibleAudioOutputConfigurations; GetAudioOutputConfigurationOptions
    (OutputTokensAvailable, SendPrimacyOptions Server/Client/Auto, OutputLevelRange 0..100);
    GetAudioDecoderConfiguration(s) and GetCompatibleAudioDecoderConfigurations;
    GetAudioDecoderConfigurationOptions (G711DecOptions: Bitrate 64, SampleRate 8).
  - **Changes are no-ops:**
    - Add with our tokens succeeds;
    - Remove is acknowledged and **ignored**, as for the microphone;
    - SetAudioOutputConfiguration accepts `AudioOutput_1`, any of the three SendPrimacy values
      and OutputLevel 0..100, and **stores nothing**: no speaker volume exists yet, and camcfg
      would refuse an `audio.speaker_level` key;
    - SetAudioDecoderConfiguration accepts our token;
    - anything else gets `ter:ConfigModify` or `ter:NoConfig`.
  - **DeviceIO (ver10):** NVRs read it to decide on a talk button.
    - It's in GetServices (`tmd:Capabilities` AudioSources/AudioOutputs = 1), and in
      GetCapabilities (Category All) as `tt:Extension/tt:DeviceIO` with AudioOutputs 1.
    - Its GetAudioOutputs, GetAudioSources, GetVideoSources and GetRelayOutputs return token
      lists.
  - **`audio.enabled=0`:** no Extension in the profiles, DeviceIO counts 0, and the output/decoder
    operations get `ter:ActionNotSupported/ter:AudioOutputNotSupported`.
  - **Assumed present:** the speaker is shown whenever audio is enabled; there's no rtspd
    `speaker.on` yet.
- **OSD:** the date/time and title overlays rtspd draws (`src/README.md`, "On-screen display";
  stock's ONVIF in docs/STOCK-OSD.md). `GetServiceCapabilities` says `OSD="true"`. (Media ver10's
  `GetCapabilities` has no OSD field.)
  - **Two fixed overlays** on `VideoSourceConfig_1`, as stock:
    - `osd_time`: TextString `DateAndTime`, DateFormat ↔ `osd.time.format`, TimeFormat `HH:mm:ss`
      (24 h) or `hh:mm:ss tt` (12 h) ↔ `osd.time.12h`;
    - `osd_title`: TextString `Plain`, PlainText ↔ `osd.title.text` (printable ASCII, at most 48;
      escaped on the way out).
  - **On and off:** an overlay that is off isn't listed by `GetOSDs`, and `GetOSD` answers
    `ter:NoConfig` for it. `DeleteOSD` turns it off; `CreateOSD` (the overlay is picked by its
    TextString Type, the request's token is ignored) and `SetOSD` turn it on. The weekday and style
    are web UI / camcfg only. The clock shows local time in `time.tz` (set by
    `SetSystemDateAndTime` or the Time page).
  - **Position:** UpperLeft/UpperRight/LowerLeft/LowerRight ↔ `ul`/`ur`/`ll`/`lr`; `Custom` with
    `Pos x, y` in −1..1 ↔ `osd.*.x = (x + 1) × 50`, `osd.*.y = (1 − y) × 50`, rounded (ONVIF's y
    points up, ours down; 0..100 is the box's place in the room left, so −1/1 are the edges).
    Read back as `x = x% / 50 − 1`, `y = 1 − y% / 50`.
  - **FontSize:** the text height in main-stream pixels: small 64, medium 96, large 128 at
    2560×1440 (48 / 80 / 96 at 1920×1080 and 2304×1296, 32 / 48 / 64 at 1280×720: the configured
    `stream.main.size`). A SetOSD FontSize takes the nearest; GetOSDOptions gives `FontSizeRange`
    small..large.
  - **GetOSDOptions** (`ConfigurationToken` VideoSourceConfig_1, else `ter:NoConfig`):
    MaximumNumberOfOSDs Total 2 (PlainText 1, DateAndTime 1, Image/Date/Time 0); Type Text; the
    four corners and Custom; TextOption types Plain and DateAndTime, the FontSizeRange, the six
    date formats and both time formats.
  - **SetOSD / CreateOSD** (operator+): anything not offered gets `ter:InvalidArgVal/ter:ConfigModify`
    and nothing is saved: Type Image (or an Image element), another TextString Type for the token,
    a bad date or time format, a non-integer FontSize, a PlainText over 48 characters or not
    printable ASCII, a Custom position without `Pos` or outside −1..1. An unknown token or another
    VideoSourceConfigurationToken gets `ter:NoConfig`; no OSD element `ter:InvalidArgs`. Omitted
    parts keep their values. FontColor and BackgroundColor are ignored (`osd.style` sets them).
  - **Saving:** each value that changed is saved with `camcfg set osd.<key>` and applied live with
    `set osd.<key>`, the `enabled` keys last so an overlay comes on in its new place. A camcfg
    failure gets `env:Receiver ter:Action`. Values come from rtspd's `get`, else cam.conf, else
    the defaults.
- `CreateProfile` stays unsupported (`ter:ActionNotSupported`). On the live run SSS tried it
  twice and went on with `Profile_1`/`Profile_2`, so that fault works. `ter:MaxNVTProfiles`
  would be the alternative if a client ever insists.

**Device:**
- `GetDeviceInformation`: Manufacturer `openlens-fw`, Model `IPC-D240W-S`, SerialNumber `0`.
- **NTP servers:** `cam.conf` `time.ntp`, comma-separated, at most 3, each `[A-Za-z0-9.-]{1,63}`
  (a host name or an IPv4 address). With no key, `time.cloudflare.com`; an empty value means
  no NTP. The NTP client (`ntpc`) reads the same key on every poll.
- `GetNTP`: `FromDHCP` false and the servers as `NTPManual` (`DNS`/`DNSname` or
  `IPv4`/`IPv4Address`).
- `SetNTP` (admin):
  - accepts `FromDHCP` false with 0–3 `NTPManual` entries of type DNS or IPv4;
  - refuses IPv6, `FromDHCP` true and more than 3 servers with `ter:InvalidArgVal`
    (`ter:InvalidArgs`), a bad name with `ter:InvalidDnsName`, a bad address with
    `ter:InvalidIPv4Address`;
  - saves with `camcfg set time.ntp <list>`.
- `GetSystemDateAndTime`: `DateTimeType` is `NTP` while any server is set (the default), else
  `Manual`. `TimeZone/TZ` is `cam.conf` `time.tz` (`src/README.md`, "Time zone"; `UTC0` without
  it or when it doesn't pass `tz.h`), XML-escaped (`&lt;+0530&gt;-5:30`). `UTCDateTime` is the
  clock; `LocalDateTime` is the same instant in that zone. `DaylightSavings` stays `false`: the TZ
  string carries the rule.
- `SetSystemDateAndTime` (admin):
  - Manual UTC: `settimeofday`, logged with the user. This doesn't switch NTP off; `SetNTP` with
    no servers does;
  - NTP: acknowledged, the clock is left to ntpc. `ter:NtpServerUndefined` when no server is set;
  - `TimeZone/TZ` (with either type): checked as camcfg checks `time.tz`; one it refuses (or over
    64 characters) gets `ter:InvalidArgVal/ter:InvalidTimeZone`, before anything is saved or the
    clock set. One that differs from the current zone is saved with `camcfg set time.tz` and sent
    to rtspd live (`set time.tz`, the OSD clock); a camcfg failure gets `env:Receiver ter:Action`.
    An empty or missing TZ changes nothing;
  - `DaylightSavings`: ignored.
- `GetRelayOutputs`: an empty list.
- The device capabilities say `NTP="3"`.

**Faults** follow SOAP 1.2 (`env:Sender` = HTTP 400, `env:Receiver` = 500):
- unknown operations: `ter:ActionNotSupported`;
- audio operations while `audio.enabled=0`: `ter:AudioNotSupported`, or for outputs and decoders
  `ter:AudioOutputNotSupported`;
- bad tokens: `ter:InvalidArgVal`/`ter:NoProfile`/`ter:NoConfig`;
- non-SOAP bodies: `ter:WellFormed`.

## Authentication
- **No credentials** on a protected operation: HTTP 401 with a Digest challenge and a
  `ter:NotAuthorized` fault body. An `Authorization` header of another scheme, such as a
  pre-emptive Basic, is ignored.
- **WS-Security UsernameToken:**
  - only `PasswordDigest` = Base64(SHA1(nonce + Created + password)). `PasswordText` is refused
    because it would put the password on the wire;
  - `Created` may be up to `-w` seconds (300) behind the camera clock and up to 30 s ahead;
  - **replays:** each nonce is remembered until its `Created` leaves the window, 2048 at most
    (64 KiB), 512 per user (an NVR sending a token every second, event pulls included, fits).
    Viewers together hold at most 1024 and viewers and operators together 1536 (Gate 3 #8), so
    whatever lower roles send, every operator keeps room for its 512 and every admin too (users of
    the same role share what is left). A full cache or share refuses the new token; nothing live is
    forgotten and no floor is raised;
  - **refused while the clock is unset**, meaning earlier than the image's build time
    (`-DBUILD_EPOCH`, from `rootfs/SOURCE_DATE_EPOCH`). The camera has no RTC, so every boot starts
    from the same time, and a token captured in an earlier boot would be fresh again. HTTP Digest
    works meanwhile;
  - **refused if created at or before a reset point:**
    - the moment camhttpd started, so a token can't be replayed after a respawn or a reboot;
    - the moment the clock became valid;
    - a `SetSystemDateAndTime`: both the time it was set to and the time it was before;
    - the clock's **high-water mark** (Gate 3 #7), while the clock is behind it. The cache forgets
      a token once the clock has passed its `Created` + 300 s; if ntpc (or anyone) then steps the
      clock back, that token would be inside the window again. So camhttpd keeps the latest second
      the clock has shown (checked every loop and on every token), and while the clock is below it,
      tokens created at or before it are refused;
    - the mark as saved before a restart: `time-floor` beside the users file (`-U`), written
      atomically (mode 0600) at most once an hour (NAND wear) and at a clean exit or a reboot,
      and read at start. After a crash or a power cut up to the last hour of it can be missing.

    What a client sees: after a start or the clock becoming valid, a token made in that second or
    before gets one refusal and its next one works. After the clock went back (a backward
    `SetSystemDateAndTime`, or ntpc correcting a fast clock), every token is refused until the clock
    has passed where it was before (the old time, or the mark): for as long as the step was, which
    for ntpc is usually seconds. HTTP Digest works throughout, and a refused token gets the 401
    with a Digest challenge. A clock that once ran far ahead (say a bad NTP answer) keeps
    UsernameToken refused until real time catches up, across reboots too; to undo that, delete
    `time-floor` over SSH and restart camhttpd;
  - a wrong password gets HTTP 400 `ter:NotAuthorized`. A token refused for any other reason
    (clock, window, replay, PasswordText) gets 401 with a Digest challenge and the same fault body,
    so a client can fall back to HTTP Digest.
- **HTTP Digest** (RFC 7616, MD5, `qop=auth` required), from the plaintext users file:
  - realm `camera`, the same as rtspd;
  - nonces need no state: time (plus a per-boot random offset, so they don't show the uptime), a
    counter and a SHA-1 keyed with a boot-random secret;
  - a nonce stays fresh for 300 s, then the reply says `stale=true`;
  - `nc` must increase for each nonce, and the `uri` must match the request target;
  - 64 nonces are tracked. When the cache is full, the oldest nonce and every nonce issued before
    it turn stale; that client retries with a new one;
  - the counter in a nonce is 32 bits. When it wraps (after 2^32 challenges) the nonce key changes
    and the nc cache and its floor start over (Gate 3 #6), so counting doesn't restart below the
    floor and leave every nonce stale for good; an outstanding nonce gets one more challenge;
  - a failure gets 401 with a new challenge.
- **Both given:** both must be valid, and the lower role counts.
- **PRE_AUTH operations** ignore credentials entirely, so a client with a wrong clock can still
  read the time.
- **Failures:** only a wrong password, or an unknown user, counts as a failure. Nothing refused
  before a password is compared counts.
- **Lockout:**
  - **Per address:** 5 failures from one IPv4 address within 60 s lock it until that minute is
    up. A locked address is never pushed out of the 32-entry table. If every entry is locked, new
    addresses count as locked too.
  - **All addresses:** 20 failures in 60 s stop the checks for every address except those where
    an **operator or admin** logged in successfully in the last 10 minutes (Gate 3 #3), so an NVR
    that is already logged in keeps working. Give SSS an operator or admin account for that.
    - A viewer's login exempts nothing: a viewer account on 8 addresses can't push the NVR out.
    - At most 8 addresses are exempt, and an entry younger than 10 minutes is never pushed out:
      when all 8 are, a ninth address isn't exempt until one ages.
    - A wrong password from an exempt address ends its exemption.
    - So a guesser rotating through addresses gets at most 20 tries a minute, plus at most one in
      all from each exempt address (28 in the first minute, 20 a minute after that; measured by
      the host test). The per-address limit applies to exempt addresses too.
  - **Cost of the global budget:** someone sending 20 wrong passwords a minute can keep a new
    client from adding the camera.
  - While locked or blocked, credentials aren't checked at all, so the lockout gives nothing away.
- **Hygiene:**
  - compares are constant time;
  - an unknown user costs the same hashing as a wrong password;
  - the log shows user names (sanitised) and addresses, never passwords;
  - `GetUsers` lists names and levels only.

**SSS and the clock:**
- The camera has no RTC, so after boot its clock is wrong until ntpc (#78) gets an answer or an
  admin sets it, and UsernameToken is refused until then.
- SSS has to use HTTP Digest, or set the time first. Its "sync time with the NAS" sends an admin
  `SetSystemDateAndTime`, which works over Digest.
- ONVIF clients are expected to read `GetSystemDateAndTime` (PRE_AUTH) and compute `Created` in
  camera time. Whether SSS does that, or falls back to Digest after a 401, is unverified.
- A larger `-w` tolerates clients whose clocks are behind, and widens the replay window.

**SSS's add / "load capacity" sequence** (live, cam #2, 2026-10-23):
1. GetCapabilities, GetServices, GetDeviceInformation, GetNetworkInterfaces.
2. GetVideoSourceConfigurations, GetGuaranteedNumberOfVideoEncoderInstances,
   GetVideoEncoderConfigurations, GetVideoEncoderConfigurationOptions.
3. GetServiceCapabilities, GetAudioEncoderConfigurationOptions, GetRelayOutputs, GetNTP,
   GetVideoSourceConfigurationOptions.
4. GetProfiles, CreateProfile (twice; the fault is fine), GetSnapshotUri.
5. To connect: GetProfiles, GetProfile, GetVideoEncoderConfiguration,
   GetVideoEncoderConfigurationOptions, then **SetVideoEncoderConfiguration before
   GetStreamUri**.

When SetVideoEncoderConfiguration failed (it used to be unsupported), SSS retried it 5 times, 2 s
apart, and gave up: "Disconnected: Updates are required. Please load the camera capacity
again". It never asked for a stream.

Now SSS's settings must lie inside the advertised options. If SSS asks for more (31 fps, or a
size we don't list, say), the fault comes back and the same symptom returns. A changed setting restarts rtspd once.

## Video orientation (Media ver10 `tt:Rotate`)

- `GetServiceCapabilities`: `Rotation="true"`. Every `tt:VideoSourceConfiguration` (Get, plural Get,
  profiles) carries `tt:Extension/tt:Rotate`: Mode ON with Degree 180 when `image.mirror` and
  `image.flip` are both 1, else Mode OFF with Degree 0 (mirror or flip alone isn't a rotation).
- `GetVideoSourceConfigurationOptions`: `tt:Extension/tt:Rotate` with Mode OFF/ON and DegreeList 180.
- `SetVideoSourceConfiguration` (operator): Bounds must stay the full picture. Rotate OFF (or ON 0)
  sets mirror and flip to 0; ON 180 sets both to 1, saved with camcfg and applied live. AUTO, 90
  and 270 get `ter:ConfigModify` (a real rotation is #123). Every Rotate received is logged.
- Stock reports `Rotation="false"` and ignores a Set (docs/STOCK-ONVIF-ORIENTATION.md).

## Imaging (ver20, `/onvif/imaging_service`, #103)
- **Source:** the values come live from rtspd's `get`. If rtspd isn't answering, they come from
  cam.conf, else the defaults (50, auto).
- **Mapping:**
  - Brightness → `image.brightness`, Contrast → `image.contrast`, ColorSaturation →
    `image.saturation`, Sharpness → `image.sharpness`, each 0..100;
  - IrCutFilter ↔ `daynight.mode`: **ON = the filter is in = `day`** (colour); **OFF = filter
    out = `night`**; AUTO = `auto`.
  - `image.exposure` isn't exposed: ONVIF Exposure is a different model.
- **GetImagingSettings / GetOptions:** VideoSource_1 only, otherwise `ter:NoSource`. The ranges
  are 0..100; the IrCutFilterModes are ON, OFF and AUTO.
- **SetImagingSettings** (operator+):
  - levels are xs:float, rounded; outside 0..100, or an unknown IrCutFilter, gives
    `ter:InvalidArgVal/ter:SettingsInvalid`;
  - each changed value is saved with `camcfg set <key> <v>`, then applied live with
    `set <key> <v>` over the control socket. If rtspd isn't answering, it picks them up at its
    next start;
  - camcfg also applies image/daynight keys live itself, so rtspd gets the value twice, which is
    harmless;
  - **ignored:** Exposure, Focus, WideDynamicRange, BacklightCompensation, WhiteBalance and
    ForcePersistence (logged with `-v`), because clients send back everything they read.
- **GetStatus / GetMoveOptions** return empty valid answers (no focus motor). **Move / Stop** get
  `ter:ActionNotSupported`.

## Events (ver10 PullPoint, `/onvif/event_service`, #77)
- **Topics** (GetEventProperties, `FixedTopicSet`, dialect ConcreteSet, ItemFilter):
  - `tns1:RuleEngine/CellMotionDetector/Motion`
    - Source: VideoSourceConfigurationToken `VideoSourceConfig_1`, VideoAnalyticsConfigurationToken
      `VideoAnalyticsConfig_1`, Rule `MyMotionDetectorRule` (the Analytics rule);
    - Data: `IsMotion`.
  - `tns1:VideoSource/MotionAlarm`
    - Source: `VideoSource_1`;
    - Data: `State`.
  - Both are properties.
- **CreatePullPointSubscription** (viewer+):
  - **Filter:** an optional `TopicExpression` on those topics is honoured (`|`, `*` for one level,
    `//.` for everything below). One naming neither topic means both; message-content filters
    are ignored.
  - **Lifetime:** `InitialTerminationTime` is a duration or a time, 60 s by default, 1 h at most.
    Each PullMessages extends it by that much again: stock grants a year and SSS never renews.
  - **Reply:** `SubscriptionReference` is `http://<addr>/onvif/event_service?sub=<16 random hex>`.
  - **Owner:** a subscription belongs to the user who created it (Gate 3 #10).
  - **Limit:** at most 2 subscriptions (an NVR needs one; held pulls must leave connection slots
    free). An expired one is reused first, else the creating user's own least recently pulled one
    that has no pull held; another user's live subscription is never taken, so a viewer can't
    push the NVR's out. If neither can be had (both live and another user's, or both the user's own
    with a pull held): `ter:Action` "Every subscription is in use". The cost: a client that keeps
    both slots (renewing or pulling) keeps other users from subscribing until they expire (at most
    1 h after its last renew or pull).
- **Addressing:** a subscription is named by `sub=` in the query string or in the `wsa:To` header.
  The id is not a credential: every call is authenticated as usual. An unknown or expired id
  gets 400 `ter:InvalidArgVal` with `wsrf-r:ResourceUnknownFault` in the Detail, and so do
  PullMessages, Renew and Unsubscribe by any user but its owner (an admin's too).
- **PullMessages:**
  - `Timeout` is held for up to 10 s. **One message per response**, as stock sends; while more
    wait (up to 8, oldest dropped), the next pull is answered at once.
  - **Answered at once:** when there is news, when Timeout is 0, or when another pull on the
    same subscription is already held.
  - **Otherwise held** without blocking the loop. rtspd is polled (`motion`) every 500 ms while
    any pull is held. The pull is answered as soon as the state changes (`PropertyOperation`
    Changed, `UtcTime` = now − `motion.since`), or at its Timeout with no messages (CurrentTime,
    TerminationTime).
  - **Every message is `Changed`**, as stock (SSS didn't report "by camera" events with
    `Initialized` first). The first pull after a subscribe, or after SetSynchronizationPoint,
    reports motion only if it is on.
  - **Edges missed between pulls** (`motion.seq` counts rising edges) come back as at most
    false, true, false per topic, cell motion before the motion alarm. A seq lower than the last
    one means rtspd restarted, and only a state change is reported.
  - **While rtspd doesn't answer `motion`**, nothing is reported.
- **Renew** (default 60 s, at most 1 h), **Unsubscribe** (a pull held on that subscription gets
  the fault) and **SetSynchronizationPoint**.
- **Event replies** carry a `wsa:Action` header.

**Not yet seen with SSS** (check in a chroot run with `camhttpd -v`):
- **The camera-motion source:** whether SSS's "camera motion detection" option shows up and
  which topic it uses: CellMotionDetector/IsMotion (what most cameras send) or
  VideoSource/MotionAlarm.
- **Events plumbing:** whether it subscribes with a filter, its PullMessages Timeout (we hold for
  10 s at most), and whether it wants `wsa:RelatesTo` or a `SubscriptionReference` inside each
  message (neither is sent).
- **Imaging:** whether its sliders use Get/SetImagingSettings (0..100) at all, or need
  Exposure/WhiteBalance to be present.

## Analytics (ver20, `/onvif/analytics_service`, #77): the motion detection area
SSS draws the camera-side motion area from the CellMotionEngine layout and edits the
CellMotionDetector rule's `ActiveCells`. Both map onto rtspd's motion detector:
- **The module:** `MyCellMotionModule`, type `tt:CellMotionEngine`.
  - SimpleItem `Sensitivity` (0..100) is `motion.sensitivity`.
  - ElementItem `Layout` is `<tt:CellLayout Columns="32" Rows="32">` with Translate x=-1 y=-1 and
    Scale x=y=0.0625 (2/32). That puts cell (c, r) at -1 + c·2/32, -1 + r·2/32 of the normalized
    frame, the Hikvision-style convention.
- **The rule:** `MyMotionDetectorRule`, type `tt:CellMotionDetector`, with SimpleItems:
  - `ActiveCells` is `motion.mask`: base64 of PackBits (Apple/TIFF) of the 32×32 bitmap,
    row-major from the top-left, MSB first. All cells active is `gf8=` (PackBits `81 ff`).
  - `MinCount` 1, `AlarmOnDelay` 400, `AlarmOffDelay` 5000 describe rtspd's detector (about 2 of
    3 evaluations 200 ms apart to start, 5 s without motion to end). Values a client sends must
    be whole numbers and are otherwise **ignored**; GetRules keeps reporting these.
- **Media ver10:** both profiles carry a VideoAnalyticsConfiguration `VideoAnalyticsConfig_1` (the
  token Events already names), with that module and rule.
  - GetVideoAnalyticsConfiguration(s) and GetCompatibleVideoAnalyticsConfigurations return it.
  - AddVideoAnalyticsConfiguration with our token is a no-op success.
  - SetVideoAnalyticsConfiguration changes the module and rule like the Modify operations.
- **ModifyRules** (operator+):
  - **Decoding:** ActiveCells is base64 with the `=` padding optional (the spec's own example has
    too much of it), then PackBits decoded strictly: every packet must fit, and the result must
    be exactly 128 bytes.
  - **Refusals:** a bad ActiveCells or rule type, or a non-numeric MinCount, gets
    `ter:InvalidArgVal/ter:InvalidRule`; another rule name gets `ter:RuleNotExistent`; another
    configuration token gets `ter:NoConfig`. Nothing is saved or applied then.
  - **Changes:** a changed mask is saved (`camcfg set motion.mask <hex>`) and applied live
    (`set motion.mask <hex>`); an unchanged one does nothing.
- **CreateRules** for our rule name behaves like ModifyRules: the one rule always exists. Another
  name gets `ter:Action/ter:TooManyRules`. **DeleteRules** gets ActionNotSupported.
- **ModifyAnalyticsModules** (operator+): Sensitivity only (rounded). A Layout must be our 32×32
  grid, otherwise `ter:InvalidModule`; another module name gets `ter:ModuleNotExistent`.
- `motion.enabled` isn't exposed: switching camera-side detection off is a camcfg setting.
- **Reading:** values come live from rtspd's `get` (about 1.2 KiB now; read with a 4 KiB buffer),
  else from cam.conf (its 268-character `motion.mask` line is read whole), else the defaults (on,
  50, every cell).

**Not yet seen with SSS:** see the end of the Events section, plus:
- whether SSS's area editor appears with this layout (32×32, the Hikvision-style transformation);
- whether it sends ModifyRules or Media's SetVideoAnalyticsConfiguration;
- whether it needs GetRuleOptions or GetAnalyticsModuleOptions (`RuleOptionsSupported` and
  `AnalyticsModuleOptionsSupported` say false; both get ActionNotSupported);
- **orientation:** whether SSS draws mask row 0 (rtspd's top row) at the top. The layout uses a
  positive y Scale like Hikvision, but ONVIF's normalized y points up. Check it by setting one
  top-left cell in SSS and reading `motion.mask` (it should start `80`).

## Snapshot (`GET /snapshot.jpg`, HTTP Digest, viewer+)
`Host` must be the camera's address (421 otherwise, see [HTTP](#http)); `GetSnapshotUri` gives
that address, so an NVR that uses the URI as given sends it.
1. camhttpd sends `snapshot\n` to rtspd's control socket. **rtspd must answer within 500 ms in
   all**; the loop blocks meanwhile. It asks rtspd at most once a second: requests in between get
   the same JPEG, or the same 503.
2. rtspd writes `/run/cam/snapshot.jpg` atomically and replies `ok <bytes>\n` (`ok\n` is accepted
   too).
3. camhttpd opens the file:
   - `O_NOFOLLOW`, regular files only, at most 8 MiB;
   - the size must equal `<bytes>`.
4. It streams the file as `image/jpeg`, `Cache-Control: no-store`.

An `err …` reply, no rtspd or a bad file gets 503 with `Retry-After: 2`.

## Web UI (#79)
Synology Surveillance Station has no image controls for this camera, so these pages are the
place for image settings, and for the rest of the camera's settings short of SSH.

- **Shape:** server-rendered HTML, plain forms (GET pages, POST `application/x-www-form-urlencoded`),
  one stylesheet (`/ui.css`) and one small script (`/ui.js`), both compiled in and served without a
  login (they hold no secrets). No inline script; every page works without `/ui.js`. Single column, a viewport meta, so it works on a phone. Every POST answers with the
  same page and the outcome at the top.
- **Pages and roles** (the ONVIF classes; links a role can't use are hidden, and the server
  refuses them with 403 anyway):

  | Path | Role | What |
  |---|---|---|
  | `/ui/` | viewer | Status: firmware (`/etc/cam/version`), uptime, time (UTC), local time (`time.tz`: zone abbreviation, offset, and whether daylight saving is in effect) and NTP, day/night, motion, streams, memory, network (IP, mask, gateway, DNS, MAC; read-only, #80), `/snapshot.jpg` |
  | `/ui/image` | operator | a preview (`/snapshot.jpg` reloaded about once a second by `/ui.js`; without scripts a link to `/preview.mjpg`); grouped: **Picture** brightness, contrast, saturation, sharpness, exposure (0..100); **Orientation** mirror and flip, Off/On (`image.mirror`/`image.flip`; Off/Off = stock's picture; 90° rotation is #123; a motion area drawn in SSS applies to the picture as shown); **Day/night** mode auto/day/night, "Switch to night below" / "Back to day above" (`daynight.night_below`/`day_above`, 1..1000000, night below day, with the score explained and its current value), IR LED %, **Exposure at night** "Same as day" / "Own value" with a slider 0..100 (`image.exposure_night`: `day` or the slider's value; while it is the same as by day the slider shows the day exposure; a note suggests 30 for a street-lit scene washed out at night), and a **Stock night tuning** checkbox (`image.night_tuning`, off by default: stock's night IQ groups at night, stronger noise reduction, softer sharpening, darker shadows; unticked = off, as browsers leave an unticked box out); **Exposure** longest shutter by day (Automatic, 1/25..1/10000 s) and at night (Automatic = 1/20 s as stock, 1/25, 1/50, 1/100 s; no 1/12 s, which would lower the frame rate) (`image.shutter_*_max`, µs). A shutter value set elsewhere (camcfg) is shown as its own choice, so applying the form keeps it; **Advanced** 2D and 3D noise reduction (`image.nr2d`/`nr3d`, sliders 0..255, 128 = as tuned), wide dynamic range Off (as tuned) / On with a strength slider 1..255 (one setting, `image.wdr`: Off sends 0, On the strength; 128 = as tuned), backlight compensation 0..255 (`image.blc`, only with WDR off; 0 = as tuned), mains frequency 50/60 Hz (`image.mains_hz`) and anti-flicker Off/On (`image.antiflicker`), with notes on each (docs/STOCK-IMAGE-TUNING.md). Saved with camcfg and applied live, as SetImagingSettings does; the two thresholds are sent in the order that keeps night below day at each step |
  | `/ui/osd` | operator | The overlays, with the same preview as the Image page (the JPEG channel carries the sub-stream's overlay): **Date and time** show, place (corners or custom across/down 0..100), date format, 24/12-hour clock, weekday, and a note that the clock shows local time with the zone on the Time page (a link for an admin); **Title** show, text (up to 48 printable ASCII characters), place; **Look** size (small/medium/large) and style (white with a black outline, black on white, white on black). A `data-live` form: a choice applies when picked, text and numbers with Apply. Saved key by key with camcfg and applied live, as SetOSD does. Shows a warning when rtspd's `osd.status` is `failed` |
  | `/ui/streams` | operator | Main/sub size (a select of `stream.<main|sub>.size`'s values), codec, kbps (an unset one shown as its size's default, labelled so, and left unset when not changed), fps (1..30; the sub's at most the main's: a higher one is saved as the main's), GOP, H.264 profile, in SetVideoEncoderConfiguration's limits; saved key by key with camcfg, and rtspd restarts once only if something changed (at most once per 10 s: within 10 s of the last restart the change is saved and the page says in how many seconds the video restarts with it). The page warns that SSS reconnects slowly and may push its own values back |
  | `/ui/motion` | operator | Motion detection on/off and sensitivity (live); microphone on/off and gain (rtspd reads these at start, so a change restarts it, with the same 10 s rule); `motion map` read-only (the area is drawn in SSS) |
  | `/ui/time` | admin | The time in UTC and local time (as on Status). `time.ntp`, validated as SetNTP does (up to 3 host names or IPv4 addresses; empty = NTP off). **Time zone** (`time.tz`, its own form): a select grouped North America (Hawaii, Alaska, Pacific, Mountain, Arizona, Central, Eastern, Atlantic, Newfoundland), Europe (UK/Ireland, Central, Eastern, Moscow), Asia and Pacific (India, China/Singapore, Japan/Korea, Sydney, New Zealand), fixed whole-hour offsets UTC−12..UTC+14 without daylight saving (`<-05>5`, `UTC0`, `<+01>-1`), and Custom with a POSIX TZ field (shown filled when the zone isn't in the list). A preset must be one of the list; Custom is checked by `tz.h` as camcfg checks it. Saved with `camcfg set time.tz` and applied live (rtspd's OSD clock, camhttpd's own local time); the reply gives the new local time and whether daylight saving is in effect |
  | `/ui/users` | admin | List (name, role), add, change password, change role, delete, through `camcfg user …` with the password on stdin (never argv). Refused here: two different password fields, a 17th user (camhttpd reads 16), deleting yourself, deleting or demoting the last admin |
  | `/ui/ssh` | admin | `camcfg sshkey list/add/del` on `/mnt/nand/cam/ssh/authorized_keys` (= `/root/.ssh`): type, SHA256 fingerprint, comment; add one line; delete (the form carries the fingerprint, so a list that changed meanwhile deletes nothing) |
  | `/ui/system` | admin | **Firmware update** (see [Firmware update](#firmware-update-from-the-web-ui-104)): upload a signed `.camfw`, see camupdate's verdict beside the installed version, then Install or Discard. **Reboot**, with a confirm box: the reply goes out first, then `sync()` and `reboot(RB_AUTOBOOT)` (3 s at most later). Both cameras run our firmware from flash, so a reboot comes back on it |

- **Passwords and keys:** camcfg is the one place that checks them (see its top comment); the
  page shows camcfg's own message. Password policy: 8..64 characters, never shortened; printable
  ASCII only, every symbol allowed (`:` `"` `\` `&` `<` `%` `+` `@` `#` `'` and space); no space at
  either end; not the user name. The users file is split on its first two colons everywhere, so
  `:` round-trips. No account is built in: a camera without an admin serves only `/setup` (see
  below).
- **HTTPS:** with camtls running the pages are at `https://<address>/ui/`; port 80 redirects
  there and refuses POSTs (see [HTTPS](#https-through-camtls-docsplan-tlsmd-b)).
- **Auth:** HTTP Digest, the same users, realm, nonces and lockout as `/snapshot.jpg`. Only by the
  camera's address: another `Host` gets 421 before the login (DNS rebinding, see [HTTP](#http)).
- **CSRF** (browsers resend Digest credentials to us from any site): every POST needs
  1. an `Origin`, or without one a `Referer`, of `http://<its own Host>` (`https://` on a
     connection from camtls; exactly that scheme, host and port; `Origin: null`, two Origins,
     another scheme or port are refused);
  2. a hidden `csrf` field: HMAC-SHA1 (the SHA-1 camhttpd already has) under a per-start random
     key, of the user name and the 15-minute bucket of the monotonic clock (NTP stepping the clock
     can't expire or revive one). The current and the previous bucket count, so a page works for
     15 to 30 minutes.

  Otherwise 403 and a log line (address, user, path, why). Order: credentials, role, Origin,
  body size (413), `Content-Type` (415 if not a form), form syntax (400), token.
- **Forms:** at most 8 KiB, at most 36 fields (the Image form sends 35); names `[a-z0-9_]{1,24}`, no name twice, no empty
  pair; values `+` and `%XX` (a bad `%` or `%00` is refused) or printable ASCII. Other decoded
  bytes reach the handler, which refuses them (camcfg for passwords and keys, with its reason).
  The form, which may hold a password, is wiped after each POST.
- **Headers on every UI reply** (pages, errors, challenges, `/ui.css`, the preview):
  `Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self';
  connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Cache-Control: no-store`. Every echoed value is HTML-escaped.
- **Slider pairs:** `/ui.js` keeps a range input and its number field in step while dragging.
  Without it the number counts when it was changed from the shown value, else the slider.
- **Live image settings:** the Image form is marked `data-live`. `/ui.js` POSTs it (same origin,
  same CSRF token) when a slider is released or a choice (day/night mode, exposure at night, mirror, flip,
  shutter, WDR, mains, anti-flicker) or a checkbox (stock night tuning) changes;
  the threshold number fields apply with Apply (or with the next slider or choice), so the preview shows the
  change without Save, and shows "Applied." or why not (a 403 after 30 minutes: reload).
- **Users:** the role and delete forms never offer you or the last admin; the server refuses
  changing your own role, deleting yourself, and demoting or deleting the last admin.
- **`GET /preview.mjpg`** (viewer+; linked from the Image page when scripts are off: Safari in
  Lockdown Mode held the stream but drew it grey, so the page itself reloads `/snapshot.jpg`): `multipart/x-mixed-replace; boundary=camframe`,
  one `image/jpeg` part (with Content-Length) per JPEG from the same source as `/snapshot.jpg`
  (rtspd's `snapshot`, shared, so both together ask rtspd at most once a second; rtspd refuses a
  JPEG older than 5 s, and then nothing is sent).
  - About one frame a second, only when the JPEG is new; an unchanged one goes again at most every
    3 s.
  - **Slot budget:** at most **1** preview (a second gets 503 "one preview at a time"), closed after
    **5 minutes** (the page says to reload). SSS holds up to 2 pulls, the preview 1 and a firmware
    upload 1, so two of the 6 connection slots always stay for ONVIF requests and the browser
    (`_Static_assert` in the code), and slot
    eviction only takes a connection whose request isn't complete (so never these).
  - Never blocks the loop: a frame goes out through the normal non-blocking send path, and the
    next one is only read once the last is fully sent, so a slow reader misses frames instead of
    queueing them. The Status page keeps the static `/snapshot.jpg`, so it doesn't take the slot.
- **Files read for Status:** `/etc/cam/version` (else the build's `FW_VERSION`), `/proc/uptime`,
  `/proc/meminfo`, `/proc/net/route` (the default route on `-i`), `/etc/resolv.conf`.
- **camcfg's directory:** users go through `camcfg -d <the -U file's directory>`, so the file must
  be named `users` there (as it is by default); SSH keys and settings through `-c`'s directory.
- **Browsers:** a page loads up to four things at once (page, CSS, script, snapshot or preview),
  which fits `PER_PEER` 4. Parallel requests on one Digest nonce may arrive with `nc` out of order; the
  late one gets a `stale=true` 401 and the browser retries it with a new nonce.

## Firmware update from the web UI (#104)
The System page's half of docs/UPDATE-PATH.md "Delivery": upload, `camupdate --check`, the version
and signer, confirm, install. camupdate does every check of the package; camhttpd only carries the
file to it, shows its verdict and starts it.

- **Transport:** `/ui.js` sends the file as the raw body of `POST /ui/firmware`
  (`Content-Type: application/octet-stream`, the page's form token in `X-CSRF-Token`). No multipart:
  the codebase has no multipart parser and doesn't need one, a raw body is the file byte for byte,
  and the custom header can't come from another site's form. The CSP is unchanged
  (`connect-src 'self'`). Without the script the page says to use SSH. Before the POST, `/ui.js`
  GETs `/ui/firmware` (admin): it renews the browser's Digest nonce and answers 409 while another
  upload or an install is under way, so megabytes aren't sent only to be refused.
- **Checks, all from the headers, before any of the body is read** (each refusal is the usual
  reply, and the 403s are logged):
  0. `Host` the camera's address (421);
  1. credentials (401), admin (403);
  2. `Origin`, or without one `Referer`, of the request's own Host (403);
  3. `X-CSRF-Token`: exactly one, the user's token as for forms (403);
  4. `Content-Type` exactly `application/octet-stream` (415);
  5. `Content-Length`, parsed by the usual strict parser (one, digits, at most 7: else 400;
     chunked: 501), present and not 0 (411), at most **5 MiB** (413);
  6. no other upload being received or checked, no install, no reboot pending (409);
  7. `MemAvailable` (`/proc/meminfo`) at least twice the file plus 2 MiB (507): the staged file
     and camupdate's copy of it in RAM.

  Only then a `100 Continue` (if asked) and the body.
- **Staging:** `/run/fw/upload.camfw`, a fixed name (nothing from the client reaches a path), mode
  0600, `O_EXCL|O_NOFOLLOW`, in `/run/fw`: a tmpfs of its own (rcS: mode 0700, size 6 MiB). Not
  `/tmp` (4 MiB): a 3.5 MB package there would leave camupdate no room for the copy of itself it
  installs from (`/tmp/camupdate.run`, about 540 KB). The mount's size is a backstop for camhttpd's
  5 MiB cap; tmpfs uses RAM only for what it holds. Our image is about 3.4 MiB.
- **Streaming:** the body goes from `recv` straight to the file (64 KiB at a time, the connection's
  own buffer); nothing past `Content-Length` is read. Time limits: the usual body rule (5 s plus 1 s
  per 4 KiB, so about 15 minutes for 3.5 MB) and 30 s without a byte. One slot (the
  `_Static_assert` counts it beside 2 held pulls and the preview, so a slot stays for ONVIF), never
  evicted, and the loop goes on serving everything else between reads.
- **Deleted on:** a lost connection or timeout mid-body, a write error (507), camupdate's refusal,
  a check that takes over 60 s (killed), Discard, a new upload, 15 minutes without Install, an
  install that ends without a reboot, and a restart of camhttpd.
- **Check:** `camupdate --check /run/fw/upload.camfw` (fork/exec of `/usr/sbin/camupdate`, a fixed
  argv, no shell, an environment of `PATH` only, stdout and stderr into a pipe), beside the loop: the
  upload's connection waits, nothing else does. The reply is camupdate's verdict as text:
  - exit 0 with `camupdate: OK: version V for DEV, N bytes, signed by S`: 200, and the file is
    kept;
  - the same with ` (downgrade allowed)`: 422, refused. The owner's decision (2026-10-24): the web UI
    never installs a package signed to allow a downgrade. `camupdate` over SSH still does;
  - anything else: 422 `REFUSED: ` and camupdate's reason (its `REFUSED:` line, or "camupdate
    isn't installed", "took longer than 60 s", "answer wasn't understood"); the file is deleted and
    the System page says why (escaped).

  `/ui.js` shows the text and, on 200, reloads the page.
- **Confirm:** the page shows the installed version (`/etc/cam/version`) and the new version,
  device, signer, payload and package size, and who uploaded it. Install is a form (CSRF and admin as every form) with a confirm box and the upload's
  id (16 random hex digits, new for each upload), and only the admin who uploaded it gets it.
  Install is refused for another id (a page of an earlier or replaced upload: 409), another admin
  (403), no checked upload (409), or a reboot pending; the file must still have the size and the
  SHA-1 taken while it streamed in, or it is deleted. Any admin may Discard.
- **Install:** the reply ("Installing V… about 1 to 2 minutes; reload this page then. Settings,
  users and keys are kept.") goes out first, then (once its connection has closed, or 3 s on)
  `camupdate /run/fw/upload.camfw` starts detached: fork, `setsid`, fork again, the middle process
  exits, stdin `/dev/null`, stdout and stderr to `/run/fw/install.log`, `PATH` only. The double
  fork matters: camupdate spares its ancestors when it SIGSTOPs every process, so as a plain child
  it would leave camhttpd and camhttpd-run running from the flash it rewrites; detached, it stops
  them too. Until the reboot the System page says it is installing, and uploads and Reboot get 409.
  If camupdate exits instead (it can only do that before it stops us, so before it writes), the page
  shows its last line and the file is deleted. camhttpd sees that end as EOF on a pipe whose only
  write end camupdate inherits (the one descriptor left open across its exec; Gate 3 #13), not by
  `kill(pid, 0)` on a process that isn't its child, which a zombie or a reused pid would fool.
- **Log lines** (with the address and the user): the upload and its size; the verdict (version,
  device, size, signer) or camupdate's refusal; a cancelled or failed upload; a refusal for size,
  memory or a busy camera; Discard, expiry, replacement; the confirmed install with version and
  signer; camupdate's start (pid) and, if it happens, its end without a reboot.
- **Not here:** camupdate's environment overrides exist only in its `CAMUPDATE_TEST` build, and
  camhttpd passes none.

## Settings backup (#172, #173)
`docs/PLAN-DATA-LOCK.md` Part 1; the file format and every check on it are camcfg's
(`camcfg backup export|import`, src/camcfg). camhttpd's monitor runs camcfg (fixed argv, the
passphrase on its stdin, `PATH` only); the worker never touches DATA.
- **Transport:** on the System page, HTTPS only (`c->tls`): over plain HTTP the page says to use
  https:// or SSH and both POSTs are refused (403) without running anything. The file and its
  passphrase together give every password and the CA key, and SSH can do the same without camtls,
  so there is no plain-HTTP fallback here. `/setup/restore` follows `/setup`: HTTPS while camtls is
  up (port 80 refuses its POST), plain HTTP while camtls is down (the claim's fallback, logged).
- **Download** (System page, admin): the form (`do=backup`, the passphrase twice) posts to
  `/ui/system`. Busy (firmware install, reboot) gives 409. The monitor's `bk-export` hands back the
  `.cambak` as an fd, served as `application/octet-stream` with
  `Content-Disposition: attachment; filename="camera-<address>-<YYYYMMDD>.cambak"` (UTC date) and
  `Cache-Control: no-store`, streamed like the snapshot. camcfg's refusal (a short passphrase, an
  unclaimed camera) shows on the page. Logged: `ADDRESS: settings backup downloaded by USER (N bytes)`.
- **Restore** (System page, admin): a `multipart/form-data` form (`csrf`, `file`, `pp`, and `pw`,
  the admin's own password again) posts to `/ui/backup-restore`. Checked in order: credentials,
  admin, `Origin`/`Referer`, multipart (strict: `mp_parse`), the user's token; then HTTPS, busy, the
  file (1 byte to 48 KiB: the whole request is buffered, `REQ_CAP`; larger backups restore over
  SSH), the passphrase and password one line. The worker stages the file as
  `/run/fw/restore.cambak` (`O_EXCL`, `O_NOFOLLOW`) and calls `bk-restore`, then deletes it, and
  wipes the request body. A wrong password (`Wrong password: nothing was restored.`) or passphrase
  (camcfg's exit 3) counts as a failed login. Success: the page says the camera reboots (its forms
  hidden), the monitor reboots it 3 s later, and a second restore meanwhile is refused.
- **At the claim (#173):** after `/setup` over HTTPS, the page with the recovery code also offers
  the download form (passphrase twice), posting to `/ui/system` with a token made for the new
  admin; the browser asks for the new login as it posts. It can be skipped; it says a backup is a
  snapshot. Over plain HTTP (camtls down) the page only points to the System page or SSH.
- **Restore instead of a claim (#173):** `/setup` has a second form, `multipart/form-data` to
  `/setup/restore` (`csrf` over "/setup", `file`, `pp`). Checked: a locked-out address first (429,
  nothing run), Host, `Origin`/`Referer`, multipart, token, the claim rate (10 a minute), the file
  and passphrase; the monitor's `bk-setup` checks again that no admin exists, the window and its own
  rate. A wrong passphrase counts as a failed login. Success: a "Restored" page (log in with the
  backup's admin after the reboot); the camera comes back claimed. On a claimed camera the path is
  a 404.

## Lock mode (#175; docs/PLAN-DATA-LOCK.md Parts 2 and 3)
When rcS finds DATA failed it writes `/run/data-failed` (the reason, one line). While it exists:
- **Every path is the lock page** (503, no login): the web UI's style and script, an alert that the
  camera is locked because DATA is corrupt, the reason, and the ways back: the form below,
  `scripts/cam-recover.py`, SSH with an update key (`camcfg unlock restore -` / `unlock erase`),
  and "no backup? erase and claim fresh". `/ui.css` and `/ui.js` are served; `/snapshot.jpg` and
  `/preview.mjpg` are 503; ONVIF answers a fault ("The camera is locked: its storage failed"); a
  POST anywhere else is 403; a request by name is answered only at the camera's address (421).
- **The challenge:** the monitor's `unlock-ch` keeps one: 32 random bytes, 10 minutes, with the
  device ID and firmware from `camcfg unlock info` (asked once). The page shows them (the form's
  `data-*`), and `GET /unlock/challenge` returns `challenge HEX`, `device ID`, `firmware VERSION`,
  `expires-in SECONDS` as text (`no-store`) for `cam-recover.py`. A GET doesn't replace a valid one.
- **The form** (ui.js): restore or erase, the backup file, its passphrase, the signature. It shows
  the message to sign (`cam-recover 1` / challenge / device / firmware / action / backup SHA-256,
  hashed in the browser: HTTPS only) and POSTs `/unlock`: the raw body camcfg unlock reads (the
  passphrase line, the signature, the backup), `application/octet-stream`, with
  `X-Unlock-Action` and `X-Unlock-Challenge`. The worker checks `Origin`, the type, both headers and
  the size (1 byte to 60 KiB), stages the body as `/run/fw/unlock.bin` (`O_EXCL`, `O_NOFOLLOW`),
  wipes it from the connection, and calls `unlock`.
- **`unlock` (monitor):** lock mode, the lockout, no reboot under way, the claim rate, then the
  challenge (the current one, unexpired, compared in constant time; spent by any attempt). It opens
  the staged file itself (`O_NOFOLLOW`; a regular file, one link) and runs
  `camcfg unlock ACTION -c CHALLENGE [-]` with it as stdin, up to 120 s (Argon2id, erasing 1 MiB of
  NOR, writing). Exit 3 (a bad signature or passphrase) counts as a failed login; success reboots
  the camera 3 s later (the monitor's tick). The reply is camcfg's line as text: 200 `ok: ...`,
  403 `refused: ...`, 429 once the address is locked out.
- **Also refused while locked:** `claim`, `recover` and `bk-setup` (the monitor's own check, as well
  as camcfg's).
- **Port 80** sends `/unlock` and `/unlock/challenge` to HTTPS while camtls is up (it runs with a
  throwaway CA in lock mode); `/unlock`'s POST on 80 is then 403.

## First-boot claim and admin recovery (#128)
The design, the threat model and the bench workflow are in `docs/CLAIM.md`; this is camhttpd's
part.
- **Claimed** = the users file (`-U`) has an admin; read on every request.
- **HTTPS:** while camtls is up, `/setup` and `/recover` exist only over HTTPS: port 80 redirects
  a GET there and refuses a POST (403), so the claim password and the recovery code don't cross in
  clear. Without camtls's ready file (owner's fallback) both work on port 80 as before, logged at
  most once a minute (see [HTTPS](#https-through-camtls-docsplan-tlsmd-b)).
- **Unclaimed:** ONVIF answers every operation (PRE_AUTH too) with `ter:NotAuthorized` "The camera
  is not set up yet: claim it in a browser at /setup"; `/snapshot.jpg` and `/preview.mjpg` 503.
  For the first 30 minutes after power-on (`/proc/uptime`, which NTP doesn't move; unreadable =
  closed) `GET`/`POST /setup` and `GET /ui.css` are served and every other path gets a 302 to
  `/setup`; after that, every path gets one 503 page saying to power-cycle the camera and claim it
  within 30 minutes. The start log says when the camera is unclaimed.
- **`/setup`:** a form (admin name, password twice, optional SSH public key line). A POST is
  checked in this order: `Origin`/`Referer` of the request's own Host, size, form type, form
  syntax, a `csrf` token keyed with the per-start `ui_key` over "/setup" and the 15-minute
  bucket (no user exists yet; a user's or `/recover`'s token is refused), and then the shared
  rate limit (10 setup/recover POSTs a minute from all addresses, then 429). Only a POST that
  passed the other checks counts against it (Gate 3 #5), so another site's page can't use it up
  and keep the owner from claiming or recovering. The `Host` must be the
  address the connection came in on (`c->local`, `:port` optional on 80), else 421 with a link to
  it (DNS rebinding). Then: both passwords equal, password and key one line of printable ASCII,
  and `camcfg -d <users dir> claim NAME` with "password\nkey\n" on stdin. camcfg refuses once an
  admin exists, checks everything, and prints `recovery-code: XXXX-…` (notes on stderr may come
  with it). The reply shows the code once (`<p class="code" id="code">`, which
  `scripts/cam-claim.py` parses) with a link to `/ui/`; camcfg's refusal is shown escaped. Logged:
  `ADDRESS: camera claimed: admin NAME[, SSH key added]` (the name cleaned), never the password or
  the code. Once claimed, `/setup` is a 404.
- **`/recover`** (claimed cameras): outside the 30 minutes after power-on a 403 page says to
  power-cycle. Inside, the same Host check, then a form: admin name (empty = the admin the code was
  made for), code, new password twice. A POST from a locked-out address (the login lockout) gets
  429 without running camcfg; otherwise the same checks as `/setup` with its own token, then
  `camcfg recover [NAME]` with "code\npassword\n" on stdin. Exit 3 (a wrong code, or none) counts
  as a failed login (`auth_failed`: 5 a minute lock the address for codes and logins alike) and
  shows "Wrong recovery code."; exit 0 shows the new code once and logs
  `ADDRESS: admin NAME's password reset with the recovery code; a new code was issued`; camcfg's
  other refusals (no such admin, the password policy) are shown and don't count.
- **Files:** camcfg writes `users`, `recovery` and `ssh/authorized_keys` in the users file's
  directory. camhttpd writes two files of its own there (Gate 3 #7, #9), each atomically (a 0600
  temporary file, fsync, rename): `epr-secret` once per camera and `time-floor` at most once an
  hour; see [Authentication](#authentication) and [WS-Discovery](#ws-discovery-udp-3702--d-to-disable).
  AGENTS.md says camcfg is the only writer of `/mnt/nand/cam`: these two are the owner's call
  (they hold no setting, and camcfg has no command for them yet).

## WS-Discovery (UDP 3702, `-D` to disable)
- **Joining:** every 5 s camhttpd checks the interface's IPv4 address. It joins 239.255.255.250
  there (TTL 1), and sends `Hello` on the first join and on each address change. `Bye` goes out at
  exit.
- **Who gets answers:** only senders in eth0's IPv4 subnet, because UDP doesn't verify the
  source and a reply to a forged one would be reflection. A client on a routed subnet can't
  discover the camera; it adds it by address. With a netmask of 0 or shorter than /8 "the subnet"
  would be most of the Internet, so then no Probe is answered (logged once; Gate 3 #12).
- **Limits:** checked before any parsing:
  - 2 replies a second per address, 8 addresses a second, 20 replies a second in all;
  - a Probe under 200 bytes is ignored (no real one is that short), so a reply is never much
    bigger than the request.
- **Probes:** a matching Probe gets a unicast `ProbeMatches` back to the sender. A Probe matches
  when:
  - its `Types` are empty or only `dn:NetworkVideoTransmitter` / `tds:Device`, with the prefixes
    resolved to the ONVIF namespaces (Windows' `wsdp:Device` gets no reply);
  - its `Scopes` match ours (`rfc3986` prefix by segment, or `strcmp0`);
  - its `MessageID` is plain (it is echoed back).
- **XAddrs:** `http://<eth0 IPv4>/onvif/device_service`; while HTTPS is up also the `https://`
  one, after it (only it with `net.plain=0`).
- **EndpointReference:** `urn:uuid:` + a version-5-style UUID of HMAC-SHA1(key,
  "openlens-fw/onvif/" + MAC; "cam-firmware-dev/onvif/" before 2026-11-12), the key being 32 random bytes made from `/dev/urandom` on the
  first start and kept in `epr-secret` beside the users file (mode 0600, written atomically; Gate
  3 #9). It is stable across reboots and unique per camera, and without the key the MAC can't be
  found from it. (The earlier unkeyed SHA-1 fell to a sweep of the 2^24 addresses under the
  vendor's OUI in seconds.) **This changes the EPR once**, at the first start of this version; an
  NVR that keyed the camera by its EPR may list it again (SSS adds cameras by address). If the file
  can't be read or written (or isn't 32 bytes, which is left alone), camhttpd logs that once and
  falls back to the unkeyed SHA-1.

## Privilege separation (Gate 3, docs/CAMHTTPD-PRIVSEP.md)
camhttpd parses the network, and it checks every password itself (WS-UsernameToken needs them in
the clear), so a parser bug running as root, or even as a user that could read the users file,
would be everything. With `-Z USER` it splits:

| | Monitor (parent, root) | Worker (child, `-Z`'s user, group `camctl`) |
|---|---|---|
| holds | the users file (read on each login), the Digest nonce key and `nc` cache, the UsernameToken replay cache, clock floor and `time-floor`, the lockout, the grants | the account list as names and roles; the EndpointReference string (made by root before the fork, its key wiped); the CSRF key (per start) |
| does | every authentication; camcfg (`set`, `user`, `sshkey`, `claim`, `recover`); `settimeofday`; reboot; camupdate (`--check` and the install, the upload as stdin) | HTTP, SOAP, every ONVIF operation, the web UI, WS-Discovery, PullPoint, snapshots and the preview (rtspd's socket, `/run/cam`), the upload into `/run/fw`, the role checks it always did |

Start-up: options, `-Z`'s ids from `/etc/passwd` and `/etc/group` (src/rtspd/drop.h, as rtspd and
ntpc), then port 80, the discovery socket, `/dev/urandom` (kept open), `time-floor` and the
EndpointReference as root; nothing of the users file is read before the fork. Then
`socketpair(AF_UNIX, SOCK_SEQPACKET)` and `fork()`: the worker closes the monitor's end, wipes
everything of the monitor's in its memory (nonce key, EPR key, replay and nonce state), calls
`drop_to` (setgroups, setgid, setuid, no capability; `setuid(0)` must then fail, else it exits)
and runs the loop. The monitor closes the listeners and answers one request at a time, raising the
UsernameToken high-water mark each second and saving it hourly and at exit. Either side's end ends
the other: the monitor sees EOF and exits; the worker sees EOF in its `select()` (or on its next
request) and exits; a malformed message makes the monitor kill the worker and exit. init's
respawn of `camhttpd-run` starts both again. Without `-Z` both halves run in one process
("in-process": each call is serialised and handed to the monitor's dispatcher directly), which is
also what the host test runs: every request of every test goes through the protocol and the
monitor's checks.

**Messages:** one per request and one per reply, at most 16 KiB (`MON_MSG`).
- Request: `u32 op, u64 grant, u32 len`, then the op's fields, each ending in NUL.
- Reply: `i32 status, u32 len`, then text; `conf`, `upd-check` and `upd-install` also pass an fd
  (`SCM_RIGHTS`).
- **Malformed** (the worker is killed): shorter than the header, a length that doesn't match, a
  field count other than the op's (a NUL inside a field shows as one more field), an unterminated
  last field, over 16 KiB, any ancillary data from the worker.
- **Refused** with a status, nothing changed and the grant not spent: an unknown op; a grant
  missing, unknown, expired, used up, too low or given to an op that takes none (`MON_DENIED`); a
  field too long, holding a newline, or (argv fields) anything but printable ASCII (status 1, as
  camcfg's own refusals, with camcfg's words where it has them: "password must be one line").

| Op | Fields | Role | The monitor |
|---|---|---|---|
| `auth` | address, method, target, `Authorization`, the UsernameToken element | none | Digest (nonce, `nc`, stale, HA1, uri and method), UsernameToken (digest, window, replay, floors), lockout (per address, global, operator+ exemption). Reply: the role (0: none given), the user and a grant; or a refusal (challenge or, for a wrong UsernameToken password, a fault) with a fresh nonce; and whether the address is locked out |
| `set` | key, value | operator; `time.*` admin | `camcfg set` (keys: `image.`, `stream.main.`, `stream.sub.`, `daynight.`, `motion.`, `audio.`, `osd.`, `time.ntp`, `time.tz`) |
| `user` | action, name, role, password | admin | `camcfg user add/passwd/role/del NAME [ROLE]`, the password on stdin |
| `sshkey` | action, key line or number | admin | `camcfg sshkey list`, `add` (stdin), `del N` |
| `settime` | seconds, microseconds | admin | `settimeofday`, then the replay floor |
| `reboot` | | admin | the floor saved, `sync`, `reboot` |
| `upd-begin` | | admin | pins the upload's grant for its one `upd-check` |
| `upd-check` | | admin, the pinned grant | opens `/run/fw/upload.camfw` (`O_NOFOLLOW`, `O_NONBLOCK`; a regular file, one link, 1 byte to 5 MiB), runs `camupdate --check -` on it from a runner; passes a socket on which the verdict comes as one record |
| `upd-install` | | admin | the same open; `camupdate -` detached (double fork, setsid), its output to `install.log` (given to the worker's uid); passes the read end of a pipe only camupdate holds |
| `claim` | address, name, password, key line | none | no admin yet, the 30-minute window, its own rate (10 a minute): `camcfg claim` |
| `recover` | address, name, code, password | none | the lockout, the window, an admin to recover, its rate: `camcfg recover`; a wrong code counts as a failed login |
| `bk-export` | passphrase | admin | `camcfg backup export` with its stdout into a file with no name (`O_TMPFILE` in `/run`, else `mkstemp` and unlink): passes that fd, at its start |
| `bk-restore` | address, password, passphrase | admin | the lockout; the grant's admin password again (a wrong one counts as a failed login); opens `/run/fw/restore.cambak` (`O_NOFOLLOW`, `O_NONBLOCK`; a regular file, one link, 1 byte to 48 KiB) and runs `camcfg backup import /proc/self/fd/3` with it as fd 3; exit 3 counts as a failed login; success reboots the camera 3 s later (the monitor's tick) |
| `bk-setup` | address, passphrase | none | the lockout, no admin yet, the window, the claim rate; then as `bk-restore` |
| `unlock-ch` | none | none | lock mode only; the current challenge (a new one if none or expired, 10 minutes) with the device ID and firmware (`camcfg unlock info`, once) |
| `unlock` | address, restore\|erase, challenge | none | lock mode, the lockout, no reboot under way, the claim rate, the current challenge (constant time; spent by any attempt); opens `/run/fw/unlock.bin` (`O_NOFOLLOW`; a regular file, one link, 1 byte to 60 KiB) as the stdin of `camcfg unlock ACTION -c CHALLENGE [-]` (120 s); exit 3 counts as a failed login; success reboots 3 s later |
| `conf` | | none | `cam.conf` opened for reading (an fd: `/mnt/nand` is root's) |
| `users` | | none | `ROLE NAME` lines: no password |

**Grants:** each successful `auth` gets a random 64-bit grant bound to that user, role and address,
valid 30 s and for 48 privileged operations (the Image form saves 35 keys); 64 are kept, the
oldest unpinned one goes first. Every privileged request carries its request's grant (the
deferred ones keep theirs: the install, 3 s after its reply, and a reboot). So a compromised worker
can act only while a real user of that role is sending requests, and only within that role (it
could swap the body of a real admin's request: so can anyone on the path over plain HTTP, the TLS
residual). The upload is the one exception: its body may take up to `5 + 5 MiB / 4096` s, so
`upd-begin` (at the headers) pins the grant for one `upd-check`, up to 1290 s later.

**Passwords** cross only in `user`, `claim` and `recover` requests, never in a reply (the host test
scans all of them); both sides wipe the message and the stdin buffer after use. The worker sees
the recovery code camcfg prints, as it shows it once.

**What changes for clients:** nothing in the HTTP or ONVIF replies; each request adds one or two
local round trips (`auth`, `users`; `conf` per settings read), microseconds against SSS's
~0.7 requests a second. A UsernameToken over ~14 KiB or with a NUL byte is refused (no client sends
one). The firmware check's and the install's `camupdate` read the package from stdin (`-`).

## Rootfs integration (recommended, not wired in)
- `rootfs/skel/usr/sbin/camhttpd-run`, like `rtspd-run`:
  ```sh
  #!/bin/sh
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  ARGS=$(grep -v '^[[:space:]]*#' /etc/cam/camhttpd.args 2>/dev/null)
  # shellcheck disable=SC2086
  /usr/sbin/camhttpd $ARGS 2>&1 | logger -t camhttpd
  sleep 2
  ```
- `etc/inittab`: `::respawn:/usr/sbin/camhttpd-run` after the rtspd line.
- **Listeners:** add HTTP 80/tcp and WS-Discovery 3702/udp (multicast 239.255.255.250 on eth0) to
  the list in rootfs/README.md and docs/ROADMAP.md. RTSP 554 and SSH 22 stay.
- **Privileges:** without `-Z` it runs as root, as before. With `-Z camhttpd` (camhttpd-run passes it
  while the image has `/etc/cam/camhttpd.user`, on since the bench test in rootfs/README.md passed,
  2026-10-24) only its monitor stays root: port 80, the users file, `settimeofday`, reboot,
  camcfg and camupdate are the monitor's, and the worker that parses the network runs as
  `camhttpd`, group `camctl` (rtspd's control socket and `/run/cam`), writing uploads into `/run/fw`
  (rcS: `camhttpd`'s, 0700). See "Privilege separation".
- `build.sh` already builds `build/arm/camhttpd`. `build-rootfs.sh` needs to install it.

## Host test (any Mac/Linux, no camera, no port)
```
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/rtspd \
    -o $TMPDIR/test_camhttpd src/camhttpd/test_camhttpd.c src/rtspd/auth.c
$TMPDIR/test_camhttpd
```
The test covers:
- **Vectors:** SHA-1 (FIPS 180), Base64 (RFC 4648), the ONVIF guide's PasswordDigest example and
  RFC 2617's Digest example.
- **Auth:** PRE_AUTH vs protected operations; the roles on GetUsers and SetSystemDateAndTime;
  UsernameToken replay, the clock window and PasswordText; the Digest flow (nc replay, stale,
  forged and expired nonces, wrong URI); the lockout.
- **Time zone over ONVIF:** an admin SetSystemDateAndTime's TZ saved as `time.tz` and applied live;
  GetSystemDateAndTime's TZ and LocalDateTime (UTC+8, US Central CDT/CST by the date, an escaped
  `<+0530>-5:30` at +5:30); the same TZ again saves nothing; 8 bad TZs (shell characters, a path,
  25 h, one rule, 65 and 80 characters, `&`) get `ter:InvalidTimeZone` with nothing saved and the
  clock untouched; an empty TZ; an operator refused; camcfg failing; a bad or missing `time.tz` in
  cam.conf reads as `UTC0`.
- **Media:** every operation, with cam.conf values.
- **SSS's sequence:** SetVideoEncoderConfiguration (role, unchanged = no save/restart, changes
  saved key by key and read back, every out-of-range value, unknown token, H.265 sub-stream,
  camcfg failure), GetGuaranteedNumberOfVideoEncoderInstances, GetVideoSourceConfigurationOptions,
  GetAudioEncoderConfigurationOptions, GetRelayOutputs, CreateProfile, GetNTP/SetNTP (DNS/IPv4,
  IPv6/bad names/too many refused, empty list), and DateTimeType NTP.
  - camcfg is faked through `RUN_CAMCFG` (and `CAMCFG_EXEC` for the web UI's user and sshkey
    commands; `DO_REBOOT` stands in for the reboot).
  - The real fork/exec runs too: a missing binary must fail cleanly. With
    `TEST_CAMCFG=<host build of src/camcfg/camcfg.c>`, camcfg itself writes cam.conf:
    ```
    clang -std=c11 -Isrc/rtspd -Isrc/camupdate $(pkg-config --cflags libsodium) -o $TMPDIR/camcfg \
        src/camcfg/camcfg.c src/rtspd/auth.c $(pkg-config --libs libsodium)
    TEST_CAMCFG=$TMPDIR/camcfg $TMPDIR/test_camhttpd
    ```
- **OSD:** capabilities; GetOSDs/GetOSD/GetOSDOptions as SSS reads them (defaults, the title
  hidden while off, wrong tokens); an SSS-shaped SetOSD (custom place, US date, 12 h, a font size)
  saved key by key and applied live, read back, and repeated without saving; five Pos values mapped
  both ways; corners; CreateOSD of a plain text (escaped back, switched on last) and of the
  clock; 17 refusals with nothing saved (Image, wrong types and formats, 49 characters, UTF-8, a
  character reference, Pos outside −1..1 or missing, unknown token or source); DeleteOSD; roles;
  camcfg failing; rtspd down (cam.conf). With `TEST_CAMCFG`, the real camcfg stores a title with
  spaces and symbols whole, an empty one, and refuses UTF-8; it stores `time.tz <+0530>-5:30`
  whole and refuses `CST6CDT;reboot` and the old `osd.tz_offset`.
- **Imaging:** settings from `get` and from cam.conf when rtspd is down; the IrCutFilter mapping;
  options; roles; an SSS-shaped SetImagingSettings (Exposure, WDR and the like included and
  ignored): only changed values saved and applied, read back. Also out-of-range values,
  repeating the same settings, rtspd down, camcfg failing, GetStatus/GetMoveOptions/Move.
- **Events:** capabilities and services, GetEventProperties, subscribe with filters.
  - **Held pulls:** answered by the next poll after a motion change, and at the timeout. Also
    the 10 s cap, polling no faster than 500 ms, one poll answering every held pull, and one
    held pull per subscription.
  - **What gets reported:** nothing at subscribe while motion is off, Changed only, missed edges
    one per pull, an rtspd restart, nothing while rtspd is down, SetSynchronizationPoint, pulls
    extending the lifetime.
  - **Lifecycle:** Renew, wsa:To addressing, the id being no credential, unknown, expired and
    unsubscribed subscriptions, the subscription limit and eviction, durations and times.
  - The clock is moved through the `MONO_ADJ_MS` hook, and rtspd's `get`/`set`/`motion` are faked
    through `CTL_CMD`.
- **Analytics:**
  - **PackBits:** round trips (all ones = `gf8=`, all zeros, checkerboard, all literal, 2000
    random masks, single/pair patterns), always within n + n/128 + 1 bytes. Overruns, a missing
    run byte and wrong lengths are refused; `-128` is a no-op.
  - **Base64:** with and without padding, and errors.
  - **Services:** capabilities and services; the profiles carrying the configuration;
    Get/Add/SetVideoAnalyticsConfiguration; GetSupportedAnalyticsModules and GetAnalyticsModules
    (the layout); GetSupportedRules and GetRules.
  - **ModifyRules:** an SSS-shaped request; roles; saving and applying through the fake camcfg
    and rtspd; read back; unchanged cells change nothing; 6 bad ActiveCells, an overlong one,
    bad MinCount/type/name with nothing saved; CreateRules; DeleteRules.
  - **ModifyAnalyticsModules:** sensitivity, a wrong layout, a range error, a wrong name.
  - **cam.conf fallback:** with rtspd down, the 268-character mask line.
  - **Events:** the same token and rule names.
  - **Real camcfg** (`TEST_CAMCFG`): it takes `motion.mask` and refuses a short one.
- **Audio:**
  - **Profiles:** both carry the audio configurations, checked in tt:Profile order.
  - **Operations:** every Get, each with a wrong token and a wrong profile; GetStreamUri
    unchanged; Add/Remove/Set as no-ops with roles, anything other than G711/64/8 refused with
    nothing saved; audio outputs refused.
  - **audio.enabled=0:** no audio anywhere, and a bad value counts as on.
- **Two-way audio:**
  - **Profiles:** the Extension's contents and order.
  - **Operations:** every output/decoder Get and Options, with wrong tokens and profiles; the
    DeviceIO service, capabilities and token lists; Add/Remove/Set as no-ops with roles; 5 bad
    output configurations refused, nothing saved.
  - **audio.enabled=0:** everything hidden, DeviceIO counts 0.
- **Snapshot:** canned rtspd replies, plus a forked fake rtspd where unix-socket bind is allowed.
  The agent sandbox doesn't allow it, so that part is skipped there.
- **Web UI:**
  - **Pages:** every page for every role (200 or 403, links hidden), the redirect, `/ui.css`, the
    security headers on pages and on the 401; the status page's values from fake `/proc` files
    (documentation addresses and MAC only).
  - **Forms:** OSD (the live form, the title escaped in its field, no UTC offset field but a note
    pointing to the Time page, every field saved key by key with the title switched on last and
    applied live, an old page's `tz` field ignored, 10 bad values with nothing saved, a viewer
    refused, no change saved twice, the failure warning), time zone (the grouped select with US
    Central as the owner wrote it and the escaped fixed offsets, UTC selected by default, every
    preset passing `tz.h`; US Central saved and applied live with the CDT/CST and DST wording in
    the reply, on the page and a Local time row on Status; the same zone again; Custom
    `<+0545>-5:45` shown in its field; a fixed offset without DST wording; 11 bad posts with nothing
    saved and the input escaped; an operator, another user's token and a foreign Origin refused;
    camcfg failing), image (slider vs number field, mode, live
    apply, bad values with nothing saved; the Advanced group's markup, the WDR select + strength as
    one key, its `set` commands; the night tuning checkbox: ticked, the same again, unticked, a bad
    value, the whole 32-field form; exposure at night: same as day by default with the day value
    on its slider, own value 30, the slider alone, the number field, back to day, bad values with
    nothing saved, the whole 35-field form),
    streams (key by key, one restart, none when unchanged, limits, camcfg failing), motion and
    audio (checkboxes, live vs restart, limits, the map, rtspd down), NTP (SetNTP's rules, escaping).
  - **CSRF:** no Origin/Referer, a foreign, `null`, https, prefixed or other-port Origin, two
    Origins, a foreign Referer, the Referer fallback, no/changed/other user's/30-minute-old token,
    last bucket's token, wrong Content-Type (415), over 8 KiB (413), a malformed form (400).
  - **Users:** the two password fields, the password on stdin and never in argv, a 64-character
    password with every symbol logging in by Digest and UsernameToken (and not cut to 63), the
    last-admin and self-delete rules, a 17th user, camcfg's message shown escaped.
  - **SSH keys:** a `<script>` comment escaped, add (the line on stdin), delete (a stale
    fingerprint deletes nothing), no keys.
  - **Reboot:** the confirm box, and the reboot only after the reply has gone (or 3 s).
  - **Firmware update (#104):** camupdate is a stub shell script (`CAMUPDATE`) that logs its argv,
    parent, file size and environment, and answers `--check` as told (OK, OK with downgrade,
    REFUSED, REFUSED with markup, garbage, hung); a missing binary too. The page (form, token, CSP,
    no RAM-test warning) and `/ui.js`; `GET /ui/firmware` per role. Refused before any body byte, with
    nothing staged: no credentials, operator, viewer, no/wrong/other user's/old/double token, a
    foreign or no Origin, 5 wrong types, no or zero `Content-Length` (411), a malformed or doubled
    one, chunked, 5 MiB + 1 (413, no `100 Continue`), an 8-digit one, too little `MemAvailable`
    (507, at the exact boundary) or none, no staging directory. OK: the 200 verdict with the
    installed version, the file byte for byte, camupdate's argv (our fixed path), `PATH` only (no
    `CU_KEYS` although set), the log lines, the page's table and the Install form with the id.
    Install refused without the box, with another or no id, by another admin, with another user's
    token, from another site, by an operator; a replaced upload's page; Discard by another admin;
    nothing to install; a file changed after the check (deleted). REFUSED, markup escaped, garbage,
    missing camupdate, a hung check killed at 60 s (the loop and a second upload's 409 meanwhile),
    a downgrade package refused and deleted. One upload at a time (409, the first untouched, `GET` and the page say so); bytes past
    `Content-Length` never reach the file; the deadlines; an upload is never the evicted slot;
    cancelled mid-body; a write failing mid-stream (507); expiry after 15 minutes. Over a
    socketpair through `client_read`: `100 Continue`, the body, the verdict, a browser leaving
    mid-body. Install: the reply first, camupdate after it (or 3 s), uploads, `GET`, Reboot and a
    second Install refused meanwhile, camupdate's argv without `--check`, its parent not camhttpd,
    `PATH` only, its end without a reboot noticed, logged and shown, its output in `install.log`.
    The fuzz has a firmware upload among its seeds.
  - **With `TEST_CAMCFG`:** the same forms against the real camcfg: the 64-character password
    stored whole; 7, 65 and 300 characters, a tab, UTF-8, outer spaces, the user name and a second
    line each refused with camcfg's reason and nothing stored; an SSH key with ssh-keygen's
    fingerprint; a DSA key refused.
  - **First-boot claim (#128):** unclaimed after the window (also with `/proc/uptime` unreadable
    or at exactly 30 minutes): every path is the power-cycle page, a setup POST runs nothing;
    inside the window: redirects to `/setup`, the form (minutes left, token, CSP), `/ui.css`,
    snapshot and preview 503, every ONVIF operation `ter:NotAuthorized` with and without
    credentials, a users file with only a viewer still unclaimed; Host checks (421 for another
    name, also when Origin agrees with it); CSRF (no Origin, another site's, a user's or
    `/recover`'s token, a stale token, no token, not a form, malformed); different passwords, a
    newline in the password or key, the name echoed escaped, camcfg's refusal; the rate limit
    (429, then fine a minute later); the claim through a fake camcfg (argv, stdin, the code shown
    once amid camcfg's notes, the log line without password or code) and `/setup` a 404 after it.
    **Recovery:** closed outside the window (GET and POST), the form inside, Host and token
    checks, 5 wrong codes then the lockout (the right code and the admin's own login refused for
    the minute), a non-admin name, the right code as typed (lower case, spaces) with the new code
    shown and the password changed, the old code refused. With `TEST_CAMCFG` the same end to end
    against the real camcfg: its refusals, the claim, the hashed recovery file, recover with the
    real code, rotation.
  - **Settings backup (#172, #173):** the multipart parser (a binary part, quoted boundary, 13
    malformed forms, 20 000 mutations under ASan); camcfg as a stub script logging its argv, the
    passphrase line and the file on its fd 3. The System page's part over HTTPS and its HTTPS-only
    note over plain HTTP; the download (plain HTTP, no token, an operator, different passphrases
    refused without camcfg; the file's type, name, length and bytes with a NUL; the UTF-8
    passphrase on stdin; camcfg's refusal on the page); `bk-export` refused without an admin's
    grant or with a newline. The restore: plain HTTP, an operator, another site, a urlencoded form,
    a wrong boundary, no token, no file, over 48 KiB, a wrong password (counted, not logged, camcfg
    not run), camcfg's exit 3 (counted) and its other refusal, then success (the page, the log, the
    argv `backup import /dev/fd/3`, the staged file gone, the body wiped, the reboot only after
    3 s, a second restore refused); `bk-restore` refusing a symlinked upload and an operator's
    grant; `bk-setup` on a claimed camera and with a grant. The claim's backup offer (HTTPS: the
    form with the new admin's token; plain: a pointer). `/setup/restore`: a wrong passphrase
    (counted), another site, no token, success and the reboot, the rate limit, a locked-out
    address, after the window, port 80 while HTTPS is up (403) and down (works), a claimed camera
    (404). With `TEST_CAMCFG` and a fake mtd0 (`CAMCFG_ENV` adds `CAMCFG_MTD0`): a real backup
    downloaded, a wrong passphrase and another camera's ID refused with nothing changed, the
    restore putting the users and cam.conf back, and the setup restore claiming the camera again.
  - **Lock mode (#175)**, with a camcfg stub: `unlock-ch` refused when not locked; the lock page for
    `/`, `/setup` and `/ui/` (the alert, the reason escaped, the form with a 64-hex challenge, the
    device and firmware, the command line), ONVIF's fault, 503 for the snapshot, `/ui.js` and
    `/ui.css` served, 421 by name, 403 for other POSTs; `GET /unlock/challenge` (text, no-store, the
    page's challenge, the same again); `claim` and `bk-setup` refused by the monitor; `/unlock`'s
    refusals before anything is staged (no Origin, another type, a bad action, a bad challenge, no
    body), another challenge refused and the current one spent, a bad signature counted until 429,
    a symlinked staged file, then a signed erase (argv, the body on stdin, the file gone, the reboot
    after the reply) and restore (`-`, the body wiped); port 80 while HTTPS is up.
  - **Preview:** 401 without credentials, multipart framing, one stream (503 for a second), one
    frame a second, no resend of an unchanged JPEG before 3 s, nothing when rtspd's JPEG is stale,
    no second frame queued for a slow reader, an ONVIF request getting a slot while two pulls and
    the preview run, the 5-minute cap (test clock); it needs `socketpair`.
  - **Fuzz:** form parsing (`+`, `%xx`, bad `%`, NUL, duplicates, empty pairs, oversize) and 20 000
    mutated forms; UI requests among the HTTP fuzz seeds.
- **Malformed input:** malformed and oversized requests, and a 33 000-case mutation fuzz under
  ASan/UBSan.
- **Security review of 2026-10-23:** one check per finding, as counts rather than wall-clock
  time:
  - bytes scanned for hostile bodies and probes, and for a header fed a byte at a time;
  - guesses checked in a simulated hour from 32 addresses;
  - bytes hashed for known and unknown users;
  - rtspd asks for rapid snapshots;
  - slot eviction;
  - replay after a restart or while the clock is unset;
  - replay-cache quotas;
  - discovery subnet and rate limits.
- **Gate 3 review (#38)** (`test_gate3`, numbered as the findings):
  - #1 ONVIF from a browser: 9 foreign `Origin`/`Sec-Fetch-Site` forms (403, the time never set, no
    failure counted for a wrong password behind one), 7 wrong, missing or doubled Content-Types
    (415, PRE_AUTH too, the type logged), 8 NVR-shaped requests (SOAP 1.2 with `action`, SOAP 1.1
    `text/xml`, case, our own Origin, `same-origin`, `none`) answered;
  - #2 six bodies in progress: no slot for a newcomer; 2 s without a byte: the one stalled longest
    is taken; a reply, held pull, preview, upload or check never; a third unfinished body from
    one address 429, another address fine;
  - #3 a viewer's login exempts nothing, an operator's does; a wrong password ends it; a ninth
    login doesn't push out a young entry; an hour of guessing from 40 addresses, 8 exempt: 28
    checked in the first minute, 1208 in the hour;
  - #4 `/ui/`, `/ui/image`, `/ui/system`, `/ui/firmware` (GET and the upload's POST),
    `/snapshot.jpg`, `/preview.mjpg` by another name or address: 421 before any login; a rebound
    form POST; `:80`; `/ui.css` open; ONVIF with any Host;
  - #5 (`test_claim`) 60 refused setup POSTs use none of the rate limit; 10 checked ones do;
  - #6 the nonce counter's wrap: new key, nc cache and floor cleared, logins on the new count, the
    old nonce challenged (not stale);
  - #7 a forgotten token replayed after the clock went back: refused (and, without the mark,
    accepted: the finding); tokens before and after the mark; Digest unaffected; `time-floor` not
    written within the hour, written after it (0600) and at exit, read back at a restart, never
    for an unset clock, a damaged one ignored;
  - #8 two viewers, then an operator and an admin keep their whole shares; three operators leave
    the admin's quarter;
  - #9 `epr-secret` made once (32 bytes, 0600), the EPR its HMAC (not the old hash), stable over a
    restart; damaged or nowhere to keep it: the unkeyed hash, logged once, the file left alone;
  - #10 another user's PullMessages/Renew/Unsubscribe (an admin's too) as unknown; a viewer's new
    subscription takes its own, never the NVR's; all another user's: refused until one expires;
  - #11 (`test_sss`, the streams page) a second change within 10 s saved with its restart put off,
    a third joining it, one restart at the end;
  - #12 netmask 0 and /7: no answers, logged once; /8 answers;
  - #13 (`test_firmware`) the install's end seen through its pipe while the pid names a live
    process;
  - #14 camcfg (a stub) gets `PATH` only from `run_camcfg` and `camcfg_exec`; a hung one is killed
    at `CAMCFG_MS` (1.5 s in the test, 10 s on the camera) and logged.
- **Privilege separation** (`test_monitor`; every other test already runs through the monitor
  in-process):
  - the worker's account list has names and roles only;
  - each privileged op's role (`set` operator, `time.*` admin, `user`, `sshkey`, `settime`,
    `reboot`, `upd-begin`, `upd-install` admin) with a grant of each role;
  - no grant, a forged one, one on an op that takes none; expiry (29 s works, 31 s doesn't);
    the 48-op budget; a refused request (a key camhttpd doesn't set, a control character, a
    newline in a password, a malformed `user`) leaves the grant unspent and runs nothing;
  - a login's grant is bound to its user, role and address, and can't do an admin's op;
  - the upload's pinned grant: refused unpinned, taken once 10 min later, nothing else after 30 s;
  - the staged file: a symlink, a hard link, a FIFO, an empty file and one over 5 MiB refused for
    the check and the install; closing the check's socket kills a hung camupdate; a missing
    camupdate's status comes back in the record;
  - claim (unclaimed, window, its own rate) and recover (wrong codes count, lockout, window,
    nobody to recover);
  - malformed messages (short, length, unterminated, field counts, over 16 KiB) and unknown ops;
    a 30 000-message mutation fuzz: no crash, every reply well framed, no grant spent;
  - every reply any test's worker received scanned for the test passwords and their HA1s (some
    15 000);
  - one real fork over the socket pair (datagram on a Mac, which has no SEQPACKET unix sockets):
    GetUsers, a setting saved and read back through the passed fd, a wrong password, the lockout
    staying in the monitor, and a malformed message ending the monitor with status 1.
- **HTTPS** (`test_tls`): `proxy_parse` on a table of 43 good, incomplete and bad lines, 200 000
  mutations (whatever it accepts is byte for byte the canonical line) and 50 000 random inputs;
  `-t`'s refusals (relative path, unknown user, root, a file that isn't a socket, left alone; no
  file left when the socket can't be made); camtls connections through `client_attach` on a
  socketpair: another uid refused, the PROXY line in one or two reads, bad lines closed, the 1 s
  limit, eviction while waiting, `PER_PEER` (0.0.0.0 while waiting, then the client's) and
  `BODY_PER_PEER` after it, the lockout on the client's address, `SO_SNDBUF`; https/http Origin and
  Host rules both ways, https links; ONVIF over HTTPS (every URL https://, rtsps:// only while up,
  http:// and rtsp:// on port 80), GetNetworkProtocols, both discovery XAddrs; `net.plain=0` (port
  80's ONVIF fault and snapshot 403 before any login, rtsps:// only, https:// XAddr only, plain
  again while HTTPS is down); port 80 while up (302s with the
  exact Location and no challenge, claimed and unclaimed, HEAD, a non-ASCII target, POST 403, the
  firmware POST refused at its headers without a 401, the unchanged paths) and without the ready
  file, or without the socket (as before; the once-a-minute log line).
- **Discovery:** Probe matching.

## Not yet
- Media2 (ver20), so also its OSD operations. H.265 streams show as `H265` in ver10, which isn't
  in the schema; the default is H.264.
- OSD: FontColor/BackgroundColor (only the three `osd.style` looks), image OSDs, more than one
  title.
- PTZ, Media2, speaker volume (OutputLevel isn't stored), audio gain over ONVIF (`audio.gain` is
  camcfg only), DeviceIO's audio output configuration operations,
  CreateProfile and other `Set*`/`Add*` media configuration, and users or network changes over
  ONVIF.
- Whether the microphone and speaker actually started: rtspd's `get` now has `audio.on`, but
  camhttpd still decides from `audio.enabled` alone (a `speaker.on` line would make both exact).
- Imaging: Exposure, WhiteBalance and the others, focus, and presets.
- Events: push (WS-BaseNotification `Subscribe`), and per-message ProducerReference /
  SubscriptionReference.
- Analytics: more modules or rules, GetRuleOptions / GetAnalyticsModuleOptions, DeleteRules,
  `motion.enabled` over ONVIF, and MinCount / AlarmOnDelay / AlarmOffDelay as settings.
- The WS-Discovery `Resolve`, and the random 0–500 ms ProbeMatch delay.
- HTTPS. The only HTTP auth is Digest; Basic isn't offered.
- The ARM build is not yet compiled here (no cross toolchain in the agent sandbox). The Linux-only
  code is the `SIOCGIF*` ioctls in `if_info`.
