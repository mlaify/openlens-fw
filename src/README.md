# src: camera userland built on our Ifado MI layer

| Path | What |
|---|---|
| `mi/mi.{h,c}` | The MI video pipeline over raw ioctls (no vendor userland): SNR → VIF → ISP → SCL → VENC H.265, plus our AE + grey-world AWB clocked by `/dev/isp_fe`. Decoded in `docs/IFADO-MI-PIPELINE.md`, verified live on cam #1 (runs 1–4). |
| `rtspd/rtspd.c` | Minimal RTSP server (issue #29): main + sub stream like stock (`/` 2560×1440, `/sub` 640×360, both H.264 by default like the owner's stock settings; each H.264 or H.265), RTP interleaved over the RTSP TCP connection (RFC 7798 / RFC 6184 packetization), Digest auth with a login lockout, single thread, at most 4 clients (connections that don't log in can't hold them; see "RTSP logins and slots"), bounded per-client buffers. |
| `mi/test_mi.c` | Host test of mi.c's sensor orientation ioctls (fake ioctl), the AE's shutter limits, anti-flicker, ISP gain and night exposure, and the ISP tuning (NR, WDR, BLC) against a fake IQ API. |
| `mi/osd.{h,c}` | On-screen display: a date/time line and a title line burned into the video through MI_RGN (docs/STOCK-OSD.md); see "On-screen display" below. `test_osd.c` host test. |
| `rtspd/daynight.{h,c}` | Day/night (#30) as stock: light status and IR-cut through the vendor `/dev/irled` driver, IR LEDs on PWM4, B/W and the night shutter limit through `mi_night`. |
| `ntpc/ntpc.c` | SNTP client (#78): `time.ntp` servers from cam.conf (default time.cloudflare.com), own DNS A lookup, step/slew, a guard on big steps after the first sync (see "Time"). `test_ntpc.c` host test. |
| `rtspd/tz.h` | The check for `time.tz`, the time zone as a POSIX TZ string (header-only; camcfg, rtspd and camhttpd use it); see "Time zone" below. |
| `rtspd/streamcfg.h` | The stream sizes, the fps range and the bit rate an unset `stream.*.kbps` gets per size (header-only; camcfg, rtspd and camhttpd use it); see "Stream settings" below. |
| `rtspd/proxy.h` | camtls's PROXY v1 line (`proxy_parse`, strict) and the uid at the other end of a UNIX socket (`peer_uid`); header-only, for rtspd's TLS socket and camhttpd's; see "RTSPS through camtls" below. |
| `rtspd/auth.{h,c}` | RTSP Digest auth: htdigest credentials (HA1 only, up to 16 users as camcfg/camhttpd; more are logged and left out), MD5 (RFC 1321), per-connection nonce. |
| `rtspd/test_rtspd.c` | Host test of the RTSP handling, packetizer, Digest auth, login lockout and slot limits, the PROXY line and RTSPS clients (no camera, no network port). |
| `camcfg/camcfg.c` | Settings (`cam.conf`), user accounts (`users`) and root's SSH keys (`ssh/authorized_keys`, `camcfg sshkey list/add/del`, #79) on DATA, atomic writes under a lock; derives rtspd's htdigest (#72). The one place that checks passwords (8..64 printable ASCII, never shortened; see its top comment) and SSH key lines. Applies `image.*` settings, `time.tz` and user changes to the running rtspd over its control socket (#73). First-boot claim and admin recovery (#128, `docs/CLAIM.md`): `claimed`, `claim NAME`, `recover [NAME]`, `recovery set/check`, the recovery code kept only as PBKDF2-HMAC-SHA256 (own SHA-256/HMAC/PBKDF2). HTTPS (`docs/PLAN-TLS.md` §B): `tls init [IP]` (first start: the camera's CA and server certificate; "exists" after that), `tls renew [IP]` (a new server certificate, the key kept) and `tls show [IP]` (camtls check's line and exit status) run `/usr/sbin/camtls` as a helper (fixed argv, no shell, PATH only, 10 s limit; `$CAMCFG_CAMTLS` in tests) and move its files into `DIR/tls` (all 0600, fsync'd and renamed under the lock, `ca.crt` last). IP defaults to eth0's. Settings backup (#171, `docs/PLAN-DATA-LOCK.md` Part 1): `backup export > FILE` and `backup import [FILE]` (the passphrase on stdin's first line): DIR's files, the CA key included, in one `.cambak` (Argon2id and XChaCha20-Poly1305 from libsodium, the header as associated data) that restores only on the camera whose U-Boot `ethaddr` made it; import checks everything in memory before it writes. Lock mode (#174, #176): the `claimed` marker (`claimed --mark`), claim and import refused while `/run/data-failed` exists, and `unlock restore [-c CHALLENGE] FILE|-`, `unlock erase [-c CHALLENGE]`, `unlock info`: with `-c` an update key's SSH signature (namespace `cam-recover`, `camupdate/sshsig.h`) over the challenge, device ID, firmware, action and the backup's SHA-256; everything checked before mtd3 is erased (MEMERASE), then the backup written onto it (mounted on /run/recover). `test_camcfg.c` host test. |
| `camupdate/sshsig.h` | The SSHSIG verifier (ssh-ed25519, and sk-ssh-ed25519 with the presence and PIN flags; libsodium), shared by camupdate (namespace `cam-firmware`) and camcfg unlock (`cam-recover`). |
| `camhttpd/camhttpd.c` | ONVIF, WS-Discovery, `/snapshot.jpg` and the web UI under `/ui/` with a live preview (#74, #79); see `camhttpd/README.md`. |
| `build.sh` | Cross-build of `build/arm/{mi-probe,rtspd}` (static ARMv7 hard-float) in Docker; also fetches and converts the OSD font (`scripts/psf2c.sh`). |

## Image settings and the control socket (#73)
- **Settings:** brightness, contrast, saturation, sharpness and exposure, each a whole number
  0..100. 50 means the stock IQ profile (and our AE target for exposure).
  - Brightness and contrast shift the IQ API levels (groups 4102 and 4101).
  - Saturation and sharpness scale them (groups 4106 and 4114). The baselines are read from the
    ISP once the profile is in, so 50 always restores what the profile set.
  - Exposure scales the AE target by 2^((v−50)/25): ×¼ at 0, ×4 at 100.
- **Night exposure:** `image.exposure_night` = `day` (the default, also when the key is absent:
  night follows `image.exposure`) or 0..100 on the same scale. In night mode the AE target comes
  from it, by day from `image.exposure`; a day/night switch switches the target at the AE's next
  step (the AE's damping makes the change gradual). **30 is the recommended value for a
  street-lit or mostly dark scene** (cam #1: its IR picture was washed-out grey at 50, right at
  30); an IR-lit garden (cam #2) looks right with the default. `get` lists it as `day` or the
  number.
- **ISP gain in the AE:** `image.isp_gain_day_max` and `image.isp_gain_night_max`, whole x 1..4,
  defaults **4 by day and 2 at night** (stock's ExposureLimit MaxISPGain, 4096 in its day bin and
  2048 in its night bin). The AE raises the shutter to its limit first, then the sensor gain to
  32×, and only then the ISP gain (CusAEResult IspGain) up to this limit; 1 = no ISP gain, the AE
  exactly as before. Anti-flicker and the shutter limits are unchanged. The day/night score uses
  the total gain (sensor × ISP), so it only changes in a scene that already maxes the sensor
  (docs/STOCK-IMAGE-TUNING.md section 5).
- **Orientation:** `image.mirror` (left-right) and `image.flip` (upside down), each 0/1, default
  0/0. 0/0 is the sensor's own orientation, which is the owner's stock picture on MCA40E (stock's
  "Horizon/Vertical Flip: Enable" gives `SetOrien(0,0)`, docs/STOCK-ENCODE-IMAGE.md §3); 1/1 turns
  it by 180°.
  - Applied as stock does it: `MI_SNR_SetOrien` (SNR nr12, `{u32 pad; u8 mirror; u8 flip}`), once
    the pipeline runs and live. `MI_SNR_GetOrien` (nr13) then reads it back every 3rd frame, up to
    10 times (stock: 10 × 100 ms), and the result is logged. With 0/0 at start it is only read back.
  - The AE luma grid (motion detection) comes from the ISP after the sensor, so it turns with the
    picture. An area drawn in Surveillance Station applies to the picture as shown, so redraw it
    after a change. Rotation by 90° is issue #123.
- **Shutter limits:** `image.shutter_day_max` and `image.shutter_night_max`, the AE's longest
  shutter in µs. 0 = automatic: one frame time (1/fps) by day, stock's 50 ms at night.
  - Day: 0 or 100..1000000; a value longer than a frame time acts as a frame time.
  - Night: 0 or 100..50000. 50 ms is already longer than a 25 or 30 fps frame (40 / 33 ms;
    stock lives with that: at the longest night shutter the sensor's frames stretch to it);
    a longer shutter would lower the sensor's frame rate further, which the encoder settings
    don't account for, so it isn't allowed.
  - Past the limit the AE raises the sensor gain (up to 32×, then the ISP gain up to its limit),
    so a short limit gives a noisier and, in poor light, darker picture. The day/night score
    (Y / (shutter s × total gain)) doesn't depend on the split.
- **Anti-flicker:** `image.antiflicker` 0|1 (default 0) and `image.mains_hz` 50|60 (default 60),
  day and night, in our own AE (no ISP write). When on, the shutter is at least half a mains cycle
  (10000 µs at 50 Hz, 8333 at 60 Hz) and a whole number of half cycles, gain making up the rest,
  never longer than the shutter limit. Stock only raises the minimum shutter. With a limit under
  half a cycle (e.g. 1/1000 s by day) it can't apply: logged once, AE as with it off.
- **ISP tuning** (docs/STOCK-IMAGE-TUNING.md), each 0..255, scaling the IQ profile's per-ISO
  values the way stock's web settings do:
  - `image.nr2d` (2D NR, NRDeSpike 4111 BlendRatio, at most 16) and `image.nr3d` (3D NR, NR3D
    4110 MdGain, at most 10230): value/128, default 128 = as tuned.
  - `image.wdr` (WDR 4118 Strength × value/128, at most 255): default 0 = the profile's own WDR,
    which is already on ("off" = as tuned).
  - `image.blc` (backlight): with `image.wdr` 0, WDR Strength = value at every ISO; 0 = as tuned.
  - Read-compare-write: each group is read whole, only the 16 strength bytes change, and it is
    written only if one differs. Baselines are read with the image controls' (after the profile);
    a group that can't be read or doesn't look like the known layout is never written. Applied
    day and night (stock: day only, as it loads a night bin at night). HLC is not offered: it
    steers the kernel AE, which we don't run.
- **Stock night tuning:** `image.night_tuning` 0|1, **default 0**. On, the night switch also
  writes the image groups stock's `gc4023_night.bin` changes (stronger noise reduction, softer
  sharpening, darker shadows: 21 groups, docs/STOCK-IMAGE-TUNING.md section 4), and the day
  switch writes their day versions back. No AE/AWB/AF group (our AE and AWB keep running); our
  50 ms night shutter cap stays.
  - Files: `/etc/cam/iq-night.bin` and `/etc/cam/iq-day-switch.bin`, derived at build time from
    the owner's dump (`scripts/iq-bin2profile.py`, pinned SHA-256), passed as
    `rtspd -q NIGHT,DAY`. rtspd checks every record against `tools/iq-dump/iq_groups.h` at start;
    without usable files the key stays 0 and a live `set image.night_tuning 1` is refused.
  - Order (stock's): night = IR LEDs, night groups + B/W, IR-cut out a second later; day = IR
    LEDs off, colour, IR-cut in, day groups a second later (the next day/night tick; nothing
    blocks the loop). With the key at 0 everything happens at once as before.
  - Each group is read and written only if it differs. The image controls (levels, saturation,
    sharpness) and `image.nr2d/nr3d/wdr/blc` keep a baseline per mode: at night they scale the
    night groups, by day the day ones, and after each switch the current values are applied to
    the new mode's baseline (a control at 50 writes the file's group unchanged).
  - Live: switching it on at night writes the night groups at once; off writes the day groups
    back at once (B/W stays while it is night).
- **`rtspd -i FILE`** applies the `image.*` lines of `cam.conf` at start (orientation, shutter
  limits and anti-flicker go into the pipeline's configuration; the levels and the ISP tuning
  wait for the IQ profile).
- **`rtspd -u PATH`** opens the control socket (default `/run/camd.sock`, mode 0600 via umask;
  with `-G GROUP` 0660 for that group, owned by the `-U` user; rtspd-run passes `-G camctl`,
  see "Users" below). It takes one line per connection:
  - `get` prints `image.KEY=N` lines (also `image.mirror`, `image.flip`,
    `image.shutter_day_max`, `image.shutter_night_max`, `image.antiflicker`, `image.mains_hz`,
    `image.nr2d`, `image.nr3d`, `image.wdr`, `image.blc`, `image.night_tuning`,
    `image.exposure_night`, `image.isp_gain_day_max`, `image.isp_gain_night_max`) and the
    `daynight.*`, `motion.*` values, then `ok`. It also reports the AE's last step: `ae.y` (mean
    Y of the 32×32 AE grid, one decimal), `ae.target` (the mean-Y target now, day or night),
    `ae.shutter_us`, `ae.sensor_gain` and `ae.isp_gain` (1024 = 1×, as the CUS3A result carries
    them); before the AE's first step `ae.y=-1.0` and the others 0;
  - `set image.KEY N` applies a value live; also `set image.mirror|flip 0|1`,
    `set image.shutter_day_max 0|100..1000000`, `set image.shutter_night_max 0|100..50000`,
    `set image.antiflicker 0|1`, `set image.mains_hz 50|60`, `set image.nr2d|nr3d|wdr|blc 0..255`,
    `set image.night_tuning 0|1`, `set image.exposure_night day|0..100`,
    `set image.isp_gain_day_max|isp_gain_night_max 1..4`;
  - `set daynight.KEY V` (mode, irled, invert, source, night_below, day_above) applies live;
  - `set osd.KEY V` applies an OSD setting live; `set osd.title.text TEXT` takes the rest of the
    line (spaces included, nothing = empty). `get` also lists the `osd.*` values and
    `osd.status` (below);
  - `set time.tz TZ` sets the time zone live (the OSD clock); `get` lists `time.tz`;
  - `auth-reload` re-reads the `-a` file. This is all or nothing: a file with no usable line
    keeps the old users, so auth can never drop to none. The first 16 users load; rtspd logs
    how many more the file has (they can't log in over RTSP).
- **`camcfg`:** `camcfg set image.saturation 45` saves the value and applies it live. `unset`
  goes back to the default (50 for the levels; 128 for nr2d/nr3d, 60 for mains_hz, `day` for
  exposure_night, 4 / 2 for isp_gain_day_max / _night_max, else 0). `camcfg ctl get` shows the
  live values. `camcfg ctl` exits 0 when rtspd's reply ends in a line `ok` or `ok …` (the
  snapshot's `ok <bytes>`), else 1 ("no ok from rtspd"). `camcfg user …` regenerates
  `/run/cam/rtspd.htdigest` and sends `auth-reload`.

## Time zone (`time.tz`)
- **Key:** `time.tz` in `cam.conf`, a POSIX TZ string [`UTC0`], set from the web UI's Time page
  (a list of zones, or Custom), by ONVIF `SetSystemDateAndTime` (`camhttpd/README.md`) or with
  `camcfg set time.tz CST6CDT,M3.2.0,M11.1.0` (US Central). glibc (static) reads the string itself,
  so the camera needs no zoneinfo files, and daylight saving switches by the rules in it.
- **Checked** by `rtspd/tz.h` (header-only; camcfg, rtspd and camhttpd use the same check before
  anything calls `setenv("TZ")`): at most 64 printable characters of
  `std offset [dst [offset] [,start[/time],end[/time]]]`:
  - names: 3+ letters (`CST`) or `<` 3+ of `A-Z a-z 0-9 + -` `>` (`<+0530>`);
  - offsets: `[+-]hh[:mm[:ss]]` up to 24 h. POSIX counts west of UTC as positive: `CST6` is UTC−6,
    `CET-1` is UTC+1;
  - rules: `Mm.w.d` (month, week 1..5 with 5 = last, weekday 0 = Sunday), `Jn` or `n`, each with an
    optional `/time` (`[+-]h` up to 167 h, POSIX.1-2024; 02:00 when left out). A `dst` without
    rules is accepted (glibc then uses the US rules), but every preset gives its rules;
  - nothing else gets through: no `:file` or path, space, shell character or control byte.
- **Used for:** the OSD clock (rtspd sets `TZ` from it at start and on `set time.tz`; osd.c uses
  `localtime_r`), and what camhttpd shows as local time (Status and Time pages, ONVIF
  `LocalDateTime`; camhttpd re-reads the key whenever it needs it).
- **Stays UTC:** the system clock, ntpc, rtspd's and camhttpd's log lines, ONVIF `UTCDateTime`,
  event `UtcTime`, the Digest/UsernameToken clocks and the build-time floor.

## On-screen display (`src/mi/osd.c`)
A date/time line and a title line, burned into the main stream, the sub-stream and the JPEG
snapshots (so the web preview shows them). Set in `cam.conf` (camcfg validates), live over the
control socket, from the web UI's OSD page, and from Surveillance Station over ONVIF
(`camhttpd/README.md`).
- **Keys** (defaults in brackets):
  - `osd.time.enabled` 0|1 [1, as stock], `osd.title.enabled` 0|1 [0];
  - `osd.time.pos`, `osd.title.pos`: `ul`, `ur`, `ll`, `lr` (corners) or `custom` [ul / ll];
  - `osd.time.x|y`, `osd.title.x|y`: 0..100 [0], for `custom`: the box's left/top edge at that
    percentage of the room left (0 = left/top edge, 100 = right/bottom edge);
  - `osd.time.format`: `yyyy-MM-dd`, `yyyy/MM/dd`, `dd/MM/yyyy`, `MM/dd/yyyy`, `dd-MM-yyyy`,
    `MM-dd-yyyy` [yyyy-MM-dd]; `osd.time.12h` 0|1 [0] (`02:05:09 PM`); `osd.time.weekday` 0|1 [0]
    (` Fri` at the end);
  - `osd.title.text`: printable ASCII, at most 48 characters [empty: nothing shown];
  - `osd.size`: `small`, `medium`, `large` [small]: ×4 / ×6 / ×8 of the 8×16 font on the 2560-wide
    main stream, ×1 / ×2 / ×3 on the 640-wide sub-stream. The scale follows each stream's width
    (`stream.*.size`; small = width / 640, whole numbers): main ×3 at 2304 and 1920, ×2 at 1280;
    sub ×1 at 960, ×2 at 1280. ONVIF's FontSize is in main-stream pixels at the configured size;
  - `osd.style`: `border` (white text, 1-pixel black outline, no box), `black-on-white`,
    `white-on-black` [border];
  - the clock shows the camera's local time, from `time.tz` ("Time zone" below). The old
    `osd.tz_offset` (fixed minutes, no summer time) is gone: camcfg refuses it, rtspd skips a
    leftover line (with a hint in its log while there's no `time.tz`), and
    `camcfg unset osd.tz_offset` removes it.
- **Where:** corners keep a character's width from the edges. When both lines share a corner, the
  title goes next to the time (below it at the top, above it at the bottom). Boxes are clipped to
  the picture.
- **How** (docs/STOCK-OSD.md has the interface):
  - one small 2-bit (I2) region per visible line and picture size; the sub-stream's regions are
    attached to the JPEG channel too;
  - created and attached between each encoder's CreateChn and StartRecvPic (mi.c's hook), as stock
    does;
  - the clock is redrawn once a second, when the second changes, from rtspd's main loop; the title
    only when it changes;
  - a move or hide is `SetDisplayAttr`; a size change (format, size, a longer title) detaches,
    destroys and creates the region again (an attached canvas is never resized);
  - teardown: detached and destroyed before the encoders.
- **Failures:** the first MI_RGN error is logged, every region is detached and destroyed, and the
  OSD stays off until rtspd restarts; the video goes on. `osd.status` in `get` is `on`, `off`
  (nothing shown) or `failed`. A JPEG attach failure only costs the snapshots their overlay.
  With every line off, rtspd makes no MI_RGN call at all.
- **Bench:** `OSD_TARGETS=sub` in rtspd's environment (rtspd-run sets it from `/etc/cam/osd-targets`) limits the OSD to some of `main`, `sub`
  and `jpeg` (comma-separated; `jpeg` shares the sub-stream's regions, so it needs `sub`), for a
  staged first test on a camera. Unset means all three.
- **Font:** Terminus 8×16 (SIL OFL 1.1), from Ubuntu's `console-setup-linux`, converted by
  `scripts/psf2c.sh` into `build/gen/osd_font.h` at build time (THIRD-PARTY-NOTICES.md). Bytes
  without a glyph are drawn as `?`. Host builds without it use a made-up test font.

## Audio (#110)
- **Capture:** the microphone as stock does it (docs/STOCK-AUDIO.md).
  - `/dev/mi_ai` dev 0: S16 mono at 16 kHz, 1280-sample (80 ms) periods, interfaces {1 mic,
    37 echo ref}, stock's gains (mic 14).
  - Buffers come from MI_SYS output-port GetBuf/PutBuf on {AI, 0, 0, 0}, woken by `/dev/mi_poll`.
- **Encode** (`src/rtspd/audio.c`): a 31-tap half-band low-pass halves the rate to 8 kHz, then
  G.711 µ-law in 320-byte (40 ms) frames, as stock's `CAuPcm2G711u`.
- **RTSP:**
  - both streams' SDP add `m=audio 0 RTP/AVP 0`, `a=rtpmap:0 PCMU/8000`, `a=control:track1`;
  - SETUP of `…/track1` takes its own interleaved channels (default 2-3);
  - one PT 0 packet per 40 ms frame, marker set as stock does.
  - No RTCP sender reports yet, so clients sync audio and video by arrival.
- **Two-way audio (#117, ONVIF backchannel):**
  - When the speaker starts, a DESCRIBE carrying `Require: …backchannel` also offers
    `m=audio 0 RTP/AVP 0 8` (PCMU/PCMA 8000) `a=control:track2 a=sendonly`.
  - Every client may SETUP `…/track2` (default interleaved 4-5); SSS's dual streaming sets it up
    on each connection. The speaker plays the client sending audible audio; another takes over
    after 0.5 s of quiet, so a connection streaming silence doesn't hold it.
  - The client's RTP is decoded (µ-law or A-law), upsampled 8→16 kHz (half-band), queued, and
    written to MI_AO in 40 ms frames from the main loop. It never blocks.
  - MI_AO is opened as stock (16 kHz mono, 20 dB, staging buffer via nr8 and MI_SYS_Mmap; nr7
    room, nr9 write).
  - The speaker amplifier, GPIO 12, is on while playing and off after 200 ms idle.
  - Video goes only to clients that set up the video track, so a talk-only client gets none.
  - Bench test without an NVR: `scripts/cam-talk.py HOST` (tone or `--wav`, PCMU or `--alaw`).
- **`cam.conf`:** `audio.enabled` (1) and `audio.gain` (0..19, 14), applied when rtspd starts.
  If the AI device doesn't start, the streams carry no audio.

## Motion detection (#77)
- **Input:** `src/rtspd/motion.c` uses the ISP's 32×32 AE luma grid, which our AE already reads
  (`mi_ae_grid`). It evaluates at most 5 times a second; each cell is ~80×45 px.
- **Background:** each cell has a slow background. A grid is scaled to the background's overall
  brightness first, so AE steps, clouds and the day/night switch don't count. A >25 % global
  brightness jump only re-learns the background.
- **Trigger:** a cell is changed when it differs from its background by more than a
  sensitivity-scaled share (8–45 %, with a floor). Motion starts when enough cells (0.2–1.5 %)
  changed in 2 of the last 3 evaluations, and ends after 5 s without.
- **`cam.conf` / live:** `motion.enabled` (0/1, default 1), `motion.sensitivity` (0..100,
  default 50), and `motion.mask`. camcfg validates them and applies them live.
  - The mask is 256 hex digits, one bit per cell of the 32×32 grid: row-major from the top
    left, the first cell in the high bit, 1 = counts. All cells count by default.
  - It is what ONVIF's CellMotionDetector `ActiveCells` maps to, so SSS can draw the area.
  - `get` shows `motion.grid=32x32` and `motion.mask`.
- **Control socket `motion`:** `motion.state`, `motion.seq` (rising edges), `motion.since`
  (seconds held). camhttpd turns this into ONVIF Events. Start and end are logged
  (`motion: start (N cells changed)`).
  Also `motion.cells` (last evaluation), `motion.peak` (most in the last 2 s; reading doesn't
  reset it) and `motion.need` (capped at the active cells, so a one-cell area can trigger).
- **`motion map` / `motion luma` / `motion noise`:** the last evaluation as 32 rows of 32
  characters: change in tens of % (`+` 100 % or more, `#` counted, `-` masked out), luma / 16 in
  hex, or each cell's learned usual change in tens of %.
- **Flicker:** a cell counts only when its change is also above 3x its usual change (an EMA,
  ~7 s), so wind in bushes doesn't hold motion on.

## Time (#78)
The camera has no RTC, so every boot starts in the past. Two ways to set the clock:
- **`ntpc`** (respawned by init). Servers come from `cam.conf` `time.ntp`: up to 3 host names or
  IPv4 addresses, comma-separated. The default is `time.cloudflare.com` (owner's choice).
  - The file is re-read at every poll: every 64 s until the first success, then every 1024 s.
    ntpc isn't root (Gate 3, "Users" below) and DATA is root-only, so the file it reads is
    `/run/ntp.conf`, a world-readable copy of the `time.ntp` line: ntpc-run makes it at every
    start, and `camcfg set|unset time.ntp` (the only writer, also for camhttpd's SetNTP and Time
    page) updates it. A change still takes effect at the next poll.
  - Names are resolved with its own DNS A query to the first nameserver in `/etc/resolv.conf`.
    Static glibc's resolver needs NSS modules the image doesn't have.
  - Replies must echo our random transmit stamp, come from the server's address (a connected
    socket), have mode 4, stratum 1..15, no alarm, receive and transmit times both after the
    firmware build and at most 4 s apart, and an offset that doesn't put the clock before the build.
  - Steps the clock above 0.5 s of offset (or while it's unset), slews below.
  - Plain NTP is unauthenticated. Step guard (Gate 3): the first sync since boot is unrestricted
    (the clock starts at a fixed old time); after it, a step over 1000 s either way is held and
    logged, and applied only when the next poll (64 s later, a fresh query, to another address
    first when DNS or `time.ntp` gives one) agrees within 5 s. A respawned ntpc knows the clock
    was set from `/run/ntpc/synced`. This stops a one-off spoofed reply (DHCP-given DNS, ARP); an
    attacker who stays on the path wins anyway. NTS is a later option.
  - `ntpc -1 -v` polls once.
- **Surveillance Station over ONVIF:** `SetSystemDateAndTime` (Manual, admin), or `SetNTP`
  pointing `time.ntp` at the NAS.

## Snapshots (#75)
- **Channel:** a hardware JPEG channel (VENC device 8, channel 3, the layout of stock's CJpg
  class; docs/STOCK-SNAPSHOT.md) is bound to SCL port 1, the sub-stream size (640×360 by default,
  which is also what stock serves; `stream.sub.size` 960×540 or 1280×720 makes `/snapshot.jpg`
  that size too), FRAME_BASE at 1 fps. It stays running. rtspd's JPEG buffer is 512 KiB and the
  sub-stream's frame buffer 1 MiB (as the main's, since the sub can be 720p): a bigger frame is
  dropped and logged.
- **Storage:** rtspd keeps the latest JPEG in memory.
- **`snapshot` on the control socket** writes it atomically to `/run/cam/snapshot.jpg` and
  replies `ok <bytes>`. With no frame in the last 5 s it replies `err no recent snapshot`.
  camhttpd serves the file as `/snapshot.jpg` (ONVIF `GetSnapshotUri`).
- **`cam.conf`:** `snapshot.quality=10..99` (Qfactor, default 80), `snapshot.enabled=0|1`.
  Snapshots need the sub-stream.
- **Stock differs:** on MCA40E it encodes snapshots in software from the same port at quality
  50. Its hardware path (the one we use) is present but unused there, so this is the first time
  it runs on this SoC.

## Day/night (#30)
Built from stock's own behaviour: static analysis of `media_server`, plus the 2026-10-23 night
watch on cam #2, where stock was in night mode with IR LEDs at 96 %, a 50 ms shutter and 4.2×
gain.
- **Light (default `daynight.source=image`): the picture's brightness.**
  - On MCA40E the `/dev/irled` status isn't a light reading: it read 0 in daylight and under a
    cover (cam #2, 2026-10-23). So we use stock's "by image" path: brightness score = mean Y /
    (shutter s × gain), from our AE.
  - **Night** when the score stays below `daynight.night_below` (15). Ours at dawn without IR
    scored ~8.
  - **Day** when it stays above `daynight.day_above` (1500). Stock's IR-lit night picture
    scores ~170, so the IR LEDs alone can't switch it back.
  - Readings must hold for 5 s. After 3 switches in 10 min the state is held for 10 min, as
    stock does.
  - `daynight.source=sensor` follows the `/dev/irled` status word instead (inverted with
    `daynight.invert=1`).
  - `camcfg ctl get` shows `daynight.score` and `daynight.raw`.
- **Night:**
  - one byte `0` to `/dev/irled`: IR-cut out (the kernel driver drives GPIO 11/80; we touch no
    GPIO);
  - IR LEDs on PWM4 (20 kHz, duty `daynight.irled`, 96 % like stock);
  - IQ ColorToGray on;
  - the AE may use a shutter up to 50 ms (or `image.shutter_night_max`) and ISP gain up to 2×
    (`image.isp_gain_night_max`), and aims for `image.exposure_night` if it has its own value.
- **Day:** byte `1` (IR-cut in), IR LEDs at 0, colour, shutter up to 1/fps (or
  `image.shutter_day_max`), ISP gain up to 4× (`image.isp_gain_day_max`).
- **The score and the ISP gain:** the score's gain is the total, sensor × ISP. Its thresholds were
  set from pictures with ISP gain 1×; the AE adds ISP gain only once the sensor is at 32×, so a
  scene that scored above ~1 before (shutter at its limit, sensor 32×) now gets more exposure and
  the same score, provided the AE statistics see the ISP gain (to be confirmed live:
  docs/STOCK-IMAGE-TUNING.md section 5).
- With `image.night_tuning=1` the night groups come in before the IR-cut moves out, and the day
  groups a second after it moves in (stock's order; Image settings above).
- **`cam.conf` / live:**
  - `daynight.mode=auto|day|night`, `daynight.irled=0..100`, `daynight.invert=0|1`;
  - `daynight.night_below` / `daynight.day_above` (1..1000000 each, 15 / 1500), night_below
    always below day_above: camcfg refuses a set or unset that breaks that, rtspd refuses such a
    live set, and at start rtspd checks the pair after reading the whole file (so the line order
    doesn't matter; a bad pair keeps the defaults). The web UI's Image page sets them in an order
    that keeps the pair valid at every step;
  - `camcfg set daynight.mode night` applies live, `unset` returns to the default;
  - `camcfg ctl get` shows `daynight.state`.
- **`rtspd -n`** turns it off (for runs next to the vendor userland).
- **Not yet:** stock's "Light Off Sensitivity" / "Light On Illumination" thresholds, and a white
  LED mode (PWM0).

## Stream settings (`cam.conf`, read at start)
- **Defaults:** both streams H.264 High profile VBR, the owner's stock values (2026-10-23), at
  30 fps, the sensor's (owner 2026-10-25):
  - main 2560×1440, 30 fps, 4000 kbps;
  - sub 640×360, 30 fps, 500 kbps;
  - a keyframe every 100 frames on both.

  H.264 is the default because Surveillance Station's event detection can't use H.265.
- **Keys:**
  - `stream.main.codec|kbps|fps|gop|size` and `stream.sub.codec|kbps|fps|gop|size`;
  - `stream.sub.enabled` (0/1).
- **Ranges** (`src/rtspd/streamcfg.h`, shared by rtspd, camcfg and camhttpd): codec h264/h265,
  kbps 64..16384, fps 1..30, gop 1..1000, and the sizes below.
  - camcfg refuses anything else.
  - rtspd logs and ignores bad lines.
  - `cam.conf` wins over the command line (`-w/-h`, `-s`, `-b`, `-k`, `-f`, `-g`).
- **Sizes** (16:9, the SCL scales the whole 2560×1440 sensor picture down to each; every sub size
  fits inside every main size). An unset `kbps` follows the size:

  | `stream.main.size` | default kbps | `stream.sub.size` | default kbps |
  |---|---|---|---|
  | `2560x1440` (default) | 4000 | `640x360` (default) | 500 |
  | `2304x1296` | 3500 | `960x540` | 900 |
  | `1920x1080` | 3000 | `1280x720` | 1500 |
  | `1280x720` | 1500 | | |

  - A set `kbps` stays as set whatever the size. On the web UI and over ONVIF a bit rate left at
    the shown default isn't saved, so it keeps following the size.
  - `stream.sub.size` only sizes a sub-stream that is on (`stream.sub.enabled=0` or `-s 0` keep it
    off). The sub size is also the snapshots' (below) and the sub-stream OSD's picture.
- **Frame rate:** the main's fps is also the sensor's: mi.c sends `MI_SNR_SetFps(pad 0, fps)` as
  stock's `Vif::Init` does, right after the VIF output port is enabled (nr5, up to 5 tries; a
  failure is logged and the video runs at the sensor's own 30 fps). Before 2026-10-25 nothing set
  it, so the sensor ran at its native 30 fps while VENC and the binds assumed 25. The sub-stream
  is fed from the main's frames, so it runs at most at the main's rate: rtspd clamps a higher
  `stream.sub.fps` (and logs it); camhttpd shows the clamped value and, when the web UI or ONVIF
  lowers the main below the sub, saves the sub's too. At night the 50 ms shutter stretches the
  sensor's frames (as stock's), whatever the setting.
- **Applying:** `camcfg set stream.main.kbps 6000`, then `camcfg ctl restart`. rtspd exits cleanly
  and init starts it again with the new settings.
- **Rate control and profile:**
  - Defaults as stock: VBR (H.264 mode 2 with max/min QP 48/30; H.265 mode 10 with 50/32), the
    bitrate as the maximum, and H.264 High profile (attr profile 2).
  - Keys: `stream.*.rc` (`vbr`/`cbr`) and `stream.*.profile` (`high`/`main`/`baseline`; H.264
    only).
  - Stock's post-create rate-control tuning is copied for H.264 (`MI_VENC_GetRcParam` nr43 →
    patch → `SetRcParam` nr42; docs/STOCK-ENCODE-IMAGE.md §1.4). VBR: IP QP delta −4, I-frame
    QP 30..51, I-frame cap 1.2× and P-frame cap 0.2× the bitrate. H.265 keeps the driver
    defaults (stock's version isn't decoded).
  - Sub-stream buffer size w×h as stock.
- **Flip and defog:**
  - The owner's stock "H/V flip Enable" is the sensor's default orientation on MCA40E
    (`SetOrien(0,0)`), which is our default; `image.mirror` / `image.flip` change it (above).
  - Stock never applies its "Defogging" setting at all.

## RTSP logins and slots (Gate 3)
rtspd has 4 client slots, and SSS records from them, so a recorder that has logged in must keep
its slot and be able to get one back. Everything but OPTIONS needs Digest auth.
- **Connections that haven't logged in:**
  - 10 s to log in after connecting, however much they send (`LOGIN_MS`);
  - at most 2 per IPv4 address (`PER_IP_UNAUTHED`; SSS's dual streaming opens 2 at once). A
    third is refused until one logs in or goes;
  - with every slot taken, a new connection evicts the oldest one that hasn't logged in. A
    logged-in client is never evicted; with all 4 logged in, newcomers are refused.
  - Residual: someone opening connections from many addresses faster than SSS logs in (well
    under a second on the LAN) can evict SSS's half-open connection; its logged-in ones stay.
- **Closing clients** (TEARDOWN, the 5th wrong password, a full output buffer) get 2 s to read
  their last reply (`CLOSING_MS`), whatever they send meanwhile. Nothing they send after the
  request that closed them is handled, including requests already buffered behind it, so
  pipelining can't get past the wrong-password limit.
- **Idle:** 60 s without a request, RTCP or send progress (`SESSION_TIMEOUT`), as before.
- **Lockout** (as camhttpd's, `src/camhttpd/README.md`), on the monotonic clock:
  - per connection: the 5th request with wrong (or unchecked) credentials closes it, unanswered;
  - per address: 5 wrong passwords from one IPv4 address within 60 s lock it until that minute
    is up. A locked address is never pushed out of the 32-entry table; if every entry is
    locked, new addresses count as locked too;
  - all addresses: 20 wrong passwords in 60 s stop the checks for every address except those
    that logged in within the last 10 minutes (8 remembered), so a logged-in NVR can reconnect
    while someone guesses from many addresses. Cost: 20 wrong passwords a minute can keep a new
    client from logging in;
  - while locked or blocked, credentials aren't checked and the reply is the usual 401
    challenge (the connection stays, so a client can't tell a lockout from a wrong password).
    The log says "address locked out, credentials not checked".
- **`-N` (no auth, bench only):** every client counts as logged in: no login deadline, no
  eviction, no per-address cap.

## RTSPS through camtls (docs/PLAN-TLS.md D)
camtls ends TLS on TCP 322 and hands each client to rtspd as plain RTSP (requests and `$`-framed
RTP/RTCP) over a UNIX socket. A client that supports RTSPS uses `rtsps://<camera>:322/` (main)
and `rtsps://<camera>:322/sub`. Surveillance Station can't: it sends plain RTSP to 322
(docs/PLAN-TLS.md D), so it stays on 554.
- **`rtspd -t PATH:USER`** (rtspd-run: `-t /run/rtspd/tls.sock:camtls` when `/etc/cam/tls.on` or
  `/run/tls.on` exists and `/etc/passwd` has camtls). USER is a name from `/etc/passwd` or
  `UID:GID`, as `-U`. As root, before the drop, rtspd removes a stale PATH and makes the socket:
  0660, group USER's primary group, non-blocking. Its directory must exist (rcS makes
  `/run/rtspd` root:camtls 0750). A bad `-t` or a socket that can't be made is logged ("no
  RTSPS") and rtspd goes on: port 554 always streams.
- **Who may connect:** USER's uid only (`SO_PEERCRED`); any other peer is closed at once.
- **PROXY line:** the first bytes must be exactly `PROXY TCP4 <client> <camera> <cport> <port>
`
  (at most 56 bytes, single spaces, dotted quads and ports as `inet_ntop` and `%u` write them, no
  `UNKNOWN`/`TCP6`; `proxy_parse` in `rtspd/proxy.h`) within 1 s of the accept (`PROXY_MS`),
  else the connection is closed. Until then it waits outside the client slots (at most 4
  waiting) under the placeholder "camtls". rtspd reads only the line; the client's first request
  stays in the socket.
- **Then it is a client like one on the port**, under the client's address (logged as
  `a.b.c.d:port (TLS)`): it takes one of the 4 slots, shared with port 554; the per-address
  limits (`PER_IP_UNAUTHED`, eviction of the oldest not logged in) and the lockout count the
  PROXY line's address together with the same address on the port, and two clients behind
  camtls are two addresses. `LOGIN_MS` counts from the accept on the socket.
- **URLs:** `rtsps://` is taken wherever `rtsp://` is (the stream is chosen by the path). For a
  TLS client the SDP's `o=` line carries the PROXY line's camera address (not the socket's), and
  `Content-Base` is `rtsps://<camera>:<port><path>/`, whatever scheme or host the client wrote.
  rtspd emits no other absolute URL (the SDP's controls are relative; no RTP-Info).
- **Back-pressure:** `SO_SNDBUF` 64 KiB on the socket (`TLS_SNDBUF`), so a viewer behind camtls
  that falls behind still fills rtspd's own buffer and drops frames to the next keyframe, as on
  the port (camtls must read rtspd only when its TLS side has taken the last chunk).
- **A PROXY line on port 554** is never taken: there it is an ordinary request (401, or 501 once
  logged in), and the connection keeps its real address.

## Users: rtspd and ntpc leave root (Gate 3)
`src/rtspd/drop.h` (header-only, shared): `-U USER` takes a name from `/etc/passwd` (its uid,
primary gid and the groups in `/etc/group` that list it) or `UID:GID` (numbers, no other group:
for the bench test on an image whose passwd hasn't got the user). Our own file read, because
static glibc's getpwnam needs NSS modules the image doesn't have. Root (uid or gid 0) is refused.
The drop is setgroups, setgid, setuid, then a check of every id (real, effective, saved) and that
`setuid(0)` and `setgid(0)` fail; anything else stops the program. The users and the boot steps
are in `rootfs/README.md` ("Users").

| Program | Runs as | Keeps | Started by |
|---|---|---|---|
| rtspd | `rtspd` (100) with `-U`, because the image has `/etc/cam/rtspd.user` (on since the bench test passed, 2026-10-24) | nothing | rtspd-run |
| ntpc | `ntpc` (101), always (`-U ntpc`) | `CAP_SYS_TIME` (effective + permitted, nothing inheritable) | ntpc-run |
| camhttpd | a root monitor and, with `-Z camhttpd` (when the image has `/etc/cam/camhttpd.user`), a `camhttpd` (102) worker in group `camctl` (src/camhttpd/README.md, "Privilege separation"); on since the bench test passed, 2026-10-24 | | camhttpd-run |

- **rtspd, in this order:** options; `-U`/`-G` looked up (a bad one exits 2 before anything
  starts); the `-a` file and `cam.conf` (`-i`) read (rtspd never reads `cam.conf` again: later
  changes come over the control socket, stream changes by a restart, which rtspd-run does as
  root); port 554 bound; `/run/camd.sock` made and given to `USER:GROUP` 0660 (`-G`); with `-t`,
  the TLS socket made (above); MI started
  (every `/dev/mi_*` fd, the encoder rings mapped, `/dev/isp_fe`); `/dev/irled`; microphone and
  speaker (`/dev/mi_ai`, `/dev/mi_ao`, the AO staging buffer mapped); then `/dev/urandom` and
  `/dev/mi_rgn` opened (they are opened lazily otherwise: session ids and nonces, an OSD enabled
  later); then the drop, logged as `rtspd: running as USER (uid …, gid …, N groups); setuid(0)
  refused`, and only then the first client. A failed drop stops rtspd (exit 1, after the MI
  teardown).
- **What rtspd opens after the drop:**

  | Access | When | How it works |
  |---|---|---|
  | `/run/cam/snapshot.jpg(.tmp)` write, rename | `snapshot` command | `/run/cam` is `rtspd:camctl` 2750 (rtspd-prep); the file 0640, group camctl (setgid) |
  | `/run/cam/rtspd.htdigest` read | `auth-reload` (user change) | camcfg, as root, gives the file to the directory's owner (rtspd), 0600 |
  | `/sys/class/pwm/pwmchip4/pwm0/{period,duty_cycle,enable}` write | every day/night switch, `daynight.irled` | rtspd-prep exports pwm0 at boot and gives the three to rtspd |
  | `/sys/class/gpio/gpio12/value` write | talk starts / 200 ms idle | rtspd-prep exports GPIO 12 (output, low) at boot and gives `value` to rtspd |
  | `/etc/cam/iq-profile.bin`, `iq-night.bin`, `iq-day-switch.bin` read | frame 10; night tuning | world-readable in the image |
  | `/proc/self/statm` | stats | its own |
  | ioctls on the open MI/RGN/AI/AO/irled fds, `MI_SYS_Mmap` | all the time | opened as root; **whether the vendor MI module checks a capability on some call is unknown: the bench test** |
  | `/run/camd.sock` unlink | exit | fails (`/run` is root's); the next rtspd (root) replaces it |
  | `/run/rtspd/tls.sock` accept; unlink | each RTSPS client; exit | the listening fd was opened as root; the unlink fails (the directory is root's), the next rtspd replaces it |

- **ntpc:** options; `-U` looked up; `/dev/urandom` opened (kept); `PR_SET_KEEPCAPS`, setgroups,
  setgid, setuid, `capset` to `CAP_SYS_TIME` only (`_LINUX_CAPABILITY_VERSION_3`, via
  `syscall()`, no libcap), `capget` to check, `setuid(0)` must fail; logged as `ntpc: running as
  ntpc (uid 101) with CAP_SYS_TIME only`. It binds no port (connected UDP sockets, ephemeral
  ports), reads `/run/ntp.conf` and `/etc/resolv.conf` (0644), and writes its marker in
  `/run/ntpc` (its own, 0700, made by ntpc-run). `settimeofday` and `adjtime` need only
  `CAP_SYS_TIME`.
- **Root clients and the socket:** camcfg (and camhttpd as one root process) connect to
  `/run/camd.sock` as root. `connect()` needs write permission on the socket file (unix(7)), and
  root's `CAP_DAC_OVERRIDE` covers that whatever the file's owner and mode (capabilities(7)). The
  rtspd bench test on cam #1 confirmed it: `camcfg ctl` and camhttpd's snapshot worked while the
  socket was `rtspd:camctl` 0660. camhttpd's unprivileged worker (`-Z`) connects through group
  `camctl`.

## Build (owner's terminal)
```
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash src/build.sh
```

## Host test (any Mac/Linux, no camera)
```
ffmpeg -f lavfi -i testsrc2=size=1280x720:rate=25 -t 4 -c:v libx265 -bsf:v hevc_mp4toannexb -f hevc /tmp/clip.h265
ffmpeg -f lavfi -i testsrc2=size=640x360:rate=20 -t 4 -c:v libx264 -g 40 -bsf:v h264_mp4toannexb -f h264 /tmp/clip.h264
cc -std=c11 -fsanitize=address,undefined -Isrc/mi -Isrc/rtspd -o /tmp/test_rtspd src/rtspd/test_rtspd.c src/rtspd/auth.c src/rtspd/daynight.c src/rtspd/motion.c src/rtspd/audio.c src/mi/osd.c -lm
/tmp/test_rtspd /tmp/clip.h265 /tmp/out.h265 /tmp/clip.h264 && ffprobe /tmp/out.h265
```
The test checks the following:
- **RTSP replies:** 461 for UDP, 455 for PLAY before SETUP, and the parameter sets in the SDP.
- **Round trip:** every NAL comes back byte-identical through single-NAL and FU packets, with
  one marker per access unit.
- **Motion:** synthetic grids. Noise and a lighting change stay quiet; a moving block starts
  motion; it is held 5 s, then ends; disabling works.
- **Snapshot:** non-JPEG frames ignored, atomic write, stale frames refused.
- **OSD settings:** `osd.*` from `cam.conf` (bad lines ignored one by one), live `set`/`get`,
  titles with spaces, `=` and empty; overlong, non-ASCII and malformed values refused.
- **Time zone:** `time.tz` from `cam.conf` and live `set`/`get` (local time CDT in October, CST in
  December, +5:30, NZDT), bad values refused (the last good one stays), a leftover `osd.tz_offset`
  skipped without "ignored", with a hint only while there is no `time.tz`.
- **Day/night:** a fake `/dev/irled` and PWM directory check the inverted status, the 5 s
  debounce, the IR-cut byte, IR LED duty 48000 and forced modes; with night tuning on, the night
  groups before the IR-cut moves out (a tick later) and the day groups a tick after it moves in,
  also when switched back before the second half; off, all in one tick as before.
- **Control socket:** get/set/auth-reload, bad keys/values/trailing junk refused, failed reload keeps
  the users; socket file 0600 (skipped where unix-socket bind is not permitted, e.g. the agent sandbox).
- **Orientation and shutter limits:** `image.mirror/flip` and `image.shutter_*` from `cam.conf`
  into the MI config (not sent before start), live `set`/`get` through stubbed `mi_orient` /
  `mi_shutter_max`, bad values refused; the day/night thresholds as a pair from `cam.conf` in
  either line order, and live.
- **Anti-flicker and ISP tuning:** `image.antiflicker/mains_hz` into the MI config,
  `image.nr2d/nr3d/wdr/blc` queued in MI from `cam.conf` (bad values ignored), live `set`/`get`
  through stubbed `mi_antiflicker` / `mi_tune_set`, bad values refused.
- **Stock night tuning:** `image.night_tuning` from `cam.conf` into the MI config (bad values
  ignored), live `set`/`get`, bad values refused, and refused with its reason when the image has
  no night files.
- **Night exposure and ISP gain:** `image.exposure_night` (`day`|0..100) from `cam.conf` into MI
  and `image.isp_gain_day_max/_night_max` (1..4) into the MI config (bad values ignored), live
  `set`/`get` through stubbed `mi_exposure_night` / `mi_isp_gain_max`, bad values refused; the
  `ae.*` lines of `get` (one decimal for Y and target, gains 1024 = 1×, the values before the AE's
  first step).
- **Slow viewers:** a stalled client drops frames and waits for a keyframe, with its buffer
  bounded.
- **H.264 sub-stream:** `/sub` SDP (`packetization-mode=1`, `profile-level-id`,
  `sprop-parameter-sets`), byte-identical round trip through FU-A, 404 when off.
- **Digest auth:** MD5 vectors, 401 challenge, wrong password, correct response, `qop=auth`.
- **Slots** (connections through `client_admit` over socketpairs with chosen addresses, the
  monotonic clock moved by `MONO_ADJ_MS`): a connection sending OPTIONS every second is closed
  10 s after connecting unless logged in, a logged-in one stays; a third connection from an
  address with 2 not logged in is refused, another address isn't, and logging in frees the
  place; with all slots taken the oldest not logged in is evicted (its peer sees EOF) and a
  logged-in one never is, all 4 logged in refuse a newcomer; a reused slot starts clean
  (tracks, channels, talk, auth); a closing client that never reads and keeps sending is closed
  after 2 s, its requests read but unanswered.
- **Lockout:** 20 wrong passwords and the right one pipelined in one buffer get 4 challenges and
  no 200; 5 wrong then OPTIONS in one buffer get no OPTIONS reply; 5 wrong from an address lock
  it (the right password then gets 401) while another address logs in, until the window ends; a
  locked entry survives a flood of 96 new addresses; 20 wrong from 5 addresses block a newcomer
  but not an address that logged in, until the window ends, and that exemption ends after
  10 minutes.
- **Users:** an htdigest file with 18 users loads 16, counts and logs the 2 left out; user 16
  can log in, user 17 can't.
- **PROXY line** (`proxy_parse`): a table of good and bad lines (TCP6, UNKNOWN, double or trailing
  spaces, LF without CR, leading zeros, port 0 or 65536, `+1`, `0x2`, a NUL inside, 56 bytes
  without a line end), every prefix of a good line waits; 300,000 fuzzed inputs, every accepted
  line exactly camtls's `snprintf` of its fields.
- **RTSPS clients** (socketpairs through `tls_take`/`tls_proxy_in`, the peer's uid chosen by the
  test's `PEER_UID`): another uid closed; `SO_SNDBUF`; no line (or half a line) within 1 s
  closed; bad lines closed; at most 4 waiting; the line and the first request in one write; the
  per-address limit and the lockout on the PROXY address, shared with the port, two clients
  through one socket kept apart; slots shared, eviction; `LOGIN_MS` from the accept; a PROXY
  line on the port is a 401/501; Digest, DESCRIBE/SETUP/PLAY on `rtsps://` URLs with the SDP's
  `o=` and `Content-Base` on the PROXY line's camera address, 30 H.265 access units
  byte-identical; `-t` parsing; the socket file 0660 with the group (skipped where unix-socket
  bind is not permitted).
- **TEARDOWN** closes the session.

mi.c's host test (sensor orientation ioctls against a fake `ioctl`, the AE's shutter limits and
anti-flicker, the ISP tuning against a fake IQ API):
```
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/mi -o $TMPDIR/test_mi src/mi/test_mi.c -lm
$TMPDIR/test_mi
```
It checks the SetOrien/GetOrien request codes and 8-byte argument, that nothing is sent before
`mi_start`, the non-blocking read-back (10 tries), the limit ranges, and the AE's shutter/gain
split by day and night, automatic and limited, with anti-flicker at 50 and 60 Hz (whole half
cycles, the minimum, a limit too short for it), all with ISP gain 1× giving exactly the results
from before it. ISP gain: shutter first, then sensor gain to 32×, then ISP gain up to the mode's
limit (4× by day and 2× at night by default, other limits, 1× = none), never past the limit with
anti-flicker's rounding, unset in `mi_cfg` = 1×; `set_ae` writes IspGain at +0x10 with the BV
unchanged (sensor gain only); `mi_ae_info`
gives the total gain (so the day/night score counts it) and `mi_ae_state` the parts.
`image.exposure_night`: the range, the night target from it and the day one from
`image.exposure`, a switch switching the target, the base target before the IQ is in, the clamps.
The ISP tuning runs against a fake IQ API
(`MI_TEST_IQ` replaces `iq_xfer`) holding the NRDeSpike/NR3D/WDR groups as the stock profile has
them: exact sizes, a read before every write, no write when nothing changes, only the 16 strength
fields change, the clamps, BLC only with WDR off and back to the baseline, and an unreadable or
unknown-looking group never written. Stock night tuning (the fake IQ API also holding ColorToGray,
the image controls' groups and DynamicBlackLevel; synthetic files in `$TMPDIR`): files with an
AE, info, Temperature, Dummy or unknown id, a wrong size, an error code, an id twice, another day
order, a truncated record, a record less or a missing file are refused; with the key off a switch
writes ColorToGray only; on, night reads every group and writes only the differing ones (exact
sizes, file order); at night a slider and 2D NR scale the night baseline, 3D NR (no night group)
the day one; to day only ColorToGray until `mi_night_day`, which restores the day versions with
the user's values on the day baselines; on/off live at night; a failing write reported; start-up
at night takes the day baselines before writing the night groups.

The night tuning converter (`scripts/iq-bin2profile.py`) has its own host test with synthetic bins:
```
python3 -I scripts/test_iq_bin2profile.py
```
A valid pair gives exactly the differing image groups (night and day versions, same order) and
skips AE, info, Dummy, Day/Night Mode, night-only, equal and multi-buffer AE groups; a bad
checksum, magic, version, length or key, a bad or truncated record, bad buffer offsets, an id twice,
nbuf ≠ 1 or a wrong size for a group it takes, a hash other than the pinned one, and no differing
group are refused with nothing written.

The chroot test's `--overnight` sampler has a small host test (no camera):
```
python3 -I scripts/test_cam_chroot_test.py
```
It checks the per-minute command as the shell sees it (the `get` grep keeps its keys and has
`^ae\.`, which picks every `ae.*` line) and that a snapshot counts by rtspd's `ok <bytes>` line,
not by camcfg's exit status, and never on "no ok from rtspd" or an `err`.

osd.c's host test (mi.c and osd.c against fake `/dev/mi_sys`, `/dev/mi_venc` and `/dev/mi_rgn`):
```
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/mi -o $TMPDIR/test_osd src/mi/test_osd.c -lm
$TMPDIR/test_osd
```
It checks:
- **Interface:** every MI_RGN request code and argument size, the header, the palette.
- **Order:** Init once; Create → Attach → first draw between each encoder's CreateChn and
  StartRecvPic (mi.c's real `setup_venc`); the JPEG channel gets the sub-stream's regions.
- **Updates:** GetCanvasInfo → flush (the whole canvas) → nr11 → flush (its range) → nr12; the
  clock once a second and nothing in between; the title only on change.
- **Changes:** a move or hide by SetDisplayAttr on every target; a size change by detach + destroy +
  create; widths 8-aligned, heights and positions 4-aligned, everything inside the picture
  (corners, custom 100/100, a shared corner, a title too long for the sub-stream).
- **Rendering:** each style against an independent reference (glyph bits, scale, outline,
  background), the I2 packing, `?` for bytes without a glyph, clipping, row padding.
- **Failures:** Create failing at start (encoders still start, nothing after it), a JPEG attach
  failing (only the snapshots lose it), a redraw failing (every region detached and destroyed,
  then silence), and no MI_RGN call at all with every line off; then switched on live.
- **Text:** settings parsing, every date format, 12 h at midnight and noon, weekday; local time
  from `TZ`: fixed offsets −12..+14 h, US Central CDT in October and CST in December with both
  2026 switches, India +5:30, Sydney's summer.
- **`OSD_TARGETS`:** sub only, sub and JPEG, main only.

camcfg's own host test (#79):
```
clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/rtspd -Isrc/camupdate \
    $(pkg-config --cflags libsodium) -o $TMPDIR/test_camcfg src/camcfg/test_camcfg.c \
    src/rtspd/auth.c $(pkg-config --libs libsodium)
$TMPDIR/test_camcfg
```
It checks SHA-256 (FIPS vectors, block edges); SSH key lines (each accepted type, fingerprints as
`ssh-keygen -l` prints them, options, other types, a mismatched or malformed blob, bad base64,
non-ASCII comments); `sshkey list/add/del` (numbering past `#` lines, duplicates, 16 at most,
0600 file); every `osd.*` key's values (title: 48 printable ASCII characters, empty allowed); and
the password policy: a 64-character password with every ASCII symbol and a space
goes through `user add` → users → `htdigest` → rtspd's Digest check (auth.c), and 7, 65 and 300
characters, a tab, UTF-8, outer spaces, the user name, two lines and no line are each refused with
their reason, leaving the users file alone. Settings: `image.mirror/flip`, the shutter limits,
anti-flicker, the ISP tuning keys, `image.night_tuning`, `image.exposure_night` (`day`|0..100)
and `image.isp_gain_day_max/_night_max` (1..4) accepted and refused value by value, with the
defaults an unset sends, and `daynight.night_below < day_above` on set and unset. `camcfg ctl`:
a reply counts when its last line is `ok` or `ok …` (the snapshot's `ok <bytes>`), not `err`,
empty or cut short; through a fake rtspd socket where unix-socket bind is allowed (skipped in the
agent sandbox). Time zone: every preset and fixed offset,
then `tz.h` value by value (signs, minutes and seconds, quoted names, `Mm.w.d`/`Jn`/`n` rules with
`/time`; refused: shell characters, a newline, paths, bad rules, over 64 characters); `set`, `get`
and `unset time.tz`; `osd.tz_offset` refused with a pointer to `time.tz`, and a leftover line
removed by `unset`. Claim and recovery (#128): SHA-256 by parts against one-shot at every split
and a million `a`, HMAC-SHA256 (RFC 4231 cases 1, 2, 6), PBKDF2-HMAC-SHA256 (c = 1, 2, 4096, 80000;
16..64-byte outputs; NULs in password and salt: the RFC 6070 inputs with SHA-256 and RFC 7914
§11); code parsing (case, spaces, dashes; 0/1/8/9 and wrong lengths refused); `claimed`; `claim`
refusing a bad password, name, key, a third line, an existing name, and a second claim, leaving
nothing behind; the claim writing a 0600 `recovery` file with salt, hash and 100000 iterations
that holds no code, the admin, then the key (a duplicate left alone); a users file that can't be
written (no key, no recovery file) and a key that can't be added (claim undone: users as before,
no recovery file, authorized_keys untouched) each leave the camera unclaimed; `user del` and
`user role` refusing the last admin (and allowing it once there is a second); `recovery check`;
`recover` with a wrong code (exit 3), a bad password (the code still valid), a non-admin, the
right code (password changed, a new code, the old one dead), the code's admin deleted (any admin
by name); the file's own iteration count and salt used, under 1000 or another algorithm refused;
`recovery set` (new salt each time). HTTPS, with a stub camtls (a shell script speaking its helper
interface): `tls show` passing check's line and status (0/1/2) through; `tls init` refusing a
malformed IP before camtls runs and failing with camtls's message (control characters made
harmless) for an address outside CAM_NET (192.0.2.0/24 in the tests), leaving nothing; then `gen-ca TMP` and `issue TMP
IP TMP` in a new `.new-*` directory, camtls given PATH only, the four files 0600 in `DIR/tls`;
`init` again says "exists"; `tls renew` keeping the key (or installing camtls's new one when there
was none) and refusing an address outside the range; no eth0 address; a leftover `.new-*`
directory (a power cut) swept by the next run; a camtls that hangs killed after 10 s with the
certificate unchanged; no camtls at all. Settings backup (#171): the device ID against a fixed
vector (the MAC's case and place in U-Boot's env don't matter; no ID without a valid `ethaddr`
or mtd0); `backup export` refused without an ID, on an unclaimed camera, and for a passphrase of
11 or 257 bytes, with a control character or none; the header as documented and no file's bytes
in the clear; `backup import` with a wrong passphrase (exit 3, nothing changed), then every file
back byte for byte and 0600, from a file or from stdin after the passphrase line; files added
since the backup removed; an empty host key and an unfinished CA (no `ca.crt`) left out of a
backup; another camera's backup refused before any key is made, and its device line edited to
this camera failing the box; edits to each header line and a flipped bit (exit 3); cuts at every
boundary; bad headers and Argon2id settings outside 1..32 passes and 1..8 MiB; forged archives
encrypted with the right key (names outside the list such as `../users` or `.lock`, duplicates,
wrong sizes, nothing after `end` allowed, users without an admin or with a bad role, a NUL, part
of the CA, an empty key, a 512-byte line) all refused with nothing changed; the archive parser
and checks fuzzed in process (20000 mutations).

## rtspd on cam #1 (issue #29; owner's OK, media_server stopped)
```
python3 scripts/rtsp-passwd.py admin                 # once: ~/.config/cam-firmware-dev/rtspd.htdigest
python3 scripts/cam-run-rtspd.py --minutes 10 --auth ~/.config/cam-firmware-dev/rtspd.htdigest \
    --iq-profile bench-logs/iq-profile-stock.bin       # after opening the root console --keep-open
ffplay -rtsp_transport tcp rtsp://admin:PASSWORD@<cam1>/      # main, on the Mac
ffplay -rtsp_transport tcp rtsp://admin:PASSWORD@<cam1>/sub   # sub-stream
```
rtspd refuses to start without `-a htdigest` or an explicit `-N` (no auth; the runner passes `-N`
when `--auth` is not given).
Options: `-a htdigest` / `-N` · `-p port` (554, as stock; scripts/cam-run-rtspd.py passes 8554 to run next to the vendor) · `-l addr` (0.0.0.0) · `-w/-h` (2560×1440) · `-b kbps` (by size: 4000) ·
`-f fps` (30) · `-c h264|h265` main codec (h264) · `-o gop` main keyframe interval (100) · `-s WxH|0` sub-stream
(640x360) · `-d` its codec (h264) · `-k` its kbps (by size: 500) · `-g` its fps (30) · `-O gop` its keyframe interval (100) · `-F` FRAME_BASE instead of HW_RING · `-T y` AE target (40) · `-P fmt` ISP output
(11 NV12 default) · `-Q profile` IQ profile (#36) · `-e us:gain` / `-W r:g:b` fixed 3A · `-v`.

Not yet (tracked in #29 / Gate 3):
- RTP over UDP. SETUP answers 461, and ffplay/VLC retry over TCP.
- Requesting an IDR when a client joins. A new viewer waits up to one GOP (4 s at the default 100 frames).
