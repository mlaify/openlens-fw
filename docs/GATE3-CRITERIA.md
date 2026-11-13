# Gate 3: security acceptance criteria (#38)

The test runs on **cam #1 flashed with our firmware** (phase E of docs/PLAN-NEXT.md), on an
isolated link or the camera VLAN, before cam #2 is flashed. A checkbox passes only with evidence
(a command and its output saved in `bench-logs/gate3-<date>/`). An exception needs the owner's
written acceptance in the issue. Items marked **(chroot)** can be pre-checked in the RAM chroot
test now.

**Tools** (2026-10-24):
- `bash scripts/host-tests.sh` runs every host test under ASan/UBSan (§3). Run it from a terminal:
  the agent sandbox refuses unix-socket bind, so some socket parts print `skip` there.
- `python3 scripts/gate3-live.py HOST --admin NAME [--viewer NAME] [--operator NAME]
  [--camfw build/update/*.camfw] [--lockout] [--udp]` runs the live checks of §1, §2, §4, §5 and
  §6 against a camera and writes `bench-logs/gate3-<date>/<HOST>/<time>/` (summary.txt, one file per
  check; the MAC is redacted). It changes nothing on the camera (`camupdate --check` only;
  `--lockout` locks this machine out of camhttpd for a minute). Run it on cam #1 after it runs the
  image with the Gate 3 fixes (§7).

## 1. Network exposure
- [ ] **(chroot)** Listeners are exactly TCP 22 (SSH), 80 (ONVIF/snapshot), 554 (RTSP) and UDP
  3702 (WS-Discovery). Check with `netstat -ltnu` on the camera and `nmap -p- -sT` plus
  `nmap -sU --top-ports 200` from the LAN. Nothing on 23, 9999, 8000, 34567, 8554 or any vendor
  port.
- [ ] **Outbound traffic is only:**
  - DHCP;
  - DNS to the DHCP-provided resolver;
  - NTP (123/udp) to the configured `time.ntp` servers (default time.cloudflare.com, owner
    choice).

  Check: 24 h `tcpdump` on the camera's switch port or the router. No other destinations, no P2P
  or cloud.
- [ ] WS-Discovery answers only probes from the camera's own subnet and never amplifies more
  than one reply per probe (rate-limited).

## 2. Authentication and authorization
- [ ] **(chroot)** No default or shared credentials:
  - a release image has no accounts at all: the first admin is created by claiming the camera
    (`/setup`, 30 minutes after power-on, #128, docs/CLAIM.md), and the image passes
    `scripts/scan-credentials.sh`;
  - root has no password (`*`), so there's no serial or SSH password login;
  - there is no hard-coded or master password anywhere in our code (`grep` of the source and
    `strings` of the binaries).
- [ ] **(chroot)** SSH: public keys only. A password login is refused, as are agent, X11 and TCP
  forwarding. Only ed25519/ecdsa/rsa-sha2/sk keys; no SHA-1, CBC or 3DES; the strict-kex
  (Terrapin) fix is present.
- [ ] **(chroot)** RTSP: every DESCRIBE, SETUP and PLAY without valid Digest credentials gets 401.
  Wrong passwords close the connection after 5 tries, and nothing pipelined behind them is
  answered. 5 failures from one address in a minute lock that address; 20 from all addresses stop
  the checks except for addresses that logged in within 10 minutes (src/README.md, "RTSP logins
  and slots").
- [ ] **(chroot)** ONVIF: only the PRE_AUTH operations answer unauthenticated.
  - Roles are enforced: a viewer can't use SetVideoEncoderConfiguration,
    SetSystemDateAndTime, SetNTP, SetImagingSettings or GetUsers.
  - `/snapshot.jpg` needs Digest.
  - The lockout and the global failure budget work (§2 of src/camhttpd/README.md).
  - An ONVIF POST from a browser on another site is refused (a foreign `Origin` or
    `Sec-Fetch-Site`: 403; a Content-Type other than SOAP's: 415).
- [ ] Web UI: Digest on every page; a role's pages above it get 403; every POST needs an `Origin`
  of the camera and the page's token (403 otherwise); a `Host` other than the camera's address
  gets 421 on the UI, `/snapshot.jpg` and `/preview.mjpg` (DNS rebinding); `/setup` is gone once
  claimed; CSP, X-Frame-Options and nosniff on every page. Firmware upload: admin only, never a
  downgrade-signed package (422).
- [ ] UsernameToken replay across a reboot is refused (the clock is unset until NTP; tokens from
  before the start are refused), and so is one after the clock is stepped back (camhttpd's
  high-water mark, kept in DATA). ntpc refuses replies before the build time and holds a step over
  1000 s until a second reply agrees.

## 3. Robustness
- [ ] Host tests pass under ASan/UBSan for rtspd, camhttpd, ntpc and camupdate, including their
  fuzz loops.
- [ ] Network fuzzing for ≥ 1 h each, against RTSP (554), HTTP/SOAP (80) and WS-Discovery
  (3702), using a mutation fuzzer from the LAN. Pass: no crash, no hang longer than the
  timeouts, and services respawn if killed.
- [ ] A slowloris on 80 and 554 can't stop a legitimate client within its timeouts.
- [ ] 24 h run with SSS recording: RSS flat (rtspd, camhttpd), no unintended restarts, day/night
  switches, watchdog never fires.

## 4. Firmware integrity and update
- [ ] `camupdate` refuses:
  - unsigned packages;
  - packages signed by another key;
  - a tampered header or payload;
  - the wrong device or part;
  - an oversized payload;
  - a downgrade without `allow-downgrade=1`.

  - a forged signature block with a non-empty SSHSIG reserved field (it overflowed a stack
    buffer before the Gate 3 fix);
  - any package while `/etc/cam/version` is missing or malformed (unless `allow-downgrade=1`).

  It accepts the owner-signed N+1. There is no stock rollback package (owner decision
  2026-10-24: "I am never going back"). If it can't take the watchdog it resumes everything and
  writes nothing; once the erase has begun it retries from RAM (3 passes) and never just exits.
- [ ] The rootfs is read-only squashfs. Writable state is only DATA (`/mnt/nand/cam`, mode 0700)
  and tmpfs.
- [ ] **Known, accepted residual:** U-Boot is stock and unauthenticated. Anyone with
  UART/physical access can boot anything, and the SoC has no verified boot. Owner acceptance is
  recorded in #38.

## 5. Vendor attack surface gone
- [ ] None of the stock vendor processes or files are present: procman, mainctrl, media_server,
  the hik/h5live/comm/ex/p2p/web/dbg servers, the vendor CGI and web root, OTA tools.
  - Check: the `MANIFEST.txt` of the image, plus `ps` on the camera.
- [ ] Every finding from the disclosure (F1–F24) is checked against the new firmware and marked
  "surface removed" or "not applicable", with a note. That checklist lives in the local
  disclosure project, not in this repo.

## 6. Secrets handling
- [ ] A release image (`rootfs.sqfs` / `.camfw`) contains no credentials: no `users.seed`,
  `rtspd.htdigest`, `authorized_keys` or root hash (`scripts/scan-credentials.sh` passes at
  build). Accounts, SSH keys and the recovery code are created per camera at claim (#128).
  - A `--bench` image carries the builder's credentials for the RAM chroot test only; make-update
    and camupdate refuse it.
- [ ] No serial number, MAC or credential appears in logs (`logread` review after the 24 h run)
  or in the ONVIF responses (SerialNumber "0"; the WS-Discovery EndpointReference is a hash).

## 7. Code review (2026-10-24)
Three independent read-only reviews of the network-facing code (camhttpd HTTP/web UI, camhttpd
ONVIF/WS-Discovery, and rtspd/ntpc/camupdate/camcfg/rootfs) ran before the live test. Fixed on
the `gate3` branch, each with host tests:
- **camupdate:** the SSHSIG reserved field was copied unbounded into a 256-byte stack buffer before
  the signature check (high); an unknown installed version skipped the downgrade rule; a watchdog
  that couldn't be taken, or a failed write, left a stopped, unfed system; the RAM copy used a
  fixed name in `/tmp`.
- **rtspd:** clients that never logged in could hold all 4 slots (high); pipelined guesses got past
  the 5-try close (high); no lockout; slot state carried over; 8-user limit.
- **camhttpd:** ONVIF CSRF through the browser's cached Digest login; stalled request bodies held
  slots; the NVR's lockout exemption could be evicted; DNS rebinding on the UI; the claim rate
  limit was spent before the token check; the nonce counter could wrap; UsernameToken replay after
  the clock moved back; two users could fill the replay cache; the EndpointReference gave the MAC
  back (now an HMAC with a per-camera secret: it changes once); subscriptions weren't bound to
  their user; rtspd restarts weren't throttled; WS-Discovery with netmask 0; pid reuse at install
  end; camcfg without a timeout or a fixed environment.
- **ntpc:** an on-path reply could set any time, before the build time too; no limit on later steps.
- **camcfg:** the last admin could be deleted or demoted from the CLI; a failed claim left its SSH
  key behind.
- **rootfs:** ICMP redirects still accepted on eth0; no nosuid/nodev/noexec on tmpfs and DATA.

**Open in Gate 3:** daemons drop root (owner decision 2026-10-24: in Gate 3; camhttpd, rtspd and
ntpc under their own users).
- **ntpc: done** (`gate3-part2`): user `ntpc` with `CAP_SYS_TIME` only, servers from the
  world-readable `/run/ntp.conf` that ntpc-run and camcfg keep in step with `time.ntp`. Pending:
  its log line `running as ntpc ... CAP_SYS_TIME only` and a sync on the first boot of a release.
- **rtspd: done, on** (`/etc/cam/rtspd.user` in the image). `rtspd -U rtspd` leaves root
  after the port, the control socket, the settings and every device are open. The bench test on
  cam #1 (20261024.4, 2026-10-24) passed:
  - the drop itself: uid and gid 100, groups 100 and 110, CapPrm and CapEff 0, `setuid(0)`
    refused, the socket `rtspd:camctl` 0660;
  - streams and SSS recording;
  - day/night: B/W with the IR at the configured 40%, then back;
  - the OSD;
  - the snapshot through camhttpd (`rtspd:camctl` 0640);
  - the microphone.

  The 5 IQ groups the profile can't set (errno 22) and the JPEG overlay attach (errno 2) fail the
  same way as root, so the drop isn't the cause. (Two-way talk isn't tested: per the owner,
  these cameras don't support it.)
- **camhttpd: done, on** (`/etc/cam/camhttpd.user` in the image; docs/CAMHTTPD-PRIVSEP.md,
  src/camhttpd/README.md "Privilege separation"). The bench test on cam #1 (20261024.5,
  2026-10-24) passed:
  - the worker: uid and gid 102, groups 102 and 110, CapEff 0, `setuid(0)` refused; the monitor
    root;
  - SSS: recording, motion events, snapshot, a stream change;
  - gate3-live's ONVIF roles, CSRF and lockout;
  - every web UI page as admin: Image, OSD, Streams, Motion, Time, Users (add, password, delete),
    SSH keys, and System (upload, verdict, discard).

  With
  `-Z camhttpd` a root monitor keeps the users file, every authentication (Digest, UsernameToken,
  replay, clock floor, lockout) and the privileged operations (camcfg, settime, reboot, camupdate),
  each behind a grant from a real login of the right role (30 s, 48 operations); the worker that
  parses HTTP/SOAP/the web UI/WS-Discovery runs as `camhttpd`, group `camctl`, and never holds a
  password, an HA1, a recovery hash or the nonce key. `/run/fw` is `camhttpd`'s 0700 (rcS);
  gate3-live reports each daemon's uid (INFO).
- **SSH post-quantum key exchange** (the owner's client warned): Dropbear 2025.87+ with
  mlkem768x25519 and sntrup761x25519 (`gate3-part2`); gate3-live checks what is negotiated.
- **Not run yet:** the full nmap scan (deferred by the owner), WS-Discovery's one-reply and rate
  checks from a machine on the camera's subnet, network fuzzing, slowloris and the 24 h run (§3).

**Residuals and the owner's decisions (2026-10-24):**
- **No TLS (web UI fixed 2026-10-25):** the web UI, `/setup` and `/recover` are HTTPS-only
  (camtls, a CA on each camera; PLAN-TLS B), verified on cam #1. ONVIF and RTSP for SSS stay plain
  on 80/554: SSS can't do HTTPS or RTSPS for a generic ONVIF camera (bench). They are reachable
  only from the NAS behind the router isolation (A). RTSPS on 322 is there for clients that support it.
  Before that, the residual was: HTTP Digest and WS-UsernameToken don't cover the body, `/setup`
  and `/recover` cross the wire in clear, and an on-path attacker can rewrite requests.
  **Decision:** being fixed, in this order (docs/PLAN-TLS.md):
  - (A) network isolation on the owner's router (the camera VLAN reaches only the NAS and the
    admin Mac);
  - (B) HTTPS for the web UI through a small TLS front end (camtls, mbedTLS 3.6);
  - (D) ONVIF over HTTPS and RTSPS, which SSS supports.

  Until B, this stays a residual mitigated by A.
- **NTP from an attacker on the path:** one on the path for both replies can still move the clock
  (ntpc refuses pre-build times and holds steps over 1000 s; camhttpd's high-water mark stops
  UsernameToken replay). **Decision: accepted.** NTP runs inside the segmented camera VLAN,
  nothing more to do.
- **DATA not mounting** made the camera claimable for 30 minutes after that boot, and the
  claimer got root (docs/CLAIM.md). **Decision: accepted (2026-10-24), then fixed by
  docs/PLAN-DATA-LOCK.md (2026-10-26):** rcS detects it and locks the camera (#174; claim refused,
  SSH with the update keys only, #178), and recovers by a restore or erase signed with an update
  key (#175-#177). Bench test #179 pending.
- **U-Boot is stock and unauthenticated (§4):** anyone with UART, a flash clip or root can boot or
  flash anything. **Decision: accepted, protect the cameras physically.** Mount them out of reach;
  tamper seals.
