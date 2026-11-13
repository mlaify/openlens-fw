# Plan: TLS for the web UI, ONVIF and RTSP (Gate 3 residual "no TLS")

Owner decision, 2026-10-24: (A) network isolation first (the owner's router), then (B) HTTPS for
the web UI, then (D) ONVIF over HTTPS and RTSP over TLS, since Surveillance Station supports both.
The NTP, DATA and U-Boot residuals are decided in docs/GATE3-CRITERIA.md §7.

## A. Network isolation (owner, router; no firmware change)
- **The camera VLAN** (CAM_NET, the subnet the image is built for: `scripts/cam-net.sh`) accepts only:
  - from the NAS (<nas>): TCP 80 (later 443), TCP 554 (later 322);
  - from the admin Mac: TCP 22, TCP 80 and 443.

  Everything else into the VLAN is dropped.
- **The cameras may send out only** DHCP, DNS to the router, and NTP (123/udp) to the configured
  servers. Nothing else goes to the internet, and nothing goes to other VLANs except replies.
- **WS-Discovery (3702/udp)** stays inside the camera VLAN. The NAS adds the cameras by address.
- **Evidence for Gate 3:** export the rules, plus one blocked attempt from another VLAN (for
  example `curl` from a laptop on the main LAN times out).

## B. HTTPS for the web UI (done 2026-10-25; on in the image)
**Bench, cam #1, 20261024.8/.9:**
- After the camera's CA was trusted on the Mac, Safari, Chrome and Firefox loaded
  `https://<cam1>/ui/` with no warning, and `http://` redirected.
- `gate3-live --only tls`: 34 checks, 0 FAIL:
  - TLS 1.0/1.1, CBC and RSA refused;
  - TLS 1.3 and 1.2 with ECDHE-ECDSA AEAD suites, X25519;
  - the certificate: IP-only SAN, 397 days, EC P-256, chained to the camera CA with critical
    nameConstraints;
  - port 80 redirects before auth; `/setup` POST refused on 80.

**Owner decisions:**
- certificates are generated **on the camera**, with no signing on the Mac or the YubiKeys;
- they name **IP addresses only**, and DHCP may change a camera's address;
- once HTTPS works, browser pages on 80 redirect to `https://`, and `/setup` and `/recover` are
  HTTPS-only;
- ONVIF and `/snapshot.jpg` stay on 80 for SSS until D.

An independent design review shaped what follows: the UNIX socket instead of loopback, the
limits, the order of the port-80 checks, the name constraints and the certificate lifetimes.

### Trust: a small CA on each camera
- **First start:** the camera makes its own CA (EC P-256). The CA certificate carries **critical
  nameConstraints**:
  - permitted `IP:` CAM_NET (for example `IP:192.0.2.0/255.255.255.0`), compiled into camtls;
  - permitted `IP:::/128`, so no IPv6 address can be signed;
  - permitted DNS `invalid`, so no DNS name can be signed (RFC 5280 constrains only names of the
    constraint's own type);
  - pathlen 0, keyCertSign.
- **The CA key never leaves DATA** (`/mnt/nand/cam/tls/`, 0600, root). The CA is valid 10
  years. It is only a trust anchor; no browser uses it for TLS.
- **The owner trusts each camera's CA in macOS once:** download it from the System page (#183),
  or over SSH (`cat /run/camtls/ca.crt`); check its fingerprint against `camcfg tls show` over
  SSH; add it in Keychain Access, set "Always Trust" for SSL.
- **The camera issues its own server certificate:**
  - EC P-256, SAN = its current IPv4 only, EKU serverAuth, CA:FALSE, ≤ 397 days (Apple's rules
    for locally trusted roots);
  - notBefore = max(now, BUILD_EPOCH) − 1 day, because the clock may be unset at first boot;
  - re-issued **by the camera** when eth0's address differs from the SAN, or 30 days before
    expiry. A DHCP change therefore brings no new browser warning.
- **Blast radius:** a compromised camera's CA can vouch only for CAM_NET, never for a website.
- **Writer:** camcfg, per AGENTS.md. `camcfg tls init|renew|show` runs `camtls gen-ca|issue|check`
  as helpers (fixed argv, pipes) and writes the files atomically under its lock.

### Data path
- **camtls** (its own user, 103) terminates TLS on 443. It passes plain HTTP to camhttpd over a
  **UNIX socket** `/run/camhttpd/tls.sock`, not loopback TCP, because any local uid can reach
  loopback.
- **PROXY line:** its first line is `PROXY TCP4 <client> <camera> <cport> 443\r\n`. camhttpd
  accepts it only on that socket, only when SO_PEERCRED says the peer is camtls's uid, and only
  within 1 s. Then it sets the client's address and `tls`, and only then applies its per-address
  checks.
- **Library:** mbedTLS 3.6 LTS from Debian trixie's signed source (`scripts/build-camtls.sh`, like
  build-dropbear.sh), with our overlay config `src/camtls/mbedtls-user-config.h`:
  - TLS 1.2 and 1.3 only;
  - ECDHE-ECDSA only, groups X25519 and P-256 (browsers' key shares);
  - ChaCha20-Poly1305 first (the A7 has no AES instructions), then AES-GCM;
  - session tickets with an in-memory key, PSK_EPHEMERAL;
  - no RSA, CBC, renegotiation, DTLS, 0-RTT, ALPN or SNI; no PSA key storage.
- **Limits:**
  - 6 connections (= camhttpd's MAX_CLIENTS), 4 per client address (a browser loads page, CSS,
    script and preview at once);
  - at most 2 handshakes at a time, plus a token bucket;
  - a 5 s handshake deadline; a connection over a limit waits rather than being closed;
  - camtls runs at nice 5 (it sets that itself with setpriority).
- **Back-pressure:** camtls reads from camhttpd only once its TLS write side is empty, and camhttpd
  sets SO_SNDBUF to about 32 KiB on TLS connections, so the preview never queues seconds of
  frames.

### camhttpd
- **Option:** `-t PATH:USER`. Root binds the socket before the privsep fork, and the monitor closes
  it.
- **Scheme by connection:** Origin must be `https://Host`; Host is `IP` or `IP:443`; pages with
  `http://` follow the scheme. `/onvif/*` over TLS is 404 until D.
- **Plain port 80 while camtls is ready:** the check comes before authentication, so 80 never asks
  for credentials.
  - GET of `/`, `/ui/*`, `/setup`, `/recover`, `/preview.mjpg`: 302 to `https://<IP><path>`.
  - POSTs to those paths: 403.
  - `/onvif/*`, `/snapshot.jpg`, `/ui.css` and `/ui.js` are unchanged.
- **Claim fallback (default, owner may change):** while camtls isn't running, `/setup` and
  `/recover` still work on plain HTTP and log loudly. A broken TLS build then can't leave a reset
  camera unclaimable (CH341A only).
- **System page (#183):** HTTPS status from `/run/camtls/info` (the certificate's address and end,
  the CA's and the certificate's fingerprints), the CA certificate to download (`/ui/ca.crt`,
  admin), and how to trust it, starting with a fingerprint check over SSH. camhttpd only reads
  camtls-run's public files; it has no X.509 code.

### Rollout
- `camtls-run` starts only with `/etc/cam/tls.on` (image) or `/run/tls.on` (bench).
- Bench test on cam #1 first; then `tls.on` goes into the image; cam #1, then cam #2.
- **Steps:**
  0. benchmark on cam #1;
  1. build-camtls;
  2. camhttpd side;
  3. camtls daemon;
  4. camcfg tls and rootfs;
  5. tools: gate3-live `tls`, cam-claim over https, cam-first-install;
  6. bench;
  7. on.

## D. ONVIF over HTTPS and RTSP over TLS (built and on; SSS can't use it)
**Bench, cam #1, 2026-10-25:**
- SSS shows "HTTPS: Not Supported" for a generic ONVIF camera. That is its own verdict, not taken
  from the camera: it stayed after camhttpd reported `TLS1.2` true.
- Given port 443, or a user-defined `rtsps://…:322/`, SSS sends **plain text**, and camtls logs
  "invalid SSL record" from <nas>.

**Owner decision:**
- SSS stays on plain ONVIF/RTSP (80/554), reachable only from the NAS behind the router isolation
  (A).
- RTSPS on 322 stays on for clients that can use it. `net.plain` stays 1 while SSS needs
  port 80.

- **RTSPS:** camtls also listens on **322** and relays to rtspd's UNIX socket `/run/rtspd/tls.sock`.
  - The same PROXY line and uid check as camhttpd's. The strict parser is shared:
    `src/rtspd/proxy.h`.
  - rtspd applies its per-address rules, lockout and login deadline to the real client, and the
    clients share its 4 slots with port 554's.
  - The SDP and `Content-Base` use `rtsps://<camera>:322`.
  - camtls never cuts a relaying RTSP session for its lifetime (recordings run for days). Its
    buffers are bounded, so rtspd's slow-viewer frame dropping still works.
- **Throughput (cam #1, mbedTLS 3.6.6, 2026-10-25):** ChaCha20-Poly1305 24 MB/s, AES-GCM-128
  6.8 MB/s. Main plus sub stream at about 0.6 MB/s is roughly 3% of ChaCha20. A full handshake is
  about 30 ms of CPU (ECDSA P-256 sign 150/s, ECDHE P-256 49/s, X25519 38/s).
- **ONVIF over HTTPS:**
  - On a TLS connection every ONVIF URL is `https://<camera>` (XAddrs, GetSnapshotUri, the
    PullPoint address).
  - `GetStreamUri` gives `rtsps://<camera>:322/` while camtls is up (one ready file for 443 and
    322), else `rtsp://`.
  - GetNetworkProtocols adds HTTPS 443.
  - WS-Discovery lists the http and https XAddrs, http first.
- **Moving SSS over:** edit the camera in SSS (HTTPS port 443, RTSPS) and check recording, events
  and snapshots. Then set `camcfg set net.plain 0`, which only acts while HTTPS is up:
  - port 80 refuses ONVIF and `/snapshot.jpg` (403) and only redirects browsers;
  - `GetStreamUri` never offers `rtsp://`;
  - discovery lists only `https://`.

  rtspd closing 554 for `net.plain=0` comes later, as its own change.
- **Tests:** socketpair-based host tests in camhttpd, rtspd and camtls, and gate3-live's `tls`
  part.

## What TLS doesn't change
- Digest and UsernameToken stay as they are inside TLS: TLS covers the body and stops
  offline cracking from a capture.
- The monitor/worker split stays: camtls runs in front of camhttpd's worker and holds no
  passwords.
- U-Boot, physical access and the DATA failure are separate residuals (GATE3-CRITERIA §7).

## Issue text
**Title:** TLS: HTTPS web UI (camtls, mbedTLS 3.6), then ONVIF over HTTPS and RTSPS (Gate 3 residual)

**Body:** see docs/PLAN-TLS.md. Owner decision 2026-10-24: network isolation (router) first, then B
(HTTPS UI via camtls on 443), then D (ONVIF over HTTPS, RTSPS on 322; SSS supports both). Each
stage goes on like the privilege drops: off in the image until its bench test on cam #1 passes.
