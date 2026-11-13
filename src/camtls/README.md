# camtls: TLS front end for the web UI (HTTPS) and RTSP (RTSPS)

camtls terminates TLS 1.2/1.3 for the camera and passes the plain bytes to the
services that already exist. It holds no passwords: camhttpd and rtspd still parse
the requests and check the Digest credentials. The design and the owner's decisions
are in [docs/PLAN-TLS.md](../../docs/PLAN-TLS.md), §B (HTTPS) and §D (RTSPS).

| File | What |
|---|---|
| `camtls.c` | The daemon, plus the certificate helpers (`gen-ca`, `issue`, `check`) |
| `mbedtls-user-config.h` | Our overlay on mbedTLS 3.6's config: no RSA, CBC, DTLS, renegotiation, ALPN or SNI |
| `test_camtls.c` | The in-process host test, and a `serve` mode that `test_camtls.py` drives |
| `test_camtls.py` | Interop with Python's ssl (OpenSSL) and the openssl CLI |
| `test.sh` | Builds mbedTLS for the host (cached), then runs both tests under ASan/UBSan |

## Why a separate process
- The UNIX sockets are `/run/camhttpd/tls.sock` and `/run/rtspd/tls.sock`, not loopback TCP,
  because any local uid can reach loopback. The backends accept the PROXY line only
  from camtls's uid (SO_PEERCRED).
- camtls runs as its own user (`camtls`, no capabilities). The TLS parser therefore never runs
  with camhttpd's or rtspd's privileges, and they never handle TLS.
- mbedTLS 3.6 LTS is built from Debian's signed source by `scripts/build-camtls.sh`.

## Usage
```
camtls -k KEY -c CERT -U USER -L PORT:SOCKET[:http|rtsp] [-L ...] [-l ADDR] [-r READYFILE] [-v]
camtls gen-ca OUTDIR | issue CADIR IP OUTDIR | check DIR [IP]
```
- `-k`, `-c`: the server key and certificate (PEM). They are root-only files, read before the
  privilege drop.
- `-L PORT:SOCKET[:KIND]`: a listener. TLS on TCP `PORT` is relayed to the UNIX `SOCKET`.
  - `KIND` is `http` or `rtsp`. By default port 322 is `rtsp` and every other port is `http`.
  - Up to 4 listeners, and at most 10 connections across all of them.
- `-p PORT -s SOCKET`: shorthand for `-L PORT:SOCKET`; `-p` defaults to 443. This keeps the
  older 443-only form working.
- `-U`: the user to drop to, read from `/etc/passwd`. `UID:GID` also works.
- `-l`: the IPv4 address to listen on (default: any).
- `-r`: written with our pid once **every** listener is bound and we have dropped root, and
  removed at an orderly exit. camtls-run should also remove it before each start, in case of a
  crash.
- `-v`: one log line per connection (version, suite, resumed, why it closed).

How camtls-run starts it (it runs as root and binds 443 and 322 before the drop):
```
camtls -k /mnt/nand/cam/tls/server.key -c /mnt/nand/cam/tls/server.crt -U camtls \
    -L 443:/run/camhttpd/tls.sock -L 322:/run/rtspd/tls.sock -r /run/camtls/ready
```

Start-up, as root: `psa_crypto_init`, seed CTR_DRBG, load the key and certificate (they must
match), check the renew conditions, bind every port, `drop_to(USER)` with no capabilities
(`src/rtspd/drop.h`) and check that `setuid(0)` fails, write `READYFILE`, serve.

Exit codes: 0 on SIGTERM/SIGINT, 1 on a configuration or start-up error, and 3 for **renew and
restart me** (camtls-run then runs `camcfg tls renew` and starts camtls again). camtls exits 3
when eth0's IPv4 differs from the certificate's IP SAN (at start and every 60 s; no address on
eth0 yet is not a reason), or when the certificate ends within 30 days (at start and hourly; not
while the clock is unset, before BUILD_EPOCH).

## TLS
- TLS 1.2 and 1.3 only.
- Suites, in this order:
  - TLS 1.3: CHACHA20_POLY1305, AES_128_GCM, AES_256_GCM;
  - TLS 1.2: ECDHE-ECDSA with the same three.

  TLS 1.2 uses our order. **TLS 1.3 in mbedTLS 3.6 takes the client's order**, so a Mac that
  offers AES-GCM first gets AES-GCM (6.8 MB/s on the A7, against 24 MB/s for ChaCha20).
- Groups: X25519, then P-256. Signatures: ECDSA P-256 SHA-256 only.
- Session tickets:
  - ChaCha20-Poly1305 key, in memory only, replaced every 24 h;
  - 2 tickets per TLS 1.3 handshake;
  - TLS 1.3 resumption always uses `psk_dhe_ke`, never PSK alone.
- No renegotiation, 0-RTT, RSA or CBC.

## Connections and limits
A connection goes through these stages:
1. **Waiting**: accepted but over a limit, not yet handshaking. Closed after 5 s.
2. **Handshake**: 5 s deadline.
3. **First bytes**: up to 10 s for the first decrypted bytes.
4. **Backend connect**: non-blocking. EAGAIN (backlog full), ECONNREFUSED or ENOENT is
   retried every 50 ms for 5 s. Then `http` gets an HTTP 503 over TLS and `rtsp` just
   close_notify (an RTSP reply would need the request's CSeq).
5. **Relay**: both ways, until the idle limit.
6. **close_notify** once the backend closes.

The first write to the backend starts with:
```
PROXY TCP4 <client ip> <camera ip> <client port> <listener port>\r\n
```
The camera ip is the address the client reached (`getsockname`). No field has leading zeros.

| | `http` (443) | `rtsp` (322) |
|---|---|---|
| connections | 6 (= camhttpd's MAX_CLIENTS) | 4 (= rtspd's slots) |
| per client address | 4, every stage | 2, counting only those not yet relaying (SSS's main + sub streams can all relay) |
| idle (no byte either way) | 120 s | 600 s; never while bytes flow; no lifetime cap |

Shared across listeners:
- **Handshakes:** at most 2 at a time.
- **Token bucket of full handshakes:** 10/s, burst 20. A resumed handshake gets its token back.
- **Waiting queue:** 10 connections. Beyond that, new connections stay in the kernel's listen
  backlog.

When a connection is over a limit it waits; it is never refused at once. The oldest waits
first, and one held back only by its own address's or listener's limit doesn't block the others.

**Back-pressure.** Each connection has one buffer each way (client to backend 16 KiB + 64 B;
backend to client 4 KiB, one TLS record), and `SO_SNDBUF` toward the client is 32 KiB (Linux
doubles it to 64 KiB). camtls reads from the backend only once `mbedtls_ssl_write` has taken the
previous chunk, retrying WANT_WRITE with the same bytes. It reads the client only while there is
room, and keeps reading while mbedTLS holds decrypted bytes. So a viewer that stops reading
stops the backend: camhttpd's preview sends a frame only after the last one, and rtspd drops
frames when its socket is full. One busy connection gets at most 16 rounds per pass; a pass cut
short there doesn't let the loop wait, so the rest moves on the next pass at once. A reused
connection slot starts empty: none of the last connection's bytes or offsets carry over.

## Certificate helpers (`camcfg tls` runs them as root)
Each helper prints one line on stdout, and its errors on stderr.

| Command | Does | Prints / exit |
|---|---|---|
| `gen-ca OUTDIR` | New CA (described below) into OUTDIR: `ca.key` (P-256 SEC1 PEM, 0600) and `ca.crt` (0644). Refuses if `OUTDIR/ca.key` exists | `ok ca_fp=<sha256 of ca.crt DER>` / 0; 1 error; 2 refused |
| `issue CADIR IP OUTDIR` | `OUTDIR/server.crt` for IP, signed with `CADIR/ca.key`. Reuses `CADIR/server.key` if it exists, else writes a new `OUTDIR/server.key` (0600) | `ok san=IP not_after=YYYY-MM-DDTHH:MM:SSZ fp=<sha256> key=new\|reused` / 0; 1 error; 2 IP not canonical or outside CAM_NET |
| `check DIR [IP]` | `DIR/server.crt` chains to `DIR/ca.crt`, matches `DIR/server.key`, has one IP SAN in CAM_NET and EKU serverAuth | see below |

`check` prints exactly one of:
- `ok san=IP not_after=YYYY-MM-DDTHH:MM:SSZ ca_fp=<hex64> fp=<hex64>`, exit 0;
- `renew <why> ...`, exit 1, where `<why>` is one of:
  - `missing server.crt` or `missing server.key`;
  - `ip san=A want=B`;
  - `expiring not_after=...`: less than 30 days left, or already expired;
  - `not-yet-valid san=A`;
- `bad <reason>`, exit 2, for example:
  - `bad missing ca.crt`;
  - `bad ca.crt has no name constraints`;
  - `bad server.key doesn't match server.crt`;
  - `bad server.crt doesn't verify against ca.crt: ...`;
  - `bad usage: ...`.

camcfg should rely only on the first word. Dates are not judged while the clock is unset (before BUILD_EPOCH).

**CA.** EC P-256.
- Subject: `CN=camera CA <first 8 hex of SHA-256(SubjectPublicKeyInfo)>, O=openlens-fw`. A CA
  made before the rename has `O=cam-firmware-dev`; `issue` still accepts it and copies its O
  into the issuer.
- `basicConstraints`: critical, CA, pathlen 0.
- `keyUsage`: critical, keyCertSign and cRLSign.
- `subjectKeyIdentifier`.
- **Critical `nameConstraints`**, permitted:
  - `IP:` CAM_NET, the camera subnet compiled in (`src/camnet.h`), e.g. `IP:192.0.2.0/255.255.255.0`;
  - `IP:::/128` (no IPv6 address fits);
  - `DNS:invalid` (no real name fits).

  mbedTLS has no writer for this extension, so it is built with asn1write. mbedTLS can't parse
  it either: the helpers parse `ca.crt` with `mbedtls_x509_crt_parse_der_with_ext_cb`, accepting
  exactly these DER bytes and no other unknown extension.
- Serial: 16 bytes, positive.
- notBefore = max(now, BUILD_EPOCH) − 1 day; valid for 10 years.

**Server certificate.**
- Subject `CN=<IP>`; SAN `IP:<IP>` only.
- `basicConstraints` CA:FALSE.
- `keyUsage` digitalSignature (critical); `extendedKeyUsage` serverAuth (mbedTLS writes it
  critical).
- SKI and AKI.
- notBefore as for the CA; valid 397 days, inside Apple's 398-day limit for locally trusted roots.

## Build
`scripts/build-camtls.sh` builds the static ARMv7 binary `build/arm/camtls`:
```
arm-linux-gnueabihf-gcc -std=c11 -O2 -mcpu=cortex-a7 ... -static -I<mbedtls>/include -Isrc/rtspd \
    $CAM_NET_CFLAGS src/camtls/camtls.c libmbedtls.a libmbedx509.a libmbedcrypto.a
```
CAM_NET, the camera subnet, is required: `CAM_NET=A.B.C.D/PREFIX` in the environment or in
`cam-net.local` at the repository root. `scripts/cam-net.sh` checks it and makes the
`-DCAM_NET_*` flags; without them the build stops (`src/camnet.h`). The tests use 192.0.2.0/24.
Its BUILD_EPOCH defaults to `rootfs/SOURCE_DATE_EPOCH`'s value, as in camhttpd; pass
`-DBUILD_EPOCH=...LL` to change it.

## Tests
```
bash src/camtls/test.sh                       # or via scripts/host-tests.sh
MBEDTLS_SRC=/path/to/mbedtls-3.6 bash src/camtls/test.sh
```
The tests need the mbedTLS source in `build/mbedtls-src` (from `scripts/build-camtls.sh`) or in
`$MBEDTLS_SRC`. Without it the test fails and says so.

No port or camera is needed: clients and backends are socketpairs, given made-up addresses
through a test hook, and the monotonic and wall clocks are the test's own.

**`test_camtls`** (in-process, an mbedTLS client on each socketpair): TLS 1.3 and 1.2 and the
suites chosen; the PROXY line and a byte-exact relay (100 KB up, 1 MB down); back-pressure (10 MB
toward a client that doesn't read: camtls takes under 1 MB and stops, then everything arrives);
close_notify both ways; the handshake, first-byte and idle deadlines; the http limits, the
waiting queue and its timeout, the token bucket; backend busy (retries every 50 ms, then 503) and
a late accept; the rtsp limits and the shared handshake limit; a 4 MB interleaved `$`-frame stream
with RTCP upstream over ~35 fake minutes, exact both ways and never cut, then closed after 600 s
of silence; `-L` parsing; resumption (TLS 1.3 with 2 tickets, TLS 1.2); the nameConstraints DER
and plain mbedTLS refusing the CA; the renew rule.

**`test_camtls.py`** (OpenSSL): TLS 1.3 and 1.2 with the chain and IP SAN verified, ChaCha20 when
offered first, our order for 1.2; resumption; TLS 1.0 and 1.1 refused (OpenSSL offers them at
SECLEVEL=0; the captured ClientHello is replayed too); RSA-only and CBC-only clients refused;
RTSPS, 3 MB exact; leaves for 198.51.100.5, `camera.example.com` and `fd00::5` signed with our CA key
fail `openssl verify` and a real handshake ("permitted subtree violation"); every `check` verdict,
and `issue`'s refusals and key reuse.
