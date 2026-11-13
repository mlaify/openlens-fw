# HTTPS and the camera CA

The web UI runs over HTTPS on port 443. Each camera makes its own small certificate authority
(CA) and issues its own certificate. You trust each camera's CA once on each computer.

## Read this first: the camera subnet is a build setting

**The camera's CA can only vouch for addresses in CAM_NET, the subnet the image was built for.**
The build won't run without it. Set it once, before you build:

```
echo 192.168.50.0/24 > cam-net.local      # your camera network, A.B.C.D/PREFIX (prefix 8..30)
```

`cam-net.local` sits at the repository root and git ignores it. Alternatively, pass
`-e CAM_NET=192.168.50.0/24` to the `docker run` of `src/build.sh` and `scripts/build-camtls.sh`.
[`scripts/cam-net.sh`](https://github.com/mlaify/openlens-fw/blob/main/scripts/cam-net.sh)
checks the value, which must be the subnet's network address, and compiles it into:

- camtls: which addresses get a certificate, and the CA's name constraint;
- camcfg: which static addresses `net set` accepts.

`scripts/build-rootfs.sh` stops if camcfg and camtls were built for different subnets, and
`BUILD-INFO.txt` records the value (`cam_net:`). The host tests always use 192.0.2.0/24.

If the camera's address is outside CAM_NET, HTTPS never starts. The camera logs that
`camcfg tls init` failed, retries every minute, and serves the web UI, `/setup` and `/recover` on
plain HTTP on port 80.

A camera that has already made its CA keeps it (it is stored on the DATA partition), with the
constraint it was made with. An image built for another subnet refuses that CA, so choose the
subnet before the camera's first start with HTTPS.

## How it works

- **At first start** the camera makes a CA (EC P-256, valid 10 years). The CA's key never leaves
  the camera.
- The CA carries **critical name constraints**: it may sign only addresses in CAM_NET, no
  IPv6 address and no DNS name. So even a stolen camera CA can't vouch for a website.
- **The camera issues itself a certificate** for its current IPv4 address only (no host name),
  valid 397 days.
- **When DHCP changes the address,** the camera notices within a minute and issues a new
  certificate from the same CA. Your browser doesn't warn, as long as the new address is in the
  range.
- It also renews the certificate 30 days before it ends.
- TLS 1.2 and 1.3 only, ECDHE-ECDSA, ChaCha20-Poly1305 or AES-GCM. No RSA, no CBC.
- `camtls`, a separate program running as its own user, handles TLS. It holds no passwords.

## Ports

| Port | What |
|---|---|
| 443 | HTTPS: web UI, `/setup`, `/recover`, ONVIF |
| 322 | RTSPS: `rtsps://<camera-ip>:322/` (main) and `rtsps://<camera-ip>:322/sub` |
| 80 | Browsers are redirected to `https://`; a form sent over port 80 is refused. ONVIF and `/snapshot.jpg` stay on port 80 for NVRs that need them (see `net.plain` in the [Settings reference](Settings-reference)) |
| 554 | Plain RTSP, unchanged |

Open the pages by IP address (`https://<camera-ip>/ui/`). The certificate names only the
address, and the web UI refuses requests made with a host name.

## Get the CA certificate

**From the web UI:** log in as an admin and open **System**. The **HTTPS** part shows the
certificate's address, its end date and the CA's and the certificate's SHA-256 fingerprints.
Click **Download the camera's CA certificate**; the file is named `camera-ca-<camera-ip>.crt`.
If the page says HTTPS is off, camtls isn't running (see [Troubleshooting](Troubleshooting)).

**Over SSH** (an SSH key added at the claim or on the SSH keys page):

```sh
ssh root@<camera-ip> cat /run/camtls/ca.crt > camera-ca.crt
```

Either way, get the fingerprint over SSH to check the file against:

```sh
ssh root@<camera-ip> camcfg tls show
```

`camcfg tls show` prints a line like:

```text
ok san=<camera-ip> not_after=... ca_fp=<64 hex digits> fp=<64 hex digits>
```

## Check the fingerprint

A download from the web UI came over a connection your browser couldn't verify yet, so the page's
own fingerprints prove nothing on their own. Compare `ca_fp` from `camcfg tls show` (over SSH)
with the file you have:

```sh
openssl x509 -in camera-ca.crt -outform DER | shasum -a 256
```

The two must be the same. (`openssl x509 -in camera-ca.crt -noout -fingerprint -sha256` shows
the same value in upper case with colons.)

Check the name constraints too:

```sh
openssl x509 -in camera-ca.crt -noout -text
```

Look for `X509v3 Name Constraints: critical`, permitting your CAM_NET (for example
`IP:192.168.50.0/255.255.255.0`), one IPv6 entry and `DNS:invalid`. Don't trust a CA without them.

## Trust it on macOS

1. Open **Keychain Access**.
2. **File → Import Items**, choose the certificate file, and import it into the **login** keychain.
   (Opening the downloaded file does the same.)
3. Double-click the certificate (its name starts with `camera CA`).
4. Open **Trust** and set **Secure Sockets Layer (SSL)** to **Always Trust**.
5. Close the window and enter your password.

Safari and Chrome use this. On the developer's Mac, Firefox also loaded the pages without a
warning once the CA was trusted in Keychain. If yours still warns, add it to Firefox as below.

## Trust it in Firefox

1. Open **Settings → Privacy & Security**.
2. Under **Certificates**, click **View Certificates**.
3. On the **Authorities** tab, click **Import** and choose the certificate file.
4. Tick **Trust this CA to identify websites**, then OK.

## Check

Open `http://<camera-ip>/ui/`. The browser goes to `https://<camera-ip>/ui/` without asking for a
login first, shows no warning, and then asks for your login.

## Turning HTTPS off

HTTPS is on in the image (the file `/etc/cam/tls.on`). To build without it, remove
`rootfs/skel/etc/cam/tls.on` before you build. Without HTTPS the web UI, `/setup` and `/recover`
work on plain HTTP on port 80.
