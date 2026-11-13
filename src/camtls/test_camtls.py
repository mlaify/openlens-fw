# SPDX-License-Identifier: MIT
"""Interop test of camtls with Python's ssl (OpenSSL) and the openssl CLI; no network port.

    python3 -I src/camtls/test_camtls.py TEST_CAMTLS TMPDIR      (src/camtls/test.sh runs it)

TEST_CAMTLS is the CAMTLS_TEST build: `serve CTLFD KEY CERT` serves 443 (http) and 322 (rtsp)
on socketpairs we hand it over a datagram control socket, and hands its backend connections back
the same way; `gen-ca|issue|check` are the real helpers (CAMTLS_TEST_NOW sets their clock).
Checks: TLS 1.3 and 1.2 negotiated; the suite chosen (ChaCha20 when offered first in 1.3, our
order in 1.2); TLS 1.0/1.1 refused (the client offers them with SECLEVEL=0; the captured
ClientHello is replayed too); RSA-only and CBC-only clients refused; the PROXY line and the reply
through camtls; resumption (1.2, 1.3); RTSPS on 322; gen-ca + issue verify against ca.crt with the
IP SAN; OpenSSL enforces the CA's name constraints (leaves for 198.51.100.5 or a DNS name, signed with
ca.key by the openssl CLI, fail in `openssl verify` and in a handshake); `check` says ok / renew /
bad as it should; issue's refusals and key reuse.
"""
import calendar
import hashlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import warnings

BIN, TMP = sys.argv[1], sys.argv[2]
D = os.path.join(TMP, "py")
LOG = open(os.path.join(TMP, "serve.log"), "a")
checks = fails = 0


def check(cond, msg):
    global checks, fails
    checks += 1
    if cond:
        print("ok:", msg)
    else:
        fails += 1
        print("FAIL:", msg)


def camtls(*args, now=None):
    env = dict(os.environ)
    if now is not None:
        env["CAMTLS_TEST_NOW"] = str(now)
    r = subprocess.run([BIN, *args], capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stdout.strip(), r.stderr


def openssl(*args):
    return subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=60)


class Server:
    """A camtls test server; backends answer HTTP (443) or RTSP (322) from threads."""

    def __init__(self, key, crt):
        self.ctl, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.p = subprocess.Popen([BIN, "serve", str(child.fileno()), key, crt, "-v"],
                                  pass_fds=[child.fileno()], stdout=LOG, stderr=LOG)
        child.close()
        self.port = 50000
        self.rtsp_down = b""
        self.ready = threading.Event()
        threading.Thread(target=self._ctl, daemon=True).start()
        if not self.ready.wait(30):
            raise RuntimeError("test server didn't start (see serve.log)")

    def _ctl(self):
        while True:
            try:
                msg, fds, _, _ = socket.recv_fds(self.ctl, 64, 1)
            except OSError:
                return
            if msg == b"ready":
                self.ready.set()
            elif msg == b"backend" and fds:
                b = socket.socket(fileno=fds[0])
                threading.Thread(target=self._backend, args=(b,), daemon=True).start()

    def _backend(self, b):
        b.settimeout(10)
        data = b""
        try:
            while b"\r\n\r\n" not in data[data.find(b"\r\n") + 2:]:
                d = b.recv(4096)
                if not d:
                    return
                data += d
            proxy = data[:data.find(b"\r\n") + 2]
            if proxy.endswith(b" 322\r\n"):
                b.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" + self.rtsp_down)
            else:
                b.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                          % (len(proxy), proxy))
        finally:
            b.close()

    def connect(self, lport=443):
        a, b = socket.socketpair()
        self.port += 1
        msg = ("conn 192.0.2.20 %d 192.0.2.159 %d" % (self.port, lport)).encode()
        socket.send_fds(self.ctl, [msg], [b.fileno()])
        b.close()
        a.settimeout(15)
        return a, self.port

    def close(self):
        try:
            self.ctl.send(b"quit")
            self.p.wait(10)
        except Exception:
            self.p.kill()
        self.ctl.close()


def ctx_verify(cafile, ver=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(cafile)
    if ver:
        c.minimum_version = c.maximum_version = ver
    return c


def ctx_noverify(lo, hi, ciphers=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        c.minimum_version, c.maximum_version = lo, hi
    if ciphers:
        c.set_ciphers(ciphers)
    return c


def request(srv, ctx, host="192.0.2.159", session=None, lport=443):
    """One request through camtls; (reply, version, cipher, reused, session, our port)"""
    a, port = srv.connect(lport)
    s = ctx.wrap_socket(a, server_hostname=host, session=session)
    s.sendall(b"GET / HTTP/1.1\r\nHost: 192.0.2.159\r\n\r\n" if lport == 443 else
              b"PLAY rtsp://192.0.2.159/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    data = b""
    while True:
        try:
            d = s.recv(65536)
        except ssl.SSLZeroReturnError:
            break
        if not d:
            break
        data += d
    out = (data, s.version(), s.cipher()[0], s.session_reused, s.session, port)
    s.close()
    return out


def refused(srv, ctx, host="192.0.2.159"):
    a, _ = srv.connect()
    try:
        ctx.wrap_socket(a, server_hostname=host).close()
        return ""
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return str(e) or type(e).__name__
    finally:
        a.close()


def der_sha256(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(path).read())).hexdigest()


def main():
    shutil.rmtree(D, ignore_errors=True)
    os.makedirs(D)
    rc, out, err = camtls("gen-ca", D)
    check(rc == 0 and re.fullmatch(r"ok ca_fp=[0-9a-f]{64}", out), "gen-ca: " + out)
    check(out.endswith(der_sha256(D + "/ca.crt")), "gen-ca's ca_fp is the SHA-256 of ca.crt's DER")
    rc, out, err = camtls("issue", D, "192.0.2.159", D)
    check(rc == 0 and re.fullmatch(r"ok san=192\.0\.2\.159 not_after=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ "
                                   r"fp=[0-9a-f]{64} key=new", out), "issue: " + out)
    for f, mode in (("ca.key", 0o600), ("server.key", 0o600), ("ca.crt", 0o644), ("server.crt", 0o644)):
        check(os.stat(os.path.join(D, f)).st_mode & 0o777 == mode, "%s is %o" % (f, mode))
    ca, key, crt = D + "/ca.crt", D + "/server.key", D + "/server.crt"

    # ---- the helpers --------------------------------------------------------------------
    rc, out, _ = camtls("check", D)
    m = re.fullmatch(r"ok san=192\.0\.2\.159 not_after=(\S+) ca_fp=([0-9a-f]{64}) fp=([0-9a-f]{64})", out)
    check(rc == 0 and m and m.group(2) == der_sha256(ca) and m.group(3) == der_sha256(crt), "check: " + out)
    na = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ")) if m else 0
    rc, out, _ = camtls("check", D, "192.0.2.159")
    check(rc == 0 and out.startswith("ok "), "check with the right IP: ok")
    rc, out, _ = camtls("check", D, "192.0.2.160")
    check(rc == 1 and out == "renew ip san=192.0.2.159 want=192.0.2.160", "IP changed: " + out)
    rc, out, _ = camtls("check", D, now=na - 10 * 86400)
    check(rc == 1 and out.startswith("renew expiring not_after="), "10 days left: " + out)
    rc, out, _ = camtls("check", D, now=na - 31 * 86400)
    check(rc == 0, "31 days left: ok")
    rc, out, _ = camtls("check", D, now=na + 86400)
    check(rc == 1 and out.startswith("renew expiring"), "expired: " + out)
    rc, out, _ = camtls("check", D, now=1000)
    check(rc == 0, "clock unset (1970): dates not judged: " + out)
    rc, out, _ = camtls("check", D, now=int(time.time()) - 3 * 86400)
    check(rc == 1 and out.startswith("renew not-yet-valid"), "clock set before notBefore: " + out)
    rc, out, _ = camtls("check", D, "192.0.2.1x")
    check(rc == 2 and out.startswith("bad usage"), "check with a bad IP: " + out)
    w = D + "-wrongkey"
    shutil.copytree(D, w)
    openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", w + "/server.key")
    rc, out, _ = camtls("check", w)
    check(rc == 2 and out == "bad server.key doesn't match server.crt", "wrong key: " + out)
    os.remove(w + "/server.crt")
    rc, out, _ = camtls("check", w)
    check(rc == 1 and out == "renew missing server.crt", "missing: " + out)
    openssl("req", "-x509", "-new", "-key", D + "/ca.key", "-subj", "/CN=plain CA", "-days", "30",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-out", w + "/ca.crt")
    shutil.copy(crt, w + "/server.crt")
    rc, out, _ = camtls("check", w)
    check(rc == 2 and out == "bad ca.crt has no name constraints", "a CA without our constraints: " + out)
    os.remove(w + "/ca.crt")
    rc, out, _ = camtls("check", w)
    check(rc == 2 and out == "bad missing ca.crt", "no CA: " + out)
    rc, out, err = camtls("issue", D, "198.51.100.5", w)
    check(rc == 2 and "refused" in err, "issue outside 192.0.2.0/24: exit 2")
    rc, out, err = camtls("issue", D, "192.0.2.07", w)
    check(rc == 2, "issue with a non-canonical address: exit 2")
    rc, out, err = camtls("gen-ca", D)
    check(rc == 2 and "exists" in err, "gen-ca over an existing CA: exit 2")
    r2 = D + "-reissue"
    shutil.copytree(D, r2)
    rc, out, _ = camtls("issue", r2, "192.0.2.160", r2)
    check(rc == 0 and out.endswith("key=reused"), "re-issue keeps CADIR/server.key: " + out)
    rc, out, _ = camtls("check", r2, "192.0.2.160")
    check(rc == 0 and out.startswith("ok san=192.0.2.160 "), "re-issued for the new address: " + out)

    # ---- the CA's O: openlens-fw; a CA made before the rename still issues ----------------
    r = openssl("x509", "-noout", "-subject", "-nameopt", "RFC2253", "-in", D + "/ca.crt")
    check(re.fullmatch(r"subject=O=openlens-fw,CN=camera CA [0-9a-f]{8}", r.stdout.strip()) is not None,
          "gen-ca names the CA O=openlens-fw: " + r.stdout.strip())
    nc = ("nameConstraints=critical,permitted;IP:192.0.2.0/255.255.255.0,"
          "permitted;IP:::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,permitted;DNS:invalid")
    for org, want in (("cam-firmware-dev", 0), ("someone-else", 1)):
        lg = "%s-org-%s" % (D, org)
        os.makedirs(lg)
        shutil.copy(D + "/ca.key", lg + "/ca.key")
        x = openssl("req", "-x509", "-new", "-key", lg + "/ca.key", "-subj", "/CN=camera CA 0123abcd/O=" + org,
                    "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", nc, "-out", lg + "/ca.crt")
        rc, out, err = camtls("issue", lg, "192.0.2.159", lg)
        if want == 0:
            rc2, out2, _ = camtls("check", lg, "192.0.2.159")
            check(x.returncode == 0 and rc == 0 and rc2 == 0 and out2.startswith("ok "),
                  "a pre-rename CA (O=cam-firmware-dev) still issues, and the leaf chains: %s / %s" % (out, out2))
        else:
            check(x.returncode == 0 and rc != 0 and "not a camtls CA name" in err,
                  "a CA with another O is refused: " + err.strip()[-60:])

    # ---- name constraints, enforced by OpenSSL --------------------------------------------
    r = openssl("verify", "-CAfile", ca, crt)
    check(r.returncode == 0, "openssl verify: our leaf: " + r.stdout.strip())
    bad = {}
    for name, san in (("ip", "IP:198.51.100.5"), ("dns", "DNS:camera.example.com"), ("v6", "IP:fd00::5")):
        k, c = "%s/bad-%s.key" % (w, name), "%s/bad-%s.crt" % (w, name)
        open(w + "/ext.cnf", "w").write("[v3]\nsubjectAltName=%s\nbasicConstraints=CA:FALSE\n"
                                         "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" % san)
        openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", k)
        openssl("req", "-new", "-key", k, "-subj", "/CN=" + san.split(":", 1)[1], "-out", w + "/x.csr")
        x = openssl("x509", "-req", "-in", w + "/x.csr", "-CA", ca, "-CAkey", D + "/ca.key", "-set_serial", "7",
                    "-days", "30", "-extfile", w + "/ext.cnf", "-extensions", "v3", "-out", c)
        r = openssl("verify", "-CAfile", ca, c)
        check(x.returncode == 0 and r.returncode != 0 and "permitted subtree violation" in r.stdout + r.stderr,
              "openssl verify refuses a leaf for %s signed by our CA: %s" % (san, (r.stdout + r.stderr).strip()[-60:]))
        bad[name] = (k, c, san.split(":", 1)[1])

    # ---- TLS through camtls ---------------------------------------------------------------
    srv = Server(key, crt)
    try:
        expect = lambda port: b"PROXY TCP4 192.0.2.20 192.0.2.159 %d 443\r\n" % port
        data, ver, cs, _, s13, port = request(srv, ctx_verify(ca))
        check(ver == "TLSv1.3" and data.endswith(expect(port)) and data.startswith(b"HTTP/1.1 200"),
              "TLS 1.3, chain and IP SAN verified, PROXY line and reply: %s %s" % (ver, cs))
        c = ctx_verify(ca)
        c.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
        data, ver, cs, _, _, _ = request(srv, c)
        check(cs == "TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3 ChaCha20 when offered first: " + cs)
        data, ver, cs, _, s12, port = request(srv, ctx_verify(ca, ssl.TLSVersion.TLSv1_2))
        check(ver == "TLSv1.2" and cs == "ECDHE-ECDSA-CHACHA20-POLY1305" and data.endswith(expect(port)),
              "TLS 1.2: %s %s" % (ver, cs))
        c = ctx_verify(ca, ssl.TLSVersion.TLSv1_2)
        c.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305")
        check(request(srv, c)[2] == "ECDHE-ECDSA-CHACHA20-POLY1305", "TLS 1.2 takes our order (ChaCha20)")
        c.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
        check(request(srv, c)[2] == "ECDHE-ECDSA-AES256-GCM-SHA384", "TLS 1.2 AES-256-GCM alone")
        # resumption
        c = ctx_verify(ca, ssl.TLSVersion.TLSv1_2)
        first = request(srv, c)
        again = request(srv, c, session=first[4])
        check(again[3], "TLS 1.2 resumed with a ticket")
        c = ctx_verify(ca, ssl.TLSVersion.TLSv1_3)
        first = request(srv, c)
        again = request(srv, c, session=first[4])
        check(again[3], "TLS 1.3 resumed with a ticket")
        # wrong name
        e = refused(srv, ctx_verify(ca), host="192.0.2.160")
        check("CERTIFICATE_VERIFY_FAILED" in e, "another IP doesn't match the SAN: " + e[-60:])
        # old protocols: the client really offers them (captured), and camtls refuses
        for v, name in ((ssl.TLSVersion.TLSv1, "1.0"), (ssl.TLSVersion.TLSv1_1, "1.1")):
            c = ctx_noverify(v, v, "ALL:@SECLEVEL=0")
            a, b = socket.socketpair()
            s = c.wrap_socket(a, do_handshake_on_connect=False)
            s.settimeout(0.5)
            try:
                s.do_handshake()
            except (socket.timeout, ssl.SSLError, OSError):
                pass
            b.settimeout(2)
            hello = b.recv(65536)
            s.close()
            b.close()
            ver_hello = hello[9:11] if len(hello) > 11 else b""
            check(hello[:1] == b"\x16" and ver_hello == bytes([3, int(name[-1]) + 1]),
                  "OpenSSL offers TLS %s here (ClientHello version %s)" % (name, ver_hello.hex()))
            r, _ = srv.connect()
            r.sendall(hello)
            try:
                resp = r.recv(4096)
            except OSError:
                resp = b""
            r.close()
            check(resp[:1] in (b"", b"\x15"), "TLS %s ClientHello replayed: alert or close, no ServerHello (%s)"
                  % (name, resp[:7].hex()))
            e = refused(srv, ctx_noverify(v, v, "ALL:@SECLEVEL=0"))
            check(e != "", "TLS %s handshake refused: %s" % (name, e[-60:]))
        e = refused(srv, ctx_noverify(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                                      "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:AES128-GCM-SHA256"))
        check(e != "", "an RSA-only client is refused: " + e[-60:])
        e = refused(srv, ctx_noverify(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                                      "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256"))
        check(e != "", "a CBC-only client is refused: " + e[-60:])
        # RTSPS on 322: a long interleaved stream, byte-exact
        frames = bytearray()
        i = 0
        while len(frames) < 3 << 20:
            n = 12 + (i * 7919) % 1388
            frames += b"$" + bytes([i & 1, n >> 8, n & 255]) + bytes((i + j) & 255 for j in range(n))
            i += 1
        srv.rtsp_down = bytes(frames)
        data, ver, cs, _, _, port = request(srv, ctx_verify(ca), lport=322)
        want = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" + srv.rtsp_down
        check(data == want, "RTSPS on 322: %d bytes of interleaved frames exact (%d)" % (len(want), len(data)))
    finally:
        srv.close()

    # a leaf outside our constraints, served by camtls: the client's OpenSSL refuses it
    for name in ("ip", "dns", "v6"):
        k, c, host = bad[name]
        srv = Server(k, c)
        try:
            e = refused(srv, ctx_verify(ca), host=host)
            check("CERTIFICATE_VERIFY_FAILED" in e, "handshake with a %s leaf outside the constraints fails: %s"
                  % (host, e[-70:]))
        finally:
            srv.close()

    print("%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


sys.exit(main())
