#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of scripts/gate3-live.py (no camera, no network): Digest against RFC 2617's example,
the camera-side parsing on canned BusyBox output (a clean camera passes; a vendor process, an
extra listener, a rw root, a loose DATA directory and a root password each fail), the MAC kept
out of the evidence, each daemon's uid (camhttpd's monitor and worker told apart), the
WS-Discovery subnet test, and the tampered .camfw copies. TLS (camtls, docs/PLAN-TLS.md §B): 443
expected only while camtls is ready; the DER walk (OIDs, both time forms, SAN, EKU, CA flag,
nameConstraints) on certificates the openssl command makes; and the whole tls part against a
fake camera on socketpairs (camtls's settings: every check passes; a server that also takes
TLS 1.0 and CBC suites, a wrong SAN, an RSA key, 800 days, a CA without nameConstraints: each
caught), plus /setup's redirect. Without the openssl command those parts print "skip:".

  python3 -I scripts/test_gate3_live.py
"""
import base64
import importlib.util
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("g3", os.path.join(HERE, "gate3-live.py"))
g3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g3)

MAC = "02:11:22:aa:bb:cc"          # locally administered, made up
CLEAN = {
    "version": ["20261024.2"],
    "uptime": [" 12:00:00 up  1:00,  load average: 0.10, 0.20, 0.30"],
    "netstat": ["Active Internet connections (only servers)",
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State",
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN",
                "tcp        0      0 0.0.0.0:554             0.0.0.0:*               LISTEN",
                "udp        0      0 0.0.0.0:3702            0.0.0.0:*"],
    "ps": ["PID   USER     TIME  COMMAND", "    1 root      0:01 init"],
    "cmdlines": ["1 init ", "88 /sbin/syslogd -n ", "90 /bin/sh /usr/sbin/rtspd-run ",
                 "91 /usr/sbin/rtspd ", "92 logger -t rtspd ", "95 /usr/sbin/camhttpd -Z camhttpd ",
                 "96 /usr/sbin/camhttpd -Z camhttpd ",
                 "97 /usr/sbin/dropbear -F -E -p 22 -r /mnt/nand/cam/ssh/dropbear_ed25519_host_key ",
                 "99 {sshd-run} /bin/sh /usr/sbin/sshd-run ", "120 sh -c echo x ", "122 -sh ", "121 cat /etc/cam/version "],
    "mounts": ["/dev/root / squashfs ro,relatime 0 0", "proc /proc proc rw,relatime 0 0",
               "tmpfs /run tmpfs rw,nosuid,nodev,relatime 0 0",
               "tmpfs /run/fw tmpfs rw,nosuid,nodev,noexec,relatime,size=6144k,mode=700 0 0",
               "/dev/mtdblock3 /mnt/nand jffs2 rw,nosuid,nodev,relatime 0 0"],
    "perms": ["drwx------    4 root     root             0 Oct 24 12:00 /mnt/nand/cam",
              "-rw-------    1 root     root           321 Oct 24 12:00 /mnt/nand/cam/cam.conf",
              "drwx------    2 root     root             0 Oct 24 12:00 /mnt/nand/cam/ssh",
              "drwx------    2 root     root            40 Oct 24 12:00 /run/fw",
              "drwxrwxrwt    2 root     root            40 Oct 24 12:00 /tmp"],
    "suid": [], "worldwritable": [], "shadow": ["root:locked"],
    "ifconfig": ["eth0      Link encap:Ethernet  HWaddr " + MAC.upper(),
                 "          inet addr:192.0.2.159  Bcast:192.0.2.255  Mask:255.255.255.0"],
    "inittab": ["::sysinit:/etc/init.d/rcS"],
    "irled": ["crw-------    1 root     root       93,   0 Oct 24 12:00 /dev/irled"],
    # PID NAME PPID UID EUID SAVED GID: the camhttpd monitor (root) and its worker, rtspd and dropbear
    # as root (their drops still off), a dropbear session; no ntpc running
    "uids": ["91 rtspd 90 0 0 0 0", "95 camhttpd 94 0 0 0 0", "96 camhttpd 95 102 102 102 102",
             "97 dropbear 1 0 0 0 0", "130 dropbear 97 0 0 0 0", "131 camhttpd 1 x 0 0 0"],
    "passwd": ["root:0", "rtspd:100", "ntpc:101", "camhttpd:102"],
    "mac": [MAC],
    "logread": ["Oct 24 12:00:01 cam user.info camhttpd: listening on 80"],
}


class FakeSsh:
    def __init__(self, sec):
        self.sec, self.calls = sec, []

    def run(self, cmd, data=None, extra=(), timeout=120):
        self.calls.append((cmd, data))
        if cmd and cmd.startswith("echo '== version'"):
            return 0, "".join(f"== {k}\n" + "".join(x + "\n" for x in v) for k, v in self.sec.items()), ""
        return 1, "", "camupdate: REFUSED: test\n"


def side(sec):
    d = tempfile.mkdtemp()
    r = g3.Run(d)
    got = g3.camera_side(r, FakeSsh(sec))
    return r, got, d


def verdict(r, check):
    m = [ln for ln in r.lines if check in ln]
    assert m, (check, r.lines)
    return m[0].split()[0]


def main():
    # RFC 2617 §3.5: Mufasa / Circle Of Life
    ch = {"realm": "testrealm@host.com", "qop": "auth,auth-int", "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
          "opaque": "5ccc069c403ebaf9f0171e9517f40e41"}
    h = g3.digest_header(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html")
    cn = re.search(r'cnonce="([^"]+)"', h).group(1)
    ha1 = g3.md5("Mufasa:testrealm@host.com:Circle Of Life")
    want = g3.md5(f"{ha1}:{ch['nonce']}:00000001:{cn}:auth:{g3.md5('GET:/dir/index.html')}")
    assert f'response="{want}"' in h and 'opaque="5ccc' in h and "qop=auth," in h, h
    # RFC 2069 form (rtspd: no qop) with the RFC's cnonce-less example value
    h = g3.digest_header({"realm": "testrealm@host.com", "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093"},
                         "Mufasa", "CircleOfLife", "GET", "/dir/index.html")
    assert 'response="1949323746fe6a43ef61f9606e7febea"' in h, h
    assert g3.parse_challenge('Digest realm="camera", nonce="abc", algorithm=MD5') == \
        {"realm": "camera", "nonce": "abc", "algorithm": "MD5"}
    print("ok: Digest (RFC 2617 qop=auth, RFC 2069 example), challenge parsing")

    r, sec, d = side(CLEAN)
    bad = [ln for ln in r.lines if ln.startswith(("FAIL", "WARN"))]
    assert not bad, bad
    assert r.mac == MAC
    ev = open(os.path.join(d, "camera-side.txt")).read()
    assert MAC.upper() not in ev.upper() and "<MAC>" in ev and "== mac" not in ev, ev
    print("ok: a clean camera passes every camera-side check; the MAC is redacted from the evidence")
    info = [ln for ln in r.lines if "§7 runs as:" in ln]
    assert all(ln.startswith("INFO") for ln in info), info
    want = ["§7 runs as: rtspd (pid 91): uid 0 (root), gid 0",
            "§7 runs as: ntpc: not running",
            "§7 runs as: camhttpd monitor (pid 95): uid 0 (root), gid 0",
            "§7 runs as: camhttpd worker (pid 96): uid 102 (camhttpd), gid 102",
            "§7 runs as: dropbear (pid 97): uid 0 (root), gid 0",
            "§7 runs as: dropbear session (pid 130): uid 0 (root), gid 0",
            "§7 runs as: camtls: not running"]
    flat = [" ".join(ln.split()) for ln in info]
    for w in want:
        assert any(w in ln for ln in flat), (w, flat)
    assert len(info) == len(want), info                  # the garbled line (pid 131) is skipped
    print("ok: each daemon's uid as INFO lines: camhttpd's monitor and worker told apart")

    def broken(**kw):
        s = {k: list(v) for k, v in CLEAN.items()}
        for k, v in kw.items():
            s[k] = s[k] + v if k in ("netstat", "cmdlines", "suid", "worldwritable") else v
        return side(s)[0]
    r = broken(cmdlines=["300 /app/procman -d "])
    assert verdict(r, "no vendor processes") == "FAIL"
    r = broken(cmdlines=["301 /usr/sbin/telnetd -l /bin/sh "])
    assert verdict(r, "allowlist") == "WARN" and "telnetd" in "\n".join(r.lines)
    r = broken(netstat=["tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN"])
    assert verdict(r, "listeners") == "FAIL"
    r = broken(netstat=["udp        0      0 0.0.0.0:68              0.0.0.0:*"])
    assert verdict(r, "listeners") == "PASS"
    r = broken(mounts=["/dev/root / squashfs rw,relatime 0 0"])
    assert verdict(r, "read-only squashfs") == "FAIL"
    r = broken(mounts=CLEAN["mounts"] + ["/dev/mtdblock4 /mnt/x ext4 rw 0 0"])
    assert verdict(r, "writable mounts") == "FAIL"
    r = broken(mounts=CLEAN["mounts"][:-1] + ["/dev/mtdblock3 /mnt/nand jffs2 rw,relatime 0 0"])
    assert verdict(r, "writable mounts") == "WARN"
    r = broken(perms=["drwxr-xr-x    4 root     root             0 Oct 24 12:00 /mnt/nand/cam"])
    assert verdict(r, "is 0700") == "FAIL"
    r = broken(perms=CLEAN["perms"] + ["-rw-r--r--    1 root     root             9 Oct 24 12:00 /mnt/nand/cam/users"])
    assert verdict(r, "readable by others") == "WARN"
    r = broken(irled=["ls: /dev/irled: No such file or directory"])
    assert verdict(r, "/dev/irled") == "FAIL"
    r = broken(irled=["-rw-r--r--    1 root     root             1 Oct 25 01:50 /dev/irled"])
    assert verdict(r, "/dev/irled") == "FAIL"
    r = broken(shadow=["root:PASSWORD SET"])
    assert verdict(r, "root has no password") == "FAIL"
    r = broken(worldwritable=["/mnt/nand/cam/x", "/mnt/nand/cam/x"])
    assert verdict(r, "world-writable") == "FAIL" and "\n".join(r.lines).count("/mnt/nand/cam/x") == 1
    r = broken(mounts=CLEAN["mounts"] + ["tmpfs /dev tmpfs rw,nosuid,noexec,relatime,mode=755 0 0"])
    assert verdict(r, "writable mounts") == "PASS", r.lines
    r = broken(logread=[f"udhcpc: lease for {MAC.replace(':', '').upper()}"])
    assert verdict(r, "MAC absent from logread") == "FAIL"
    assert MAC.replace(":", "") not in "\n".join(r.lines).lower()
    print("ok: vendor process, extra listener, rw root, other rw fs, jffs2 without nosuid, loose DATA,"
          " root password, world-writable file and a MAC in the log are each caught")
    r = broken(uids=["96 camhttpd 95 102 0 0 102"])        # a half-done drop shows (still INFO)
    assert any("euid 0, saved 0" in ln and ln.startswith("INFO") for ln in r.lines), r.lines
    print("ok: a uid whose effective or saved id differs is shown")

    s = FakeSsh(CLEAN)
    s.sec = {}
    r = g3.Run(tempfile.mkdtemp())
    assert g3.camera_side(r, s) is None and verdict(r, "ssh to the camera") == "FAIL"
    print("ok: an SSH failure is a FAIL, not a pass")

    assert g3.BAD_SSH.search("|       hmac-sha1-etm@openssh.com")
    assert g3.BAD_SSH.search("|       aes128-cbc")
    assert g3.BAD_SSH.search("|       ssh-rsa")
    for good in ("|       rsa-sha2-256", "|       curve25519-sha256", "|       hmac-sha2-256-etm@openssh.com",
                 "|       chacha20-poly1305@openssh.com", "|       diffie-hellman-group14-sha256",
                 "|       ssh-ed25519", "|       kex-strict-s-v00@openssh.com"):
        assert not g3.BAD_SSH.search(good), good
    print("ok: weak SSH algorithm names are caught, good ones aren't")

    t = tempfile.mkdtemp()
    hdr = b"magic=camfw1\ndevice=MCA40E-IFADO\npart=rootfs\nversion=20261024.2\nsize=8192\nsha256=00\n\n"
    ok_key, hf = os.path.join(t, "owner"), os.path.join(t, "h")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ok_key], check=True, stdin=subprocess.DEVNULL)
    open(hf, "wb").write(hdr)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", ok_key, "-n", "cam-firmware", hf], check=True,
                   capture_output=True, stdin=subprocess.DEVNULL)
    sig = open(hf + ".sig", "rb").read()
    pay = b"hsqs" + bytes(8188)
    f = os.path.join(t, "p.camfw")
    open(f, "wb").write(hdr + sig + pay)
    v = g3.camfw_variants(f, t)
    assert b"version=20261024.999" in v["header tampered (version raised)"]
    assert v["payload tampered (one bit)"] != hdr + sig + pay and len(v["payload tampered (one bit)"]) == len(hdr + sig + pay)
    assert v["unsigned (no signature)"] == hdr + pay
    assert v["payload truncated"] == hdr + sig + pay[:4096]
    o = v["signed by another key (version raised)"]
    assert o.startswith(hdr.replace(b".2\n", b".999\n")) and b"BEGIN SSH SIGNATURE" in o and o.endswith(pay)
    hdr2 = hdr.replace(b".2\n", b".999\n")
    sigf = os.path.join(t, "o.sig")
    open(sigf, "wb").write(o[len(hdr2):-len(pay)])
    open(os.path.join(t, "o.hdr"), "wb").write(hdr2)
    pub = open(os.path.join(t, "stranger.pub")).read().split()
    open(os.path.join(t, "allowed"), "w").write(f"s {pub[0]} {pub[1]}\n")
    p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", os.path.join(t, "allowed"), "-I", "s", "-n",
                        "cam-firmware", "-s", sigf], stdin=open(os.path.join(t, "o.hdr"), "rb"), capture_output=True)
    assert p.returncode == 0, p.stderr
    r = g3.Run(tempfile.mkdtemp())
    fs = FakeSsh({})
    g3.camupdate_checks(r, fs, [f], t, "20261024.2")       # unfixed camupdate: the forgery isn't sent
    assert len(fs.calls) == 7 and any(ln.startswith("INFO") and "predates the fix" in ln for ln in r.lines), r.lines
    r, fs = g3.Run(tempfile.mkdtemp()), FakeSsh({})
    g3.camupdate_checks(r, fs, [f], t, "20261024.3")
    # the reserved-field forgery, on a real ssh-keygen signature: same key and signature, 2000 bytes reserved
    real = sig
    forged = g3.sshsig_reserved(real, 2000)
    def fields(a):
        bl = base64.b64decode("".join(a.decode().strip().splitlines()[1:-1]))
        o, f = 10, []
        for _ in range(5):
            n = int.from_bytes(bl[o:o + 4], "big")
            f.append(bl[o + 4:o + 4 + n])
            o += 4 + n
        assert o == len(bl)
        return f
    fr, ff = fields(real), fields(forged)
    assert fr[2] == b"" and ff[2] == b"A" * 2000 and fr[:2] == ff[:2] and fr[3:] == ff[3:]
    assert g3.sshsig_reserved(real, 0) == real
    assert len(fs.calls) == 8 and all(c[0] == "camupdate --check -" for c in fs.calls)
    assert all(ln.startswith("PASS") for ln in r.lines), r.lines
    print("ok: .camfw copies (header/payload tampered, truncated, appended bytes, unsigned, another key's"
          " valid signature, filled SSHSIG reserved field) and camupdate --check over stdin")
    # RTSP replies without Content-Length have no body: no wait for more (rtspd's login deadline)
    import socket, time as _t
    x, y = socket.socketpair()
    x.settimeout(10)
    y.sendall(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"ab\"\r\n\r\n")
    t0 = _t.time()
    st, h, body, _ = g3.recv_reply(x, rtsp=True)
    assert st == 401 and body == b"" and _t.time() - t0 < 1 and h["www-authenticate"].startswith("Digest"), (st, body)
    y.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 5\r\n\r\nv=0\r\n")
    assert g3.recv_reply(x, rtsp=True)[2] == b"v=0\r\n"
    x.close(); y.close()
    print("ok: RTSP replies: no Content-Length = no body, Content-Length honoured")
    tls_tests()
    print("all gate3-live tests passed")


# ---- TLS (camtls) ----
HOST = "192.0.2.159"


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True, stdin=subprocess.DEVNULL)


def make_pki(d):
    """A camera-like CA (P-256, critical nameConstraints) and server certificate for HOST, plus bad
    ones: an RSA server certificate with a DNS name, 800 days and no EKU, and a CA without
    nameConstraints. The paths by name."""
    nc = ("nameConstraints=critical,permitted;IP:192.0.2.0/255.255.255.0,"
          "permitted;IP:::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,permitted;DNS:invalid")
    for name, extra in (("ca", ["-addext", nc]), ("ca-plain", [])):
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", f"{name}.key", "-out", f"{name}.crt", "-days", "3650", "-subj", "/CN=camera CA",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", *extra, cwd=d)
    with open(os.path.join(d, "srv.ext"), "w") as f:
        f.write(f"subjectAltName=IP:{HOST}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\n")
    with open(os.path.join(d, "bad.ext"), "w") as f:
        f.write(f"subjectAltName=DNS:cam.example,IP:{HOST}\nauthorityKeyIdentifier=keyid\n")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "srv.key",
            "-out", "srv.csr", "-subj", f"/CN={HOST}", cwd=d)
    openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", "2",
            "-days", "397", "-extfile", "srv.ext", "-out", "srv.crt", cwd=d)
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "bad.key", "-out", "bad.csr",
            "-subj", "/CN=bad", cwd=d)
    openssl("x509", "-req", "-in", "bad.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", "3",
            "-days", "800", "-extfile", "bad.ext", "-out", "bad.crt", cwd=d)
    return {n: os.path.join(d, n) for n in ("ca.crt", "ca-plain.crt", "srv.crt", "srv.key", "bad.crt")}


def der_of(path):
    return ssl.PEM_cert_to_DER_cert(open(path).read())


class FakeCamera:
    """camtls on 443 and camhttpd on 80 while camtls is ready, each connection a socketpair served
    by a thread. weak: the server also takes TLS 1.0 and a CBC suite (what the checks must catch)."""

    def __init__(self, pki, weak=False, redirect_to=HOST):
        self.pki, self.weak, self.redirect_to, self.seen = pki, weak, redirect_to, []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki["srv.crt"], pki["srv.key"])
        ctx.set_ciphers("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
                        + (":ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0" if weak else ""))
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1 if weak else ssl.TLSVersion.TLSv1_2
        self.ctx = ctx

    def connect(self, host, port, timeout=10):
        a, b = socket.socketpair()
        a.settimeout(timeout)
        b.settimeout(10)
        threading.Thread(target=self.serve, args=(b, port), daemon=True).start()
        return a

    def answer(self, port, method, path):
        if port == 80:
            if method == "GET" and (path in ("/", "/setup") or path.startswith("/ui/")):
                return f"302 Found\r\nLocation: https://{self.redirect_to}{path}", ""
            if method == "POST" and path == "/setup":
                return "403 Forbidden", "no"
            if path == "/snapshot.jpg":
                return '401 Unauthorized\r\nWWW-Authenticate: Digest realm="camera", nonce="ab", qop="auth"', ""
            if path.startswith("/onvif/"):
                return "200 OK\r\nContent-Type: application/soap+xml", "<s:Envelope/>"
        else:
            if path.startswith("/ui/"):
                return '401 Unauthorized\r\nWWW-Authenticate: Digest realm="camera", nonce="cd", qop="auth"', ""
        return "404 Not Found", "not here"

    def serve(self, sock, port):
        try:
            if port == 443:
                sock = self.ctx.wrap_socket(sock, server_side=True)
            req = b""
            while b"\r\n\r\n" not in req:
                d = sock.recv(4096)
                if not d:
                    return
                req += d
            method, path, _ = req.split(b"\r\n")[0].decode().split(" ")
            self.seen.append((port, method, path))
            status, body = self.answer(port, method, path)
            sock.sendall(f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode())
        except (ssl.SSLError, OSError, ValueError):
            pass
        finally:
            sock.close()


def tls_sec(pki, ready=True, ca="ca.crt", leaf="srv.crt"):
    sec = {k: list(v) for k, v in CLEAN.items()}
    info = f"ok san={HOST} not_after=20271127T000000Z ca_fp={g3.fp(der_of(pki[ca]))} fp={g3.fp(der_of(pki[leaf]))}"
    sec["tls"] = (["ready"] if ready else []) + [info, ""]
    sec["tlsca"] = open(pki[ca]).read().strip().splitlines()
    return sec


def tls_tests():
    g3.CAM_NET = g3.ipaddress.ip_network("192.0.2.0/24")    # main() sets it from --cam-net/CAM_NET
    # 443 only while camtls is ready; camtls and camtls-run on the allowlist; its uid reported
    sec = {k: list(v) for k, v in CLEAN.items()}
    l443 = "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN"
    l322 = "tcp        0      0 0.0.0.0:322             0.0.0.0:*               LISTEN"
    sec["netstat"] = CLEAN["netstat"] + [l443, l322]
    sec["cmdlines"] = CLEAN["cmdlines"] + ["140 /usr/sbin/camtls -k /mnt/nand/cam/tls/server.key ",
                                           "139 {camtls-run} /bin/sh /usr/sbin/camtls-run "]
    sec["uids"] = CLEAN["uids"] + ["140 camtls 139 103 103 103 103"]
    sec["passwd"] = CLEAN["passwd"] + ["camtls:103"]
    sec["tls"] = ["ready", "ok san=192.0.2.159 not_after=20271127T000000Z ca_fp=aa fp=bb", ""]
    r = side(sec)[0]
    assert verdict(r, "listeners") == "PASS" and verdict(r, "allowlist") == "PASS", r.lines
    assert any("HTTPS (camtls): ready; san=192.0.2.159" in ln for ln in r.lines), r.lines
    assert any("camtls (pid 140): uid 103 (camtls)" in " ".join(ln.split()) for ln in r.lines), r.lines
    sec["tls"] = []
    assert verdict(side(sec)[0], "listeners") == "FAIL"           # 443/322 open, camtls not ready
    sec["tls"], sec["netstat"] = ["ready"], CLEAN["netstat"] + [l443]
    assert verdict(side(sec)[0], "listeners") == "FAIL"           # ready, but 322 (RTSPS) not listening
    sec["tls"], sec["netstat"] = ["ready"], CLEAN["netstat"]
    assert verdict(side(sec)[0], "listeners") == "FAIL"           # ready, but 443 not listening
    assert g3.tcp_ok(sec) == {22, 80, 322, 443, 554} and g3.tcp_ok(CLEAN) == {22, 80, 554}
    assert g3.tls_state({"tls": ["ready"], "tlsca": ["junk"]}) == (True, {}, "")
    print("ok: 443 and 322 expected exactly while camtls is ready; camtls and camtls-run allowed, its uid reported")

    assert g3.der_oid(bytes.fromhex("2a8648ce3d030107")) == g3.OID_P256
    assert g3.der_oid(bytes.fromhex("2b06010505070301")) == g3.OID_SERVER_AUTH
    assert g3.der_time(0x17, b"491231235959Z").year == 2049 and g3.der_time(0x17, b"500101000000Z").year == 1950
    assert g3.der_time(0x18, b"20501231235959Z").year == 2050
    for bad in (b"\x30", b"\x30\x05\x00", b"\x30\x85\x00\x00\x00\x00\x01"):
        try:
            g3.der(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    print("ok: DER: OIDs, UTCTime and GeneralizedTime, truncated or oversized lengths refused")

    if not shutil.which("openssl"):
        print("skip: no openssl command: the certificate and handshake tests")
        return
    d = tempfile.mkdtemp()
    try:
        pki = make_pki(d)
    except subprocess.CalledProcessError as e:
        print(f"skip: openssl couldn't make the test certificates: {e.stderr.decode(errors='replace')[-200:]}")
        return
    ca, leaf, bad, plain = (der_of(pki[n]) for n in ("ca.crt", "srv.crt", "bad.crt", "ca-plain.crt"))
    c = g3.parse_cert(leaf)
    assert g3.cert_san(c) == [f"IP {HOST}"] and g3.cert_eku(c) == [g3.OID_SERVER_AUTH], c
    assert c["key"] == (g3.OID_EC, g3.OID_P256) and not g3.cert_is_ca(c)
    assert (c["not_after"] - c["not_before"]).days == 397
    a = g3.parse_cert(ca)
    assert g3.cert_is_ca(a) and c["issuer"] == a["subject"]
    assert g3.cert_nc(a) == (True, ["IP 192.0.2.0/24", "IP ::/128", "DNS invalid"], []), g3.cert_nc(a)
    assert g3.cert_nc(g3.parse_cert(plain)) is None
    b = g3.parse_cert(bad)
    assert g3.cert_san(b) == ["DNS cam.example", f"IP {HOST}"] and g3.cert_eku(b) == [] and b["key"][1] is None
    print("ok: certificates read with the DER walk: SAN, EKU, key, CA flag, issuer, nameConstraints")

    info = {"fp": g3.fp(leaf), "ca_fp": g3.fp(ca)}
    r = g3.Run(tempfile.mkdtemp())
    g3.cert_checks(r, HOST, leaf, ca, info)
    assert len(r.lines) == 9 and all(ln.startswith("PASS") for ln in r.lines), r.lines
    r = g3.Run(tempfile.mkdtemp())
    g3.cert_checks(r, HOST, bad, plain, {"fp": "00", "ca_fp": g3.fp(ca)})
    for check in ("(SAN)", "EKU serverAuth", "lifetime", "EC P-256", "info names", "issued by the camera's CA",
                  "nameConstraints", "CA is the one"):
        assert verdict(r, check) == "FAIL", (check, r.lines)
    assert verdict(r, "CA:FALSE") == "PASS"
    r = g3.Run(tempfile.mkdtemp())
    g3.cert_checks(r, "192.0.2.160", leaf)
    assert verdict(r, "(SAN)") == "FAIL" and len(r.lines) == 5, r.lines
    r = g3.Run(tempfile.mkdtemp())
    g3.cert_checks(r, HOST, b"\x30\x03\x02\x01\x01")
    assert r.lines == ["FAIL TLS server certificate: can't read it: DER: truncated"] or \
        verdict(r, "TLS server certificate") == "FAIL", r.lines
    print("ok: certificate checks: the camera's pass; a DNS name, no EKU, RSA, 800 days, another issuer, "
          "no nameConstraints, a wrong fingerprint and another IP each fail")

    real = g3.connect
    try:
        cam = FakeCamera(pki)
        g3.connect = cam.connect
        r = g3.Run(tempfile.mkdtemp())
        g3.tls_checks(r, HOST, tls_sec(pki))
        bad_lines = [ln for ln in r.lines if not ln.startswith(("PASS", "INFO"))]
        assert not bad_lines, r.lines
        assert verdict(r, "TLS 1.3 with") == "PASS" and verdict(r, "TLS 1.2 with") == "PASS"
        assert verdict(r, "only CBC") == "PASS" and verdict(r, "only RSA") == "PASS"
        assert verdict(r, "chain verifies") == "PASS" and verdict(r, "nameConstraints") == "PASS"
        assert any("ECDHE-ECDSA-" in ln and "TLSv1.2" in ln for ln in r.lines), r.lines
        assert (80, "POST", "/setup") in cam.seen and (443, "GET", "/ui/") in cam.seen, cam.seen
        print("ok: tls part against a fake camtls with camtls's settings: every check passes "
              f"({sum(ln.startswith('PASS') for ln in r.lines)} PASS, TLS 1.0/1.1 "
              f"{'tested' if verdict(r, 'TLS 1.0') == 'PASS' else 'INFO (not offered here)'})")

        cam = FakeCamera(pki, weak=True, redirect_to="evil.example")
        g3.connect = cam.connect
        r = g3.Run(tempfile.mkdtemp())
        g3.tls_checks(r, HOST, tls_sec(pki, ca="ca-plain.crt"))
        assert verdict(r, "only CBC") == "FAIL" and verdict(r, "only RSA") == "PASS", r.lines
        assert verdict(r, "TLS 1.0") in ("FAIL", "INFO") and verdict(r, "GET /ui/ on port 80") == "FAIL"
        assert verdict(r, "chain verifies") == "FAIL" and verdict(r, "issued by the camera's CA") == "FAIL"
        print("ok: a server taking TLS 1.0 and CBC, a CA that didn't sign it and a redirect elsewhere are caught")

        r = g3.Run(tempfile.mkdtemp())
        g3.tls_checks(r, HOST, tls_sec(pki, ready=False))
        assert r.lines and r.lines[0].startswith("FAIL HTTPS: camtls ready") and len(r.lines) == 1, r.lines

        cam = FakeCamera(pki)
        g3.connect = cam.connect
        r = g3.Run(tempfile.mkdtemp())
        g3.setup_gone_checks(r, HOST, True)
        assert [ln.split()[0] for ln in r.lines] == ["PASS", "PASS"], r.lines
        assert (80, "GET", "/setup") in cam.seen and (443, "GET", "/setup") in cam.seen
        r = g3.Run(tempfile.mkdtemp())
        g3.setup_gone_checks(r, HOST, False)
        assert verdict(r, "/setup is gone once claimed") == "FAIL", r.lines    # 302 where 404 is due
        print("ok: not ready is a FAIL; /setup: port 80 to https://, then 404 over HTTPS")
    finally:
        g3.connect = real
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
