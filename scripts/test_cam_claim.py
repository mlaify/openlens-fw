#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of scripts/cam-claim.py's helpers (#128): no camera, no network, no listening port.

  python3 scripts/test_cam_claim.py

Checks: the password rules (and that scripts/rtsp-passwd.py gives the same answers), the name rule, the
form token / recovery code / error parsing against camhttpd's markup, the .pub key reader (private
keys, options, several lines refused), key listing, the saved file (0600 in a 0700 folder, mode
reset when overwriting), the form body, argument parsing (HTTPS by default on 443, --http on 80,
--pin's forms) and IPv4 literal resolution. HTTPS (docs/PLAN-TLS.md §B): against a fake camera on
a socketpair with a certificate the openssl command makes (skipped without it), the fingerprint
returned, a wrong pin refused before anything is sent, Origin https://<IP> on the POST, and a
camera without TLS reported as such. Backups (#173): the passphrase rule (camcfg's), Digest (the RFC
2617 vector) and the camera's challenge, the multipart form (its boundary never in the file), the
backup file (0600, never over an existing one), --backup / --restore's arguments, and both flows
against a fake camera: the login, the System page's token and the download; the restore's upload.
"""
import hashlib
import importlib.util
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


cc = load("cam_claim", "cam-claim.py")
rp = load("rtsp_passwd", "rtsp-passwd.py")

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g me@laptop"
P64 = "Aa0!\"#$%&'()*+,-./:;<=>?@[\\]^_ `{|}~Zz9bcdefghijklmnopqrstuvwxyz"


class Policy(unittest.TestCase):
    cases = [  # (user, password, substring of the reason, or None)
        ("admin", "Secret-pass1", None),
        ("admin", P64, None),
        ("admin", "12345678", None),
        ("admin", "1234567", "at least 8"),
        ("admin", "x" * 65, "at most 64"),
        ("admin", "x" * 300, "at most 64"),
        ("admin", " leading-space", "start or end"),
        ("admin", "trailing-space ", "start or end"),
        ("admin", "tab\there-x", "ASCII"),
        ("admin", "café-pass", "ASCII"),
        ("admin", "line\nbreak-x", "ASCII"),
        ("Admin123", "admin123", "user name"),
        ("bob", "inner space ok", None),
    ]

    def test_password(self):
        self.assertEqual(len(P64), 64)
        for user, pw, want in self.cases:
            got = cc.password_problem(user, pw)
            if want is None:
                self.assertIsNone(got, (user, pw))
            else:
                self.assertIn(want, got or "", (user, pw))
            self.assertEqual(got, rp.password_problem(user, pw), "rtsp-passwd.py and cam-claim.py differ")

    def test_name(self):
        for n in ["admin", "a", "A.b_c-9", "x" * 32]:
            self.assertIsNone(cc.name_problem(n))
        for n in ["", "x" * 33, "a:b", "a b", "é", "a/b"]:
            self.assertIsNotNone(cc.name_problem(n))


class Pages(unittest.TestCase):
    # camhttpd's markup (src/camhttpd/camhttpd.c page_setup / page_code; test_camhttpd checks it)
    SETUP = ('<form method="post" action="/setup"><input type="hidden" name="csrf" '
             'value="0123456789abcdef0123456789abcdef01234567"><label>Admin name')
    CODE = '<h2>Recovery code</h2><p class="code" id="code">ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ</p><p class="warn">'
    ERR = '<p class="msg err">password must be at least 8 characters &amp; &lt;b&gt;</p>'

    def test_token(self):
        self.assertEqual(cc.parse_token(self.SETUP), "0123456789abcdef0123456789abcdef01234567")
        self.assertIsNone(cc.parse_token("<html>404</html>"))
        self.assertIsNone(cc.parse_token(self.SETUP.replace("01234567\"", "0123456Z\"")))

    def test_code(self):
        self.assertEqual(cc.parse_code(self.CODE), "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ")
        self.assertIsNone(cc.parse_code('<p class="code" id="code"><script></p>'))
        self.assertIsNone(cc.parse_code(self.ERR))

    def test_error(self):
        self.assertEqual(cc.parse_error(self.ERR), "password must be at least 8 characters & <b>")
        self.assertIsNone(cc.parse_error(self.CODE))

    def test_form_body(self):
        body = cc.form_body("t" * 40, "owner", "p&w=d +%x", KEY)
        q = urllib.parse.parse_qs(body, keep_blank_values=True)
        self.assertEqual(q, {"csrf": ["t" * 40], "name": ["owner"], "pw": ["p&w=d +%x"], "pw2": ["p&w=d +%x"],
                             "key": [KEY]})
        self.assertNotIn(" ", body)
        self.assertEqual(urllib.parse.parse_qs(cc.form_body("t", "o", "p" * 8, None), keep_blank_values=True)["key"], [""])


class Keys(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))

    def tearDown(self):
        for f in os.listdir(self.d):
            os.unlink(os.path.join(self.d, f))
        os.rmdir(self.d)

    def put(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_good(self):
        self.assertEqual(cc.key_line(self.put("id_ed25519.pub", KEY + "\n")), KEY)
        self.assertEqual(cc.key_line(self.put("c.pub", "# comment\n\n" + KEY + "  \n")), KEY)
        sk = ("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAECAwQFBgcICQoLDA0O"
              "DxAREhMUFRYXGBkaGxwdHh8gAAAABHNzaDo= yubikey")
        self.assertEqual(cc.key_line(self.put("sk.pub", sk)), sk)

    def test_refused(self):
        bad = {
            "id_ed25519": KEY,                                            # not .pub
            "priv.pub": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\n",
            "two.pub": KEY + "\n" + KEY + "\n",
            "empty.pub": "",
            "opts.pub": 'from="10.0.0.1" ' + KEY,
            "dss.pub": "ssh-dss AAAAB3NzaC1kc3MAAAABcAAAAAFxAAAAAWcAAAABeQ== x",
            "long.pub": "ssh-rsa " + "A" * 2100,
            "utf8.pub": KEY + " café",
        }
        for name, text in bad.items():
            with self.assertRaises(cc.ClaimError, msg=name):
                cc.key_line(self.put(name, text))

    def test_list(self):
        self.put("b.pub", KEY)
        self.put("a.pub", KEY)
        self.put("id_ed25519", "private")
        self.put("known_hosts", "x")
        self.assertEqual([os.path.basename(p) for p in cc.list_pubkeys(self.d)], ["a.pub", "b.pub"])


class Save(unittest.TestCase):
    def test_save(self):
        top = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        conf = os.path.join(top, "conf")
        try:
            p = cc.save_code(conf, "cam1.lan", "192.0.2.10", "owner", "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ")
            self.assertEqual(os.path.basename(p), "recovery-cam1.lan.txt")
            self.assertEqual(stat.S_IMODE(os.stat(conf).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            with open(p) as f:
                text = f.read()
            self.assertIn("recovery-code: ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", text)
            self.assertIn("camera: cam1.lan (192.0.2.10)\n", text)
            self.assertIn("admin: owner\n", text)
            os.chmod(p, 0o644)                       # a reclaim overwrites, and the mode is reset
            cc.save_code(conf, "cam1.lan", "192.0.2.10", "owner", "BCDE-FGHI-JKLM-NOPQ-RSTU-VWXY-ZA")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            with open(p) as f:
                self.assertNotIn("ABCD-EFGH", f.read())
            self.assertEqual(cc.safe_name("../../etc/passwd"), "_.._etc_passwd")
            self.assertEqual(cc.safe_name("192.0.2.159"), "192.0.2.159")
            self.assertEqual(cc.safe_name("..."), "camera")
            self.assertEqual(cc.safe_name("fe80::1%en0"), "fe80__1_en0")
        finally:
            for root, dirs, files in os.walk(top, topdown=False):
                for f in files:
                    os.unlink(os.path.join(root, f))
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(top)


class Backup(unittest.TestCase):
    def test_passphrase(self):
        for pp, why in (("long enough pass", None), ("x" * 12, None), ("é" * 128, None), ("x" * 11, "at least 12"),
                        ("é" * 129, "at most 256"), ("x" * 257, "at most 256"), ("tab\there-long", "control"),
                        ("del\x7fhere-long", "control")):
            got = cc.passphrase_problem(pp)
            self.assertTrue(got is None if why is None else why in got, (pp, got))

    def test_digest(self):
        chal = cc.parse_challenge('Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"')
        h = cc.digest_header("Mufasa", "Circle Of Life", "GET", "/dir/index.html", chal, 1, "0a4f113b")
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', h)       # RFC 2617 3.5
        self.assertIn("nc=00000001", h)
        chal = cc.parse_challenge('Digest realm="camera", qop="auth", algorithm=MD5, nonce="n0nce", stale=true')
        self.assertEqual((chal["realm"], chal["nonce"], chal["algorithm"], chal["stale"]), ("camera", "n0nce", "MD5", "true"))
        self.assertIsNone(cc.parse_challenge('Basic realm="x"'))
        self.assertIsNone(cc.parse_challenge(None))

    def test_multipart(self):
        ct, body = cc.multipart([("csrf", "t" * 40), ("pp", "pässphrase-1")], b"cam-backup 1\n\0\r\n")
        b = ct.split("boundary=")[1]
        self.assertTrue(ct.startswith("multipart/form-data; boundary=camclaim"))
        self.assertTrue(body.startswith(f"--{b}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n".encode()))
        self.assertIn("pässphrase-1".encode(), body)
        self.assertIn(b'name="file"; filename="backup.cambak"\r\nContent-Type: application/octet-stream\r\n\r\n'
                      b"cam-backup 1\n\0\r\n\r\n--" + b.encode() + b"--\r\n", body)
        ct, body = cc.multipart([], b"xx--clash--xx", boundary="clash")
        self.assertNotIn("clash", ct)                           # a boundary found in the file is replaced

    def test_save(self):
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        try:
            p = os.path.join(d, "b.cambak")
            cc.save_backup(p, b"cam-backup 1\n")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            with self.assertRaises(cc.ClaimError):
                cc.save_backup(p, b"other")
            self.assertEqual(open(p, "rb").read(), b"cam-backup 1\n")
        finally:
            shutil.rmtree(d)

    def test_args(self):
        self.assertEqual(cc.parse_args(["h", "--backup", "b.cambak"]).backup, "b.cambak")
        self.assertEqual(cc.parse_args(["h", "--restore", "b.cambak", "--pin", "ab" * 32]).restore, "b.cambak")
        for bad in (["h", "--backup", "b", "--http"], ["h", "--backup", "b", "--restore", "b"],
                    ["h", "--restore", "b", "--name", "x"], ["h", "--restore", "b", "--no-key"]):
            with self.assertRaises(SystemExit, msg=bad):
                cc.parse_args(bad)


class Args(unittest.TestCase):
    def test_args(self):
        a = cc.parse_args(["cam1"])
        self.assertEqual((a.host, a.port, a.http, a.pin, a.name, a.key, a.no_key),
                         ("cam1", 443, False, None, None, None, False))
        a = cc.parse_args(["192.0.2.159", "--port", "8080", "--name", "owner", "--key", "k.pub"])
        self.assertEqual((a.port, a.name, a.key), (8080, "owner", "k.pub"))
        self.assertTrue(cc.parse_args(["h", "--no-key"]).no_key)
        a = cc.parse_args(["h", "--http"])
        self.assertEqual((a.http, a.port), (True, 80))
        self.assertEqual(cc.parse_args(["h", "--http", "--port", "8080"]).port, 8080)
        fp = "AB:" * 31 + "CD"
        self.assertEqual(cc.parse_args(["h", "--pin", fp]).pin, "ab" * 31 + "cd")
        for bad in (["h", "--key", "k.pub", "--no-key"], ["h", "--port", "0"], ["h", "--port", "70000"], [],
                    ["h", "--pin", "ab" * 31], ["h", "--pin", "zz" * 32], ["h", "--http", "--pin", "ab" * 32]):
            with self.assertRaises(SystemExit, msg=bad):
                cc.parse_args(bad)

    def test_pin_and_origin(self):
        self.assertEqual(cc.norm_pin("AB CD:" + "ef" * 30), "abcd" + "ef" * 30)
        self.assertIsNone(cc.norm_pin("SHA256:" + "ab" * 32))
        self.assertIsNone(cc.norm_pin(None))
        self.assertEqual(cc.fingerprint(b"x"), hashlib.sha256(b"x").hexdigest())
        self.assertEqual(cc.base_url("192.0.2.159", 443, True), "https://192.0.2.159")
        self.assertEqual(cc.base_url("192.0.2.159", 8443, True), "https://192.0.2.159:8443")
        self.assertEqual(cc.base_url("192.0.2.159", 80, False), "http://192.0.2.159")
        self.assertEqual(cc.base_url("192.0.2.159", 443, False), "http://192.0.2.159:443")

    def test_resolve_literal(self):
        self.assertEqual(cc.resolve_ipv4("192.0.2.10"), "192.0.2.10")


@unittest.skipUnless(shutil.which("openssl"), "no openssl command to make a test certificate")
class Https(unittest.TestCase):
    """request() against a fake camera: TLS on one end of a socketpair, http.client on the other."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", "k.pem", "-out", "c.pem", "-days", "30", "-subj", "/CN=192.0.2.159",
                        "-addext", "subjectAltName=IP:192.0.2.159"], cwd=cls.d, check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(os.path.join(cls.d, "c.pem"), os.path.join(cls.d, "k.pem"))
        cls.fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(os.path.join(cls.d, "c.pem")).read())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def setUp(self):
        self.seen, self.real = [], socket.create_connection
        socket.create_connection = self.fake

    def tearDown(self):
        socket.create_connection = self.real

    class Pair(socket.socket):
        """A socketpair end that takes http.client's TCP_NODELAY (no TCP here)."""

        def setsockopt(self, level, opt, value, *a):
            if level != socket.IPPROTO_TCP:
                super().setsockopt(level, opt, value, *a)

    def fake(self, addr, timeout=None, *a, **k):
        x, y = socket.socketpair()
        x = self.Pair(fileno=x.detach())
        x.settimeout(10)
        y.settimeout(10)
        threading.Thread(target=self.serve, args=(y, addr[1]), daemon=True).start()
        return x

    def serve(self, sock, port):
        try:
            if port == 443:
                sock = self.ctx.wrap_socket(sock, server_side=True)
            elif port == 8080:                                  # plain HTTP answering a ClientHello
                sock.recv(4096)
                sock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            req = b""
            while b"\r\n\r\n" not in req:
                d = sock.recv(4096)
                if not d:
                    return
                req += d
            # the whole body before answering, as a real server does: closing on the headers alone
            # broke the client's separate body write now and then (EPIPE)
            head, _, rest = req.partition(b"\r\n\r\n")
            m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            while m and len(rest) < int(m.group(1)):
                d = sock.recv(4096)
                if not d:
                    return
                rest += d
            self.seen.append(req.decode(errors="replace"))
            body = b'<input type="hidden" name="csrf" value="' + b"0" * 40 + b'">'
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        except (ssl.SSLError, OSError):
            pass
        finally:
            sock.close()

    def test_fingerprint_and_origin(self):
        st, page, fp = cc.request("192.0.2.159", 443, "GET", "/setup")
        self.assertEqual((st, fp, cc.parse_token(page)), (200, self.fp, "0" * 40))
        st, _, fp = cc.request("192.0.2.159", 443, "POST", "/setup", "csrf=x", pin=self.fp)
        self.assertEqual((st, fp), (200, self.fp))
        self.assertIn("Origin: https://192.0.2.159\r\n", self.seen[-1])
        self.assertIn("Host: 192.0.2.159\r\n", self.seen[-1])

    def test_wrong_pin_sends_nothing(self):
        with self.assertRaises(cc.ClaimError) as e:
            cc.request("192.0.2.159", 443, "POST", "/setup", "csrf=x&pw=secret", pin="0" * 64)
        self.assertIn("not the pinned", str(e.exception))
        self.assertIn(self.fp, str(e.exception))
        self.assertEqual(self.seen, [])

    def test_plain_http_and_no_tls(self):
        st, _, fp = cc.request("192.0.2.159", 80, "POST", "/setup", "csrf=x", tls=False)
        self.assertEqual((st, fp), (200, None))
        self.assertIn("Origin: http://192.0.2.159\r\n", self.seen[-1])
        with self.assertRaises(cc.ClaimError) as e:             # HTTPS to a server that speaks plain HTTP
            cc.request("192.0.2.159", 8080, "GET", "/setup")
        self.assertIn("--http", str(e.exception))


class BackupFlow(Https):
    """download_backup and --restore against a fake camera (the same socketpair and certificate)."""
    # Https's own tests are for its fake, not this one
    test_fingerprint_and_origin = test_wrong_pin_sends_nothing = test_plain_http_and_no_tls = None

    def serve(self, sock, port):
        try:
            sock = self.ctx.wrap_socket(sock, server_side=True)
            req = b""
            while b"\r\n\r\n" not in req:
                d = sock.recv(65536)
                if not d:
                    return
                req += d
            head, _, rest = req.partition(b"\r\n\r\n")
            m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            while m and len(rest) < int(m.group(1)):
                d = sock.recv(65536)
                if not d:
                    return
                rest += d
            self.seen.append((head.decode(errors="replace") + "\r\n", rest))
            line = head.split(b"\r\n", 1)[0].decode()
            tok = b'<input type="hidden" name="csrf" value="' + b"1" * 40 + b'">'
            ctype, body, extra = "text/html", b"", ""
            if line.startswith("GET /ui/system") and b"Authorization:" not in head:
                st, extra = 401, 'WWW-Authenticate: Digest realm="camera", qop="auth", algorithm=MD5, nonce="n0nce"\r\n'
            elif line.startswith("GET /ui/system"):
                st, body = 200, tok
            elif line.startswith("POST /ui/system"):
                st, ctype, body = 200, "application/octet-stream", b"cam-backup 1\ndevice x\n\n\0box"
            elif line.startswith("GET /setup"):
                st, body = 200, tok
            elif line.startswith("POST /setup/restore"):
                st, body = 200, b"<h1>Restored</h1>"
            else:
                st = 404
            sock.sendall(b"HTTP/1.1 %d X\r\nContent-Type: %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (st, ctype.encode(), extra.encode(), len(body), body))
        except (ssl.SSLError, OSError):
            pass
        finally:
            sock.close()

    def test_download(self):
        p = os.path.join(self.d, "first.cambak")
        n = cc.download_backup("192.0.2.159", 443, self.fp, "owner", "Owner-pass-1", "long enough pass", p)
        self.assertEqual(open(p, "rb").read(), b"cam-backup 1\ndevice x\n\n\0box")
        self.assertEqual(n, 27)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        (h1, _), (h2, _), (h3, b3) = self.seen
        self.assertNotIn("Authorization", h1)
        self.assertIn('Authorization: Digest username="owner", realm="camera", nonce="n0nce", uri="/ui/system"', h2)
        self.assertIn("nc=00000001", h2)
        self.assertIn("nc=00000002", h3)
        self.assertIn("Origin: https://192.0.2.159\r\n", h3)
        form = urllib.parse.parse_qs(b3.decode())
        self.assertEqual((form["csrf"], form["do"], form["pp"], form["pp2"]),
                         (["1" * 40], ["backup"], ["long enough pass"], ["long enough pass"]))
        with self.assertRaises(cc.ClaimError):                    # never over an existing file
            cc.download_backup("192.0.2.159", 443, self.fp, "owner", "Owner-pass-1", "long enough pass", p)
        os.unlink(p)

    def test_restore(self):
        p = os.path.join(self.d, "r.cambak")
        with open(p, "wb") as f:
            f.write(b"cam-backup 1\nrest\0of it")
        a = cc.parse_args(["192.0.2.159", "--restore", p, "--pin", self.fp])
        real = cc.getpass.getpass
        cc.getpass.getpass = lambda prompt="": "long enough pass"
        try:
            self.assertEqual(cc.restore(a, "192.0.2.159"), 0)
        finally:
            cc.getpass.getpass = real
        h, b = self.seen[-1]
        self.assertTrue(h.startswith("POST /setup/restore "))
        self.assertIn("Origin: https://192.0.2.159\r\n", h)
        self.assertIn("Content-Type: multipart/form-data; boundary=camclaim", h)
        self.assertIn(b"cam-backup 1\nrest\0of it\r\n--camclaim", b)
        self.assertIn(b'name="csrf"\r\n\r\n' + b"1" * 40, b)
        self.assertIn(b'name="pp"\r\n\r\nlong enough pass\r\n', b)
        with open(p, "wb") as f:
            f.write(b"not a backup")
        with self.assertRaises(cc.ClaimError):
            cc.restore(a, "192.0.2.159")
        with open(p, "wb") as f:
            f.write(b"cam-backup 1\n" + b"x" * cc.RESTORE_MAX)
        with self.assertRaises(cc.ClaimError) as e:
            cc.restore(a, "192.0.2.159")
        self.assertIn("over SSH", str(e.exception))
        os.unlink(p)


if __name__ == "__main__":
    unittest.main()
