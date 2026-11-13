#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of scripts/cam-recover.py (#177): no camera, no network, no listening port.

  python3 scripts/test_cam_recover.py

Checks: the signed message against a fixed vector (test_camcfg.c checks camcfg's recover_msg
against the same bytes), the challenge page parser, the signature and passphrase checks, the
argument rules, and end to end: the script's message signed by ssh-keygen and its POST body fed to
a real host camcfg (`unlock restore -c CHALLENGE -`, `unlock erase -c`) on a fake locked camera
(fake mtd0, mtd3 and new DATA), which restores the backup or erases; a stranger's key, another
challenge and an edited backup are refused with nothing erased.
"""
import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("cam_recover", os.path.join(HERE, "cam-recover.py"))
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)

CH = {"challenge": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      "device": "2afc57ce8604f5b6fbd6c026517444da", "firmware": "20261026.1"}
VECTOR = (b"cam-recover 1\nchallenge 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
          b"device 2afc57ce8604f5b6fbd6c026517444da\nfirmware 20261026.1\naction restore\n"
          b"backup e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
PP = "correct horse battery"


class Offline(unittest.TestCase):
    def test_vector(self):
        self.assertEqual(cr.message(CH, "restore", hashlib.sha256(b"").hexdigest()), VECTOR)
        self.assertTrue(cr.message(CH, "erase", None).endswith(b"action erase\nbackup none\n"))
        with self.assertRaises(ValueError):
            cr.message(CH, "wipe", None)

    def test_challenge_page(self):
        page = "challenge %s\ndevice %s\nfirmware %s\nexpires-in 600\n" % (CH["challenge"], CH["device"], CH["firmware"])
        self.assertEqual(cr.parse_challenge(page), CH)
        for bad in (page.replace("challenge 00", "challenge 0g"), page.replace("device 2a", "device 2"),
                    page.replace("firmware 20261026.1", "firmware a b"), "", "<html>locked</html>"):
            with self.assertRaises(cr.RecoverError):
                cr.parse_challenge(bad)

    def test_signature_and_passphrase(self):
        sig = "%s\nAAAA\n%s" % (cr.SIG_BEGIN, cr.SIG_END)
        self.assertEqual(cr.check_signature("  " + sig + "\n\n"), sig + "\n")
        for bad in ("", "AAAA", cr.SIG_BEGIN + "\nAAAA\n", "x\n" + sig):
            with self.assertRaises(cr.RecoverError):
                cr.check_signature(bad)
        self.assertIsNone(cr.passphrase_problem(PP))
        self.assertTrue(cr.passphrase_problem("elevenchars"))
        self.assertTrue(cr.passphrase_problem("a" * 257))
        self.assertTrue(cr.passphrase_problem("twelve\tchars!"))

    def test_body(self):
        self.assertEqual(cr.body("restore", PP, "SIG\n", b"BK"), PP.encode() + b"\nSIG\nBK")
        self.assertEqual(cr.body("erase", "", "SIG\n", b""), b"SIG\n")

    def test_args(self):
        a = cr.parse_args(["cam", "--erase", "--key", "k", "--pin", "AB:" * 31 + "AB"])
        self.assertEqual(a.pin, "ab" * 32)
        for bad in (["cam", "--key", "k"], ["cam", "--erase"], ["cam", "--erase", "--backup", "f", "--key", "k"],
                    ["cam", "--erase", "--key", "k", "--print-message"], ["cam", "--erase", "--key", "k", "--pin", "x"]):
            with self.assertRaises(SystemExit):
                cr.parse_args(bad)

    def test_backup_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x")
            with open(p, "wb") as f:
                f.write(b"GIF89a")
            with self.assertRaises(cr.RecoverError):
                cr.read_backup(p)
            with self.assertRaises(cr.RecoverError):
                cr.read_backup(os.path.join(d, "none"))


@unittest.skipUnless(shutil.which("ssh-keygen") and shutil.which("clang"), "needs ssh-keygen and clang")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="camrecover.")
        cc = os.environ.get("TEST_CAMCFG")
        if not cc:
            cc = os.path.join(cls.d, "camcfg")
            fl = subprocess.run(["pkg-config", "--cflags", "--libs", "libsodium"], capture_output=True,
                                text=True).stdout.split() or ["-I/opt/homebrew/include", "-L/opt/homebrew/lib",
                                                              "-lsodium"]
            subprocess.run(["clang", "-std=c11", "-I" + os.path.join(ROOT, "src", "rtspd"),
                            "-I" + os.path.join(ROOT, "src", "camupdate"), "-o", cc,
                            os.path.join(ROOT, "src", "camcfg", "camcfg.c"),
                            os.path.join(ROOT, "src", "rtspd", "auth.c")] + fl, check=True)
        cls.cc = cc
        j = lambda *p: os.path.join(cls.d, *p)
        img = bytearray(b"\xff" * 0x40000)
        env = b"\x12\x34\x56\x78a=b\x00ethaddr=00:11:22:aa:bb:cc\x00"
        img[0x3F000:0x3F000 + len(env)] = env
        with open(j("mtd0"), "wb") as f:
            f.write(img)
        for k in ("k", "o"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", j(k)], check=True,
                           stdin=subprocess.DEVNULL)
        os.mkdir(j("data"))
        with open(j("data", "users"), "w") as f:
            f.write("own:admin:Secret-pass1\n")
        cls.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CAMCFG_MTD0": j("mtd0"),
                   "CAMCFG_MTD3": j("mtd3"), "CAMCFG_RECOVER_DIR": j("new"), "CAMCFG_UPDATE_KEYS": j("k.pub"),
                   "CAMCTL_SOCK": "/nonexistent/camd.sock"}
        r = subprocess.run([cc, "-d", j("data"), "backup", "export"], input=(PP + "\n").encode(),
                           capture_output=True, env=cls.env)
        assert r.returncode == 0, r.stderr
        cls.backup = r.stdout
        r = subprocess.run([cc, "-d", j("data"), "backup", "export"], input=(PP + "\n").encode(),
                           capture_output=True, env=cls.env)
        cls.other_backup = r.stdout
        with open(j("data-failed"), "w") as f:
            f.write("mount: test\n")
        cls.env["CAMCFG_DATA_FAILED"] = j("data-failed")
        dev = subprocess.run(["python3", "-c", "import hashlib;print(hashlib.sha256(b'cam-backup device 1\\n"
                              "00:11:22:aa:bb:cc').hexdigest()[:32])"], capture_output=True, text=True).stdout.strip()
        cls.ch = {"challenge": "ab" * 32, "device": dev, "firmware": "unknown"}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d)

    def setUp(self):
        with open(os.path.join(self.d, "mtd3"), "wb") as f:
            f.write(os.urandom(65536))
        shutil.rmtree(os.path.join(self.d, "new"), ignore_errors=True)
        os.mkdir(os.path.join(self.d, "new"))

    def erased(self):
        with open(os.path.join(self.d, "mtd3"), "rb") as f:
            return f.read() == b"\xff" * 65536

    def unlock(self, action, data, challenge=None):
        args = [self.cc, "-d", os.path.join(self.d, "tmpfs"), "unlock", action, "-c", challenge or self.ch["challenge"]]
        if action == "restore":
            args.append("-")
        return subprocess.run(args, input=data, capture_output=True, env=self.env)

    def test_restore(self):
        sha = hashlib.sha256(self.backup).hexdigest()
        sig = cr.sign(os.path.join(self.d, "k"), cr.message(self.ch, "restore", sha))
        r = self.unlock("restore", cr.body("restore", PP, sig, self.backup))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.erased())
        with open(os.path.join(self.d, "new", "cam", "users")) as f:
            self.assertEqual(f.read(), "own:admin:Secret-pass1\n")

    def test_erase(self):
        sig = cr.sign(os.path.join(self.d, "k"), cr.message(self.ch, "erase", None))
        r = self.unlock("erase", cr.body("erase", "", sig, b""))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.erased())

    def test_refusals(self):
        sha = hashlib.sha256(self.backup).hexdigest()
        stranger = cr.sign(os.path.join(self.d, "o"), cr.message(self.ch, "restore", sha))
        r = self.unlock("restore", cr.body("restore", PP, stranger, self.backup))
        self.assertEqual(r.returncode, 3)
        good = cr.sign(os.path.join(self.d, "k"), cr.message(self.ch, "restore", sha))
        r = self.unlock("restore", cr.body("restore", PP, good, self.backup), challenge="cd" * 32)
        self.assertEqual(r.returncode, 3)
        r = self.unlock("restore", cr.body("restore", PP, good, self.other_backup))
        self.assertEqual(r.returncode, 3)
        self.assertFalse(self.erased())


if __name__ == "__main__":
    unittest.main(verbosity=2)
