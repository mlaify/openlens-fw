#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of the DATA lock's boot scripts (#174, #178; docs/PLAN-DATA-LOCK.md): no camera.

  python3 scripts/test_lock_mode.py

rootfs/skel/etc/init.d/data-check runs with a real host build of camcfg ($TEST_CAMCFG from
host-tests.sh, else built here with clang and libsodium): a fresh DATA, a claimed camera without
the marker (it gets one), with the marker, and the marker with the users file missing, without an
admin or unreadable (each locks: exit 1, the reason in data-failed). rootfs/skel/usr/sbin/sshd-lock
with stub dropbear/dropbearkey/logger: authorized_keys holds the update keys only (sk keys with
verify-required, comments and other lines dropped), 0600 in a 0700 directory; dropbear gets -D and
the throwaway host key, never DATA's; no update keys means no dropbear. sshd-run picks sshd-lock
only when data-failed exists.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SKEL = os.path.join(ROOT, "rootfs", "skel")
DATA_CHECK = os.path.join(SKEL, "etc", "init.d", "data-check")
SSHD_LOCK = os.path.join(SKEL, "usr", "sbin", "sshd-lock")
SSHD_RUN = os.path.join(SKEL, "usr", "sbin", "sshd-run")

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZ0wQ3dn6bP1qQK0q2fQ3uYwQ9zZ7m3C2m2k5Y1l9eS owner@mac"
SK = ("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIGc0d3S2l8mQ0e7c0vB6"
      "1yPq2kq4m1Q5o5a8v3gZ9mWuAAAABHNzaDo= yubikey-1")


def stub(d, name, body):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(p, 0o755)


class Base(unittest.TestCase):
    camcfg = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="lockmode.")
        cc = os.environ.get("TEST_CAMCFG")
        if not cc:
            cc = os.path.join(cls.tmp, "camcfg")
            fl = subprocess.run(["pkg-config", "--cflags", "--libs", "libsodium"], capture_output=True,
                                text=True).stdout.split() or ["-I/opt/homebrew/include", "-L/opt/homebrew/lib",
                                                              "-lsodium"]
            subprocess.run(["clang", "-std=c11", "-I" + os.path.join(ROOT, "src", "rtspd"),
                            "-I" + os.path.join(ROOT, "src", "camupdate"), "-o", cc,
                            os.path.join(ROOT, "src", "camcfg", "camcfg.c"),
                            os.path.join(ROOT, "src", "rtspd", "auth.c")] + fl, check=True)
        cls.bin = os.path.join(cls.tmp, "bin")
        os.mkdir(cls.bin)
        os.symlink(cc, os.path.join(cls.bin, "camcfg"))
        cls.log = os.path.join(cls.tmp, "log")
        # logger -t TAG reads stdin; logger -t TAG MESSAGE doesn't
        stub(cls.bin, "logger", '[ $# -le 2 ] && cat >/dev/null\necho "logger $*" >> "%s"\n' % cls.log)
        stub(cls.bin, "sleep", "exit 0\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_sh(self, script, env, timeout=10):
        e = {"PATH": "/usr/bin:/bin", "CAM_STUB_PATH": self.bin, "CAMCTL_SOCK": "/nonexistent/camd.sock"}
        e.update(env)
        return subprocess.run(["/bin/sh", script], env=e, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout)


class DataCheck(Base):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=self.tmp)
        self.cam = os.path.join(self.d, "cam")
        self.failed = os.path.join(self.d, "data-failed")

    def check(self):
        return self.run_sh(DATA_CHECK, {"DATA_DIR": self.cam, "DATA_FAILED": self.failed})

    def put(self, name, text):
        os.makedirs(self.cam, exist_ok=True)
        with open(os.path.join(self.cam, name), "w") as f:
            f.write(text)

    def test_fresh_data(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.failed))
        self.assertFalse(os.path.exists(os.path.join(self.cam, "claimed")))

    def test_unclaimed_users(self):
        self.put("users", "view:viewer:Viewer-pass1\n")
        self.assertEqual(self.check().returncode, 0)
        self.assertFalse(os.path.exists(self.failed))
        self.assertFalse(os.path.exists(os.path.join(self.cam, "claimed")))

    def test_first_boot_marks(self):
        self.put("users", "own:admin:Secret-pass1\n")
        self.assertEqual(self.check().returncode, 0)
        self.assertFalse(os.path.exists(self.failed))
        m = os.path.join(self.cam, "claimed")
        self.assertTrue(os.path.isfile(m))
        self.assertEqual(stat.S_IMODE(os.stat(m).st_mode), 0o600)

    def test_marker_and_admin(self):
        self.put("users", "own:admin:Secret-pass1\n")
        self.put("claimed", "claimed\n")
        self.assertEqual(self.check().returncode, 0)
        self.assertFalse(os.path.exists(self.failed))

    def locked(self):
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stderr)
        with open(self.failed) as f:
            self.assertTrue(f.read().startswith("users: "))

    def test_marker_no_users(self):
        self.put("claimed", "claimed\n")
        self.locked()

    def test_marker_no_admin(self):
        self.put("claimed", "claimed\n")
        self.put("users", "view:viewer:Viewer-pass1\n")
        self.locked()

    def test_marker_users_unreadable(self):
        self.put("claimed", "claimed\n")
        os.makedirs(os.path.join(self.cam, "users"))
        self.locked()


class SshdLock(Base):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=self.tmp)
        self.lock = os.path.join(self.d, "lockssh")
        self.keys = os.path.join(self.d, "update-keys")
        self.args = os.path.join(self.d, "dropbear.args")
        stub(self.bin, "dropbearkey", 'case "$1" in -t) echo hostkey > "$4";; -y) echo "Fingerprint: x";; esac\n')
        stub(self.bin, "dropbear", 'echo "$@" > "%s"\n' % self.args)

    def run_lock(self):
        return self.run_sh(SSHD_LOCK, {"UPDATE_KEYS": self.keys, "LOCK_DIR": self.lock})

    def test_update_keys_only(self):
        with open(self.keys, "w") as f:
            f.write("# Firmware update signing keys\n\n%s\n%s\nssh-rsa AAAAB3Nza junk\n"
                    'command="x" %s\n' % (SK, ED, ED))
        r = self.run_lock()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.lock, "authorized_keys")) as f:
            ak = f.read().splitlines()
        self.assertEqual(ak, ["verify-required " + SK, ED])
        self.assertEqual(stat.S_IMODE(os.stat(self.lock).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.lock, "authorized_keys")).st_mode), 0o600)
        with open(self.args) as f:
            args = f.read().split()
        self.assertIn("-D", args)
        self.assertEqual(args[args.index("-D") + 1], self.lock)
        self.assertEqual(args[args.index("-r") + 1], os.path.join(self.lock, "dropbear_ed25519_host_key"))
        self.assertFalse(any("/mnt/nand" in a for a in args))

    def test_no_update_keys(self):
        with open(self.keys, "w") as f:
            f.write("# none\n")
        r = self.run_lock()
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.args))
        self.assertFalse(os.path.exists(os.path.join(self.lock, "authorized_keys")))

    def test_missing_update_keys(self):
        r = self.run_lock()
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.args))


class SshdRun(Base):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=self.tmp)
        self.mark = os.path.join(self.d, "ran-lock")
        stub(self.bin, "sshd-lock", 'echo lock > "%s"\n' % self.mark)

    def tearDown(self):
        os.unlink(os.path.join(self.bin, "sshd-lock"))

    def test_lock_mode_runs_sshd_lock(self):
        failed = os.path.join(self.d, "data-failed")
        with open(failed, "w") as f:
            f.write("mount: x\n")
        r = self.run_sh(SSHD_RUN, {"DATA_FAILED": failed})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.mark))

    def test_normal_mode_waits_for_the_claim(self):
        # camcfg claimed fails (no /mnt/nand here); with sleep stubbed the wait loop spins, so the
        # run is cut off: sshd-lock must not have run
        try:
            self.run_sh(SSHD_RUN, {"DATA_FAILED": os.path.join(self.d, "none")}, timeout=2)
        except subprocess.TimeoutExpired:
            pass
        self.assertFalse(os.path.exists(self.mark))


if __name__ == "__main__":
    unittest.main(verbosity=2)
