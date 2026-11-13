#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of the network boot script (#80): no camera.

  python3 scripts/test_net_up.py

rootfs/skel/etc/init.d/net-up runs with a real host build of camcfg ($TEST_CAMCFG from
host-tests.sh, else built here with clang and libsodium) and stub ifconfig, route, arping, udhcpc,
hostname, logger and reboot that log their arguments. Covered: DHCP by default and in lock mode;
net.dns handed to udhcpc.script; a static address after both ARP checks; a failed check falls back
to DHCP for the boot and keeps the settings; the address check waits up to 10 s for the link; a failed check of a change waiting for confirmation
reverts it now; a change in use starts the confirmation wait; "net-up wait" reverts and reboots
unless confirmed; invalid settings mean DHCP.
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NET_UP = os.path.join(ROOT, "rootfs", "skel", "etc", "init.d", "net-up")


def stub(d, name, body):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(p, 0o755)


class NetUp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="netup.")
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
        cls.camcfg = cc

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.d = tempfile.mkdtemp(dir=self.tmp)
        self.cam = os.path.join(self.d, "cam")
        os.mkdir(self.cam)
        self.bin = os.path.join(self.d, "bin")
        os.mkdir(self.bin)
        os.symlink(self.camcfg, os.path.join(self.bin, "camcfg"))
        self.log = os.path.join(self.d, "log")
        self.dad = os.path.join(self.d, "dad-rc")       # arping -D's exit status (0: address free)
        self.gw = os.path.join(self.d, "gw-rc")         # arping to the gateway (0: it answered)
        for name in ("ifconfig", "route", "udhcpc", "hostname", "reboot", "sleep", "spawn"):
            stub(self.bin, name, 'echo "%s${*:+ $*}" >> "%s"\n' % (name, self.log))
        stub(self.bin, "logger", '[ $# -le 2 ] && cat >/dev/null\necho "logger $*" >> "%s"\n' % self.log)
        stub(self.bin, "arping", 'echo "arping $*" >> "{log}"\n'
             'case " $* " in *" -D "*) exit $(cat "{dad}" 2>/dev/null || echo 0) ;; esac\n'
             'exit $(cat "{gw}" 2>/dev/null || echo 0)\n'.format(log=self.log, dad=self.dad, gw=self.gw))
        self.status = os.path.join(self.d, "net-status")
        self.dns = os.path.join(self.d, "net-dns")
        self.resolv = os.path.join(self.d, "resolv.conf")
        self.failed = os.path.join(self.d, "data-failed")

    def cc(self, *args):
        return subprocess.run([self.camcfg, "-d", self.cam] + list(args), capture_output=True, text=True)

    def net_up(self, *args):
        e = {"PATH": "/usr/bin:/bin", "CAM_STUB_PATH": self.bin, "DATA_DIR": self.cam,
             "DATA_FAILED": self.failed, "NET_STATUS": self.status, "NET_DNS": self.dns,
             "NET_RESOLV": self.resolv, "NET_WAIT_SPAWN": os.path.join(self.bin, "spawn"),
             "NET_CARRIER": getattr(self, "carrier", os.path.join(self.d, "no-carrier-file")),
             "CAMCTL_SOCK": "/nonexistent/camd.sock"}
        r = subprocess.run(["/bin/sh", NET_UP] + list(args), env=e, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def calls(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def stat(self):
        with open(self.status) as f:
            return dict(l.split("=", 1) for l in f.read().splitlines())

    def conf(self):
        with open(os.path.join(self.cam, "cam.conf")) as f:
            return f.read()

    def set(self, *kv):
        r = self.cc("net", "set", *kv)
        self.assertEqual(r.returncode, 0, r.stderr)

    def put(self, path, text):
        with open(path, "w") as f:
            f.write(text)

    def confirm(self):
        self.assertEqual(self.cc("net", "confirm").returncode, 0)

    STATIC = ("mode=static", "address=192.0.2.159/24", "gateway=192.0.2.1", "dns=192.0.2.1,1.1.1.1",
              "hostname=cam1")

    def test_dhcp_default(self):
        self.net_up()
        c = self.calls()
        self.assertIn("hostname -F /etc/hostname", c)
        self.assertTrue(any(l.startswith("udhcpc -i eth0 -b -S") for l in c), c)
        self.assertFalse(any(l.startswith("arping") for l in c))
        self.assertFalse(os.path.exists(self.dns))
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"], s["state"], s["pending"]), ("dhcp", "dhcp", "ok", "0"))
        self.assertEqual(oct(os.stat(self.status).st_mode & 0o777), "0o644")
        self.assertNotIn("spawn wait", c)

    def test_lock_mode_uses_dhcp(self):
        self.set(*self.STATIC)
        self.confirm()
        self.put(self.failed, "mount: DATA (mtd3) didn't mount as jffs2\n")
        self.net_up()
        c = self.calls()
        self.assertTrue(any(l.startswith("udhcpc") for l in c))
        self.assertFalse(any(l.startswith("arping") for l in c))
        self.assertEqual(self.stat()["configured"], "none")

    def test_dhcp_with_dns_and_hostname(self):
        self.set("mode=dhcp", "dns=192.0.2.1,9.9.9.9", "hostname=porch")
        self.confirm()
        self.net_up()
        c = self.calls()
        self.assertIn("hostname porch", c)
        with open(self.dns) as f:
            self.assertEqual(f.read(), "192.0.2.1 9.9.9.9\n")

    def test_static_ok(self):
        self.set(*self.STATIC)
        self.confirm()
        self.net_up()
        c = self.calls()
        self.assertIn("hostname cam1", c)
        self.assertIn("ifconfig eth0 192.0.2.159 netmask 255.255.255.0 up", c)
        self.assertIn("route add default gw 192.0.2.1 dev eth0", c)
        dad = [l for l in c if l.startswith("arping -D")]
        self.assertEqual(len(dad), 1)
        self.assertIn("192.0.2.159", dad[0])
        self.assertTrue(any(l.startswith("arping -q -f") and l.endswith("192.0.2.1") for l in c), c)
        self.assertLess(c.index(dad[0]), c.index("ifconfig eth0 192.0.2.159 netmask 255.255.255.0 up"))
        self.assertFalse(any(l.startswith("udhcpc") for l in c))
        with open(self.resolv) as f:
            self.assertEqual(f.read(), "nameserver 192.0.2.1\nnameserver 1.1.1.1\n")
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"], s["state"]), ("static", "static", "ok"))

    def test_static_waits_for_carrier(self):
        self.set(*self.STATIC)
        self.confirm()
        carrier = os.path.join(self.d, "carrier")
        self.put(carrier, "0\n")                              # the link never comes up
        self.carrier = carrier
        self.net_up()
        c = self.calls()
        self.assertEqual(c.count("sleep 1"), 10)              # 10 s at most, then the checks
        self.assertTrue(any(l.startswith("arping -D") for l in c))
        self.put(carrier, "1\n")
        open(self.log, "w").close()
        self.net_up()
        self.assertNotIn("sleep 1", self.calls())

    def test_static_gateway_silent_falls_back(self):
        self.set(*self.STATIC)
        self.confirm()
        before = self.conf()
        self.put(self.gw, "1")
        self.net_up()
        c = self.calls()
        self.assertTrue(any(l.startswith("udhcpc") for l in c))
        self.assertIn("ifconfig eth0 0.0.0.0", c)            # the static address taken off first
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"], s["state"]), ("static", "dhcp", "fallback"))
        self.assertIn("gateway 192.0.2.1 didn't answer", s["reason"])
        self.assertEqual(self.conf(), before)                 # the settings stay
        self.assertNotIn("spawn wait", c)

    def test_static_conflict_falls_back(self):
        self.set(*self.STATIC)
        self.confirm()
        self.put(self.dad, "1")
        self.net_up()
        c = self.calls()
        self.assertNotIn("ifconfig eth0 192.0.2.159 netmask 255.255.255.0 up", c)
        s = self.stat()
        self.assertEqual((s["mode"], s["state"]), ("dhcp", "fallback"))
        self.assertIn("another host answers for 192.0.2.159", s["reason"])

    def test_pending_change_that_fails_reverts_now(self):
        self.set(*self.STATIC)                                # from DHCP: waits for confirmation
        self.put(self.dad, "1")
        self.net_up()
        c = self.calls()
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"], s["state"], s["pending"]), ("dhcp", "dhcp", "reverted", "0"))
        self.assertNotIn("net.mode=static", self.conf())
        self.assertFalse(os.path.exists(os.path.join(self.cam, "net-pending")))
        self.assertIn("hostname -F /etc/hostname", c)         # cam1 was the new setting's
        self.assertNotIn("spawn wait", c)

    def test_pending_static_to_other_static_that_fails(self):
        self.set(*self.STATIC)
        self.confirm()
        self.set("mode=static", "address=192.0.2.160/24", "gateway=192.0.2.1")
        # the new address conflicts; the confirmed .159 is free again for the second try
        stub(self.bin, "arping", 'echo "arping $*" >> "{log}"\n'
             'case " $* " in *" -D "*" 192.0.2.160 "*) exit 1 ;; esac\nexit 0\n'.format(log=self.log))
        self.net_up()
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"], s["state"]), ("static", "static", "reverted"))
        self.assertIn("ifconfig eth0 192.0.2.159 netmask 255.255.255.0 up", self.calls())
        self.assertIn("net.address=192.0.2.159/24", self.conf())

    def test_pending_change_in_use_waits(self):
        self.set(*self.STATIC)
        self.net_up()
        for _ in range(100):                                  # started in the background
            if "spawn wait" in self.calls():
                break
            time.sleep(0.05)
        c = self.calls()
        self.assertIn("spawn wait", c)
        self.assertEqual(self.stat()["pending"], "1")
        self.assertTrue(any("confirm within 10 minutes" in l for l in c), c)

    def test_wait_reverts_and_reboots(self):
        self.set(*self.STATIC)
        self.net_up("wait")
        c = self.calls()
        self.assertIn("reboot", c)
        self.assertNotIn("net.mode=static", self.conf())
        self.assertFalse(os.path.exists(os.path.join(self.cam, "net-pending")))

    def test_wait_after_confirm_does_nothing(self):
        self.set(*self.STATIC)
        self.confirm()
        self.net_up("wait")
        self.assertNotIn("reboot", self.calls())
        self.assertIn("net.mode=static", self.conf())

    def test_invalid_settings_mean_dhcp(self):
        self.put(os.path.join(self.cam, "cam.conf"), "net.mode=static\nnet.address=192.168.1.5/24\n"
                 "net.gateway=192.168.1.1\n")
        self.net_up()
        c = self.calls()
        self.assertTrue(any(l.startswith("udhcpc") for l in c))
        self.assertFalse(any(l.startswith("arping") for l in c))
        s = self.stat()
        self.assertEqual((s["configured"], s["mode"]), ("none", "dhcp"))
        self.assertIn("settings unreadable", s["reason"])


if __name__ == "__main__":
    unittest.main()
