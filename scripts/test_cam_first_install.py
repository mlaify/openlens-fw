#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test of scripts/cam-first-install.py's checks: no camera, no socket.

  python3 scripts/test_cam_first_install.py

Checks: the /proc/mtd test (mtd2 must be the 0xCB0000-byte "rootfs"), the BUILD-INFO release line
(a bench build is refused), the reading of the console after the detached launch, and what the
answer to GET / says: /setup over HTTP, our redirect to https:// (HTTPS on), then /setup over
HTTPS, a login, anything else.
"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("fi", os.path.join(HERE, "cam-first-install.py"))
fi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fi)

STOCK_MTD = '''dev:    size   erasesize  name
mtd0: 00040000 00010000 "BOOT"
mtd1: 00200000 00010000 "kernel"
mtd2: 00cb0000 00001000 "rootfs"
mtd3: 00100000 00010000 "DATA"
'''


class Mtd(unittest.TestCase):
    def test_stock_layout(self):
        self.assertTrue(fi.mtd2_ok(STOCK_MTD))

    def test_wrong_size_name_or_index(self):
        self.assertFalse(fi.mtd2_ok(STOCK_MTD.replace("00cb0000", "00c00000")))
        self.assertFalse(fi.mtd2_ok(STOCK_MTD.replace('"rootfs"', '"rootfs2"')))
        self.assertFalse(fi.mtd2_ok(STOCK_MTD.replace("mtd2:", "mtd4:")))
        self.assertFalse(fi.mtd2_ok(""))


class BuildInfo(unittest.TestCase):
    def check(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(text)
        try:
            return fi.build_info_release(f.name)
        finally:
            os.unlink(f.name)

    def test_release_line_as_build_rootfs_writes_it(self):
        self.assertTrue(self.check("version: 20261024.1\nimage: release (no credentials; scan passed)\n"))

    def test_bench_and_missing(self):
        self.assertFalse(self.check("image: BENCH (carries the builder's credentials; never flash)\n"))
        self.assertFalse(self.check("image: releaseX\n"))
        self.assertFalse(self.check("version: 1\n"))
        self.assertFalse(fi.build_info_release("/nonexistent/BUILD-INFO.txt"))


class Console(unittest.TestCase):
    def test_failures_before_the_erase(self):
        self.assertTrue(fi.install_failed("camupdate: REFUSED: not newer than the installed version"))
        self.assertTrue(fi.install_failed('camupdate: no mtd "rootfs"'))
        self.assertTrue(fi.install_failed("camupdate: can't copy to /tmp/camupdate.run"))
        self.assertTrue(fi.install_failed("sh: setsid: applet not found"))
        self.assertTrue(fi.install_failed("chroot: can't execute '/bin/busybox': No such file or directory"))

    def test_progress_or_silence(self):
        self.assertFalse(fi.install_failed(""))
        self.assertFalse(fi.install_failed("camupdate: installing 20261024.1 (signed by owner) to /dev/mtd2;"
                                           " the camera reboots when done\ncamupdate: erased 0%"))
        # printed after "installing", while it erases: must not read as a failure
        self.assertFalse(fi.install_failed("camupdate: installing 1 (signed by owner) to /dev/mtd2; the camera "
                                           "reboots when done\ncamupdate: can't take the watchdog (Device or "
                                           "resource busy); continuing"))

    def test_watchdog_refused_before_erase(self):
        # camupdate since Gate 3: no watchdog -> everything resumed, nothing written, exit 1
        self.assertTrue(fi.install_failed("camupdate: installing 20261024.3 (signed by owner) to /dev/mtd2; the "
                                          "camera reboots when done\ncamupdate: watchdog feeder restarted\n"
                                          "camupdate: can't take the watchdog (Device or resource busy): nothing "
                                          "written, everything resumed"))


class Answer(unittest.TestCase):
    H = "192.0.2.159"

    def test_plain_http(self):
        self.assertEqual(fi.classify(302, "/setup", self.H), "ours, unclaimed (/setup)")
        self.assertEqual(fi.classify(303, f"http://{self.H}/setup", self.H), "ours, unclaimed (/setup)")
        self.assertEqual(fi.classify(401, None, self.H), "ours or stock asking for a login (claimed already?)")
        self.assertEqual(fi.classify(200, None, self.H), "answers HTTP 200")
        self.assertEqual(fi.classify(302, "/index.html", self.H), "answers HTTP 302")

    def test_https_redirect(self):
        # camhttpd while camtls is ready: GET / on 80 -> https://IP/, before the claimed check
        self.assertEqual(fi.classify(302, f"https://{self.H}/", self.H), fi.HTTPS_UP)
        self.assertEqual(fi.classify(302, f"https://{self.H}/setup", self.H), "ours, unclaimed (/setup over HTTPS)")
        self.assertEqual(fi.classify(302, "https://other.example/", self.H), "answers HTTP 302")
        # then over HTTPS: / -> /setup while unclaimed
        self.assertEqual(fi.classify(302, "/setup", self.H, tls=True), "ours, unclaimed (/setup over HTTPS)")
        self.assertEqual(fi.classify(401, None, self.H, tls=True),
                         "ours or stock asking for a login (claimed already?)")
        self.assertEqual(fi.classify(404, None, self.H, tls=True), "answers HTTP 404 over HTTPS")


if __name__ == "__main__":
    unittest.main()
