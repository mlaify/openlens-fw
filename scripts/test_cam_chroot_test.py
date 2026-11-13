#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for scripts/cam-chroot-test.py's --overnight sampler (no camera, no network):

  python3 -I scripts/test_cam_chroot_test.py

The per-minute command still greps day/night, the IR LED, the shutter limits and time.tz from
`camcfg ctl get`, now with the AE values (^ae\\.), as the shell sees it after the console's quoting;
and a snapshot counts by rtspd's "ok SIZE" line, whatever camcfg's exit status (it used to exit 1
on that reply), never on camcfg's "no ok from rtspd" or an err.
"""
import importlib.util
import os
import re
import shlex

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cct", os.path.join(HERE, "cam-chroot-test.py"))
cct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cct)
fails = 0


def check(what, cond):
    global fails
    print(("ok: " if cond else "FAIL ") + what)
    fails += not cond


cmd = cct.OVERNIGHT_SAMPLE
outer = shlex.split(cmd)                        # the console's shell: chroot ... /bin/sh -c "..."
check("sampler runs one sh -c inside the chroot", outer[:2] == ["chroot", cct.NR] and outer[-2] == "-c")
inner = outer[-1]                               # what the chroot's sh runs
greps = re.findall(r"grep -E '([^']*)'", inner)
check("two greps (get, motion)", len(greps) == 2)
pats = greps[0].split("|") if greps else []
check("get grep has ^ae\\. (the AE values)", "^ae\\." in pats)
check("... and keeps ^daynight, ^image.irled, ^image.shutter, ^time.tz",
      all(p in pats for p in ("^daynight", "^image.irled", "^image.shutter", "^time.tz")))
get = ("image.exposure=50\nimage.exposure_night=day\nimage.shutter_day_max=0\ndaynight.score=58\n"
       "ae.y=37.2\nae.target=40.0\nae.shutter_us=40000\nae.sensor_gain=32768\nae.isp_gain=2048\n"
       "aeX=1\nmotion.enabled=1\ntime.tz=UTC0\nok\n")
picked = [line for line in get.splitlines() if any(re.search(p, line) for p in pats)]
check("... which picks every ae.* line and nothing like it", picked == [
    "image.shutter_day_max=0", "daynight.score=58", "ae.y=37.2", "ae.target=40.0", "ae.shutter_us=40000",
    "ae.sensor_gain=32768", "ae.isp_gain=2048", "time.tz=UTC0"])
check("lines joined with tr '\\n' ' '", "tr '\\n' ' '" in inner)

check("snapshot: \"ok 12345\" counts", cct.snapshot_ok("ok 12345\n"))
check("... also with camcfg's old failure message after it", cct.snapshot_ok(
    "ok 12345\r\ncamcfg: no ok from rtspd on /run/camd.sock\n"))
check("... not \"no ok from rtspd\" alone", not cct.snapshot_ok("camcfg: no ok from rtspd on /run/camd.sock\n"))
check("... not an err", not cct.snapshot_ok("err no recent snapshot\n"))
check("... not a bare ok or nothing", not cct.snapshot_ok("ok\n") and not cct.snapshot_ok(""))
import tempfile                                  # --conf: the settings file
with tempfile.TemporaryDirectory() as d:
    good = os.path.join(d, "cam2.conf")
    with open(good, "w") as f:
        f.write("# cam #2 nights\n\nimage.exposure_night=30\ntime.tz=CST6CDT,M3.2.0,M11.1.0\r\n"
                "osd.title.text=Front door: 1 & 2\n  # indented comment\n")
    check("--conf: key=value lines, comments and blank lines skipped, CRLF taken",
          cct.read_conf(good) == [("image.exposure_night", "30"), ("time.tz", "CST6CDT,M3.2.0,M11.1.0"),
                                  ("osd.title.text", "Front door: 1 & 2")])
    q = "camcfg set " + " ".join(shlex.quote(x) for x in ("osd.title.text", "Front door: 1 & 2; reboot"))
    check("... a value goes to the camera's shell as one quoted word",
          shlex.split(q)[-1] == "Front door: 1 & 2; reboot")
    for bad in ("no equals sign", "Image.Exposure=5", "key with space=1", "image.x=tab\there", "=empty key"):
        p2 = os.path.join(d, "bad.conf")
        with open(p2, "w") as f:
            f.write(bad + "\n")
        try:
            cct.read_conf(p2)
            ok = False
        except SystemExit:
            ok = True
        check(f"... refused: {bad!r}", ok)
print("all cam-chroot-test sampler checks passed" if not fails else f"{fails} FAILED")
raise SystemExit(1 if fails else 0)
