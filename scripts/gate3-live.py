#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gate 3 (#38) live checks against a camera running our firmware (docs/GATE3-CRITERIA.md).

  python3 scripts/gate3-live.py HOST --admin NAME [--viewer NAME] [--operator NAME]
                                [--camfw FILE.camfw ...] [--lockout] [--udp] [--skip-nmap]
                                [--only ssh,nmap,rtsp,onvif,wsd,camupdate,lockout,tls]

Run it from the owner's terminal against cam #1 (the sandbox can't reach the cameras). It asks
for each account's password (never echoed, logged or saved) and uses the owner's SSH key for
root@HOST (one YubiKey touch: the connection is shared for the whole run). Evidence goes to
bench-logs/gate3-<UTC date>/<HOST>/<UTC time>/ (gitignored, a folder per run): one file per check and summary.txt with one
PASS/FAIL/WARN/INFO line each. The camera's MAC never reaches the evidence: every saved text has
it replaced by <MAC>.

What it does, all read-only on the camera except where noted:
  - on the camera (SSH): version, listeners (netstat), processes against an allowlist and the
    vendor's names, mounts, DATA permissions, setuid/world-writable files, root's password field,
    logread searched for the MAC, and who each daemon runs as (rtspd, ntpc, camhttpd's monitor and
    worker, dropbear: INFO lines from /proc/PID/status);
  - from here: nmap of every TCP port (and, with --udp, the top 200 UDP ports via sudo), the SSH
    algorithms (nmap ssh2-enum-algos: no SHA-1, CBC or 3DES, strict kex present), a password
    login (must be refused), stdio/remote forwarding and agent/X11 forwarding (refused);
  - RTSP: DESCRIBE/SETUP/PLAY without credentials get 401, a valid login works, 5 wrong
    passwords close the connection;
  - ONVIF: PRE_AUTH operations answer without credentials, the others get 401; with --viewer /
    --operator, the operations above their role are refused (sent with invalid arguments, so
    nothing could change even if a check were missing); GetDeviceInformation's SerialNumber is 0;
    /snapshot.jpg needs Digest; the web UI needs Digest, /setup is gone, a POST without the
    page's Origin and token is refused (the web UI over HTTPS when camtls is ready: port 80 then
    sends /setup to https://, which has none);
  - tls (when camtls is ready: /run/camtls/ready): TLS 1.0 and 1.1 refused (offered with
    @SECLEVEL=0; INFO if this machine's OpenSSL can't offer them), offers of only CBC or only RSA
    suites refused, TLS 1.3 and 1.2 negotiated with ECDHE-ECDSA and an AEAD cipher (cipher and
    group reported); the server certificate: SAN = the camera's IP only, EKU serverAuth, at most
    397 days, EC P-256, CA:FALSE; the chain verified against the camera's CA (/run/camtls/ca.crt,
    over SSH), which must carry critical nameConstraints (CAM_NET, and IPv6 and DNS names
    constrained too), and both fingerprints as /run/camtls/info says; port 80 sends GET /ui/ to
    https:// without asking for a login, refuses POST /setup, keeps /snapshot.jpg and ONVIF for
    SSS; the web UI over https asks for Digest. Listeners then include 443 and 322 (RTSPS);
  - with --lockout: 5 wrong passwords lock this machine's address out of camhttpd for a minute
    (SSS and other addresses keep working); the script waits it out and checks the admin again;
  - WS-Discovery: a Probe gets exactly one reply (or none when this machine is on another
    subnet), a burst of 10 gets at most 2, the EndpointReference doesn't carry the MAC;
  - camupdate --check on the camera (nothing is installed: --check stops before any write) with
    each --camfw (expected refused: not newer than the installed version) and with copies of the
    first one that are tampered (header, payload), truncated, unsigned, signed by a throwaway key
    carry bytes after the payload or a filled SSHSIG reserved field (the Gate 3 overflow; refused
    since the fix).
Standard library only, plus the nmap and ssh commands.
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import ipaddress
import os
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import warnings

VENDOR_RE = re.compile(r"procman|mainctrl|media_server|hik_?server|h5live|comm_?server|ex_?server|"
                       r"p2p|web_?server|dbg_?server|anjoy|ota_?upgrade|upgrade_server|dvr|xm_", re.I)
# what our image runs (rootfs/skel inittab, rcS and the *-run wrappers), plus this script's own
# commands over SSH
PROC_OK = {"init", "sh", "ash", "syslogd", "klogd", "udhcpc", "rtspd", "camhttpd", "ntpc", "dropbear",
           "camtls", "logger", "sleep", "watchdog", "getty", "rtspd-run", "camhttpd-run", "ntpc-run",
           "sshd-run", "camtls-run", "ps", "cat", "grep", "awk", "find", "ls", "logread", "netstat",
           "ifconfig", "uptime", "busybox"}
DAEMONS = ("rtspd", "ntpc", "camhttpd", "dropbear", "camtls")   # §7: each one's uid is reported (INFO)
TCP_OK = {22, 80, 554}                # + TLS_PORT while camtls is ready (camera_side reports it)
TLS_PORT = 443
RTSPS_PORT = 322                      # camtls's second listener (docs/PLAN-TLS.md D)
UDP_OK = {3702}
UDP_INFO = {68}                       # udhcpc's socket while renewing
BAD_SSH = re.compile(r"cbc|3des|arcfour|hmac-sha1|hmac-md5|umac-64|-sha1\b|group1-|group14-sha1|"
                     r"group-exchange-sha1|ssh-dss|[|\s]ssh-rsa\s*$", re.I | re.M)
SOAP = ('<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
        ' xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">'
        '<s:Body>{}</s:Body></s:Envelope>')
PRE_AUTH = {"GetSystemDateAndTime": "<tds:GetSystemDateAndTime/>",
            "GetCapabilities": "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
            "GetServices": "<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>",
            "GetHostname": "<tds:GetHostname/>"}
NEED_AUTH = {"GetDeviceInformation": ("device", "<tds:GetDeviceInformation/>"),
             "GetUsers": ("device", "<tds:GetUsers/>"),
             "GetNetworkInterfaces": ("device", "<tds:GetNetworkInterfaces/>"),
             "GetProfiles": ("media", "<trt:GetProfiles/>"),
             "GetStreamUri": ("media", "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>"
                              "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>"
                              "<trt:ProfileToken>Profile_1</trt:ProfileToken></trt:GetStreamUri>")}
# above a role; every Set* carries an argument the camera must refuse, so a missing role check
# would show as an argument fault, not as a change
SET_NTP_BAD = ("<tds:SetNTP><tds:FromDHCP>false</tds:FromDHCP><tds:NTPManual><tt:Type>DNS</tt:Type>"
               "<tt:DNSname>gate3 invalid name!</tt:DNSname></tds:NTPManual></tds:SetNTP>")
SET_TIME_BAD = ("<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType>"
                "<tds:DaylightSavings>false</tds:DaylightSavings><tds:UTCDateTime><tt:Time><tt:Hour>99</tt:Hour>"
                "<tt:Minute>99</tt:Minute><tt:Second>99</tt:Second></tt:Time><tt:Date><tt:Year>1900</tt:Year>"
                "<tt:Month>13</tt:Month><tt:Day>40</tt:Day></tt:Date></tds:UTCDateTime></tds:SetSystemDateAndTime>")
SET_VENC_BAD = ('<trt:SetVideoEncoderConfiguration><trt:Configuration token="gate3-none"><tt:Name>x</tt:Name>'
                "<tt:UseCount>1</tt:UseCount><tt:Encoding>MJPEG</tt:Encoding></trt:Configuration>"
                "<trt:ForcePersistence>false</trt:ForcePersistence></trt:SetVideoEncoderConfiguration>")
SET_IMG_BAD = ("<timg:SetImagingSettings><timg:VideoSourceToken>gate3-none</timg:VideoSourceToken>"
               "<timg:ImagingSettings><tt:Brightness>500</tt:Brightness></timg:ImagingSettings>"
               "</timg:SetImagingSettings>")
ABOVE = {"viewer": {"SetVideoEncoderConfiguration": ("media", SET_VENC_BAD),
                    "SetImagingSettings": ("imaging", SET_IMG_BAD),
                    "SetSystemDateAndTime": ("device", SET_TIME_BAD),
                    "SetNTP": ("device", SET_NTP_BAD),
                    "GetUsers": ("device", "<tds:GetUsers/>")},
         "operator": {"SetSystemDateAndTime": ("device", SET_TIME_BAD),
                      "SetNTP": ("device", SET_NTP_BAD),
                      "GetUsers": ("device", "<tds:GetUsers/>")}}
UI_ABOVE = {"viewer": ["/ui/image", "/ui/streams", "/ui/users", "/ui/system", "/ui/ssh"],
            "operator": ["/ui/users", "/ui/system", "/ui/ssh", "/ui/time"]}
PROBE = ('<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
         ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
         ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
         ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:{}</w:MessageID>'
         '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
         '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
         '</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>')


class Run:
    def __init__(self, out):
        self.out, self.lines, self.mac = out, [], None

    def redact(self, text):
        if not self.mac:
            return text
        h = self.mac.replace(":", "")
        for form in (self.mac, h, "-".join(h[i:i + 2] for i in range(0, 12, 2))):
            text = re.sub(re.escape(form), "<MAC>", text, flags=re.I)
        return text

    def save(self, name, text):
        with open(os.path.join(self.out, name), "w") as f:
            f.write(self.redact(text))

    def result(self, verdict, check, detail=""):
        line = f"{verdict:4} {check}" + (f": {detail}" if detail else "")
        line = self.redact(line)
        print(line, flush=True)
        self.lines.append(line)


# ---- SSH (one shared connection) ----
class Ssh:
    def __init__(self, host, ctl):
        self.host, self.ctl = host, ctl
        self.base = ["ssh", "-o", "ControlMaster=auto", "-o", f"ControlPath={ctl}", "-o", "ControlPersist=900",
                     "-o", "BatchMode=no", "-o", "ConnectTimeout=10"]

    def run(self, cmd, data=None, extra=(), timeout=120):
        argv = self.base + list(extra) + [f"root@{self.host}"] + ([cmd] if cmd is not None else [])
        p = subprocess.run(argv, input=data,
                           capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")

    def close(self):
        subprocess.run(["ssh", "-o", f"ControlPath={self.ctl}", "-O", "exit", f"root@{self.host}"],
                       capture_output=True)


# ---- HTTP / RTSP with Digest ----
def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def parse_challenge(h):
    return dict(re.findall(r'(\w+)="?([^",]*)"?', h.split(" ", 1)[1] if " " in h else ""))


def digest_header(ch, user, pw, method, uri, nc=1):
    ha1, ha2 = md5(f"{user}:{ch['realm']}:{pw}"), md5(f"{method}:{uri}")
    parts = [f'username="{user}"', f'realm="{ch["realm"]}"', f'nonce="{ch["nonce"]}"', f'uri="{uri}"',
             "algorithm=MD5"]
    if "auth" in ch.get("qop", "").split(","):
        cn, ncs = uuid.uuid4().hex[:16], f"{nc:08x}"
        parts += ["qop=auth", f"nc={ncs}", f'cnonce="{cn}"',
                  f'response="{md5(f"{ha1}:{ch["nonce"]}:{ncs}:{cn}:auth:{ha2}")}"']
    else:
        parts.append(f'response="{md5(f"{ha1}:{ch["nonce"]}:{ha2}")}"')
    if "opaque" in ch:
        parts.append(f'opaque="{ch["opaque"]}"')
    return "Digest " + ", ".join(parts)


def recv_reply(s, limit=4 << 20, rtsp=False):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    m = re.match(r"(?:HTTP|RTSP)/1\.\d (\d{3})", lines[0]) if lines and lines[0] else None
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs.setdefault(k.strip().lower(), v.strip())
    # RTSP: no Content-Length means no body (reading on would run into rtspd's login deadline);
    # HTTP (Connection: close): read to the end
    n = int(hdrs.get("content-length", "0" if rtsp else "-1"))
    while (n < 0 or len(body) < n) and len(body) < limit:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        body += d
    return (int(m.group(1)) if m else 0), hdrs, body, head.decode(errors="replace")


def connect(host, port, timeout=10):
    """A TCP connection to the camera (the offline test puts a socketpair here)."""
    return socket.create_connection((host, port), timeout=timeout)


def http(host, method, path, body=b"", headers=None, auth=None, port=None, tls=False):
    """One request per connection (camhttpd's rule); with auth=(user, pw), answers a 401 once.
    tls: over HTTPS (443 unless port says otherwise), the certificate not checked here (tls_checks
    does that)."""
    port = port or (TLS_PORT if tls else 80)

    def once(extra):
        s = connect(host, port)
        if tls:
            try:
                s = tls_ctx().wrap_socket(s, server_hostname=host)
            except (ssl.SSLError, OSError):
                s.close()
                raise
        try:
            h = {"Host": host, "Connection": "close", **(headers or {}), **extra}
            if body or method == "POST":
                h["Content-Length"] = str(len(body))
            req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
            s.sendall(req.encode() + body)
            return recv_reply(s)
        finally:
            s.close()
    r = once({})
    if r[0] == 401 and auth and "www-authenticate" in r[1]:
        r = once({"Authorization": digest_header(parse_challenge(r[1]["www-authenticate"]), *auth, method, path)})
    return r


def soap(host, service, body, auth=None):
    return http(host, "POST", f"/onvif/{service}_service", SOAP.format(body).encode(),
                {"Content-Type": "application/soap+xml; charset=utf-8"}, auth)


class Rtsp:
    def __init__(self, host, port=554):
        self.s = socket.create_connection((host, port), timeout=10)
        self.host, self.cseq = host, 0

    def req(self, method, url, extra=None):
        self.cseq += 1
        h = {"CSeq": str(self.cseq), "User-Agent": "gate3-live", **(extra or {})}
        self.s.sendall((f"{method} {url} RTSP/1.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
                        + "\r\n").encode())
        return recv_reply(self.s, rtsp=True)

    def closed(self):
        self.s.settimeout(3)
        try:
            return self.s.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False

    def close(self):
        self.s.close()


# ---- checks ----
def camera_side(r, ssh):
    cmd = ("echo '== version'; cat /etc/cam/version; echo '== uptime'; uptime; "
           "echo '== netstat'; netstat -ltnu; echo '== ps'; ps; echo '== cmdlines'; "
           "for p in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null); "
           "[ -n \"$c\" ] && echo \"${p#/proc/} $c\"; done; echo '== irled'; ls -l /dev/irled 2>&1; echo '== mounts'; cat /proc/mounts; "
           "echo '== perms'; ls -ld /mnt/nand/cam /mnt/nand/cam/* /run/fw /tmp 2>&1; "
           "echo '== suid'; find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null; "
           "find /mnt/nand -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null; "
           "echo '== worldwritable'; find / /mnt/nand -xdev -type f -perm -0002 2>/dev/null; "
           "echo '== shadow'; awk -F: '{print $1\":\"($2==\"*\"||$2==\"!\"||$2==\"x\"||$2==\"!*\"?\"locked\":\"PASSWORD SET\")}' /etc/shadow; "
           "echo '== ifconfig'; ifconfig eth0; echo '== inittab'; cat /etc/inittab; "
           "echo '== uids'; for p in /proc/[0-9]*; do n=$(cat $p/comm 2>/dev/null); case $n in "
           f"{'|'.join(DAEMONS)}) echo \"${{p#/proc/}} $n $(awk '/^PPid:/ {{ pp = $2 }} "
           "/^Uid:/ { u = $2 \" \" $3 \" \" $4 } /^Gid:/ { g = $2 } END { print pp, u, g }' $p/status 2>/dev/null)\";; "
           "esac; done; echo '== passwd'; cut -d: -f1,3 /etc/passwd; "
           "echo '== tls'; [ -e /run/camtls/ready ] && echo ready; cat /run/camtls/info 2>/dev/null; echo; "
           "echo '== tlsca'; cat /run/camtls/ca.crt 2>/dev/null; "
           "echo '== mac'; cat /sys/class/net/eth0/address; echo '== logread'; logread")
    rc, out, err = ssh.run(cmd, timeout=180)
    sec, cur = {}, None
    for ln in out.splitlines():
        if ln.startswith("== "):
            cur = ln[3:]
            sec[cur] = []
        elif cur:
            sec[cur].append(ln)
    if rc != 0 or "version" not in sec:
        r.result("FAIL", "ssh to the camera", (err.strip() or f"exit {rc}")[-300:])
        return None
    mac = "".join(sec.get("mac", [])).strip().lower()
    r.mac = mac if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None
    sec.pop("mac", None)
    r.save("camera-side.txt", "\n".join(f"== {k}\n" + "\n".join(v) for k, v in sec.items()) + "\n")
    r.result("INFO", "firmware version", " ".join(sec["version"]).strip())

    tcp, udp = set(), set()
    for ln in sec.get("netstat", []):
        f = ln.split()
        if len(f) >= 4 and f[0] in ("tcp", "tcp6") and "LISTEN" in ln:
            tcp.add(int(f[3].rsplit(":", 1)[1]))
        elif len(f) >= 4 and f[0] in ("udp", "udp6"):
            udp.add(int(f[3].rsplit(":", 1)[1]))
    ready, info, _ = tls_state(sec)
    r.result("INFO", "HTTPS (camtls)", ("ready" if ready else "not ready (no /run/camtls/ready)")
             + (f"; {' '.join(f'{k}={v}' for k, v in info.items())}" if info else ""))
    want = tcp_ok(sec)
    ok = tcp == want and (udp - UDP_INFO) == UDP_OK
    r.result("PASS" if ok else "FAIL", "§1 listeners on the camera (netstat)",
             f"tcp {sorted(tcp)} udp {sorted(udp)}; want tcp {sorted(want)} udp {sorted(UDP_OK)}"
             + (" (443/322: camtls is ready)" if ready else "") + (" (+68 udhcpc renewing)" if 68 in udp else ""))

    procs, vendor = set(), []
    for ln in sec.get("cmdlines", []):
        f = ln.split(None, 1)
        if len(f) < 2:
            continue
        args = f[1].split()
        name = args[0].strip("{}").rsplit("/", 1)[-1].lstrip("-")       # "-sh": a login shell
        if name in ("sh", "ash") and len(args) > 1 and args[1].startswith("/"):
            name = args[1].rsplit("/", 1)[-1]
        procs.add(name)
        if VENDOR_RE.search(f[1]):
            vendor.append(f[1])
    r.result("FAIL" if vendor else "PASS", "§5 no vendor processes", "; ".join(vendor) or "none")
    other = sorted(procs - PROC_OK)
    r.result("WARN" if other else "PASS", "§5 processes outside the image's allowlist",
             ", ".join(other) or "none")

    irl = " ".join(sec.get("irled", [])).strip()
    r.result("PASS" if irl.startswith("c") else "FAIL", "/dev/irled is the IR-cut device (rtspd's day/night)",
             irl or "missing")
    rw, ro_root = [], False
    for ln in sec.get("mounts", []):
        f = ln.split()
        if len(f) < 4:
            continue
        opts = f[3].split(",")
        if f[1] == "/" and f[2] == "squashfs" and "ro" in opts:
            ro_root = True
        if "rw" in opts and f[2] not in ("proc", "sysfs", "devpts", "devtmpfs", "debugfs"):
            hard = [o for o in ("nosuid", "nodev") if o not in opts and not (o == "nodev" and f[1] == "/dev")]
            rw.append(f"{f[1]} {f[2]}" + (f" (no {'/'.join(hard)})" if hard else ""))
    r.result("PASS" if ro_root else "FAIL", "§4 root is read-only squashfs", "yes" if ro_root else "no")
    bad_rw = [m for m in rw if not re.match(r"\S+ (tmpfs|jffs2|ramfs)\b", m)]
    r.result("FAIL" if bad_rw else ("WARN" if any("(no " in m for m in rw) else "PASS"),
             "§4 writable mounts are tmpfs/DATA only", "; ".join(rw))
    perms = sec.get("perms", [])
    dm = [ln for ln in perms if ln.rstrip().endswith("/mnt/nand/cam")]
    r.result("PASS" if dm and dm[0].startswith("drwx------") else "FAIL", "§4 /mnt/nand/cam is 0700",
             dm[0].split()[0] if dm else "missing")
    loose = [ln for ln in perms if ln.startswith("-") and not re.match(r"-r[w-]-------", ln)]
    r.result("WARN" if loose else "PASS", "§6 files on DATA readable by others",
             "; ".join(ln.split()[0] + " " + ln.split()[-1] for ln in loose) or "none")
    suid = [ln for ln in sec.get("suid", []) if ln.strip()]
    r.result("WARN" if suid else "PASS", "setuid/setgid files", ", ".join(suid) or "none")
    ww = list(dict.fromkeys(ln.strip() for ln in sec.get("worldwritable", []) if ln.strip()))
    r.result("FAIL" if ww else "PASS", "world-writable files", ", ".join(ww) or "none")
    sh = sec.get("shadow", [])
    rootl = [ln for ln in sh if ln.startswith("root:")]
    r.result("PASS" if rootl == ["root:locked"] else "FAIL", "§2 root has no password",
             ", ".join(sh) or "no /etc/shadow")
    logs = "\n".join(sec.get("logread", []))
    if r.mac:
        n = len(re.findall(re.escape(r.mac) + "|" + re.escape(r.mac.replace(":", "")), logs, re.I))
        r.result("PASS" if n == 0 else "FAIL", "§6 MAC absent from logread", f"{n} occurrences")
    else:
        r.result("WARN", "§6 MAC absent from logread", "couldn't read eth0's MAC")
    pw_hits = [ln for ln in logs.splitlines() if re.search(r"pass(word)?[=:]\s*\S", ln, re.I)]
    r.result("WARN" if pw_hits else "PASS", "§6 no password-looking values in logread",
             f"{len(pw_hits)} lines (see camera-side.txt)" if pw_hits else "none")
    daemon_uids(r, sec)
    return sec


def tls_state(sec):
    """camtls as camera_side saw it: (ready, the fields of /run/camtls/info's "ok ..." line, the CA
    certificate's PEM from /run/camtls/ca.crt, or "")."""
    lines = [ln.strip() for ln in (sec or {}).get("tls", []) if ln.strip()]
    info = {}
    for ln in lines:
        if ln.startswith("ok "):
            info = dict(kv.split("=", 1) for kv in ln.split()[1:] if "=" in kv)
    pem = "\n".join((sec or {}).get("tlsca", [])).strip()
    return "ready" in lines, info, (pem + "\n" if "BEGIN CERTIFICATE" in pem else "")


def tcp_ok(sec):
    """The TCP listeners the image should have: 443 and 322 too while camtls is ready."""
    return TCP_OK | ({TLS_PORT, RTSPS_PORT} if tls_state(sec)[0] else set())


def daemon_uids(r, sec):
    """§7: who each daemon runs as (/proc/PID/status), one INFO line per process. camhttpd with -Z
    is two: the monitor (root) and its child, the worker (camhttpd); dropbear's sessions are
    children of its listener."""
    names = {}
    for ln in sec.get("passwd", []):
        f = ln.strip().split(":")
        if len(f) == 2 and f[1].isdigit():
            names.setdefault(f[1], f[0])
    procs = []
    for ln in sec.get("uids", []):
        f = ln.split()
        if len(f) == 7 and f[1] in DAEMONS and all(x.isdigit() for x in f[2:]) and f[0].isdigit():
            procs.append(f)
    pids = {f[0]: f[1] for f in procs}
    for name in DAEMONS:
        mine = [f for f in procs if f[1] == name]
        if not mine:
            r.result("INFO", f"§7 runs as: {name}", "not running")
        for pid, _, ppid, ruid, euid, suid, gid in mine:
            label = name
            if name == "camhttpd":
                label += " worker" if pids.get(ppid) == "camhttpd" else " monitor"
            elif name == "dropbear" and pids.get(ppid) == "dropbear":
                label += " session"
            who = names.get(ruid, "?")
            same = ruid == euid == suid
            r.result("INFO", f"§7 runs as: {label} (pid {pid})",
                     f"uid {ruid} ({who})" + ("" if same else f", euid {euid}, saved {suid}") + f", gid {gid}")


class Out:
    def __init__(self, text):
        self.stdout, self.stderr = text, ""


def nmap_live(argv, what, limit=3600):
    """Run nmap with its progress on the terminal (a full scan takes minutes); the output as .stdout."""
    print(f"{what}: {' '.join(argv)} (progress every 30 s)", flush=True)
    p = subprocess.Popen(argv[:2] + ["--stats-every", "30s"] + argv[2:], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=argv[0] != "sudo")      # sudo prompts on our terminal
    fd, buf, end, quiet = p.stdout.fileno(), b"", time.time() + limit, 0
    while True:
        ready = select.select([fd], [], [], 1.0)[0]
        chunk = os.read(fd, 65536) if ready else b""
        if chunk:
            buf += chunk
            for ln in chunk.decode(errors="replace").splitlines():
                print("    " + ln, flush=True)
        elif ready:
            break                                       # EOF
        if p.poll() is not None and not chunk:
            quiet += 1
            if quiet >= 3:                              # nmap is gone; don't wait on whoever holds the pipe
                break
        if time.time() > end:
            try:
                if argv[0] == "sudo":
                    p.kill()
                else:
                    os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            buf += f"\n(gate3-live: nmap stopped after {limit} s)\n".encode()
            break
    p.stdout.close()
    p.wait()
    lines = [buf.decode(errors="replace")]
    return Out("".join(lines))


def nmap_checks(r, host, udp, full=True, want_tcp=TCP_OK):
    """The SSH algorithms (one port, quick); with full, every TCP port too (minutes; long over Wi-Fi)."""
    if not shutil.which("nmap"):
        r.result("FAIL", "nmap", "not installed (brew install nmap)")
        return
    if full:
        p = nmap_live(["nmap", "-Pn", "-sT", "-p-", "-T4", "--open", host], "every TCP port")
        r.save("nmap-tcp.txt", p.stdout + p.stderr)
        tcp = {int(m) for m in re.findall(r"^(\d+)/tcp\s+open", p.stdout, re.M)}
        r.result("PASS" if tcp == want_tcp else "FAIL", "§1 nmap -p- -sT (every TCP port)",
                 f"open {sorted(tcp)}; want {sorted(want_tcp)}")
    else:
        r.result("INFO", "§1 nmap -p- -sT (every TCP port)", "skipped (--skip-nmap); still to do for Gate 3")
    p = subprocess.run(["nmap", "-Pn", "-p22", "--script", "ssh2-enum-algos", host], capture_output=True,
                       text=True, timeout=300)
    r.save("nmap-ssh-algos.txt", p.stdout + p.stderr)
    algos = p.stdout
    bad = sorted(set(m.group(0).strip() for m in BAD_SSH.finditer(algos)))
    r.result("FAIL" if bad else "PASS", "§2 SSH algorithms (no SHA-1, CBC, 3DES, DSS)",
             ", ".join(bad) or "none weak")
    r.result("PASS" if "kex-strict-s-v00@openssh.com" in algos else "FAIL", "§2 SSH strict kex (Terrapin)",
             "kex-strict-s-v00@openssh.com " + ("offered" if "kex-strict-s" in algos else "missing"))
    if udp and full:
        print("nmap -sU needs root: sudo asks for your Mac password", flush=True)
        p = nmap_live(["sudo", "nmap", "-Pn", "-sU", "--top-ports", "200", host], "top 200 UDP ports")
        r.save("nmap-udp.txt", p.stdout + p.stderr)
        opn = {int(m) for m in re.findall(r"^(\d+)/udp\s+open(?!\|)", p.stdout, re.M)}
        amb = {int(m) for m in re.findall(r"^(\d+)/udp\s+open\|filtered", p.stdout, re.M)}
        r.result("PASS" if opn <= UDP_OK else "FAIL", "§1 nmap -sU --top-ports 200",
                 f"open {sorted(opn)}; open|filtered {sorted(amb)[:20]}")


def ssh_checks(r, host, ssh):
    try:
        s = socket.create_connection((host, 22), timeout=5)
        banner = s.recv(256).split(b"\r\n")[0].decode(errors="replace").strip()
        s.close()
    except OSError as e:
        banner = f"({e})"
    r.result("INFO", "SSH banner", banner)
    p = subprocess.run(["ssh", "-S", "none", "-o", "ControlMaster=no", "-o", "PubkeyAuthentication=no",
                        "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "BatchMode=yes",
                        "-o", "NumberOfPasswordPrompts=0", "-o", "ConnectTimeout=10", f"root@{host}", "true"],
                       capture_output=True, text=True, timeout=60)
    m = re.search(r"Permission denied \(([^)]*)\)", p.stderr)
    ok = p.returncode != 0 and m and "password" not in m.group(1) and "keyboard" not in m.group(1)
    r.result("PASS" if ok else "FAIL", "§2 SSH password login refused",
             f"methods offered: {m.group(1)}" if m else p.stderr.strip()[-200:])
    rc, out, err = ssh.run(None, data=b"GET / HTTP/1.0\r\n\r\n", extra=["-W", "127.0.0.1:80"], timeout=60)
    refused = re.search(r"prohibited|open failed|forwarding failed|refused", err)
    ok = "HTTP/1." not in out
    r.result(("PASS" if refused else "WARN") if ok else "FAIL", "§2 SSH TCP forwarding (direct-tcpip) refused",
             (err.strip().splitlines() or [f"exit {rc}"])[-1][:160])
    rc, out, err = ssh.run("echo FORWARD-ACCEPTED", extra=["-o", "ExitOnForwardFailure=yes",
                                                           "-R", "0:127.0.0.1:9"], timeout=60)
    ok = re.search(r"forwarding failed|Could not request|prohibited", err) or "FORWARD-ACCEPTED" not in out
    r.result("PASS" if ok else "FAIL", "§2 SSH remote forwarding refused",
             (err.strip().splitlines() or [f"exit {rc}"])[-1][:160])
    if os.environ.get("SSH_AUTH_SOCK"):
        rc, out, err = ssh.run("echo AGENT=${SSH_AUTH_SOCK:-none}", extra=["-o", "ForwardAgent=yes"])
        r.result("PASS" if "AGENT=none" in out else "FAIL", "§2 SSH agent forwarding refused", out.strip())
    else:
        r.result("INFO", "§2 SSH agent forwarding", "no local agent to forward; compiled out "
                 "(DROPBEAR_SVR_AGENTFWD 0, rootfs/dropbear/localoptions.h)")
    # the key exchange this client and the camera agree on (no login needed: auth method "none")
    p = subprocess.run(["ssh", "-v", "-S", "none", "-o", "ControlMaster=no", "-o", "BatchMode=yes",
                        "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=none",
                        "-o", "ConnectTimeout=10", f"root@{host}", "true"],
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    m = re.search(r"kex: algorithm: (\S+)", p.stderr)
    mine = subprocess.run(["ssh", "-Q", "kex"], capture_output=True, text=True).stdout
    if not re.search(r"mlkem|sntrup", mine):
        r.result("INFO", "§2 SSH post-quantum key exchange", "this ssh client offers none; can't tell")
    else:
        ok = bool(m and re.search(r"mlkem|sntrup", m.group(1)))
        r.result("PASS" if ok else "FAIL", "§2 SSH post-quantum key exchange",
                 f"negotiated {m.group(1) if m else 'nothing (see -v output)'}")
    if os.environ.get("DISPLAY"):
        rc, out, err = ssh.run("echo X11=${DISPLAY:-none}", extra=["-o", "ForwardX11=yes"])
        r.result("PASS" if "X11=none" in out else "FAIL", "§2 SSH X11 forwarding refused", out.strip())
    else:
        r.result("INFO", "§2 SSH X11 forwarding", "no local DISPLAY; compiled out (DROPBEAR_X11FWD 0)")


def rtsp_checks(r, host, admin):
    log = []
    try:
        c = Rtsp(host)
        url = f"rtsp://{host}:554/"
        st_d, h, _, raw = c.req("DESCRIBE", url, {"Accept": "application/sdp"})
        log.append(raw)
        st_s, _, _, raw = c.req("SETUP", url + "track0", {"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"})
        log.append(raw)
        st_p, _, _, raw = c.req("PLAY", url, {"Session": "12345678", "Range": "npt=0.000-"})
        log.append(raw)
        c.close()
        ok = (st_d, st_s, st_p) == (401, 401, 401)
        r.result("PASS" if ok else "FAIL", "§2 RTSP DESCRIBE/SETUP/PLAY without credentials",
                 f"{st_d}/{st_s}/{st_p}")
        c = Rtsp(host)
        st, h, _, raw = c.req("DESCRIBE", url, {"Accept": "application/sdp"})
        ch = parse_challenge(h.get("www-authenticate", ""))
        st, h, body, raw = c.req("DESCRIBE", url, {"Accept": "application/sdp",
                                                   "Authorization": digest_header(ch, *admin, "DESCRIBE", url)})
        log.append(raw)
        c.close()
        r.result("PASS" if st == 200 and b"m=video" in body else "FAIL", "§2 RTSP DESCRIBE with the admin's Digest",
                 str(st))
        c = Rtsp(host)
        t0 = time.time()
        st, h, _, raw = c.req("DESCRIBE", url)
        ch = parse_challenge(h.get("www-authenticate", ""))
        codes = []
        for i in range(5):
            try:
                st, _, _, raw = c.req("DESCRIBE", url, {"Authorization": digest_header(
                    ch, "gate3-nobody", f"wrong-{i}", "DESCRIBE", url)})
                codes.append(st)
            except OSError:
                codes.append("closed")
                break
        closed = c.closed()
        took = time.time() - t0
        c.close()
        # well inside rtspd's 10 s login deadline, so it was the 5 tries that closed it
        r.result("PASS" if closed and took < 8 and codes[:4] == [401] * 4 else "FAIL",
                 "§2 RTSP closes after 5 wrong passwords",
                 f"replies {codes}, then {'closed' if closed else 'still open'} after {took:.1f} s")
    except OSError as e:
        r.result("FAIL", "§2 RTSP", str(e))
    r.save("rtsp.txt", "\n\n".join(log))


def fault(body):
    m = re.search(rb"<(?:\w+:)?Subcode>.*?<(?:\w+:)?Value>([^<]+)</", body, re.S)
    return m.group(1).decode() if m else ""


def onvif_checks(r, host, admin, others, ui_tls=False):
    """ui_tls: camtls is ready, so the web UI (/ui/*, /setup) is checked over HTTPS; ONVIF and
    /snapshot.jpg stay on port 80 (SSS)."""
    log = []
    origin = f"{'https' if ui_tls else 'http'}://{host}"
    if ui_tls:
        r.result("INFO", "§2 web UI checks below", "over HTTPS (camtls is ready)")
    for op, b in PRE_AUTH.items():
        st, h, body, raw = soap(host, "device", b)
        log.append(f"--- {op} (no credentials)\n{raw}\n{body[:400].decode(errors='replace')}")
        r.result("PASS" if st == 200 else "FAIL", f"§2 ONVIF {op} without credentials (PRE_AUTH)", str(st))
    for op, (svc, b) in NEED_AUTH.items():
        st, h, body, raw = soap(host, svc, b)
        log.append(f"--- {op} (no credentials)\n{raw}\n{body[:400].decode(errors='replace')}")
        r.result("PASS" if st == 401 else "FAIL", f"§2 ONVIF {op} without credentials", str(st))
    st, h, body, raw = soap(host, "device", "<tds:GetDeviceInformation/>", admin)
    log.append(f"--- GetDeviceInformation (admin)\n{raw}\n{body.decode(errors='replace')}")
    sn = re.search(rb"<tds:SerialNumber>([^<]*)<", body)
    r.result("PASS" if st == 200 and sn and sn.group(1) == b"0" else "FAIL", "§6 ONVIF SerialNumber is \"0\"",
             f"{st}, {sn.group(1).decode() if sn else 'none'}")
    st, h, body, raw = soap(host, "device", "<tds:GetUsers/>", admin)
    r.result("PASS" if st == 200 else "FAIL", "§2 ONVIF GetUsers as admin (positive control)", str(st))
    for role, (user, pw) in others.items():
        for op, (svc, b) in ABOVE[role].items():
            st, h, body, raw = soap(host, svc, b, (user, pw))
            log.append(f"--- {op} ({role})\n{raw}\n{body[:600].decode(errors='replace')}")
            f = fault(body)
            ok = st in (400, 401, 403) and "NotAuthorized" in body.decode(errors="replace")
            r.result("PASS" if ok else "FAIL", f"§2 ONVIF {op} refused for a {role}", f"{st} {f}")
        st, h, body, raw = soap(host, "media", "<trt:GetProfiles/>", (user, pw))
        r.result("PASS" if st == 200 else "FAIL", f"§2 ONVIF GetProfiles as {role} (positive control)", str(st))
        for path in UI_ABOVE[role]:
            st, *_ = http(host, "GET", path, auth=(user, pw), tls=ui_tls)
            r.result("PASS" if st == 403 else "FAIL", f"§2 web UI {path} refused for a {role}", str(st))
    r.save("onvif.txt", "\n\n".join(log))

    st, h, body, _ = http(host, "GET", "/snapshot.jpg")
    r.result("PASS" if st == 401 else "FAIL", "§2 /snapshot.jpg without credentials", str(st))
    st, h, body, _ = http(host, "GET", "/snapshot.jpg", auth=admin)
    r.result("PASS" if st == 200 and body[:2] == b"\xff\xd8" else "FAIL", "§2 /snapshot.jpg with Digest",
             f"{st}, {len(body)} bytes (not saved)")
    st, *_ = http(host, "GET", "/ui/", tls=ui_tls)
    r.result("PASS" if st == 401 else "FAIL", "§2 web UI without credentials", str(st))
    setup_gone_checks(r, host, ui_tls)
    st, h, body, _ = http(host, "POST", "/ui/firmware", b"x" * 16, {"Content-Type": "application/octet-stream"},
                          auth=admin, tls=ui_tls)
    r.result("PASS" if st == 403 else "FAIL", "§2 web UI POST without Origin and form token (CSRF)", str(st))
    # /ui/time with a field it doesn't know: even with both checks missing nothing would change
    st, h, body, _ = http(host, "GET", "/ui/time", auth=admin, tls=ui_tls)
    tok = re.search(rb'name="csrf" value="([0-9a-f]{40})"', body)
    form = b"csrf=" + (tok.group(1) if tok else b"") + b"&gate3=1"
    ct = {"Content-Type": "application/x-www-form-urlencoded"}
    st, *_ = http(host, "POST", "/ui/time", form, {**ct, "Origin": "http://gate3.invalid"}, auth=admin, tls=ui_tls)
    r.result("PASS" if st == 403 and tok else "FAIL", "§2 web UI POST from another Origin, valid token (CSRF)",
             str(st) + ("" if tok else ", no token on the page"))
    st, *_ = http(host, "POST", "/ui/time", b"gate3=1", {**ct, "Origin": origin}, auth=admin, tls=ui_tls)
    r.result("PASS" if st == 403 else "FAIL", "§2 web UI POST from our Origin without the token (CSRF)", str(st))
    st, h, body, _ = http(host, "GET", "/ui/", auth=admin, tls=ui_tls)
    need = ["content-security-policy", "x-frame-options", "x-content-type-options"]
    miss = [k for k in need if k not in h]
    r.result("PASS" if st == 200 and not miss else "FAIL", "§2 web UI security headers",
             f"{st}" + (f", missing {miss}" if miss else ""))
    if r.mac:
        hits = [ln for ln in "\n".join(log).splitlines() if r.mac.replace(":", "") in ln.lower().replace(":", "")]
        r.result("PASS" if not hits else "FAIL", "§6 MAC absent from the ONVIF replies above", f"{len(hits)} lines")


def setup_gone_checks(r, host, ui_tls):
    """/setup once claimed: 404; while camtls is ready, port 80 sends it to https:// (before the
    claimed check, as for every page) and HTTPS answers 404."""
    if not ui_tls:
        st, *_ = http(host, "GET", "/setup")
        r.result("PASS" if st == 404 else "FAIL", "§2 /setup is gone once claimed", str(st))
        return
    st, h, *_ = http(host, "GET", "/setup")
    loc = h.get("location", "")
    r.result("PASS" if st == 302 and loc == f"https://{host}/setup" else "FAIL",
             "§2 /setup on port 80 goes to https:// (camtls ready)", f"{st} Location {loc or 'none'}")
    st, *_ = http(host, "GET", "/setup", tls=True)
    r.result("PASS" if st == 404 else "FAIL", "§2 /setup is gone once claimed (HTTPS)", str(st))


# ---- TLS (camtls, docs/PLAN-TLS.md §B) ----
APPLE_DAYS = 397                      # a locally trusted server certificate's lifetime on macOS
OID_SAN, OID_EKU, OID_BC, OID_NC = "2.5.29.17", "2.5.29.37", "2.5.29.19", "2.5.29.30"
OID_SKI, OID_AKI = "2.5.29.14", "2.5.29.35"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_EC, OID_P256 = "1.2.840.10045.2.1", "1.2.840.10045.3.1.7"
CAM_NET = None                        # the camera subnet: main() sets it (--cam-net, CAM_NET, cam-net.local)


def cam_net_setting():
    """CAM_NET as scripts/cam-net.sh reads it: the environment, else the first line of cam-net.local
    at the repository root that isn't blank or a comment; None if neither."""
    v = os.environ.get("CAM_NET")
    if not v:
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cam-net.local")) as f:
                v = next((s.strip() for s in f if s.strip() and not s.strip().startswith("#")), None)
        except OSError:
            v = None
    return v
TLS13_AEAD = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
TLS12_GOOD = re.compile(r"ECDHE-ECDSA-(AES(128|256)-GCM-SHA(256|384)|CHACHA20-POLY1305)")


def der(b, i=0):
    """The DER element at b[i]: (tag, where its content starts, where it ends)."""
    if i + 2 > len(b):
        raise ValueError("DER: truncated")
    tag, n, i = b[i], b[i + 1], i + 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or i + k > len(b):
            raise ValueError("DER: bad length")
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    if i + n > len(b):
        raise ValueError("DER: truncated")
    return tag, i, i + n


def der_list(b, start, end):
    """The elements from start to end (a SEQUENCE's content)."""
    out = []
    while start < end:
        t, s, e = der(b, start)
        if e > end:
            raise ValueError("DER: element past its parent")
        out.append((t, s, e))
        start = e
    return out


def der_oid(c):
    first = min(c[0] // 40, 2)
    parts, v = [str(first), str(c[0] - 40 * first)], 0
    for x in c[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def der_time(tag, c):
    t = c.decode("ascii")
    if tag == 0x17:                                     # UTCTime: YYMMDDHHMMSSZ
        t = ("19" if int(t[:2]) >= 50 else "20") + t
    return datetime.datetime.strptime(t, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def general_names(b, s, e):
    """A GeneralNames (or nameConstraints base) list as text: "IP a.b.c.d", "IP net/len", "DNS x"."""
    out = []
    for t, cs, ce in der_list(b, s, e):
        v = b[cs:ce]
        if t == 0x87 and len(v) in (4, 16):
            out.append(f"IP {ipaddress.ip_address(v)}")
        elif t == 0x87 and len(v) in (8, 32):           # a constraint: address and mask
            h = len(v) // 2
            out.append(f"IP {ipaddress.ip_address(v[:h])}/{bin(int.from_bytes(v[h:], 'big')).count('1')}")
        elif t == 0x82:
            out.append(f"DNS {v.decode('ascii', 'replace')}")
        else:
            out.append(f"other (tag 0x{t:02x})")
    return out


def parse_cert(d):
    """What these checks need from an X.509 certificate (DER), with a minimal DER walk."""
    _, s, e = der(d)
    _, ts, te = der(d, s)                               # tbsCertificate
    items = der_list(d, ts, te)
    if items[0][0] == 0xA0:                             # version
        items = items[1:]
    _, _, issuer, validity, subject, spki = items[:6]
    nb, na = der_list(d, validity[1], validity[2])
    _, as_, ae = der(d, spki[1])                        # AlgorithmIdentifier
    alg = der_list(d, as_, ae)
    c = {"issuer": d[issuer[1]:issuer[2]], "subject": d[subject[1]:subject[2]],
         "not_before": der_time(nb[0], d[nb[1]:nb[2]]),
         "not_after": der_time(na[0], d[na[1]:na[2]]),
         "key": (der_oid(d[alg[0][1]:alg[0][2]]),
                 der_oid(d[alg[1][1]:alg[1][2]]) if len(alg) > 1 and alg[1][0] == 0x06 else None),
         "ext": {}}
    for t, xs, xe in items[6:]:
        if t != 0xA3:
            continue
        _, ss, se = der(d, xs)
        for _, es, ee in der_list(d, ss, se):
            f = der_list(d, es, ee)
            crit = len(f) == 3 and f[1][0] == 0x01 and d[f[1][1]] != 0
            c["ext"][der_oid(d[f[0][1]:f[0][2]])] = (crit, d[f[-1][1]:f[-1][2]])
    return c


def cert_san(c):
    v = c["ext"].get(OID_SAN, (False, b""))[1]
    return general_names(v, *der(v)[1:]) if v else []


def cert_eku(c):
    v = c["ext"].get(OID_EKU, (False, b""))[1]
    return [der_oid(v[s:e]) for _, s, e in der_list(v, *der(v)[1:])] if v else []


def cert_is_ca(c):
    v = c["ext"].get(OID_BC, (False, b""))[1]
    f = der_list(v, *der(v)[1:]) if v else []
    return bool(f) and f[0][0] == 0x01 and v[f[0][1]] != 0


def cert_key_ids(leaf, ca):
    """The leaf's authorityKeyIdentifier and the CA's subjectKeyIdentifier (each None if absent)."""
    aki = ski = None
    v = leaf["ext"].get(OID_AKI, (False, b""))[1]
    for t, s, e in (der_list(v, *der(v)[1:]) if v else []):
        if t == 0x80:
            aki = v[s:e]
    v = ca["ext"].get(OID_SKI, (False, b""))[1]
    if v:
        _, s, e = der(v)
        ski = v[s:e]
    return aki, ski


def cert_nc(c):
    """nameConstraints: (critical, permitted names, excluded names), or None without it."""
    if OID_NC not in c["ext"]:
        return None
    crit, v = c["ext"][OID_NC]
    sub = {0xA0: [], 0xA1: []}
    for t, s, e in der_list(v, *der(v)[1:]):
        for _, gs, ge in der_list(v, s, e):             # GeneralSubtree: its base name first
            sub.setdefault(t, []).extend(general_names(v, gs, der(v, gs)[2]))
    return crit, sub[0xA0], sub[0xA1]


def fp(der_bytes):
    return hashlib.sha256(der_bytes).hexdigest()


def same_fp(a, b):
    return a.replace(":", "").lower() == (b or "").replace(":", "").lower()


def cert_checks(r, host, leaf, ca_der=None, info=None):
    """The server certificate (DER) and, with ca_der, the camera's CA; results into r."""
    try:
        c = parse_cert(leaf)
        sans, eku = cert_san(c), cert_eku(c)
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        r.result("FAIL", "TLS server certificate", f"can't read it: {e}")
        return
    r.result("PASS" if sans == [f"IP {host}"] else "FAIL", "TLS certificate names the camera's IP only (SAN)",
             ", ".join(sans) or "no SAN")
    r.result("PASS" if OID_SERVER_AUTH in eku else "FAIL", "TLS certificate EKU serverAuth",
             ", ".join(eku) or "no EKU")
    days = (c["not_after"] - c["not_before"]).total_seconds() / 86400
    r.result("PASS" if days <= APPLE_DAYS else "FAIL", f"TLS certificate lifetime at most {APPLE_DAYS} days (macOS)",
             f"{days:.1f} days, {c['not_before']:%Y-%m-%d} to {c['not_after']:%Y-%m-%d}")
    r.result("PASS" if c["key"] == (OID_EC, OID_P256) else "FAIL", "TLS certificate key EC P-256",
             "EC P-256" if c["key"] == (OID_EC, OID_P256) else f"{c['key'][0]} {c['key'][1] or ''}".strip())
    r.result("FAIL" if cert_is_ca(c) else "PASS", "TLS certificate is no CA (CA:FALSE)",
             "CA:TRUE" if cert_is_ca(c) else "not a CA")
    if info:
        r.result("PASS" if same_fp(fp(leaf), info.get("fp")) else "FAIL",
                 "TLS certificate is the one /run/camtls/info names", f"sha256 {fp(leaf)}")
    if ca_der is None:
        return
    try:
        a = parse_cert(ca_der)
        nc = cert_nc(a)
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        r.result("FAIL", "TLS camera CA (/run/camtls/ca.crt)", f"can't read it: {e}")
        return
    aki, ski = cert_key_ids(c, a)
    same_key = aki is None or ski is None or aki == ski
    r.result("PASS" if c["issuer"] == a["subject"] and same_key and cert_is_ca(a) else "FAIL",
             "TLS certificate issued by the camera's CA (CA:TRUE)",
             ("issuer = CA subject" if c["issuer"] == a["subject"] else "issuer differs from the CA's subject")
             + ("" if same_key else ", another CA key (authorityKeyIdentifier)")
             + ("" if cert_is_ca(a) else ", the CA isn't CA:TRUE"))
    if nc is None:
        r.result("FAIL", "TLS camera CA has critical nameConstraints", "no nameConstraints extension")
    else:
        crit, perm, excl = nc
        v4 = [n for n in perm if n.startswith("IP ") and "." in n]
        v4_in = bool(v4) and all(ipaddress.ip_network(n[3:]).subnet_of(CAM_NET) for n in v4)
        v6 = any(n.startswith("IP ") and ":" in n for n in perm)
        dns = any(n.startswith("DNS ") for n in perm)
        ok = crit and v4_in and v6 and dns
        r.result("PASS" if ok else "FAIL", f"TLS camera CA has critical nameConstraints ({CAM_NET} only)",
                 ("critical" if crit else "NOT critical") + f"; permitted {', '.join(perm) or 'none'}"
                 + (f"; excluded {', '.join(excl)}" if excl else "")
                 + ("" if v4_in else f"; IPv4 must stay in {CAM_NET}") + ("" if v6 else "; IPv6 unconstrained")
                 + ("" if dns else "; DNS names unconstrained"))
    if info:
        r.result("PASS" if same_fp(fp(ca_der), info.get("ca_fp")) else "FAIL",
                 "TLS camera CA is the one /run/camtls/info names", f"sha256 {fp(ca_der)}")


def tls_ctx(lo=None, hi=None, ciphers=None, ca_pem=None):
    """A client context: no certificate check, unless ca_pem (then that CA only, and the name)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_pem:
        ctx.load_verify_locations(cadata=ca_pem)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():                     # TLSv1 / TLSv1_1 are deprecated names
        warnings.simplefilter("ignore", DeprecationWarning)
        if ciphers:
            ctx.set_ciphers(ciphers)
        if lo:
            ctx.minimum_version = lo
        if hi:
            ctx.maximum_version = hi
    return ctx


def suites(pick):
    """This machine's TLS 1.2-and-older suites that pick() selects, as a cipher string (or None)."""
    ctx = tls_ctx(ciphers="ALL:@SECLEVEL=0")
    names = [c["name"] for c in ctx.get_ciphers() if c["protocol"] != "TLSv1.3" and pick(c)]
    return ":".join(names) + ":@SECLEVEL=0" if names else None


def can_offer(ctx):
    """True if this machine's OpenSSL makes a ClientHello with ctx (TLS 1.0/1.1 may be compiled
    out or refused by its policy)."""
    out = ssl.MemoryBIO()
    try:
        ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname="192.0.2.1").do_handshake()
    except ssl.SSLWantReadError:
        return out.pending > 0
    except (ssl.SSLError, ValueError):
        return False
    return False


def tls_try(host, ctx):
    """One handshake on 443: ((version, cipher, group or None, peer certificate DER), None) or
    (None, why). why starts with "connect:" when nothing answered."""
    try:
        raw = connect(host, TLS_PORT)
    except OSError as e:
        return None, f"connect: {e}"
    try:
        s = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        raw.close()
        return None, f"certificate: {e.verify_message}"
    except (ssl.SSLError, OSError) as e:
        raw.close()
        return None, f"refused: {getattr(e, 'reason', None) or e}"
    try:
        grp = s.group() if hasattr(s, "group") else None
        return (s.version(), s.cipher()[0], grp, s.getpeercert(binary_form=True)), None
    finally:
        s.close()


def tls_checks(r, host, sec):
    """camtls on 443 (docs/PLAN-TLS.md §B), its certificates, and port 80 while it is ready."""
    ready, info, ca_pem = tls_state(sec)
    if not ready:
        r.result("FAIL", "HTTPS: camtls ready (/run/camtls/ready)",
                 "not ready: /etc/cam/tls.on or /run/tls.on? (logread | grep camtls)")
        return
    log = []
    v1, v11, v12, v13 = (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2,
                         ssl.TLSVersion.TLSv1_3)
    cbc = suites(lambda c: not c["aead"] and c["auth"] in ("auth-ecdsa", "auth-rsa"))
    rsa = suites(lambda c: c["auth"] == "auth-rsa")
    for name, lo, hi, ciphers in (("TLS 1.0", v1, v1, "ALL:@SECLEVEL=0"), ("TLS 1.1", v11, v11, "ALL:@SECLEVEL=0"),
                                  ("TLS 1.2 offering only CBC suites", v12, v12, cbc),
                                  ("TLS 1.2 offering only RSA suites", v12, v12, rsa)):
        try:
            ctx = tls_ctx(lo, hi, ciphers) if ciphers else None
        except (ssl.SSLError, ValueError):
            ctx = None
        if ctx is None or not can_offer(ctx):
            r.result("INFO", f"HTTPS refuses {name}", "this machine's OpenSSL can't offer it: not tested")
            continue
        res, why = tls_try(host, ctx)
        log.append(f"--- {name}: {res[:3] if res else why}")
        r.result("FAIL" if res or why.startswith("connect") else "PASS", f"HTTPS refuses {name}",
                 f"negotiated {res[0]} {res[1]}" if res else why)
    leaf = None
    for name, ver in (("TLS 1.3", v13), ("TLS 1.2", v12)):
        res, why = tls_try(host, tls_ctx(ver, ver))
        log.append(f"--- {name}: {res[:3] if res else why}")
        if not res:
            r.result("FAIL", f"HTTPS {name} with ECDHE-ECDSA and an AEAD cipher", why)
            continue
        got, cipher, grp, cert = res
        good = cipher in TLS13_AEAD if ver == v13 else bool(TLS12_GOOD.fullmatch(cipher))
        want = "TLSv1.3" if ver == v13 else "TLSv1.2"
        r.result("PASS" if good and got == want else "FAIL", f"HTTPS {name} with ECDHE-ECDSA and an AEAD cipher",
                 f"{got} {cipher}, group {grp or 'not reported by this Python'}")
        leaf = leaf or cert
    ca_der = None
    if ca_pem:
        try:
            ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
        except ValueError as e:
            r.result("FAIL", "TLS camera CA (/run/camtls/ca.crt)", f"not a PEM certificate: {e}")
    else:
        r.result("FAIL", "TLS camera CA (/run/camtls/ca.crt)", "missing (camtls-run publishes it)")
    if leaf:
        cert_checks(r, host, leaf, ca_der, info)
    if ca_der:
        try:
            res, why = tls_try(host, tls_ctx(ca_pem=ca_pem))
        except ssl.SSLError as e:
            res, why = None, f"this machine's OpenSSL won't load the CA: {e}"
        r.result("PASS" if res else "FAIL", "HTTPS chain verifies against the camera's CA, for the camera's IP",
                 f"{res[0]}, as a browser that trusts the CA would" if res else why)
    try:
        port80_checks(r, host)
    except OSError as e:
        r.result("FAIL", "HTTPS: port 80 while camtls is ready", str(e))
    r.save("tls.txt", "\n".join(log) + "\n")


def port80_checks(r, host):
    """Port 80 while camtls is ready: browsers go to https:// before any login, the claim is
    HTTPS-only, ONVIF and /snapshot.jpg stay for SSS; the web UI over https asks for Digest."""
    st, h, *_ = http(host, "GET", "/ui/")
    loc = h.get("location", "")
    ok = st == 302 and loc == f"https://{host}/ui/" and "www-authenticate" not in h
    r.result("PASS" if ok else "FAIL", "HTTPS: GET /ui/ on port 80 goes to https:// without a login",
             f"{st} Location {loc or 'none'}" + (", asks for a login" if "www-authenticate" in h else ""))
    st, *_ = http(host, "POST", "/setup", b"csrf=gate3", {"Content-Type": "application/x-www-form-urlencoded",
                                                         "Origin": f"http://{host}"})
    r.result("PASS" if st == 403 else "FAIL", "HTTPS: POST /setup on port 80 refused while camtls is ready", str(st))
    st, *_ = http(host, "GET", "/snapshot.jpg")
    r.result("PASS" if st == 401 else "FAIL", "HTTPS: /snapshot.jpg stays on port 80 (Digest, for SSS)", str(st))
    st, *_ = soap(host, "device", PRE_AUTH["GetSystemDateAndTime"])
    r.result("PASS" if st == 200 else "FAIL", "HTTPS: ONVIF stays on port 80 (GetSystemDateAndTime)", str(st))
    st, h, *_ = http(host, "GET", "/ui/", tls=True)
    r.result("PASS" if st == 401 and h.get("www-authenticate", "").startswith("Digest") else "FAIL",
             "HTTPS: the web UI over https asks for Digest", str(st))


def lockout_check(r, host, admin):
    codes = [http(host, "GET", "/snapshot.jpg", auth=("gate3-nobody", f"wrong-{i}"))[0] for i in range(5)]
    st = http(host, "GET", "/snapshot.jpg", auth=admin)[0]
    r.result("PASS" if st == 401 else "FAIL", "§2 camhttpd lockout after 5 failures from one address",
             f"wrong {codes}, then the admin {st} (want 401 while locked)")
    print("waiting 65 s for the lockout to end", flush=True)
    time.sleep(65)
    st = http(host, "GET", "/snapshot.jpg", auth=admin)[0]
    r.result("PASS" if st == 200 else "FAIL", "§2 camhttpd lockout ends after a minute", str(st))


def wsd_checks(r, host, sec):
    me = None
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.connect((host, 3702))
        me = t.getsockname()[0]
        t.close()
    except OSError:
        pass
    same = None
    if sec:
        m = re.search(r"inet addr:([\d.]+).*Mask:([\d.]+)", " ".join(sec.get("ifconfig", [])))
        if m and me:
            a, mask, b = (int.from_bytes(socket.inet_aton(x), "big") for x in (m.group(1), m.group(2), me))
            same = (a & mask) == (b & mask)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    s.settimeout(0.3)

    def probe(n):
        for _ in range(n):
            s.sendto(PROBE.format(uuid.uuid4()).encode(), (host, 3702))
        got, end = [], time.time() + 2.5
        while time.time() < end:
            try:
                got.append(s.recvfrom(65536)[0])
            except socket.timeout:
                pass
        return got
    one = probe(1)
    time.sleep(1.5)
    burst = probe(10)
    s.close()
    req = len(PROBE.format(uuid.uuid4()))
    r.save("wsd.txt", f"this machine {me}, same subnet {same}\n--- one probe: {len(one)} replies\n"
           + "\n".join(x.decode(errors="replace") for x in one)
           + f"\n--- burst of 10: {len(burst)} replies\n")
    if same is False:
        r.result("PASS" if not one and not burst else "FAIL", "§1 WS-Discovery ignores other subnets",
                 f"{len(one)}+{len(burst)} replies to a probe from {me}")
        return
    r.result("PASS" if len(one) == 1 else "FAIL", "§1 WS-Discovery: one reply per probe", f"{len(one)} replies")
    r.result("PASS" if len(burst) <= 2 else "FAIL", "§1 WS-Discovery rate limit (burst of 10 probes)",
             f"{len(burst)} replies")
    if one:
        ratio = len(one[0]) / req
        r.result("PASS" if ratio < 4 else "WARN", "§1 WS-Discovery amplification", f"{len(one[0])}/{req} bytes = {ratio:.1f}x")
        epr = re.search(rb"<[\w:]*Address>(urn:uuid:[^<]+)<", one[0])
        leak = r.mac and r.mac.replace(":", "") in one[0].decode(errors="replace").lower().replace(":", "")
        r.result("PASS" if epr and not leak else "FAIL", "§6 WS-Discovery EndpointReference is a hash",
                 (epr.group(1).decode() if epr else "none") + (", MAC present" if leak else ""))


def sshsig_reserved(armor, n):
    """The same SSHSIG (trusted key, real signature) with n bytes in its reserved field, which
    OpenSSH leaves empty: camupdate before the Gate 3 fix copied it unbounded onto its stack."""
    lines = armor.decode().strip().splitlines()
    blob = base64.b64decode("".join(lines[1:-1]))
    o, f = 10, []                                       # "SSHSIG", u32 version
    for _ in range(5):                                  # pk, namespace, reserved, hash alg, signature
        ln = struct.unpack(">I", blob[o:o + 4])[0]
        f.append(blob[o + 4:o + 4 + ln])
        o += 4 + ln
    f[2] = b"A" * n
    out = blob[:10] + b"".join(struct.pack(">I", len(x)) + x for x in f)
    b64 = base64.b64encode(out).decode()
    return ("\n".join([lines[0]] + [b64[i:i + 70] for i in range(0, len(b64), 70)] + [lines[-1]]) + "\n").encode()


def camfw_variants(src, tmp):
    data = open(src, "rb").read()
    i = data.find(b"-----BEGIN SSH SIGNATURE-----")
    j = data.find(b"-----END SSH SIGNATURE-----\n")
    if i < 0 or j < 0:
        raise SystemExit(f"{src}: no SSH signature block; is it a .camfw?")
    hdr, sig, pay = data[:i], data[i:j + 28], data[j + 28:]
    v = {}
    h2 = re.sub(rb"version=(\d{8})\.\d+", rb"version=\g<1>.999", hdr)
    v["header tampered (version raised)"] = h2 + sig + pay
    p2 = bytearray(pay)
    p2[len(p2) // 2] ^= 0x01
    v["payload tampered (one bit)"] = hdr + sig + bytes(p2)
    v["payload truncated"] = hdr + sig + pay[:len(pay) // 2]
    v["bytes appended after the payload"] = hdr + sig + pay + b"\0" * 4096
    v["unsigned (no signature)"] = hdr + pay
    v["SSHSIG reserved field filled (the Gate 3 overflow)"] = hdr + sshsig_reserved(sig, 2000) + pay
    key, hf = os.path.join(tmp, "stranger"), os.path.join(tmp, "hdr")
    for f in (key, key + ".pub", hf + ".sig"):          # ssh-keygen would ask before overwriting
        if os.path.exists(f):
            os.unlink(f)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "gate3 stranger", "-f", key], check=True,
                   stdin=subprocess.DEVNULL)
    open(hf, "wb").write(h2)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", "cam-firmware", hf], check=True,
                   capture_output=True, stdin=subprocess.DEVNULL)
    v["signed by another key (version raised)"] = h2 + open(hf + ".sig", "rb").read() + pay
    return v


FIXED_IN = (20261024, 3)        # the first release with the Gate 3 camupdate fixes (assumed: .3)


def vtuple(v):
    m = re.fullmatch(r"(\d{8})\.(\d+)", v.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def camupdate_checks(r, ssh, files, tmp, installed=None):
    log = []
    for f in files:
        rc, out, err = ssh.run("camupdate --check -", data=open(f, "rb").read(), timeout=300)
        log.append(f"--- {os.path.basename(f)}: exit {rc}\n{out}{err}")
        r.result("PASS" if rc != 0 and "REFUSED" in (out + err) else "FAIL",
                 f"§4 camupdate refuses {os.path.basename(f)} (not newer than installed)",
                 (out + err).strip().splitlines()[-1][:200] if (out + err).strip() else f"exit {rc}")
    for name, data in camfw_variants(files[0], tmp).items():
        if "reserved field" in name and (vtuple(installed or "") or (0, 0)) < FIXED_IN:
            r.result("INFO", f"§4 camupdate: {name}", f"not sent: {installed or 'unknown version'}'s camupdate "
                     "predates the fix (it would crash on it); run again on the fixed release")
            continue
        rc, out, err = ssh.run("camupdate --check -", data=data, timeout=300)
        log.append(f"--- {name}: exit {rc}\n{out}{err}")
        msg = (out + err).strip().splitlines()[-1][:200] if (out + err).strip() else f"exit {rc}"
        r.result("PASS" if rc != 0 and "OK:" not in out + err else "FAIL", f"§4 camupdate refuses: {name}", msg)
    r.save("camupdate.txt", "\n".join(log))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("host")
    ap.add_argument("--admin", required=True)
    ap.add_argument("--viewer")
    ap.add_argument("--operator")
    ap.add_argument("--camfw", nargs="*", default=[], help="owner-signed packages no newer than the installed one")
    ap.add_argument("--lockout", action="store_true", help="lock this machine out of camhttpd for a minute")
    ap.add_argument("--udp", action="store_true", help="also nmap -sU --top-ports 200 (sudo)")
    ap.add_argument("--skip-nmap", action="store_true", help="skip the full port scans (the SSH algorithm scan stays)")
    ap.add_argument("--only", help="comma list of: ssh,nmap,rtsp,onvif,wsd,camupdate,lockout,tls "
                    "(the camera-side checks always run)")
    ap.add_argument("--cam-net", help="the camera subnet the image was built for (default: CAM_NET or "
                    "cam-net.local, as scripts/cam-net.sh reads it)")
    a = ap.parse_args()
    global CAM_NET
    try:
        CAM_NET = ipaddress.ip_network(a.cam_net or cam_net_setting() or "")
    except ValueError as e:
        sys.exit(f"CAM_NET: the camera subnet (A.B.C.D/PREFIX), from --cam-net, CAM_NET or cam-net.local: {e}")
    parts = {"ssh", "nmap", "rtsp", "onvif", "wsd", "camupdate", "lockout", "tls"}
    only = set(a.only.split(",")) if a.only else parts
    if only - parts:
        sys.exit(f"--only: unknown {', '.join(sorted(only - parts))}")

    def want(part):
        return part in only
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", a.host):
        sys.exit("HOST: the camera's IPv4 address")
    admin = (a.admin, getpass.getpass(f"password for {a.admin}: "))
    others = {}
    for role in ("viewer", "operator"):
        if getattr(a, role):
            others[role] = (getattr(a, role), getpass.getpass(f"password for {getattr(a, role)} ({role}): "))
    now = datetime.datetime.now(datetime.timezone.utc)
    day, run = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    out = os.path.join(root, "bench-logs", f"gate3-{day}", a.host, run)     # one folder per run
    os.makedirs(out, exist_ok=True)
    r = Run(out)
    tmp = tempfile.mkdtemp(prefix="gate3-")
    ssh = Ssh(a.host, os.path.join(tmp, "ctl"))
    print(f"evidence: {out}\nSSH to root@{a.host}: touch your key when it blinks", flush=True)
    try:
        sec = camera_side(r, ssh)                       # always: the version, the MAC to redact
        if want("ssh"):
            ssh_checks(r, a.host, ssh)
        if want("nmap"):
            nmap_checks(r, a.host, a.udp, full=not a.skip_nmap, want_tcp=tcp_ok(sec))
        if want("rtsp"):
            rtsp_checks(r, a.host, admin)
        if want("onvif"):
            onvif_checks(r, a.host, admin, others, ui_tls=tls_state(sec)[0])
        if want("wsd"):
            wsd_checks(r, a.host, sec)
        if want("camupdate") and a.camfw:
            camupdate_checks(r, ssh, a.camfw, tmp, " ".join(sec["version"]) if sec else None)
        elif want("camupdate"):
            r.result("INFO", "§4 camupdate", "no --camfw given: skipped")
        if a.lockout and want("lockout"):
            lockout_check(r, a.host, admin)
        if want("tls"):
            tls_checks(r, a.host, sec)
    finally:
        ssh.close()
        shutil.rmtree(tmp, ignore_errors=True)
        admin = others = None
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        r.save("summary.txt", f"gate3-live {a.host} {stamp}\n" + "\n".join(r.lines) + "\n")
    fails = sum(ln.startswith("FAIL") for ln in r.lines)
    warns = sum(ln.startswith("WARN") for ln in r.lines)
    print(f"\n{fails} FAIL, {warns} WARN; evidence in {out}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
