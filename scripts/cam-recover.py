#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unlock a camera whose DATA failed (#177, docs/PLAN-DATA-LOCK.md Part 3): restore a settings
backup, or erase DATA, signed with one of the image's update keys.

  python3 scripts/cam-recover.py HOST --backup FILE.cambak --key ~/.ssh/KEY [--pin SHA256]
  python3 scripts/cam-recover.py HOST --erase --key ~/.ssh/KEY
  python3 scripts/cam-recover.py HOST (--backup FILE | --erase) --print-message > msg
      (sign elsewhere: ssh-keygen -Y sign -n cam-recover -f KEY msg, then)
  python3 scripts/cam-recover.py HOST (--backup FILE | --erase) --signature msg.sig

A locked camera serves only its lock page. Its one-time challenge (GET /unlock/challenge: the
challenge, the camera's device ID and firmware; 10 minutes, replaced after every attempt) goes into
the message the key signs, with the action and, for a restore, the backup file's SHA-256:

  cam-recover 1 / challenge HEX / device ID / firmware VERSION / action restore|erase /
  backup SHA256|none                      (one line each, "\\n" after every line)

The script signs it with `ssh-keygen -Y sign -n cam-recover` (a YubiKey asks for its touch and
PIN), asks for the backup's passphrase (never echoed), and POSTs to /unlock: the passphrase line,
the signature, then the backup, as the raw body (the action and challenge in X-Unlock-Action and
X-Unlock-Challenge). The camera checks it all with `camcfg unlock` before DATA is erased, then
reboots. Its certificate is a throwaway one in lock mode (the real CA was on DATA), so the
connection can't be verified: the script prints its fingerprint, and --pin requires one. Recover
on the camera network only you use, or a direct cable: someone on the path could read the
passphrase (they couldn't change the signed backup or action). Standard library and ssh-keygen.
"""
import argparse
import getpass
import hashlib
import http.client
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile

NS = "cam-recover"
HEX64 = re.compile(r"[0-9a-f]{64}")
DEVICE = re.compile(r"[0-9a-f]{32}")
FIRMWARE = re.compile(r"[A-Za-z0-9._+-]{1,32}")
SIG_BEGIN = "-----BEGIN SSH SIGNATURE-----"
SIG_END = "-----END SSH SIGNATURE-----"
BACKUP_MAX = 1024 * 1024
PP_MIN, PP_MAX = 12, 256


class RecoverError(Exception):
    pass


def parse_challenge(text):
    """The challenge page's lines "challenge HEX", "device ID", "firmware VERSION" (others
    ignored) as a dict; RecoverError if one is missing or malformed."""
    got = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k in ("challenge", "device", "firmware"):
            got[k] = v
    for k, rx in (("challenge", HEX64), ("device", DEVICE), ("firmware", FIRMWARE)):
        if not rx.fullmatch(got.get(k, "")):
            raise RecoverError(f"the camera's challenge page has no valid {k} (is it locked?)")
    return got


def message(ch, action, backup_sha):
    """The bytes the update key signs (camcfg's recover_msg)."""
    if action not in ("restore", "erase"):
        raise ValueError(action)
    return (f"cam-recover 1\nchallenge {ch['challenge']}\ndevice {ch['device']}\nfirmware {ch['firmware']}\n"
            f"action {action}\nbackup {backup_sha or 'none'}\n").encode()


def read_backup(path):
    """The .cambak file's bytes, checked to look like one."""
    try:
        with open(path, "rb") as f:
            b = f.read(BACKUP_MAX + 1)
    except OSError as e:
        raise RecoverError(f"{path}: {e.strerror}") from None
    if len(b) > BACKUP_MAX or not b.startswith(b"cam-backup "):
        raise RecoverError(f"{path}: not a camera backup (.cambak)")
    return b


def check_signature(text):
    """An armored SSH signature, normalised to its lines with a final newline."""
    lines = [l.strip() for l in text.strip().splitlines()]
    if len(lines) < 3 or lines[0] != SIG_BEGIN or lines[-1] != SIG_END or len(lines) > 64:
        raise RecoverError("not an armored SSH signature (-----BEGIN SSH SIGNATURE----- ... END)")
    return "\n".join(lines) + "\n"


def passphrase_problem(pp):
    if len(pp.encode()) < PP_MIN:
        return "the passphrase has at least 12 characters"
    if len(pp.encode()) > PP_MAX:
        return "the passphrase has at most 256 bytes"
    if any(ord(c) < 32 or ord(c) == 127 for c in pp):
        return "the passphrase has no control characters"
    return None


def body(action, passphrase, signature, backup):
    """POST /unlock's body: camcfg unlock's stdin."""
    out = b""
    if action == "restore":
        out += passphrase.encode() + b"\n"
    out += signature.encode()
    if action == "restore":
        out += backup
    return out


def sign(key, msg, keygen="ssh-keygen"):
    """ssh-keygen -Y sign -n cam-recover over msg with KEY (its touch/PIN prompts on the terminal)."""
    with tempfile.TemporaryDirectory() as d:
        m = os.path.join(d, "msg")
        with open(m, "wb") as f:
            f.write(msg)
        r = subprocess.run([keygen, "-Y", "sign", "-n", NS, "-f", key, m])
        if r.returncode:
            raise RecoverError(f"ssh-keygen couldn't sign (exit {r.returncode})")
        with open(m + ".sig") as f:
            return check_signature(f.read())


def norm_pin(pin):
    p = re.sub(r"[:\s]", "", pin or "").lower()
    return p if HEX64.fullmatch(p) else None


def resolve_ipv4(host):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise RecoverError(f"{host}: {e}") from None
    if not infos:
        raise RecoverError(f"{host}: no IPv4 address")
    return infos[0][4][0]


def tls_context():
    """Lock mode's certificate comes from a throwaway CA: no chain check; fingerprint shown/pinned."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def request(ip, port, method, path, headers=None, data=None, pin=None, timeout=120):
    """(status, text, certificate fingerprint); a certificate other than pin is refused first."""
    conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=tls_context())
    try:
        conn.connect()
        fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if pin and fp != pin:
            raise RecoverError(f"{ip}:{port}: the certificate's SHA-256 is {fp}, not the pinned {pin}: nothing sent")
        conn.request(method, path, body=data, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read(64 * 1024).decode("utf-8", "replace"), fp
    except ssl.SSLError as e:
        raise RecoverError(f"{ip}:{port}: TLS: {e.reason or e}") from None
    except OSError as e:
        raise RecoverError(f"{ip}:{port}: {e}") from None
    finally:
        conn.close()


def parse_args(argv):
    ap = argparse.ArgumentParser(description="Restore or erase a locked camera's DATA, signed with an "
                                 "update key (docs/PLAN-DATA-LOCK.md)")
    ap.add_argument("host", help="the camera's address or name")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--pin", help="require this SHA-256 fingerprint of the camera's (lock-mode) certificate")
    act = ap.add_mutually_exclusive_group(required=True)
    act.add_argument("--backup", help="restore this .cambak (made by this camera)")
    act.add_argument("--erase", action="store_true", help="erase DATA; claim the camera afresh after")
    how = ap.add_mutually_exclusive_group(required=True)
    how.add_argument("--key", help="the update key to sign with (OpenSSH private key or sk key handle)")
    how.add_argument("--print-message", action="store_true", help="print the message to sign, and stop")
    how.add_argument("--signature", help="a signature made elsewhere (ssh-keygen -Y sign -n cam-recover)")
    a = ap.parse_args(argv)
    if a.pin is not None and not norm_pin(a.pin):
        ap.error("--pin: a SHA-256 fingerprint (64 hex digits; colons and case don't matter)")
    a.pin = norm_pin(a.pin) if a.pin else None
    return a


def main(argv=None):
    a = parse_args(argv)
    try:
        action = "erase" if a.erase else "restore"
        backup = read_backup(a.backup) if a.backup else b""
        sha = hashlib.sha256(backup).hexdigest() if a.backup else None
        ip = resolve_ipv4(a.host)
        st, text, fp = request(ip, a.port, "GET", "/unlock/challenge", pin=a.pin)
        print(f"camera {ip}: certificate SHA-256 {fp} (lock mode: a throwaway certificate)", file=sys.stderr)
        if st != 200:
            raise RecoverError(f"GET /unlock/challenge: HTTP {st}: {text.strip()[:200]} (is the camera locked?)")
        ch = parse_challenge(text)
        msg = message(ch, action, sha)
        if a.print_message:
            sys.stdout.write(msg.decode())
            print(f"sign it: ssh-keygen -Y sign -n {NS} -f KEY FILE; then --signature FILE.sig "
                  "within 10 minutes", file=sys.stderr)
            return 0
        if a.signature:
            with open(a.signature) as f:
                sig = check_signature(f.read())
        else:
            print(f"signing {action} for device {ch['device']} with {a.key}", file=sys.stderr)
            sig = sign(a.key, msg)
        pp = ""
        if action == "restore":
            pp = getpass.getpass("backup passphrase: ")
            why = passphrase_problem(pp)
            if why:
                raise RecoverError(why)
        headers = {"Content-Type": "application/octet-stream", "X-Unlock-Action": action,
                   "X-Unlock-Challenge": ch["challenge"], "Origin": f"https://{ip}" if a.port == 443
                   else f"https://{ip}:{a.port}"}
        st, text, _ = request(ip, a.port, "POST", "/unlock", headers, body(action, pp, sig, backup),
                              pin=fp)
        print(text.strip())
        if st != 200:
            return 1
        print("the camera reboots now" + (": claim it afresh" if a.erase else ""), file=sys.stderr)
        return 0
    except RecoverError as e:
        print(f"cam-recover: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
