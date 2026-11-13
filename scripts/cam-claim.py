#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Claim a freshly flashed camera over HTTPS (#128, docs/CLAIM.md, docs/PLAN-TLS.md §B): its first
admin, an optional SSH public key, and the recovery code saved on this machine.

  python3 scripts/cam-claim.py HOST [--pin SHA256] [--port N] [--name NAME] [--key FILE.pub | --no-key]
  python3 scripts/cam-claim.py HOST --http ...     (a camera whose HTTPS (camtls) isn't running)
  python3 scripts/cam-claim.py HOST --backup FILE ...   (claim, then download a first backup)
  python3 scripts/cam-claim.py HOST --restore FILE [--pin SHA256]   (restore this camera's backup
                                                                     instead of claiming it)

An unclaimed camera serves only /setup, for the first 30 minutes after power-on: over HTTPS once
camtls is ready (then port 80 sends browsers there and refuses a POST), else over plain HTTP. The
camera makes its own certificate, which this machine can't check yet (its CA is trusted after the
claim), so the script prints the certificate's SHA-256 fingerprint; --pin requires that
fingerprint (hex, colons and case don't matter), and the form is only posted to the certificate
the form came from. This script does what the setup page does:
  - asks for the admin name and the password (twice, never echoed), checked against camcfg's rules
    before anything is sent;
  - offers the public keys in ~/.ssh/*.pub to choose from (or --key, or --no-key). Only a .pub file
    holding one public key line is read; anything that looks like a private key is refused;
  - fetches /setup's form token and posts the form to the camera's IPv4 address (the camera only
    answers setup at its own address, against DNS rebinding), with Origin https://<IP>;
  - prints the recovery code once and saves it to
    ~/.config/cam-firmware-dev/recovery-<HOST>.txt (mode 0600, folder 0700). The code resets an
    admin password at https://HOST/recover within 30 minutes after a power-on; using it replaces it.
  - --backup FILE (#173, docs/PLAN-DATA-LOCK.md): then logs in as the new admin (HTTP Digest) and
    downloads a first settings backup into FILE (0600, never over an existing file), as the
    System page's form does; asks for its passphrase twice (12..256 bytes, never echoed). HTTPS
    only. The file and its passphrase together give every password and the camera's CA key.
  - --restore FILE: instead of a claim, uploads this camera's own backup to /setup/restore with its
    passphrase (asked once); the camera checks it, restores it and reboots, claimed again with the
    backup's accounts. Wrong passphrases count as failed logins.
Claim on a network only you use: until it is claimed, anyone who reaches the camera can claim it.
Standard library only. The password is never printed, logged or saved.
"""
import argparse
import datetime
import secrets
import getpass
import glob
import hashlib
import html
import http.client
import os
import re
import socket
import ssl
import sys
import urllib.parse

NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
KEY_RE = re.compile(r"(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|"
                    r"sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,2}( [ -~]*)?")
TOKEN_RE = re.compile(r'name="csrf" value="([0-9a-f]{40})"')
RESTORE_MAX = 48 * 1024                 # camhttpd's limit for a backup restored over the web (BK_UP_MAX)
CHAL_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,]+))')
CODE_RE = re.compile(r'<p class="code" id="code">([A-Z2-7-]{26,39})</p>')
ERR_RE = re.compile(r'<p class="msg err">(.*?)</p>', re.S)
CONF_DIR = os.path.expanduser("~/.config/cam-firmware-dev")
PIN_RE = re.compile(r"[0-9a-f]{64}")


class ClaimError(Exception):
    pass


def name_problem(user):
    """None if camcfg takes the user name, else the reason (camcfg's valid_name)."""
    return None if NAME_RE.fullmatch(user) else "user names: 1-32 of A-Z a-z 0-9 . _ -"


def password_problem(user, pw):
    """None if camcfg takes the password, else its reason (camcfg's pw_check, same order; kept in
    step with scripts/rtsp-passwd.py, which scripts/test_cam_claim.py checks)."""
    if any(not 0x20 <= ord(c) <= 0x7E for c in pw):
        return "password: letters, digits, symbols and spaces only (ASCII)"
    if pw and (pw[0] == " " or pw[-1] == " "):
        return "password must not start or end with a space"
    if len(pw) < 8:
        return "password must be at least 8 characters"
    if len(pw) > 64:
        return "password must be at most 64 characters (a longer one is never shortened)"
    if pw.lower() == user.lower():
        return "password must not be the user name"
    return None


def key_line(path):
    """The one public key line in a .pub file, or ClaimError. Never reads anything but *.pub."""
    if not path.endswith(".pub"):
        raise ClaimError(f"{path}: only a .pub file is read (never a private key)")
    with open(path, "rb") as f:
        data = f.read(8192)
    if b"PRIVATE KEY" in data:
        raise ClaimError(f"{path}: this looks like a private key: refused")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ClaimError(f"{path}: not a public key file (non-ASCII)") from None
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if len(lines) != 1:
        raise ClaimError(f"{path}: want exactly one key line, found {len(lines)}")
    line = lines[0]
    if len(line) >= 2048 or not KEY_RE.fullmatch(line):
        raise ClaimError(f"{path}: not a key the camera takes (ssh-ed25519, sk-ssh-ed25519, "
                         "ecdsa-sha2-nistp256, sk-ecdsa-sha2-nistp256 or ssh-rsa, no options)")
    return line


def list_pubkeys(ssh_dir):
    return sorted(glob.glob(os.path.join(ssh_dir, "*.pub")))


def resolve_ipv4(host):
    """HOST's first IPv4 address (an IPv4 literal is returned as is)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ClaimError(f"{host}: {e}") from None
    if not infos:
        raise ClaimError(f"{host}: no IPv4 address")
    return infos[0][4][0]


def safe_name(host):
    """HOST as a file name part: anything outside A-Z a-z 0-9 . _ - becomes _."""
    s = re.sub(r"[^A-Za-z0-9._-]", "_", host).strip(".")
    return s or "camera"


def parse_token(page):
    m = TOKEN_RE.search(page)
    return m.group(1) if m else None


def parse_code(page):
    m = CODE_RE.search(page)
    return m.group(1) if m else None


def parse_error(page):
    m = ERR_RE.search(page)
    return html.unescape(re.sub(r"<[^>]*>", "", m.group(1))).strip() if m else None


def form_body(token, name, pw, key):
    return urllib.parse.urlencode({"csrf": token, "name": name, "pw": pw, "pw2": pw, "key": key or ""})


def passphrase_problem(pp):
    """None if camcfg takes the backup passphrase, else its reason (camcfg's read_pp)."""
    b = pp.encode("utf-8")
    if len(b) > 256:
        return "passphrase: at most 256 bytes, on one line"
    if len(b) < 12:
        return "passphrase: at least 12 characters (the file holds the passwords and the CA key)"
    if any(c < 0x20 or c == 0x7F for c in b):
        return "passphrase: no control characters"
    return None


def parse_challenge(value):
    """A Digest challenge (WWW-Authenticate) as a dict of its parameters, or None."""
    if not value or not value.lower().startswith("digest "):
        return None
    return {k.lower(): q if q else t for k, q, t in CHAL_RE.findall(value[7:])}


def digest_header(user, pw, method, uri, chal, nc, cnonce):
    """The Authorization header for a Digest challenge (RFC 2617, MD5, qop=auth)."""
    md5 = lambda s: hashlib.md5(s.encode("utf-8")).hexdigest()   # noqa: E731
    ncs = f"{nc:08x}"
    ha1 = md5(f"{user}:{chal['realm']}:{pw}")
    ha2 = md5(f"{method}:{uri}")
    resp = md5(f"{ha1}:{chal['nonce']}:{ncs}:{cnonce}:auth:{ha2}")
    return (f'Digest username="{user}", realm="{chal["realm"]}", nonce="{chal["nonce"]}", uri="{uri}", '
            f'algorithm=MD5, qop=auth, nc={ncs}, cnonce="{cnonce}", response="{resp}"')


def multipart(fields, file_bytes, boundary=None):
    """(content type, body) of a multipart/form-data form: text fields, then the file as "file"."""
    while boundary is None or boundary.encode() in file_bytes:
        boundary = "camclaim" + secrets.token_hex(16)
    parts = []
    for k, v in fields:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
                     + v.encode("utf-8") + b"\r\n")
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="backup.cambak"\r\n'
                 "Content-Type: application/octet-stream\r\n\r\n".encode() + file_bytes + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", b"".join(parts)


def save_backup(path, data):
    """data into a new file at path, 0600; an existing file is never replaced (ClaimError)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ClaimError(f"{path} exists: choose another name (a backup is never written over)") from None
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def norm_pin(pin):
    """A SHA-256 fingerprint as 64 lowercase hex digits (colons, spaces and case dropped), or None."""
    p = re.sub(r"[:\s]", "", pin or "").lower()
    return p if PIN_RE.fullmatch(p) else None


def fingerprint(der):
    return hashlib.sha256(der).hexdigest()


def base_url(ip, port, tls):
    """The scheme, address and port as the camera expects them in Origin (the port only if not the
    scheme's own)."""
    scheme = "https" if tls else "http"
    return f"{scheme}://{ip}" if port == (443 if tls else 80) else f"{scheme}://{ip}:{port}"


def save_code(conf_dir, host, ip, name, code, now=None):
    """Write the recovery code to conf_dir/recovery-<host>.txt, 0600 (folder 0700). The path."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    os.makedirs(conf_dir, mode=0o700, exist_ok=True)
    os.chmod(conf_dir, 0o700)
    path = os.path.join(conf_dir, f"recovery-{safe_name(host)}.txt")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# cam-firmware-dev camera recovery code (#128, docs/CLAIM.md): keep it private\n"
                f"camera: {host} ({ip})\nadmin: {name}\n"
                f"claimed: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}\nrecovery-code: {code}\n"
                f"use: https://{ip}/recover (http:// while its HTTPS isn't running) within 30 minutes "
                "after a power-on; it is replaced on use\n")
    return path


def parse_args(argv):
    ap = argparse.ArgumentParser(description="Claim a freshly flashed camera (first admin, SSH key, "
                                 "recovery code).")
    ap.add_argument("host", help="the camera's address or name")
    ap.add_argument("--port", type=int, help="default 443 (80 with --http)")
    ap.add_argument("--http", action="store_true",
                    help="plain HTTP: only for a camera whose HTTPS (camtls) isn't running")
    ap.add_argument("--pin", help="require this SHA-256 fingerprint of the camera's TLS certificate")
    ap.add_argument("--name", help="admin name (asked if not given; default admin)")
    k = ap.add_mutually_exclusive_group()
    k.add_argument("--key", help="an SSH public key file (*.pub) to add")
    k.add_argument("--no-key", action="store_true", help="add no SSH key (SSH stays off)")
    b = ap.add_mutually_exclusive_group()
    b.add_argument("--backup", metavar="FILE", help="after the claim, download a first settings backup into FILE")
    b.add_argument("--restore", metavar="FILE", help="restore this camera's backup instead of claiming it")
    a = ap.parse_args(argv)
    if a.backup and a.http:
        ap.error("--backup needs HTTPS: not with --http")
    if a.restore and (a.name or a.key or a.no_key):
        ap.error("--restore takes no --name, --key or --no-key: the backup holds the accounts and keys")
    if a.port is None:
        a.port = 80 if a.http else 443
    if not 1 <= a.port <= 65535:
        ap.error("--port: 1..65535")
    if a.pin is not None:
        if a.http:
            ap.error("--pin is for HTTPS: not with --http")
        if not norm_pin(a.pin):
            ap.error("--pin: a SHA-256 fingerprint, 64 hex digits (colons allowed)")
        a.pin = norm_pin(a.pin)
    return a


def choose_key(a):
    if a.no_key:
        return None
    if a.key:
        return key_line(a.key)
    keys = list_pubkeys(os.path.expanduser("~/.ssh"))
    if not keys:
        print("no ~/.ssh/*.pub: no SSH key (an admin can add one later on the SSH keys page)")
        return None
    print("SSH public key to add (root login over SSH):")
    for i, p in enumerate(keys, 1):
        print(f"  [{i}] {p}")
    while True:
        ans = input("number, or Enter for none: ").strip()
        if not ans:
            return None
        if ans.isdigit() and 1 <= int(ans) <= len(keys):
            try:
                return key_line(keys[int(ans) - 1])
            except ClaimError as e:
                print(e)
        else:
            print("pick one of the numbers")


def tls_context():
    """The camera's certificate is its own CA's, which this machine doesn't trust yet: no chain
    check here; the fingerprint is shown, and pinned (--pin, and from the GET to the POST)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def request(ip, port, method, path, body=None, tls=True, pin=None):
    """(status, page, the certificate's fingerprint or None). With tls and pin, a certificate
    whose fingerprint isn't pin is refused before anything is sent."""
    headers = {}
    if body is not None:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    status, _, data, fp = request_raw(ip, port, method, path, body, headers, tls, pin)
    return status, data.decode("utf-8", "replace"), fp


def request_raw(ip, port, method, path, body=None, headers=None, tls=True, pin=None, limit=256 * 1024):
    """(status, the response's headers (lower-case names), its bytes (at most limit), the
    certificate's fingerprint or None). A body goes with Origin <scheme>://<IP>. With tls and pin,
    a certificate whose fingerprint isn't pin is refused before anything is sent."""
    if tls:
        conn = http.client.HTTPSConnection(ip, port, timeout=60, context=tls_context())
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=60)
    headers = dict(headers or {})
    if body is not None:
        headers["Origin"] = base_url(ip, port, tls)
    try:
        conn.connect()
        fp = fingerprint(conn.sock.getpeercert(binary_form=True)) if tls else None
        if pin and fp != pin:
            raise ClaimError(f"{ip}:{port}: the TLS certificate's SHA-256 is {fp}, not the pinned {pin}: "
                             "nothing sent")
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(limit), fp
    except ssl.SSLError as e:
        raise ClaimError(f"{ip}:{port}: TLS: {e.reason or e} (is the camera's HTTPS running? --http "
                         "claims one without it)") from None
    except OSError as e:
        hint = " (no HTTPS there? --http claims a camera whose camtls isn't running)" if tls else ""
        raise ClaimError(f"{ip}:{port}: {e}{hint}") from None
    finally:
        conn.close()


def download_backup(ip, port, pin, user, pw, pp, path):
    """Log in as user (Digest), take the System page's form token and post its backup form; the
    .cambak goes to path. HTTPS only, to the pinned certificate."""
    sys_path = "/ui/system"
    st, hd, _, _ = request_raw(ip, port, "GET", sys_path, pin=pin)
    chal = parse_challenge(hd.get("www-authenticate"))
    if st != 401 or not chal or "nonce" not in chal or "realm" not in chal:
        raise ClaimError(f"GET {sys_path} gave {st}, not a login challenge")
    cnonce = secrets.token_hex(8)
    st, _, page, _ = request_raw(ip, port, "GET", sys_path, pin=pin,
                                 headers={"Authorization": digest_header(user, pw, "GET", sys_path, chal, 1, cnonce)})
    token = parse_token(page.decode("utf-8", "replace")) if st == 200 else None
    if not token:
        raise ClaimError(f"GET {sys_path} as {user} gave {st}, not the System page")
    body = urllib.parse.urlencode({"csrf": token, "do": "backup", "pp": pp, "pp2": pp})
    st, hd, data, _ = request_raw(ip, port, "POST", sys_path, body, pin=pin, limit=2 * 1024 * 1024, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": digest_header(user, pw, "POST", sys_path, chal, 2, cnonce)})
    if st != 200 or not hd.get("content-type", "").startswith("application/octet-stream"):
        page = data.decode("utf-8", "replace")
        raise ClaimError(f"backup refused ({st}): {parse_error(page) or page.strip()[:200]}")
    if not data.startswith(b"cam-backup 1\n"):
        raise ClaimError("the camera sent something that isn't a backup")
    save_backup(path, data)
    return len(data)


def restore(a, ip):
    """--restore FILE at /setup/restore: this camera's own backup in place of a claim."""
    with open(a.restore, "rb") as f:
        data = f.read(RESTORE_MAX + 1)
    if len(data) > RESTORE_MAX:
        raise ClaimError(f"{a.restore}: over {RESTORE_MAX // 1024} KiB: restore it over SSH (camcfg backup import)")
    if not data.startswith(b"cam-backup 1\n"):
        raise ClaimError(f"{a.restore}: not a camera backup (.cambak)")
    tls = not a.http
    status, page, fp = request(ip, a.port, "GET", "/setup", tls=tls, pin=a.pin)
    if tls:
        print(f"{ip}:{a.port} TLS certificate SHA-256: {fp}" + (" (pinned)" if a.pin else " (not checked)"))
    token = parse_token(page) if status == 200 else None
    if not token:
        raise ClaimError(f"{a.host} ({ip}): GET /setup gave {status}, not the setup form (claimed already, "
                         "or setup closed: power-cycle it)")
    pp = getpass.getpass("the backup's passphrase: ")
    why = passphrase_problem(pp)
    if why:
        raise ClaimError(why)
    ctype, body = multipart([("csrf", token), ("pp", pp)], data)
    pp = None
    status, _, out, _ = request_raw(ip, a.port, "POST", "/setup/restore", body, {"Content-Type": ctype},
                                    tls=tls, pin=fp)
    page = out.decode("utf-8", "replace")
    if status != 200 or "<h1>Restored</h1>" not in page:
        raise ClaimError(f"restore refused ({status}): {parse_error(page) or page.strip()[:200]}")
    print(f"{a.host} ({ip}) restored from {a.restore}: it reboots now and is back in about a minute; "
          "log in with the backup's admin")
    return 0


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    ip = resolve_ipv4(a.host)
    if a.restore:
        return restore(a, ip)
    if a.backup and os.path.exists(a.backup):
        raise ClaimError(f"{a.backup} exists: choose another name (a backup is never written over)")
    tls = not a.http
    status, page, fp = request(ip, a.port, "GET", "/setup", tls=tls, pin=a.pin)
    if tls:
        print(f"{ip}:{a.port} TLS certificate SHA-256: {fp}" + (" (pinned)" if a.pin else
              " (not checked: --pin requires one; once claimed, compare it with fp= in "
              "`camcfg tls show` over SSH)"))
    if status in (301, 302, 303, 307, 308) and not tls:
        raise ClaimError(f"{a.host} ({ip}): port {a.port} sends /setup to HTTPS: its camtls is running, "
                         "so claim without --http")
    if status == 404:
        raise ClaimError(f"{a.host} ({ip}) is already claimed (no /setup)")
    if status == 503 and "setup is closed" in page:
        raise ClaimError(f"{a.host} ({ip}): setup is closed. Power-cycle the camera and run this again "
                         "within 30 minutes")
    token = parse_token(page) if status == 200 else None
    if not token:
        raise ClaimError(f"{a.host} ({ip}): GET /setup gave {status}, not the setup form")
    print(f"{a.host} ({ip}) is unclaimed. Claim it only on a network you trust."
          + ("" if tls else " Plain HTTP: the password crosses the network readable."))
    name = a.name or input("admin name [admin]: ").strip() or "admin"
    why = name_problem(name)
    if why:
        raise ClaimError(why)
    pw = getpass.getpass(f"password for {name}: ")
    if pw != getpass.getpass("again: "):
        raise ClaimError("the passwords differ")
    why = password_problem(name, pw)
    if why:
        raise ClaimError(why)
    key = choose_key(a)
    # the form goes only to the certificate it came from (pinned or not)
    pp = None
    if a.backup:                                          # asked before the claim: nothing half done after it
        pp = getpass.getpass("passphrase for the backup: ")
        if pp != getpass.getpass("again: "):
            raise ClaimError("the passphrases differ")
        why = passphrase_problem(pp)
        if why:
            raise ClaimError(why)
    status, page, _ = request(ip, a.port, "POST", "/setup", form_body(token, name, pw, key), tls=tls,
                              pin=fp)
    code = parse_code(page) if status == 200 else None
    if not code:
        raise ClaimError(f"claim refused ({status}): {parse_error(page) or page.strip()[:200]}")
    path = save_code(CONF_DIR, a.host, ip, name, code)
    print(f"claimed: admin {name}{', SSH key added' if key else ', no SSH key'}")
    print(f"recovery code (shown once by the camera): {code}")
    print(f"saved to {path} (0600). Keep a copy offline too.")
    if a.backup:
        try:
            n = download_backup(ip, a.port, fp, name, pw, pp, a.backup)
        except ClaimError as e:
            raise ClaimError(f"claimed, but the first backup failed: {e}. Download one from the System page.") from None
        print(f"first backup saved to {a.backup} ({n} bytes, 0600). Keep it and its passphrase as safe as the "
              "admin password; it is a snapshot: download a new one after changing settings")
    pw = pp = None
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ClaimError as e:
        sys.exit(f"cam-claim: {e}")
    except KeyboardInterrupt:
        sys.exit(1)
