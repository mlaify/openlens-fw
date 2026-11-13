#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Talk to the camera's speaker over the ONVIF RTSP backchannel (#117), the way an NVR does:

  python3 scripts/cam-talk.py HOST [--port 554] [--user admin] [--tone 1000 | --wav FILE]
                              [--seconds 5] [--level 0.3] [--alaw]

DESCRIBE with "Require: www.onvif.org/ver20/backchannel", SETUP track2 (interleaved over the
RTSP connection), PLAY, then 20 ms G.711 packets in real time: a sine tone, or a 16-bit PCM WAV
(any rate, mono or stereo; resampled to 8 kHz). The password comes from CAM_PASS or a prompt.
Standard library only; no ffmpeg needed (ffmpeg has no RTSP backchannel).
"""
import argparse
import getpass
import hashlib
import math
import os
import re
import socket
import struct
import sys
import threading
import time
import wave

RATE = 8000
PKT = 160                                       # samples per packet: 20 ms


def ulaw(s):
    sign = 0x80 if s < 0 else 0
    x = min(-s if s < 0 else s, 32635) + 0x84
    seg = 7
    m = 0x4000
    while seg > 0 and not x & m:
        seg -= 1
        m >>= 1
    return ~(sign | seg << 4 | (x >> (seg + 3)) & 0x0F) & 0xFF


def alaw(s):
    sign = 0x80 if s >= 0 else 0
    x = min(-s - 1 if s < 0 else s, 32767) >> 3
    if x < 32:
        v = x >> 1
    else:
        seg = x.bit_length() - 5
        v = seg << 4 | (x >> seg) & 0x0F
    return (v | sign) ^ 0x55


def tone(hz, seconds, level):
    n = int(seconds * RATE)
    return [int(level * 32767 * math.sin(2 * math.pi * hz * i / RATE)) for i in range(n)]


def read_wav(path, level):
    with wave.open(path, "rb") as w:
        if w.getsampwidth() != 2:
            sys.exit("cam-talk: the WAV must be 16-bit PCM")
        ch, rate, raw = w.getnchannels(), w.getframerate(), w.readframes(w.getnframes())
    s = struct.unpack("<%dh" % (len(raw) // 2), raw)
    mono = [sum(s[i:i + ch]) // ch for i in range(0, len(s) - ch + 1, ch)]
    out, step = [], rate / RATE                 # linear resample; fine for a speaker check
    pos = 0.0
    while pos < len(mono) - 1:
        i = int(pos)
        f = pos - i
        out.append(int((mono[i] * (1 - f) + mono[i + 1] * f) * level / 0.3))
        pos += step
    return [max(-32768, min(32767, v)) for v in out]


class Rtsp:
    def __init__(self, host, port, user, password):
        self.base = "rtsp://%s:%d/" % (host, port)
        self.user, self.password = user, password
        self.sock = socket.create_connection((host, port), timeout=10)
        self.cseq = 0
        self.auth = None
        self.buf = b""

    def _digest(self, method, uri):
        realm, nonce = self.auth
        h = lambda t: hashlib.md5(t.encode()).hexdigest()
        resp = h("%s:%s:%s" % (h("%s:%s:%s" % (self.user, realm, self.password)), nonce,
                               h("%s:%s" % (method, uri))))
        return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"'
                % (self.user, realm, nonce, uri, resp))

    def _reply(self):
        while b"\r\n\r\n" not in self.buf:
            d = self.sock.recv(4096)
            if not d:
                sys.exit("cam-talk: the camera closed the connection")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        head = head.decode(errors="replace")
        m = re.search(r"(?im)^Content-Length:\s*(\d+)", head)
        n = int(m.group(1)) if m else 0
        while len(self.buf) < n:
            self.buf += self.sock.recv(4096)
        body, self.buf = self.buf[:n].decode(errors="replace"), self.buf[n:]
        return int(head.split()[1]), head, body

    def request(self, method, uri, headers=""):
        for _ in range(2):
            self.cseq += 1
            auth = "Authorization: %s\r\n" % self._digest(method, uri) if self.auth else ""
            msg = "%s %s RTSP/1.0\r\nCSeq: %d\r\n%s%s\r\n" % (method, uri, self.cseq, auth, headers)
            self.sock.sendall(msg.encode())
            code, head, body = self._reply()
            if code != 401 or self.auth:
                return code, head, body
            realm = re.search(r'realm="([^"]*)"', head)
            nonce = re.search(r'nonce="([^"]*)"', head)
            if not realm or not nonce:
                return code, head, body
            self.auth = (realm.group(1), nonce.group(1))
        return code, head, body


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=554)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--tone", type=float, default=1000.0, help="sine frequency in Hz (default 1000)")
    ap.add_argument("--wav", help="play this 16-bit PCM WAV instead of a tone")
    ap.add_argument("--seconds", type=float, default=5.0, help="tone length (default 5)")
    ap.add_argument("--level", type=float, default=0.3, help="0..1 of full scale (default 0.3)")
    ap.add_argument("--alaw", action="store_true", help="send PCMA (PT 8) instead of PCMU (PT 0)")
    a = ap.parse_args()
    if not 0 < a.level <= 1:
        sys.exit("cam-talk: --level must be in (0, 1]")
    password = os.environ.get("CAM_PASS") or getpass.getpass("password for %s: " % a.user)
    pcm = read_wav(a.wav, a.level) if a.wav else tone(a.tone, a.seconds, a.level)

    r = Rtsp(a.host, a.port, a.user, password)
    code, head, sdp = r.request("DESCRIBE", r.base, "Accept: application/sdp\r\n"
                                "Require: www.onvif.org/ver20/backchannel\r\n")
    if code != 200:
        sys.exit("cam-talk: DESCRIBE -> %d\n%s" % (code, head))
    if "a=control:track2" not in sdp or "sendonly" not in sdp:
        sys.exit("cam-talk: no backchannel in the SDP (speaker off or audio.enabled=0?)\n" + sdp)
    code, head, _ = r.request("SETUP", r.base + "track2",
                              "Transport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n")
    if code != 200:
        sys.exit("cam-talk: SETUP track2 -> %d (453 = someone else is talking)\n%s" % (code, head))
    sess = re.search(r"(?im)^Session:\s*([^;\r\n]+)", head).group(1).strip()
    ch = int(re.search(r"interleaved=(\d+)", head).group(1))
    code, head, _ = r.request("PLAY", r.base, "Session: %s\r\n" % sess)
    if code != 200:
        sys.exit("cam-talk: PLAY -> %d\n%s" % (code, head))

    def drain():                                # RTCP or anything else the camera sends
        try:
            while r.sock.recv(65536):
                pass
        except OSError:
            pass
    r.sock.settimeout(None)
    threading.Thread(target=drain, daemon=True).start()

    enc, pt = (alaw, 8) if a.alaw else (ulaw, 0)
    ssrc, seq, ts = int.from_bytes(os.urandom(4), "big"), 0, 0
    print("talking: %.1f s of %s, %s, level %.2f" % (len(pcm) / RATE, a.wav or "%g Hz" % a.tone,
                                                     "PCMA" if a.alaw else "PCMU", a.level))
    t0 = time.monotonic()
    for k, i in enumerate(range(0, len(pcm) - PKT + 1, PKT)):
        rtp = struct.pack("!BBHII", 0x80, pt | (0x80 if k == 0 else 0), seq, ts, ssrc)
        rtp += bytes(enc(v) for v in pcm[i:i + PKT])
        r.sock.sendall(struct.pack("!cBH", b"$", ch, len(rtp)) + rtp)
        seq, ts = (seq + 1) & 0xFFFF, (ts + PKT) & 0xFFFFFFFF
        delay = t0 + (k + 1) * PKT / RATE - time.monotonic()
        if delay > 0:
            time.sleep(delay)
    r.sock.sendall(("TEARDOWN %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n\r\n"
                    % (r.base, r.cseq + 1, sess)).encode())
    time.sleep(0.3)
    print("done")


if __name__ == "__main__":
    main()
