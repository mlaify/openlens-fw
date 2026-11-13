# PLAN-NEXT: from "SSS plays" to a flashed, updatable, accepted camera (2026-10-23)

Where we start: our firmware streams to Synology Surveillance Station over ONVIF on cam #2, in
the RAM chroot test (docs/RESUME.md §2). Nothing is flashed. This plan orders what's left,
says what each step needs, and names the decisions. Every step has a GitHub issue.

## Phases
| Phase | Step | Issue | Depends on | Done when |
|---|---|---|---|---|
| **A. Today** | A1 SSS motion detection on our stream (owner test in any chroot run) | #102 | — | SSS's own motion detection fires on a wave at the TEST camera and records an event clip |
| | A2 Camera motion detector (AE grid) + ONVIF Events (PullPoint) | #77 | — | SSS "camera motion detection" receives events; tested in a chroot run |
| | A3 ONVIF Imaging (Get/SetImagingSettings, GetOptions → `image.*`) | #103 | — | SSS's image sliders move our picture and persist |
| | A4 Firmware update path: `camupdate`, signed single-slot mtd2 updates | #104 | the signing-key decision (below) | host-tested: valid image accepted; unsigned, tampered, wrong-device and rollback images refused; dry-run on the camera (no write) |
| | A5 Gate 3 criteria written and the self-checks that can run in a chroot | #38 | — | docs/GATE3-CRITERIA.md agreed; chroot pass of the automatable checks |
| **B. Tonight** | B1 Combined live run on cam #2: SSS recording for hours + a real night (auto day/night) + motion events | #102 | A1–A3 | ≥ 6 h, RSS flat, no unintended restarts, day/night switches at dusk/dawn, motion events recorded |
| **C. Gate 1** | C1 CH341A full-chip read ×2 + a tested restore on cam #1 | #33 | owner hardware time | hashes match; a restore written and booted back to stock |
| **D. First flash** | D1 Flash `rootfs.sqfs` to mtd2 on cam #1 from the stock root shell; first real boot | #39 | C1, A4 (so the next version can be installed without the clip) | boots to our firmware: video, IR, SSH, NTP, ONVIF/SSS, settings persist on DATA, clean reboot; `camupdate` installs a newer signed image and the stock mtd2 image (rollback) |
| **E. Gate 3** | E1 Run the full acceptance test on cam #1 (flashed) | #38 | D1 | every criterion in docs/GATE3-CRITERIA.md passes or has an owner-accepted exception |
| **F. Features** | F1 Web UI (#79), F2 network config (#80), F3 image fine-tuning (#36), F4 RTP/UDP | #79 #80 #36 | D1 (ship via camupdate) | per issue |
| **G. cam #2** | G1 Flash cam #2 | #39 | E1 | owner decision |

## Decisions (owner)
1. **Update signing key** (A4).
   - **Recommendation:** a dedicated `ed25519-sk` key on a YubiKey, used with
     `ssh-keygen -Y sign -n cam-firmware`, plus a second YubiKey as a backup signer. Both public
     keys get baked into the image.
   - **Alternative:** a plain ed25519 key kept encrypted, offline.
   - The camera verifies OpenSSH "sshsig" signatures either way.
2. **Rollback allowed?** The proposal: refuse an older version unless the update carries
   `allow-downgrade` in its signed header. The stock mtd2 image, signed by us, is the explicit
   way back to stock.
3. **Outbound NTP to time.cloudflare.com** stays allowed by Gate 3 (owner choice). Everything
   else outbound is refused.
4. **Single-slot updates.**
   - U-Boot boots `root=/dev/mtdblock2` and its env lives in mtd0, which we never write, so
     there is no A/B.
   - A power cut while mtd2 is being written leaves the camera unbootable until a CH341A (or
     UART/TFTP) restore.
   - The proposal accepts this and mitigates it: write in about 10 s, verify before and after,
     and keep the CH341A route proven (Gate 1).

## Order today
A2 and A3 run in parallel: the motion detector in rtspd (assistant) and Imaging + Events in
camhttpd (subagent, against a fixed control-socket interface). A4's design is written
(docs/UPDATE-PATH.md); its code starts once A2/A3 are in review, or earlier if the key
decision is made. A5's criteria are written now. A1 runs whenever a chroot test is up.

## Interfaces fixed for parallel work
- **Control socket** (`/run/camd.sock`, one line in, reply ending `ok`):
  - `get` (has `image.*`, `daynight.*`);
  - `set image.K N` (0..100);
  - **new `motion`** replies `motion.state=0|1`, `motion.seq=N` (counts rising edges),
    `motion.since=S` (seconds the state has held), `ok`.
  - Settings: `set motion.enabled 0|1` and `set motion.sensitivity 0..100`, also in `cam.conf`.
- **camhttpd** reads image and motion state over the socket; it saves settings with
  `camcfg set …` and changes them live with `set …` over the socket.
