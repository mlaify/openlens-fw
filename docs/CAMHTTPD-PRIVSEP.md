# camhttpd privilege separation (Gate 3, #38)

Owner decision 2026-10-24: camhttpd stops parsing the network as root, split into a small root
**monitor** and an unprivileged **worker**. A worker compromised through a parser bug must not
learn any password, and must be able to do privileged things only inside a real, verified
request of a user with the right role.

**Status: implemented** (src/camhttpd/camhttpd.c, "---- privilege separation"; the reference is
src/camhttpd/README.md, "Privilege separation"), **on**. camhttpd-run passes `-Z camhttpd` while
the image has `/etc/cam/camhttpd.user`, which it has since the bench test passed on cam #1
(20261024.5, 2026-10-24; rootfs/README.md, "Bench test: camhttpd as its own user"). Where the code differs from the design below, "Deviations" at the
end says how and why.

## Why not a plain privilege drop
camhttpd checks every password itself, and ONVIF's WS-UsernameToken needs them in the clear
(SHA-1 of nonce + Created + password). So a camhttpd that merely ran as another user would still
read the plaintext users file, and an admin can add root SSH keys from the web UI. A compromised
camhttpd would therefore still be root, one step removed.

## Processes
`camhttpd` starts as root (`camhttpd-run`, unchanged command line plus `-Z camhttpd`):
1. Parses its options, binds TCP 80 and the WS-Discovery UDP socket, loads what only root may
   read (the EndpointReference secret, the clock high-water mark), and computes the
   EndpointReference (public).
2. `socketpair(AF_UNIX, SOCK_SEQPACKET)` and `fork()`.
3. **Worker** (child):
   - `setgroups` to `camctl` only (rtspd's control socket and `/run/cam`), `setgid`/`setuid`
     to `camhttpd`, and checks that `setuid(0)` now fails;
   - closes the monitor's end of the socket pair;
   - runs today's select loop: HTTP, SOAP, the web UI, WS-Discovery, PullPoint and the preview;
   - writes uploads to `/run/fw` (owned `camhttpd`, 0700).
4. **Monitor** (parent, root):
   - keeps only its end of the socket pair, and closes the listeners;
   - answers one request at a time, as described below;
   - exits when the worker exits, and kills the worker if it gets a malformed message. Either
     way init's respawn of `camhttpd-run` starts both again.

The worker never holds a password, an HA1, a recovery hash or the Digest nonce secret.

## What moves into the monitor
- **Accounts:** the users file (it reads it on every request, as today) and, from it, the
  account list for the worker: names and roles, **never passwords**.
- **Authentication, all of it:**
  - Digest: nonce issue and check, the `nc` cache, stale, HA1, uri and method binding;
  - UsernameToken: digest, window, replay cache, the clock floor and the high-water mark
    (`time-floor` is the monitor's file);
  - lockout: per address, the global budget and the operator+ exemption.

  The worker sends the peer address, method, request target, the `Authorization` header and the
  `wsse:Security` header slice. The monitor answers `{role, user, grant}`, or `{wrong|stale|retry|
  blocked}` plus a fresh challenge nonce.
- **A grant** is a random 64-bit id bound to `{user, role, peer, issue time}`, valid for 30 s and
  for at most 48 privileged operations (the Image form saves 35 keys). Every privileged request
  carries one. The monitor checks that the operation's required role is at most the grant's role.
  A worker can therefore act only while a real user of that role is sending requests, and only
  within that role. It could swap the body of a real admin request; on plain HTTP an on-path
  attacker can do the same, which is the TLS residual.
- **Privileged operations,** each a fixed shape with no free argv:

  | Op | Role | What the monitor runs |
  |---|---|---|
  | `set KEY VALUE` | operator; `time.*` admin | `camcfg -d DIR set KEY VALUE` |
  | `user add/passwd/role/del NAME [ROLE]` + stdin | admin | `camcfg -d DIR user …` |
  | `sshkey list/add/del [FP]` + stdin | admin | `camcfg -d DIR sshkey …` |
  | `settime SECS USEC` | admin | `settimeofday`, then the replay floor as today |
  | `reboot` | admin | `sync`, `reboot` |
  | `upd-check` | admin | opens `/run/fw/upload.camfw` with `O_NOFOLLOW`; regular file, ≤ 5 MiB; runs `camupdate --check -` with it as stdin |
  | `upd-install` | admin | the same fd discipline, `camupdate -` detached as today |
  | `claim NAME` + stdin | none: monitor checks unclaimed and the 30-min window | `camcfg claim` |
  | `recover [NAME]` + stdin | none: monitor checks the window and its own rate limit | `camcfg recover` |
  | `conf` | none | `cam.conf`'s text (settings only, no secrets) |
  | `users` | none | names and roles |

  Values are checked by the monitor with the same validators as today (key names from a fixed
  table, printable ASCII, lengths). camcfg stays the authority on content.
- **Reading cam.conf** goes through `conf`, because `/mnt/nand` is root-only.

## What stays in the worker
- HTTP framing and slots, the SOAP parser, every ONVIF operation, the web UI pages, CSRF tokens
  (their key is per start and grants nothing by itself), the Origin and Host checks;
- WS-Discovery, rtspd's control socket (group `camctl`) and the snapshot read;
- PullPoint subscriptions, and the role checks it already does. The monitor checks the role
  again for privileged operations.

## Protocol
`SOCK_SEQPACKET`, one message per request and one per reply, at most 8 KiB.
- **Requests:** a fixed header `{u32 op, u64 grant, u32 len}` followed by NUL-separated fields;
  stdin data such as a password or key line is the last field.
- **Replies:** `{i32 status, u32 len}` plus text (camcfg's message, camupdate's verdict, the conf
  text, the user list).
- **The monitor refuses:**
  - any message that isn't exactly well formed;
  - an unknown op;
  - an expired or exhausted grant, or one whose role is too low;
  - a field with a NUL or newline inside it.

  It answers with a status and keeps no state from a refused request. Passwords in requests are
  wiped after use, on both sides.

## Tests
- The host test keeps running camhttpd in one process: built with `MON_INPROC`, each worker call
  serialises its message and calls the monitor's dispatcher directly. Every existing auth, UI
  and ONVIF test therefore goes through the real protocol and the monitor's checks.
- **New monitor tests:**
  - each op's role table;
  - grant expiry, its op budget and a forged grant;
  - malformed messages (fuzzed);
  - `O_NOFOLLOW` on the upload;
  - the claim and recover windows;
  - the worker never receiving a password: the reply buffers are scanned in the test.
- **One fork test** through a real `socketpair`, where the sandbox allows it.

## Rootfs
- **Users and groups:** user `camhttpd` (locked, no shell), member of `camctl` (also rtspd's
  group, for `/run/camd.sock` and `/run/cam`). Both are added together with rtspd's privilege
  drop.
- **rcS:** `/run/fw` is owned by `camhttpd`, 0700.
- **`camhttpd-run`:** passes `-Z camhttpd` only while `/etc/cam/camhttpd.user` exists, so a
  release can ship without it if the bench test fails.

## Live test on cam #1 before cam #2
- Surveillance Station: adding the camera, recording, events and snapshots.
- The web UI pages: users, SSH keys, time, firmware upload and install, reboot.
- Claim on a reset DATA, in the bench chroot or on a spare.
- `gate3-live.py`, plus `ps` showing the worker as `camhttpd` and the monitor as root.
  The procedure: rootfs/README.md, "Bench test: camhttpd as its own user"; gate3-live's
  camera-side part reports each daemon's uid (`§7 runs as:` INFO lines).

## Deviations (implementation, 2026-10-24)
- **Messages are at most 16 KiB, not 8 KiB.** A form field (a password, a key line) may be up to
  8 KiB and must reach camcfg whole, so that camcfg refuses it with its own reason instead of
  seeing it cut.
- **`conf` passes an open fd of cam.conf, not its text.** camcfg lets cam.conf grow to 64 KiB, and
  one open file is one consistent version for the reader; the worker reads it with the code it
  always used.
- **One more op, `upd-begin` (admin):** an upload's body may take up to 5 + 5 MiB / 4096 s, far
  past a 30 s grant, so at the upload's headers the worker has the monitor pin that login's grant
  for the upload's one `upd-check` (1290 s at most). The pinned grant does nothing else after its
  30 s.
- **`upd-check` doesn't block the monitor or the loop** (camupdate may take up to 60 s): the monitor
  starts a runner (a grandchild, adopted by init) and passes the worker one end of a stream socket;
  the verdict comes on it as one record (killed at the time limit, camupdate's wait status, its
  output), then EOF. The worker closing it (its own 60 s limit, a dropped upload) kills camupdate
  at once, as before. A socket, not a pipe: a pipe's write end doesn't report the reader's close
  on every system. `upd-install` passes the read end of the pipe only camupdate holds, as before.
- **Which fields may hold what:** argv fields (key, value, action, role, the numbers, the address)
  printable ASCII; stdin and name fields (password, code, key line, user name) anything but NUL and
  newline, so camcfg judges their content and the UI keeps camcfg's messages (a newline is refused
  with camcfg's words, "password must be one line"); `Authorization` and the request target
  anything but CR and LF (they are header bytes); the UsernameToken element anything but NUL (XML
  has newlines). A field is a C string, so a NUL inside one shows as an extra field: malformed.
- **Malformed (the worker is killed) is the framing only:** short, a wrong length, an unterminated
  field, a field count other than the op's, over 16 KiB, ancillary data. An unknown op, a bad grant
  and a bad field are refused with a status (`MON_DENIED`, or 1 where camcfg would refuse) and change
  nothing, the grant included.
- **`auth` with no credentials** gives the nonce for a challenge that follows no refusal, and tells
  `/recover` whether its address is locked out (its first check, as before): no op of its own.
- **Without `-Z` the halves run in one process** through the same messages (each call goes to the
  dispatcher directly). That is the host test's in-process mode (the "MON_INPROC" above) and also
  what a release without `/etc/cam/camhttpd.user` runs, so the protocol's checks run either way.
- **Groups:** `-Z camhttpd` takes the user's groups from `/etc/group` (drop.h, as rtspd): the
  primary `camhttpd` and `camctl`. The bench test's `-Z 102:110` has the one group 110.
- **The EndpointReference is made once, before the fork** (its key is root's and wiped in the
  worker); it was made again at each discovery join before, with the same value unless eth0's MAC
  couldn't be read at the start.
- **Hosts without `SOCK_SEQPACKET` unix sockets** (macOS: the host test's fork test) use a datagram
  socket pair; the camera uses `SOCK_SEQPACKET`.
