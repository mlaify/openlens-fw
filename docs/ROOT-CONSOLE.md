# Temporary root console on the expendable IPC-D240W-S

This procedure uses the **already confirmed** F22/F23 debug chain on the
owner's old camera. The replacement camera is out of scope. It is intended for
read-only board probing and testing temporary userland binaries, not as a
production management service or a firmware-write procedure.

## Current status (2026-10-22)

- `<cam1>:80` returned HTTP 200 after the full-chip capture and reboot.
- The owner enabled a narrow rule from this Mac (`<workstation>`) to the old
  camera on TCP 23 and 9999 and chose to retain the rule for later testing.
  The camera listeners themselves are **closed** after the 2026-10-22 reboot;
  both ports refused connections from this Mac.
- `scripts/camera-root-console.py open --keep-open` **worked live**: a second
  connection read `/proc/self/status` and confirmed all UID fields zero; the
  owner's Terminal showed the camera prompt and `pwd` output. See
  `docs/SOFTWARE-FULL-CHIP-BACKUP.md` for the subsequent read-only 16 MiB
  capture and reboot cleanup.
- First attempt exposed a helper bug: this BusyBox build has no `id` applet.
  The helper now verifies `/proc/self/status` instead. The first leftover
  Telnet listener was closed before the successful retry.

## Open and use

Keep the old camera on its no-internet VLAN. A narrow temporary firewall rule
must allow only this Mac to reach that camera on TCP 23 and 9999. The owner
retained the narrow rule; verify the Mac's source IP and the rule before a
later session. The camera listeners must be re-enabled for a new session.

From a real Mac terminal, run:

```sh
cd openlens-fw
python3 scripts/camera-root-console.py open --host <cam1> --user USER
```

The script prompts for the **camera web password locally**, enables the debug
listener, starts the normal Telnet daemon, applies the previously tested
`SetVersion` shell switch, and confirms all four UID fields are zero in
`/proc/self/status` before relaying an interactive
terminal. It does not print or save the password. Press **Ctrl-]** to disconnect;
by default it then removes the temporary debug flag, stops the two daemons, and
checks that ports 23 and 9999 are no longer reachable from this Mac.

For Claude to use a separate terminal while the owner's first console stays
open, run `python3 scripts/camera-root-console.py connect --host <cam1>`
in a second **local Mac** terminal. If the
first console will exit before the second, start it with `--keep-open`, then
finish with:

```sh
python3 scripts/camera-root-console.py close --host <cam1> --user USER
```

The owner chose to retain the narrow cross-VLAN rule for later testing on
2026-10-22. Remove it when bench access is no longer needed; closing the
camera listeners remains part of every session.
`close` also asks for the camera web password privately. The debug endpoint
passes credentials in an HTTP query inside the isolated LAN, so do not run
this through a proxy or expose the endpoint to any broader network.

## Scope for firmware development

The root console can run `scripts/bench-probe.sh`, inspect `/proc`, GPIO and
sensor state, measure free RAM, and try temporary programs. It can also
write flash as root, so follow `docs/DELIVERY.md` separately before any MTD
change. A working shell does not establish that a replacement kernel or
filesystem will boot. Never write BOOT (`mtd0`) or per-device DATA (`mtd3`).
To copy small text scripts into `/tmp`, follow
[COPY-FILES-TO-CAMERA.md](COPY-FILES-TO-CAMERA.md).

The 2026-10-18 live proof and cleanup steps are recorded in
`<research-notes>/report/evidence/F22-web-cgi-enables-root-telnet.md`,
`F23-debug-command-root-execution.md`, and the private dump notes. If the
helper fails, preserve its short error message and retest port reachability;
do not send the camera password, session cookie, or full CGI URL to an agent.
