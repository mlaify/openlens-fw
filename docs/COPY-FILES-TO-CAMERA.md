# Copy small text files to the old camera

The old IPC-D240W-S has no SSH/SCP service. With its temporary root Telnet
shell open as described in [ROOT-CONSOLE.md](ROOT-CONSOLE.md), use the local
`camera-copy-text.py` helper to place a **small printable UTF-8 text file** in
the camera's RAM-backed `/tmp` directory. This was verified live with
`scripts/bench-probe.sh` on 2026-10-21.

From a Mac terminal in this repository:

```sh
cd openlens-fw
python3 scripts/camera-copy-text.py scripts/bench-probe.sh --host <cam1>
```

The helper connects to the already-open root shell and confirms UID 0. It
copies the file via a quoted shell heredoc to `/tmp/<source basename>`, sets
mode `700`, then compares the camera's `sha256sum` and byte count with the local
file. It prints `Verified:` only when both match. No camera password is
required for this step because the temporary root shell is already open.

For the probe, run `sh /tmp/bench-probe.sh` at the camera prompt when ready.
Copying the script does **not** execute it. Files in `/tmp` disappear on reboot.
The helper does not touch flash or the working replacement camera.

This transfer accepts at most 8 KiB of printable UTF-8 text plus newlines, with a
final newline. It is suitable for short shell scripts and configuration text.
Do not use it for firmware images, executables, binary data, secrets, or large
files; Telnet terminal processing can corrupt arbitrary bytes. Validate a
separate binary transport before transferring build artifacts. When finished,
close the root console and remove the temporary TCP 23/9999 firewall rule as
described in [ROOT-CONSOLE.md](ROOT-CONSOLE.md).
