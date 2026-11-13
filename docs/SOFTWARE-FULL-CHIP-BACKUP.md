# Old camera: read-only, network-only full-chip capture

**Status on 2026-10-22:** completed on cam #1 (`<cam1>`), stock Linux
`5.10.117 #89 PREEMPT`. Two independently captured **16,777,216-byte** images
match byte for byte. This did **not** write flash or test a CH341A restore.
Cam #2 (`<cam2>`) was untouched. Treat the images as verified software
reads, not as proof that a physical restore works.

This is a handoff for Claude and the owner. The full evidence, module source,
transfer helper, and binary are local to `<research-notes>/`; none belongs
in this Git repository. Begin with
`<research-notes>/analysis/fullchip-tail/ATTEMPT.md` and
`<research-notes>/3.5.2.1/fullchip-2026-10-22/full-chip-manifest.json`.

## Result and location

| File | Purpose |
|---|---|
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/full-chip-read1.bin` | complete first software read |
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/full-chip-read2.bin` | independent complete second read |
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/full-chip-manifest.json` | offsets, lengths, SHA-256 values, capture method |
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/SHA256SUMS` | checksums for both images, partition sets, tail reads, and manifests |
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/read1/`, `read2/` | independently captured mtd0–mtd3 partitions |
| `<research-notes>/3.5.2.1/fullchip-2026-10-22/tail-read1.bin`, `tail-read2.bin` | independent final 64 KiB reads |

Both complete files have SHA-256
`48316bdd707e59499630116b0915d60ee53421f38a8903d59d1c003e0e899fa7`.
The final 64 KiB has SHA-256
`71189f7fb6aed638640078fba3a35fda6c39c8962e74dcc75935aac948da9063`.
After both complete captures, a third read of the tail matched. `cmp -s`
confirmed the two complete files are byte-identical. The notes folder is on an
encrypted volume; the capture directory is mode `0700`, files `0600`.
DATA can contain credentials, so keep these files private and move a copy to
the owner's offline encrypted drive. That transfer is **not yet confirmed**.
From the capture directory, `shasum -a 256 -c SHA256SUMS` verified all 15
listed evidence files. Repeat that command after the offline copy.

## Why the ordinary dump was incomplete

The live `/proc/mtd` map was BOOT `0x40000`, kernel `0x200000`, rootfs
`0xCB0000`, DATA `0x100000`. Together they end at `0xFEFFFF`, leaving
`0xFF0000–0xFFFFFF` outside the exposed partition devices. `dmesg` identifies
the underlying `nor0` as 16 MiB, but it has no whole-chip `/dev/mtd*` node.
Padding the four partitions with `0xFF` would invent the missing bytes.

The stock kernel exports `get_mtd_device`, `put_mtd_device`, and `mtd_read`.
Its `mtd_read_oob` disassembly at virtual `0xC013B4E8` follows an MTD
partition's parent pointer at struct offset `0x234`. The RAM-only module
`<research-notes>/analysis/fullchip-tail/tail_ro.c` reads that parent
pointer from mtd3 and confirms that a 32-byte read at its offset zero equals
a 32-byte BOOT read. Only then does it expose `/proc/nor0_tail_ro` as mode
`0400`. Opening that proc file performs a fresh `mtd_read` of the last 64 KiB.
The module contains no flash-write or erase call. Its exact offsets and ABI
are specific to this stock kernel; **do not load it on cam #2 or a changed
kernel** without repeating the reverse engineering and validation.

## Reproduce the capture on this exact old camera

1. Keep cam #1 on its no-internet VLAN. Check that the Mac source address and
   narrow rule still fit the session. On 2026-10-22 the Mac was `<workstation>`,
   with TCP 23 and 9999 allowed only to `<cam1>`. The owner elected to
   retain that firewall rule for later tests. The camera listeners are
   currently **closed** after a reboot.
2. The owner opens the root console from their terminal and enters the camera
   web password at the hidden prompt. Never paste a password or CGI URL into
   chat or a log:

   ```sh
   cd openlens-fw
   python3 scripts/camera-root-console.py open --host <cam1> --user USER --keep-open
   ```

   A later assistant can connect to that temporary shell only when the owner
   authorizes the bench work. The helper's `connect` action needs no password
   and verifies root via `/proc/self/status`.
3. Verify the old camera's MAC and `/proc/mtd` against the already recorded
   unit/layout. `tools/anpviz-flash-dump.py` and the transfer helper enforce
   that check. Confirm `uname -a` is still `5.10.117 #89 PREEMPT`. The
   prebuilt local module is
   `<research-notes>/analysis/fullchip-tail/tail_ro-stock-init.ko`, SHA-256
   `1f9e8311f74598e7d55b7bfcfac0f54958d0732b075d3be4027c7f8a99cc796c`.
   If this file or kernel differs, stop and rebuild/revalidate before loading.
4. With the temporary root shell open, copy the module into RAM-backed `/tmp`:

   ```sh
   python3 <research-notes>/analysis/fullchip-tail/transfer.py
   ```

   That helper sends a base64-encoded tar.gz through a separate Telnet shell,
   extracts **only** `/tmp/tail_ro.ko`, and checks its on-camera SHA-256.
   Direct `gzip -d` failed on this BusyBox build despite its help text;
   `tar -xz` worked. Nothing is copied to flash.
5. In the owner's root console, run `insmod /tmp/tail_ro.ko` and check that
   `/proc/nor0_tail_ro` exists and `dmesg | grep tail_ro` contains
   `64 KiB read-only window at 0xff0000`. A missing proc file means **no
   tail capture**. Do not substitute zeros or `0xFF`.
6. Capture the tail at least twice by opening `/proc/nor0_tail_ro` twice,
   base64-encoding each read over Telnet and requiring exactly 65,536 decoded
   bytes. The 2026-10-22 capture used the existing `connect_shell` and
   `run_marked` helpers from
   `<research-notes>/tools/anpviz-flash-dump.py` with command
   `cat /proc/nor0_tail_ro | base64`. The two SHA-256 values must match.
7. Make two new empty, mode-`0700` capture directories on an encrypted
   volume and run the existing partition dumper once into each:

   ```sh
   python3 <research-notes>/tools/anpviz-flash-dump.py --output-dir /absolute/encrypted/path/read1
   python3 <research-notes>/tools/anpviz-flash-dump.py --output-dir /absolute/encrypted/path/read2
   ```

   It checks the old camera's MAC and exact MTD layout, reads only
   `/dev/mtd0ro`–`/dev/mtd3ro`, and writes per-file SHA-256 manifests. Confirm
   every corresponding partition matches. DATA differed from the older
   October 18 capture but matched between both October 22 reads.
8. Read the tail a third time after the partitions. Then concatenate, **in
   order**, mtd0 BOOT, mtd1 kernel, mtd2 rootfs, mtd3 DATA, and the matching
   tail. Require exactly `0x1000000` bytes per image, hash each, and compare
   the two images byte for byte. The exact segment offsets and digests are in
   `full-chip-manifest.json` above. Do not label a mismatched pair golden.
9. Reboot cam #1 to clear the RAM module and temporary debug listeners. The
   tested command was `/sbin/reboot -f` from the root shell while keeping the
   Telnet socket open for several seconds so the command was consumed. A
   send-and-immediate-close attempt did **not** reboot it. Observe the down/up
   cycle, HTTP 200, and refusal of TCP 23/9999. On 2026-10-22 HTTP returned
   in about 18 seconds. Ask the owner before changing their retained VLAN
   rule.

## Rebuild the local module if necessary

The source, Makefile, patched ELF, and scripts live under
`<research-notes>/analysis/fullchip-tail/`. They are local evidence, not
Git artifacts. The module was compiled in the existing amd64 Docker build
tree at `/work/firmware/output/build/linux-custom` using the OpenIPC ARM
toolchain, then adapted **only for this stock kernel**:

1. `make -C /work/firmware/output/build/linux-custom M=/src ARCH=arm CROSS_COMPILE=/work/firmware/output/host/bin/arm-openipc-linux-musleabihf- modules`
   inside `claude-openipc-build:24.04`, with local analysis mounted at `/src`
   and the `claude-openipc-work` Docker volume at `/work`.
2. Cross-`objcopy` dumped `.modinfo`; its `vermagic=5.10.61 preempt
   mod_unload ARMv7 thumb2 p2v8` string was changed to `5.10.117` and
   written back with `--update-section`. A one-byte placeholder was added
   for each required `.plt` and `.init.plt` section. Without these sections,
   the stock kernel rejected the module before executing it.
3. `patch-module-init.py` changed only the ELF init relocation target from
   `0x11C` to `0xE8`, matching both examined stock modules; cleanup remained
   at `0x1A4`. `readelf -rW` verified both offsets. Without the patch, the
   module appeared in `/proc/modules` but never ran its initializer.
4. The OpenIPC `mtd_info` C struct also differs from the stock build. Direct
   access to its `parent`/`size` fields failed safely. A named `nor0` lookup
   returned `-ENODEV`. The final source uses the `0x234` parent pointer
   derived from the **stock** kernel and checks the parent against BOOT.

Do not generalize this ABI patch. If a rebuild changes the module hash, recheck
its imports, vermagic, PLT sections, init/cleanup relocations, stock-kernel
version, camera identity, and live read guard before using it. A kernel panic
is possible when loading an ABI-mismatched module; the owner accepted that
bench risk on the expendable unit, with the CH341A as fallback.

## What remains

- Move a copy of both software images, the manifest, and this note to the
  offline encrypted drive, then verify their hashes there.
- Make a physical CH341A read and **test a restore** before calling the
  project's recovery gate complete. A matching software image does not prove
  physical write/boot recovery.
- Nothing was flashed or RAM-booted. UART/U-Boot access remains unresolved;
  network-only firmware delivery and rollback are separate experiments.
