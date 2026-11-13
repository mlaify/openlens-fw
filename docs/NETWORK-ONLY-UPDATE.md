# Network-only firmware route: what is proven and what remains to prove

The owner wants to develop on the expendable old IPC-D240W-S without opening its
housing again. This note is based on the local V3.5.2.1 flash dump and the live
tests already recorded in `<research-notes>/report/evidence/`. It does not
authorize a flash write or claim that a custom image is ready to install.

**2026-10-22 capture update:** cam #1 now has two matching read-only **16 MiB
software images**, including the formerly unmapped final 64 KiB. The exact
method, hashes, and private local paths are in
`docs/SOFTWARE-FULL-CHIP-BACKUP.md`. No physical CH341A restore has been
tested; that recovery gate remains open. Later references below to the older
four-partition capture describe its historical status, not today's backup.

## Short answer

**A network-only update is technically plausible, but a recoverable custom
OpenIPC/Thingino install has not been demonstrated.** The camera has three useful
network paths:

1. **The live V3.5.2.1 web UI has a firmware-upload page.** Its extracted
   `var/www/html/upgradeConfig.html` submits a `.bin` file to
   `/IPC_FirmwareUpgrade`; `var/www/js/upgradeConfig.js` first requests
   `/setFirmwareUpgradeFreeMemory`, polls `/getFirmwareUploadProgress`, then
   calls `/setFirmwareUpgrade`. This proves an update workflow is present in
   the installed web application. It does *not* prove that a custom package
   will pass model checks or boot. A raw SquashFS or kernel image is not the
   `.bin` package this workflow expects.
2. An authenticated web CGI can enable the debug service. On the owner's old,
   isolated camera, this led to a temporary root shell and a verified *read-only*
   dump of `/dev/mtd0ro` through `/dev/mtd3ro`. See
   `<research-notes>/report/evidence/F22-web-cgi-enables-root-telnet.md`,
   `F23-debug-command-root-execution.md`, and `live-v3521-mtd-capture.md`.
   Root access might permit a userspace or flash-update experiment over the
   network, but no custom image has been written this way. The debug listener
   itself lacks command-level authentication; keep it off except during a
   short, isolated bench session.
3. On boot, the camera broadcasts a UDP 25000 upgrade request and can fetch an
   `ANJOY888` package by TFTP. The owner's config-only test was downloaded and
   reported package-check completion. It did **not** demonstrate a config or
   flash write, nor a successful reset. See
   `<research-notes>/report/evidence/bootloader-network-recovery.md` and
   `boot-upgrade-live-result.md`. A valid, board-matched kernel/rootfs package
   and observed write/boot/rollback behavior are still missing.

## Least-disruptive development sequence

1. Keep the replacement camera untouched. Work only on the expendable old unit
   behind the no-internet VLAN.
2. First build and validate candidate userland and the SC4336P video path as
   far as possible without flashing. A temporary root shell could stage
   binaries in RAM for compatibility checks; it cannot by itself prove that a
   replacement root filesystem will boot. Check the actual free RAM first.
3. Preserve the **two matching 16 MiB software images** and manifest from
   `docs/SOFTWARE-FULL-CHIP-BACKUP.md`. Move a verified copy offline. The
   earlier four-partition MTD capture remains useful historical evidence, but
   it lacks the final 64 KiB and its DATA differs from the current capture.
   Neither backup has a tested physical restore yet.
4. Investigate a board-matched `ANJOY888` package containing **only kernel and
   rootfs**. Establish the current web/application and boot updater's section
   checks and progress codes offline before any transfer. Do not include BOOT
   or DATA. The older 40E and MCF26 public firmware images are not proven
   compatible with this MCA40E_V0 board.
5. If the owner elects a network-only flash on the expendable unit, prefer the
   authenticated web upload while the stock OS is healthy; retain the boot-TFTP
   mechanism as a potential fallback. Capture the exchange and require
   evidence of kernel/rootfs *write completion*; TFTP ACKs and `CHECK_FW_END`
   only prove delivery/checking. Verify the new boot, video, and rollback path
   before considering the replacement camera.

## Recovery boundary

Without UART or a chip clip, a bad **kernel or rootfs** may still be recoverable
through the boot-time TFTP updater **if that updater lives in intact BOOT and
still runs**. That is a conditional possibility, not a proven rescue. A failed
BOOT write, an incompatible package, or an updater that rejects the recovery
image can still require physical access. The repository's Gate 1 should remain
mandatory for the working replacement camera; on the expendable old camera,
the owner may choose a higher-risk network-only experiment with this limit
understood.

The partition layout ends with DATA at `0xFEFFFF`; `0xFF0000–0xFFFFFF` is
unmapped **at the end of the 16 MiB chip**. Earlier wording that called this
64 KiB an IPL/preload header region was incorrect. The boot code is in the
mapped BOOT partition at the beginning of the chip. The 2026-10-22 software
capture read the tail three times, each with the same SHA-256. Its role in
boot and physical restore remains untested.
