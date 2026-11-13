# Firmware delivery — clipless install via root-shell or U-Boot TFTP

Goal: flash the new (OpenIPC) kernel+rootfs onto the camera **without the CH341A clip**,
using paths already available on the device. Owner's hardware, owner installing its own
firmware. Verified from the dump: busybox has `flashcp`, `flash_eraseall`, `nandwrite`,
`dd`, `tftp`, `wget`, `mount`, `ubiupdatevol`; U-Boot has working TFTP (`sstar_emac`,
`ipaddr`/`serverip`/`ethaddr` env).

## The ONE rule that keeps "willing to brick" recoverable
**Never software-write `mtd0` (BOOT = IPL + U-Boot).** Only write `mtd1` (kernel) and
`mtd2` (rootfs). As long as U-Boot is intact, a bad kernel/rootfs is recoverable over
U-Boot TFTP. Overwrite U-Boot and your only way back is the clip + golden image.

MTD map (NOR): `mtd0 BOOT 0x40000` · `mtd1 kernel 0x200000` · `mtd2 rootfs 0xCB0000`
· `mtd3 DATA 0x100000` (keep DATA — per-unit MAC/cal). Devices: `/dev/mtdN`.

## Build constraint (solve before flashing)
Keep stock U-Boot and its boot flow:
`bootcmd_nor = sf probe 0; loados nor 0x23000000 kernel by_header; bootm 0x23000000`.
So the OpenIPC image must be packaged to **fit the existing partitions** (kernel ≤ **1.75 MiB**
= 0x1C0000 so mtd1's trailing blobs survive — see BOARD.md; rootfs ≤13 MiB) and the kernel
must be a **uImage the stock U-Boot can `bootm by_header`** (XZ payload — IMAGE-PACKAGING.md).
If OpenIPC needs a different layout, you must also update U-Boot env/mtdparts — which
means touching BOOT and losing the easy-recovery property. Prefer fitting the stock map.

---

## Method 1 — Root-shell flashcp (NO UART, NO clip) — primary path
Uses the already-proven debug→root-shell chain (F22→F23). This is the least-hardware
route.

1. Host on the camera VLAN serves the images (pick one):
   - HTTP:  `python3 -m http.server 8080`  (serve openipc-kernel.bin, openipc-rootfs.bin)
   - TFTP:  any tftpd exporting the two files
2. Enable debug + get the root shell (your existing procedure): console.cgi enables the
   9999 debug service; `SetVersion $(... telnetd -l /bin/sh ...)` → root shell (Uid 0).
   The reusable, interactive helper and cleanup procedure are in
   `docs/ROOT-CONSOLE.md`.
3. Pull the images into tmpfs (rootfs ~13 MiB fits in the 64 MiB RAM):
       cd /tmp
       wget http://<host>:8080/openipc-kernel.bin
       wget http://<host>:8080/openipc-rootfs.bin
       # or: tftp -g -r openipc-kernel.bin <host> ; tftp -g -r openipc-rootfs.bin <host>
4. Quiesce the camera apps (free RAM, stop writers):
       killall media_server mainctrl comm_server hik_server dbg_server 2>/dev/null
5. Write + verify (flashcp erases, writes, and verifies NOR):
       flashcp -v /tmp/openipc-kernel.bin /dev/mtd1
       flashcp -v /tmp/openipc-rootfs.bin /dev/mtd2
   (Do NOT touch /dev/mtd0 or /dev/mtd3.)
6. `reboot`. Stock U-Boot loads the new kernel from mtd1 → new rootfs from mtd2.

If flashcp verify fails, DO NOT reboot — re-pull and re-write; the old image is already
gone but U-Boot TFTP (Method 2) can still rescue after a reboot.

---

## Method 2 — U-Boot TFTP (needs UART) — the SAFE test + the recovery channel
The default `bootcmd` has no auto-netboot, so you need the **UART** to reach the U-Boot
prompt (see scripts/uart-console.md). This path is worth it: it gives a non-destructive
test AND the recovery route for Method 1.

Interrupt U-Boot, then:

  # set the network (don't saveenv unless you want it persisted)
  setenv serverip <host-ip>; setenv ipaddr <cam-ip>

  # (A) GATE 2 — prove video from RAM, writes NOTHING to flash:
  tftpboot 0x22000000 openipc-uImage
  bootm 0x22000000
  # watch for stable video, IR/night, clean behavior. Power-cycle returns to stock.

  # (B) PERSIST kernel (only after RAM-boot looks good):
  tftpboot 0x22000000 openipc-kernel.bin
  sf probe 0
  sf erase 0x40000 0x1C0000      # NOT 0x200000: last 256 KiB of mtd1 holds blobs to keep (BOARD.md)
  sf write 0x22000000 0x40000 ${filesize}

  # (C) PERSIST rootfs:
  tftpboot 0x22000000 openipc-rootfs.bin
  sf erase 0x240000 0xCB0000
  sf write 0x22000000 0x240000 ${filesize}

  reset

---

## Method 3 — Stock web-UI firmware upload (see docs/NETWORK-ONLY-UPDATE.md)
The installed web app has an upload workflow (`upgradeConfig.html` ->
`/setFirmwareUpgradeFreeMemory` -> `/IPC_FirmwareUpgrade` -> poll
`/getFirmwareUploadProgress` -> `/setFirmwareUpgrade`). Lowest effort IF it accepts a
custom package — but it most likely enforces a vendor header / model check (and only
CRC/MD5, not a real signature, per finding F6), so a raw OpenIPC kernel/SquashFS will
probably be **rejected or mis-flashed**. Treat as unproven: do not feed it a custom
image until the packaging/validation is understood. Full evidence and limits are in
`docs/NETWORK-ONLY-UPDATE.md`. Methods 1 (root-shell flashcp) and 2 (U-Boot TFTP) are
the controllable paths; Method 3 is a convenience only if the vendor updater can be
satisfied.

---

## Recovery matrix (what saves you)
| What you broke | Recoverable by | Needs |
|---|---|---|
| kernel/rootfs, U-Boot intact | U-Boot TFTP (Method 2 B/C) | UART |
| kernel/rootfs, no UART | CH341A clip + golden image | clip |
| U-Boot (mtd0) — only if you break the rule | CH341A clip + golden image | clip |

**Therefore, before the first write, have at least ONE of:**
- a working **UART** (so U-Boot TFTP can rewrite kernel/rootfs), AND/OR
- one **golden full-chip clip backup** (`scripts/flash-backup.sh`) — recovers anything,
  including a trashed U-Boot.
You own the clip; taking one golden image is ~10 min and converts "brick" into "oops,
reflash." Strongly recommended even though you're accepting risk.

## Recommended sequence (clipless-first, but safe)
1. Take ONE golden clip backup anyway (insurance; store offline).    [Gate 1]
2. Find UART, get a boot log, interrupt U-Boot.                       [enables Method 2]
3. **RAM-boot** the OpenIPC uImage via TFTP → prove video.           [Gate 2, no writes]
4. Only then persist: Method 1 (flashcp from root shell) OR Method 2 B/C (sf write).
5. Security acceptance test on the isolated link.                    [Gate 3]

If you truly skip UART+clip: Method 1 alone can install, but a failed flash with no UART
and no golden image = the $35 paperweight you said you're OK with. Your call — it's
documented here so the trade-off is explicit.
