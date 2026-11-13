# UART console — find the pads & capture a boot log (I6C)

> For cam #1 follow the step-by-step runbook **`docs/UART-BOOT-LOG.md`** (listen-only first,
> logs in gitignored `bench-logs/`, read-only U-Boot only). This file is the general background.

The I6C uses **ttyS0 @ 115200 8N1, 3.3 V logic** (confirmed in U-Boot bootargs).
A serial console turns bring-up from blind-reflash roulette into minutes: you get
IPL/U-Boot/kernel logs, an interactive U-Boot prompt, and the sensor-probe output.

## Hardware
- USB-TTL adapter set to **3.3 V** (CP2102/CH340/FT232 — NEVER 5 V; it can kill the SoC).
- Jumper wires; optional: multimeter/logic analyzer to find pads.

## Find the 3 pads (TX, RX, GND)
Most of these boards have 3 unpopulated test points near the SoC even without a header.
1. **GND:** continuity to a known ground (shield can, electrolytic cap negative, SoC GND).
2. **TX:** with the camera booting, TX idles at 3.3 V and pulses during boot. Probe
   candidate pads with a scope/logic analyzer, or a USB-TTL RX + `screen` and watch
   for readable text at 115200. TX is the one that spews the IPL/U-Boot banner.
3. **RX:** the remaining data pad (often next to TX). Confirm by typing at the U-Boot
   prompt once you have TX working.

Wiring: adapter **GND→GND**, adapter **RX→board TX**, adapter **TX→board RX**.

## Capture the boot log (macOS)
Find the device:  `ls /dev/tty.usb*`  (e.g. /dev/tty.usbserial-XXXX)

screen (quick):
    screen -L -Logfile boot.log /dev/tty.usbserial-XXXX 115200
    # Ctrl-A then \  to quit screen

picocom (nicer, if installed `brew install picocom`):
    picocom -b 115200 --imap lfcrlf -g boot.log /dev/tty.usbserial-XXXX
    # Ctrl-A Ctrl-X to quit

minicom:  minicom -D /dev/tty.usbserial-XXXX -b 115200  (capture: Ctrl-A L)

Power-cycle the camera and save the full log from IPL banner through kernel/userland.

## What to grab from the log (record in docs/DEVLOG.md)
- IPL + **U-Boot version/build string**, DRAM size/training, SoC revision.
- The **autoboot countdown** — hit a key to interrupt and get the `#` prompt.
- Kernel version banner, DTB/board name, MTD partition registration.
- **Sensor probe lines** for SC4336P (I2C addr, MIPI lanes, chmap) — key for Gate 2.
- Any signature/secure-boot messages (informs whether the boot chain is verified).

## Useful U-Boot commands at the `#` prompt (read-only / safe)
    printenv                 # full env incl. bootcmd/bootargs/mtdparts
    sf probe 0               # init SPI-NOR
    mtdparts                 # partition map
    bdinfo ; version         # board info / u-boot version
RAM-boot a candidate WITHOUT flashing (Gate 2), e.g. over serial Ymodem:
    loady 0x22000000         # receive kernel into RAM (send file from host)
    # ...load rootfs/dtb as the board expects, then:
    bootm 0x22000000         # boot the RAM image; nothing on flash is touched
(TFTP alternative if Ethernet works in U-Boot: `setenv serverip ...; tftpboot ...`.)

SAFETY: at the U-Boot prompt, avoid `sf erase`/`sf write`/`saveenv` until you have a
verified full-chip golden backup (scripts/flash-backup.sh). Reading is safe; writing
is not.
