# UART boot log — cam #1 runbook

**Goal:** a serial console on **cam #1** (<cam1>, the expendable dev unit), plus saved logs
of complete stock boots. This is step 2 of RESUME.md §5. It makes the later steps safe:
- It is the recovery channel for everything after this.
- It tells us the exact SSC377 variant and the U-Boot version.
- It shows whether we can stop U-Boot's autoboot. The RAM-boot test (Gate 2) depends on that.

**Nothing in this runbook writes to the camera's flash.** Every step is read-only. The general
pad-finding notes are in `scripts/uart-console.md`; this file is the cam #1 procedure.

## What we already know (stock U-Boot env, from the 2026-10-18 dump)
| Setting | Value | Meaning |
|---|---|---|
| console | `ttyS0`, `115200n8r` | 115200 baud, 8N1. The `r` asks Linux for RTS/CTS; leave CTS unconnected |
| `baudrate` | 115200 | U-Boot uses the same speed |
| `stdin/stdout/stderr` | serial | U-Boot talks on this UART |
| `bootdelay` | **0** | no countdown. Interrupting needs a key arriving the moment U-Boot starts (step 7) |
| `bootcmd` | `dcache on; run bootargs_run; run bootcmd_nor \|\| run bootcmd_mmc` | normal stock boot |
| `ipaddr` / `serverip` | 192.168.124.7 / 192.168.124.68 | stock TFTP defaults. Note them for RAM-boot; don't change them now |

## Rules for this session
1. **cam #1 only.** cam #2 (<cam2>) stays closed and untouched.
2. **3.3 V adapter only.** Never 5 V on any pin.
3. **Never connect the adapter's VCC/3V3 pin.** The camera powers itself, and only GND, TX and RX
   get wired.
4. **Listen-only first.** Wire only GND and board TX → adapter RX until a full boot log is saved
   (steps 1–6). The adapter's TX gets connected only for step 7.
5. **At a U-Boot prompt, only the read-only commands listed in step 7.** No `sf erase`,
   `sf write`, `saveenv`, `setenv`, `env`, `mw`, `tftp*`, `bootm` or `reset`-then-anything-else.
   Writes and RAM-boot come later, after the golden CH341A backups exist.
6. **Never probe or short pads near the SoC's power section.** Never touch GPIO 30, the core
   voltage. Probe only with the camera powered **off**, except where a step says otherwise.
7. **Logs stay local** in `bench-logs/` (gitignored). A stock boot log can show the device
   serial number, the MAC and vendor credentials. Don't paste raw logs into PRs, issues or
   chats. The assistant summarises the hardware facts into DEVLOG/BOARD.md and leaves out
   serial, MAC and any keys or passwords.

## You need
- A USB-to-TTL adapter switchable to **3.3 V**: CP2102, CH340 or FT232 type, set to 3.3 V.
- Dupont jumpers, or fine wire plus a soldering iron to tack wires or a 3-pin header onto pads.
- A multimeter with continuity and DC volts. A logic analyser is optional.
- A Phillips screwdriver and a spudger to open the housing.
- The camera's normal power: PoE or its 12 V supply. Keep its Ethernet on the no-internet VLAN.
- On the Mac, `picocom` (`brew install picocom`), or the no-install fallback in step 5.

## Steps

### 1. Open cam #1 and photograph the board
Power off and unplug it. Open the housing and photograph both sides of the main board in good
light, with the SoC and SPI flash in frame. Look for a row of 3–4 pads or holes, usually near the
SoC or the board edge. They may be labelled `TX RX GND` (sometimes `3V3`/`VCC`), or be bare
test points such as `TP1…`. **Send the photos;** the assistant can help pick candidates.

### 2. Find GND (power off)
Continuity mode. One probe on a known ground: a USB/Ethernet shield, the metal can, or the
negative side of an electrolytic cap. The other probe on each candidate pad. The pad that beeps
is **GND**.

### 3. Rule out the 3.3 V pad (power on, probes only)
Power the camera. DC volts, black probe on GND. A pad that sits **steady at ~3.3 V** through the
whole boot is probably VCC. Mark it **do not connect**. (Board TX also idles near 3.3 V, but it
dips while text is being sent: step 4.)

### 4. Find board TX (power on)
- **Meter method:** on DC volts, watch each remaining candidate across a power-cycle. TX idles
  at ~3.3 V and **flickers lower** during the first seconds of boot, while the IPL, U-Boot and
  kernel banners print. The pad that stays at ~3.3 V and never flickers is more likely RX.
- **Adapter method:** power off. Wire adapter GND → board GND, and adapter RX → the candidate
  pad. Start the capture (step 5), then power on. Readable text means you found TX. Nothing
  means try the next pad. Garbage usually means the wrong pad or a missing GND, and rarely the
  wrong baud; it is 115200 here.

### 5. Start the capture on the Mac (listen-only wiring)
Wiring for steps 5–6: **adapter GND → board GND** and **adapter RX → board TX**. Nothing else.

Find the adapter. On macOS use the `cu.` device:
```
ls /dev/cu.usb*
```
```
mkdir -p bench-logs
```
Capture with picocom. Replace `XXXX` with your adapter, and quit with Ctrl-A then Ctrl-X:
```
picocom -b 115200 -g bench-logs/cam1-stock-boot-1.log /dev/cu.usbserial-XXXX
```
No-install fallback (untested here; quit with Ctrl-C):
```
(stty 115200 cs8 -cstopb -parenb raw; cat) < /dev/cu.usbserial-XXXX | tee bench-logs/cam1-stock-boot-1.log
```

### 6. Capture two full stock boots
With the capture running, power-cycle cam #1 and **leave it alone for about 2 minutes**, until
the stock app is up and the output goes quiet. Quit the capture. Repeat once into
`cam1-stock-boot-2.log`. Two logs let us tell fixed output from noise. If text stops right
after "Starting kernel" while the camera still comes up on the network, note it; that's the
`n8r` flow-control setting, not a fault.

**Stop here and tell the assistant the file names.** Steps 1–6 alone are enough to continue.

### 7. Try to stop autoboot (optional; needs RX wired)
Only after step 6's logs are saved. Power off, then add **adapter TX → board RX** (the
remaining data pad). Some adapters back-feed the board through TX; if the camera behaves oddly
when unpowered, add a 1 kΩ resistor in that wire.

With `bootdelay=0` there is no countdown, so the key has to be arriving as U-Boot starts.
1. Start picocom with a new log, `cam1-uboot.log`.
2. **Hold Enter** (or tap Ctrl-C repeatedly) and power on.
3. You're in if you get a prompt such as `SigmaStar #`, `=>` or `#` instead of a kernel boot.
   Otherwise, power off and try the other key. If neither works after a few tries, stop and
   report it. Some vendor U-Boots need a specific key, and the assistant can look for it in
   the BOOT dump.

At the prompt, **only these read-only commands:**
```
version
bdinfo
printenv
mtdparts
sf probe 0
help
```
Then **power-cycle** the camera. Don't type `reset` or `boot`. It boots stock as normal.
**Never `saveenv`.**

## What to send back
- Photos of the board, with the pads marked.
- Which pad is TX, RX, GND and VCC. A photo with labels is fine.
- The log file names in `bench-logs/`. The assistant reads them locally.
- From step 7: whether autoboot stopped, and with which key.

## What the assistant pulls from the logs (into DEVLOG / BOARD.md)
- The IPL and U-Boot version/build strings, and the **exact SoC variant**
  (SSC377 / D / DE / QE). This decides `BOARD=ssc377_lite` vs `ssc377de_lite` and so on.
- DRAM size and training, the CPU type (Cortex-A7 vs A35; the defconfig says A35), and the
  kernel command line as booted.
- The MTD map and the SPI-NOR ID.
- The SC4336P probe lines: I2C, MIPI lanes, `chmap`, MCLK. This decides whether
  `sensor_rst_pol` matters.
- Any signature or secure-boot messages, which tell us whether the boot chain is verified.
- Whether autoboot can be interrupted and how. That gates the TFTP RAM-boot.

Serial numbers, MACs and credentials seen in the logs are **not** copied anywhere.

## After this
1. Golden CH341A full-chip backup ×2 with matching hashes, and a **tested** restore
   (`scripts/flash-backup.sh`, `flash-restore.sh`).
2. RAM-boot the OpenIPC kernel over TFTP from the U-Boot prompt (DELIVERY.md Method 2). No
   flash write. Then check video, IR-cut (GPIO 11/80), IR LEDs (PWM4) and a clean reboot.
