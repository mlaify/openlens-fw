#!/bin/sh
# SPDX-License-Identifier: MIT
# bench-probe.sh — READ-ONLY hardware probe for the STOCK firmware (busybox sh).
# Run in the stock root shell (F22->F23 debug path) to resolve the board facts that
# static analysis could not: product type, exported GPIOs (IR-cut A/B, IR-LED enable),
# /dev/irled, PWM state, sensor/I2C. Writes nothing to flash; only reads /proc, /sys, /tmp.
#
# Usage on the camera (paste, or wget from your host into /tmp and `sh /tmp/bench-probe.sh`):
#   sh bench-probe.sh > /tmp/probe-day.txt     # with the camera in DAY mode
#   (switch to NIGHT in the stock web UI, or cover the lens)
#   sh bench-probe.sh > /tmp/probe-night.txt
# Then diff the two: GPIOs whose value flips are IR-cut A/B and the IR-LED enable.

echo "=== product type ==="
cat /tmp/product_type.txt 2>/dev/null || echo "(no /tmp/product_type.txt)"

echo "=== exported GPIOs: gpioN dir value active_low ==="
for g in /sys/class/gpio/gpio*; do
  [ -d "$g" ] || continue
  printf '%s %s %s %s\n' "${g##*/}" "$(cat "$g/direction" 2>/dev/null)" \
    "$(cat "$g/value" 2>/dev/null)" "$(cat "$g/active_low" 2>/dev/null)"
done

echo "=== gpio debugfs (labels, if available) ==="
cat /sys/kernel/debug/gpio 2>/dev/null | head -80 || echo "(debugfs not mounted)"

echo "=== IR LED / day-night devices ==="
ls -la /dev/irled /dev/sar* /dev/adc* 2>/dev/null
cat /tmp/ircut_night_mode 2>/dev/null && echo "(^ /tmp/ircut_night_mode)"

echo "=== PWM ==="
for p in /sys/class/pwm/pwmchip*; do
  [ -d "$p" ] || continue
  echo "${p##*/}: npwm=$(cat "$p/npwm" 2>/dev/null)"
  for c in "$p"/pwm*; do [ -d "$c" ] && echo "  ${c##*/} en=$(cat "$c/enable" 2>/dev/null) period=$(cat "$c/period" 2>/dev/null) duty=$(cat "$c/duty_cycle" 2>/dev/null)"; done
done

echo "=== sensor / MI modules ==="
grep -E 'sc4336|sstar_mi|mi_' /proc/modules 2>/dev/null
cat /sys/module/*sc4336*/parameters/* 2>/dev/null | head

echo "=== I2C buses ==="
ls /dev/i2c-* 2>/dev/null

echo "=== mtd layout ==="
cat /proc/mtd

echo "=== cmdline ==="
cat /proc/cmdline
