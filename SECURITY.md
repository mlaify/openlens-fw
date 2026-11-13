<!-- SPDX-License-Identifier: MIT -->
# Security policy

## Reporting a vulnerability
Please **don't open a public issue** for a security problem.

Report it privately through GitHub: the repository's **Security** tab, then **Report a
vulnerability**. Include:
- the firmware version (System page or `/etc/cam/version`);
- what an attacker needs (network position, an account and its role, physical access);
- steps to reproduce, and what they lead to.

Remove MAC addresses, serial numbers, passwords and recovery codes from logs and captures before
you send them.

You'll get an answer when the report has been read. A fix goes into a signed release, and the
report is published with credit once cameras can be updated, unless you'd rather not be named.

## In scope
This firmware: everything built from this repository.
- **The daemons:** rtspd, camhttpd, camtls, camcfg, ntpc and camupdate.
- **The image:** the rootfs, its boot scripts and the Dropbear configuration.
- **The processes:** the claim and recovery flow, the update signing and verification, and the
  build scripts.

## Out of scope
- **The stock Anpviz/Anjoy firmware.** Report vulnerabilities in it to the vendor, or through a
  coordinator such as CERT/CC.
- **The stock U-Boot and kernel**, which this firmware keeps. Weaknesses that need physical access
  to the board (UART, flash clip) are known and accepted: protect the camera physically
  (docs/GATE3-CRITERIA.md §7).
- **Known residuals** that the docs already list as accepted, unless you've found a way to make
  them worse than described there.

## Supported versions
Only the latest release. Fixes are not backported.
