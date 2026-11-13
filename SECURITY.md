<!-- SPDX-License-Identifier: MIT -->
# openlens-fw Vulnerability Disclosure Policy

## Introduction

openlens-fw is replacement firmware for IP cameras that sit on people's home and business
networks, so security reports are welcome from researchers and users alike. If you believe you
have found a vulnerability in this firmware or in how it is built, signed or installed, we want to
hear from you. This policy says how to report it, what we ask of you, and what you can expect from
us.

## Official Channels

Please **don't open a public issue** for a security problem. Report it privately, either way:

- **GitHub:** the repository's **Security** tab, then **Report a vulnerability**
  ([direct link](https://github.com/mlaify/openlens-fw/security/advisories/new)).
- **Email:** [security@mlaify.io](mailto:security@mlaify.io). To encrypt your report, use the
  [security@mlaify.io PGP key](https://mlaify.io/publickey.security.mlaify.io-38642d275f820a026f3bfc5e7e44d7d05bafd4df.asc)
  (fingerprint `3864 2D27 5F82 0A02 6F3B FC5E 7E44 D7D0 5BAF D4DF`).

Include:
- the firmware version (the web UI's System page, or `cat /etc/cam/version` over SSH), or the
  commit you built from;
- what an attacker needs: network position, an account and its role, physical access;
- steps to reproduce, and what they lead to.

**Remove MAC addresses, serial numbers, passwords, recovery codes and RTSP URLs with credentials
from logs and captures before you send them.**

## Systems in Scope

This firmware: everything built from this repository.
- **The daemons:** rtspd, camhttpd, camtls, camcfg, ntpc and camupdate.
- **The image:** the root filesystem, its boot scripts and the Dropbear configuration.
- **The processes:** the claim and recovery flow, the settings backup, lock mode, update signing
  and verification, and the build and install scripts.

## Out of Scope

- **The stock Anpviz/Anjoy firmware.** Report vulnerabilities in it to the vendor, or through a
  coordinator such as [CERT/CC](https://www.kb.cert.org/vuls/report/).
- **The vendor files in `vendor-blobs/`** (the stock kernel, U-Boot, SigmaStar modules and
  libraries). We can't change them. A weakness in how *our* code uses them is in scope.
- **Weaknesses that need physical access** to the board (UART, flash clip). The stock bootloader
  doesn't check signatures; this is known and accepted, and the docs say to protect cameras
  physically.
- **Known limits** that the [security model](https://docs.mlaify.io/openlens-fw/security-model/)
  already lists, such as plain ONVIF/RTSP for NVRs and unauthenticated NTP, unless you've found a
  way to make them worse than described there.
- Cameras, networks and accounts that aren't yours.

## Our Commitments

When working with us under this policy, you can expect us to:
- Respond to your report promptly, and work with you to understand and validate it;
- Keep you informed as the report is handled;
- Fix confirmed vulnerabilities in a timely manner, within our operational constraints. A fix
  ships in the source; every owner builds and signs their own image, so the advisory says which
  commit to build;
- Publish an advisory with credit once the fix is available, unless you'd rather not be named;
  and
- Extend Safe Harbor for your vulnerability research that is related to this policy.

## Our Expectations

In participating in our vulnerability disclosure program in good faith, we ask that you:
- Play by the rules, including following this policy and any other relevant agreements. If there
  is any inconsistency between this policy and any other applicable terms, the terms of this
  policy will prevail;
- Report any vulnerability you've discovered promptly;
- Test only on cameras you own or have explicit permission to test, and never on someone else's
  camera, network or recordings;
- Avoid violating the privacy of others: if you come across video, audio, images or personal data
  that isn't yours, stop, don't keep it, and tell us;
- Use only the Official Channels to discuss vulnerability information with us;
- Provide us a reasonable amount of time (at least 90 days from the initial report) to resolve the
  issue before you disclose it publicly; and
- Do not engage in extortion.

## Safe Harbor

When conducting vulnerability research according to this policy, we consider this research to
be:
- Authorized concerning any applicable anti-hacking laws, and we will not initiate or support
  legal action against you for accidental, good-faith violations of this policy;
- Authorized concerning any relevant anti-circumvention laws, and we will not bring a claim
  against you for circumvention of technology controls;
- Exempt from restrictions in our Terms of Service (TOS) and/or Acceptable Usage Policy (AUP)
  that would interfere with conducting security research, and we waive those restrictions on a
  limited basis; and
- Lawful, helpful to the overall security of the Internet, and conducted in good faith.

You are expected, as always, to comply with all applicable laws. If legal action is initiated by
a third party against you and you have complied with this policy, we will take steps to make it
known that your actions were conducted in compliance with this policy.

If at any time you have concerns or are uncertain whether your security research is consistent
with this policy, please submit a report through one of our Official Channels before going any
further.

Note that the Safe Harbor applies only to legal claims under the control of the organization
participating in this policy, and that the policy does not bind independent third parties, such as
the camera's manufacturer or the makers of the vendor files.

## Supported versions

Only the latest commit on `main`. Fixes are not backported.

> This policy follows the [disclose.io](https://disclose.io) vulnerability disclosure framework.
