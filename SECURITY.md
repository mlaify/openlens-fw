<!-- SPDX-License-Identifier: MIT -->
# Security reporting

This repository follows the
[mlaify organization-wide security reporting policy](https://github.com/mlaify/.github/blob/main/SECURITY.md).
That policy defines the reporting channel, maintainer limits, unsupported environments, and the
absence of payment, rewards, swag, response commitments, or remediation commitments.

Use this repository's **Security** tab and select **Report a vulnerability** for a credible,
confidential vulnerability in openlens-fw. Use a public issue for ordinary firmware bugs,
compatibility problems, feature requests, and documentation corrections.

Include the firmware version or commit, attacker prerequisites, safe reproduction steps, and
realistic impact. Remove MAC addresses, serial numbers, passwords, recovery codes, and RTSP URLs
containing credentials from logs and captures.

## Project-specific scope

**In scope:** code and build or installation tooling maintained in this repository, including the
firmware daemons, root filesystem, claim and recovery flow, settings backup, lock mode, update
signing and verification, and build and install scripts.

**Out of scope:**

- stock Anpviz or Anjoy firmware;
- vendor files under `vendor-blobs/`, except for a distinct vulnerability in how openlens-fw uses
  them;
- physical-access weaknesses and limits already documented in the
  [security model](https://docs.mlaify.io/openlens-fw/security-model/), unless the report
  demonstrates a distinct impact beyond the documented limit; and
- cameras, networks, accounts, recordings, or data the reporter does not own or have explicit
  permission to test.

Only the latest commit on `main` is considered for fixes. Fixes are not backported. The supported
firmware target and build environment are the ones documented by this repository; Windows is not
supported.
