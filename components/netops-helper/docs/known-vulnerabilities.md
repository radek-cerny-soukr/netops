# Known vulnerability findings

## Exception record

This record lists every finding the release gate ignores and every finding this document reviews and ships without a fix. Each entry names the image it applies to by the manifest digest of the published ARM64 image (the `netops-helper-<version>-image-digest.txt` asset of the release page), the reason, the date of the last review and the condition that ends it.

For 0.3.8, the release assets identify the exact final image digest and its Grype scan. The release notes bind the reviewed exception to that image digest. The source record refers to those assets because embedding an image's own digest in a source file inside that image would change the digest.

| Finding | Package | Severity and gate | Images | Reason | Last review | Ends when |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-60002 | `openssh-client` `1:10.0p1-7+deb13u4` | Critical, ignored by the release gate (the only ignored entry) | 0.3.7 `sha256:c99b8c1343b9c65845e89ea3d748d5f29a7ef91cab4b652a21da131a3317823e`; 0.3.8 exact image identified by its release image-digest asset; accepted since 0.3.0 (release scan of 18 September 2026) | Debian trixie marks it `no-dsa` and ships no fixed package; the upstream fix is OpenSSH 10.4 and trixie stays on 10.0. Exposure and containment: [Existing OpenSSH exception](#existing-openssh-exception) | 5 October 2026: Debian tracker lists the trixie and trixie-security packages as vulnerable, `<no-dsa>`, fixed only in forky and sid | The image ships an `openssh-client` with the fix (a trixie update, a reviewed backport or a base with OpenSSH 10.4 or newer), shown by its SBOM and Grype report; the ignore rule is then removed |
| CVE-2026-59999, CVE-2026-60000 | `openssh-client` `1:10.0p1-7+deb13u4` | High, active (`wont-fix`), reported, not ignored | 0.3.7 `sha256:c99b8c1343b9c65845e89ea3d748d5f29a7ef91cab4b652a21da131a3317823e`; 0.3.8 exact image identified by its release image-digest asset | Both concern the SSH server; the image installs the client package only | 2 October 2026: the layers of the published 0.3.7 OCI archive contain `usr/bin/ssh` and `usr/bin/ssh-keyscan` and no `sshd`, `sshd-session` or `sshd-auth` | Debian ships a fixed `openssh-client`, or an image contains SSH server code (then the reachability argument no longer holds and the finding needs a new review) |

The ignore rule of CVE-2026-60002 names the package version: a build that installs any other `openssh-client` version is no longer covered by it, and an active Critical match then blocks the release until the new package is reviewed. The other active High, Medium and Low matches are distribution packages labelled `wont-fix` or `not-fixed`; they are listed in the Grype report of each image and are not reviewed one by one here.

## Helper 0.3.9 installation-fix release

This release changes installation documentation, archive tests and version pins. It keeps the digest-pinned Python 3.14.8 base and runtime lock of 0.3.8. A fresh build, image SBOM and full Grype scan are required; its release notes bind the exact image digest and counts. Earlier scans remain historical evidence.

At the 6 October 2026 review, the [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-60002) still marks trixie openssh-client 1:10.0p1-7+deb13u4 as vulnerable with no-dsa. The existing package-version-specific CVE-2026-60002 exception applies to 0.3.9 only if its actual SBOM has that exact version; no ignore rule is added or widened. The unresolved Python findings below remain explicit, including the still-open [3.14 TemporaryDirectory backport](https://github.com/python/cpython/pull/158430).

## Helper 0.3.8 candidate scan

Helper 0.3.8 updates the official digest-pinned slim-trixie ARM64 base to Python 3.14.8 and its locked PyJWT dependency to 2.15.0. The image still applies available Debian upgrades before installing openssh-client. No vulnerability ignore rule is added or widened.

Python 3.14.8 fixes CVE-2026-17084, CVE-2026-19672, CVE-2026-15806 and CVE-2026-15310, according to the [Python release announcement](https://www.python.org/downloads/release/python-3148/). PyJWT 2.15.0 fixes the pre-verification recursive-payload exception described in [GHSA-42vr-xj54-vc7v](https://github.com/advisories/GHSA-42vr-xj54-vc7v). The isolated reproducer returns RecursionError on 2.14.0 and DecodeError on 2.15.0.

The final image is built and scanned from the signed release commit. Its image SBOM and full Grype JSON are authoritative for installed package versions, active matches and ignored matches. Review the digest and severity counts in the release notes against those exact assets; reports of earlier 0.3.8 candidates are historical evidence.

Package matches are not a count of distinct flaws or proven exploitable paths. The existing package-version-specific Critical exception remains explicit. Active High, Medium and Low distribution findings remain visible even when the release policy permits them.

### Fixed in 0.3.4, first published in 0.3.5: Python TAR extraction

CVE-2026-82049 allowed hard-link extraction to relocate a relative symbolic link so that it could expose or change a file outside the destination. The fix moved the runtime to Python 3.14.7 in 0.3.4; the tag `netops-helper/v0.3.4` never got a release page, so 0.3.5 is the first published image with it. An isolated regression reproduces the outside-file modification on 3.13.15, verifies its absence on the updated runtime with both `data` and `tar` filters, and verifies valid regular files and hard links still extract successfully.

Sources: [CPython issue and correction](https://github.com/python/cpython/issues/157190), [security announcement](https://mail.python.org/archives/list/security-announce@python.org/thread/EFJWGAZJA56AKSBR2WHMHQZO7RRLZPRH/).

### Remaining Python findings

The 3.14.8 candidate retains these Python matches; none is claimed fixed or ignored:

- CVE-2026-87910: the tarfile link-fallback correction for 3.14 merged on 1 October, after the 3.14.8 release. [3.14 backport](https://github.com/python/cpython/pull/157307).
- CVE-2025-15367: poplib control-character handling; upstream did not backport the behavior change to this branch. [Correction](https://github.com/python/cpython/pull/143924).
- CVE-2026-12345: TemporaryDirectory cleanup race; the 3.14 backport remains open at the 5 October review. [3.14 backport](https://github.com/python/cpython/pull/158430).

Core host-key probing uses TemporaryDirectory, so modification of its tree by another local actor during cleanup is a relevant condition. Private permissions do not fix compromise of the same user. First-party application paths do not use POP or archive extraction for this assessment; that observation does not prove absence of all dependency reachability.

A correction version for another branch does not establish this branch is fixed. Review the complete exact-image report, digest and current upstream status; this release does not claim a zero-finding image.

## Existing OpenSSH exception

CVE-2026-60002 remains present in `openssh-client` 1:10.0p1-7+deb13u4 and remains the single previously accepted Critical exception. The upstream correction is available in OpenSSH 10.4, but the Debian trixie package is still marked vulnerable and `no-dsa` by the Debian tracker (checked on 5 October 2026; the fixed version is only in forky and sid). This release neither introduces a new exception nor claims the client flaw is fixed.

A malicious SSH server can trigger a client-side use-after-free during host-key re-exchange. Host-key pinning restricts the helper to enrolled devices; it does not make a compromised enrolled device safe. Short-lived processes, an unprivileged user, a read-only container, dropped capabilities and runner egress restrictions reduce exposure but do not repair the vulnerable client or prove exploitation is contained.

Fixing this while the distribution lacks an updated package requires a separately maintained backport/custom client or a reviewed change of the image distribution. Those are possible engineering choices, not an available dependency bump within the current baseline. Operators who do not accept the documented exposure should not deploy this release.

Sources: [Debian package status](https://security-tracker.debian.org/tracker/CVE-2026-60002), [OpenSSH release notes](https://www.openssh.org/releasenotes.html#10.4p1).

## Other distribution findings

The remaining High entries are recorded as `wont-fix` or `not-fixed` in the scan. These scanner labels do not establish exploitability or guarantee that a package will never receive a correction. Multiple binary packages from one source package can repeat the same CVE.

CVE-2026-59999 and CVE-2026-60000 concern SSH server functionality. The image installs `openssh-client`, not `openssh-server`; the layers of the published 0.3.7 image contain no `sshd`, `sshd-session` or `sshd-auth` (checked on 2 October 2026). Their package matches remain visible, rather than being silently ignored. That reachability assessment does not apply to the client-side CVE-2026-60002.

Sources: [forwarding policy finding](https://security-tracker.debian.org/tracker/CVE-2026-59999), [GSSAPI finding](https://security-tracker.debian.org/tracker/CVE-2026-60000).

## Release checks

Every build must scan its exact image with a current valid vulnerability database and retain both active and ignored matches. Active Critical findings block the release. Each ignored Critical finding requires an applied rule and an explicit risk review, recorded in the [exception record](#exception-record) with the digest of the released image. High and Medium findings remain disclosed even when policy allows the release. Remove an exception only after verifying the corresponding package is fixed; neither a renamed image nor a source-version string is sufficient evidence.

Helper 0.3.3 and the earlier 0.3.4 candidate had 51 active High matches, and 0.3.6 had 50 on 21 September; the same packages now match 51 with a newer database. Historical reports describe their images on their date. Repeat the scan and review for every rebuilt image.
