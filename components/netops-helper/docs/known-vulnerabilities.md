# Known vulnerability findings

## Published 0.1.0 snapshot

Release 0.1.0 uses the digest-pinned official Python 3.12.14 slim-trixie ARM64 base image. Its published Grype JSON contains:

- 7 reviewed Critical entries under `ignoredMatches`;
- 61 active High entries under `matches`;
- 56 active Medium entries under `matches`.

The seven reviewed Critical entries affect Debian base packages. Debian classified the underlying issues as minor, postponed, or not requiring a stable Trixie advisory at the time of that release.

| Finding | Package and version | Debian assessment | Runtime relevance |
| --- | --- | --- | --- |
| CVE-2026-5450 | libc-bin 2.41-12+deb13u3 | no-DSA, minor | Requires a specific GNU scanf format and explicit width over 1024; no known helper path uses it. |
| CVE-2026-5450 | libc6 2.41-12+deb13u3 | no-DSA, minor | Same narrowly triggered glibc issue; no known helper path uses it. |
| CVE-2026-8376 | perl-base 5.40.1-6 | no-DSA, minor | The memory corruption applies to 32-bit Perl; the maintained image is ARM64. |
| CVE-2026-13221 | perl-base 5.40.1-6 | no-DSA, minor | Requires compiling an attacker-controlled Perl regex with more than 65,535 fixed branches; the helper does not invoke Perl. |
| CVE-2026-42496 | perl-base 5.40.1-6 | postponed, minor | Requires extracting an attacker-controlled archive through Perl Archive::Tar; the helper does not invoke Perl. |
| CVE-2026-12087 | perl-base 5.40.1-6 | no-DSA, minor | Requires attacker-controlled input to a Perl Socket function; the helper does not invoke Perl. |
| CVE-2026-57433 | perl-base 5.40.1-6 | no-DSA, minor | Requires Perl Storable to deserialize a crafted record; the helper does not invoke Perl. |

Authoritative Debian records:

- https://security-tracker.debian.org/tracker/CVE-2026-5450
- https://security-tracker.debian.org/tracker/CVE-2026-8376
- https://security-tracker.debian.org/tracker/CVE-2026-13221
- https://security-tracker.debian.org/tracker/CVE-2026-42496
- https://security-tracker.debian.org/tracker/CVE-2026-12087
- https://security-tracker.debian.org/tracker/CVE-2026-57433

These are risk acceptances, not claims that packages are fixed. The 0.1.0 JSON retains each exception with its applied rule. The active High and Medium counts were not ignored, fixed, or absent; they remained part of the operator's review burden. The phrase "seven reviewed findings" refers only to the Critical ignore set, never to the complete scan.

## Published 0.2.0 snapshot

Release 0.2.0 keeps the same digest-pinned base image and its published Grype JSON contains the same counts as 0.1.0: 7 reviewed Critical entries under `ignoredMatches`, 61 active High entries, and 56 active Medium entries under `matches`. The seven Critical exceptions are the same CVE, package, and version rows listed above; the table applies unchanged. Equal counts across two releases are a coincidence of one scan date, not a guarantee.

## 0.3.0: one Critical entry shipped unfixed, by decision

**Read this before deploying 0.3.0.** The release ships a known Critical vulnerability in the `ssh` client it runs, and it is not fixed, not worked around, and not fixable inside this project. It is accepted, dated and documented, which is the whole of what this project can do about it.

0.3.0 installs `openssh-client` into the image, because the SSH transport of the family is the OpenSSH client (see `docs/security-model.md`). The package comes from the digest-pinned Debian trixie base image and is not pinned to a version in the Dockerfile; the version the image carries is the one trixie ships at build time and is recorded in the release SBOM. The first release scan of the 0.3.0 tree (18 September 2026, Grype over the Python 3.13.15 slim-trixie ARM64 image) therefore carries one more Critical entry than 0.2.x. The fix exists upstream (OpenSSH 10.4) but trixie stays on 10.0 and Debian rates the issue no-DSA, minor, so there is no package update to install and no dependency bump this project could make. The choice was between shipping with the exception below, dropping the OpenSSH transport the whole family is built on, or leaving the pinned distribution; the project owner chose the exception:

| Finding | Package and version | Debian assessment | Runtime relevance |
| --- | --- | --- | --- |
| CVE-2026-60002 | openssh-client 1:10.0p1-7+deb13u4 | no-DSA, minor; fixed upstream in OpenSSH 10.4, trixie stays on 10.0 | Client-side use-after-free when the *server* changes its host key during a key re-exchange. The only servers the helper talks to are enrolled devices with a pinned host key, each call is one short `ssh`/`sftp` process (timeouts of seconds, snapshots capped at 2 MB, no multiplexing), and the process runs as an unprivileged user in a read-only container with every capability dropped. A device that triggers the bug is a compromised enrolled device, which the security model already treats as a hostile input source; the exposure is the collector process, not the host. Reviewed at every release; the exception is dropped the moment trixie ships an OpenSSH at or above 10.4. |

Reference: https://security-tracker.debian.org/tracker/CVE-2026-60002

What this means for an operator, stated plainly:

- The `ssh` and `sftp` processes the helper starts are vulnerable to a malicious or compromised SSH *server*. The helper connects only to devices enrolled with a pinned host key, so the attacker has to already control an enrolled device.
- Nothing in this release detects or blocks an exploitation attempt. The containment is the process boundary: one short-lived process per call, an unprivileged user, a read-only root filesystem, every capability dropped, and the egress policy of the runner.
- If that exposure is not acceptable in your environment, do not deploy 0.3.0 as published. Rebuild the image on a base that ships OpenSSH 10.4 or newer (the Dockerfile takes the base image as its first line), or wait for a release whose base carries the fix.
- The exception is re-reviewed at every release and is dropped the moment trixie ships OpenSSH 10.4 or newer; the release notes of every later version say whether it still applies.

## 0.2.0 and later

Vulnerability counts are scan snapshots and must not be copied forward as immutable gates. Database updates, base-image rebuilds, package changes, and matching changes can alter every severity.

The tree now pins the official Python 3.13.15 slim-trixie base image. The counts and the Critical table above describe the 3.12.14 image of those two published snapshots and state nothing about the current base image, which needs its own scan.

For each candidate, publish the complete Grype JSON and count both `matches` and `ignoredMatches` across Critical, High, Medium, Low, Negligible, and Unknown. Active Critical findings stop the release. Every ignored Critical requires an applied rule and explicit risk review. Active High/Medium findings also require review and disclosure even when they do not automatically fail the gate.

Remove exceptions when fixed packages become available. Operators remain responsible for evaluating all active and ignored findings against their environment, updating the image, restricting credentials and egress, and rebuilding when fixes are published. The MIT license provides the software without warranty.
