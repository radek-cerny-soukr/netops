# Known vulnerability findings

This page describes the vulnerability scan of the current release image and the one finding it ships unfixed by decision. The authoritative report is the Grype JSON attached to the release page next to the image digest; the counts below were read from a scan of the same tree, built on the same base image digest, with the Grype database of the release day. Counts are scan snapshots: a database update, a base image rebuild, or a matcher change alters every severity, so a number on this page is tied to the report it came from and is never a gate for a later build.

## What the scan of this release contains

The image is built from the digest-pinned official Python 3.13.15 slim-trixie ARM64 base image plus the single distribution package `openssh-client`. The scan over the resulting image contains:

| | Critical | High | Medium | Low | Negligible | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| active (`matches`) | 0 | 51 | 58 | 10 | 68 | 1 |
| reviewed and ignored (`ignoredMatches`) | 1 | 0 | 0 | 0 | 0 | 0 |

- The one ignored Critical entry is CVE-2026-60002 in `openssh-client`, described in the next section. It is the only ignore rule the release gate applies to this image; every Critical entry Debian has since fixed in the base image is gone from the scan rather than ignored.
- Of the 51 active High entries, one has a fixed version anywhere: CVE-2026-82049 in the `python` interpreter itself, fixed in Python 3.14.0b1 and in no 3.13 release the base image could carry. The other 50, and every Medium, Low, Negligible and Unknown entry, are marked not fixed in Debian trixie.
- The one Unknown entry is CVE-2026-82560 in `perl-base`, which Debian has not assessed; the helper does not invoke Perl.

The release gate requires both `matches` and `ignoredMatches` in the report, counts every severity, fails on an active Critical entry, and requires an applied ignore rule with a written risk review for every ignored Critical entry. Active High and Medium entries do not fail the gate; they are disclosed here and stay part of the operator's review.

## One Critical entry shipped unfixed, by decision

**Read this before deploying.** The release ships a known Critical vulnerability in the `ssh` client it runs, and it is not fixed, not worked around, and not fixable inside this project. It is accepted, dated and documented, which is the whole of what this project can do about it.

The image installs `openssh-client` because the SSH transport of the family is the OpenSSH client (see `docs/security-model.md`). The package comes from the digest-pinned Debian trixie base image and is not pinned to a version in the Dockerfile; the version the image carries is the one trixie ships at build time and is recorded in the release SBOM. The fix exists upstream (OpenSSH 10.4) but trixie stays on 10.0 and Debian rates the issue no-DSA, minor, so there is no package update to install and no dependency bump this project could make. The choice was between shipping with the exception below, dropping the OpenSSH transport the whole family is built on, or leaving the pinned distribution; the project owner chose the exception:

| Finding | Package and version | Debian assessment | Runtime relevance |
| --- | --- | --- | --- |
| CVE-2026-60002 | openssh-client 1:10.0p1-7+deb13u4 | no-DSA, minor; fixed upstream in OpenSSH 10.4, trixie stays on 10.0 | Client-side use-after-free when the *server* changes its host key during a key re-exchange. The only servers the helper talks to are enrolled devices with a pinned host key, each call is one short `ssh`/`sftp` process (timeouts of seconds, snapshots capped at 2 MB, no multiplexing), and the process runs as an unprivileged user in a read-only container with every capability dropped. A device that triggers the bug is a compromised enrolled device, which the security model already treats as a hostile input source; the exposure is the collector process, not the host. |

Reference: https://security-tracker.debian.org/tracker/CVE-2026-60002

What this means for an operator, stated plainly:

- The `ssh` and `sftp` processes the helper starts are vulnerable to a malicious or compromised SSH *server*. The helper connects only to devices enrolled with a pinned host key, so the attacker has to already control an enrolled device.
- Nothing in this release detects or blocks an exploitation attempt. The containment is the process boundary: one short-lived process per call, an unprivileged user, a read-only root filesystem, every capability dropped, and the egress policy of the runner.
- If that exposure is not acceptable in your environment, do not deploy the image as published. Rebuild it on a base that ships a fixed `openssh-client` (the Dockerfile takes the base image as its first line), or wait for a release whose base carries the fix.

**The exception ends at a fixed package, not at an upstream version number.** In this image the installed `openssh-client` package reports `1:10.0p1-7+deb13u4`, while the binary itself answers `ssh -V` with `OpenSSH_10.0p2 Debian-7+deb13u4` - the package's declared version and the binary's own self-reported version disagree in this one image, so tracking "upstream reaches 10.4" is not a reliable signal of when trixie carries a fix. The exception is re-reviewed at every release against the state of the Debian package, and is dropped the moment a rebuild's scan shows a fixed `openssh-client` package, whatever version number that package then reports.

## The other `openssh-client` entries

The scanner attributes 20 entries to the installed `openssh-client` package: the Critical entry above, 2 High (CVE-2026-59999, CVE-2026-60000), 6 Medium, 3 Low and 8 Negligible. Debian marks the three entries of 2026 that are rated Critical or High **wont-fix**.

A package match is not the same claim as a reachable vulnerability. CVE-2026-60002's client-side use-after-free is exercised by the code this image actually runs, and the reviewed exposure above stands as written. CVE-2026-59999 and CVE-2026-60000 are different: per their primary Debian tracker descriptions, the vulnerable code is in `sshd`, not in the SSH client. This image installs only `openssh-client` (see `Dockerfile`); it never installs `openssh-server`, never runs `sshd`, and carries no unit or entrypoint that starts it. Debian ships both binaries from the same source package, so Grype's package-version match against `openssh-client` does not by itself demonstrate that this image contains or exercises the `sshd` code path the two advisories describe; it demonstrates only that the installed package version is the one the advisory names. Confirming or ruling out reachability for these two findings would need reading what the specific vulnerable function is and whether any code outside `sshd` shares it - work not yet done for this document, so both stay listed as active High entries rather than argued away.

References: https://security-tracker.debian.org/tracker/CVE-2026-59999, https://security-tracker.debian.org/tracker/CVE-2026-60000

## How the scan is read at every release

For each candidate, publish the complete Grype JSON and count both `matches` and `ignoredMatches` across Critical, High, Medium, Low, Negligible and Unknown. Active Critical findings stop the release. Every ignored Critical requires an applied rule and explicit risk review. Active High and Medium findings require review and disclosure even when they do not fail the gate.

Remove exceptions when fixed packages become available. Operators remain responsible for evaluating all active and ignored findings against their environment, updating the image, restricting credentials and egress, and rebuilding when fixes are published. The MIT license provides the software without warranty.
