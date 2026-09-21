# Known vulnerability findings

## Helper 0.3.6 runtime scan

Helper 0.3.6 uses the official Python 3.14.7 slim-trixie ARM64 image pinned by digest and installs `openssh-client` from Debian trixie after applying available package upgrades. Its Python dependency versions are unchanged from the reviewed 20 September update; both Helper lockfiles have been regenerated for Python 3.14.7 with the same hash-pinned generator.

The 21 September 2026 Grype 0.118.0 scan of the rebuilt runtime reports:

| Report entries | Critical | High | Medium | Low | Negligible | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Active (`matches`) | 0 | 50 | 58 | 10 | 68 | 1 |
| Existing reviewed exception (`ignoredMatches`) | 1 | 0 | 0 | 0 | 0 | 0 |

The image SBOM and full Grype JSON accompanying each build are authoritative. These are package matches, not a count of distinct flaws or proven exploitable paths. Compared with the previous 0.3.4 candidate, the only removed package/CVE match is CVE-2026-82049 in Python. No new package/CVE match was added. No finding was hidden or downgraded to achieve the reduction.

### Fixed: Python TAR extraction

CVE-2026-82049 allowed hard-link extraction to relocate a relative symbolic link so that it could expose or change a file outside the destination. The runtime now uses Python 3.14.7. An isolated regression reproduces the outside-file modification on 3.13.15, verifies its absence on the updated runtime with both `data` and `tar` filters, and verifies valid regular files and hard links still extract successfully.

Sources: [CPython issue and correction](https://github.com/python/cpython/issues/157190), [security announcement](https://mail.python.org/archives/list/security-announce@python.org/thread/EFJWGAZJA56AKSBR2WHMHQZO7RRLZPRH/).

### Remaining Python findings

The scan still reports Python entries at Medium and Low severity. Four list a fix in the Python 3.15 prerelease series; two have no fix version in the scan. This release does not move the runtime to a prerelease or claim these findings are fixed. The complete report retains them for review.

## Existing OpenSSH exception

CVE-2026-60002 remains present in `openssh-client` 1:10.0p1-7+deb13u4 and remains the single previously accepted Critical exception. The upstream correction is available in OpenSSH 10.4, but the Debian trixie package is still marked vulnerable and `no-dsa` by the Debian tracker. This release neither introduces a new exception nor claims the client flaw is fixed.

A malicious SSH server can trigger a client-side use-after-free during host-key re-exchange. Host-key pinning restricts the helper to enrolled devices; it does not make a compromised enrolled device safe. Short-lived processes, an unprivileged user, a read-only container, dropped capabilities and runner egress restrictions reduce exposure but do not repair the vulnerable client or prove exploitation is contained.

Fixing this while the distribution lacks an updated package requires a separately maintained backport/custom client or a reviewed change of the image distribution. Those are possible engineering choices, not an available dependency bump within the current baseline. Operators who do not accept the documented exposure should not deploy this release.

Sources: [Debian package status](https://security-tracker.debian.org/tracker/CVE-2026-60002), [OpenSSH release notes](https://www.openssh.org/releasenotes.html#10.4p1).

## Other distribution findings

The remaining High entries are recorded as `wont-fix` or `not-fixed` in the scan. These scanner labels do not establish exploitability or guarantee that a package will never receive a correction. Multiple binary packages from one source package can repeat the same CVE.

CVE-2026-59999 and CVE-2026-60000 concern SSH server functionality. The image installs `openssh-client`, not `openssh-server`; earlier layer inspection found no `sshd` or `sshd-session`. Their package matches remain visible, rather than being silently ignored. That reachability assessment does not apply to the client-side CVE-2026-60002.

Sources: [forwarding policy finding](https://security-tracker.debian.org/tracker/CVE-2026-59999), [GSSAPI finding](https://security-tracker.debian.org/tracker/CVE-2026-60000).

## Release checks

Every build must scan its exact image with a current valid vulnerability database and retain both active and ignored matches. Active Critical findings block the release. Each ignored Critical finding requires an applied rule and an explicit risk review. High and Medium findings remain disclosed even when policy allows the release. Remove an exception only after verifying the corresponding package is fixed; neither a renamed image nor a source-version string is sufficient evidence.

Helper 0.3.3 and the earlier 0.3.4 candidate had 51 active High matches. Their historical reports describe those images, not the corrected runtime. Repeat the scan and review for every rebuilt image.
