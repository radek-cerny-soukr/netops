NetOps 1.0.6 follows NetOps 1.0.5. It fixes eight defects in the Helper, the SNMP worker, routing triage and the Auditor and refreshes the container base image. It adds no tool, changes no tool definition and no catalogue, and has no breaking change. The product remains one container with Helper, Auditor and Admin behind one audited HTTPS MCP endpoint. The syslog audit format and receiver requirements are unchanged.

## Changes in 1.0.6

- Helper redaction completely redacts quoted secrets that contain escaped quotes; an unclosed quote is redacted to the end of the line (#7.1).
- SNMPv3 authPriv `snmp_get` works in the shipped image; the worker no longer refuses it before the Helper policy (#7.3).
- Routing triage (`triage_routing`) correlates the next-hop ARP entry with the egress interface (#7.2).
- Auditor text output labels not-evaluated findings `(not-evaluated)` instead of `(gone)` (#7.8).
- Auditor refuses to write history when the platform changes under the same alias; use a new alias or a separate store (#7.4).
- Auditor finding detail for a carried finding names the run that holds its evidence (#7.6).
- Auditor REST collector refuses an answer with ambiguous framing: conflicting or non-numeric `Content-Length`, or `Content-Length` together with `Transfer-Encoding` (#7.5).
- Auditor `schema-check --full-snapshot --catalog-vdoms` refuses, before writing the report, a catalog coverage above the reader limit of 1600 entries instead of producing a report the reader rejects (#7.7).
- The container base image is refreshed to the current `python:3.14.10-alpine3.24` digest. This fixes `zlib` CVE-2026-4738 (Critical) and `openssh` CVE-2026-123158 (High), which were reported for the 1.0.5 image after its release; the other scan findings of 1.0.5 remain, because no fixed packages exist upstream yet (#7.9, see Known limitations).
- NetOps 1.0.6 upgrades the state of NetOps 1.0.5; see the upgrade procedure below.

See the CHANGELOG for the authoritative list.

## Upgrade from 1.0.5

Follow [Upgrade from the previous release](../docs/quickstart-1.0.md#upgrade-from-the-previous-release):

1. Check the 1.0.5 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.6 release files. Prepare a separate instance directory and a new Compose project with the same server name and port, and download the 1.0.6 image.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.5 to 1.0.6 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.5 to 1.0.6. A second start changes nothing. CA, keys, token, role data and connection details are unchanged.

Do not run `init` on the restored state. State of any other product version is refused; there is no skipped-release upgrade (1.0.4 must first be upgraded to 1.0.5).

For rollback, stop 1.0.6, preserve its audit records written after the backup, and start the unchanged 1.0.5 instance; see [Rollback](../docs/quickstart-1.0.md#rollback). A direct downgrade of a converted volume is not supported.

## Known limitations

- **Base image CVEs without an upstream fix (#7.9).** The scan of 2026-11-07 (Grype 0.121.2, database v6.1.10, amd64) of the refreshed image reports the same findings as the 1.0.5 image rebuilt with `--pull`: 0 Critical, 4 High, 11 Medium, 2 Low. Python 3.14.10 is the latest stable 3.14 release, and Alpine 3.24 offers no fixed `sqlite-libs` or `busybox`, so the findings cannot be removed today:
  - `python` 3.14.10: CVE-2025-15367 (Medium, fixed in 3.15.0a6), CVE-2026-116566 (Medium, fixed in 3.16.0), CVE-2026-103995 (Low, fixed in 3.16.0).
  - `sqlite-libs` 3.53.4-r0, no fixed version: High CVE-2026-119586, CVE-2026-119379, CVE-2026-119374, CVE-2026-119373; Medium CVE-2026-119378, CVE-2026-119375, CVE-2026-119371, CVE-2026-119376, CVE-2026-119591, CVE-2026-119372; Low CVE-2026-119377.
  - `busybox`, `busybox-binsh`, `ssl_client` 1.37.0-r31, no fixed version: CVE-2025-60876 (Medium).
- **Impact.** `netops-1.0.6-vulnerability-assessments.json` assesses each finding against the advisory text and the NetOps code. CVE-2025-15367, CVE-2026-103995 and CVE-2025-60876 are assessed as not exploitable in NetOps from its code, and so are four findings assessed on 2026-11-07: CVE-2026-119586 (a flaw of the `sqlite3` command-line shell, which NetOps never runs), CVE-2026-119379 (the session extension's changeset API, which Python's `sqlite3` module does not expose), CVE-2026-119377 (an `sqlite3_set_authorizer()` bypass, while NetOps sets no authorizer and accepts no SQL from a client) and CVE-2026-116566 (a null byte in a host name passed to `socket.getaddrinfo()`: every host name comes from the operator's private configuration or is validated first, never from an MCP client or a device; the Auditor REST collector and the Admin ntfy server do not reject a null byte, so this rests on that trust boundary). The eight remaining `sqlite-libs` findings are assessed as not exploitable in NetOps under its threat model: CVE-2026-119374, CVE-2026-119373, CVE-2026-119378, CVE-2026-119375, CVE-2026-119371, CVE-2026-119376, CVE-2026-119591 and CVE-2026-119372. NetOps submits no SQL that reaches them; the only path is a crafted store file in the Auditor's private state or in a restored backup, and whoever can plant such a file already controls the instance's state, which is outside the threat model. They remain present in the image and are not fixed; checking the schema object types of an opened store is planned hardening.
- **Next step.** The base image will be refreshed and the scan repeated as soon as fixed packages are available, probably in the next release. Until then 1.0.6 ships with these findings.

## Acceptance

The acceptance of 1.0.6 is proportional to its change and consists of these checks:

- The unit tests of the repository, including the state version, previous-release upgrade and start tests, `release/acceptance/tests` and `release/sign/tests`, and the acceptance suites of the candidate in GitHub Actions on amd64 and arm64.
- `release/acceptance/upgrade-check.sh` from 1.0.5 to 1.0.6. It compares whole tool definitions and role responses per JSON pointer against `release/acceptance/api-changes-1.0.5-1.0.6.json`, which declares no change; the check passes only if none is undeclared.
- An installation on Debian 13 and on Fedora Server 44 with SELinux enforcing, and the upgrade from a restored 1.0.5 state with the rollback to the unchanged 1.0.5 instance, each by following the README and the quickstart.
- An independent review of the changes since 1.0.5.
- The release signing tool with its documentation, checksum, registry and vulnerability checks on the candidate.

The results are the acceptance reports (`acceptance-*.json`) covered by the signed checksum list. The maintainer signs only a release whose required reports pass; a candidate without that signature is not a release.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.6-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.6-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.6-SHA256SUMS
```
