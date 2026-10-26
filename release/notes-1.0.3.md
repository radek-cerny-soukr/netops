NetOps 1.0.3 follows NetOps 1.0.2 and upgrades the state of an instance of NetOps 1.0.2. It is a corrective release of the same single product: one container image that runs the Helper, Auditor and Admin roles behind one audited HTTPS MCP endpoint. Apart from the audited response delivery controls in the gateway, the runner SSH diagnostics of the Helper (the negotiation message and the classification of failures), the status wait of the health check and the recorded product version, the product code is unchanged. A login banner of the runner that does not reproduce an OpenSSH client message no longer changes the category of a runner SSH failure that the Helper reports, and a failed remote command is never reported in an SSH category. The syslog audit format and the receiver requirements of 1.0.2 stay as they are.

## Changes in 1.0.3

- Gateway: after an audited response and its audit commit are recorded, its delivery has one absolute deadline of 60 seconds that progress does not reset. An observed client disconnect, a timeout or cancellation, or a failed send during the delivery leads to an attempt to record `interrupted` delivery with `automatic_retry` false and `operation_may_have_completed`, followed by a `connection_end` with delivery `interrupted`, and the operation slot is released. See [Response delivery](#response-delivery).
- The Helper SSH connection to a runner host keeps the message of the OpenSSH client about a failed algorithm negotiation (client log level `INFO` instead of `ERROR`) and reports it as `ssh_negotiation`: `SSH algorithm negotiation with the runner failed. Update the runner SSH service or review its allowed algorithms.` The message names neither the host nor the offered algorithms; the algorithms that the client offers are unchanged. An SSH category (`ssh_host_key`, `ssh_negotiation`, `ssh_authentication`, `ssh_connection`) is reported only when the SSH client itself fails with exit status 255; any other exit status comes from the remote command and is reported as `remote_exec` or `ssh_transport`, as in 1.0.2. The category is decided by the last line of the client standard error other than the closing `Disconnected from ...` line of OpenSSH, matched against the exact OpenSSH client messages, and the Helper keeps the last 64 KiB of that output instead of the first, so a login banner of the runner, which the `INFO` level prints, neither changes the category nor pushes the real error out unless its last line reproduces such an OpenSSH message.
- The health check `netops health` queries the roles at the same time and waits up to 5 seconds instead of 2 in total for their status answers, so single runs of the container healthcheck no longer fail while the Helper redacts an SSH output of 2 MB to 16 MiB on a slow CPU; a role that does not answer within these 5 seconds still fails the check, within the 10-second timeout of the container healthcheck.
- Upgrade the state of NetOps 1.0.2: the first start of 1.0.3 converts its state under the instance lock and changes only the recorded product version, in the same way as the upgrade from 1.0.1 to 1.0.2.

## Response delivery

The gateway validates the buffered ASGI response before committing its response audit. An invalid start/body/completion sequence takes the existing operation-failed path: interrupted outcome, an audited 503 response and no committed-before-send delivery record.

After a valid response and its audit commit are recorded, its ASGI send sequence has one absolute deadline of 60 seconds for all parts, including delivery-task cleanup and the final send. Progress does not reset it. This deadline does not cover admission waiting, operation execution, audit persistence, or direct gateway error and health responses. Previously a blocked send could keep its operation slot without this deadline.

During body delivery the gateway watches the ASGI receive channel for http.disconnect because the shipped uvicorn h11 send can return silently after a disconnect. An observed disconnect, timeout, cancellation, receive-channel failure or send failure triggers an attempt to record interrupted delivery with automatic_retry false and operation_may_have_completed, followed by connection_end with delivery interrupted. These records require a writable audit. The operation slot is released even when recording the interruption fails. An observed http.disconnect returns after that audit tail without raising an application exception; timeout, cancellation and unexpected channel errors still propagate.

Body writes are limited to 32 KiB, and an additional nonterminal send checks backpressure after the last payload. The sole receive watcher is stopped and awaited before the terminal send, so normal response completion is not mistaken for a disconnect. A response that fits in the transport buffer, or a close after the monitored phase, can go unobserved. Completion of the ASGI send sequence does not prove that the client received or read the response. Inspect audit pending, the recorded response and the device before repeating an operation; never retry writes automatically.

## Release process

- The privacy gate of the release reports (`release/report_gate.py`) also decodes canonical standard and URL-safe base64 text, within shared limits for decoding layers and bytes, before it searches the reports for private markers and private paths. Decoded content that is not UTF-8 text is searched without its NUL bytes, which covers UTF-16, and by its printable runs of at least 8 characters. The public host-name checks do not decode base64, so Docker manifest and configuration JSON embedded in the Grype reports raises no false host findings.
- The platform smoke check of the release acceptance (`release/acceptance/platform_smoke.sh`) installs `python3` together with `ca-certificates` and `curl` on hosts with apt before its checks.
- Each architecture SBOM is validated offline against the complete, pinned CycloneDX 1.7 JSON schema before a release candidate is written; the SBOM must list components and its root container must match the exact image name and architecture digest.
- The source privacy gate (`release/check_source.py`) skips only its domain check for the five vendored CycloneDX 1.7 schema files in `release/schema/cyclonedx-1.7/`, including the SPDX license schema, and only while each file matches its pinned SHA-256; every other check still applies to them.
- Open placeholders in the public documentation (`release/placeholder_gate.py`): the candidate workflow refuses to build a release candidate while its release notes are missing, its changelog has no section of its version or its public documentation carries a placeholder other than the acceptance placeholder of that version (`acceptance-X.Y.Z`) and the release-date placeholder (`release-date`) in the heading of its changelog section. These two are filled after the acceptance of the candidate digests, so the candidate is not rebuilt for them. The signing tool (`release/sign/netops-release-sign.ps1`) takes the source checkout of the release with `-SourceDir` and refuses to sign while its Markdown still carries any placeholder, its release notes are missing or the changelog section of its version has no date.

## Documentation

- Quickstart: script forms of steps 7 and 8 (`-T` and `< /dev/null` also for `up` and `ps`, its own block for `ca`, `token show` and `connection`); step 7 names the `Container ... Creating`/`Created` lines of `docker compose run` as Compose progress on standard error; step 9 counts the tools of an authenticated `tools/list` over `curl` and shows how to find the step 9 requests in the audit.
- Quickstart upgrade: the check lists the `instance_start` records with a ready `jq` filter, the variable block sets `umask 077` so that `netops-ca.pem` stays private in a new shell, the hint about `-p` that `connection` prints does not apply in the directory of the new instance, and the directory of the previous instance is found from its Compose label.
- Document the upgrade from 1.0.2 to 1.0.3 in the quickstart with the structure of the upgrade from 1.0.1 to 1.0.2, including an instance of 1.0.2 that was itself upgraded from 1.0.1 (`~/netops-1.0.2`, project `netops-102`).
- Helper tools and README: `ftp_list` is refused in the shipped profile before any device contact; its engine checks the path against `sftp_roots` only lexically (see [Known limitations](#known-limitations)).
- Admin configuration: how NetOps ends an Admin FortiOS operation with `unknown` and `safeguard_kept` (it reads no firing record from FortiOS and waits until `safeguard.fire_at` plus 20 seconds), and how to prove on the device that the safeguard stitch fired, with the measured firing delay of 0.1 to 5 seconds on a FortiGate 80F with FortiOS 8.0.2 and a FortiGate 60F with FortiOS 7.6.7.
- README: the covered assets of the signed checksum list are named by kind, and the checksum list itself is the complete list.

## Acceptance

NetOps 1.0.3 is a corrective release and was accepted in proportion to its change: CI suites and engine tests of the candidate image in GitHub Actions on amd64 and arm64, a blind installation by the README and the quickstart on Fedora Server 44 and Debian 13 on amd64, a blind upgrade from 1.0.2 to 1.0.3 on amd64 and an independent code review. Ubuntu, Raspberry Pi OS, arm64 hosts and rootless Docker were not installed by a blind run for 1.0.3.

## Upgrade from 1.0.2

Follow [Upgrade from the previous release](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/quickstart-1.0.md#upgrade-from-the-previous-release). The upgrade has four steps:

1. Check the 1.0.2 instance, stop it and back it up as described in [Before the upgrade](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/quickstart-1.0.md#before-the-upgrade).
2. Download and verify the 1.0.3 release files, then prepare a clean 1.0.3 instance in a new directory, with the same server name and port and a `.env` with the 1.0.3 image.
3. Restore the backup into it as described in the same section of the quickstart.
4. Start it; the restore block of the quickstart ends with the start. The first start of 1.0.3 converts the restored state of 1.0.2 under the instance lock.

A syslog receiver configured for 1.0.2 stays unchanged. State of any other product version or state schema is refused, there is no upgrade that skips a release and no downgrade: upgrade an instance of NetOps 1.0.1 to 1.0.2 first, as described in the [1.0.2 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/release/notes-1.0.2.md), and an instance of NetOps 1.0.0 to 1.0.1 before that, including its syslog receiver change described in the [1.0.1 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/release/notes-1.0.1.md). The 1.0.2 instance, its directory and its state volume stay unchanged. Rollback: stop the 1.0.3 instance, export its audit records written after the backup as described in [Rollback](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/quickstart-1.0.md#rollback) and start the original 1.0.2 instance.

## Known limitations

- The separate Helper SSH proxy to a runner host supports both keyboard-interactive and password authentication. When a server offers both methods, one connection with an incorrect password can cause two failed authentication attempts, which may count under the runner account's lockout policy.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request. Other authenticated requests can use the remaining slots within the shared limit of 16.
- 1.0.3 upgrades only NetOps 1.0.2; it does not upgrade or migrate 0.x installations or data.
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- `ftp_list` is refused in the shipped SSH/HTTPS-only profile before any device contact, and no configuration enables it. Its engine checks the requested path against the target's `sftp_roots` only lexically; unlike `sftp_stat`, it does not let the server resolve the path, so a symbolic link below a root that leads out of it would not be refused.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check uses a nominal 50 ms sampling interval and can miss processes that start and exit between observations; the [1.0.1 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/release/notes-1.0.1.md#known-limitations) give the exact attribution rule.
- When the converting first start of 1.0.3 stops after the conversion, for example because a role refuses its configuration or the start is interrupted, no audit record names the upgrade. The only indirect evidence is the version in the last 1.0.2 records and in the next `instance_start` of 1.0.3, and only with audit history kept from before the upgrade; see [Refused first start](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/quickstart-1.0.md#refused-first-start).
- The SHA-256 of a syslog record detects damaged or incomplete part archives. It does not prove the authenticity of data that an attacker controlled before the record was complete.
- Audit events suppressed before NetOps sends them cannot be detected from the receiver archive.

Details: [verified support](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/verified-support.md) and [security](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/SECURITY.md).

## Install

Follow [the quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/docs/quickstart-1.0.md). In short: download `compose.yaml`, `env.example`, `netops-1.0.3-manifest.json`, `netops-1.0.3-SHA256SUMS` and `netops-1.0.3-SHA256SUMS.sigstore.json` from this release, verify them, set the bind address, port and server name, then run `init` and start the service.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.3-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.3-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.3-SHA256SUMS
```

The checksum list covers `compose.yaml`, `env.example`, the release manifest, which records the image index and per-architecture digests, the acceptance manifest, the per-architecture SBOMs, vulnerability scans and scan gate results, the vulnerability assessments and the acceptance reports (`acceptance-*.json`); the checksum list itself is the complete list of covered files. `env.example` already pins the image by that index digest. A download is verified only after both commands succeed.

## Security

Every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild. Each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding, of any severity, ships with a written assessment (`netops-1.0.3-vulnerability-assessments.json`). SBOMs cover the application, its Python dependencies and the operating-system packages. The Core SFTP banner fix of 1.0.2 is described in the [1.0.2 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.3/release/notes-1.0.2.md#security-fix). The release tooling, not the product, has a stricter privacy gate: the release reports are also searched for private markers and private paths in canonical standard and URL-safe base64 text and in decoded content that is not UTF-8 text (see [Release process](#release-process)).
