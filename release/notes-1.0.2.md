NetOps 1.0.2 follows NetOps 1.0.1 and upgrades the state of an instance of NetOps 1.0.1. It is a corrective release of the same single product: one container image that runs the Helper, Auditor and Admin roles behind one audited HTTPS MCP endpoint. Apart from one security fix in the Core SFTP banner handling, two operator hints and the recorded product version, the product code is unchanged. The syslog audit format and the receiver requirements of 1.0.1 stay as they are.

## Security fix

- The Core `sftp_stat` took the first stderr line that began with `Connected to ` as the end of the SSH login banner. A device whose banner contained such a line, for example `Connected to the lab network`, could make every call with `sftp_roots` fail and an empty directory unreadable. A banner that also contained a forged OpenSSH client message let `sftp_stat` list a directory reached through a symbolic link out of an enrolled root (metadata only: names, sizes and modes, not file content). This needs an SSH server whose banner the attacker controls and an existing symbolic link below the root. NetOps 1.0.2 takes the last line exactly `Connected to <host>.` for the target host, which the client prints after authentication and therefore after any banner. Banner text before that line is ignored; if the line is missing, the whole stderr is treated as client output. Regression tests cover both banners, and the fix was checked against OpenSSH 10.0p2 `sftp-server`.

## Changes in 1.0.2

- The CA export hints printed by `init`, `connection` and `ca rotate` now name the complete command `docker compose run --rm netops ca > netops-ca.pem`. They lacked the redirection, so a copied command printed the CA to the terminal instead of writing the file that the client configuration uses.
- Upgrade the state of NetOps 1.0.1: the first start of 1.0.2 converts its state under the instance lock and changes only the recorded product version, in the same way as the upgrade from 1.0.0 to 1.0.1.
- Rebuild the quickstart into numbered steps, each ending with a check, after blind installation tests of 1.0.1 on Fedora Server 44 and Ubuntu: Docker Engine from Docker's repository for every host family, SELinux support in the Fedora Docker daemon, account access through the `docker` group or rootless Docker, cosign from the official Sigstore 3.x release, a download block that stops at the first failed download, a separate step for an MCP client on the same host, and a check of the running instance without an MCP client.
- Document that the Core `sftp_stat` refuses paths below a root (fail-closed) on embedded SFTP servers that send no permissions in their stat answer or return `REALPATH` in another form; the path equal to a root works.

## Acceptance

NetOps 1.0.2 is a corrective release and was accepted in proportion to its change: CI in GitHub Actions on amd64 and arm64, a blind installation by the README and the quickstart on Fedora Server 44 and Debian 13 on amd64, a blind upgrade from 1.0.1 to 1.0.2 on amd64 and an independent code review. Ubuntu, Raspberry Pi OS, arm64 hosts and rootless Docker, whose quickstart commands are newly written in 1.0.2, were not tested by a blind run for 1.0.2; the product code on these paths is unchanged since 1.0.1, whose acceptance covered them.

## Upgrade from 1.0.1

Follow [Upgrade from the previous release](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md#upgrade-from-the-previous-release). The upgrade has four steps:

1. Check the 1.0.1 instance, stop it and back it up as described in [Before the upgrade](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md#before-the-upgrade).
2. Download and verify the 1.0.2 release files, then prepare a clean 1.0.2 instance in a new directory, with the same server name and port and a `.env` with the 1.0.2 image.
3. Restore the backup into it as described in the same section of the quickstart.
4. Start it; the restore block of the quickstart ends with the start. The first start of 1.0.2 converts the restored state of 1.0.1 under the instance lock.

A syslog receiver configured for 1.0.1 stays unchanged. State of any other product version or state schema is refused, there is no upgrade that skips a release and no downgrade: upgrade an instance of NetOps 1.0.0 to 1.0.1 first, as described in the [1.0.1 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/release/notes-1.0.1.md), including its syslog receiver change. The 1.0.1 instance, its directory and its state volume stay unchanged. Rollback: stop the 1.0.2 instance, export its audit records written after the backup as described in [Rollback](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md#rollback) and start the original 1.0.1 instance.

## Known limitations

- The separate Helper SSH proxy to a runner host supports both keyboard-interactive and password authentication. When a server offers both methods, one connection with an incorrect password can cause two failed authentication attempts, which may count under the runner account's lockout policy.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request. Other authenticated requests can use the remaining slots within the shared limit of 16.
- The 60-second deadline covers only the receipt of the request body: a client that does not read a large response keeps its operation slot until the response is sent, so such clients can occupy the shared limit of 16.
- 1.0.2 upgrades only NetOps 1.0.1; it does not upgrade or migrate 0.x installations or data.
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check uses a nominal 50 ms sampling interval and can miss processes that start and exit between observations; the [1.0.1 release notes](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/release/notes-1.0.1.md#known-limitations) give the exact attribution rule.
- When the converting first start of 1.0.2 stops after the conversion, for example because a role refuses its configuration or the start is interrupted, no audit record names the upgrade. The only indirect evidence is the version in the last 1.0.1 records and in the next `instance_start` of 1.0.2, and only with audit history kept from before the upgrade; see [Refused first start](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md#refused-first-start).
- The SHA-256 of a syslog record detects damaged or incomplete part archives. It does not prove the authenticity of data that an attacker controlled before the record was complete.
- Audit events suppressed before NetOps sends them cannot be detected from the receiver archive.

Details: [verified support](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/verified-support.md) and [security](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/SECURITY.md).

## Install

Follow [the quickstart](https://github.com/radek-cerny-soukr/netops/blob/v1.0.2/docs/quickstart-1.0.md). In short: download `compose.yaml`, `env.example`, `netops-1.0.2-manifest.json`, `netops-1.0.2-SHA256SUMS` and `netops-1.0.2-SHA256SUMS.sigstore.json` from this release, verify them, set the bind address, port and server name, then run `init` and start the service.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.2-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.2-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.2-SHA256SUMS
```

The checksum list covers the release manifest, which records the image index and per-architecture digests, the SBOMs, the vulnerability scans and their assessments, and the acceptance reports of this release. `env.example` already pins the image by that index digest. A download is verified only after both commands succeed.

## Security

Every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild. Each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding, of any severity, ships with a written assessment (`netops-1.0.2-vulnerability-assessments.json`). SBOMs cover the application, its Python dependencies and the operating-system packages. The only security fix in 1.0.2 is the Core SFTP banner fix described under [Security fix](#security-fix).
