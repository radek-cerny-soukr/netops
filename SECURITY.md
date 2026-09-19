# Security policy

## Supported versions

Security fixes are maintained for the latest tagged minor release of each component. Pre-1.0 releases may make breaking configuration changes when required to fail closed. Version 0.2.0 intentionally rejects legacy target-policy records that omit the mandatory platform, query, or egress contract, and rejects the removed `https_endpoints` key.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, device access, private network data, or a capability-boundary bypass. Contact the repository owner privately through GitHub Security Advisories. Never include live credentials, addresses, configurations, or command output.

## Threats in scope

- Leakage or cross-target injection of credentials, communities, private keys, or host-key inventories.
- Authentication-context, target-alias, inventory, metadata/listing-root, or egress-scope confusion.
- SSH host-key bypass or a mutating FortiOS session-preparation command.
- Escape from typed query templates or SFTP/FTP metadata and listing roots.
- A write-capable or configuration-reading tool appearing in the phase-1 surface.
- Prompt injection through device-controlled output.
- Missing mandatory audit coverage, persistent secret-bearing audit data, or unbounded audit growth.
- Container privilege, filesystem-hardening, or host-firewall regressions.
- Supply-chain substitution of base images, Python dependencies, or release artifacts.

## Required deployment boundary

Every target account must be restricted to read-only permissions by the target platform. Local templates and `account_role` enrollment are defense in depth, not substitutes for remote authorization.

Use a dedicated agent/session with no mutating MCP tools, generic shell, write-capable file tools, or deployment integrations. Client-side safety instructions help handle untrusted device text, but prompt instructions are not a security boundary.

Apply and verify an explicit host-firewall egress policy. The generated DOCKER-USER contract restricts forwarded traffic from the stable `nh-egress0` bridge, but it is not full containment and does not govern traffic from that bridge to runner-local services through INPUT. See [Egress control](docs/egress-control.md).

## Residual risk

One target record deliberately supplies the same `login` and `password` to SSH, SFTP, FTPS, and plain FTP operations. Plain FTP sends those credentials and listing data without encryption. Use FTPS or a separate least-privilege FTP identity and alias; because `sftp_roots` also authorizes `sftp_stat`, enforce unwanted-protocol denial on the target rather than assuming target policy makes an alias FTP-only.

Device output remains sensitive and attacker-controlled after best-effort redaction. The sanitizer may miss novel secrets or replace legitimate neighboring prose, so secret-bearing sources must be excluded before redaction. Phase 1 deliberately cannot read running/startup/full/backup configurations, generic HTTP response bodies, or remote file contents and cannot browse arbitrary or unbounded device logs, but allowed diagnostics and metadata may still expose operational data.

Plain FTP is unencrypted. SNMPv2c also has no confidentiality and transmits its dedicated community in plaintext. Password-backed credential storage and the askpass environment are compatibility compromises. Client-side path roots do not replace remote permissions or chroot.

The container images of the family carry the OpenSSH client of the pinned Debian base, and a vulnerability in that client that the distribution does not fix is shipped as a reviewed, dated exception rather than fixed; each component's `docs/known-vulnerabilities.md` names every such exception, what it exposes and what an operator who cannot accept it should do. `netops-helper` 0.3.0 ships CVE-2026-60002 this way.

The Compose bridge uses `internal: false` so diagnostics work. DOCKER-USER forwarding rules do not by themselves block runner-host INPUT, Docker embedded DNS behavior depends on the live engine/NAT path, and compromise containment therefore remains incomplete until verified and supplemented for the deployment. A compromised client, runner, dependency, or target can still return malicious data. No release is certified for a regulatory framework.
