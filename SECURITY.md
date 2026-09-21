# Security policy

## Supported versions

Security fixes are maintained for the latest tagged release of each component. Pre-1.0 releases may make breaking configuration changes when required to fail closed. `netops-helper` enrolls devices only through the `helper` section of `inventory.json`: a leftover `target-policy.json` in the configuration directory, or a retired `NETOPS_TARGET_POLICY_PATH`, `NETOPS_KNOWN_HOSTS_PATH` or `NETOPS_MASTER_ALIAS` variable, is refused fail-closed by the proxy at startup and by `scripts/check_operator_config.py` alike.

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

The family has three roles, not one, and they do not share a boundary. A read-only MCP surface is a claim about that one surface, not about every account behind it.

**The helper's target account.** Every account the helper's MCP surface uses to reach a device must be restricted to read-only permissions by the target platform. Local templates and `account_role` enrollment are defense in depth, not substitutes for remote authorization.

**The auditor's collector.** Reading a complete configuration needs an account the platform will not grant read-only permissions to: FortiOS requires a `super_admin` administrator, and ExtremeXOS requires an administrator account because a user-level account is refused `show configuration`. This is a decided, documented project position, not an oversight; see [Collection channels](components/netops-auditor/docs/channels.md). Because that account could write, the read-only boundary for its traffic is the tool's fixed command table and the pinned host key, not the account's own permissions. Run the collector as its own process, under its own dedicated credential, separate from the helper's target accounts and from the auditor's own MCP surface below. A shared credential-store format (the vault schema of `netops_core.vault`) does not mean a component should be handed the whole store: the operator must point the collector at a vault holding only the collector's own records, never the shared vault used by other components.

**The auditor's MCP surface.** This one holds no credentials and reaches no device: it opens an already-written audit database read-only and serves findings from it. It runs as its own process, separate from the collector, and needs no device account at all.

Use a dedicated agent/session with no mutating MCP tools, generic shell, write-capable file tools, or deployment integrations, for whichever of these MCP surfaces is in use. Client-side safety instructions help handle untrusted device text, but prompt instructions are not a security boundary.

Apply and verify an explicit host-firewall egress policy for the helper. The generated DOCKER-USER contract restricts forwarded traffic from the stable `nh-egress0` bridge, but it is not full containment and does not govern traffic from that bridge to runner-local services through INPUT. See [Egress control](components/netops-helper/docs/egress-control.md).

## Residual risk

One target record deliberately supplies the same `login` and `password` to SSH, SFTP, FTPS, and plain FTP operations. Plain FTP sends those credentials and listing data without encryption. Use FTPS or a separate least-privilege FTP identity and alias; because `sftp_roots` also authorizes `sftp_stat`, enforce unwanted-protocol denial on the target rather than assuming target policy makes an alias FTP-only.

Device output remains sensitive and attacker-controlled after best-effort redaction. The sanitizer may miss novel secrets or replace legitimate neighboring prose, so secret-bearing sources must be excluded before redaction. Phase 1 deliberately cannot read running/startup/full/backup configurations, generic HTTP response bodies, or remote file contents and cannot browse arbitrary or unbounded device logs, but allowed diagnostics and metadata may still expose operational data.

Plain FTP is unencrypted. SNMPv2c also has no confidentiality and transmits its dedicated community in plaintext. Password-backed credential storage and the askpass environment are compatibility compromises. Client-side path roots do not replace remote permissions or chroot.

The `netops-helper` 0.3.5 ARM64 image carries CVE-2026-60002 in its OpenSSH client as a reviewed exception, not a fix. [Known vulnerability findings](components/netops-helper/docs/known-vulnerabilities.md) describes the exposure and operator options; the image SBOM and Grype report attached to the current Helper release record the shipped package and scan results. Auditor and Core currently publish source-only releases, with no container images.

The Compose bridge uses `internal: false` so diagnostics work. DOCKER-USER forwarding rules do not by themselves block runner-host INPUT, Docker embedded DNS behavior depends on the live engine/NAT path, and compromise containment therefore remains incomplete until verified and supplemented for the deployment. A compromised client, runner, dependency, or target can still return malicious data. No release is certified for a regulatory framework.
