# NetOps Helper

NetOps Helper phase 1 is a security-focused, read-only MCP server for bounded network troubleshooting. It gives any compatible MCP client explicitly enrolled diagnostic visibility without exposing a configuration path. It is intentionally not a general CLI, configuration reader, log browser, or network-discovery service.

Operators address explicitly enrolled devices by alias. A local stdio proxy validates the target policy, injects one target's credentials after the MCP client boundary, transports the request over verified SSH, and invokes an isolated container on a runner. Device output keeps identifiers needed for correlation while recognized secrets are removed on a best-effort basis.

This is a self-hosted community project for experienced operators and security reviewers. It is not an enterprise orchestrator, a replacement for device-side authorization, or proof that a diagnostic conclusion is correct.

## Architecture

```text
dedicated read-only agent/session
  -> local stdio proxy: alias discovery, policy/egress checks, credential injection
  -> verified SSH transport (`ssh -T`; stock password/keyboard-interactive authentication)
  -> fixed `docker exec -i netops-helper python -m netops_helper.server`
  -> isolated phase-1 read-only MCP server
  -> device account with externally enforced read-only permissions
```

The required order of controls is:

1. read-only accounts enforced by each target platform;
2. an exact per-target policy for named queries, inventories, metadata/listing roots, and network egress;
3. host-side egress rules applied before the container starts;
4. best-effort response redaction and explicit byte pagination;
5. per-target rate limiting and bounded SSH continuation caching;
6. a standalone phase-1 server with no write tools.

## Capabilities

The remote FastMCP server registers exactly 10 tools: two control-plane tools and eight device tools. The local proxy adds `target_scope`, so a client sees exactly 11 tools: three control-plane tools and eight device tools.

- Alias discovery through `helper_status` and enrolled-scope inspection through `target_scope`.
- DNS, TCP, ICMP, and certificate-verifying TLS diagnostics.
- Named SSH troubleshooting queries for FortiOS, Extreme Switch Engine, Cisco IOS, IOS-XE and NX-OS, Arista EOS, Junos, and Linux.
- Opt-in ARP/neighbor, MAC/FDB, and LLDP/CDP queries where a reviewed platform command exists.
- Typed parameters selected from per-target interface, service, address, and switch inventories.
- SNMPv2c GET with a dedicated community value that is never reused from the SSH password.
- SFTP metadata under per-target non-root paths; no remote file body download.
- FTPS directory listing and explicitly acknowledged read-only plain FTP listing.
- Explicit pagination metadata and a stable content digest for long SSH output.

`target_scope` does not return the vault's `host` field, login, credentials, community, or host-key material. It intentionally returns enrolled inventories, SFTP metadata/listing roots, and egress addresses; this can reveal target addressing and other operational topology. Treat it as credential-free but environment-sensitive data.

See [Tool reference](docs/tools.md), [Read-only accounts](docs/read-only-accounts.md), [Configuration](docs/configuration.md), and [Installation](docs/installation.md).

## Deliberate non-capabilities

Phase 1 never reads running, startup, full, or backup configuration and provides no configuration export. It also has no generic HTTP response-body reader or remote file-content reader. It provides no prepare/apply workflow, upload, deletion, restart, reboot, process control, software installation, network discovery, arbitrary shell, raw CLI input, or autonomous target expansion.

There is no general device-log browser. The only deliberately log-oriented query is the fixed, opt-in, one-hour Linux service journal query. Some fixed status/history diagnostics may contain event-like output, but the client cannot select arbitrary device logs, time ranges, filters, or files.

A future Phase 2 may consider configuration or other body reads only under a separate threat model, binary, container, credential set, client profile, and operator-controlled activation boundary. Phase 1 must not be broadened by adding a full-configuration query or a generic body-read escape hatch.

## Security properties

- The helper exposes no listening port; MCP uses SSH-tunneled stdio.
- The container runs non-root with a read-only root filesystem, no Linux capabilities, `no-new-privileges`, resource limits, and no Docker socket.
- Every target must declare `account_role: "read-only"`; the operator must separately verify the actual device-side role over the same access path.
- Every request is checked against exact target policy and per-tool egress scope before credentials are forwarded.
- FortiOS sessions use a no-paging-write driver and require preverified `output standard`.
- SSH and SFTP refuse the `ssh-rsa` host key algorithm and SHA-1 key exchange for every target. A target which offers only `ssh-rsa` needs the named per-target exception `legacy_ssh: "rsa-sha1"`; there is no global switch and no algorithm list in configuration. See [Legacy SSH algorithms](docs/configuration.md#legacy-ssh-algorithms).
- SSH and SFTP require pre-enrolled host keys; only entries matching the selected target are injected into the container.
- The client supplies query names and typed parameters, never raw commands.
- Inventory-bound slots prevent device output from becoming a new command argument or expanding target scope.
- IP, IPv6, MAC, hostname, username, email, and serial values remain visible because troubleshooting requires correlation.
- Injected credentials and recognized secret forms are redacted on a best-effort basis; policy and remote permissions must keep secret-bearing data out of scope.
- Every device response is marked as untrusted data and must run in a dedicated read-only agent/session.
- Mandatory audit writes a durable `started` record before a device operation and a terminal record afterward; interrupted attempts can remain visibly incomplete.
- Audit JSONL contains allowlisted metadata only and rotates into five 2 MB segments.

Read [Security model](docs/security-model.md), [Egress control](docs/egress-control.md), [Security policy](../../SECURITY.md), and the release-specific [known vulnerability findings](docs/known-vulnerabilities.md) before deployment.

## Requirements

- A Linux ARM64 runner with Docker Engine and Compose v2.
- A local MCP client host with Python 3.12+, OpenSSH, and verified runner and target host keys.
- Dedicated device identities whose read-only permissions are enforced on the targets.
- A local credential source and target policy that are never shipped with the source or container image.
- A dedicated agent/session without shell, write-capable file, deployment, or mutating MCP tools.
- An out-of-band recovery path while applying host firewall rules.

## Quick start

This sequence deliberately creates the Compose network and container in a stopped state. Do not start the helper until the generated egress contract has been reviewed, applied, and checked.

1. Clone and verify the same release on the proxy host and runner as needed.
2. Create dedicated target accounts and independently test both allowed reads and denied configuration, export, maintenance, and shell actions. Follow [Read-only accounts](docs/read-only-accounts.md).
3. Create the mode-`600` credential JSON object with its separate runner and target records, then create the exact target-only policy. Follow the [vault structure and protocol credential semantics](docs/configuration.md#credential-vault-structure-and-protocol-use). Use the optional, separate `snmp_community` only for targets that need SNMP; never reuse the target password. Pre-enroll runner and target SSH host keys.
4. On the runner, build the image and create the network and container without starting the service:

   ```bash
   docker compose build --pull=false
   docker compose up --no-start --no-build
   docker compose ps --all
   docker network inspect netops-helper
   ```

5. On the proxy host, generate a mode-`600`, secret-free but topology-sensitive bundle from file paths:

   ```bash
   python3 scripts/generate_egress_rules.py \
     --vault /path/to/vault.json \
     --policy /path/to/target-policy.json \
     --output /restricted/path/netops-helper-egress.json
   ```

6. Transfer the bundle through a host-key-verified channel if proxy and runner differ. On the runner, compare its SHA-256 digest with the sender, inspect its manifest and rules, retain out-of-band recovery, then explicitly apply and check it:

   ```bash
   sudo python3 scripts/apply_egress_rules.py \
     --bundle /restricted/path/netops-helper-egress.json --apply
   sudo python3 scripts/check_egress_rules.py \
     --expected /restricted/path/netops-helper-egress.json
   ```

   Continue only after `egress_apply=ok` and `egress_check=ok` and after reviewing the residual INPUT-path risk in [Egress control](docs/egress-control.md).

7. Start the already-created service and confirm its state:

   ```bash
   docker compose start
   docker compose ps
   ```

8. Configure `scripts/remote_mcp_proxy.py` as a stdio MCP server in a dedicated read-only profile of any compatible client. Start a fresh session, call `helper_status`, inspect `target_scope` for one listed alias, and test one harmless enrolled query against a controlled test target.

The default password-backed credential file is a portability compromise, not the preferred production secret design. A target record reuses its login and password across SSH, SFTP, FTPS, and plain FTP; plain FTP transmits them without encryption. SNMPv2c sends its separate community in plaintext at the protocol layer. The stock image validates public trust; `tls_probe` and system-trust FTPS will normally reject private-CA or self-signed devices until a private image contains an independently verified trust anchor and the device certificate has a matching SAN. Follow the [credential](docs/configuration.md#credential-vault-structure-and-protocol-use) and [private CA and FTPS pin](docs/configuration.md#private-tls-and-ftps-ca-san-and-pins) procedures; verification must not be disabled.

The Compose network has `internal: false` so diagnostics can reach targets. Bundle schema 3 installs only an IPv4 iptables/DOCKER-USER ruleset. IPv6 is disabled on this Docker network with `enable_ipv6: false`; no ip6tables protection is claimed. DOCKER-USER covers forwarded traffic, not necessarily traffic to services on the runner's INPUT path. Treat egress as constrained only after the live checks in [Egress control](docs/egress-control.md).

## Development

Use Python 3.12, install the locked dependencies and pytest in a maintained development environment, then run:

```bash
python -m pytest -q
PYTHONPATH=src python tests/run_tests.py
python scripts/check_public_release.py
```

The base image is digest-pinned. Runtime dependencies are hash-locked, and release metadata includes CycloneDX SBOM data. A clean test run is necessary but not sufficient; review the source diff, effective target permissions, complete vulnerability report, license inventory, egress behavior on the actual ARM64 runner, and residual risks.

## License

MIT. See [LICENSE](LICENSE).
