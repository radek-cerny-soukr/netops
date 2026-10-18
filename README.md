# NetOps

NetOps is a self-hosted MCP server for network diagnostics, configuration audits and bounded, reversible device changes. Version 1.0 ships as one Docker image that runs the Helper, Auditor and Admin roles behind one token-protected HTTPS (Streamable HTTP) MCP endpoint, with every request and response written to a mandatory audit.

The image contains no AI agents. Any MCP client that verifies TLS normally can connect; the quickstart covers Claude Code and Codex.

**Start here:** [NetOps 1.0 quickstart](docs/quickstart-1.0.md)

## Highlights

- **One product, one image.** A single multi-architecture image for `linux/amd64` and `linux/arm64`, pinned by digest in the release `env.example`. Core, Helper, Auditor and Admin share one dependency closure and one product version.
- **One MCP endpoint.** HTTPS only, bearer token, instance-local certificate authority with name constraints and an automatically renewed short-lived server certificate.
- **Audit before action.** Requests are durably recorded before dispatch and responses before delivery. If the audit cannot be written, the operation is refused (`audit_unavailable`). The audit goes to a TLS syslog receiver (recommended) or to a local, size-limited log.
- **Role isolation.** Gateway and roles run as separate long-running processes under their own UID/GID (51000–51003), with no Linux capabilities, `no-new-privileges`, a read-only root filesystem and CPU, memory and process limits. A short start-up bootstrap uses the capabilities listed in `compose.yaml` and then drops all of them.
- **Explicit device scope.** No device is enrolled implicitly. Each role has its own inventory and credentials; MCP clients pass enrolled aliases, never device credentials.
- **Device output is untrusted data**, never instructions.
- **Safeguarded changes.** Admin changes run behind an on-device safeguard with prediction, independent readback and verified return; unknown writes are never retried automatically.
- **Errors stay visible.** Refused, failed or uncertain operations are MCP errors (`isError`) with their full structured result.
- **Signed releases.** The checksum list is signed with Sigstore; SBOMs, vulnerability scans with written assessments and acceptance reports are covered by it.

## Roles and what they can do

`netops selftest` prints the MCP tool names of each role: **13 Helper, 7 Auditor and 6 Admin tools**. Core has no MCP tools.

### Core

The shared engine used by the other roles: inventory and credential-vault schemas and the SSH/SFTP transport with host-key pinning. See [Core inventory](components/netops-core/docs/inventory.md) and [Core vault](components/netops-core/docs/vault.md).

### Helper — read-only diagnostics

Read-only queries against enrolled targets, using a named query catalogue of **289 query templates across 10 platform profiles** (`linux`, `fortinet`, `extreme_exos`, `cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `juniper_junos_els`, `ruckus_unleashed`). The catalogue excludes running/startup/full configuration, arbitrary CLI, debug activation, packet capture, shells and every write or lifecycle action. Query parameters are accepted only when their value is listed in the target's `read_inventory`.

| Tool | Behavior |
|---|---|
| `helper_status` | Enrolled aliases, validation and rate state; no device contact |
| `target_scope` | Public enrollment boundary for one alias; no device contact |
| `read_query_catalog` | Named typed queries and metadata; not automatic authorization |
| `dns_probe` | Enrolled DNS resolution with address scope checks |
| `tcp_probe` | Enrolled TCP port reachability |
| `icmp_probe` | Explicitly permitted bounded diagnostics |
| `tls_probe` | Verified peer certificate and enrolled SNI/port |
| `ssh_read` | Enabled named query, pinned SSH host key, bounded/paginated output |
| `sftp_stat` | Metadata within enrolled roots; no file content |
| `schema_read` | Not a supported workflow in 1.0 (see [Known limitations](#known-limitations)) |
| `fortios_diagnostics` | Not a supported workflow in 1.0 (see [Known limitations](#known-limitations)) |
| `snmp_get` | Refused in the shipped SSH/HTTPS-only profile |
| `ftp_list` | FTP and FTPS refused in the shipped profile |

Each target has its own scope (enabled queries, egress addresses and ports, optional SFTP roots) and a per-target rate limit (default 30 requests per 60 seconds). The account must be independently verified as read-only on the device; the JSON declaration alone does not restrict it.

Docs: [Helper configuration](docs/helper-configuration.md) · [Helper tools](components/netops-helper/docs/tools.md) · [Query catalogue](components/netops-helper/docs/query-catalog.md) · [Account boundaries](components/netops-helper/docs/read-only-accounts.md)

### Auditor — configuration audit

Evaluates FortiOS and ExtremeXOS configurations against a rule catalogue (**25 FortiOS and 9 EXOS rules**) and stores finished findings in a private store.

Operator commands (run with the instance stopped):

- `auditor run` evaluates a configuration snapshot from standard input offline, without contacting a device; output as text, `--json` or `--sarif`.
- `auditor collect` reads the configuration from an explicitly configured device through one pinned channel (`ssh` or `fortios-rest`, with host-key or TLS fingerprint verification); the Auditor never changes a device.
- `auditor import-snapshot` and `auditor import-policy` place reusable snapshots and operator management policies into private state.
- `--baseline-accept` accepts the findings of a run into the device baseline; later runs report them as `open-known`.

The seven MCP tools only read stored findings; they contact no device, start no collection and write nothing:

| Tool | Behavior |
|---|---|
| `audit_status` | Per device: `fresh`, `stale`, `never` or `incomplete`, finding counts per severity and state |
| `list_rules` | Rules of the configured catalog with ID, version, class, severity, title and references |
| `rule_detail` | One rule with remediation, evidence fields and known false positives |
| `list_findings` | Findings of the last run with state (`new`, `open-known`, `gone`, `not-evaluated`) and optional grouping by object |
| `finding_detail` | One finding with its baseline and suppression record |
| `compare` | `added`, `removed` and `kept` findings between two completely evaluated runs |
| `schema_report` | Refused in 1.0 (no schema report manifest is configured) |

Docs: [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows) · [Auditor tools](components/netops-auditor/docs/tools.md) · [Collection channels](components/netops-auditor/docs/channels.md) · [Management policy](components/netops-auditor/docs/management-policy.md)

### Admin — bounded, reversible changes

Admin is enabled by default (`init --disable-admin` omits its worker and MCP tools) and refuses device changes until it is configured and the device is enrolled. Supported change scope:

- **FortiOS:** firewall address, address group and DHCP reservation.
- **ExtremeXOS:** VLAN, port display string and port VLAN membership.

Each change runs behind an on-device safeguard (60–900 seconds), with protected objects, per-device/hour and daily limits, an independent check account, a change journal and a notification over trusted HTTPS (ntfy). A device whose operation ends `unknown` or `revert-failed`, or with a blocking reason, stays blocked until a person investigates.

| MCP tool | Behavior |
|---|---|
| `admin_doctor` | Readiness report without a change |
| `admin_preview` | Every check of apply without a change: proposed commands, prediction and refusal reasons |
| `admin_apply` | One change behind the device safeguard; result `confirmed`, `reverted`, `rejected`, `unknown` or `revert-failed` |
| `admin_status` | The stored operation record by `change_id` or `request_id` |
| `admin_schema_preview` / `admin_schema_apply` | Schema transactions; not a supported workflow in 1.0 |

Operator commands (instance stopped), not MCP tools:

- `admin enroll` performs a real temporary probe change and lets the on-device safeguard return it; `admin doctor` then has to report `"ready": true`.
- `admin undo` returns a confirmed change as a new safeguarded operation with its own change ID.
- `admin recover` inspects and settles an interrupted or unknown operation using its saved safeguard and original state.
- `admin status`, `admin notify-retry` and `admin unblock` (for a person who has inspected the record and the device).

There is no MCP tool to undo a change, unblock a device, cancel a safeguard or edit a plan.

Docs: [Admin configuration](docs/admin-configuration.md) · [Admin MCP tools](docs/admin-configuration.md#mcp-tools)

## Supported devices and firmware

Compatibility is scoped to the exact platform, firmware build, model, account policy and operation documented by each component. Catalogue presence does not qualify every deployment, and software-image results do not establish physical forwarding or hardware behavior.

| Platform | Documented scope |
|---|---|
| FortiOS | 7.6.7 build3704 and 8.0.0 build0167; model scopes FortiGate 60F, FortiGate 80F and FortiGate-VM64-KVM kept separate |
| ExtremeXOS | 33.7.1.6, 33.7.1.6-patch1-11 and the 33.6.1.14 virtual-image scope; model identifiers X435-8P-4S, X440-G2-12p and X440-G2-12p-10G4 |
| Arista EOS | 4.36.1F (Helper catalogue) |
| Cisco | NX-OS 9.3(12), IOS-XE 17.18.2, IOS 15.9(3)M12 and IOS 15.2(20200924) (Helper catalogue) |
| Juniper Junos | 26.2R1.7 (Helper catalogue) |
| Ruckus Unleashed | Explicit administrator-bounded role and catalogue boundary (Helper) |
| Linux | Documented distribution, architecture and permission requirements (Helper) |

Auditor catalogs cover FortiOS and ExtremeXOS. Admin execution is limited to the FortiOS and ExtremeXOS profiles listed above; a read catalogue on another platform does not imply Admin support there. The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries are unverified on stacking- or PoE-capable hardware.

Details: [Verified platform support](docs/verified-support.md) · [Compatibility boundaries](docs/compatibility-boundaries.md)

## Supported platforms

- **Host:** Linux with Docker Engine and the Compose plugin on Ubuntu, Debian, Fedora Server (SELinux enforcing, with SELinux support enabled in the Docker daemon) or Raspberry Pi OS 64-bit, natively or in a Linux virtual machine.
- **Architectures:** `linux/amd64` and `linux/arm64`; Raspberry Pi OS is arm64.
- **Not supported as runtime:** Docker Desktop. Docker Engine in rootless mode is not part of the qualified platform matrix. Network-backed state storage, including NFS, is not qualified.
- **Clients:** macOS and Windows can run MCP clients or host a supported Linux guest. MCP clients connect over the network from any system.

## Security model

- **Endpoint:** HTTPS only with a bearer token. The token is checked before any request body is read; unauthenticated rejections are only counted, not stored.
- **Instance CA:** private, constrained to the configured DNS subtree, all IPv4/IPv6 names excluded (so the server name must be a DNS name). The server leaf lasts seven days and renews automatically; the CA is valid for 730 days and is rotated explicitly with `netops ca rotate`.
- **Audit boundary:** every supported request, notification, response and connection boundary is audited, with requests durable before dispatch and responses before delivery. A failed audit refuses the operation; a failed response audit reports that the operation may have completed and forbids automatic retry. Offline operator workflows first record an allowlisted workflow name through a gateway-UID preflight.
- **Redaction:** explicit. Known token values, secret-bearing fields, private-key blocks and documented password forms are redacted; worker-side credentials are removed before reaching the gateway. Audit is parsed protocol content, not a raw byte transcript, and output is escaped for terminals. Device output remains sensitive after redaction.
- **Untrusted device output:** device text is data, never instructions; a diagnostic finding does not authorize a write, retry or another target.
- **UID separation:** gateway, Helper, Auditor and Admin have separate UID/GID, private state and credentials; local IPC authenticates the peer UID in both directions. This is process and filesystem isolation inside one container, not a boundary against the host administrator or the container runtime. The runtime never mounts the Docker socket or uses host networking.
- **Syslog over TLS:** the bounded, durable syslog queue sends to a verified TLS receiver. A successful delivery is a TLS transport hand-over, not a receiver acknowledgement; a full queue blocks new operations.
- **Fail-closed:** an unwritable audit, an incomplete final local audit record, a full syslog queue, a second instance on the same state or a mismatched product/state version stops operations instead of continuing silently.

Details: [Architecture](docs/architecture-1.0.md) · [Security policy](SECURITY.md) · [CIS Docker Benchmark mapping](docs/security/cis-docker-benchmark.md)

## Quick start

This is a shortened version of the [quickstart](docs/quickstart-1.0.md); follow the full document for multiple instances, Fedora/SELinux, syslog receivers, backup, restore and upgrades.

**1. Download and verify.** Download `compose.yaml`, `env.example`, `netops-1.0.0-manifest.json`, `netops-1.0.0-SHA256SUMS` and `netops-1.0.0-SHA256SUMS.sigstore.json` from the same GitHub release into an empty directory. Verification needs cosign 2.5 or newer.

```sh
cosign verify-blob --bundle netops-1.0.0-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.0-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.0-SHA256SUMS
```

Both commands must succeed: cosign prints `Verified OK` and sha256sum prints `OK` for every downloaded file.

**2. Configure and initialize.**

```sh
umask 077
cp env.example .env
```

Edit `.env`: keep `NETOPS_IMAGE` exactly as pinned by digest, set `NETOPS_BIND_IP` to the host address you explicitly want to expose, `NETOPS_PORT` to the host port and `NETOPS_SERVER_NAME` to the exact DNS name your MCP clients will use (IP certificate names are refused). Then:

```sh
docker compose run --rm netops init && docker compose up -d --wait && docker compose ps
```

`init` asks for the audit target (TLS syslog receiver recommended, or local audit with an explicit disk-warning acceptance). Without a terminal, choose explicitly with `init --audit syslog --syslog-host <host> [--syslog-port <port>]` or `init --audit local --accept-local-audit`.

**3. Export the CA and token.**

```sh
docker compose run --rm netops ca > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm netops token show)" &&
export NETOPS_TOKEN &&
docker compose run --rm netops connection
```

**4. Connect a client.** Use the URL printed by `connection`.

Claude Code:

```sh
export NODE_EXTRA_CA_CERTS="$PWD/netops-ca.pem"
claude mcp add-json -s user netops '{"type":"http","url":"https://<server-name>:<port>/mcp","headers":{"Authorization":"Bearer ${NETOPS_TOKEN}"}}'
claude mcp list
```

Codex (`~/.codex/config.toml`, token kept in the environment):

```sh
export CODEX_CA_CERTIFICATE="$PWD/netops-ca.pem"
```

```toml
[mcp_servers.netops]
url = "https://<server-name>:<port>/mcp"
bearer_token_env_var = "NETOPS_TOKEN"
```

Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification.

**5. Enroll devices.** Start with `helper_status` and `read_query_catalog`. Enrollment is an operator action with the instance stopped, using private JSON files (mode 600) outside the source repository:

```sh
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

See [Helper configuration](docs/helper-configuration.md), [Admin configuration](docs/admin-configuration.md) and the [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows).

## Verification and release

A release is the maintainer's personally signed checksum list together with the assets it covers. A candidate branch, digest, build or CI run without that signature is not a release.

- **Signature:** `netops-1.0.0-SHA256SUMS` is signed with Sigstore (`netops-1.0.0-SHA256SUMS.sigstore.json`); certificate identity `325383355+radek-cerny-soukr@users.noreply.github.com`, OIDC issuer `https://github.com/login/oauth`.
- **Covered assets:** the release manifest (image index and per-architecture digests), the SBOMs, the vulnerability scans and their assessments, and the acceptance reports of every tested platform.
- **Build once:** every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild.
- **Vulnerabilities:** each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding ships with a written assessment (`netops-1.0.0-vulnerability-assessments.json`). The digests of the latest release are rescanned daily against its assessments.
- **Acceptance:** the signing checklist requires 79 acceptance rows. Platform runs repeat the quickstart as an ordinary docker-group operator without sudo, and Fedora Server runs add an SELinux label negative test. Download verification, installation, first MCP use, audit, restart and every supported upgrade are release gates. A successful source import or selftest is only its stated evidence scope.

Use the image digest and configuration files from one signed release manifest. Qualification from a source checkout is described in [Qualification](docs/testing-1.0.md).

## Documentation

| Topic | Document |
|---|---|
| Installation, clients, audit, lifecycle, backup and restore | [Quickstart](docs/quickstart-1.0.md) |
| Helper inventory/vault input and first device operation | [Helper configuration](docs/helper-configuration.md) |
| Admin device, safeguard, notification, enrollment, preview, apply and undo | [Admin configuration](docs/admin-configuration.md) |
| MCP tool references | [Helper](components/netops-helper/docs/tools.md) · [Auditor](components/netops-auditor/docs/tools.md) · [Admin](docs/admin-configuration.md#mcp-tools) |
| Role UIDs, peer authentication, audit durability and redaction, certificates, syslog delivery | [Architecture](docs/architecture-1.0.md) |
| Exact host, firmware and model scope | [Verified support](docs/verified-support.md) · [Compatibility boundaries](docs/compatibility-boundaries.md) |
| Security policy and vulnerability reporting | [SECURITY.md](SECURITY.md) |
| CIS Docker Benchmark v1.6.0 self-assessment | [CIS mapping](docs/security/cis-docker-benchmark.md) |
| Qualification from a source checkout | [Testing](docs/testing-1.0.md) |
| Product changes | [CHANGELOG](CHANGELOG.md) |
| Historical 0.x documentation (not current instructions) | [0.x archive](docs/archive/0.x/ARCHIVE.md) |

## Known limitations

- 1.0 starts from a clean installation; it does not upgrade or migrate 0.x installations or data.
- Docker Engine in rootless mode is not part of the qualified platform matrix.
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request; other authenticated requests share the remaining slots within the limit of 16.
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- Audit records of up to 8 MiB plus framing exceed the RFC 5425 minimum interoperability baseline. The supported receiver is explicitly configured rsyslog 8.2512 with the gtls driver, `maxMessageSize="9m"` and imtcp `MaxFrameSize="9437184"`; default receiver settings do not guarantee complete records.
- There is no supported provisioning path for the schema registry/library files of Helper `schema_read` and `fortios_diagnostics`, the extra input files of Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline and schema workflows.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check samples at a nominal 50 ms interval and can miss short-lived processes; see the [release notes](release/notes-1.0.0.md) for the exact attribution rule.

## 0.x releases and packaging

Version 1.0 does not migrate 0.x data or modify 0.x volumes. Previously published component releases remain available and unchanged. The new product is not published to PyPI by default. An inventory written for 0.x needs the 1.0 Helper section and the English device roles `perimeter`, `internal` and `lab`.

## License

NetOps is an open-source project by Radek Černý, distributed under the [MIT license](LICENSE). Claude Code and Codex assist implementation and independent review; compatible MCP clients remain vendor-neutral.
