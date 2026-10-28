# NetOps

This README describes NetOps 1.0.4, the current release. Changes since 1.0.3 are listed in the [release notes](release/notes-1.0.4.md); the response delivery fixes came with [1.0.3](release/notes-1.0.3.md), the Core SFTP security fix with [1.0.2](release/notes-1.0.2.md) and the fixes for [issue #6](https://github.com/radek-cerny-soukr/netops/issues/6) with [1.0.1](release/notes-1.0.1.md). To upgrade an existing 1.0.3 instance, follow [Upgrade from the previous release](docs/quickstart-1.0.md#upgrade-from-the-previous-release).

NetOps is a self-hosted MCP server for network diagnostics, configuration audits and bounded, reversible device changes. Version 1.0 ships as one Docker image that runs the Helper, Auditor and Admin roles behind one token-protected HTTPS (Streamable HTTP) MCP endpoint. Supported, authenticated MCP traffic passes through a mandatory durable audit boundary.

NetOps is an independent, open-source, multi-vendor tool. It is not a product of any vendor whose devices, software or MCP clients it supports or names, and it is not affiliated with, endorsed by or supported by any of them; see the [disclaimer](#disclaimer).

The image contains no AI agents. Any MCP client that verifies TLS normally can connect; the quickstart covers Claude Code and Codex. See [Tested MCP clients](#tested-mcp-clients) for the clients and models tested for 1.0.1.

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

`netops selftest` prints the MCP tool names of each role: **15 Helper, 7 Auditor and 6 Admin tools**. Core has no MCP tools.

### Core

The shared engine used by the other roles: inventory and credential-vault schemas and the SSH/SFTP transport with host-key pinning. See [Core inventory](components/netops-core/docs/inventory.md) and [Core vault](components/netops-core/docs/vault.md).

### Helper — read-only diagnostics

Read-only queries against enrolled targets, using a named query catalogue of **290 query templates across 11 platform profiles** (`linux`, `fortinet`, `extreme_exos`, `cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `juniper_junos_els`, `ruckus_unleashed`, `fortiadc`). The catalogue excludes running/startup/full configuration, arbitrary CLI, debug activation, packet capture, shells and every write or lifecycle action. Query parameters are accepted only when their value is listed in the target's `read_inventory`.

| Tool | Behavior |
|---|---|
| `helper_status` | Enrolled aliases, validation and rate state; no device contact |
| `target_scope` | Public enrollment boundary for one alias; no device contact |
| `read_query_catalog` | Named typed queries and metadata; not automatic authorization |
| `dns_probe` | Enrolled DNS resolution with address scope checks |
| `tcp_probe` | Enrolled TCP port reachability |
| `icmp_probe` | Explicitly permitted bounded diagnostics |
| `tls_probe` | Verified peer certificate and enrolled SNI/port |
| `ssh_read` | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`) |
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
- **Docker Engine:** as root or in rootless mode.
- **Not supported as runtime:** Docker Desktop. Network-backed state storage, including NFS, is not qualified.
- **Clients:** macOS and Windows are supported only as MCP client hosts (Claude Code, Codex), not as NetOps servers. MCP clients connect over the network from any system.

## Security model

- **Endpoint:** HTTPS only with a bearer token. The token is checked before any request body is read; unauthenticated rejections are only counted, not stored.
- **Instance CA:** private, constrained to the configured DNS subtree, all IPv4/IPv6 names excluded (so the server name must be a DNS name). The server leaf lasts seven days and renews automatically; the CA is valid for 730 days from init or its last rotation (`connection` shows the remaining whole days, so 729 right after init) and is rotated explicitly with `netops ca rotate`.
- **Audit boundary:** every supported request, notification, response and connection boundary is audited, with requests durable before dispatch and responses before delivery. A failed audit refuses the operation; a failed response audit reports that the operation may have completed and forbids automatic retry. Offline operator workflows first record an allowlisted workflow name through a gateway-UID preflight.
- **Redaction:** explicit. Known token values, secret-bearing fields, private-key blocks and documented password forms are redacted; worker-side credentials are removed before reaching the gateway. Audit is parsed protocol content, not a raw byte transcript, and output is escaped for terminals. Device output remains sensitive after redaction.
- **Untrusted device output:** device text is data, never instructions; a diagnostic finding does not authorize a write, retry or another target.
- **UID separation:** gateway, Helper, Auditor and Admin have separate UID/GID, private state and credentials; local IPC authenticates the peer UID in both directions. This is process and filesystem isolation inside one container, not a boundary against the host administrator or the container runtime. The runtime never mounts the Docker socket or uses host networking.
- **Syslog over TLS:** the bounded, durable syslog queue sends to a verified TLS receiver. A successful delivery is a TLS transport hand-over, not a receiver acknowledgement; a full queue blocks new operations.
- **Fail-closed:** an unwritable audit, an incomplete final local audit record, a full syslog queue, a second instance on the same state or state of another product version or state schema stops operations instead of continuing silently. The one exception is the state of the immediately preceding release: the first start of the new release converts it under the instance lock and changes only its recorded product version. There is no downgrade.
- **CIS:** the container architecture and the release tests are inspired by the recommendations of the CIS Docker Benchmark; NetOps does not claim compliance with CIS.

Details: [Architecture](docs/architecture-1.0.md) · [Security policy](SECURITY.md) · [CIS Docker Benchmark mapping](docs/security/cis-docker-benchmark.md)

## Quick start

This is a shortened version of the [quickstart](docs/quickstart-1.0.md). Follow the full document for a new host: it installs the prerequisites step by step for Debian, Ubuntu, Fedora Server and Raspberry Pi OS, and covers rootless Docker, syslog receivers, backup, restore, upgrades and removal.

**0. Prerequisites.** Docker Engine with the Compose plugin from [Docker's repository](https://docs.docker.com/engine/install/), and an account that can run `docker info` (root, the `docker` group or rootless Docker); on Fedora, SELinux support enabled in the Docker daemon (`"selinux-enabled": true`) before the first start, so that `docker info` lists `name=selinux`. Further `curl`, `jq` and cosign 2.5 or newer; the quickstart installs the official Sigstore 3.x release (checked with v3.1.4). See quickstart steps [1–4](docs/quickstart-1.0.md#1-install-docker-engine).

**1. Download and verify.** In a new, empty directory download the five release files and verify them. The block stops at the first failed download or check:

```sh
mkdir -m 700 ~/netops && cd ~/netops &&
(
  for f in compose.yaml env.example netops-1.0.4-manifest.json netops-1.0.4-SHA256SUMS netops-1.0.4-SHA256SUMS.sigstore.json; do
    curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.4/$f" || exit 1
  done
) &&
cosign verify-blob --bundle netops-1.0.4-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.4-SHA256SUMS &&
sha256sum -c --ignore-missing netops-1.0.4-SHA256SUMS
```

cosign must print `Verified OK`, and sha256sum `OK` for `compose.yaml`, `env.example` and the release manifest; cosign authenticates the checksum list using the signature bundle.

**2. Configure.** Create `.env` and keep `NETOPS_IMAGE` exactly as pinned by digest. For an MCP client on the same host, bind to the loopback address and use the name `localhost`:

```sh
umask 077
cp env.example .env
sed -i -e 's/^NETOPS_BIND_IP=.*/NETOPS_BIND_IP=127.0.0.1/' -e 's/^NETOPS_SERVER_NAME=.*/NETOPS_SERVER_NAME=localhost/' .env
```

For clients on other machines, set `NETOPS_BIND_IP` to the host address you explicitly want to expose and `NETOPS_SERVER_NAME` to the exact DNS name the clients will use instead (IP certificate names and the unedited `env.example` placeholders are refused); see [step 6](docs/quickstart-1.0.md#6-configure-env).

**3. Initialize and start.**

```sh
docker compose run --rm netops init && docker compose up -d --wait && docker compose ps
```

`init` asks for the audit target: a TLS syslog receiver (recommended), or, when you leave it blank, local audit, which you accept by typing `LOCAL`. `docker compose ps` must show the service as `healthy`.

Without a terminal, for example in a script or over `ssh` without a terminal, choose the audit explicitly, add `-T` to every `docker compose run` and `docker compose exec`, redirect every other `docker compose` command with `< /dev/null`, and run the commands from a file, not from standard input. For local audit the block is the following; for a TLS syslog receiver replace `--audit local --accept-local-audit` with `--audit syslog --syslog-host <host> [--syslog-port <port>]`:

```sh
docker compose run --rm -T netops init --audit local --accept-local-audit < /dev/null && docker compose up -d --wait < /dev/null && docker compose ps < /dev/null
```

**4. Export the CA and the token.**

```sh
docker compose run --rm netops ca > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm netops token show)" &&
export NETOPS_TOKEN &&
docker compose run --rm netops connection
```

Without a terminal use the script form in [step 8](docs/quickstart-1.0.md#8-export-the-ca-and-the-token) of the quickstart; the token stays in the shell, so run it and the token requests of quickstart [step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) in the same script file.

**5. Check without an MCP client.**

```sh
docker compose exec -T netops netops health < /dev/null
docker compose exec -T netops netops version < /dev/null
curl -sS -o /dev/null -w '%{http_code}\n' --cacert netops-ca.pem \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST https://localhost:8443/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

They print `ready`, `1.0.4` and `401`: a request without the token is refused. Use the URL printed by `connection` when it is not `https://localhost:8443/mcp`. [Step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) adds requests with the token, including the MCP tool list, and how to find them in the audit.

**6. Connect a client.** Use the URL printed by `connection`.

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

The [quickstart](docs/quickstart-1.0.md#10-connect-an-mcp-client) adds the Codex settings, the commands for a first non-interactive `helper_status` call with either client and how to find that call in the audit.

Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification.

#### Tested MCP clients

Tested for 1.0.1 against a NetOps 1.0.1 instance, with each call found in the audit as a request and a response record:

| Client | Version | Platform | Models |
|---|---|---|---|
| Claude Code | 2.1.310 | Linux (Ubuntu 26.04, blind run of the quickstart), macOS 26.6.2 arm64, Windows 11 (PowerShell 5.1) as a remote client | Claude models of the client's provider account |
| Open WebUI | v0.12.3 | container image | Laguna XS 2.1 Q4 and gpt-oss-120b MXFP4, local, through llama.cpp `llama-server` (OpenAI-compatible API), 16,384-token context |
| Codex CLI | 0.164.0 | Linux (Debian GNU/Linux 13, amd64) | gpt-6.1-sol (medium reasoning) |

Codex CLI made three read-only calls per role. The three Admin calls returned the expected `admin_not_configured` refusal on an instance without enrolled devices, so no device changes were tested with Codex.

Other MCP clients with Streamable HTTP, bearer tokens and normal TLS verification can be used; the [quickstart](docs/quickstart-1.0.md#open-webui) has notes for Open WebUI.

**7. Enroll devices.** Start with `helper_status` and `read_query_catalog`. Enrollment is an operator action with the instance stopped, using private JSON files (mode 600) outside the source repository:

```sh
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

See [Helper configuration](docs/helper-configuration.md), [Admin configuration](docs/admin-configuration.md) and the [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows).

## Verification and release

A release is the maintainer's personally signed checksum list together with the assets it covers. A candidate branch, digest, build or CI run without that signature is not a release.

- **Signature:** `netops-1.0.4-SHA256SUMS` is signed with Sigstore (`netops-1.0.4-SHA256SUMS.sigstore.json`); certificate identity `325383355+radek-cerny-soukr@users.noreply.github.com`, OIDC issuer `https://github.com/login/oauth`.
- **Covered assets:** `compose.yaml`, `env.example`, the release manifest (image index and per-architecture digests), the acceptance manifest, the per-architecture SBOMs, vulnerability scans and scan gate results, the vulnerability assessments and the acceptance reports (`acceptance-*.json`). The signed checksum list itself is the complete list of covered files.
- **Build once:** every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild.
- **Vulnerabilities:** each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding ships with a written assessment (`netops-1.0.4-vulnerability-assessments.json`). The digests of the latest release are rescanned daily against its assessments.
- **Acceptance of 1.0.4:** this release is accepted in proportion to its change; the [release notes](release/notes-1.0.4.md#acceptance) list the checks, and the acceptance reports covered by the signed checksum list record the results. The acceptance of 1.0.3 is described in its [release notes](release/notes-1.0.3.md#acceptance).

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
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request; other authenticated requests share the remaining slots within the limit of 16.
- The request body has a 60-second receipt deadline. Since 1.0.3 the gateway has a separate 60-second deadline for the whole buffered, audited MCP response send sequence, not for each chunk. This does not bound execution time or prove that the client application read the response. During body delivery a receive watcher also detects ASGI disconnect events. An observed disconnect, timeout, cancellation, receive-channel or send-channel failure attempts an interruption record when the audit is writable, and the operation slot is released. A small buffered send or a close after the monitored phase may go unobserved; inspect `audit pending` before repeating an operation. See the [1.0.3 response-delivery notes](release/notes-1.0.3.md#response-delivery).
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- Syslog records remain bounded at 8 MiB and use numbered 1024-byte parts with a persistent record ID and whole SHA256. Messages are at most 1618 bytes including their header. Configure a dedicated receiver archive filtered by RFC5424 APP-NAME `netops`, preserving exact MSG+LF, before the first start. Offline `audit reassemble --record-id` freezes the first complete SHA-valid set in archive order: later conflicts or invalid rows preserve its bytes and produce typed warnings/exit 3; earlier validation or input-read errors give exit 2 without record output. Keep older 1.0 full-record archives separately. Native default-limit storage checks verified rsyslog 8.2504 and 8.2512 with gtls and ossl and syslog-ng 4.12 on arm64 and amd64, each receiver running in a container.
- There is no supported provisioning path for the schema registry/library files of Helper `schema_read` and `fortios_diagnostics`, the extra input files of Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline and schema workflows.
- `ftp_list` is refused in the shipped SSH/HTTPS-only profile before any device contact, and no configuration enables it. Its engine checks the requested path against the target's `sftp_roots` only lexically, as a canonical absolute path equal to a root or below it; unlike `sftp_stat`, it does not let the server resolve the path, so a symbolic link below a root that leads out of it would not be refused.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check samples at a nominal 50 ms interval and can miss short-lived processes; see the [1.0.1 release notes](release/notes-1.0.1.md) for the exact attribution rule.

## 0.x releases and packaging

Version 1.0 does not migrate 0.x data or modify 0.x volumes. Previously published component releases remain available and unchanged. The new product is not published to PyPI by default. An inventory written for 0.x needs the 1.0 Helper section and the English device roles `perimeter`, `internal` and `lab`.

## License

NetOps is an open-source project by Radek Černý, distributed under the [MIT license](LICENSE). Claude Code and Codex assist implementation and independent review; compatible MCP clients remain vendor-neutral.

## Disclaimer

NetOps is open-source software provided **"as is", without warranty of any kind**, as stated in the [MIT license](LICENSE). You use it entirely **at your own risk**. The author currently has no plans to offer a commercial NetOps product or paid support. The MIT license permits commercial use, forks and redistribution.

- **No liability.** The [MIT license](LICENSE) disclaims liability for the software's authors or copyright holders for claims, damages or other liability arising from the software or its use, including changes that the Admin role makes to network devices.
- **No obligation to support or fix.** There is no service-level agreement and no commitment to provide support, answer questions, fix defects or security issues, publish updates or keep the project maintained. Any fix or release is voluntary and may never happen.
- **Your responsibility.** Before any production use, you are responsible for evaluating NetOps in your environment, verifying device accounts and permissions, keeping configuration backups, testing changes, and following your organization's policies and applicable law.
- **Not a vendor product.** NetOps is not a product of Fortinet, Extreme Networks, Cisco, Arista, Juniper, Ruckus or any other vendor whose devices or software it supports, nor of the vendors of the MCP clients and models named in this documentation. These vendors bear no responsibility for defects or errors in NetOps or for its effects on their devices, and they provide no support for it. Product and company names are trademarks of their respective owners and are used only to describe compatibility.
- **No certification.** Published tests, qualification results and supported-platform lists describe their documented scope and observations. They are not a guarantee, certification or fitness-for-purpose statement for your deployment.
- **Forks and redistributions.** Anyone may fork or redistribute NetOps under the MIT license, including commercially. Such versions are not provided, endorsed or supported by the author, and they create no obligation on the author's part toward their users.
