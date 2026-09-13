# Configuration

## Local proxy

The proxy uses these environment variables:

| Variable | Default |
| --- | --- |
| `NETOPS_VAULT_PATH` | `$XDG_CONFIG_HOME/netops-helper/vault.json` |
| `NETOPS_KNOWN_HOSTS_PATH` | `~/.ssh/known_hosts` |
| `NETOPS_TARGET_POLICY_PATH` | `$XDG_CONFIG_HOME/netops-helper/target-policy.json` |
| `NETOPS_MASTER_ALIAS` | `netops-runner` |

### Credential vault structure and protocol use

The credential file is one valid JSON object containing two kinds of records:

- exactly one runner SSH record under the alias selected by `NETOPS_MASTER_ALIAS`;
- one separate target record for every enrolled device alias.

It is not JSONL: whitespace and line wrapping are irrelevant, and the complete file must parse as one object. Set mode `600`. This synthetic shape uses documentation-only names and placeholders:

```json
{
  "netops-runner": {
    "host": "runner.example.invalid",
    "port": 22,
    "login": "<RUNNER_SSH_LOGIN>",
    "password": "<RUNNER_SSH_PASSWORD>"
  },
  "edge-a": {
    "host": "device.example.invalid",
    "port": 22,
    "login": "<TARGET_READ_ONLY_LOGIN>",
    "password": "<TARGET_PASSWORD>",
    "snmp_community": "<SEPARATE_READ_ONLY_COMMUNITY>"
  }
}
```

If `NETOPS_MASTER_ALIAS` is changed, its value must exactly match the runner key in this object. The runner record is used only for the proxy-to-runner SSH transport: its `host`, `port`, `login`, and `password` are not target credentials. Do not add the runner alias to `target-policy.json`; only device aliases have target-policy entries, and the proxy rejects the runner alias as a target.

Each target record has exactly `host`, `port`, `login`, and `password`, plus optional `snmp_community`. `host` must be a canonical IPv4 literal or canonical lowercase hostname without a trailing dot. IPv6 target hosts are not supported. `port` is an integer from 1 through 65535.

For a target record, the same `login` and `password` are used by `ssh_read`, `sftp_stat`, and `ftp_list` over either FTPS or plain FTP. The target vault `port` is only the SSH/SFTP port; the FTP/FTPS control port is the `ftp_list` argument and must also be explicitly enrolled in target egress. The negotiated FTP passive data port must fall in an explicitly enrolled TCP range.

> **Plain FTP credential warning:** `ftp_list(use_tls=false)` transmits that same target `login`, `password`, and directory-listing data without encryption. It requires `acknowledge_unencrypted=true`, but acknowledgement does not add confidentiality. Prefer FTPS. If legacy FTP is unavoidable, create a separate least-privilege remote FTP identity and a dedicated target alias instead of reusing an SSH identity.

For a dedicated FTP identity, set `ssh_platform: null` and `enabled_queries: []`, and make the remote service/account reject SSH and SFTP. Target policy alone cannot make the alias FTP-only: `sftp_roots` is the shared path allowlist needed by `ftp_list`, and it also authorizes a proxy call to `sftp_stat`. Device-side protocol denial remains mandatory.

The optional SNMP value must be a different secret from the target password, contain 3-255 printable UTF-8 bytes, and be omitted when SNMP is unused. There is no password fallback for SNMP.

Never place credentials in the project directory, command line, logs, target policy, generated egress bundle, or source control. The runner password is never exported into the `ssh` process environment; the proxy hands it to its own askpass re-execution once over a private abstract socket. Password-backed records are a portability compromise. A dedicated secret broker and platform-appropriate key or certificate authentication would be preferable in a separately designed integration, but the stock proxy does not implement those alternatives.

> SNMPv2c provides no encryption. Its community is transmitted in plaintext in UDP packets. Use a separate least-privilege read-only community, restrict UDP egress and device source ACLs, and prefer SNMPv3 when available.

## Exact target policy

`target-policy.json` is credential-free but security- and topology-sensitive. Copy [the example](../config/target-policy.example.json), replace every documentation address, and review every scope.

The reserved `_egress` object configures host-firewall generation and is never a target alias. It must contain exactly these eight fields:

| Field | Exact contract |
| --- | --- |
| `schema_version` | Integer `1`. |
| `profile` | `"strict-target"` or `"lan-constrained"`. |
| `backend` | `"iptables"`; no other backend is reviewed. |
| `bridge_name` | `"nh-egress0"`, matching Compose. |
| `network_name` | `"netops-helper"`, matching Compose. |
| `ipv6_mode` | `"deny"`, paired with Compose `enable_ipv6: false`. |
| `dns_resolvers` | At most 16 unique canonical IPv4 literals. |
| `lan_cidrs` | At most 32 unique canonical IPv4 CIDRs, with profile rules below. |

`strict-target` requires `lan_cidrs: []` and keeps each target's destinations associated with only that target's effective ports, ranges, and ICMP permission. `lan-constrained` requires a non-empty `lan_cidrs` list; every CIDR must be wholly inside one RFC1918 block, and every enrolled target destination must lie within the declared CIDR union. It grants the union of every enrolled target's TCP/UDP ports and ranges plus ICMP permission throughout every declared CIDR, so it is intentionally broader than per-target isolation.

Any target with `allow_dns: true` requires at least one global resolver. A hostname target additionally requires `allow_dns: true`, non-empty explicitly enrolled canonical IPv4 results, and global resolvers; every runtime IPv4 result must remain within the target list. DNS rules allow TCP and UDP port 53 only to the listed resolver addresses, but do not filter query names.

The egress generator reads `NETOPS_MASTER_ALIAS` independently. When a non-default runner alias is used, export the same `NETOPS_MASTER_ALIAS` value for both `remote_mcp_proxy.py` and every invocation of `generate_egress_rules.py`. The value must name the runner vault record, and that alias must remain absent from target policy.

Each target permits only these keys:

- `account_role`, `ssh_platform`, `enabled_queries`, `read_inventory`, and `sftp_roots`;
- `fortios_output_standard_verified`, `legacy_ssh`, `rate_limit`, and `egress`.

Unknown keys fail closed. `account_role`, `ssh_platform`, `enabled_queries`, and the exact `egress` object are mandatory. An old-format policy is not interpreted as unrestricted access. Version 0.2.0 removes `https_get`; the legacy `https_endpoints` key is therefore rejected as an unknown field and must be deleted during upgrade. Set `ssh_platform: null` and `enabled_queries: []` to disable SSH reads.

The hidden proxy-to-server authentication envelope also has an exact schema: identity fields plus the validated policy projection, with mandatory `ssh_platform`, `enabled_queries`, and `egress`. Unknown fields, legacy envelopes, alias mismatch, and client-supplied `auth_context` fail closed.

The account role is an operator assertion, not proof of remote authorization. Independently verify the account over the real access path as described in [Read-only accounts](read-only-accounts.md).

### Discovery and information exposure

Call `helper_status` first. The proxy augments server status with valid non-runner target aliases and current per-target rate state. Invalid or incomplete records are counted in `invalid_target_count` but are not named.

Call `target_scope(target)` for one returned alias. The proxy handles this locally without contacting the target. It intentionally returns:

- alias, account role, SSH platform, and enabled query names;
- all enrolled interface, service, address, and switch inventory values;
- exact SFTP metadata/listing roots;
- full per-tool egress policy, including enrolled IPv4 addresses, ports/ranges, DNS/ICMP permission, and TLS server names;
- rate state, the enrolled legacy SSH profile, plus boolean SNMP and device host-key enrollment status.

It does not return the vault's `host` field, login, password, SNMP community, or host-key contents. This is not anonymity: a literal target address normally appears in `egress.addresses`, and hostname targets expose their enrolled IPv4 results. Roots, inventory names, and TLS names may also reveal topology. Keep `target_scope` available only inside the dedicated operational session and do not publish its output.

### SSH queries and inventory

`enabled_queries` is an opt-in subset for exactly one `ssh_platform`. The client supplies that same platform, an enabled public query name, and only the typed parameters declared for that query. It never supplies raw CLI. `read_query_catalog` lists all available names and metadata; `target_scope` lists what one target permits.

Inventory categories are validated against query-specific types. The broad mapping is:

- interface-like query slots use `interfaces`;
- service slots use `services`;
- address slots use canonical IP literals from `addresses`;
- switch/member slots use `switches`.

Some vendors use stricter interface or address grammar than the broad category. A value must pass the selected query's exact type and match the enrolled inventory byte-for-byte. Keep inventories narrow and review them after topology changes. Device output cannot enroll a value.

For FortiOS, set `fortios_output_standard_verified: true` only after an administrator persistently configures and independently verifies console `output standard`. Other platforms leave it `false`.

Phase 1 deliberately has no running, startup, full, or backup configuration query, no configuration export, no generic HTTP response-body or remote file-content reader, and no general device-log browser. Do not enroll secret stores, configuration backups, unrestricted log paths, or support bundles as SFTP roots even for metadata/listing access.

### Metadata and directory-listing roots

SFTP roots are bounded, canonical, absolute, non-root POSIX paths without NUL or `..`. `sftp_stat` metadata lookups and FTP/FTPS directory listings must equal an enrolled root or be descendants. A root never authorizes a file-body download: Phase 1 has no such tool.

Remote permissions or chroot remain necessary because lexical checks cannot resolve remote symlinks, and `sftp_stat` uses the server's normal stat semantics. Grant only metadata/listing permission and keep configuration backups, secrets, private keys, support bundles, and broad log trees outside these roots.

### Per-tool egress

Every target `egress` object has exactly:

- canonical IPv4 `addresses`;
- explicit `tcp_ports` and `udp_ports`;
- non-overlapping `tcp_port_ranges` and `udp_port_ranges` as `[[start,end]]`;
- boolean `allow_icmp` and `allow_dns`;
- canonical `tls_server_names` for an explicit TLS SNI different from the target host.

A literal target `host` must be canonical IPv4 and occur in `addresses`. A hostname target must be canonical lowercase DNS form and requires `allow_dns: true`, non-empty explicit IPv4 `addresses`, and global DNS resolvers. Every runtime IPv4 resolution result must be enrolled. An IPv6 literal is rejected even if the local known-hosts parser is capable of safely recognizing IPv6-formatted entries.

Authorization is tool-specific:

| Tool | Required scope |
| --- | --- |
| `dns_probe` | `allow_dns` |
| `icmp_probe` | `allow_icmp` |
| `tcp_probe`, `tls_probe` | explicit TCP port/range; TLS also checks alternate SNI |
| `ssh_read` | exact platform and enabled query |
| `sftp_stat` | at least one enrolled root; metadata only |
| `snmp_get` | explicit UDP port/range and separate community |
| `ftp_list` | explicit TCP control port, at least one passive TCP range, and file root |

The firewall generator derives the credential port only when at least one SSH query or SFTP metadata root is enabled. Do not duplicate that derived port in explicit `tcp_ports`. Explicit TCP scope remains necessary for TCP/TLS probes and FTP; no HTTPS port is derived.

See [Egress control](egress-control.md) for schema-3 generation, review, application, and residual host-access limits.

## Rate limiting and snapshots

Each proxy process enforces a per-alias sliding window before forwarding; two vault aliases that point at the same host have separate windows. The default is 30 device calls per 60 seconds; `requests` is bounded to 1-60 and `window_seconds` to 1-3600. Rate state is process-local, not a distributed device quota.

A valid `ssh_read` continuation with integer `offset > 0` does not consume another device rate slot because it must use an existing in-memory SSH snapshot. Every other device call consumes a slot. Expired or missing continuation state fails and must restart at offset 0.

An offset-0 SSH read captures at most 2 MB after sanitization. Output exceeding the capture limit fails rather than silently truncating. A retained SSH snapshot lasts at most 120 seconds, up to eight entries per process; the last page discards it. No other Phase-1 tool has a body snapshot or continuation path.

### Legacy SSH algorithms

Since the release which introduces this field, the SSH and SFTP transports refuse the `ssh-rsa` host key algorithm and SHA-1 key exchange for **every** platform. Both were silently available to every target up to and including 0.2.3, where only FortiOS targets rejected SHA-1 key exchange. This is a behaviour change: a target which offers no algorithm outside that default stops being reachable until the exception below is enrolled for it.

`ssh-rsa` means an RSA host key signed with SHA-1. It is not the same as having an RSA host key: a target which offers `rsa-sha2-256` or `rsa-sha2-512` keeps working with its existing `ssh-rsa` known-hosts entry and needs no exception, because the entry names the key, not the signature algorithm. Only a target which offers nothing but `ssh-rsa`, typically an old switch or an unpatched appliance, is affected.

The exception is named per target, in that target's policy entry, and nowhere else:

```json
"device-alias": {
  "account_role": "read-only",
  "legacy_ssh": "rsa-sha1"
}
```

`legacy_ssh` accepts exactly `null` (the default, modern algorithms only) or the string `"rsa-sha1"`. `"rsa-sha1"` re-enables the `ssh-rsa` host key algorithm for that one target and nothing else. Any other value, including an algorithm name, fails closed in the proxy, in the egress generator, and in the server's authentication envelope.

There is deliberately no global switch and no list of algorithm names in configuration. A named profile expands to a fixed algorithm set written in the code, so a policy file can never widen the cryptography of a connection beyond what the component already ships and reviewed. Enabling SHA-1 for one target must not enable it for the others, which a global option or an inherited default could not guarantee.

SHA-1 key exchange has no profile at all and stays disabled for every target. If a device needs it, it is out of scope for this component.

One profile governs both transports. `ssh_read` (Netmiko/Paramiko) and `sftp_stat` (asyncssh) read the same field, so a target cannot be reachable over one and unreachable over the other.

An enrolled exception is visible at runtime, not only in the policy file: `target_scope` returns `legacy_ssh` for the alias, and every audit record for a device call on that target carries `"legacy_ssh":"rsa-sha1"`. Records for targets without the exception stay unchanged and carry no such field.

When a target needs the exception and does not have it, the tool result names it:

```text
LegacySshProfileRequired: target "device-alias" offers no SSH host key or key exchange
algorithm enabled by default; for a target which offers only ssh-rsa host keys set
"legacy_ssh": "rsa-sha1" in its target-policy.json entry, which allows them for that
target alone. SHA-1 key exchange has no profile and stays disabled.
```

That message replaces the underlying library error, which reports a host key mismatch as a connection timeout and names no remedy. It is raised only when the library proves the algorithm sets do not intersect; an unrelated timeout, an authentication failure, or a wrong host key keeps its own error.

On the SFTP path the message depends on which side reports first. Measured against a device which offers only `ssh-rsa`, the device closed the connection before asyncssh evaluated the offer, so the result was `ConnectionLost: Connection lost` with no algorithm detail. Read an opaque SFTP connection failure against an old target as the same cause and apply the same fix; `ssh_read` against the same target names it explicitly.

## Host keys

The runner SSH connection uses the full operator-configured known-hosts file locally. For device SSH/SFTP, the proxy extracts and injects only entries matching the selected target host and port. Comments, unrelated hosts, and unrelated keys remain on the proxy host.

Plain, hashed, custom-port, marker, comma-hostlist, and IPv6-formatted known-hosts records are parsed fail-closed. Parser support for an IPv6 record format does not make an IPv6 target reachable: runtime target hosts remain canonical IPv4 literals or enrolled hostnames resolving only to enrolled IPv4 addresses.

Unknown and changed keys fail closed. Never disable strict host-key verification or use automatic first-use acceptance for deployment.

## Stable proxy and SSH transport errors

After a syntactically valid `tools/call` reaches recognized tool handling, target-, policy-, and argument-level rejection returns a JSON-RPC error with `data.category`. Malformed JSON-RPC envelopes, invalid batches, unknown methods, duplicate IDs, and transport failure follow their separate protocol or transport paths and are not all promised a category from this table. The categories below are intentionally distinct:

| Category | JSON-RPC code | Exact public message |
| --- | ---: | --- |
| `unknown_alias` | `-32001` | `The target alias is not present in the credential vault.` |
| `policy_rejected` | `-32002` | `The target is not enrolled by policy.` |
| `role_rejected` | `-32003` | `The target account is not explicitly enrolled as read-only.` |
| `vault_permission` | `-32004` | `Credential vault permissions are invalid; mode 600 is required.` |
| `vault_schema` | `-32005` | `The credential vault schema is invalid.` |
| `auth_material` | `-32006` | `Required authentication material is unavailable or invalid.` |
| `rate_limit` | `-32007` | `The target request rate limit is exceeded.` The data includes `retry_after_seconds`. |
| `policy_schema` | `-32008` | `The target policy schema is invalid.` |
| `policy_scope` | `-32009` | `The requested operation is outside the enrolled target scope.` |
| `invalid_params` | `-32602` | `Tool arguments do not match the exact input schema.` |
| `internal_error` | `-32603` | `The proxy encountered an internal error.` |

Do not interpret `rate_limit`, `policy_scope`, or `invalid_params` as credential failure. Correct the indicated operational state instead of rotating a valid password.

The outer runner SSH process cannot return a JSON-RPC response if transport fails. It writes exactly one or more fixed, secret-redacted diagnostics to local stderr in this form:

```text
netops_proxy_transport category=<category> message=<fixed public message>
```

The categories are:

| Category | Exact public message(s) |
| --- | --- |
| `runner_alias` | `The runner alias is not present in the credential vault.` |
| `vault_permission` | `Credential vault permissions are invalid; mode 600 is required.` |
| `vault_schema` | `The credential vault schema is invalid.` |
| `auth_material` | `Required authentication material is unavailable or invalid.` or `The proxy script is not executable.` |
| `ssh_host_key` | `SSH host-key verification failed.` |
| `ssh_authentication` | `SSH authentication to the runner failed.` |
| `ssh_connection` | `The SSH connection to the runner failed.` |
| `remote_exec` | `The fixed remote container command could not start.` |
| `ssh_timeout` | `The remote MCP transport timed out.` |
| `ssh_transport` | `The local SSH process could not start.`, `The local SSH process pipes are unavailable.`, or `The remote MCP SSH transport failed.` |

Raw SSH stderr, topology details, remote command output, and credentials are not relayed. The proxy first sanitizes the bounded raw stream, uses it only to choose a fixed category, and emits fixed public text. Use that category plus runner-side privileged logs for diagnosis; do not weaken host-key verification to obtain more detail.

## Mandatory audit failure semantics

Every device-touching server operation requires a durable `started` audit record before network work and a terminal record afterward. If the preflight write fails, the operation is not started. If the terminal write fails, the operation may already have succeeded even though its response is replaced by an audit failure. A kill or host failure can leave only `started`; that means completion is unknown.

The implementation distinguishes `AuditPreflightError` and `AuditPostOperationError`. Their Python `operation_started` class attributes are internal runtime/test semantics, not a documented structured JSON-RPC or MCP response field. Clients must not parse or depend on such a wire field. Diagnose using the returned tool failure, the presence or absence of the paired audit records, and server-side logs. This fail-closed observability policy is intentional; an unwritable audit volume is not a device-authentication failure.

## Redaction boundary

Response redaction is best-effort defense in depth. It preserves operational identifiers such as addresses, MACs, hostnames, usernames, serials, and timestamps while removing injected credentials and recognized explicit secret forms. It can still miss a novel or unusually formatted secret, and a heuristic match can replace legitimate neighboring prose. Therefore a query or metadata/listing root is safe to enroll only when its source is expected not to contain secrets before redaction. Do not expose configuration, backup, credential, private-key, support-bundle, or broad log locations and rely on the sanitizer to make them safe.

## Private TLS and FTPS CA, SAN, and pins

The stock image contains the base image's public CA bundle. `tls_probe` and FTPS without an alias-specific pin require a certificate chain to a trusted root and a matching SAN. Private enterprise CAs and self-signed device certificates normally fail by design until a reviewed private image adds the required trust material.

1. Obtain the issuing CA certificate as PEM, never its private key. For a deliberately self-signed leaf, the reviewed self-signed certificate is the trust anchor.
2. Verify certificate ownership, validity, purpose, and SHA-256 fingerprint through an independent trusted channel. Do not trust a certificate merely because it was presented by the unverified endpoint.
3. Confirm the target certificate has an exact Subject Alternative Name. `tls_probe` verifies the selected target name or enrolled alternate SNI; system-trust FTPS verifies the credential target hostname/address. A legacy Common Name alone is insufficient.
4. In a private build copy, place a global trust anchor under `config/container/ca/` with a `.crt` suffix. Keep only reviewed CA/trust-anchor certificates there. Do not commit, export, or publish them; the public release gate rejects environment-specific trust material.
5. Build the private image. Preserve the stopped-container egress sequence: create/recreate it with `docker compose up --no-start --no-build --force-recreate`, rerun the egress checker, and only then `docker compose start`.
6. Enroll the exact TCP port and optional alternate SNI for `tls_probe`; for FTPS also enroll the control port, passive range, and directory root. Test the intended path in a controlled test environment. Never disable certificate-chain or hostname verification merely to make a test pass.

`tls_probe` returns verified certificate metadata only; it sends no HTTP request and reads no application response body. A different `server_name` is accepted only when that canonical name is enrolled in `tls_server_names`.

For FTPS only, a private image may use an alias-specific pin. Copy the independently reviewed PEM certificate to `config/container/certs/edge-a-cert`, then put only this shape in the private build's `config/container/tls-pins.json`:

```json
{
  "edge-a": {
    "sha256": "<64-lowercase-hex-leaf-certificate-sha256>",
    "certificate": "/etc/netops-helper/certs/edge-a-cert"
  }
}
```

The JSON key must exactly match the target alias. `certificate` must resolve to an existing file strictly beneath `/etc/netops-helper/certs/` in the image, and `sha256` is the exact lowercase SHA-256 digest of the peer leaf certificate in DER form. Keep the source certificate under `config/container/certs/`; the Dockerfile copies that directory to the runtime path. Never publish deployment-specific certificates or a populated pin file.

The alias-pin branch deliberately sets `check_hostname = False`. It still validates the peer chain against the specified certificate file, enables OpenSSL partial-chain verification when the runtime supports it, and separately compares the actual peer leaf digest with `sha256`. The digest comparison binds the exact leaf while the certificate file supplies the trust path. This branch does not claim SAN/hostname validation and does not apply to `tls_probe`.

Without an alias pin, FTPS uses system trust and verifies the target hostname/address against SAN. `tls_probe` always uses system trust and verifies the selected target or enrolled alternate SNI against SAN. A legacy Common Name alone is insufficient for those hostname-verifying paths.

A global trust anchor affects `tls_probe` and every unpinned FTPS connection in that private image. Review the complete CA, pin, and certificate directories on every rebuild. The public defaults intentionally contain no environment-specific trust material.

## Configuration review checklist

Before starting or restarting the helper, confirm:

- vault and transferred bundle modes are exactly `600`;
- the `NETOPS_MASTER_ALIAS` runner record is not a device target and every target has `account_role: "read-only"`;
- target host form, host keys, DNS results, and egress addresses agree;
- enabled queries and every typed inventory item are the minimum required;
- no configuration, backup, secret store, support bundle, or broad log root is exposed;
- TLS/FTPS certificate trust, SAN, and any FTPS pin are valid;
- SNMP community is separate from the target password and UDP scope is narrow;
- the schema-3 IPv4 bundle was regenerated, securely transferred, reviewed, explicitly applied, and checked;
- Docker network inspection reports the expected stable bridge and exact `EnableIPv6: false`;
- live negative tests cover denied target egress and attempted runner-host access.

## Container state

Only `/var/lib/netops-helper` is persistent inside the Compose service. It contains credential-free audit segments. The active segment and four retained segments are each limited to 2,000,000 bytes. The SSH continuation cache lives only in process memory, and temporary selected device host-key files live on tmpfs and are removed after use.
