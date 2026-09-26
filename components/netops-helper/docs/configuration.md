# Configuration

## The four operator files

The proxy reads four files. None of them is written by the tool, and every one of them is fail-closed: a file that does not match this page is refused as a whole.

| File | Variable | Default | Content |
| --- | --- | --- | --- |
| `inventory.json` | `NETOPS_INVENTORY_PATH` | `$XDG_CONFIG_HOME/netops-helper/inventory.json` | the device document of `netops_core.inventory`, file version 2 |
| `vault.json` | `NETOPS_VAULT_PATH` | `$XDG_CONFIG_HOME/netops-helper/vault.json` | the credential document of `netops_core.vault`, file version 2 |
| `egress-policy.json` | `NETOPS_EGRESS_POLICY_PATH` | beside the inventory | the eight fields the host-firewall generator needs |
| `runner.json` | `NETOPS_RUNNER_PATH` | beside the inventory | the runner the proxy reaches over SSH |

`target-policy.json`, `NETOPS_TARGET_POLICY_PATH`, `NETOPS_KNOWN_HOSTS_PATH` and `NETOPS_MASTER_ALIAS` are gone. A run that finds one of those files or variables stops with the transport category `legacy_configuration` and names the files above. There is no fallback and no migration tool: the enrollment is written once in the new shape and reviewed.

The common device fields and the credential records are documented by the shared access layer: [inventory](../../netops-core/docs/inventory.md) and [credential store](../../netops-core/docs/vault.md). This page documents what the helper adds: the `helper` section of a device, the cross-checks between the section and the common fields, the egress policy, and the runner file.

## The `helper` section of a device

A device belongs to the helper when its `helper` field is an object. The alias a client uses is the device `name`. The section holds exactly these fields; an unknown field is refused.

| Field | Required | Exact contract |
| --- | --- | --- |
| `account_role` | yes | `"read-only"`; any other value is `role_rejected` |
| `ssh_platform` | yes | a canonical platform name of `netops_core.platforms` (`fortios`, `exos`, `linux`, `cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `juniper_junos_els`, `ruckus_unleashed`) or `null`. An alias such as `fortinet` is refused here; the inventory carries canonical names |
| `enabled_queries` | yes | an opt-in subset of that platform's catalogue, unique, at most 256 names; empty when `ssh_platform` is `null` |
| `egress` | yes | exactly the eight fields below |
| `read_inventory` | no (`{}`) | `interfaces`, `services`, `addresses`, `switches`, `vlans`, `managed_switches`, `certificates`; every value canonical for its category |
| `sftp_roots` | no (`[]`) | canonical absolute paths below `/`, no `..`, no NUL, at most 2000 characters |
| `fortios_output_standard_verified` | no (`false`) | boolean operator assertion |
| `rate_limit` | no (30/60) | `requests` 1-60 and `window_seconds` 1-3600 |
| `snmp_credential` | no | the name of a vault record of kind `snmp-community`; absent disables `snmp_get` for that device |

Validation lives in `src/netops_helper/inventory.py` and is the same code in the proxy and in the egress generator. Besides the fields it checks the device it belongs to:

- `address` and `port` must both be set: the helper reaches a device over the network;
- an IPv4 `address` must appear in `egress.addresses`;
- a host name `address` requires `egress.allow_dns` and a non-empty `egress.addresses`, and the egress policy must declare at least one resolver;
- `host_key_fingerprint` must pin the host key, so `target_scope` reports `host_key_pinned: true` for every enrolled device;
- `credential` must name a vault record of kind `password` or `ssh-key`;
- `snmp_credential`, when present, must name a record of kind `snmp-community`; a `snmp_get` against a device without it fails with `auth_material`.

A complete device, with documentation values only:

```json
{
  "version": 2,
  "devices": [
    {
      "name": "device-alias",
      "platform": "linux",
      "address": "192.0.2.10",
      "port": 22,
      "role": "interni",
      "credential": "device-alias-account",
      "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "legacy_ssh": null,
      "auditor": null,
      "helper": {
        "account_role": "read-only",
        "ssh_platform": "linux",
        "enabled_queries": ["hostname", "neighbors"],
        "read_inventory": {
          "interfaces": ["example-interface"],
          "services": ["example.service"],
          "addresses": ["192.0.2.20"],
          "switches": ["example-switch"]
        },
        "sftp_roots": [],
        "fortios_output_standard_verified": false,
        "snmp_credential": "device-alias-community",
        "rate_limit": {"requests": 30, "window_seconds": 60},
        "egress": {
          "addresses": ["192.0.2.10"],
          "tcp_ports": [],
          "udp_ports": [161],
          "tcp_port_ranges": [],
          "udp_port_ranges": [],
          "allow_icmp": false,
          "allow_dns": false,
          "tls_server_names": []
        }
      }
    }
  ]
}
```

[`config/inventory.example.json`](../config/inventory.example.json) is that document. Copy it, replace every documentation address and name, and review every scope.

The account role is an operator assertion, not proof of remote authorization. Independently verify the account over the real access path as described in [Read-only accounts](read-only-accounts.md).

A device whose `helper` section is `null` belongs to another component of the family; the proxy refuses it as `policy_rejected` and never reads its credential.

## Credentials and protocol use

The vault is one mode-`600` or mode-`400` regular file holding one JSON object of credential records. A device record is of kind `password` or `ssh-key` and carries the `login`; the SNMP community is a separate record of kind `snmp-community` and carries no login. [`config/vault.example.json`](../config/vault.example.json) shows the three kinds with `replace-me` placeholders.

For a device, the same record authenticates `ssh_read`, `sftp_stat`, and `ftp_list` over either FTPS or plain FTP. The device `port` is only the SSH/SFTP port; the FTP/FTPS control port is the `ftp_list` argument and must also be enrolled in `egress`. The negotiated FTP passive data port must fall in an explicitly enrolled TCP range.

> **Plain FTP credential warning:** `ftp_list(use_tls=false)` transmits that same `login`, secret, and directory-listing data without encryption. It requires `acknowledge_unencrypted=true`, but acknowledgement does not add confidentiality. Prefer FTPS. If legacy FTP is unavoidable, create a separate least-privilege remote FTP identity and a dedicated device entry instead of reusing an SSH identity.

For a dedicated FTP identity, set `ssh_platform: null` and `enabled_queries: []`, and make the remote service/account reject SSH and SFTP. The section alone cannot make a device FTP-only: `sftp_roots` is the shared path allowlist needed by `ftp_list`, and it also authorizes a proxy call to `sftp_stat`. Device-side protocol denial remains mandatory.

The SNMP community must be a different secret from the device secret. There is no password fallback for SNMP.

Never place credentials in the project directory, command line, logs, inventory, generated egress bundle, or source control. The runner password is never exported into the `ssh` process environment; the proxy hands it to its own askpass re-execution once over a private abstract socket. A runner or device key is written to a mode-`600` file in the proxy's private temporary directory, which is removed when the proxy exits.

> SNMPv2c provides no encryption. Its community is transmitted in plaintext in UDP packets. Use a separate least-privilege read-only community, restrict UDP egress and device source ACLs, and prefer SNMPv3 when available.

## The egress policy file

`egress-policy.json` holds exactly the eight fields the host-firewall generator needs. It is credential-free but topology-sensitive. Copy [the example](../config/egress-policy.example.json).

| Field | Exact contract |
| --- | --- |
| `schema_version` | Integer `1`. |
| `profile` | `"strict-target"` or `"lan-constrained"`. |
| `backend` | `"iptables"`; no other backend is reviewed. |
| `bridge_name` | `"nh-egress0"`, matching Compose. |
| `network_name` | `"netops-helper"`, matching Compose. |
| `ipv6_mode` | `"deny"`, paired with Compose `enable_ipv6: false`. |
| `dns_resolvers` | At most 16 unique canonical IPv4 literals. |
| `lan_cidrs` | At most 32 unique canonical IPv4 CIDRs, with the profile rules below. |

`strict-target` requires `lan_cidrs: []` and keeps each device's destinations associated with only that device's effective ports, ranges, and ICMP permission. `lan-constrained` requires a non-empty `lan_cidrs` list; every CIDR must be wholly inside one RFC1918 block, and every enrolled destination must lie within the declared CIDR union. It grants the union of every enrolled device's TCP/UDP ports and ranges plus ICMP permission throughout every declared CIDR, so it is intentionally broader than per-device isolation.

Any device with `allow_dns: true` requires at least one resolver here, and the proxy refuses the device when the list is empty. DNS rules allow TCP and UDP port 53 only to the listed resolver addresses, but do not filter query names.

## The runner file

`runner.json` names the single host the proxy reaches over SSH to run the fixed remote command. The runner is not a device: it has no inventory entry, no section, and can never be addressed as a target.

```json
{
  "version": 1,
  "host": "runner.example.invalid",
  "port": 22,
  "credential": "runner-account",
  "host_key_fingerprint": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
}
```

`version` must be `1`. `host` is a bare name or address without a leading `-` and without `@`. `credential` names a vault record of kind `password` or `ssh-key`; a password is handed over through the askpass socket, a key through a mode-`600` identity file with `IdentitiesOnly=yes`. `host_key_fingerprint` is the same pin form as a device: before the credential is used, the proxy runs `ssh-keyscan` against `host` and `port`, keeps the offered line only when its fingerprint equals the pin, and writes exactly that one line into the private `UserKnownHostsFile` of the run. A pin that no offered key matches ends the run with the transport category `ssh_host_key` before any credential is read.

## Per-tool egress

Every `egress` object of a section has exactly:

- canonical IPv4 `addresses`;
- explicit `tcp_ports` and `udp_ports`;
- non-overlapping `tcp_port_ranges` and `udp_port_ranges` as `[[start,end]]`;
- boolean `allow_icmp` and `allow_dns`;
- canonical `tls_server_names` for an explicit TLS SNI different from the device address.

Authorization is tool-specific:

| Tool | Required scope |
| --- | --- |
| `dns_probe` | `allow_dns` |
| `icmp_probe` | `allow_icmp` |
| `tcp_probe`, `tls_probe` | explicit TCP port/range; TLS also checks alternate SNI |
| `ssh_read` | exact platform and enabled query |
| `sftp_stat` | at least one enrolled root; metadata only, a directory only as a count |
| `snmp_get` | explicit UDP port/range and an enrolled `snmp_credential` |
| `ftp_list` | explicit TCP control port, at least one passive TCP range, and file root |

The firewall generator derives the device `port` only when at least one SSH query or SFTP metadata root is enabled. Do not duplicate that derived port in explicit `tcp_ports`. Explicit TCP scope remains necessary for TCP/TLS probes and FTP; no HTTPS port is derived.

See [Egress control](egress-control.md) for schema-3 generation, review, application, and residual host-access limits.

## The hidden authentication envelope

The current proxy-to-server envelope has an exact schema and carries exactly: `alias`, `host`, `port`, `login`, `credential_kind`, `secret`, `host_key_fingerprint`, `legacy_ssh`, `account_role`, `ssh_platform`, `enabled_queries`, `read_inventory`, `sftp_roots`, `fortios_output_standard_verified`, `egress`, and `snmp_community` only for `snmp_get`. The removed `known_hosts` and `password` keys are refused as unsupported fields, so an old proxy fails closed instead of half-working. Unknown fields, a legacy envelope, an alias mismatch, and a client-supplied `auth_context` all fail closed.

### Discovery and information exposure

Call `helper_status` first. The proxy augments server status with the names of the devices whose helper section is valid, and the current per-device rate state. A device whose section is refused is counted in `invalid_target_count` but is not named.

Call `target_scope(target)` for one returned alias. The proxy handles this locally without contacting the target. It intentionally returns:

- alias, account role, SSH platform, and enabled query names;
- all enrolled interface, service, address, and switch inventory values;
- exact SFTP metadata/listing roots;
- full per-tool egress policy, including enrolled IPv4 addresses, ports/ranges, DNS/ICMP permission, and TLS server names;
- rate state, the enrolled legacy SSH profile, `snmp_enrolled`, and `host_key_pinned`, which is always true because the loader refuses a device without a pin.

It does not return the device address, the login, any credential name, the secret, the SNMP community, or the host key pin. This is not anonymity: a literal device address normally appears in `egress.addresses`, and host name devices expose their enrolled IPv4 results. Roots, inventory names, and TLS names may also reveal topology. Keep `target_scope` available only inside the dedicated operational session and do not publish its output.

### SSH queries and inventory

`enabled_queries` is an opt-in subset for exactly one `ssh_platform`. The client supplies that same platform, an enabled public query name, and only the typed parameters declared for that query. It never supplies raw CLI. `read_query_catalog` lists all available names and metadata; `target_scope` lists what one device permits.

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

## Rate limiting and snapshots

Each proxy process enforces a per-device sliding window before forwarding; two devices that point at the same address have separate windows. The default is 30 device calls per 60 seconds; `requests` is bounded to 1-60 and `window_seconds` to 1-3600. Rate state is process-local, not a distributed device quota.

A valid `ssh_read` continuation with integer `offset > 0` does not consume another device rate slot because it must use an existing in-memory SSH snapshot. Every other device call consumes a slot. Expired or missing continuation state fails and must restart at offset 0.

An offset-0 SSH read captures at most 2 MB after sanitization. Output exceeding the capture limit fails rather than silently truncating. A retained SSH snapshot lasts at most 120 seconds, up to eight entries per process; the last page discards it. No other Phase-1 tool has a body snapshot or continuation path.

The proxy's `rate_limit` above and the server's own connection pacing are independent controls at different layers. `rate_limit` bounds how many device calls the proxy forwards in a window; it is per device, configurable, and enforced before the server is ever reached. Server-side connection pacing instead bounds how fast the *server* opens SSH-family connections to one address and port - a fixed table in the code, not configuration, and unaffected by `rate_limit` in either direction: a generous `rate_limit` does not make FortiOS connections go out faster, and a strict one does not add spacing on a platform that has none. See [Security model](security-model.md#device-side-authorization).

### Legacy SSH algorithms

The SSH and SFTP transports refuse the `ssh-rsa` host key algorithm and SHA-1 key exchange by default for **every** platform. When migrating an older deployment that allowed these algorithms implicitly, a target which offers no algorithm outside that default stops being reachable until the exception below is enrolled for it.

`legacy_ssh` is a common device field of the shared inventory, not a field of the `helper` section, so one enrolled exception is the same exception for every component that reaches that device.

`ssh-rsa` means an RSA host key signed with SHA-1. It is not the same as having an RSA host key: a target which offers `rsa-sha2-256` or `rsa-sha2-512` keeps working with its existing `ssh-rsa` known-hosts entry and needs no exception, because the entry names the key, not the signature algorithm. Only a target which offers nothing but `ssh-rsa`, typically an old switch or an unpatched appliance, is affected.

The exception is named per device, in that device's inventory entry, and nowhere else:

```json
{
  "name": "device-alias",
  "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "legacy_ssh": "rsa-sha1"
}
```

A profile requires a host key pin: weakening the algorithms of a session whose key is not recognised would make no sense, and the inventory refuses it.

`legacy_ssh` accepts exactly `null` (the default, modern algorithms only), `"rsa-sha1"` or `"rsa-sha1-dh14"`. `"rsa-sha1"` re-enables the `ssh-rsa` host key algorithm for that one device and nothing else. `"rsa-sha1-dh14"` does the same and adds exactly one SHA-1 key exchange, `diffie-hellman-group14-sha1`, for that one device; it exists for classic Cisco IOS switches and routers, which offer no other key exchange (measured on IOSv 15.9(3)M12 and IOSvL2 15.2: `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1` and `diffie-hellman-group-exchange-sha1` only, and no command to change it). `diffie-hellman-group1-sha1` and the SHA-1 group exchange stay disabled even there. Any other value, including an algorithm name, fails closed in the inventory loader and in the server's authentication envelope.

There is deliberately no global switch and no list of algorithm names in configuration. A named profile expands to a fixed algorithm set written in the code, so an operator file can never widen the cryptography of a connection beyond what the component already ships and reviewed. Enabling SHA-1 for one target must not enable it for the others, which a global option or an inherited default could not guarantee.

SHA-1 key exchange stays disabled for every target that does not carry `"rsa-sha1-dh14"`. Because `ssh-keyscan` cannot be told to offer a SHA-1 key exchange, the host key of such a target is read by one `ssh` connection that authenticates with nothing (every authentication method off, login `netops-hostkey`) into a private, temporary known-hosts file; the pinned fingerprint is then checked exactly as for a key scan, and the credential is used only afterwards. The device logs that connection as a failed login of `netops-hostkey`.

One profile governs both transports. `ssh_read` (the OpenSSH `ssh` client of `netops-core`) and `sftp_stat` (the OpenSSH `sftp` client of `netops-core`) read the same field, so a target cannot be reachable over one and unreachable over the other. On both paths `"rsa-sha1"` becomes the two options `HostKeyAlgorithms=+ssh-rsa` and `PubkeyAcceptedAlgorithms=+ssh-rsa`, and `"rsa-sha1-dh14"` those two and `KexAlgorithms=+diffie-hellman-group14-sha1`, appended after the hardening options so an exception can only widen the algorithm list, never replace the hardening.

An enrolled exception is visible at runtime, not only in the policy file: `target_scope` returns `legacy_ssh` for the alias, and every audit record for a device call on that target carries `"legacy_ssh":"rsa-sha1"`. Records for targets without the exception stay unchanged and carry no such field.

When a target needs the exception and does not have it, the tool result names it:

```text
LegacySshProfileRequired: target "device-alias" offers no SSH host key or key exchange
algorithm enabled by default; for a target which offers only ssh-rsa host keys set
"legacy_ssh": "rsa-sha1" in its inventory.json entry, which allows them for that
device alone; a target which also offers only SHA-1 key exchange needs "legacy_ssh":
"rsa-sha1-dh14", which adds diffie-hellman-group14-sha1 and nothing else for that device alone.
```

On the `ssh_read` path that message replaces the client's own refusal, which names the offered algorithm but no remedy. It is raised only when the client reports that the algorithm sets do not intersect and the device has no profile yet; an unrelated timeout, an authentication failure, or a wrong host key keeps its own error, and a device that already carries the exception gets the plain failure.

On the SFTP path the message depends on which side reports first. `sftp` is a facade over `ssh`, so when the client reports the failed negotiation the same remedy appears. Measured on 13 September 2026 against a device which offers only `ssh-rsa`, the device closed the connection before the client had evaluated the offer; then standard error carries no algorithm marker and all that is left is the generic failure - a closed connection, exit status 255, no algorithm named. Read an opaque SFTP connection failure against an old target as the same cause and apply the same fix, `legacy_ssh` for that one device; `ssh_read` against the same target usually names it explicitly, so ask the exec channel first.

## Host keys

There is no `known_hosts` file any more, on either side. Trust is the pin, and the pin is a field of the device.

For a device, `host_key_fingerprint` travels in the envelope and the **server** verifies it: before any credential is used, the server runs `ssh-keyscan` against the enrolled address, one key type at a time (for a `"rsa-sha1-dh14"` target the unauthenticated `ssh` connection described above instead), compares `SHA256:` fingerprints, and refuses the operation by name when the pinned key was not offered. It never prints a key. The same verified key becomes the single known-hosts line of that one operation, for both the `ssh` path (`ssh_read`) and the `sftp` path (`sftp_stat`), and it is removed with the operation. Both paths use the same `netops_core.hostkey` code as the auditor.

For the runner, the proxy does the same locally with `ssh-keyscan` before it starts `ssh`, and writes the one matching line into its private temporary directory.

Obtain both pins over an independently trusted channel, exactly as `ssh-keygen -lf` prints them. For a `"rsa-sha1-dh14"` device a plain `ssh-keyscan` cannot negotiate at all, so take the fingerprint from the device itself or from an OpenSSH client that carries the same three options over a path you trust. A wrong or changed key fails closed on first contact; there is no first-use acceptance to disable.

## Stable proxy and SSH transport errors

After a syntactically valid `tools/call` reaches recognized tool handling, target-, policy-, and argument-level rejection returns a JSON-RPC error with `data.category`. Malformed JSON-RPC envelopes, invalid batches, unknown methods, duplicate IDs, and transport failure follow their separate protocol or transport paths and are not all promised a category from this table. The categories below are intentionally distinct:

| Category | JSON-RPC code | Exact public message |
| --- | ---: | --- |
| `unknown_alias` | `-32001` | `The target alias is not present in the credential vault.` No device of that name is in the inventory. |
| `policy_rejected` | `-32002` | `The target is not enrolled by policy.` The device exists but has no helper section. |
| `role_rejected` | `-32003` | `The target account is not explicitly enrolled as read-only.` |
| `vault_permission` | `-32004` | `Credential vault permissions are invalid; mode 600 or 400 is required.` |
| `vault_schema` | `-32005` | `The credential vault schema is invalid.` |
| `auth_material` | `-32006` | `Required authentication material is unavailable or invalid.` |
| `rate_limit` | `-32007` | `The target request rate limit is exceeded.` The data includes `retry_after_seconds`. |
| `policy_schema` | `-32008` | `The target policy schema is invalid.` The inventory or the egress policy was refused. |
| `policy_scope` | `-32009` | `The requested operation is outside the enrolled target scope.` |
| `invalid_params` | `-32602` | `Tool arguments do not match the exact input schema.` |
| `runner_file` | `-32010` | `The runner file is unavailable or invalid.` |
| `legacy_configuration` | `-32011` | The message names the four files and the removed variables. |
| `internal_error` | `-32603` | `The proxy encountered an internal error.` |

Do not interpret `rate_limit`, `policy_scope`, or `invalid_params` as credential failure. Correct the indicated operational state instead of rotating a valid password.

The outer runner SSH process cannot return a JSON-RPC response if transport fails. It writes exactly one or more fixed, secret-redacted diagnostics to local stderr in this form:

```text
netops_proxy_transport category=<category> message=<fixed public message>
```

The categories are:

| Category | Exact public message(s) |
| --- | --- |
| `runner_file` | `The runner file is unavailable or invalid.` |
| `legacy_configuration` | The message names `inventory.json`, `runner.json` and `egress-policy.json` and the removed files and variables. |
| `vault_permission` | `Credential vault permissions are invalid; mode 600 or 400 is required.` |
| `vault_schema` | `The credential vault schema is invalid.` |
| `auth_material` | `Required authentication material is unavailable or invalid.` or `The proxy script is not executable.` |
| `ssh_host_key` | `SSH host-key verification failed.` The runner offered no key matching its pin, or `ssh` refused the line built from it. |
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
3. Confirm the target certificate has an exact Subject Alternative Name. `tls_probe` verifies the selected target name or enrolled alternate SNI; system-trust FTPS verifies the device host name or address. A legacy Common Name alone is insufficient.
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

- vault mode is `600` or `400` and the transferred bundle mode is exactly `600`;
- the runner file names a credential of its own and no device entry repeats it, and every helper section has `account_role: "read-only"`;
- device address form, host key pins, DNS results, and egress addresses agree;
- enabled queries and every typed inventory item are the minimum required;
- no configuration, backup, secret store, support bundle, or broad log root is exposed;
- TLS/FTPS certificate trust, SAN, and any FTPS pin are valid;
- SNMP community is separate from the target password and UDP scope is narrow;
- the schema-3 IPv4 bundle was regenerated, securely transferred, reviewed, explicitly applied, and checked;
- Docker network inspection reports the expected stable bridge and exact `EnableIPv6: false`;
- live negative tests cover denied target egress and attempted runner-host access.

## Container state

Only `/var/lib/netops-helper` is persistent inside the Compose service. It contains credential-free audit segments. The active segment and four retained segments are each limited to 2,000,000 bytes. The SSH continuation cache lives only in process memory, and temporary selected device host-key files live on tmpfs and are removed after use.

## Scoped diagnostic queries

Helper 0.3.4 includes eight opt-in queries. `vlans`, `managed_switches` and `certificates` are separate `read_inventory` categories, checked independently by the proxy and server. A software-switch value in `switches` cannot authorize a managed-switch query. Every parameter must match an enrolled value exactly; returned output never enrolls objects automatically.

| Query | Platform | Parameter / inventory | Result scope |
| --- | --- | --- | --- |
| `vlan_details` | `extreme_exos` | `vlan` / `vlans` | One VLAN's operational details |
| `dhcp_snooping_entries` | `extreme_exos` | `vlan` / `vlans` | Binding entries for one VLAN |
| `certificate_details` | `fortinet` | `certificate` / `certificates` | Public certificate metadata and validity; no private-key export |
| `managed_switch_status` | `fortinet` | `managed_switch` / `managed_switches` | One managed switch's status |
| `managed_switch_poe` | `fortinet` | `managed_switch` / `managed_switches` | PoE summary |
| `managed_switch_mac` | `fortinet` | `managed_switch` / `managed_switches` | MAC table |
| `managed_switch_stacking` | `fortinet` | `managed_switch` / `managed_switches` | Stacking status, when the model supports it |
| `managed_switch_lldp` | `fortinet` | `managed_switch` / `managed_switches` | LLDP neighbor summary |

VLAN names contain 1-32 ASCII letters, digits, underscores or hyphens, starting with a letter. Certificate names contain 1-79 ASCII letters, digits, underscores, dots or hyphens, starting with a letter. Reserved selector keywords are rejected. Managed-switch serials contain 12-16 uppercase ASCII letters or digits and start with `S`. Whitespace, wildcards, control characters and selectors outside these grammars are rejected. The exact templates and volume bounds appear in the [generated catalogue](query-catalog.md).

Add each required query to the target's `enabled_queries` and its exact selector to the matching inventory category. Existing enrollments stay unchanged and gain no automatic access. Controller requests use the enrolled FortiGate connection and its host-key pin; they do not connect directly to the managed switch. No FortiAP query is added in this release.

Live CLI checks on 20-21 September 2026 observed certificate details under a read-only account on FortiOS 8.0.0 and DHCP bindings on EXOS 33.7.1. Three VLANs returned complete detail output through exec and interactive SSH on EXOS 33.7.1; status 250 is preserved, not normalized to zero. FortiOS 8.0.1 returned controller status, PoE, MAC and LLDP data using an administrator account. The tested switch does not support stacking and returned the recognized feature refusal -7622. These are direct CLI observations, not end-to-end MCP verification of the new queries. Restricted controller-profile permissions and positive stacking behavior remain unverified. Deployments must still validate each query with their intended read-only identity, firmware, hardware and output mode; see [read-only accounts](read-only-accounts.md) and the [FortiOS](vendor-cli-references/fortinet-fortios.md#scoped-diagnostic-queries) and [EXOS](vendor-cli-references/extreme-switch-engine.md#scoped-diagnostic-queries) evidence.
