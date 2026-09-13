# Security model

## Capability boundary

Phase 1 is a standalone read-only MCP server. It registers no write, prepare, apply, upload, delete, restart, configuration, configuration-export, traceroute, arbitrary-log, or raw-command tool. It must run with credentials independently restricted to read-only access by each target platform.

It never reads running, startup, full, or backup configuration. It cannot export configuration and has no generic HTTP response-body or remote file-content reader. It has no general device-log browser; only the fixed, opt-in Linux one-hour service journal query is deliberately log-oriented. Some fixed status/history queries may contain event-like output, but callers cannot choose arbitrary device log sources, ranges, or filters.

A future Phase 2 may consider configuration or other body reads only with a separate threat model, binary, container, credential set, client profile, and operator-controlled activation window. Phase 1 must not acquire a full-configuration query or a generic body-read escape hatch as a convenience feature.

The container exposes no listening port, has no Docker socket, runs unprivileged, drops all Linux capabilities, uses a read-only root filesystem, and has only tmpfs plus a persistent volume for bounded audit metadata.

## Discovery and exact policy

The remote FastMCP server registers 10 tools: `helper_status`, `read_query_catalog`, and eight device tools. The proxy exposes only those remote tools, removes private authentication schema, and adds its local `target_scope`; the client-visible surface is therefore exactly 11 tools, comprising three control-plane and eight device tools.

The client starts with the remote `helper_status`, which the local proxy augments with valid non-runner aliases and current rate state. The proxy-local `target_scope` then returns one alias's enrolled capabilities without contacting the target. `read_query_catalog` is the other remote control-plane tool.

These discovery responses do not expose the vault `host` field, login, credentials, SNMP community, or host-key material. They are not topology-anonymous: `target_scope` intentionally returns inventories, SFTP metadata/listing roots, TLS names, and enrolled egress IPv4 addresses. A literal target address will normally appear in that egress list. Treat discovery output as environment-sensitive and keep it in the dedicated operational session.

Legacy, incomplete, or misspelled target policy fails closed. The proxy requires exact platform/query and egress fields, checks per-tool scope, and only then injects one target's authentication envelope. The server independently validates the same envelope and scope, but only their shape and policy, not their origin: the envelope carries no signature, nonce, or expiry, so anything able to write to the server process's stdin on the runner is trusted as the proxy. The private proxy-to-server hop and the runner's `docker exec` authorization are the security boundary. Exact argument validation failures return `invalid_params` before authentication, rate consumption, or forwarding.

SSH reads use named templates and typed inventory slots. SFTP metadata and FTP directory-list paths use canonical non-root roots. The client cannot introduce raw commands, arbitrary URLs, arbitrary paths, or scope learned from device output; no Phase-1 tool reads an HTTP response body or remote file content.

## Credential and host-key transport

The vault is one mode-`600` regular file (symlinks are rejected) holding one JSON object with one runner record under `NETOPS_MASTER_ALIAS` and separate target records. The runner password reaches OpenSSH's askpass helper exactly once over a per-session abstract Unix socket whose random name is the only credential-related value in the `ssh` process environment; the listener checks the peer's UID and discards the secret after the first delivery. The runner record is used only for the fixed proxy-to-runner SSH hop and has no target-policy entry. Each target record has independent connection material and a target-policy entry.

Within one target record, `ssh_read`, `sftp_stat`, FTPS, and plain FTP all reuse the same `login` and `password`. The target record's `port` selects SSH/SFTP only; `ftp_list` receives its control port as a tool argument and requires explicit control/passive egress. Plain FTP sends the same target credentials and listing data without encryption. A separate least-privilege FTP remote identity and alias reduce cross-protocol reuse, but `sftp_roots` also authorizes `sftp_stat`; only target-side account/service policy can make that identity reject SSH/SFTP.

A target record may have a separate `snmp_community`. Reusing the target password as that community is rejected, omission disables SNMP, and there is no fallback.

SNMPv2c transmits the community in plaintext in UDP. This design requires a dedicated read-only community, narrow egress, and target-side source ACLs; it does not provide SNMPv3 confidentiality.

The local runner SSH connection uses the operator's configured known-hosts file. For device SSH/SFTP, the proxy extracts only matching target entries and injects those lines into the container. Unrelated hostnames, comments, and keys remain local. Target hosts are canonical IPv4 literals or canonical hostnames resolving only to explicitly enrolled IPv4 addresses; IPv6 target hosts are rejected in this release.

Proxy request failures have distinct JSON-RPC categories for alias, policy, role, vault permissions/schema, authentication material, rate, scope, invalid arguments, and internal failure. Preflight or outer SSH failure is reported to local stderr with a fixed `runner_alias`, `vault_permission`, `vault_schema`, `auth_material`, `ssh_host_key`, `ssh_authentication`, `ssh_connection`, `remote_exec`, `ssh_timeout`, or `ssh_transport` category. Raw SSH stderr is sanitized and not relayed. See [Configuration](configuration.md#stable-proxy-and-ssh-transport-errors).

## Device-side authorization

`account_role: "read-only"` is an operator assertion, not proof. Vendor-native authorization must deny mutation, configuration display/export, secret-bearing bulk diagnostics, maintenance, privilege escalation, and shell escape while permitting only required named queries.

The upstream Netmiko driver performs platform-specific session preparation and cleanup around the requested command; the wire test `tests/test_netmiko_wire_safety.py` pins the exact command sequence for every non-FortiOS profile against a real Paramiko server, so a driver upgrade that changes it fails the release gate. FortiOS is the exception with a dedicated driver that deliberately skips configuration-writing paging setup and cleanup and requires externally verified `output standard`. Independently of the platform, both SSH transports disable the `ssh-rsa` host key algorithm and SHA-1 key exchange; a target which offers nothing else is reachable only after the named per-target exception `legacy_ssh: "rsa-sha1"` is enrolled, which re-enables the `ssh-rsa` host key for that target alone and never SHA-1 key exchange. For every platform, effective behavior must be verified over the same SSH transport after firmware, driver, role, or AAA changes. See [Read-only accounts](read-only-accounts.md).

## Network egress boundary

The Compose network deliberately uses `internal: false`; otherwise the diagnostic container cannot reach enrolled targets. This setting is not an egress security control.

A guarded installation first creates the named network and container in a stopped state. The operator generates and securely transfers a topology-sensitive but credential-free schema-3 bundle, reviews it, explicitly applies it, runs the checker, and only then starts the container. Enrollment changes do not update firewall state automatically.

The generator derives a deterministic IPv4 iptables/DOCKER-USER contract anchored to the stable `nh-egress0` bridge. The `strict-target` profile retains target-specific destination and port/range/ICMP rules. The `lan-constrained` profile accepts only non-empty canonical CIDRs wholly contained in RFC1918 space, requires every enrolled target destination to lie within their union, and then grants the union of all enrolled TCP/UDP ports and ranges plus ICMP permission to every address in every declared CIDR. DNS remains resolver-scoped. This intermediate profile reduces internet exfiltration but deliberately broadens lateral reach and is not per-target isolation.

Bundle schema 3 installs only one IPv4 ruleset using one `iptables-restore` COMMIT. It does not create or claim an ip6tables chain. The IPv6 boundary is the Compose network's exact `enable_ipv6: false`, which apply and check inspect before trusting the IPv4 forwarding contract. This is a network-scoped setting, not a host-wide IPv6 firewall guarantee.

DOCKER-USER restricts forwarded traffic originating on the bridge. Traffic to services on the runner itself may traverse INPUT and fall outside the managed chain. No generic INPUT drop is supplied because host-specific Docker DNS/NAT and management access must be observed before such a rule is designed. Docker embedded DNS at `127.0.0.11` is engine- and host-dependent. DNS permission also enables a name-unfiltered exfiltration channel, so the strictest deployment uses literal IPv4 targets, `allow_dns: false`, and no resolvers.

A fixed bridge name is the firewall anchor. A fixed subnet is intentionally not required and could collide with existing runner addressing. ARM64 deployment tests must verify allowed and denied target traffic, Docker-network IPv6 denial, embedded DNS, runner-local service access, rule ordering after Docker restart, and checker drift detection. See [Egress control](egress-control.md) and [Installation](installation.md#5-review-explicitly-apply-and-check-egress).

## Per-tool enforcement

The proxy rejects malformed or out-of-scope requests before credential forwarding or device rate consumption. The server repeats scope validation before network access, resolves hostname targets fail-closed to enrolled canonical IPv4 addresses, and opens the SSH/SFTP TCP connection itself to a verified address; the hostname is passed to the SSH libraries only for host-key matching, so no second resolution happens outside the egress check.

The credential SSH/SFTP port is derived by the firewall generator only when SSH queries or SFTP metadata roots are enabled. Explicit TCP ports/ranges are used for TCP/TLS probes and FTP; FTP additionally requires a passive TCP range. No HTTPS port is derived. SNMP requires explicit UDP scope. DNS, ICMP, and alternate TLS SNI each require their dedicated permission.

Application allowlisting and the host firewall protect different layers. Neither substitutes for target authorization, and neither proves that a nominal metadata or directory-list operation is harmless.

## Pagination and rate

An offset-0 SSH read captures at most 2 MB after sanitization and retains one of at most eight snapshots for 120 seconds per process only when continuation is needed. Output over the cap fails rather than being silently truncated. A continuation uses the same snapshot, does not reconnect or rerun the command, and fails after expiry. The last page removes the snapshot. No other Phase-1 tool has a body snapshot or continuation path.

The default proxy limit is 30 device calls per alias per 60 seconds (the window is keyed by vault alias, not by host). A valid `ssh_read` continuation with `offset > 0` does not consume another device rate slot; every other device call does. This per-process limit is not a distributed global quota.

## Mandatory two-phase audit

Every server-side device tool is wrapped by a mandatory two-phase audit boundary:

1. Before any operation, a `status: "started"` record is appended, flushed, and fsynced. If this preflight write fails, the internal `AuditPreflightError` has `operation_started = False`; device work does not start.
2. After a returned result, a terminal `ok` or `failed` record is durably written. After an exception, a `rejected` record carrying the same permitted argument metadata plus the exception type as `detail` is attempted before the exception propagates.
3. If the terminal write fails, the internal `AuditPostOperationError` has `operation_started = True`. The device operation may have succeeded even though its result is not returned.

Those `operation_started` attributes describe internal Python exception classes and tests. They are not a stable structured JSON-RPC/MCP wire field. Client diagnosis must combine the surfaced tool error with the audit pair and server-side logs.

A process kill or host failure can leave a durable `started` record without a terminal partner. Completion is then unknown and must be investigated; an incomplete pair is not evidence that the device was untouched or changed. Proxy-side policy rejection happens before the server device call and therefore creates no device audit pair.

Records contain allowlisted metadata: alias, event/status, safe options and counts, query/platform, pagination metadata, exception type, and hashes of paths/results. They contain no command output, raw path, credential, community, network address, or configuration. The active file and four retained segments are limited to 2 MB each and mode `600`.

Mandatory audit intentionally fails closed to observability: an unwritable audit volume prevents new device operations, while a terminal-write failure replaces an otherwise successful response with a typed post-operation error.

## TLS trust and untrusted output

`tls_probe` and unpinned FTPS verify certificate trust and SAN. The alias-specific FTPS branch disables hostname checking, validates a chain against its configured certificate file with partial-chain support when available, and separately verifies the exact peer leaf SHA-256 digest. The stock image supports public PKI in its base trust store. Private enterprise CAs and self-signed devices require reviewed private trust material and, for hostname-verifying paths, a matching DNS/IP SAN. Verification must never be disabled. See [Configuration](configuration.md#private-tls-and-ftps-ca-san-and-pins).

All device and network output is attacker-controlled evidence, never instructions. The proxy redacts every message the server sends, including notifications and server-initiated requests, using the credentials, SNMP communities, and authentication envelopes seen during the session, not only responses to `tools/call`. Redaction removes injected secrets and recognized patterns but is not a complete classifier and can produce false positives or miss novel secret forms. Network identifiers deliberately remain visible, so returned data remains sensitive after sanitization. A dedicated session without mutating or generic shell tools limits what prompt injection in device output can reach.

## Residual-risk checklist

Before relying on a deployment, verify all of the following externally:

- device roles allow intended reads and deny configuration display/export, mutation, maintenance, bulk support collection, and shell escape;
- the actual Netmiko SSH session emits only behavior accepted by target AAA policy;
- target aliases, scope output, audit metadata, and generated bundle receive environment-sensitive handling;
- the schema-3 bundle matches enrollment, is installed before start, and survives/reports Docker changes;
- IPv6 is disabled on the exact Docker network and no host-wide IPv6 claim is inferred;
- runner INPUT exposure and embedded DNS behavior were tested on the actual ARM64 host;
- private CA material and certificate SAN were independently verified;
- a rate limit, audit failure, expired SSH snapshot, or transport error is interpreted by its typed category rather than as generic credential failure.
