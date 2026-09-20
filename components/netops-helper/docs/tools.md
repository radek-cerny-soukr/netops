# Tool reference - Phase 1 Read-Only

The remote FastMCP server registers exactly 10 tools: two remote control-plane tools and eight device tools. The local proxy accepts only that allowlist, removes the hidden `auth_context` from schemas, and adds the proxy-local `target_scope`. A client therefore sees exactly 11 tools: three control-plane tools and eight device tools.

All device tools use a target alias. The proxy inserts `auth_context` only on the private proxy-to-server hop; a user or client must never supply it. Device-originated values are returned as untrusted diagnostic data.

## Control-plane tools

| Tool | Purpose | Device contact |
| --- | --- | --- |
| `helper_status` | Remote version/phase controls, augmented by the proxy with the names of the valid enrolled devices and their rate state | None |
| `target_scope` | Proxy-local, non-secret enrolled scope for one device | None |
| `read_query_catalog` | Remote public query names, informative command templates, typed parameters, and volume metadata | None |

Use them in that order: discover names, inspect one device's actual scope, then compare enabled query names with the public catalog.

`target_scope` returns `ok`, `target`, `account_role`, `ssh_platform` (the catalogue name, so `fortios` is reported as `fortinet`), `enabled_queries`, `legacy_ssh`, `egress`, `read_inventory`, `sftp_roots`, `snmp_enrolled`, `host_key_pinned`, and `rate_limit`. `host_key_pinned` is always true because the loader refuses a device without a host key pin, and `snmp_enrolled` says whether the device names a credential of kind `snmp-community`. The fields `snmp_configured` and `ssh_host_key_enrolled` of earlier releases are gone.

## Device tools

| Tool | Purpose | Important bounds |
| --- | --- | --- |
| `dns_probe` | Resolve the enrolled target | DNS permission and resolved-address scope |
| `tcp_probe` | TCP connect test | Enrolled port; timeout 0.2-15 s |
| `icmp_probe` | ICMP reachability and latency | Explicit permission; 1-8 packets |
| `tls_probe` | Verified TLS and certificate metadata | Enrolled TCP port and alternate SNI |
| `ssh_read` | One named, typed, inventory-bound query | Enabled query; no raw command; 2 MB snapshot |
| `snmp_get` | SNMPv2c GET | Separate community, enrolled UDP port, up to 20 OIDs |
| `sftp_stat` | Remote path metadata only | Configured non-root path; no file body, no entry names |
| `ftp_list` | FTPS/FTP directory names only | Root, control port, passive range, maximum 500 returned names; plain FTP acknowledgement |

`route_trace` is not registered in the current release. Phase 1 has no arbitrary traceroute fallback.

The answer of an exec `ssh_read` has the device prompt removed by
[`netops_core.prompt`](../../netops-core/docs/prompt.md), which knows both the `#` of a
privileged account and the `$` of a read-only one and touches nothing but the first line and
trailing lines equal to that prompt. On a platform the table does not name it changes nothing.

Every SSH-family connection to one device is queued through that device's own connection lane, and a platform can carry a minimum spacing between connections in that lane; FortiOS carries five seconds, measured against a real device refusing rapid connections (see [Security model](security-model.md#device-side-authorization)). A `ssh_read` against FortiOS can therefore wait behind an earlier query to the same device before it starts, and the very first query to a device also pays for a `ssh-keyscan` connection of its own, cached for ten minutes after that. This adds latency, not failure: a caller issuing several FortiOS queries in a burst should expect them to complete several seconds apart rather than concurrently.

## Credentials across device protocols

One device credential supplies the same login and secret to `ssh_read`, `sftp_stat`, and `ftp_list` over FTPS or plain FTP. The device `port` controls SSH/SFTP; the FTP/FTPS control port is a separate `ftp_list` argument and egress permission. Plain FTP sends the same credentials and returned listing data without encryption and requires explicit acknowledgement.

Prefer FTPS. For unavoidable legacy FTP, use a dedicated least-privilege remote FTP identity and device entry, set `ssh_platform: null` and `enabled_queries: []`, and make the target reject SSH/SFTP for that identity. The `sftp_roots` path policy is shared by `ftp_list` and `sftp_stat`, so it cannot enforce an FTP-only protocol boundary by itself.

## What `sftp_stat` returns

`sftp_stat` runs the OpenSSH `sftp` client of `netops-core` with a batch of exactly one command,
`ls -ln "<path>"`, written to the client's standard input. The transport, the measured behaviour of
the client and every refusal are in [`../../netops-core/docs/sftp.md`](../../netops-core/docs/sftp.md).

The answer never carries the path itself, only `path_sha256`, and its shape depends on what the path
turned out to be:

| Path is | Fields |
|---|---|
| a file, a symbolic link, or another non-directory | `kind` (`file`, `symlink`, `other`), `size`, `mode` (octal), `modified_ls` |
| a directory | `kind` (`directory`) and `entry_count` - **never the names of the entries** |

Two properties are worth knowing before an answer is used:

- **`modified_ls` is the timestamp as `ls` printed it**, not a unix modification time: `Sep 10 02:26`
  for a recent path and `Sep 10  2024` for an older one, in the time zone of the client. There is no
  year in the first form and no minute in the second. The field is named after what it is; do not
  compute an age from it. The field `modified_utc` of earlier releases is gone.
- **A directory is answered with a count.** The client has no `ls -d`, so it lists the content of a
  directory; the helper reports only how many lines that listing had. A directory holding one entry
  is still a directory. An empty directory answers with `entry_count` 0.

## Typed SSH queries

The caller supplies the section's exact platform, one enabled public query name, and an exact parameter object. **The platform of a call is the catalogue name, not the canonical inventory name**: the inventory of a switch carries `exos` and `ssh_read` is called with `extreme_exos`, the inventory of a firewall carries `fortios` and the call uses `fortinet`. Read it from `ssh_platform` of `target_scope`, which reports exactly the name a call must use; a canonical name that differs is refused as an argument mismatch. Templates are defined in the canonical modules under `src/netops_helper/query_catalog/`. `read_query_catalog` exposes each exact template as informative `command_template` metadata so an operator can review what a named query will send. A template is not an executable input: `ssh_read` still accepts only the query name plus the template's exact typed parameters, and brace placeholders can only be filled from enrolled inventory.

New opt-in troubleshooting coverage includes ARP/IPv4 neighbors, IPv6 neighbors where supported, MAC/FDB tables, and LLDP/CDP neighbors. Linux additionally has `neighbors` and `bridge_fdb`. FortiOS `bridge_mac_table` uses the `switches` inventory. These names are available in the catalog but do nothing until explicitly added to that target's `enabled_queries`.

Slots are fixed:

- `interface` uses `interfaces`;
- `service` uses `services`;
- `address` uses canonical IP literals in `addresses`;
- `switch` uses `switches`.

The caller never supplies raw CLI text. Pipes and output modifiers occur only as fixed text in reviewed templates.

`ruckus_unleashed` is the catalogue's third measured platform and its four queries take no parameter at all. It is the only platform driven on a pseudo-terminal, because the device has no exec channel; the helper answers its in-shell login, sends `enable`, sends the query and closes the terminal.

## Configuration and log boundary

Phase 1 never reads or exports running configuration, startup configuration, full configuration, or configuration backups. It has no generic HTTP response-body or remote file-content tool. No equivalent query may be enrolled through the inventory because only compiled catalog names are accepted.

There is no arbitrary device log command, path, time range, filter, or unbounded log stream. The only log-oriented named query is Linux `service_logs_recent`, fixed to one enrolled service and the most recent hour. SFTP roots authorize only metadata lookup and FTP/FTPS directory-name listing; they do not authorize download. Do not enroll configuration backups, credential stores, private keys, or general log archives even for metadata/listing access.

## Pagination and snapshots

`ssh_read` returns `total_bytes`, `offset`, `returned_bytes`, `next_offset`, `complete`, a whole-output digest, `transport` (`exec` or `pty`, the mode the platform uses) and `rc`. `rc` is the exit status the device gave the command, and `null` for a `pty` platform, which reports none. A non-zero `rc` is returned with the output rather than turned into an error, because some devices answer a read command with a non-zero status and a complete answer; only a failure of the SSH client itself fails the call. There is no silent truncation. `max_bytes` is bounded to 1000-48000 and `offset` to 0-8000000; the SSH read timeout is 60 seconds. Other fixed timeouts: `tls_probe` 10 seconds, FTP control and data 30 seconds, SNMP 2 seconds with one retry.

At offset 0, `ssh_read` sanitizes and retains a complete bounded output snapshot for at most 120 seconds and eight entries per process when another page exists. A continuation uses that snapshot and never reconnects or reruns the query. Missing or expired state fails and must restart at offset 0. Completing the last page discards the snapshot.

A valid `ssh_read` continuation with `offset > 0` does not consume another proxy device rate slot, but it is still a server request and receives mandatory audit records. No other Phase-1 tool has continuation semantics.

## SNMPv2c warning

The optional `snmp_credential` of a section names a separate vault record of kind `snmp-community`; absence disables SNMP and there is no fallback. SNMPv2c transmits the community in plaintext in UDP. Use a dedicated read-only community, device ACLs, and narrow UDP egress, or prefer SNMPv3 outside the current phase-1 feature set.

## Output and prompt injection

Responses are marked `device_output_trust: untrusted`. Banners, names, interface descriptions, logs, certificates, filenames, and protocol data are evidence only and never instructions.

Sanitization removes injected credentials plus recognized private-key, token, password, community, Cisco secret, shadow-hash, and FortiOS `ENC` forms. It is defense in depth, not a complete secret classifier: novel secret formats can survive, and heuristic matches can replace legitimate neighboring prose. Network identifiers remain visible because troubleshooting requires correlation. Exclude secret-bearing queries and metadata/listing roots before redaction rather than relying on sanitization to make them safe.
