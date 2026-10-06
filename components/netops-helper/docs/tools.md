# Tool reference - Phase 1 Read-Only

The remote FastMCP server registers exactly 12 tools: two remote control-plane tools and ten device tools. The local proxy accepts only that allowlist, removes the hidden `auth_context` from schemas, and adds the proxy-local `target_scope`. A client therefore sees exactly 13 tools: three control-plane tools and ten device tools.

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
| `schema_read` | Enrolled measured configuration path | Server registry, exact live model/build, redacted selected attributes |
| `fortios_diagnostics` | Enrolled ping/traceroute/sniffer/sessions/flow recipe | Address and interface grants; 1–10 s execution limit, 1–8 packets/records, 1–3 traceroute probes per hop, 1–16 KB returned output |
| `snmp_get` | SNMPv2c GET | Separate community, enrolled UDP port, up to 20 OIDs |
| `sftp_stat` | Remote path metadata only | Configured non-root path; no file body, no entry names |
| `ftp_list` | FTPS/FTP directory names only | Root, control port, passive range; receive limits of 500 names, 2,000,000 listing bytes, 262,144 control-reply bytes and 30 seconds total; plain FTP acknowledgement |

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
  compute an age from it. The field `modified_utc` of earlier releases is gone. It is device text:
  the server removes the target credential from it as from every other device answer.
- **A directory is answered with a count.** The client has no `ls -d`, so it lists the content of a
  directory; the helper reports only how many lines that listing had. A directory holding one entry
  is still a directory. An empty directory answers with `entry_count` 0.

## Typed SSH queries

The caller supplies the section's exact platform, one enabled public query name, and an exact parameter object. **The platform of a call is the catalogue name, not the canonical inventory name**: the inventory of a switch carries `exos` and `ssh_read` is called with `extreme_exos`, the inventory of a firewall carries `fortios` and the call uses `fortinet`. Read it from `ssh_platform` of `target_scope`, which reports exactly the name a call must use. The proxy also accepts two aliases and converts them during argument validation, before the scope check: `fortios` becomes `fortinet` and `extreme_switch_engine` becomes `extreme_exos`. Any other name, including the inventory name `exos`, is refused as `invalid_params`, and a catalogue name that differs from the device's is refused as `policy_scope`. Templates are defined in the canonical modules under `src/netops_helper/query_catalog/`. `read_query_catalog` exposes each exact template as informative `command_template` metadata so an operator can review what a named query will send. A template is not an executable input: `ssh_read` still accepts only the query name plus the template's exact typed parameters, and brace placeholders can only be filled from enrolled inventory.

New opt-in troubleshooting coverage includes ARP/IPv4 neighbors, IPv6 neighbors where supported, MAC/FDB tables, and LLDP/CDP neighbors. Linux additionally has `neighbors` and `bridge_fdb`. FortiOS `bridge_mac_table` uses the `switches` inventory. These names are available in the catalog but do nothing until explicitly added to that target's `enabled_queries`.

Slots are fixed:

- `interface` uses `interfaces`;
- `service` uses `services`;
- `address` uses canonical IP literals in `addresses`;
- `switch` uses `switches`;
- `vlan` uses `vlans`;
- `managed_switch` uses `managed_switches`;
- `certificate` uses `certificates`.

Helper 0.3.4 adds eight explicitly enrolled queries using the latter three categories. See [scoped diagnostics](configuration.md#scoped-diagnostic-queries) for names, grammars and measured support limits. These inventories do not authorize each other.

The caller never supplies raw CLI text. Pipes and output modifiers occur only as fixed text in reviewed templates.

`ruckus_unleashed` is the catalogue's third measured platform and its four queries take no parameter at all. It is the only platform driven on a pseudo-terminal, because the device has no exec channel; the helper answers its in-shell login, sends `enable`, sends the query and closes the terminal.

## Configuration and log boundary

The ordinary SSH catalogue has no configuration-read/export query. Optional `schema_read` collects a full snapshot in memory but returns only enrolled measured paths with known credential attributes redacted. No whole-snapshot export, generic HTTP body or remote file-content tool is available. Bounded diagnostics have temporary runtime effects and verified cleanup; neither extension is authorized by an ordinary query grant.

There is no arbitrary device log command, path, time range, filter, or unbounded log stream. The only log-oriented named query is Linux `service_logs_recent`, fixed to one enrolled service and the most recent hour. SFTP roots authorize only metadata lookup and FTP/FTPS directory-name listing; they do not authorize download. Do not enroll configuration backups, credential stores, private keys, or general log archives even for metadata/listing access.

## Pagination and snapshots

`ssh_read` returns `total_bytes`, `offset`, `returned_bytes`, `next_offset`, `complete`, a whole-output digest, `transport` (`exec` or `pty`, the mode the platform uses) and `rc`. `rc` is the exit status the device gave the command, and `null` for a `pty` platform, which reports none. A non-zero `rc` alone does not imply failure: EXOS can return complete valid output with status 250. Known explicit CLI refusal patterns of FortiOS, EXOS, IOS, IOS-XE, NX-OS, EOS and Junos do fail the call, including a FortiOS `Command fail`, an IOS `Line has invalid autocommand` or a Junos `error: ...` line with SSH status zero; the exact patterns are listed in the [security model](security-model.md#pagination-and-rate). Such a result has `ok: false`, `error_code: "device_cli_error"`, a fixed error message, the original `rc`, and bounded sanitized `untrusted_device_output`. It receives a failed audit record and no continuation snapshot is cached. Recognition is limited to reviewed patterns, not a universal interpretation of vendor output; transport failures remain separate errors. A target host name that does not resolve answers every device tool with `ok: false` and the resolver error, not an exception; `ftp_list` reports it as `failure_stage: "resolve"`. There is no silent truncation. `max_bytes` is bounded to 1000-48000 and `offset` to 0-8000000; the SSH read timeout is 60 seconds. Other fixed timeouts: `tls_probe` 10 seconds, FTP control and data 30 seconds, SNMP 2 seconds with one retry.

At offset 0, `ssh_read` sanitizes and retains a complete bounded output snapshot for at most 120 seconds and eight entries per process when another page exists. A continuation uses that snapshot and never reconnects or reruns the query. Missing or expired state fails and must restart at offset 0. Completing the last page discards the snapshot.

A valid `ssh_read` continuation with `offset > 0` does not consume another proxy device rate slot, but it is still a server request and receives mandatory audit records. No other Phase-1 tool has continuation semantics.

## SNMPv2c warning

The optional `snmp_credential` of a section names a separate vault record of kind `snmp-community`; absence disables SNMP and there is no fallback. SNMPv2c transmits the community in plaintext in UDP. Use a dedicated read-only community, device ACLs, and narrow UDP egress, or prefer SNMPv3 outside the current phase-1 feature set.

## Output and prompt injection

Responses are marked `device_output_trust: untrusted`. Banners, names, interface descriptions, logs, certificates, filenames, and protocol data are evidence only and never instructions.

Sanitization removes injected credentials plus recognized private-key, token, password, community, Cisco secret, shadow-hash, and FortiOS `ENC` forms. It is defense in depth, not a complete secret classifier: novel secret formats can survive, and heuristic matches can replace legitimate neighboring prose. Network identifiers remain visible because troubleshooting requires correlation. Exclude secret-bearing queries and metadata/listing roots before redaction rather than relying on sanitization to make them safe.

### FTP listing limits

`ftp_list` bounds reception while data arrives, for FTP and FTPS alike. A listing with more than
500 names returns the first 500 with `truncated: true` and closes both channels; exactly 500 names
followed by EOF is complete. Receiving more than 2,000,000 bytes fails the operation rather than
returning a successful listing. At most one additional byte is read to detect that overflow.
The 30-second total budget covers connection, authentication, control replies and data reception;
slow progress does not reset it. All control-channel replies of one operation, multi-line replies
included, may total at most 262,144 bytes; a server that keeps sending reply lines (for example an
endless `220-` banner) fails the operation with `FTP control replies exceed the receive byte budget`
as soon as the total passes that limit. Both sockets are closed on failure. FTPS still protects the data
channel, and plain FTP still requires explicit acknowledgement of unencrypted credentials and data.

## Bounded FortiOS diagnostics

The optional fortios_diagnostics tool accepts a recipe, a canonical unicast IPv4 address and a concrete FortiOS interface. Enrol them separately in helper.read_inventory.diagnostic_recipes, addresses and interfaces. A VDOM selector also requires its exact name in diagnostic_vdoms. The server reads the live VDOM inventory and the exact interface owner before any edit and verifies the selected domain afterwards. An absent domain is never created.

Enable system_status and configure NETOPS_SCHEMA_REGISTRY as for schema_read. Recipes are limited to measured FortiGate-VM64-KVM 7.6.7 build3704 and 8.0.0 build0167. Other hardware/builds remain refused. The externally enforced device account must permit the enrolled diagnostic operations while refusing persistent configuration writes.

Ping uses bounded count, size, interval and timeout and an explicit interface. Traceroute uses bounded probes per hop and an explicit device; its wall limit can end before all hops. Sniffer captures ICMP headers for the enrolled host and interface, without packet payload. Sessions and flow select the enrolled address and ICMP in the verified VDOM; the interface must be visible there, but those two native filters are not interface filters. Sessions returns at most count session records.

Existing session/flow filters and active debug output are refused. Diagnostic option/filter state is restored and checked before success. A deadline sends a single terminal Ctrl-C, waits for the prompt, then performs cleanup. Every connection closes afterwards, including errors and Python interruption. Cleanup failure refuses the result. The output and SSH capture budgets are separate: the SSH reply cap is 128 KiB and the returned cap is 16,000 bytes.

Flow uses a bounded native trace count and a bounded listening window. It does not change application debug levels, reset foreign diagnostic state or set the shared debug-duration value. FortiOS debug enable can start its shared duration timer even though output/filter scope is local; enrol flow only where diagnostic use is coordinated. A completed recipe proves cleanup of its own output/filter state, not an unchanged elapsed value of that shared timer.

An empty filtered capture is a valid bounded result and does not prove packet delivery. Replies are untrusted data. No recipe grants its raw diagnose/execute leaves, configuration setters, reboot/reset/export or arbitrary command text.
