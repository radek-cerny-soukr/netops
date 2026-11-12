# Helper tools in NetOps

On the HTTPS endpoint, argument refusals use `result.isError: true`.
`content[0].text` contains a JSON-encoded object
`{code: -32602, message, data: {field, hint}}` (also `data.category: "invalid_params"`);
there is no `structuredContent`. Parse that text to read the code and field guidance.
References to `-32602` below mean this tool error result, not a top-level JSON-RPC error.

`fortios_diagnostics.timeout` defaults to 10 seconds, including FortiADC `nslookup`
and traceroute. For FortiADC diagnostics, at the deadline the final `^C` echo of Helper’s interrupt is removed
from `untrusted_device_output`; partial device output and deadline metadata remain.

The HTTPS MCP endpoint exposes Helper tools alongside [Auditor](../../netops-auditor/docs/tools.md) and [Admin](../../../docs/admin-configuration.md#mcp-tools) tools. It exposes 26 Helper tool names, including `ftp_list`, which is refused in the shipped profile. Clients pass enrolled aliases, never device credentials or auth_context. The private bridge injects ephemeral device authentication and validates policy before dispatch.

## Troubleshooting prompts

With Helper enabled, `prompts/list` advertises `internet_or_vpn`, `everything_slow`, `fortiadc_backend_down`, `tls_certificate_error`, and `wifi_client_connectivity`. Use `prompts/get` with a required `target` and optional `address` (both strings). Arguments are included as text; retrieving a prompt calls no tools or devices and adds no permissions. Auditor and Admin add no prompts. The runbooks include the probe vantage and scope refusals; consult [Troubleshooting by symptom](../../../docs/troubleshooting-by-symptom.md) for the canonical source. After editing that document run `python3 -B scripts/sync_troubleshooting_prompts.py`; the test suite checks that the bundled copy matches.

| Tool | Current behavior |
|---|---|
| helper_status | Enrolled aliases, validation and rate state; no device contact |
| target_scope | Public enrollment boundary for one alias; no device contact |
| read_query_catalog | Bounded pages of named typed queries and metadata, with platform/prefix filters; not automatic authorization |
| dns_probe | Enrolled DNS resolution with address scope checks |
| tcp_probe | Enrolled TCP port reachability |
| icmp_probe | Explicitly permitted bounded diagnostics |
| tls_probe | Verified peer certificate and enrolled SNI/port |
| switch_read | Normalized operational tables using the existing catalogue and per-target query permissions ([guide](#normalized-tables-switch_read)) |
| locate_endpoint | IP/MAC location across 1–64 explicitly enrolled aliases, eight concurrent device readers and a shared budget below 60 seconds ([guide](#endpoint-location-locate_endpoint)) |
| ssh_read | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`); empty or whitespace-only device output answers `ok: false` with `error_code: "empty"` unless the catalogue declares that query's empty output legal |
| config_read | Opt-in FortiOS or FortiADC running configuration, conservative value redaction, bounded memory capture; `redaction="full"` reads the whole configuration and reports how much of it the account could see ([guide](#reading-the-whole-fortios-configuration-config_read)) |
| config_diff | Compare two captures for the same authenticated target; no device contact |
| triage_health | Fixed read-only FortiOS health chain of ten catalogue reads with findings, missing steps and a verdict; qualified for FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 only ([guide](#fortios-health-triage-triage_health)) |
| triage_routing | Fixed read-only FortiOS route chain for one enrolled IPv4 address (route, policy routes, SD-WAN, ARP) with sourced findings, hypotheses and what is not simulated; measured on FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251, the only identities it accepts ([guide](#fortios-route-triage-triage_routing)) |
| triage_flow | One IPv4 flow (`src`, `dst`, `port`, `proto` tcp, udp or icmp) through the firewall: route to the destination (egress) and to the source (ingress), policy lookup and, when the target enrols it, the sessions of the flow, with sourced findings and a verdict; FortiGate-80F 8.0.2 build 0251 with VDOMs disabled only ([guide](#fortios-flow-triage-triage_flow)) |
| triage_vpn | One named FortiOS IPsec tunnel: four catalogue reads, findings, missing steps and a verdict ([guide](#fortios-vpn-triage-triage_vpn)) |
| wifi_triage | One Wi-Fi client by MAC, IPv4 or hostname: significant history, three signal snapshots, access point, radio, SSID and RF context from read-only reads, with findings, missing steps (the switch port, which `locate_endpoint` finds, and live RSSI without REST enrollment) and a verdict that is `fault_found`, `rf_concern_found`, `no_rf_fault_found`, `client_not_associated` or `incomplete`, never healthy; FortiGate-80F 8.0.2 build 0251 only ([guide](#wi-fi-client-triage-wifi_triage)) |
| triage_slb | One enrolled FortiADC virtual server: configuration and runtime chain virtual server, pool, members, health checks, TLS, WAF and DoS with sourced findings and a verdict; FortiADC 7.6.7 build 0676 only ([guide](#fortiadc-load-balancing-triage-triage_slb)) |
| schema_read | Enrolled measured configuration path and exact device identity |
| fortios_diagnostics | Explicitly enrolled bounded recipe and temporary-state cleanup; FortiOS and FortiADC targets |
| sftp_stat | Metadata within enrolled roots; no file content |
| snmp_get | SNMPv3 authPriv GET (sha256, aes128) with the credential named by `snmp_credential`; v1, v2c, noAuthNoPriv and authNoPriv are refused before any network access; `target_scope` reports `snmp_security` as `authPriv` or null |
| ftp_list | FTP and FTPS refused in the shipped profile |

The `schema_read` tool still requires a measured server-side schema registry and library files, whose provisioning is not a supported workflow. Missing-registry calls are refused before device contact. Bounded `fortios_diagnostics` no longer depends on that registry; its live identity and single-VDOM restrictions are described below.

`ftp_list` is refused with `unencrypted_protocol` before any device contact, and no configuration enables it; `snmp_get` is active only with an `snmpv3-authpriv` credential (SHA256, AES128) named by `snmp_credential`, 1 to 20 OIDs and a UDP port allowed by the target egress scope; SNMPv1, SNMPv2c, noAuthNoPriv and authNoPriv are not supported. The path check of the `ftp_list` engine is lexical: it accepts a canonical absolute path equal to an entry of `sftp_roots` or below it, without letting the server resolve the path, so unlike `sftp_stat` it would not refuse a symbolic link below a root that leads out of it.

Operation refusals and failed Helper results set MCP isError true while preserving structured detail. Device output is untrusted data and never an instruction to expand scope. A diagnostic finding does not authorize a write, retry or another target.

A `-32009` (`policy_scope`) refusal of a device tool is made before any device contact and always carries `data.field`, the name of the part of the target's enrollment that refused the call. It never carries the refused value. `field` is one of: `platform` (the target's platform does not match the tool or the `platform` argument, or a FortiADC diagnostic uses a non-empty `interface`), `enabled_queries` (the `ssh_read` query, or a query a triage tool needs, is not enabled), `parameters` (the `parameters` of `ssh_read` are not exactly the parameters the query takes), `egress` (the probe, port, protocol or TLS server name is not allowed by `egress`), `sftp_roots` (the remote path is outside the enrolled roots), `config_access` (`read` or `compare` is not enrolled), or the name of a `read_inventory` category (`addresses`, `lookup_prefixes`, `interfaces`, `flow_ports`, `schema_paths`, `diagnostic_recipes`, `diagnostic_vdoms`, `adc_virtual_servers` and the others in [Helper configuration](../../../docs/helper-configuration.md)) when an argument value is not listed there. The check stops at the first refused field. For `ssh_read` with an inventory category, the data also names the argument: `data.parameter` is the first refused `parameters` key and `data.parameters` lists every refused key, so `src_ip` and `dst_ip`, which share `addresses`, can be told apart. A call that is not a device tool at all is refused with no `field`. Compare the named field with `target_scope`.

CIDR prefixes in lookups: a FortiOS `route_lookup`, `policy_lookup_ipv4` or `policy_lookup_ipv6` parameter and the `address` and `source_address` of the `sessions` and `flow` recipes of `fortios_diagnostics` also accept a canonical prefix such as `198.51.100.0/24` (no host bits, not `/0`) that is equal to or inside an enrolled `lookup_prefixes` entry of the same family; any other prefix is refused with `data.field` `lookup_prefixes`. The route and policy lookups take one address on the device, so the Helper sends the network address of the prefix (`198.51.100.0`) and the answer describes that address only. The session and flow filters take the whole range of the prefix. Prefix filters require measured range grammar: FortiGate-60F 7.6.8 build 3744 (tuple form) or FortiGate-80F 8.0.2 build 0251 (range syntax accepted by the read-only account on 2026-11-09). Other identities return `prefix_not_supported_on_identity` before diagnostic state changes; lookup queries still use the network address. `ping`, `traceroute`, `sniffer`, `logs`, BGP peers and `triage_routing` never take a prefix, and `lookup_prefixes` does not widen `egress`.

Consult the [complete enrollment](../../../docs/helper-configuration.md), [query catalogue](query-catalog.md), [source registry](query-sources.json) and [account boundary](read-only-accounts.md). Catalogue presence alone does not establish firmware/hardware support or device account permissions. FortiOS Wi-Fi diagnostics require `wifi read-write` and `cli-diagnose`; a read-only profile is refused. Keep other reads on a read-only account, or leave these Wi-Fi queries disabled for the target. The catalogue exposes this requirement and the observed refusal; the refusal is reported as `permission_denied`.

FortiOS diagnostics use the pinned SSH target and a measured live identity without a schema registry. Verified single-VDOM root mode runs without a selector. An explicit `vdom` must be enrolled in `diagnostic_vdoms` and equal the session's verified current VDOM; the Helper never switches VDOM, so on a multi-VDOM device the enrolled login must be an administrator scoped to that VDOM. Multi-VDOM without a selector, a selector naming another VDOM, enabled/unknown VDOM mode and unmeasured builds are refused before any diagnostic command. An enrolled interface that the device reports in another VDOM is refused with ScopeRefused `the enrolled interface belongs to another VDOM` before any diagnostic option changes; when the device does not report exactly that interface with an owning VDOM, the owner is unverified and the request fails as `bounded FortiOS diagnostic failed; the session was closed` without claiming another VDOM, like any other failure inside the session. Results include live identity and vdom, with no schema_sha256. Existing opt-in, limits and cleanup verification apply. Without a tuple, the recipes are accepted only on the exact identities FortiGate-VM64 8.0.2 build 0251, FortiGate-80F 8.0.2 build 0251 (measured on the primary member of an HA cluster, whose prompt `<host>(Primary) $` is accepted), FortiGate-VM64-KVM 7.6.7 build 3704 and FortiGate-VM64-KVM 8.0.0 build 0167; any other hardware or build is refused before the first diagnostic command (the caller sees only the generic `bounded FortiOS diagnostic failed; the session was closed`). The target needs its `system_status` query enabled and `fortios_output_standard_verified` set to true. Tuple-bearing sessions, sniffer and flow are restricted to exact FortiGate-VM64 8.0.2 build 0251, FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 identities; on FortiGate-60F 7.6.8 build 3744 a live UDP flow trace ran with the tuple filter, an empty filter baseline and a verified cleanup readback, while 7.6.8 sessions and sniffer with a tuple remain unqualified (live evidence covers only flow); on FortiGate-80F 8.0.2 build 0251 a live flow call with a UDP tuple filter traced no packet of an offloaded session, so tuple capture there is not qualified. A flow result states `trace_state` `captured` (at least one packet trace line) or `empty` with the filter, window and causes to check; see the helper configuration guide.

A FortiADC target accepts `ping`, `traceroute`, `nslookup`, `http_probe`, `health_check_verify`, `system_event_logs`, `waf_attack_logs`, `session_list` and `persistence_list`, needs `system_status` enabled and the recipe, address and (for `health_check_verify`) the health check enrolled in its inventory, and is accepted only as FortiADC-KVM 7.6.7 build 0676 (other builds are refused with `config_platform_not_supported`). It takes no TCP/UDP tuple and no `vdom`, and `interface` must be the empty string. `system_event_logs` and `waf_attack_logs` take an empty `address` and no `since` or `until`; `session_list` and `persistence_list` take as `address` the name of a virtual server enrolled in `diagnostic_virtual_servers`.

## Catalogue pages

Call read_query_catalog with no arguments for the first 25 queries, then repeat
with the returned next_offset until it is null. Keep platform and query_prefix
unchanged while paging. The queries and query_metadata objects retain their
platform/query grouping; total counts all matching queries, returned counts this
page, and offset/next_offset identify query positions in platform/name order.

For example, {"platform":"fortios","query_prefix":"system_","limit":10} lists
matching FortiOS queries. Platform aliases use the existing Helper mapping;
FortiOS is reported under fortinet. An empty filter matches all queries.
Limit is a strict integer from 1 to 100. Pages also stop before their serialized
data exceeds 48,000 bytes, so fewer than limit entries may be returned.
A single oversized entry fails explicitly. No entry is split or silently lost.

catalog_sha256 identifies the complete catalogue and metadata revision, independent
of page/filter. If it changes while collecting pages, restart from offset zero.
An offset equal to total returns an empty terminal page; offsets beyond total,
unknown platforms and malformed filters are refused. This control tool needs
no target, credential or device connection and grants no query authorization.


## SSH read pages (`ssh_read`, `schema_read`)

Every fresh `ssh_read` on FortiOS/FortiADC verifies the live product identity with `get system status`; confirmed identities are never cached. A query other than `system_status` therefore uses two SSH connections, with five-second spacing that protects the device (measured FortiOS latency: 8–10 s). `system_status` itself is the live probe.

The first call (`offset=0`, `content_sha256` omitted or `null`) reads the device once and returns one page with `total_bytes`, `returned_bytes`, `offset`, `next_offset` (`null` after the last page), `complete` and `content_sha256`. To read the next page repeat the same call with `offset=<next_offset>` and the `content_sha256` of the first page; it is served from the stored result, contacts no device and is not counted by the rate limit. The stored result lives 120 seconds in process memory and is dropped on restart or upgrade.

FortiOS exec reads and the exec reads of the normalized EXOS, IOS/IOS XE, NX-OS, EOS and Junos profiles (`ssh_read`, `switch_read`, `locate_endpoint`) replace only known secret literals, longest first, before and after converting `\r\n` to `\n`; the literals include original, LF and carriage-return-free forms. This preserves configuration syntax for `schema_read`, which parses the result and redacts its structured values. `ssh_read`, triage, `switch_read` and `locate_endpoint` then apply the full redaction rules in their callers before hashing and paging. Full output redaction always includes original, LF and carriage-return-free forms of known secrets, protecting PTY, prompt and sequence reads too. Thus `content_sha256`, the byte counts and offsets describe the returned text. FortiADC, Linux and the other platforms keep the line ends the device prints. This compatible change only affects a result fetched after the upgrade (a stored snapshot lives 120 s and is not shared with an older Helper); a lone `\r` that is not followed by a line feed stays as the device printed it.

A continuation (`offset` > 0) is refused before any device contact, as a tool error (`isError: true`, not a JSON-RPC `-32603`), with a structured result `{"ok": false, "error_code": ..., "error": ..., "restart_offset": 0}` (`schema_redaction_unverified` is the one refusal that omits `restart_offset`):

| `error_code` | Meaning | What to do |
|---|---|---|
| `ssh_pagination_snapshot_required` / `schema_pagination_snapshot_required` | `content_sha256` is missing, `null` or not 64 lower-case hex characters. `error` is `SSH pagination needs the content_sha256 of its first page; restart at offset 0` (`schema pagination ...` for `schema_read`) | copy `content_sha256` and `next_offset` from the first page |
| `ssh_pagination_expired` / `schema_pagination_expired` | no stored result for this hash (older than 120 s, wrong hash, other arguments, already read to the end, restart), or the stored text contains a secret that became known after its first page, for example another target's credential used in the same session. A secret that does not occur in the stored text, such as one from reading another target between two pages, does not expire it | restart at `offset=0`; a different operation is never replayed automatically |
| `schema_redaction_unverified` | `schema_read` only, on the first page: the redacted report could not be proven free of every known secret (for example a secret that spans JSON punctuation between two values), so it was withheld on purpose. The result has no `restart_offset`, because reading again gives the same refusal. `error` is `schema redaction could not be verified; report withheld` | do not retry unchanged; narrow `path`, `view`, `vdom` or `owners` to what is needed, or ask the operator to check the configured values |

Check `isError` and `error_code`; do not parse `-32603`. The codes are new, the texts are unchanged.

### What `content_sha256` and the offsets describe

`ssh_read` applies the Helper engine, proxy and worker redaction rules to the whole output before storing, hashing and splitting it. This canonical redaction includes all known target, session and transport secrets, passed through the private proxy-to-engine handoff before hashing or paging. A secret split across page boundaries is therefore already hidden in the complete output. The proxy and worker retain their response redaction as a second layer. `content_sha256` is the SHA-256 of that complete redacted text in UTF-8; `total_bytes`, `offset`, `next_offset` and `returned_bytes` count bytes of the same text. Concatenating the successful pages' `untrusted_device_output` as UTF-8 produces exactly that length and hash. Take `next_offset` from the previous page.

- Response redaction retains the credential keywords: `set password` and `set passwd` values become `[REDACTED]`. Canonical, value-free numbered markers such as `set psksecret <REDACTED:credential#1>` and `set community <REDACTED:credential#1>` survive; a marker with trailing credential text does not. `set community` and SNMP `set name` hide the entire value through the end of the line, including unquoted words after a marker. SNMP community strings, including FortiOS/FortiADC `set name` in SNMP community blocks and EXOS community commands, are hidden. SNMP context is recorded on the original text (LF, CRLF or CR), including blocks after unmatched outer `config`/`end` lines; the original credential ranges are carried through the helper → proxy → worker chain before masking, so legacy quote or cross-line matches cannot reveal a credential hidden by 1.0.6. A value-less `unset password` deliberately keeps the following line (`next`/`end`); it carries no credential. Terminal controls are removed between complete passes.
- `content_sha256`, `total_bytes`, `offset`, `returned_bytes`, `next_offset` and `complete` are typed protocol metadata computed by the engine. The proxy and worker keep them unchanged in both `structuredContent` and the JSON text, even when a known secret equals a byte count or occurs in the hash. Fields of another type or shape remain subject to redaction. This metadata protection applies to both paged tools.
- For both paged tools, the worker compares the final page text and all six metadata fields with the engine result in both representations. A changed page is withheld with `error_code: page_changed_by_redaction`, `restart_offset: 0` and `changed_fields` containing only field names. Restart with a different `max_bytes` if the text changed, for example where a page boundary cut a redaction marker.
- A page of `ssh_read` that is not the last one ends after the last newline inside it, so `returned_bytes` can be smaller than `max_bytes` and a redaction marker on a line (`Passphrase = [REDACTED]`) is not cut. The cut keeps UTF-8 characters whole and `offset`, `next_offset` and `returned_bytes` count the bytes the client receives; `content_sha256` and `total_bytes` do not depend on `max_bytes`. Only a page without any newline, such as a very long single line, is cut at the byte limit and can be withheld as above. A page of `schema_read` that is not the last one ends after the last comma outside a JSON string before the first byte a later layer would change (at most 16 tries), so neither that page ends nor the next one starts inside a key, a value or a marker. A page that cannot be made stable that way is still withheld.
- Both tools’ hashes and offsets can differ from 1.0.6. Restart at offset 0 after an upgrade; stored results do not survive a restart. Triage source digests use the same whole-output redaction.

`schema_read` redacts the report tree before serializing it as JSON, then stores, hashes and pages that complete document. Secret field values, including arrays or objects under a secret key, become a JSON string marker; a scalar that any redaction rule changes is hidden as a whole. With `view=show`, the textual `show` copy of an object whose attributes are redacted is rebuilt from the redacted attributes; a line that the rules still change becomes `[REDACTED]`. All known target, session and transport secrets are included. The engine then applies the proxy and worker response redaction to the document until it changes nothing more, as text, because that is how they judge a page: a value under a key that the proxy recognises by its name, such as `fortitoken` or `psksecret`, is the proxy marker `<REDACTED>`. The layers judge a document that fits in one page as JSON and would change such a value again, so that document is sent in more than one page. The worker checks the final page against the engine page. Concatenating successful pages yields valid JSON with the reported `total_bytes` and `content_sha256`, stable across `max_bytes`. If a later layer still changes a page, it is withheld with `page_changed_by_redaction`; the client must restart at offset 0.

## Reading the whole FortiOS configuration (config_read)

This guide describes the current behavior for FortiOS targets. Inventory fields
and capture limits are in [Optional configuration captures](../../../docs/helper-configuration.md#optional-configuration-captures)
and [Semantic full configuration redaction](../../../docs/helper-configuration.md#semantic-full-configuration-redaction).

### Enable it for one target (opt-in)

Nothing is readable until the target opts in. In the existing `helper.read_inventory`
object of the alias, set `"config_access": ["read"]` for `config_read`, or
`["read", "compare"]` to add `config_diff`; `compare` without `read` is refused at
load time. Leave the field out to disable both tools. The `helper` section itself,
next to `read_inventory` and not inside it, must set
`"fortios_output_standard_verified": true` (a FortiOS read is refused while it is
`false`); the target must also use the `fortinet` SSH platform with a pinned host key, and allow the SSH
port in its egress policy. A client never sends credentials or `auth_context`.

The device account stays read-only. Its profile must allow CLI get and CLI show
(`cli-show enable`) and keep `cli-config` disabled ([account model](../../../docs/account-model.md)).
An account that can authenticate but is refused `show` produces a failed capture,
not an empty configuration.

### Choose the read mode

| Goal | Arguments (besides `target`, `platform="fortios"`) | Device command |
|---|---|---|
| One section, short | `section="system interface"` (or `firewall policy`, `firewall address`, `router static`, `vpn ipsec phase1-interface`) | `show <section>` |
| Configured switch-port VLANs | `section="switch-controller managed-switch", redaction="full"` | `show switch-controller managed-switch` |
| SSID VLAN and forwarding configuration | `section="wireless-controller vap", redaction="full"` | `show wireless-controller vap` |
| Whole configuration, short | `section="all", include_all=true` | `show` |
| Whole configuration, full view | `section="all", include_all=true, redaction="full"` | `show` |
| Full view with default values | the row above plus `include_defaults=true` | `show full-configuration` |

`include_defaults` is accepted only with `redaction="full"`; otherwise the call is
refused with `config_platform_not_supported: full redaction mode required`. Any
other `section`/`include_all` combination is refused before a device command.
The default `redaction="minimal"` keeps its earlier behavior and requires a
verified single-VDOM device (`Virtual domain configuration: disable`); it returns
none of the scope fields described below. The full view is the one that keeps
mapped safe values, reads global/VDOM layouts and states how much was visible.

Firmware must be a measured build (FortiOS 7.6.8 build 3744 or 8.0.2 build 0251);
another build is refused with the detected and supported builds named.

### VLAN, switch-port and Wi-Fi relationships

FortiOS read-only accounts use the `wifi_*` read set described in [Wi-Fi reads for a read-only account](#wi-fi-reads-for-a-read-only-account). It supplies no live station list and no client RSSI.

Use `redaction="full"` for all three configuration reads: `system interface`
resolves interface names to VLAN IDs; `switch-controller managed-switch` exposes
port native VLAN, allowed VLANs and untagged VLANs; `wireless-controller vap`
exposes SSID, configured VLAN and local-bridging mode. These are configured
relationships: they do not show that a VLAN currently passes traffic on a port,
that a port is up, or which VLAN a client is in. Correlate them with the
managed-switch MAC/LLDP and wireless
station/VAP reads to locate the actual client and AP uplink. A station VLAN of
zero or a VAP without a VLAN ID does not establish a client VLAN; keep the
forwarding mode and interface relationship visible instead. Wi-Fi passphrases
remain redacted. The two controller sections require the full semantic mode.

### Pages and snapshots

A successful capture stores the redacted result in process memory and returns
`snapshot_id`, `content_sha256`, `total_bytes`, `returned_bytes`, `offset` and
`next_offset` (`null` after the last page). `limit` is 1-48,000 bytes. To read the
next page repeat the same call with `snapshot_id` and `offset=<next_offset>`, keeping
`section`, `include_all`, `redaction` and `include_defaults` unchanged. Such a call
is served from the stored capture and contacts no device, so all pages come from
one device read and carry the same scope fields. A different section, option, target
account, expired snapshot (24 h) or invalid offset fails explicitly; start again
with a new capture. The first call must use `offset=0`.

`content_sha256` and `total_bytes` describe the whole stored text, and joining the
`untrusted_device_output` of all pages in `offset` order gives exactly that text. A page
that is not the last one ends after its last line feed, so `returned_bytes` can be
smaller than `limit`; only a page without any line feed is cut at `limit`. Before it
hashes and pages a snapshot, a filtered view or a diff, the engine applies the proxy and
worker response redaction (including keyword preservation and numbered credential markers, see above) to the whole text, in their order,
until it changes nothing more. The stored text is therefore what the client receives:
each `set password <value>` line arrives as `set password [REDACTED]` (likewise
`passwd` and `secret` retain their keywords); a canonical numbered PSK or community
marker such as `<REDACTED:credential#1>` remains intact, while unmarked community
values become `<REDACTED>`, and `token: ...` inside a public value as `[REDACTED]`; hidden values
remain at least as protected as in 1.0.6; `credential_redactions` counts only the values the engine itself hid. A
value-less `unset password` line and the line after it stay unchanged. As for
`ssh_read`, the page metadata (`content_sha256`, `total_bytes`, `offset`,
`returned_bytes`, `next_offset`, `snapshot_sha256`, `filter_sha256`) of `config_read`
and `config_diff` is kept out of response redaction, and a page that a later layer would
still change is withheld with `error_code: page_changed_by_redaction`; restart at
offset 0, with a different `limit` if the page text changed (for example a page that
starts inside a line). NetOps 1.0.6 let the response redaction rewrite such lines after
the hash was computed, so a joined export could be shorter than `total_bytes` and miss
lines such as `next` or `end`. The Auditor reads a `[REDACTED]` line as no attribute.

`contains` and `context` search the already redacted lines of a snapshot; see
[Find lines in a redacted configuration](../../../docs/helper-configuration.md#find-lines-in-a-redacted-configuration).

To compare, take two captures with identical arguments and call
`config_diff(target, platform="fortios", base_snapshot=..., other_snapshot=...)`.
It reads no device and pages with `offset`/`limit`. For full captures the response
adds `base_capture` and `other_capture`, which repeat each capture's scope fields.
Captures that differ in section, firmware, redaction profile, `include_defaults`
or scope metadata are refused. `identical=true` means only that the visible redacted
text is equal; it says nothing about hidden credentials or parts the account could
not see.

### What the scope fields mean

A full capture returns these fields on every page and in `config_diff`:

| Field | Meaning |
|---|---|
| `capture_complete` | `true`: the device stream ended with valid grammar and was stored |
| `configuration_complete` | `true` only when the whole device configuration is shown as visible; see below |
| `config_scope` | `single-vdom-device`: the status output reported exactly `Virtual domain configuration: disable` and the capture does not declare more than one VDOM. A different status or multiple captured VDOMs gives `device-account-visible` with `vdom-coverage-not-verified`: the result covers only what this account could see |
| `identity_scope_verified` | `true` only for the single-VDOM case above |
| `visibility_limitations` | list of reasons why completeness is not claimed; empty when complete |
| `credential_redactions`, `unverified_count`, `unsupported_format_count`, `unverified_fields`, `unverified_truncated` | counts and up to 32 paths of hidden or unclassified fields, never values |

Values of `visibility_limitations` for FortiOS:

| Value | Reason |
|---|---|
| `vdom-coverage-not-verified` | the device did not report single-VDOM mode, or the captured `config vdom` block declares more than one VDOM; `config_scope` is `device-account-visible` |
| `account-rights-not-verified` | the capture does not prove that the enrolled login has exactly one global access profile with `cli-show enable` and `read` or `read-write` in every configuration group, with no profile/VDOM override, wildcard or remote authentication |
| `requested-section-only` | a section other than `all` was requested |
| `schema-fields-unverified` | at least one field or object is not classified for this firmware |
| `formats-not-verified` | a known field holds an embedded format the product cannot interpret |

Values of `visibility_limitations` for FortiADC (FortiADC-KVM 7.6.7 build 0676):

| Value | Reason |
|---|---|
| `system`, `networking`, `load-balance`, `log`, `link-load-balance`, `global-load-balance`, `security`, `share-resource`, `user` | the access profile of the enrolled login has `none` for this area |
| `access-profile-unverified` | the capture does not prove the rights of the enrolled login: its own `system admin` entry must appear exactly once with exactly one `access-profile` whose profile lists all nine areas, or with `is-system-admin yes` and no `access-profile` (a system administrator, whose rights FortiADC does not limit); `accprofile-override` must be absent or `disable` |
| `vdom-unverified` | the capture does not declare exactly one VDOM |
| `vdom-override-unverified` | the login's entry sets `vdom-override` to anything but `disable` |
| `requested-section-only`, `schema-fields-unverified`, `formats-not-verified` | as for FortiOS |

`configuration_complete` is `true` only when the list is empty and the device is a
verified single-VDOM device. It is derived from the captured configuration itself:
the account's own `system admin` entry and the access profile it points to must
appear in the output. Paging and `config_diff` never re-read rights from the device.

### Why a restricted account gets an incomplete result

`show` returns what the logged-in account is allowed to read, and a finished,
well-formed stream does not prove that this was everything. The product therefore
cannot tell from the output alone that something is missing, for example with a
profile that is not global-scope, lacks `read` in a configuration group, or hides
`system admin` or `system accprofile` from the account.
It does not guess: such a capture is stored and returned with
`configuration_complete=false` and `account-rights-not-verified`, and a
multi-VDOM device additionally gets `vdom-coverage-not-verified`. A profile name,
even a built-in one, is not accepted as proof. If the device refuses `show`, the
identity probe or the stream fails, the call is refused and no snapshot exists.

For a global/VDOM device the full view keeps the `config global` and `config vdom`
structure line by line, with only credentials replaced. For example, a global
account reading a device with two VDOMs returns
`config_scope="device-account-visible"`, `identity_scope_verified=false`,
`visibility_limitations=["vdom-coverage-not-verified"]` and
`configuration_complete=false`, even if the account's own profile checks out.

Treat an incomplete result as usable but partial: available redacted lines are
valid, a missing object is not evidence that it does not exist, and a diff of two
incomplete captures covers only what was visible.

### What stays visible and what is hidden

Visible when the field semantics are verified for the firmware: interface names,
addresses and masks, routes, object references and names, descriptions, public
certificates and fingerprints, and SNMP community strings. Showing a community
keeps SNMP queries SNMPv3 authPriv (SHA256, AES128) only.

Hidden before storage: passwords, authentication and privacy keys, private keys and
credential encodings, shown as `<REDACTED:credential#N>` (`N` is an occurrence number
and carries no information about the value; the same applies inside complete
commands of auto-scripts, which are never executed). A field or object the product
cannot classify is shown as `<UNVERIFIED:unclassified-field>`, and a known field
with an unsupported embedded format as `<UNVERIFIED:unsupported-format>`. These
markers are counted in the response and also cannot be searched or recovered.

Synthetic example of one page excerpt (`192.0.2.0/24` is documentation space):

```text
config system interface
    edit port1
        set ip 192.0.2.1 255.255.255.0
        set password [REDACTED]
    next
end
```

with the response fields

```json
{"redaction": "full", "section": "all", "capture_complete": true,
 "config_scope": "single-vdom-device", "identity_scope_verified": true,
 "configuration_complete": false,
 "visibility_limitations": ["account-rights-not-verified"],
 "credential_redactions": 1, "unverified_count": 0, "next_offset": null}
```

### Refusals that mean "not captured"

A refusal returns `isError` and publishes no snapshot or partial text. The category
names what failed: `config access is not enabled for this target`,
`firmware-not-supported`, `read-refused` (minimal read refused),
`device-refused` (full capture refused by the device), `identity-unverifiable`,
`capture-limit-exceeded` (byte/record limits, never silently truncated),
`redaction-unverifiable` (consumer or grammar failure), `transport-failed`, and
`configuration memory budget exhausted` (per-target `memory_bytes` or the shared
process budget). For `config_read`, `capture-limit-exceeded`, `read-refused`,
`device-refused` during full capture and `redaction-unverifiable` return JSON-RPC
`-32602` with fixed `data.category`, `data.reason` and operator `data.guidance`;
private device output and exception text are withheld. Other failures retain their
existing error handling. A memory refusal keeps that category in minimal and full reads,
including a nested auto-script, and does not appear as `redaction-unverifiable`.

## Triage budget and progress

Concurrent calls on one Helper instance queue, so set the client timeout for the sum of the queued call durations.

The per-target `rate_limit` caps the sum of manual queries and reserved triage reads (default 30 per 60 seconds). Triage also has its own sublimit of the same size. A triage reserves its complete read plan on acceptance: `triage_health` 10, `triage_routing` 5, `triage_vpn` 4, `triage_slb` 21, `triage_flow` 5 and `wifi_triage` 7 (15 when the target has an enrolled REST token). Both budgets are checked atomically; refusal returns `rate_limit` and `retry_after_seconds` without charging either. One `triage_slb` leaves 9 manual reads in the default window. `target_scope` and `helper_status` expose the total as `rate_limit` and the triage subset as `triage_rate_limit`.

`triage_slb` also reads up to four distinct DOWN real-server objects to fill follow-up diagnostic addresses; recommendations are returned only for enrolled addresses. Failed or excess reads make the result incomplete. A step refused locally before device transport has `reason: local_refusal` and does not advance read progress. Follow-up `health_check_verify` arguments include `count: 3` and `timeout: 20` so the checks can finish.

A triage runs a bounded plan of device reads. Measured `triage_slb` calls took about 61 seconds for HTTP, 71 seconds with a DOWN member (including its configuration read), and 81 seconds for HTTPS with a TLS profile; DOWN members can add up to four real-server reads. When the client sends a `progressToken` in `_meta` of the `tools/call` request, the triage reports `notifications/progress` after every device read: `progress` is the number of reads done (0 at the start), `total` the planned maximum (10, 5, 4 or 21; a call can finish with fewer reads) and `message` names the tool and the query or step that was just read, for example `triage_slb: 3 of at most 21 reads (pool_config)`. The message never contains device output. A client that resets its request timeout on progress, as the MCP SDK clients can, therefore does not abandon a long triage. Without a `progressToken` nothing changes: no notification is sent and the result is the same.

Through the NetOps HTTPS endpoint, a `tools/call` of a triage tool that carries a `progressToken` is answered as `text/event-stream` (Streamable HTTP) instead of one JSON body, as soon as the first progress report exists: server-sent `message` events with the progress notifications, then the JSON-RPC result as the last event. Every notification is written to the audit (`progress` records) before it is sent, and the result is audited before it is sent, as for any response. A call that is refused before its first device read (authorization, rate limit, platform) is answered with an ordinary JSON body. Without a `progressToken` the endpoint answers JSON as before. At most 64 progress notifications are sent per call. A failure after the first notification ends the stream with a JSON-RPC `error` event (`operation_failed`, `automatic_retry: false`); do not retry automatically, because the reads are already audited.

## FortiOS health triage (`triage_health`)

`triage_health(target)` runs one fixed, read-only sequence of ten catalogue reads on a FortiOS target and returns the facts it found, the rules that fired and what it could not check. It is qualified only for the exact identities FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 (HA A-P cluster, measured); any other model, version or build is refused with `config_platform_not_supported` after the first read (`system_status`), before any other command. The target must use the `fortinet` platform and enable `system_status`. One call consumes ten requests of the target's total budget and triage sublimit (see [Triage budget and progress](#triage-budget-and-progress)) and is refused as a whole when fewer remain.

| Chain part | Query | What is taken from it |
|---|---|---|
| identity | `system_status` | model, version, build |
| resources | `conserve_state`, `performance` | conserve mode, used/freeable memory and the device's own red and extreme thresholds; CPU and memory percentages |
| sessions | `session_stats` | session counters, including memory-tension and low-memory drops (context only) |
| ha | `ha_status`, `ha_checksum` | HA mode and every OK/WARNING line; per-member global and all checksums (skipped on standalone) |
| ntp | `ntp_status` | synchronized and ntpsync |
| updates | `autoupdate_versions` | each package version and expiry |
| links | `physical_interfaces`, `sdwan_health` | port state and speed (context only); SD-WAN health-check member state |

Rules (each finding names its rule, query, object and the fact that fired it):

| Rule | Fires when |
|---|---|
| F-CONSERVE-ON | memory conserve mode is on |
| F-MEM-RED | used memory reaches the device's red threshold |
| F-MEM-EXTREME | used plus freeable memory reaches the device's extreme threshold |
| F-HA-STATUS | `ha_status` reports a WARNING line |
| F-HA-CHECKSUM | cluster members differ in the global or all checksum |
| F-NTP-UNSYNC | NTP sync is enabled but the clock is not synchronized |
| F-UPDATE-EXPIRED | a package expiry date is before the capture date |
| F-SDWAN-DEAD | an SD-WAN health-check member is dead |

`verdict` is `incomplete` when any required step is missing (refused, timed out, truncated, empty or not parsed), `fault_found` when at least one rule fired, otherwise `no_fault_in_checked_data`. The verdict never claims the device is healthy: it covers only the data in `checked`. `missing` lists each unread step with its reason; `ha_checksum` on a standalone unit (the `Mode:` line compared without letter case) and an empty SD-WAN table or the exact reply `SD-WAN health monitor is not running.` or `SD-WAN daemon is not running.` (FortiOS 7.6.8 on a FortiGate-60F) are `not_applicable` and do not make the verdict incomplete. `hypotheses` stays empty; `next_steps` names the `ssh_read` query that shows the detail behind a memory or checksum finding. Device output is redacted before it is parsed, and the result carries no raw output.

The quick `dns_probe`, `tcp_probe`, `icmp_probe` and `tls_probe` results include `vantage: helper_host`: they measure from the Helper host.

## FortiOS route triage (`triage_routing`)

`triage_routing` recommends `fortios_diagnostics` ping and traceroute to measure from the firewall. Each step is a complete call: `target`, `recipe`, `address` and `interface`, the interface of the first forwarding (FIB) next hop that names one. Without such an interface (no route, `F-ROUTE-NONE`, or no forwarding hop with an interface) the steps are left out. The target must still enroll the recipe, the address and that interface, otherwise `fortios_diagnostics` refuses the call with `-32009` and `data.field`.

`triage_routing(target, address)` answers "which way does this device send traffic for one address, and is anything on that way documented as broken". It runs one fixed, read-only sequence of five catalogue reads and reports only what the device printed; it does not simulate the data plane (`dataplane_simulated` is always `false` and `not_simulated` lists what is left out: policy route and SD-WAN rule matching on source, ports, protocol and ingress interface, member selection inside a rule, firewall policy, NAT and sessions, recursive next-hop resolution). It accepts only the measured identities FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251. The five reads were measured live on the FortiGate-80F 8.0.2 build 0251 (HA primary, single VDOM, read-only account, 2026-11-08) and the parsers are tested on the anonymised outputs. Any other identity (another build, FortiGate-VM64 8.0.2 build 0251, which was not measured, `FortiGate-VM64-KVM`, another model) is refused with `config_platform_not_supported` after `system_status`, before any other command. The target must use the `fortinet` platform, enable `system_status` and `route_lookup`, and `address` must be an IPv4 address enrolled in the target's `addresses` inventory (the same rule as `ssh_read` with `route_lookup`); anything else is refused before the device is contacted. One call consumes five requests of the target's total budget and triage sublimit.

| Chain part | Query | What is taken from it |
|---|---|---|
| identity | `system_status` | model, version, build |
| route | `route_lookup` (`address`) | matched prefix, protocol, distance, metric, best flag, every next hop (gateway, interface, FIB flag, recursive tunnels); `% Network not in table` means no route |
| policy routes | `policy_routes_ipv4` | number of entries; entries whose destination covers the address (id, SD-WAN rule, outgoing interfaces, gateway); entries with internet services or negation are listed as not evaluated |
| SD-WAN | `sdwan_health` | health-check state of the members that are next-hop interfaces |
| neighbours | `arp_table` | for each directly reachable gateway, only the ARP entries on the next hop's egress interface count: complete, incomplete (all-zero hardware address) or absent (an entry on another interface does not count); `unknown` when the egress interface is not known; hardware addresses are not returned |

| Rule | Kind | Fires when |
|---|---|---|
| F-ROUTE-NONE | finding | the route lookup prints `% Network not in table` |
| F-EGRESS-SDWAN-DEAD | finding | a FIB next-hop interface is an SD-WAN member in `state(dead)` |
| F-NEXTHOP-ARP-INCOMPLETE | finding | the gateway of a FIB next hop has only incomplete ARP entries on its egress interface |
| H-NEXTHOP-NO-ARP | hypothesis | the gateway has no ARP entry on the next hop's egress interface, or is not in the ARP table at all (it may not have answered, or the entry aged out); not evaluated when the egress interface is unknown |
| H-POLICY-ROUTE | hypothesis | a policy route or SD-WAN rule covers the address and would override the route when its other match fields fit |
| H-POLICY-UNEVALUATED | hypothesis | some policy routes could not be evaluated |

Findings cite every read they rest on (`query`, `content_sha256`, `captured_at`); hypotheses carry the same `basis` and never change the verdict. `verdict` is `incomplete` when any step after `system_status` is missing (refused, timed out, truncated, empty or not parsed), `fault_found` when a finding fired, otherwise `no_fault_in_checked_data`; an empty SD-WAN table or the exact reply `SD-WAN health monitor is not running.` or `SD-WAN daemon is not running.` is `not_applicable`. Any output line of an unknown shape makes that step `unparsed` instead of being guessed. `next_steps` names `routing_table` after F-ROUTE-NONE, `sdwan_member_detail` for a dead egress member (the member number must be enrolled to run it) and, when a forwarding next hop names an interface, the two `fortios_diagnostics` calls described above. `vdom_mode` in the result is the `Virtual domain configuration` line of `get system status` (`disable`, `multiple`, or `null` when the line is absent). The reads cover only the default VDOM of the account; with `multiple` the result is not the whole device. On an HA cluster the route, SD-WAN and ARP state is read from the member the target address points to; the result does not describe the other member. When the matching prefix has several routes, the route marked `best` is used; an SD-WAN member is paired with a next hop by the part of its name before the first `/` (or the whole name without `/`), because FortiOS interface names cannot contain `/` ([naming rules](https://community.fortinet.com/fortigate-3/technical-tip-naming-rules-and-character-restrictions-98552)); a member shown as `<interface>/<name>`, e.g. `LTE-1/MOD-1-LTE`, belongs to that interface. Device output is redacted before it is parsed, and the result carries no raw output.

## FortiOS flow triage (`triage_flow`)

`triage_flow(target, src, dst, port, proto)` answers "does this firewall route and allow one flow, and does it have a session for it". It sends no packet. It reads, in this order: `system_status` (identity), `route_lookup` for `dst` (egress), `route_lookup` for `src` (ingress), `policy_lookup_ipv4` and, only when the policy accepts the flow, the sessions of the flow. It consumes five requests of the target rate limit. Its four catalogue reads and the session read use only the catalogue commands `get system status`, `get router info routing-table details <address>` and `diagnose firewall iprope lookup <src> <sport> <dst> <dport> <protocol> <ingress interface> policy`, and the bounded `sessions` recipe of `fortios_diagnostics`.

**Inputs.** `src` and `dst` are canonical IP literals (unicast, not loopback, no zone), `port` is an integer from 1 to 65535 and `proto` is exactly `tcp`, `udp` or `icmp`; anything else is refused before the device is contacted. The addresses do not have to be in the target's `addresses` inventory, and the ports, protocol and ingress interface of the policy lookup are not looked up in `flow_ports`, `ip_protocols`, `interfaces` or `policy_types`: the tool builds them from the checked input and the device's own route to `src`, and the catalogue still validates the shape of every value. The target must use the `fortinet` platform and enable `system_status`, `route_lookup` and `policy_lookup_ipv4`. For `icmp` the `port` is validated and then ignored.

**IPv6.** A call in which `src` or `dst` is an IPv6 literal returns `ok: false`, `verdict: "unsupported"` and `reason: "ipv6_not_supported"` without contacting the device; mixed IPv4 and IPv6 is the same. Use `ssh_read` with `policy_lookup_ipv6` for IPv6.

**Identity.** Only FortiGate-80F 8.0.2 build 0251 with `Virtual domain configuration: disable`; any other model, build or VDOM mode is refused with `config_platform_not_supported` after `system_status`. The reads were measured on that model (HA primary, read-only account, 2026-11-08) and the parsers are tested on the anonymised outputs (`fortios_80f_802_flow_*` fixtures). The shape of the `policy_action: deny` line of an explicit deny policy and an `ICMP` lookup result were not measured on 8.0.2: see the limits below.

**Reading the answer.**

| Field | Content |
|---|---|
| `verdict` | `allowed_and_session_seen`, `allowed_no_session`, `denied_by_policy`, `no_route`, `incomplete` |
| `chain.ingress` | the route to `src` and the `interface` derived from it (a single forwarding interface; with no route to `src` the policy lookup is not run: `ingress_unknown`, with several interfaces: `ingress_not_unique`) |
| `chain.egress` | the route to `dst` and its forwarding `interfaces` |
| `chain.policy` | `matched`, `policy_id`, `action` (`accept` or `deny`), `implicit` (no policy matched) and `nat`, always `not_reported_by_lookup`: the lookup does not print NAT |
| `chain.session` | `state` (`read`, `not_run` or `not_needed`), `device_total`, `matching` and up to five `sessions` (policy id, state, duration, expiry, source port, NAT action and translated address) |
| `vantage` | `device_cli_lookup`: the tool reads the firewall's tables and sends no packet; the ingress interface and the probe source port it used |
| `findings`, `missing`, `checked`, `next_steps` | as for the other triage tools; every finding cites the reads it rests on |
| `assumptions`, `not_simulated` | what the answer depends on and what it does not cover |

**Verdicts.** A missing step comes first: when `missing` is not empty the verdict is `incomplete`, whatever else was read. `no_route`: the routing table has no route to `dst` (`F-FLOW-NO-ROUTE-DST`; policy routes are not evaluated, see `not_simulated`) and no required step is missing; the finding stays in `findings` when the verdict is `incomplete` because the route to `src` could not be read or derived. `denied_by_policy`: the policy lookup found the implicit deny or a policy whose action is `deny`. `allowed_and_session_seen`: the policy accepts and at least one session on the device matches `src`, `dst`, `port` and `proto` (any source port). `allowed_no_session`: the policy accepts and a complete session read found none. Everything else is `incomplete`: a read that was refused, timed out, was empty or not parsed (`missing` names the step and the reason), a device lookup error (`F-FLOW-LOOKUP-ERROR`, for example `err_src_route`), no route to `src` (`F-FLOW-NO-ROUTE-SRC`: reverse-path filtering may drop the packet, but that is not read; `missing` carries `{"step": "policy_lookup", "reason": "ingress_unknown"}` because no ingress interface can be derived, as it does when the route to `src` could not be read), an `icmp` flow (the policy lookup of 8.0.2 answers `Invalid ICMP type and code` for every combination tried, so only the two routes are read, `missing` carries `unsupported` for the policy lookup and the session, and the verdict is `incomplete` even without a route to `dst`) and a policy that accepts when the session read was not possible. An accepted flow is never called `allowed_no_session` unless the session read was complete.

**Fixed source port.** The policy lookup needs a source port. The tool uses the fixed port 40000 for every flow and says so in `assumptions` and in the finding. A policy whose service restricts the source port to a range that does not contain 40000 is not matched by the lookup, although a connection from a source port inside that range may match it, so `denied_by_policy` and the policy id hold for a connection from port 40000. The ingress interface is the interface of the route to `src`; the real packet may arrive elsewhere (asymmetric routing).

**Sessions without a source port.** The existing `sessions` recipe needs the whole tuple including the client's source port, which a triage does not know. `triage_flow` runs the same recipe with the filter `src`, `dst`, `dport` and `proto` and no `sport`, and repeats the tuple filter on the returned sessions itself; it reports the device's total beside the matching count and calls the read `incomplete` when they differ. The recipe changes the session filter of the administrator session and restores and verifies it afterwards, so the account needs what the `sessions` recipe needs, and the target must enrol the `sessions` recipe in `diagnostic_recipes` and the ingress interface in `interfaces`; otherwise `missing` carries `{"step": "session", "reason": "not_enrolled"}` and the verdict of an accepted flow is `incomplete`. The session read was measured on a FortiGate-80F 8.0.2 build 0251 (HA primary) with a read-only account: the filter `src`, `dst`, `dport` and `proto` without `sport` is accepted, `diagnose sys session list` then prints only the sessions of that tuple (two DNS sessions with different source ports from one client) or only `total session: 0`; both outputs are anonymised fixtures of the tests (`fortios_80f_802_flow_session_seen.txt`, `fortios_80f_802_flow_session_none.txt`). The empty list as the Helper itself receives it from the session (the prompt and the final line end already removed) is only `total session: 0` without a line feed, measured on 2026-11-09 on the same device and kept as `fortios_80f_802_flow_session_none_pty.txt`. The parser accepts the empty list when, after removing prompt lines, carriage returns and blank lines, exactly the line `total session: 0` remains; any other line next to it leaves the read `unparsed`, and the `missing` entry then carries `first_lines`: at most three leading lines of the redacted text, each at most 80 printable characters, so the unknown shape can be diagnosed without another device read. Sessions the FortiGate itself originates (`hook=out`, seen in a list filtered by `dport` only) are not a forwarded flow; a session whose `hook` line has a shape the parser does not know makes the read `incomplete`. `next_steps` are complete calls of the Helper tools, including `target`.

**Not done.** There is no flow trace (`diagnose debug flow`) in this tool; run `fortios_diagnostics` with the `flow` recipe, the real client source port and a window in which the client sends traffic. NAT of a flow without a session is not reported; `next_steps` offers `config_read` of `firewall policy` for the policy id. Policy routes and SD-WAN rules are not matched against the flow (use `triage_routing` for the destination), and traffic to the FortiGate itself (local-in policy) is not covered.

## FortiOS VPN triage (`triage_vpn`)

`triage_vpn(target, tunnel)` reads one named IPsec tunnel on a FortiOS target with four fixed catalogue reads and returns the facts, the rules that fired and what it could not check. Identity, platform and scope rules are the same as for `triage_health` (FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251; `fortinet` platform with `system_status` enabled). `tunnel` must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,34}`; it is never sent to the device, it only selects lines of the parsed output. The phase 1 name selects the tunnel and its dial-up or ADVPN instances `<tunnel>_<number>`. One call consumes four requests of the target's total budget and triage sublimit. Detailed IKE gateway and tunnel dumps are not read, so no keying material reaches the result.

| Chain part | Query | What is taken from it |
|---|---|---|
| identity | `system_status` | model, version, build |
| tunnel | `ipsec_summary` | per instance: peer, selectors total and up, rx and tx packets and errors; an empty summary means no tunnels |
| routes | `routing_table` | prefixes whose interface (`via <tunnel> tunnel <peer>`, `via <gateway>, <tunnel>` or `directly connected, <tunnel>`) is the tunnel |
| ike | `ike_errors` | number of counters and the non-zero ones (`nonzero`; context only, no rule). Counters named `ha.*` describe the HA synchronisation, not IKE failures; they are listed apart under `context` |

| Rule | Fires when |
|---|---|
| F-VPN-NOT-FOUND | the summary has no instance of the tunnel |
| F-VPN-DOWN | no selector is up |
| F-VPN-PARTIAL | some but not all selectors are up |
| F-VPN-NO-RX | selectors are up but no packet was received (an SA alone is not data flow) |
| F-VPN-ERRORS | rx or tx error counter is above zero. Severity `fault` when the errors reach 1 % of the packets of their direction (or there are errors and no packet), otherwise `notice` |
| F-VPN-NO-ROUTE | the tunnel exists but no route in the routing table uses it (a policy-based tunnel has no routes) |

Every finding carries a `severity`. `verdict` is `incomplete` when any step is missing (refused, timed out, truncated, empty or not parsed), `fault_found` when at least one rule of severity `fault` fired, otherwise `no_fault_in_checked_data`; a `notice` finding (a few packet errors on a tunnel that carries traffic: measured 0.04 % and 0.2 % on a healthy tunnel pair) stays in `findings` but does not change the verdict. It never claims the tunnel is healthy. Rules that need a missing step do not fire. `hypotheses` and `next_steps` stay empty. Device output is redacted before it is parsed, and the result carries no raw output.

## Wi-Fi reads for a read-only account

On a read-only FortiOS account the five `diagnose wireless-controller` queries (`wifi_clients`, `wifi_client_detail`, `wifi_access_points`, `wifi_ap_detail`, `wifi_ssid_mapping`) are refused. They stay in the catalogue for `admin-bounded` accounts; the set below is their replacement for a read-only account. It was measured on FortiGate-80F 8.0.2 build 0251 with two FortiAP (see [the measurement](vendor-cli-references/fortinet-fortios.md#wi-fi-reads-for-a-read-only-account-measured)); each query is enabled per target.

| Query | Device command | Parameters | Result in `ssh_read` (`wifi`) |
|---|---|---|---|
| `wifi_ap_status` | `get wireless-controller wtp-status [<wtp-id>]` | optional `wtp_id` | per access point: serial, name, IP, state, version, `join_time` always `null` with `join_time_note` (the SSH wall clock has no timezone; use `wifi_aps_live` for the UTC join time), LLDP uplink, and per radio: channel, TX power, clients, channel utilisation, TX retries, rogue and interfering AP counters, antenna RSSI |
| `wifi_vap_status` | `get wireless-controller vap-status` | none | per SSID: name, state, online and offline clients, bridging flags |
| `wifi_neighbors` | `get wireless-controller scan` | none | per scan entry: SSID, BSSID, channel, rate, signal, noise, capabilities, flags, age; the table does not name the access point that heard the entry |
| `wifi_controller_status` | `get wireless-controller status` | none | access point sessions, clients, client peaks per quarter hour, hour and day |
| `wifi_controller_statistics` | `get wireless-controller statistics` | none | session, client, rogue AP and rogue client totals |
| `wifi_rf_analysis` | `get wireless-controller rf-analysis [<wtp-id>]` | optional `wtp_id` | per access point and channel: rssi total, rf score, overlapping and interfering APs, channel utilisation |
| `wifi_events` | `execute log filter category event`, `execute log filter field subtype wireless`, `execute log filter view-lines <lines>`, `execute log display` in one SSH session | `lines` (integer 1 to 200), optional `mac_literal` | per record: time, log description, event class, client MAC and IP, SSID, VAP, access point, radio, channel, signal, SNR, reason |

The result of each of these `ssh_read` calls carries the usual text and, beside it, `wifi`: `records` (the normalised records above), `unparsed` (line numbers of every output line the parser did not recognise, at most 20) and `unparsed_count`. A line of an unknown shape is reported, never guessed; all output measured on the 80F 8.0.2 parses without an unrecognised line. `wifi_rf_analysis` ends with a `Controller: <id>` block of the two columns `channel` and `rssi_total` (the sum over all access points); it is returned as a record with `scope: "controller"` and `controller_rows` (`channel`, `rssi_total`), next to the per-access-point records with `channels`. Not every field exists in every output: `wtp-status` reports neither a channel width nor an uptime (`width_mhz` and `uptime_s` are null), and a client's live signal is not in any of these reads.

**`wtp_id`.** The slot is optional for `wifi_ap_status` and `wifi_rf_analysis`. A value is sent to the device only if it matches `[A-Za-z0-9][A-Za-z0-9_-]{0,34}` and is either listed in `read_inventory.wtp_ids` or was returned by an earlier `wifi_ap_status` of the same target in this Helper process (remembered for an hour, at most 256 ids per target, never shared between targets). The proxy checks the syntax and the Helper engine checks the origin, so an id that the target never listed is refused as `not enrolled in target inventory`.

**`wifi_events`.** This is a separate template type: a fixed sequence of exactly the four `execute log` commands above, in this order, in one SSH session. The log filter is session state and is gone when the session ends; nothing is written to the configuration. No other `execute` command can be sent: the catalogue accepts only that sequence, and the engine checks the rendered commands again just before sending them. `lines` must be a canonical integer from 1 to 200. If a filter command prints anything, the device refused it and the call ends as `device_cli_error` without running `execute log display`. The log holds the newest records first; `view-lines` limits how many are read, and the optional `mac_literal` (lower-case `aa:bb:cc:dd:ee:ff`) keeps afterwards only the records whose client MAC or BSSID equals it. The Helper applies this filter to the redacted text of the returned lines, never on the device, so it cannot reach back beyond `lines` records; the device's own "N logs found" and "M logs returned" lines stay as they were. Records are untrusted device text (the `message` field is cut to 200 characters). Event classes are inferred from description, reason, status and action (`client_dhcp`, `client_connect`, `client_disconnect`, `client_roam`, `client_error`, `rogue_ap`, `other`); only the descriptions measured on the device (`Wireless client disassociated`, `Wireless client disconnected by WTP`, `Wireless station DNS process failed with no server response` and the `Rogue AP` events) are certain.

**Volume.** `wifi_vap_status`, `wifi_controller_status` and `wifi_controller_statistics` are about ten lines and not marked high-volume; `wifi_ap_status` (about 110 lines per access point), `wifi_neighbors`, `wifi_rf_analysis` and `wifi_events` (up to 200 records) can need continuation.

## Wi-Fi client triage (`wifi_triage`)

`wifi_triage(target, mac)`, `wifi_triage(target, ip)` or `wifi_triage(target, name=…)` follows one Wi-Fi client through the reads above and returns what the controller shows, the rules that fired and what no read-only path can show. Give exactly one selector: `mac` in lower-case `aa:bb:cc:dd:ee:ff` form or `ip` as a canonical IPv4 address, or an exact case-insensitive hostname `name`. An IP can be resolved through `arp_table` or a unique REST match; the canonical station MAC is sent as an exact REST history filter before the 200-row bound (SSH filters its returned batch locally). The target must use the `fortinet` platform with `system_status` enabled; `wifi_events` is optional; `arp_table` (for `ip`), `wifi_ap_status`, `wifi_vap_status`, `wifi_rf_analysis` and `wifi_neighbors` complete the chain, and a read that is not enabled or fails becomes a `missing` step (`permission_denied` and the other usual reasons). The first read is the device identity; any model or build other than FortiGate-80F 8.0.2 build 0251 is refused with `config_platform_not_supported`. The call reserves seven reads of the target's rate limit, plus eight when REST is enrolled (client/AP/identity once, two station-only snapshots, one station-filtered history GET and rogue/interfering GETs).

Calls on one target are serialized: a Wi-Fi triage taking about 25–30 seconds
blocks subsequent reads of that target until it completes; transport delays and
three signal snapshots can extend this. Schedule other polling after triage.
With REST enrollment and a resolved MAC, triage takes three client snapshots with
starts about three seconds apart (slow reads can lengthen the gap), within its
15-read reservation: seven possible CLI reads plus eight REST GETs (client/AP/identity once, station-only samples 2 and 3, one log GET and rogue/interfering GETs). Both views show `chain.signal_samples` with RSSI/SNR
minimum, maximum and last value, actual fetch times, AP/radio context and gaps.
The minimum triggers weak-signal/SNR heuristics even if the final read fails; a weak-signal fault requires minimum and final RSSI below the severe threshold, otherwise warning. Every sampling gap remains visible and the finding states whether the last RSSI is weak, recovered or unavailable. No sample from another MAC is included.

`chain.client_state` describes this client's signal/link. `chain.radio_context`
describes utilization/retries shared by all clients on its radio; radio findings
say "radio-wide, shared by N clients, not specific to this client" and retain the
source, known utilization interval and unknown retry interval. `fetched_at` (and
the compatible `captured_at`) means retrieval time. Signal measurement age and
common radio measurement age are null when the source provides no measurement
time; `channel_utilization_age_seconds` uses only that metric's source timestamp.
A warning-level successful handshake is not an authentication failure. Both views
explicitly report "no authentication failure in retained history of this MAC"
when none is found, qualified by the retained history coverage.

| Chain part | Query | What is taken from it |
|---|---|---|
| client address | `arp_table` | with `ip` only: the one MAC of that IP and the interface it was learned on; none or several MACs end the chain with a `missing` step |
| events | `wifi_events` (200 lines, `mac_literal` set to the client) | the client's records; the newest one gives the access point, radio, SSID, channel and last logged signal |
| access point, radio | `wifi_ap_status` | state of that access point, and of the radio the event names: channel, utilisation, TX retries, interfering and rogue counters |
| SSID | `wifi_vap_status` | state and client counts of the SSID named in the event |
| RF | `wifi_rf_analysis` (with that access point's id, listed by the previous read) | the row for the radio's operating channel |
| neighbours | `wifi_neighbors` | scan entries on that channel and the strongest signal (controller-wide, not per access point) |

Every finding carries a `severity`. The rules of severity `fault` decide the verdict:

| Rule | Severity | Fires when |
|---|---|---|
| F-WIFI-CLIENT-ERROR | fault or historical notice | the newest event is an error; downgraded if older than the current successful association |
| F-WIFI-WEAK-SIGNAL | warning / fault | minimum RSSI below −70; fault only if minimum and last are both below −75 dBm |
| F-WIFI-LOW-SNR | warning | SNR below 20 dB |
| F-WIFI-AP-NOT-CONNECTED | fault | the access point of the newest event is not in connection-state `Connected` |
| F-WIFI-RADIO-NOT-OPERATING | fault | the radio of the event reports `oper-chan` 0 |
| F-WIFI-VAP-DOWN | fault | the SSID of the event is not `up` |
| F-WIFI-CLIENT-DISCONNECTED | notice | the newest event of the client is a disconnect |
| F-WIFI-RADIO-BUSY | notice | channel utilisation of the radio is 70% or more |
| F-WIFI-RADIO-RETRIES | notice | TX retries of the radio are 20% or more |
| F-WIFI-RADIO-INTERFERENCE | notice | the radio reports 5 or more interfering access points |
| F-WIFI-STRONG-COCHANNEL-NEIGHBOR | notice | a neighbor heard by the client's AP has matching band and possible channel-width overlap through wifi_relevance, with signal -60 dBm or stronger; controller-wide matches are context only |

The numeric limits are Helper heuristics, not vendor limits, and each finding says so in its `fact`. Hypotheses (`H-WIFI-CHANNEL-CHANGED`: the event was on another channel than the radio now uses; `H-WIFI-EARLIER-ERROR`; `H-WIFI-AP-LAST-FAILURE`) never change the verdict.

`verdict` is `client_not_associated` when the final successful REST snapshot does not list the selected MAC; history supplies a logged cause or `unknown`. Otherwise it is `fault_found` when a fault-level finding fires, otherwise it follows `rf_verdict` (`incomplete`, `no_rf_fault_found` or `rf_concern_found`; see the diagnostic evidence section below). It is never healthy: the triage does not follow the client to its switch port, so `missing` always holds `{"step": "locate_endpoint", "reason": "not_correlated"}` with a `detail`, and with a known client MAC `next_steps` holds a `locate_endpoint` call (`targets` this target, `endpoint` the client MAC) to which the enrolled switches of the path can be added. Without REST enrollment, `missing` holds `{"step": "client_rssi", "reason": "rest_token_not_enrolled"}`; its `detail` says that live RSSI and SNR need a read-only REST token for this target ([enrollment](../../../docs/fortios-wifi-rest.md)). With a unique live client and RSSI/SNR, this missing item is removed. Every `next_steps` entry carries the `target` (or `targets`) argument and can be called as it is. REST failure, no matching client or missing signal fields remain explicit missing evidence. A client without a record among the newest 200 wireless log records is `client_events` with the reason `not_in_window`: that is not proof that the client is absent. Output with an unrecognised line makes its step `unparsed` and nothing is concluded from it. `vantage` states the path (FortiOS CLI over SSH with a read-only account), what it sees and what it does not. Event times are the device's local time with the offset the device logs. Device output is redacted before it is parsed.

## FortiADC load-balancing triage (`triage_slb`)

`triage_slb(target, virtual_server, vdom="root")` follows one FortiADC virtual server through its configuration and runtime state and returns the chain, the rules that fired and what it could not check. The target must use the `fortiadc` platform with `read` in `config_access`, `virtual_server` must be listed in `adc_virtual_servers`, `vdom` in `adc_vdoms`, and the queries `slb_vs_stat`, `slb_load` and `system_performance` must be enabled. The first read is the device identity; any build other than FortiADC 7.6.7 build 0676 returns `ok: false` with `error_code: config_platform_not_supported`, and an unreachable, refused or unverifiable identity read returns its [transport class](#transport-classes) (for example `unreachable`, `timeout`, `host_key_mismatch` or `auth`), `device_cli_error` or `product_identity` (with `failed_step: "system_status"`, see [Triage read failures](#triage-read-failures-and-schema-availability)) before anything else is read. One call consumes 21 requests of the target's total budget and triage sublimit and is refused as a whole when fewer remain. The 21 requests are charged when the call is accepted and leave the window `window_seconds` later; a call can run longer than the default 60-second window (about 61 seconds for HTTP, 71 seconds with a DOWN member (including its configuration read), and 81 seconds for HTTPS with a TLS profile, measured on FortiADC-KVM 7.6.7 build 0676). The helper handles calls one at a time, so a `target_scope` sent during the call returns only after it finishes and no longer counts them; `triage_rate_limit.used: 0` then does not mean nothing was charged. The call reports progress after every device read (see [Triage budget and progress](#triage-budget-and-progress)).

| Chain part | Source | What is taken from it |
|---|---|---|
| virtual server | `config_read` `load-balance virtual-server <name>` | status, pool, client SSL, WAF and DoS profile names |
| pool | `config_read` `load-balance pool <pool>` | members (id, real server, status, health checks) and pool health checks |
| health checks | `config_read` `system health-check <name>` | at most four, each enrolled in `adc_health_checks`; others are reported missing |
| TLS and WAF profile | `config_read` of the attached profile | profile presence only |
| runtime | `slb_vs_stat`, `slb_load` | availability, per-member health state and last change, load status and weight |
| TLS, DoS, WAF runtime | `tls_handshake_stats`, `dos_access_limit`, `dos_conn_limit`, `dos_req_limit`, `waf_signature_status` | only when the profile is attached |
| resources | `system_performance` | key/value counters (context) |

Fault rules: F-VS-DISABLED, F-VS-AVAIL, F-MEMBER-DOWN, F-POOL-ALL-DOWN, F-MISMATCH and F-TLS-FAIL. F-MEMBER-DISABLED, F-NO-HC, F-DOS and F-WAF are informative findings and do not make the verdict `fault_found`. Every finding names its source (`call`, `query` or `section`, `content_sha256`, `captured_at`). For a member that is not UP, `next_steps` names `fortios_diagnostics` with `health_check_verify` and `ping`, each only when the target would accept it: the recipe is in `diagnostic_recipes`, the health check in `adc_health_checks`, and for `ping` `allow_icmp` is true.

`verdict` is `incomplete` when any step is missing (timeout, truncated, empty, unsupported, permission_denied, device_cli_error, unparsed or not_applicable) or one of the required steps (virtual server, pool, `slb_vs_stat`, `system_performance`) did not run, `fault_found` when a fault rule fired, otherwise `no_fault_in_checked_data`; it never claims the service is healthy. Configuration is read with full redaction and the result carries no raw output.

## FortiSwitch MCLAG state

For the FortiOS queries `switch_mclag_icl`, `switch_trunk_status` and `switch_mclag_consistency`, `ssh_read` adds a `mclag` object next to the bounded device text. It holds only grammar-checked values: port names `port1` to `port999`, switch serials and fixed state words, never MAC addresses. The `trunk` field repeats the enrolled `mclag_trunk` value; FortiLink trunk names can contain a FortiGate serial number or a MAC address, so treat that field as inventory data. A switch that answers `does not support MCLAG feature!` returns `ok: true` with `mclag.state` `not_supported` for all three queries. Any output the parser cannot read completely, including empty output, a missing or truncated row or a port token outside the grammar (for example a split port), gives `incomplete`, never `ok`.

| Query | What it shows | `mclag.state` |
|---|---|---|
| `switch_mclag_icl` | configuration only: ICL trunk name, ICL ports, local and peer serial, split-brain setting; it says nothing about whether the ICL link is up, read that with `switch_trunk_status` on the ICL trunk | `configured`, `not_configured` (the answer has the `Managed Switch` header, ends with an empty line and holds no MCLAG ICL), `not_supported`, `incomplete` |
| `switch_trunk_status` | trunk status, role (`icl`, `mclag`, `lag`) and every member port with its status | `ok` (trunk up, all members up), `degraded` (trunk up, some member not up, listed in `missing_members`), `down`, `not_found` (the listing is complete and the trunk is not in it), `not_supported`, `incomplete` |
| `switch_mclag_consistency` | peer configuration checks, LAG member state on both peers and STP state of the active LAG ports; it does not show link state, use `switch_trunk_status` for that | `ok`, `degraded`, `down`, `inconsistent`, `not_found`, `not_supported`, `incomplete` |

The peer consistency states are decided in this order: `not_found` (trunk not on the local switch); `incomplete` when no configuration check could be read; `inconsistent` when any configuration check is not `OK`; `incomplete` when a required LAG or STP row is missing or unreadable (named in `unreadable_fields`); `down` when the LAG state is not `UP`, or no LAG member is active on either peer, or neither peer has an active LAG port; `degraded` when a local or peer member is inactive (`missing_members`) or a side is in STP `LEARNING`, `LISTENING`, `BLOCKING` or `DISCARDING` (`stp_state`); otherwise `ok`. Any other STP state word is unreadable and gives `incomplete`. `stp_blocked` lists active LAG ports on a side that is not `FORWARDING`; a non-empty `stp_blocked` is a finding, because traffic on a working member is discarded.

Every complete answer seen from FortiOS 8.0.2 and 7.6.8 ends with an empty line, and the parsers use that as the end of the answer. A `switch_mclag_icl` answer that stops after the `Managed Switch` header without that empty line is `incomplete`, not `not_configured`. A `switch_trunk_status` answer is `not_found` only when it ends with that empty line and every trunk block in it is complete (status, port count and the same number of member rows); a header without any trunk block, a missing end or a cut block gives `incomplete`.

The trunk toward an HA secondary FortiGate in active-passive mode is normally inactive: one MCLAG peer reports its member as inactive, no active LAG ports and STP `DISCARDING`, and `switch_trunk_status` shows the trunk `down` with the member suspended. That gives `degraded` with an empty `stp_blocked` and is expected; compare it with the HA role before calling it a failure. The trunk toward the HA primary should be `ok` on both peers. These parsers were checked against FortiSwitchOS output managed by FortiOS 8.0.2 (FS-224E) and against the `not_supported` answer of an FS-108 managed by FortiOS 7.6.8; other output forms give `incomplete`.

## FortiSwitch DHCP snooping bindings

For the FortiOS query `switch_dhcp_bindings` (`dhcp-snooping status`), `ssh_read` adds a `dhcp_bindings` object next to the bounded device text. Each entry of `bindings` is one IPv4 row of the switch `Client db` table: `flags` (the `S`, `A`, `D` column, empty when not set), `mac` (lower case), `vlan`, `ip`, `lease` and `expiry` (as printed, `D:H:M:S`), `port` (the switch interface the client was learned on) and `server_ip`. The `Host Name`, `Domain Name` and `Vendor` columns are left out, because an empty column is not marked in the output and the values cannot be assigned reliably; they stay in the device text. The snooping settings (snooping VLANs, trusted ports, database limits) are read with `switch_dhcp_snooping` (`dhcp-snooping database`), which has no per-client row.

| Field | Meaning |
|---|---|
| `state` | `ok` (the answer is complete and holds at least one binding), `empty` (complete, the `Client db` table has no row; a switch without bindings prints the section names without the column header), `incomplete` (the `Client db` section, the following `Server db` section or the closing `Flags: S (Static), ...` legend is missing, a row comes without the `Client db` column header, or some row is unreadable) |
| `total_bindings` | readable IPv4 bindings in the whole answer |
| `bindings` | the bindings whose row starts on the returned page; read the next pages with `next_offset` and every binding appears on exactly one page |
| `unreadable_rows` | `Client db` rows outside the grammar (MAC address, VLAN 1 to 4094, IPv4 addresses, `D:H:M:S` times, port name); they are not returned and make the state `incomplete` |
| `ipv6_rows_present` | `true` when the `Client6 db` table has rows; IPv6 bindings are not parsed, read them in the device text |

The parser was checked against output of FortiOS 8.0.2 build 0251 (FS-224E managed by a FortiGate 80F) and 7.6.8 build 3744 (FortiGate 60F); other output forms give `incomplete`.

## Live Wi-Fi through RO REST

`wifi_clients(target, ssid=None, ap=None, mac=None, limit=100, offset=0, max_bytes=16000, name=None)` reads normalized live clients (MAC, IP, SSID, AP label and distinct serial or unresolved ID, radio/band/channel, RSSI/SNR, noise, Mbps PHY rates, association time in ISO 8601 UTC/duration, authentication/security/state). Exact local filters combine with AND; AP matches name, serial or ID. This public REST tool is distinct from the legacy `ssh_read` query named `wifi_clients`, which remains refused for read-only SSH accounts.

`wifi_aps_live(target, summary=false, limit=100, offset=0, max_bytes=16000)` combines managed AP records and controller counts; summary shows one AP name and existing radio measurements, source width, operating/traffic state and separate utilization age (common radio age is unknown). `wifi_rogue` defaults to a relevant neighborhood (four reserved reads), while `full=true` requests all grouped observations. Client reads reserve three requests, AP reads two. Unenrolled tools return `unsupported` without contacting the device and cost one slot. Both `wifi_triage` views retain deciding RF facts and explanatory findings, with separate RF and wired completeness. See [diagnostic evidence](#wi-fi-diagnostic-evidence-107) for fields, thresholds, timeline and relevance semantics.

All calls use the private `api-token` vault reference `helper.fortios_rest_credential`, mandatory certificate pin or CA, explicit TCP egress for `fortios_rest_port` (default 443), fixed root-VDOM GET endpoints, response/time/rate limits, redaction and mandatory auditing. Clients cannot supply a token, method, path, server filter or request body. [FortiOS Wi-Fi REST setup and security](../../../docs/fortios-wifi-rest.md) lists exact endpoints, measured 200/403 evidence, all returned fields, FortiGate provisioning and token rotation/revocation.

### Transport classes

Every Helper tool that reads a device over SSH (`ssh_read`, `schema_read`, `switch_read`,
`locate_endpoint`, `config_read`, `fortios_diagnostics` with its FortiADC recipes, and the triage tools) reports a
failed SSH transport with one fixed class in `error_code` and the fixed advice of that class in
`error`. The Helper audit records the same class in `detail` of the failed operation. Neither
field ever carries device text, SSH client text or a secret.

| `error_code` | Cause | First check |
|---|---|---|
| `unreachable` | no route to the target, or the host is down | power, address, routing |
| `timeout` | the target did not answer in time | reachability, firewall, SSH port |
| `dns` | the enrolled name did not resolve | host name, Helper DNS |
| `connection_refused` | the host answered and refused the SSH port | SSH service, trusted hosts |
| `host_key_unavailable` | the host answered, but no usable host key could be read | SSH service, `legacy_ssh` |
| `host_key_mismatch` | the offered host key does not match the pin | verify the key out of band |
| `negotiation` | no common SSH algorithm | `legacy_ssh` for this device |
| `auth` | the device refused the account or password after the pin matched | account, password, lockout |
| `auth_method_unsupported` | the device asked for a second factor or another prompt than the password | an account that logs in with its password alone |
| `disconnected` | the device closed the SSH connection | session limits, admin access |
| `output_limit`, `exit_status`, `transport_failure` | output over the limit, a failure exit status, or an unclassified failure | narrow the request; SSH access |

`ssh-keyscan` does not say why it obtained no key. The Helper then runs one SSH probe that
offers no credential and maps the client's own message to a class: only a host that answered
without a usable key is `host_key_unavailable`; a silent, unreachable or refusing host is
`timeout`, `unreachable` or `connection_refused`. Change the pin only for `host_key_mismatch`.
The class comes from the closing message of the SSH client; a device's pre-login banner, which the
client prints before it, cannot change the class.

### Triage read failures and schema availability

`triage_health`, `triage_routing`, `triage_flow`, `triage_vpn`, `wifi_triage` and `triage_slb`
return a structured result (not the JSON-RPC error `-32603`; at the HTTPS endpoint it is a tool
error, `isError: true`, like every Helper result with `ok:false`) with `ok:false`, `error_code`,
`failed_step:"system_status"`, `missing` and `verdict:"incomplete"` when the identity read
fails; an SSH connection failure names its transport class in `error_code` (the classes of
[normalized reads](#transport-classes)) with the fixed advice of that class in `error`, a
timeout uses `timeout`, and a local refusal before any connection keeps `ssh_unavailable`. An unqualified
identity returns `config_platform_not_supported` at `system_status`; `triage_slb` also
returns `device_cli_error` for a refused identity read and `product_identity` for an
identity it cannot parse. Nothing after the identity is read. A later SSH connection failure or timeout
keeps `ok` as before and adds `error_code` and `failed_step`; partial facts and `missing`
remain available. A step that failed in the transport is in `missing` with `reason`
`transport_error` (or `timeout`), its class in `error_code` and the advice in `error`.
Disabled or refused optional reads stay in `missing` (`permission_denied`,
`device_cli_error`) without `error_code`; empty, truncated and unparsed steps retain their
documented reasons. No raw SSH exception is included.

`fortios_diagnostics` (FortiOS recipes and every FortiADC recipe, including the log, session and
persistence reads), `config_read` and `schema_read` return the same structured failure when the SSH transport
fails: `ok: false`, `target`, the recipe, section or query, the class in `error_code` and its advice in
`error`, instead of the JSON-RPC error `-32603`. A diagnostic returns it only when no diagnostic
state was left behind or its restoration was verified; otherwise the restoration error names the
check. The per-call audit `detail` holds the same class.

Every triage result, also a failed one, carries `vantage`: `kind` (`device_cli_read`, for
`triage_flow` `device_cli_lookup`), `device` (the target alias), `packets_sent: false`, and
`sees` and `does_not_see`, which say that the facts are what the target's CLI reports about
itself. A triage sends no probe packet: whether a client's new connections pass a virtual
server, a route or a tunnel needs a test from that client. The quick probes say
`vantage: "helper_host"` instead. The short form of `wifi_triage` (`summary=true`) leaves
`vantage` out, like the sources.

Without `NETOPS_SCHEMA_REGISTRY`, `schema_read` returns `ok:false`,
`error_code:unsupported`, `reason:schema_registry_missing` before any device contact.
Install a verified server-side registry to use this tool.

`tls_probe` keeps `ok:false` after a verification failure. It then attempts one
additional TLS 1.2+ handshake to the same allowed address and port, without HTTP
or credentials, to obtain **unverified** certificate diagnostics. The result has
`certificate_verified:false` and the diagnostics only under `unverified_certificate`:
`source`, `certificate_sha256` (DER SHA-256), `subject` and `issuer` (RFC 4514
strings), `san`, `not_before`, `not_after` (ISO 8601 UTC) and `pin_match`. The
verified result (`ok:true`) has the same names at the top level, with `subject` and
`issuer` as lists of objects. `pin_match` compares the observed certificate with the
target's `fortios_rest_certificate_sha256` and is only computed on the enrolled
`fortios_rest_port` with the target's own name as server name; for another port
or `server_name`, or without a pin,
it is null. `tls_probe` defaults to port 443; when REST uses 8443, pass `port=8443` explicitly. A matching pin does not change the chain/hostname verification result.
If the diagnostic handshake also fails, `certificate_details_error` reports that
details are unavailable.

`wifi_rogue(target, limit=100, min_signal=null, offset=0, max_bytes=16000, mac=None, ap=None, full=false)` bounds the shared neighbor page
(1–500 rows across both lists) and filters by minimum signal (-150–0 dBm). `counts` reports total,
matched and returned rows per list. Each list is ordered by the strongest signal
first (a row without a valid signal last), then by MAC.
Wi-Fi REST times, units and PHY fields are described in [Wi-Fi REST](../../../docs/fortios-wifi-rest.md#normalized-wi-fi-data).

Invalid Wi-Fi selectors return a tool error result containing `code: -32602` with `data.field` and `data.hint`.
`ssh_read`, `switch_read` and `locate_endpoint` do the same: `data.field` names the
argument (`target`, `platform`, `query`, `parameters`, `offset`, `max_bytes`,
`content_sha256`, `table`, `vlan_id`, `mac`, `ip`, `interface`, `targets` or `endpoint`) and
`data.hint` its rule, never the refused value. Their `inputSchema` publishes the
limits a client can check before the call: `ssh_read` `max_bytes` 1000–48000 and
`offset` 0–8000000, the `switch_read` `table` names as `enum`, and `locate_endpoint`
`targets` as 1–64 distinct aliases (`minItems`, `maxItems`, `uniqueItems`),
`icmp_probe` `count` 1–8, and `fortios_diagnostics` the widest bounds of its recipes:
`count` 1–50, `timeout` 1–60 and `max_bytes` 1000–16384, with the bounds per recipe in
the property description. `fortios_diagnostics` then checks the bounds of the named recipe
and answers with a tool error result containing `code: -32602` with `data.field` (`count`, `timeout` or `max_bytes`) and a hint such
as `count is a whole number from 1 to 8 for recipe ping`: `session_list` and
`persistence_list` take `count` 1–50, `system_event_logs` and `waf_attack_logs` 1–20,
FortiOS `traceroute` 1–3 and the other FortiOS recipes 1–8, FortiADC
`health_check_verify` 1–5 and the other FortiADC recipes exactly 3. The HTTPS
endpoint checks these limits first and names the field and the published limit in
`data.hint`, for example `max_bytes is at least 1000, as shown by tools/list`.
`wifi_triage` requires exactly one of `mac`/`ip`/`name`; MACs use lower-case
`aa:bb:cc:dd:ee:ff`. Missing prompt arguments also return a tool error result containing `code: -32602` before
rendering, without a render traceback. Prompts contain a short shared introduction
and only their selected scenario; Internet/VPN starts with `triage_routing`,
slow-network troubleshooting with `triage_health`, and Wi-Fi names REST
`wifi_clients` separately from the SSH query of the same name. Enrollment warnings
for refused SSH Wi-Fi queries explicitly name that REST alternative.

SSH AP status does not supply a timezone for its join wall clock. Its normalized
`join_time` is null with `join_time_note`; use REST `wifi_aps_live` for the exact
UTC value. Wireless events require a device offset or `eventtime` epoch; without
either, only that record is left out and counted (`undated` in the parsed result,
`undated_records` in the `wifi_triage` events window) rather than assigned the Helper
timezone; the other records stay usable.

## Normalized tables (switch_read)

`table="interface_errors"` returns `port`, `rx_errors`, `crc`, `tx_errors`,
`discards_in`, `discards_out`, `last_flap`, `link_flaps` and `carrier_transitions`.
Counters are cumulative since the device last cleared them, not rates or errors
in the last polling interval. Missing source fields are `null`, never inferred
zeroes or sums. `interface` selects one port; other table filters do not apply.
On Junos it is required and must be enrolled in `read_inventory.interfaces`.

| Profile | Catalogue sources | Scope |
|---|---|---|
| Cisco IOS / IOS XE errors | `interfaces_counters_errors`; on unsupported, denied or empty output, `interfaces_details` (`show interfaces`) | Both read all ports; `interface` is a local filter; fallback needs its own enabled query |
| NX-OS | `interfaces_counters_errors` | Existing singular `show interface counters errors`; discard columns where printed |
| Arista EOS errors | `interfaces_counters_errors`, plus `interfaces_counters_discards` when enabled | Joined by normalized port |
| EXOS | `ports_rx_errors`, `ports_tx_errors` | Joined CRC and TX Errors; no aggregate RX total in these sources |
| Junos / ELS | `interface_details` | Extensive errors, drops, Last flapped, Carrier transitions, receive CRC/Align |

Each source requires its own existing `enabled_queries` authorization; slotted
reads retain inventory checks. Missing EXOS TX authorization makes coverage
incomplete. Optional EOS discards without authorization stay `null`, with
`discards_query_not_enabled`. Partial/failed reads retain their source statuses.
IOS syntax/view refusals cannot distinguish an unsupported image from a command
hidden by the view. The authorized `show interfaces` fallback retains the failed
counter source and `counters_unavailable_used_interfaces_details` warning. It
extracts input errors, CRC, output errors, input queue drops and total output
drops where printed. Last input/output and interface resets are not flaps;
unknown values stay null. Empty counter output or a filter with no ports has
`ok: false`, `coverage.complete: false`. Transport failures, truncation and
unrecognized counter output do not trigger a retry. EXOS/EOS joins and possible
IOS/XE fallback reserve two read slots, including requests without `interface`.


`switch_read(target, table, vlan_id=None, mac=None, ip=None, limit=100, offset=0, max_bytes=16000, interface=None, managed_switch=None)` uses the target SSH profile,
existing fixed query templates, the same device account and enabled-query policy
as `ssh_read`. It verifies the live OS before every read (never cached), unifies CRLF
line ends and redacts before parsing (see [SSH read pages](#ssh-read-pages-ssh_read-schema_read)) and
returns the identity envelope fields `schema_version`, `profile`, `captured_at`,
`status`, `sources` (query/hash/status), `coverage` and `warnings`, plus `table`,
`records` and `unparsed` (line number and redacted text). Identity is null for a
table response; no identity fields are inferred from unrelated output.

| table | Record fields |
|---|---|
| interface | name, description, admin_status, oper_status, speed, vlan_id, trunk |
| port_vlan | port, mode, access_vlan, native_vlan, tagged_vlans (integer list), oper_status |
| vlan | vlan_id, name, ports |
| mac_entry | mac, vlan_id, port, type, vlan_name |
| neighbor_l3 | ip, mac, interface, vlan_id, vrf |
| lldp_neighbor | local_port, neighbor, neighbor_port, management_ip, capabilities |
| route | prefix, next_hop, interface, protocol, vrf |
| ospf_neighbor | neighbor_id, address, interface, state, role, vrf |
| bgp_peer | neighbor, remote_as, state, prefixes, vrf |
| lag | name, protocol, status, members (`[{port, state}]`) |
| stp_port | instance, port, role, state, cost |
| aggregate | name, member_count |
| ip_interface | interface, ip, prefix_length, vlan_id, admin_status, oper_status, vrf |

`port_vlan` accepts an optional local `interface` filter (short and canonical port
names compare equally). IOS/IOS XE/NX-OS/EOS combine `interfaces_trunk` with
`interfaces`; Junos ELS uses `ethernet_switching_interfaces`; EXOS uses the new
slot-free `vlan_detail` (`show vlan detail`) and, when enabled, `ports` for link
state. Every source needs its existing per-target `enabled_queries` permission;
no role or device permission is added. Missing secondary reads leave incomplete
coverage. Unknown lines from either capture survive filtering and paging.
For a trunk allowing the entire VLAN space, use `max_bytes=48000`: its expanded
integer list can exceed the default 16000-byte page, and a record is indivisible.
IOS/IOS XE `vlan` also joins enabled `interfaces_trunk` so a trunk-only VLAN has
member ports; without that read an otherwise empty `ports` is null with
`trunk_vlan_join_not_enabled`, never evidence of no ports.

Endpoint findings include `vlan_membership: {carries_vlan, tagging}` from the
enabled `port_vlan` reads: `tagged`, `untagged`, or `missing`; a known nonmember
has `carries_vlan=false` and `tagging=null`. On standalone switches, disabled
optional membership reads leave `carries_vlan=null, tagging="missing"` without changing the existing
MAC/LLDP location verdict. Failed enabled reads remain in `missing`. FortiLink
managed ports require an enrolled `managed_switch` serial and both enabled queries
`managed_switch_port_vlans` and `interface_vlan_ids`. Their numeric VLAN membership
is marked `source: configuration`; it describes configuration, not forwarding state.
Without those queries, locate reports `configured_vlan_reads_not_enabled`,
missing membership and incomplete coverage/verdict for the managed-switch edge.

MAC and port comparison keys use the shared normalizer; Junos logical units
remain distinct. Speed retains the vendor unit/auto-negotiation spelling.
Absent fields are null, not inferred from a hostname, VLAN name, or link state.
`coverage.missing_fields` and warnings expose absent columns. A recognized empty
table is `empty`; any unknown line makes status `unparsed`, even if locally
filtering records yields no match. Parse status and field coverage are separate:
a correctly parsed summary can have `status=ok` and incomplete field coverage.
Raw CLI error, pagination and transport states remain failures.

CLI classification follows 1.0.6 (`1fad86c`): device patterns search for refusal
lines anywhere in the complete output, for all profiles and all read paths.
`permission_denied`, `unsupported` and `not_applicable` are independent of the
optional `command` metadata. Existing refusal checks in identity reads, schema snapshots,
diagnostic shell answers/navigation and sequential reads use the same patterns.
Recipes that previously only parsed identity without checking refusal lines
retain that behavior.

The narrow table exception applies in `normalized_query`, `switch_read` and
`locate_endpoint` only to `permission_denied`, `unsupported` and `not_applicable`
when the parser returns data rows. It never overrides `transport_error` or a
nonzero rc that would fail without the refusal-like line (including EXOS 250
with an error marker). The parser treats that line as ordinary unknown data:
status is `unparsed` when unknown lines remain, otherwise `ok`. Coverage is
incomplete and `coverage.warnings` and `warnings` contain
`refusal_like_line_in_data`, without the line text. Unknown lines remain in
`unparsed`. Parsing precedes local filters and pagination; even a page or filter
returning no records retains the capture warning. The Junos ELS MAC/VLAN join
also retains warnings and unknown lines from `vlans`. `locate_endpoint` checks
read status and `refusal_like_line_in_data` rather than catalogue-only
`coverage.complete` gaps. The warning is reported in `missing` even at status
`unparsed`; it prevents `not_found_in_checked_data` and a confirmed MAC/LLDP/LAG
edge. See [Endpoint location](#endpoint-location-locate_endpoint). With no parsed rows,
the original refusal/rc status remains. Capture limits, terminal pagers and
timeouts take precedence. Identity checks and raw `ssh_read` have no table exception.

The ReDoS fixes bound Wi-Fi key/value whitespace, Junos LACP/route age,
EOS/Junos LLDP, CLI diagnostic/pager matching and multiline refusal whitespace
(`^[^\S\n]*` keeps leading whitespace on its own line). A pager at the end of the
capture is `truncated`, including one appended to the final data line without a
newline, as in `1fad86c`. A standalone final prompt may have trailing blank lines. An appended marker followed by a newline, or any marker followed by later data, is not a terminal pager. The historical classifier matrix covers 1023 texts (1012 earlier texts plus five live OSPF, four FortiGate-local and two NX-OS port VLAN captures):
all real captures, FortiGate-80F files and HA responses, FortiADC export, Ruckus
transcript, identity, documentation and table fixtures. It checks all 11 profiles
plus no profile at rc 0/1/250, with three `command` variants. Linux has no native
capture; every text is nevertheless classified under that profile.

Refusal detection matches `1fad86c` on every capture. The retained pager rule
necessarily changes two complete Junos ELS logs (`log_messages` and
`log_interactive_commands`): `truncated` → `ok` at rc 0, and to `transport_error`
at rc 1/250, except EXOS rc 250 which is `ok` under its historical success rule.
These 72 raw status differences are separate from the parsed-table exception.
Raw `ssh_read` already removed this Junos artifact before classification; the
product correction now also removes its standalone line and following blank
erasure line before limiting logs, returning all 200 messages with
`line_limit.truncated: false` instead of 198 and a false `log_line_limit` warning.
Table tests reproduce an IOS LLDP description containing `% Permission denied`
and check real refusal shapes on every profile.

| Profile | Interface | VLAN / MAC | ARP / ND | LLDP | Route |
|---|---|---|---|---|---|
| EXOS | `ports` (display string as description, speed, `trunk` = more than one VLAN); VLAN tag absent | summary VLAN lacks ports (tag 4095 of `Mgmt` included); FDB with VLAN name and tag | yes, with VR | `lldp_neighbors_detail`: capabilities and management address when the neighbour sends them | `route_table` (whole table); `ip` narrows it locally to the longest prefix; IPv6 unsupported |
| IOS / IOS XE | status, name, speed, VLAN/trunk; admin may be absent | yes; CPU and SVI rows are not hosts | yes | detail | `route_table` (whole table without `ip`); `route_lookup` with `ip`, with whole-table fallback on empty IPv4 lookup |
| NX-OS | status | yes (`Legend:`, vPC peer-link) | yes | detail (`lldp_neighbors`) | existing address lookup, or the whole default-VRF table (`route_table`) |
| EOS | status | yes (Cpu is no port, PEt is the MLAG peer) | yes | `lldp_neighbors_detail`: capabilities and management address when the neighbour sends them | `route_table` (whole table without `ip`); `route_lookup` with `ip` |
| Junos (common catalogue) | terse incl. pseudo interfaces; description/speed/VLAN absent | unsupported by common catalogue | yes (`no-resolve` layout, flags such as `permanent published`) | detail (`lldp_neighbors_detail`: capabilities, management address) | existing address lookup (`detail` layout) or every routing table (`route_table`, VRF = routing instance) |
| Junos ELS | terse | yes (any release layout: Age, GBP Tag, NH Index columns); MAC VLAN name may lack numeric tag | yes | detail | as the common catalogue |
| FortiOS | FortiSwitch `managed_switch_port_stats` (serial required) | FortiSwitch MAC via `managed_switch_mac`; VLAN table unsupported | `arp_table` (`get system arp`), `ipv6_neighbors` | FortiSwitch summary via `managed_switch_lldp` (no management IP) | `route_lookup` with enrolled IPv4 `ip`, `routing_table` without `ip` |

For FortiOS `mac_entry`, `lldp_neighbor`, `interface`, `interface_errors` and `port_vlan`, supply `managed_switch`, for example

```python
switch_read(target="gateway", table="mac_entry", managed_switch="S000SSSS00000001", vlan_id="100")
```

The serial must be in the target's `read_inventory.managed_switches`; the target
must enable `managed_switch_mac` or `managed_switch_lldp`, respectively. Both the
proxy and worker enforce the existing catalogue slot and inventory policy, as for
`locate_endpoint`. The MAC/LLDP queries retain their existing permissions. The response echoes the
selected `managed_switch`; each page reads only that serial with the fixed catalogue
command. Missing serials and selectors on other tables/profiles are invalid arguments;
unlisted serials and disabled queries are refused before any device read.
MAC/VLAN filters and pagination work as for other profiles.

Enable `managed_switch_port_stats` for link state/speed (`interface`) and
cumulative RX/TX errors and drops (`interface_errors`). Both tables accept an
optional `interface="port3"` that must be enrolled under `managed_switch_ports`;
without it they read all ports of that serial. Unreported CRC/flap counters stay null.
For `port_vlan`, enable both `managed_switch_port_vlans` and `interface_vlan_ids`:
the two fixed `show` reads resolve configured `vlan`, `allowed-vlans` and
`untagged-vlans` names to numeric IDs. Results carry `source: configuration`,
including `locate_endpoint` VLAN findings; this shows configured carriage, not
forwarding state. A refused configuration read is `unsupported` with a reason.
`interface` filters `port_vlan` locally. Its `oper_status` remains null; location
reads actual link state separately. These RO outputs were captured on 2026-11-10
and replayed in parser/proxy/worker tests. Unsupported FortiOS tables return
`status: unsupported` with `data.field: table` and `data.supported_tables`,
without device contact.

The two FortiSwitch configuration queries expose a local projection of the VLAN fields also through `ssh_read`; unrelated fields are omitted, malformed configuration lines are reported by line number without their values, and source hashes describe this projected, redacted text.
The read-only captures of FortiGate 80F, FortiOS 8.0.2 build0251 (2026-11-09) include
MAC flags/trunks and the `Portname Status Device-name ... Port-ID` LLDP summary;
empty LLDP slots produce no neighbour. LLDP capabilities use canonical comma-separated
codes (`B,W,R,S`); the summary has no management address, so `management_ip` is null
and coverage reports that missing field. FortiSwitch firmware was not captured.


`ip_interface` has one record per IPv4 address an interface carries (an interface without an address is no record;
its state is in `interface`). `prefix_length` is a number, `vlan_id` the VLAN of an SVI (`Vlan10`, Junos `irb.10`,
the EXOS VLAN), never derived from a subinterface number such as `Gi0/1.10`, whose dot1Q tag the output does not
print. `admin_status` and `oper_status` are `up`/`down`; a value the output does not print stays null.

| Profile | Source of `ip_interface` | What it gives |
|---|---|---|
| IOS / IOS XE | `ip_interfaces` (`show ip interface brief`) + `route_table` | address, Status (administratively down → admin down) and Protocol (oper); the brief output has no mask, so `prefix_length` comes from the connected route (`C`) of the same interface that contains the address; without that route (interface down) or without `route_table` in `enabled_queries` it stays null (warning `route_table_join_not_enabled`) |
| NX-OS | `ip_interfaces` + `route_table` | as IOS (`direct` route), `admin-`/`protocol-` state and `vrf` from the VRF heading |
| EOS | `ip_interfaces` | address with prefix length, Status (`admin down` → admin down) and Protocol |
| EXOS | `ipconfig` (`show ipconfig`) + `vlan_summary` | the routed VLANs with address and mask, flag `E` (enabled) and `U` (up); `vlan_id` is the tag of the VLAN of the same name from `vlan_summary` (warning `vlan_summary_join_not_enabled` without it) |
| Junos, Junos ELS | `interfaces` (`show interfaces terse`) | every `inet` address of a logical interface, continuation lines included; an address printed without a mask (`lo0.0`) keeps `prefix_length` null; `inet6` is not part of this table |
| FortiOS | `system_interfaces` (`get system interface`) | every interface with an address other than `0.0.0.0`, mask as prefix length; `status` is the configured state (`admin_status`), the output has no link state and no VLAN ID, so `oper_status` and `vlan_id` stay null |

The optional `interface` argument filters `ip_interface` by interface name (one name of letters, digits and
`_.:/-`, compared after the shared port normalization, so `Gi0/1.10` selects `GigabitEthernet0/1.10`); it applies to
no other table. The second read (`route_table`, `vlan_summary`) runs only when it is in the target's
`enabled_queries`; its source, a failure, unknown lines and warnings appear in the same envelope, as for the
Junos ELS MAC/VLAN join. An IOS or IOS XE target that declares `device_types` `router` without `switch` reads the
`interface` table from `ip_interfaces` instead of `show interfaces status`, which a router image refuses: name,
`admin_status` and `oper_status` only (`speed`, `vlan_id` and `trunk` stay null and are listed in
`coverage.missing_fields`).

`aggregate` exists for EXOS only (`lacp`: `show lacp`): the LAG master ports, which the EXOS FDB prints like
physical ports. `locate_endpoint` prefers enabled `lag_summary` (`show sharing`) on EXOS vantages,
which identifies both LACP and static master ports as transit. Without that permission it reads
`aggregate` to identify LACP transit ports, but cannot rule out static aggregation: an edge is not
promised (`aggregation_not_verified`). A failed or unparsed sharing read also leaves the edge unverified.

`capabilities` is one canonical string of the IEEE 802.1AB letters `O P B W R T C S`
("B,W" = bridge and WLAN AP), whatever spelling the OS prints. `coverage.missing_fields`
lists a field only when no row supplies it; a value that is empty in some rows (a port without
description, a link-down speed) is normal.

The rows are OS profiles; a switch, router or firewall running the same OS uses
the same row, and a table or command the box does not provide is reported as
`unsupported`. The L2 tables (`vlan`, `mac_entry`, `lldp_neighbor`) and routing
tables (`neighbor_l3`, `route`) are bound to catalogue templates only. A template
that carries a group is usable on a target only when its `device_types` declares
that type; templates without a group (all current ones) serve any type. No
permission or firmware support is implied by this table. Fixtures and their
[manufacturer sources](../tests/fixtures/tables/README.md) qualify selected text
layouts offline. Other layouts are retained in `unparsed` rather than discarded.

`vlan_id` is a decimal string 1–4094, `mac` is a strict MAC literal and `ip` is an
IPv4/IPv6 literal (no hostname, prefix, zone, whitespace or CLI metacharacters).
Filters run locally over the classified full capture. `neighbor_l3` selects
ARP by default, ND when `ip` is IPv6. `route` with `ip` uses the catalogue lookup (that address must
also be enrolled under `addresses` because the lookup slot requires it) or, on EXOS, narrows the
whole table locally; `route` without `ip` returns the whole routing table where the profile has a plain
table template (`route_table` on IOS, IOS XE, NX-OS, EOS, Junos and EXOS; `routing_table` on FortiOS). Elsewhere a missing `ip` returns a tool error result containing `code: -32602` with `data.field: "ip"`.
`ospf_neighbor`, `bgp_peer`, `lag` and `stp_port` exist for IOS, IOS XE, NX-OS and EOS (`ospf_neighbors`,
`bgp_summary`, `lag_summary`/`port-channel dense`, `stp_tree`) and for Junos (`ospf_neighbors`, `bgp_summary`,
`lacp_interfaces`; `stp_interfaces` on ELS only; the Junos spanning-tree `instance` is the instance number, `0` for RSTP/CIST); a
protocol that is not configured (`% BGP not active`, `% BGP inactive`, `! IPv6 routing not enabled`, Junos `BGP is not running`,
`Spanning-tree is not enabled at global level` and `warning: lacp subsystem not running - not needed by configuration.`) is
`not_applicable`, a valid response with `ok: true` and MCP `isError: false`. Triage tools retain it as missing evidence and an `incomplete` verdict when the protocol is required; it does not mean a healthy protocol. On NX-OS a feature that is off answers
`Syntax error while parsing`, which is `unsupported`. IOS and IOS XE answer a command outside the account's view and a
command the image does not have (on a router image `interface`, `vlan`, `mac_entry` and `lag`) with the same
`Line has invalid autocommand "..."` or `% Invalid input` line, so such a read stays `permission_denied` and carries
`hint`: `The command was refused by the account or does not exist on this image (for example a router image without switching commands)`.
Check the image before the account's rights. OSPF neighbour `state` uses lowercase canonical names (`full`, `2way`,
`exstart`, etc.); EOS `2 WAYS`, NX-OS `TWOWAY` and Junos `2Way` become `2way`. Junos `role` is
absent (the summary prints no DR role).
`state` of an OSPF neighbour is the part before `/` (`full`, `2way`) and `role` the part after it (`DR`,
`BDR`, `DROTHER`, none on point-to-point links); a BGP `state` is `Established` for a numeric IOS
`State/PfxRcd` and `prefixes` holds that number; `stp_port` role and state are spelled out
(`designated`/`root`/`alternate`/`backup`, `forwarding`/`blocking`/`learning`/`discarding`) whatever
the OS abbreviates.
The shared [value names](normalization.md#operational-value-names) also apply to route protocols, BGP states and LACP protocols.
A route filter selects its containing route, not a fictitious per-record IP field.
For ELS MAC records, an enabled `vlans` query joins observed names to numeric tags; this additional source and any failure appear in the same envelope. No arbitrary query name or command is accepted by this interface.
One call consumes one request of the target `rate_limit`, two for an ELS `mac_entry` with the `vlans` join and for an
`ip_interface` whose second read (`route_table` or `vlan_summary`) is enabled.

## Endpoint location (locate_endpoint)

Example: `locate_endpoint(targets=["lab-gateway", "lab-access"], endpoint="192.0.2.10")`.
The caller supplies 1–64 distinct, already enrolled target aliases and exactly one
strict IP/MAC literal. No inventory scan, DNS endpoint lookup, neighbor-driven
connection, VLAN change, packet generation or new command is performed.
The proxy authorizes all aliases before injecting their authentication over the
private worker pipe; clients cannot provide authentication contexts.

Reads of different devices run concurrently (at most eight), with one SSH connection per device at a time, including aliases sharing an address/port; tables on the same device stay sequential and every read retains catalogue authorization and mandatory audit. The shared deadline is 59.5 seconds from the parent call, including worker startup, leaving cleanup within the 60-second boundary, and 40 physical CLI reads for up to eight aliases or eight reads per alias for larger scopes (at most 64 aliases, including managed-switch vantage slots). MAC correlation starts as soon as an enrolled cache resolves the IP, while the remaining ARP/ND readers continue in parallel; one slow cache cannot hold up a fast edge. After all ARP/ND readers finish, any later resolved MAC is also correlated against every saved MAC capture, reusing auxiliary captures. Transport reads use the remaining time. The per-alias physical read caps are exposed as `limits.target_reads`. The result retains all collected findings with the existing edge/transit/own-interface rules; a missed deadline or read limit returns `incomplete` (or an already established ownership/ambiguity verdict), with `coverage.complete`, `requested_targets`, `completed_targets`, `unfinished_targets` and target-specific `missing` reasons, so partial coverage never claims a fully located edge.

Readers are chosen by the inventory attribute `device_types`, never by the SSH
profile. For an IP the tool reads the enabled ARP or ND cache of its address family
(`arp_table`, `ipv6_neighbors`) from targets declaring `router` or `firewall`; a MAC
starts without a cache lookup. It reads every enabled MAC table (`mac_table`) from
targets declaring `switch`. If a MAC has no confirmed edge and only transit findings
(or no switch reader), it then checks enabled IPv4 ARP caches for an enrolled
interface owner within the same budget.
A layer-3 switch declares `["switch", "router"]`. The proxy refuses the whole call with
`policy_scope` when any named target is no reader at all (no declared type, or none of
its types has the matching enabled query); the error data carries `target`, the alias that
failed the check, so the inventory entry to fix is named. A worker started without that proxy check reports such a target
as `device_type_not_declared` and does not read it. Among reader targets, one whose
type does not match a table is simply skipped, and a missing reader kind is reported as
`no_enrolled_l3_reader` or `no_enrolled_switch_reader`. FortiGate
(`firewall`) uses its existing ARP/ND queries;
FortiLink switches use `managed_switch_mac` and `managed_switch_lldp` through a
`firewall` target, only for serials in `managed_switches`. A managed switch also consumes a target slot.
Targets past the 64-vantage limit are reported missing. Auxiliary reads follow each device’s MAC table only on
switches whose MAC table holds the MAC; a switch without it is a branch away from the
endpoint and costs its MAC table only. There LLDP is read first. On native switches, a port with an LLDP
switch neighbour is transit, so its `interface` stays null and its `vlan_membership`
`missing` (not read, no `missing` entry). Only when a matched port has no LLDP switch
neighbour do the EXOS, IOS/IOS XE, NX-OS, EOS and Junos profiles read the enabled
interface summary, `port_vlan` membership and, on EXOS, `show lacp`. The VLAN table is
read only to turn a VLAN name of the MAC table into its tag (Junos ELS), joined when
unambiguous. On FortiLink-managed switches a MAC on a FortiLink/ICL trunk is transit without further
reads, the switch's own MAC on its `internal` port is `own_interface_of_target`, port state is read only
on a switch with an edge candidate and the configured VLAN membership only once, for a confirmed edge
port; at about 5 s per FortiOS read (connection spacing), an AP behind one of two FortiSwitches takes
8 reads and about 45 of the 60 seconds. Every physical CLI read, including the
once-per-alias identity check, consumes the shared read budget. With all seven GNS3 lab
nodes enrolled (IOSv, IOSvL2, cEOS, EXOS-VM, NX-OS, vJunos, IOL XE; every switch also a
router, every locate query enabled), the offline replay of their read-only output needs
28 reads for either the router VLAN interface address or its MAC
(`own_interface_of_target`) and 25–28 for a host behind the NX-OS or vJunos access port (`located`);
the earlier read order stopped at 40 reads (`read_limit`). Each read keeps its
existing catalogue authorization and mandatory audit. Endpoint location reserves `min(40, helper.rate_limit.requests, 7 + exos + vlan_reads + managed_reads * managed_switches)` reads per alias. `exos` is 1 on EXOS, otherwise 0; `vlan_reads` is 1 when the profile's port-VLAN query is enabled, plus 1 on campus profiles (IOS/IOS XE/NX-OS/EOS) or EXOS for its join. `managed_reads` is 2 (MAC/LLDP), plus 1 with FortiOS `managed_switch_port_stats`, plus 2 when both `managed_switch_port_vlans` and `interface_vlan_ids` are enabled. The worker caps actual reads per alias at that reservation, including identity and joins; exhaustion returns incomplete coverage with `target_read_limit`. The reservation permits a call to start under the default 30-request limit, but does not guarantee completion. FortiOS connection starts on one FortiGate are at least 5 seconds apart; at the observed roughly 5.6 seconds per read, about ten reads fit the 59.5-second deadline. An IP lookup with all edge queries needs at least N + 6 reads for N managed switches when only one switch needs edge details: roughly four switches can complete under these conditions. Larger sites, including twelve or thirty switches, return partial findings with incomplete coverage when the deadline or read limit is reached; startup time, latency and additional matched switches can reduce this capacity. Unused reservations are not refunded: a reservation of 30 blocks subsequent calls to that alias for the rest of its 60-second rate window, even if fewer reads run. Each alias uses its own total `rate_limit`, without the triage sublimit; if any alias lacks the reservation the whole call is refused with `rate_limit` and no alias is charged.

An LLDP neighbour is a *switch* when it is an enrolled target (alias or management
address) or advertises bridge/router capability. A neighbour that advertises no capabilities
(EXOS sends neither capabilities nor a management address) is an enrolled target too when its
system name equals the host name of another enrolled target already read in this call, compared
without case and without a domain: the host name of the identity check (`show version`), on EXOS
and EOS the identity supplement `switch` (sysName of `show switch`) or `hostname` when that query is
enabled, read once per such target and counted against the budget (it fits the existing per-alias
reservation). Two enrolled EXOS in a row then give `transit` on the link and `located` at the edge of
the other switch. The LLDP chassis ID is not part of the table and is not compared. A neighbour with telephone (T) or
WLAN AP (W) capability and no router capability is a *phone* or *ap*; a WLAN AP that is also a
station (FortiAP advertises `B,W,R,S`) or whose system name starts with FortiAP/FAP is an *ap* too. An aggregate,
trunk, known uplink/peer-link description or switch neighbor is transit, except that a
port with a phone or AP is the edge as far as the switch can see
(`role: edge_behind_phone` / `edge_behind_ap`, `behind` names it). A MAC seen only on
transit ports without evidence of an enrolled interface owner is never "not found":
the verdict is `incomplete` with
`{"table": "edge", "reason": "edge_beyond_enrolled_targets", "port": ...}`, because the
endpoint sits behind a switch that is not enrolled. Unknown LLDP capabilities of a neighbour
that is no enrolled target, or unreadable MAC/LLDP/LAG prevent a confirmed edge. An empty readable LLDP table is normal for an endpoint.
A read is complete for correlation when its status is `ok` or `empty` and neither
`coverage.warnings` nor `warnings` contains `refusal_like_line_in_data`.
Other statuses (including `unparsed`, refusal and transport errors) add their status
to `missing`. The protection warning always adds its own reason to `missing`,
even together with `unparsed`; it prevents a definitive `not_found_in_checked_data`
and prevents a confirmed edge when it affects MAC/LLDP/LAG evidence.
An incomplete read of any table, including auxiliary interface/VLAN summaries,
makes the verdict `incomplete` unless multiple MACs/edges make it `ambiguous`
or a successful read directly establishes an enrolled interface owner. Ownership
is reported as `own_interface_of_target` with `own_interfaces` (target, interface,
IP, MAC and source table). Several owners on different targets remain ambiguous;
several interfaces of the same target can share a MAC. Ownership uses explicit
local/interface ARP evidence or matching addresses already read from interface
tables; when nothing located the endpoint, the enabled `ip_interface` read of each target that
no complete ARP cache rules out (IOS/IOS XE list their own addresses there; a cache holding the endpoint
learned it) finds EOS, NX-OS, Junos, EXOS and FortiOS addresses, for a MAC those its ARP entries resolve to. Transit findings are preserved without `edge_beyond_enrolled_targets`;
failures of other reads remain visible in `missing`.

Catalogue field gaps (`coverage.complete: false`, `missing_fields` or
`fields_absent_in_catalogue_output`) alone do not make a read incomplete for
correlation. Decisions use the observed MAC/port and existing LLDP capability
rules; absent unrelated fields such as LLDP management IP do not block an edge.
Interface/VLAN field gaps alone also do not block it. A missing VLAN tag on a
matched finding is still reported as `vlan_id_absent`. EXOS, IOS router IP
lookups, FortiLink and Junos ELS with a successful VLAN join can therefore return
`located` despite unrelated catalogue gaps. Unsupported layouts are explicit;
LLDP advertisements remain
untrusted observations. The tool cannot detect a silent downstream switch from
an empty LLDP table alone and makes no claim about connectivity or health.

Results include `verdict` (`located`, `own_interface_of_target`, `ambiguous`, `incomplete`,
`not_found_in_checked_data`), `findings`, `missing`, ARP/ND observations,
`vantage` (target/profile/table/time/source hash/status), actual `reads` and limits.
A candidate edge can remain useful with `incomplete`; multiple edges or multiple
MACs for an IP remain ambiguous. The wall deadline is enforced by an isolated
worker; on expiration the last completed evidence is returned and SIGTERM
unwinds SSH cleanup (up to two seconds for cleanup, then forced termination).
No device reads continue in a background thread.


## Bounded table and REST results

`switch_read`, `wifi_clients`, `wifi_aps_live` and `wifi_rogue` accept `limit`
(default 100, 1–500 records), `offset` (default 0, 0–8,000,000 records) and
`max_bytes` (default 16,000, 1,000–48,000 bytes). These bounds are published in
`inputSchema` and checked before device access; invalid bounds return a tool error result containing `code: -32602`
with `data.field`. The byte bound covers the JSON result serialized with ASCII
escapes, including metadata; the MCP text/structured copies stay below the IPC
cap. A record is indivisible: one record or metadata that cannot fit returns
`ok: false`, `error_code: result_too_large`, `failed_step`, and `next: null`.
Such an error has `has_more: false`; increase `max_bytes` or narrow the filter.

`page` reports `offset`, `limit`, `max_bytes`, `total`, `returned` and full list
`counts`; `coverage.returned` counts returned normalized records. `has_more`
means another page is available, and `next` is either null or the next `offset`, `limit`
and `max_bytes` arguments. Repeat the same tool, target, filters and summary
option with those arguments. `status: "truncated"` describes an incomplete
device capture independently of `has_more`: an incomplete capture can have
`has_more: false` when all captured rows fit on the page. These new 1.0.7 tools
use no top-level `truncated` paging flag; the existing 1.0.6 SSH page fields keep
their contract. Rows are ordered as `records` then `unparsed`
for switch tables and `rogue` then `interfering` for rogue observations; the
record budget is shared across these lists. No unparsed line disappears
silently. Capture classification and field coverage describe the full read,
not just the returned page. A page limit does not change a successful status.

Each page performs a fresh device read and consumes its normal rate budget;
these record pages are not cached SSH snapshots. Check source hashes and
restart at offset 0 if the table changes. Local filters, VLAN/AP joins, signal
sorting and the AP summary view run before paging. `wifi_triage` filters its
REST client evidence before selecting a client, so the public page limit
cannot hide a client beyond the first page. Rogue `counts` retain full totals
and signal-filtered matches and report the page's returned rows.

REST failure `error_code` distinguishes `tls_pin_mismatch`,
`tls_verification_failed`, `tls_error`, `authentication_failed` (401),
`authorization_failed` (403), `timeout`, `http_server_error` (5xx), `http_status`
(other non-200), `invalid_json`, `invalid_response` (nonfinite numbers),
`response_too_large`, `unsupported_encoding`, `unparsed_envelope`,
`configuration`, `rate_limited` and `egress_denied` from `transport_error`.
`failed_step` is the fixed GET endpoint and `http_status` is numeric when known.
The older coarse `error_subcode` remains available for triage compatibility.
No response body or raw exception text is returned.

`triage_flow` preserves session recipe refusals as `ok: false`,
`error_code: restore_unverified|scope_refused`, `failed_step: session`, an
`incomplete` verdict and the same reason in `missing` and `chain.session`.
`restore_unverified` instructs the operator to inspect `diagnose sys session
filter` and, if set, clear it with `diagnose sys session filter clear`.
`locate_endpoint` stops all further reads on audit persistence failure and
returns `audit_preflight_failed` or `audit_post_operation_failed`; a failed
worker returns `worker_failed` and a deadline returns `timeout`, all with
`ok: false` and a structured `failed_step`.

## Log result window

The Helper caps redacted log output at 200 device lines before caching and
byte pagination. EXOS (`extreme_exos`) `log_messages` and `log_warnings` keep
the leading, newest messages, cutting at a message boundary. IOS (`cisco_ios`),
IOS XE (`cisco_xe`), NX-OS (`cisco_nxos`), EOS (`arista_eos`), Junos
(`juniper_junos`) and ELS (`juniper_junos_els`) `log_messages` and
`log_interactive_commands`, where available, keep the last 200 lines because
the oldest messages come first. Some catalogue commands already limit the
window on the device. A Helper truncation adds one explanatory line outside
the 200 device lines. `ssh_read.line_limit` and the triage read's
`log_line_limit` report `max_lines`, `total_lines`, `returned_lines` and
`truncated`; byte continuation cannot recover older discarded lines.

IOS/IOS XE `show logging` reads the in-memory log buffer. Its logging
configuration summary is present only if it fits in the last 200 lines;
callers must not rely on that header being returned with a long buffer.
The catalogue description describes the device command; this result-window
rule describes the Helper response.


### Wi-Fi diagnostic evidence (1.0.7)

`wifi_clients(name="TabletExample")` and `wifi_triage(name="TabletExample")`
match exact case-insensitive hostname. Triage requires exactly one MAC, IPv4 or
hostname; ambiguous names are reported as missing identity. `wifi_events` is an
optional step: an enrolled REST token supplies the preferred bounded wireless
history GET filtered by canonical station MAC before its 200-row limit; otherwise an enrolled SSH display query remains available. A failed
history read does not discard live signal/AP observations.

Both triage views always include `chain.observation` with the client AP name,
radio/band/channel/width, RSSI/SNR, utilisation/retry, retrieval times, separate utilization age and unknown common measurement ages.
Findings carry explanatory `text` and configurable `helper.wifi_thresholds`.
`no_rf_fault_found` means RF evidence is complete with no triggered RF rule;
`incomplete` means deciding radio data (including noise and interference) is missing.
A missing background RF/neighbor scan alone does not block a verdict when
operating-radio measurements are complete; `chain.rf` names the REST fallback
source. Client history reports filtered totals, parsed/returned counts and
completeness. Neither verdict proves wired connectivity. AP
LLDP is context in the separate missing wired step. Summary includes coverage
and significant history events (failures, disconnects with reasons, AP changes,
last successful connection and last DHCP), while full detail retains the bounded client timeline and technical AP identities. Historical errors older than a successful
association at the last successful observation are notices, even if the final snapshot fails.

Link RX/TX Mbps are separate PHY rates, not throughput. Current source traffic
and retry/discard remain separate. `wifi_rogue` with `mac=…` and `ap=…` defaults to relevant
AP/band/channel-overlap observations with signal ≥−75 dBm; `full=true` requests
all grouped BSSIDs and their observations. Missing context is explicit; counts
retain source totals and deduplication is marked. See the complete [Wi-Fi REST
contract](../../../docs/fortios-wifi-rest.md#diagnostic-interpretation-in-107) for
thresholds, units, timestamps, overlap uncertainty and enrollment. REST calls
reserve three reads for clients, two for APs and four for relevant neighbors.


Name-selected Wi-Fi results carry `identity_trust: "client_supplied"`: DHCP/device
hostnames are not authenticated identity. `name` needs REST and, where needed,
User & Device identity permission. Identity read failures remain in `missing`;
MAC selection avoids dependence on hostname enrichment. Unicode control/format
characters are refused. Significant summary history is capped at 20 groups,
with repeated-event counts and explicit omitted totals; authentication failures
use bounded event-index references and a total. Reason/status auth detection is
heuristic without a measured bad-PSK fixture and is independent of disconnect
class. Summary omits source hashes; full detail retains them without the entire
managed AP row or duplicated recent events. Both views expose
`findings_max_severity` alongside `rf_verdict`, even for `client_not_associated`.
Triage requires an AP observer, matching band and channel overlap through
`wifi_relevance` before a neighbor finding; the current controller-wide SSH scan
is context only. Unknown own width retains exact primary-channel relevance and
reports `width_unknown`; failed rogue context reads retain fixed failure fields
and `context_read_failed`. SSH history advice appears only without REST history
and with enrolled `wifi_events`; otherwise enrollment advice uses `target_scope`.

REST-enrolled `wifi_triage` reads `rogue_ap` and `interfering_ap` once each,
reusing its already selected AP/radio context. Neighbor findings require a
matching detecting AP and the same band/channel overlap rules as `wifi_rogue`;
strength comes from the selected observer. Interfering observations join their
BSSID to rogue spectral facts; unmatched rows cannot establish RF relevance.
Without REST, `neighbors.relevance_status` is `observer_unavailable` and
`F-WIFI-STRONG-COCHANNEL-NEIGHBOR` does not run. SSH scan remains context only.
Full triage history uses `history_limit` (default 100, 1–500) and
`history_offset` (default 0, 0–8 000 000), returning `truncated`, `page`, `next`.
Its complete structured result is limited to 48 000 bytes; compact timeline
records add `source_sha256`. Each continuation rereads sources and costs the
normal 15-read reservation (seven CLI + eight REST) and takes about 30 seconds. The default rate limit of 30 reads per 60 seconds permits two pages per window; prefer `summary=true` when full history is unnecessary.

IOS / IOS XE IPv4 route lookups that return empty read the enabled `route_table` and select its longest matching prefix. The result has `source: longest_prefix_from_table` and retains both reads in `sources`; a missing permission or failed table read is reported instead of asserting that no route exists.

Failed normalized transport reads carry an allowlisted `error_code` (`unreachable`, `timeout`, `dns`, `connection_refused`, `host_key_unavailable`, `host_key_mismatch`, `negotiation`, `auth`, `auth_method_unsupported`, `disconnected`, `output_limit`, `exit_status` or `transport_failure`) and the fixed advice of that class in `error`, in the result and in locate `missing`, with the same class in per-read audit `detail`, without exception or device text; a host key that cannot be read is followed by one credential-free SSH probe, so a host that does not answer is `unreachable`, `timeout` or `connection_refused` and only a host that answered without a usable key is `host_key_unavailable`; an enrolled LLDP neighbor matched by alias, verified sysName/hostname or enrolled management address yields `endpoint_not_seen_on_neighbor_target` instead of `edge_beyond_enrolled_targets` when no endpoint edge is observed.

Device output drops ANSI escape sequences and C0 controls except newline and tab before hashing, paging and client delivery; other text is preserved subject to existing secret redaction.

FortiSwitch configured membership preserves `allowed-vlans-all enable`: it expands only VLANs whose interface configuration establishes the same FortiLink parent as the native VLAN. Missing parent context leaves membership unknown with `allowed_vlans_all_context_missing`. NX-OS direct and local routes have no IP next hop. Junos route detail and whole-table reads both return only the active route entry, retaining all its next hops.
