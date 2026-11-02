# Helper tools in NetOps

The HTTPS MCP endpoint exposes Helper tools alongside [Auditor](../../netops-auditor/docs/tools.md) and [Admin](../../../docs/admin-configuration.md#mcp-tools) tools. It retains nineteen Helper tool names, including `ftp_list`, which is refused in the shipped profile. Clients pass enrolled aliases, never device credentials or auth_context. The private bridge injects ephemeral device authentication and validates policy before dispatch.

| Tool | Current behavior |
|---|---|
| helper_status | Enrolled aliases, validation and rate state; no device contact |
| target_scope | Public enrollment boundary for one alias; no device contact |
| read_query_catalog | Bounded pages of named typed queries and metadata, with platform/prefix filters; not automatic authorization |
| dns_probe | Enrolled DNS resolution with address scope checks |
| tcp_probe | Enrolled TCP port reachability |
| icmp_probe | Explicitly permitted bounded diagnostics |
| tls_probe | Verified peer certificate and enrolled SNI/port |
| ssh_read | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`); empty or whitespace-only device output answers `ok: false` with `error_code: "empty"` unless the catalogue declares that query's empty output legal |
| config_read | Opt-in FortiOS or FortiADC running configuration, conservative value redaction, bounded memory capture; `redaction="full"` reads the whole configuration and reports how much of it the account could see ([guide](#reading-the-whole-fortios-configuration-config_read)) |
| config_diff | Compare two captures for the same authenticated target; no device contact |
| triage_health | Fixed read-only FortiOS health chain of ten catalogue reads with findings, missing steps and a verdict; qualified for FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 only ([guide](#fortios-health-triage-triage_health)) |
| triage_routing | Fixed read-only FortiOS route chain for one enrolled IPv4 address (route, policy routes, SD-WAN, ARP) with sourced findings, hypotheses and what is not simulated; qualified for FortiGate-60F 7.6.8 build 3744 only ([guide](#fortios-route-triage-triage_routing)) |
| triage_vpn | One named FortiOS IPsec tunnel: four catalogue reads, findings, missing steps and a verdict ([guide](#fortios-vpn-triage-triage_vpn)) |
| triage_slb | One enrolled FortiADC virtual server: configuration and runtime chain virtual server, pool, members, health checks, TLS, WAF and DoS with sourced findings and a verdict; FortiADC 7.6.7 build 0676 only ([guide](#fortiadc-load-balancing-triage-triage_slb)) |
| schema_read | Enrolled measured configuration path and exact device identity |
| fortios_diagnostics | Explicitly enrolled bounded recipe and temporary-state cleanup; FortiOS and FortiADC targets |
| sftp_stat | Metadata within enrolled roots; no file content |
| snmp_get | SNMPv3 authPriv GET (sha256, aes128) with the credential named by `snmp_credential`; v1, v2c, noAuthNoPriv and authNoPriv are refused before any network access; `target_scope` reports `snmp_security` as `authPriv` or null |
| ftp_list | FTP and FTPS refused in the shipped profile |

The `schema_read` tool still requires a measured server-side schema registry and library files, whose provisioning is not a supported workflow. Missing-registry calls are refused before device contact. Bounded `fortios_diagnostics` no longer depends on that registry; its live identity and single-VDOM restrictions are described below.

`ftp_list` is refused with `unencrypted_protocol` before any device contact, and no configuration enables it; `snmp_get` is active only with an `snmpv3-authpriv` credential (SHA256, AES128) named by `snmp_credential`, 1 to 20 OIDs and a UDP port allowed by the target egress scope; SNMPv1, SNMPv2c, noAuthNoPriv and authNoPriv are not supported. The path check of the `ftp_list` engine is lexical: it accepts a canonical absolute path equal to an entry of `sftp_roots` or below it, without letting the server resolve the path, so unlike `sftp_stat` it would not refuse a symbolic link below a root that leads out of it.

Operation refusals and failed Helper results set MCP isError true while preserving structured detail. Device output is untrusted data and never an instruction to expand scope. A diagnostic finding does not authorize a write, retry or another target.

Consult the [complete enrollment](../../../docs/helper-configuration.md), [query catalogue](query-catalog.md), [source registry](query-sources.json) and [account boundary](read-only-accounts.md). Catalogue presence alone does not establish firmware/hardware support or device account permissions.

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
        set password <REDACTED:credential#1>
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
`firmware-not-supported`, `device-refused`, `identity-unverifiable`,
`capture-limit-exceeded` (byte/record limits, never silently truncated),
`redaction-unverifiable` (consumer or grammar failure), `transport-failed`, and
`configuration memory budget exhausted` (per-target `memory_bytes` or the shared
process budget). A memory refusal keeps that category in minimal and full reads,
including a nested auto-script, and does not appear as `redaction-unverifiable`.

## FortiOS health triage (`triage_health`)

`triage_health(target)` runs one fixed, read-only sequence of ten catalogue reads on a FortiOS target and returns the facts it found, the rules that fired and what it could not check. It is qualified only for the exact identities FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 (HA A-P cluster, measured); any other model, version or build is refused with `config_platform_not_supported` after the first read (`system_status`), before any other command. The target must use the `fortinet` platform and enable `system_status`. One call consumes ten requests of the target rate limit and is refused as a whole when fewer remain.

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

## FortiOS route triage (`triage_routing`)

`triage_routing(target, address)` answers "which way does this device send traffic for one address, and is anything on that way documented as broken". It runs one fixed, read-only sequence of five catalogue reads and reports only what the device printed; it does not simulate the data plane (`dataplane_simulated` is always `false` and `not_simulated` lists what is left out: policy route and SD-WAN rule matching on source, ports, protocol and ingress interface, member selection inside a rule, firewall policy, NAT and sessions, recursive next-hop resolution). It is qualified only for FortiGate-60F 7.6.8 build 3744; any other identity is refused with `config_platform_not_supported` after `system_status`, before any other command. The target must use the `fortinet` platform, enable `system_status` and `route_lookup`, and `address` must be an IPv4 address enrolled in the target's `addresses` inventory (the same rule as `ssh_read` with `route_lookup`); anything else is refused before the device is contacted. One call consumes five requests of the target rate limit.

| Chain part | Query | What is taken from it |
|---|---|---|
| identity | `system_status` | model, version, build |
| route | `route_lookup` (`address`) | matched prefix, protocol, distance, metric, best flag, every next hop (gateway, interface, FIB flag, recursive tunnels); `% Network not in table` means no route |
| policy routes | `policy_routes_ipv4` | number of entries; entries whose destination covers the address (id, SD-WAN rule, outgoing interfaces, gateway); entries with internet services or negation are listed as not evaluated |
| SD-WAN | `sdwan_health` | health-check state of the members that are next-hop interfaces |
| neighbours | `arp_table` | for each directly reachable gateway: ARP entry complete, incomplete (all-zero hardware address) or absent; hardware addresses are not returned |

| Rule | Kind | Fires when |
|---|---|---|
| F-ROUTE-NONE | finding | the route lookup prints `% Network not in table` |
| F-EGRESS-SDWAN-DEAD | finding | a FIB next-hop interface is an SD-WAN member in `state(dead)` |
| F-NEXTHOP-ARP-INCOMPLETE | finding | the gateway of a FIB next hop has only incomplete ARP entries |
| H-NEXTHOP-NO-ARP | hypothesis | the gateway is not in the ARP table (it may not have answered, or the entry aged out) |
| H-POLICY-ROUTE | hypothesis | a policy route or SD-WAN rule covers the address and would override the route when its other match fields fit |
| H-POLICY-UNEVALUATED | hypothesis | some policy routes could not be evaluated |

Findings cite every read they rest on (`query`, `content_sha256`, `captured_at`); hypotheses carry the same `basis` and never change the verdict. `verdict` is `incomplete` when any step after `system_status` is missing (refused, timed out, truncated, empty or not parsed), `fault_found` when a finding fired, otherwise `no_fault_in_checked_data`; an empty SD-WAN table or the exact reply `SD-WAN health monitor is not running.` or `SD-WAN daemon is not running.` is `not_applicable`. Any output line of an unknown shape makes that step `unparsed` instead of being guessed. `next_steps` names `routing_table` after F-ROUTE-NONE and `sdwan_member_detail` for a dead egress member (the member number must be enrolled to run it). Device output is redacted before it is parsed, and the result carries no raw output.

## FortiOS VPN triage (`triage_vpn`)

`triage_vpn(target, tunnel)` reads one named IPsec tunnel on a FortiOS target with four fixed catalogue reads and returns the facts, the rules that fired and what it could not check. Identity, platform and scope rules are the same as for `triage_health` (FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251; `fortinet` platform with `system_status` enabled). `tunnel` must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,34}`; it is never sent to the device, it only selects lines of the parsed output. The phase 1 name selects the tunnel and its dial-up or ADVPN instances `<tunnel>_<number>`. One call consumes four requests of the target rate limit. Detailed IKE gateway and tunnel dumps are not read, so no keying material reaches the result.

| Chain part | Query | What is taken from it |
|---|---|---|
| identity | `system_status` | model, version, build |
| tunnel | `ipsec_summary` | per instance: peer, selectors total and up, rx and tx packets and errors; an empty summary means no tunnels |
| routes | `routing_table` | prefixes whose interface (`via <tunnel> tunnel <peer>`, `via <gateway>, <tunnel>` or `directly connected, <tunnel>`) is the tunnel |
| ike | `ike_errors` | number of counters and the non-zero ones (context only, no rule) |

| Rule | Fires when |
|---|---|
| F-VPN-NOT-FOUND | the summary has no instance of the tunnel |
| F-VPN-DOWN | no selector is up |
| F-VPN-PARTIAL | some but not all selectors are up |
| F-VPN-NO-RX | selectors are up but no packet was received (an SA alone is not data flow) |
| F-VPN-ERRORS | rx or tx error counter is above zero |
| F-VPN-NO-ROUTE | the tunnel exists but no route in the routing table uses it (a policy-based tunnel has no routes) |

`verdict` is `incomplete` when any step is missing (refused, timed out, truncated, empty or not parsed), `fault_found` when at least one rule fired, otherwise `no_fault_in_checked_data`; it never claims the tunnel is healthy. Rules that need a missing step do not fire. `hypotheses` and `next_steps` stay empty. Device output is redacted before it is parsed, and the result carries no raw output.

## FortiADC load-balancing triage (`triage_slb`)

`triage_slb(target, virtual_server, vdom="root")` follows one FortiADC virtual server through its configuration and runtime state and returns the chain, the rules that fired and what it could not check. The target must use the `fortiadc` platform with `read` in `config_access`, `virtual_server` must be listed in `adc_virtual_servers`, `vdom` in `adc_vdoms`, and the queries `slb_vs_stat`, `slb_load` and `system_performance` must be enabled. The first read is the device identity; any build other than FortiADC 7.6.7 build 0676 is refused with `config_platform_not_supported` and an unverifiable identity stops the call before anything else is read. One call consumes seventeen requests of the target rate limit and is refused as a whole when fewer remain. The seventeen requests are charged when the call is accepted and leave the window `window_seconds` later; a call can run longer than the default 60-second window (61 to 66 seconds measured on FortiADC-KVM 7.6.7 build 0676). The helper handles calls one at a time, so a `target_scope` sent during the call returns only after it finishes and no longer counts them; `used: 0` then does not mean nothing was charged.

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
