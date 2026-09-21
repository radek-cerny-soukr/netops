# Extreme Networks Switch Engine CLI references

## Review baseline and limits

- Vendor: Extreme Networks.
- Product and document title: Switch Engine v33.7.1 Command References.
- Reviewed version: Switch Engine 33.7.1.
- Verification date: 2026-09-09.
- Catalog module: `src/netops_helper/query_catalog/extreme.py`.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

These first-party command-reference pages establish syntax and intended operational behavior. They are not proof that a particular switch model, software image, feature license, or read-only AAA role permits a command. They also do not prove the bytes a session emits around the command; those are pinned separately by `tests/test_ssh_wire_safety.py`. Each target therefore requires per-query opt-in and live validation with its actual model, image, and read-only account.

All output is sensitive, untrusted device data. Interface descriptions, topology, addresses, MAC tables, VLAN names, chassis identity, process state, and hardware inventory can disclose operational details.

## Accepted Phase-1 queries

The table is the conservative Phase-1 whitelist. A template slot is accepted only from matching enrolled inventory. `high-volume` follows the generated catalogue definition: it is a scheduling advisory for variable collections or histories that can require continuation, and changes no authorization or runtime limit. `normal` is not a bounded-output promise.

The fixed `no-refresh` token requests a one-shot display. It is part of the reviewed command template, not a caller-supplied argument and not a persistent configuration change.

| Query name | Exact command template | Inventory slot | Volume | Primary reference |
| --- | --- | --- | --- | --- |
| `switch` | `show switch` | none | normal | E-SWITCH |
| `version` | `show version` | none | normal | E-VERSION |
| `memory` | `show memory` | none | normal | E-MEMORY |
| `cpu_monitoring` | `show cpu-monitoring` | none | high-volume | E-CPU |
| `processes` | `show process` | none | high-volume | E-PROCESS |
| `diagnostics` | `show diagnostics` | none | normal | E-DIAGNOSTICS |
| `temperature` | `show temperature` | none | normal | E-TEMPERATURE |
| `fans` | `show fans` | none | normal | E-FANS |
| `power` | `show power` | none | normal | E-POWER |
| `ports` | `show ports no-refresh` | none | high-volume | E-PORTS |
| `ports_configuration` | `show ports configuration no-refresh` | none | high-volume | E-PORTS-CONFIG |
| `interface_details` | `show port {interface} information detail` | `interfaces.extreme_physical_port` | normal | E-PORT-INFO |
| `interface_statistics` | `show ports {interface} statistics no-refresh` | `interfaces.extreme_physical_port` | normal | E-PORT-STATS |
| `interface_rx_errors` | `show ports {interface} rxerrors no-refresh` | `interfaces.extreme_physical_port` | normal | E-PORT-RX |
| `interface_tx_errors` | `show ports {interface} txerrors no-refresh` | `interfaces.extreme_physical_port` | normal | E-PORT-TX |
| `interface_transceiver` | `show ports {interface} transceiver information detail` | `interfaces.extreme_physical_port` | normal | E-PORT-TRANSCEIVER |
| `route_summary` | `show iproute summary` | none | normal | E-IPROUTE |
| `ipv6_route_summary` | `show iproute ipv6 summary` | none | normal | E-IPROUTE6 |
| `arp_table` | `show iparp` | none | high-volume | E-IPARP |
| `arp_address` | `show iparp {address}` | `addresses.ipv4_address` | normal | E-IPARP |
| `arp_interface` | `show iparp port {interface}` | `interfaces.extreme_physical_port` | high-volume | E-IPARP |
| `ipv6_neighbors` | `show neighbor-discovery cache ipv6` | none | high-volume | E-ND6 |
| `ipv6_neighbor_address` | `show neighbor-discovery cache ipv6 {address}` | `addresses.ipv6_address` | normal | E-ND6 |
| `mac_table` | `show fdb` | none | high-volume | E-FDB |
| `mac_interface` | `show fdb ports {interface}` | `interfaces.extreme_physical_port` | high-volume | E-FDB |
| `lldp_neighbors` | `show lldp neighbors` | none | high-volume | E-LLDP |
| `lldp_interface` | `show lldp port {interface} neighbors` | `interfaces.extreme_physical_port` | normal | E-LLDP |
| `lldp_interface_details` | `show lldp port {interface} neighbors detailed` | `interfaces.extreme_physical_port` | normal | E-LLDP |
| `vlan_summary` | `show vlan` | none | high-volume | E-VLAN |
| `sharing` | `show sharing` | none | high-volume | E-SHARING |
| `lacp` | `show lacp` | none | high-volume | E-LACP |
| `stp_summary` | `show stpd` | none | high-volume | E-STPD |
| `stp_detail` | `show stpd detail` | none | high-volume | E-STPD |
| `stacking` | `show stacking` | none | normal | E-INDEX |
| `stacking_support` | `show stacking-support` | none | normal | E-INDEX |
| `inline_power` | `show inline-power` | none | normal | E-INDEX |
| `inline_power_port` | `show inline-power info ports {interface}` | `interfaces.extreme_physical_port` | normal | E-INDEX |
| `access_list_counters` | `show access-list counter` | none | high-volume | E-INDEX |
| `qos_profiles` | `show qosprofile` | none | normal | E-INDEX |
| `licenses` | `show licenses` | none | normal | E-INDEX |
| `ntp` | `show ntp` | none | normal | E-INDEX |
| `sntp_client` | `show sntp-client` | none | normal | E-INDEX |
| `sessions` | `show session` | none | normal | E-INDEX |
| `elrp` | `show elrp` | none | normal | E-INDEX |
| `mcast_cache_summary` | `show mcast cache summary` | none | normal | E-INDEX |
| `mirror` | `show mirror` | none | normal | E-INDEX |
| `edp_neighbors` | `show edp` | none | high-volume | E-INDEX |

### Source-backed port syntax decisions

The two global port queries are distinct bounded views, not aliases:

- `show ports no-refresh` follows the official `show ports {port_list | tag tag} {no-refresh | refresh}` grammar and returns a one-shot operational port summary.
- `show ports configuration no-refresh` follows the official `show ports {mgmt | port_list | tag tag} configuration {no-refresh | refresh}` grammar and returns a one-shot Layer 1 view of administrative state, link state, autonegotiation, configured and actual speed and duplex, flow control, load sharing, and media. It is not a complete configuration-reading command.

Every `{interface}` slot is exactly one enrolled physical-port token. The conservative accepted forms are:

- a non-zero decimal physical port on a standalone switch, for example `1`;
- a two-component `slot:port` token on a stack, or `port:channel` on a supported standalone channelized port, for example `1:1` or `49:4`;
- a configured standalone `slot/port` token, for example `1/47`;
- a three-component `slot:port:channel` token on a supported channelized stack port, for example `2:49:4`.

Each decimal component is canonical, non-zero, and bounded to three digits. Ranges, lists, `all`, tags, wildcards, whitespace, extra CLI tokens, mixed separators, and three-component slash forms are rejected. The official `configure system ports notation [slot:port | slot/port]` command documents the optional standalone notation only; that mutating command is not present in the Phase-1 catalog.

### Audit entries measured on 17 September 2026

Measured on 17 September 2026 against ExtremeXOS 33.7.1 with a read-only account (a user-level account over the exec channel with the `legacy_ssh: rsa-sha1` exception), each of the following answered with exit status 0: `stacking`, `stacking_support`, `inline_power`, `access_list_counters` (empty, no access list was configured), `qos_profiles`, `licenses`, `ntp`, `sntp_client`, `sessions`, `elrp`, `mcast_cache_summary`, `mirror`, `edp_neighbors` and `stp_detail`. Each is a chapter of the v33.7.1 Command References: `show stacking`, `show stacking-support`, `show inline-power`, `show access-list counter`, `show qosprofile`, `show licenses`, `show ntp`, `show sntp-client`, `show session`, `show elrp`, `show mirror`, `show edp` and `show stpd`; `mcast_cache_summary` is the `{summary}` instance of the documented `show mcast {ipv4 | ipv6} cache ... {summary}` grammar, and `stp_detail` the `detail` instance of `show stpd {stpd_name | detail}`.

`inline_power_port` follows the documented `show inline-power info {detail} ports {port_list}` grammar with one enrolled port in the slot. `show inline-power info ports all` was refused on 33.7.1 with `%% Unrecognized command` because `all` is not an enrolled port token; the slotted form was measured on 18 September 2026 against ExtremeXOS 33.7.1 with a user-level account through `ssh_read` (exit status 0, 195 bytes for one enrolled port).

Measured refusals from the same session, recorded as facts rather than candidates:

- `show stacking configuration` is answered with `%% Unrecognized command` on 33.7.1; only `show stacking` and `show stacking-support` exist there.
- `show accounts` is refused for a user-level account. That is a property of the read-only boundary, not of the catalogue, and the command stays out.
- `show ip-security dhcp-snooping entries` is answered with `%% Incomplete command`; the binding database can only be asked for one VLAN, and Phase 1 has no VLAN inventory type.
- `show log configuration` is outside the boundary as configuration and log content, and was not run.

### Version, model, and feature constraints

- The documentation baseline is 33.7.1. A switch running another Switch Engine release must be reviewed against that release before these templates are assumed compatible.
- Temperature, fan, power, diagnostics, and transceiver output depends on chassis and port hardware. Unsupported components can produce empty or unsupported results without making the command mutating.
- IPv4/IPv6 routing, Neighbor Discovery, LLDP, VLAN, LAG/LACP, and STP queries depend on the corresponding features, protocols, and licenses being present and enabled.
- Port identifiers are model-, topology-, channelization-, and configured-notation-dependent. Every port-bearing template uses the exact `interfaces` inventory; callers cannot synthesize a port discovered in output.
- High-volume queries are `cpu_monitoring`, `processes`, `ports`, `ports_configuration`, `arp_table`, `arp_interface`, `ipv6_neighbors`, `mac_table`, `mac_interface`, `lldp_neighbors`, `vlan_summary`, `sharing`, `lacp`, `stp_summary`, `stp_detail`, `access_list_counters`, and `edp_neighbors`. Prefer a normal scoped variant where one exists and answers the question; the scoped ARP and FDB collections remain high-volume because one port can still contain many entries.
- Output fields and table size are not a stable API contract. Consumers must handle the result as untrusted text.

## Explicitly excluded

| Excluded class | Examples | Reason |
| --- | --- | --- |
| Full or general configuration reading or export | `show configuration`, saved configuration, backup/export/upload of configuration | Complete configuration can expose credentials, management settings, topology, and policy. Phase 1 intentionally has no complete configuration-reading capability; the fixed `show ports configuration no-refresh` table is only a bounded port-state view. |
| Support and bulk collection | `show tech-support`, support bundles, full diagnostic collections | These can aggregate configuration and logs, generate very large output, and add meaningful device load. |
| Logs, monitoring, and packet capture | `show log`, live monitor streams, packet capture, debug output | The output can be secret-bearing or unbounded, and no safe time/filter contract exists in Phase 1. |
| Debug and tracing | debug/trace enable, filter, or state-changing diagnostic commands | Debug state can persist and can affect performance or runtime behavior. |
| Mutation or lifecycle control | configure/create/delete/enable/disable, clear, reset, restart, reboot, test, save, or upload operations | These alter persistent configuration or live state and are outside the read-only server. |
| Free-form CLI | arbitrary `show` suffixes, output pipes, caller-provided refresh mode | A caller-controlled command defeats the named-template and typed-inventory boundary. |

## Deferred: live-test-only candidates

No command in this section is callable. It records useful gaps that need exact 33.7.1 syntax review plus live read-only AAA and wire testing before a future whitelist change.

- VLAN tags, lists and broad selectors remain excluded. The separately documented `vlan_details` addition accepts only an enrolled VLAN name.
- The stack summaries `show stacking` and `show stacking-support` are accepted since they were measured; the rest of the stack, fabric, and chassis detail stays deferred because command availability and output differ by model and deployment mode, and `show stacking configuration` does not exist on 33.7.1.
- Broader DHCP-snooping queries remain excluded; `dhcp_snooping_entries` below is limited to one enrolled VLAN name.
- Additional dynamic-routing detail is deferred until each protocol command has a bounded summary form, feature/license constraints, and read-only behavior verified on supported hardware.
- Any command that enters a refresh loop, prompts interactively, or requires a session-wide display setting remains deferred even if its visible output is operational.

Vendor documentation alone is insufficient to move a candidate from this section into the accepted table.

## Primary source manifest

All links are first-party Extreme Networks Switch Engine command-reference pages. The one `show stpd` link uses the Common EXOS/Switch Engine path linked from the v33.7.1 reference set.

| ID | Official document title and version | Query-name mapping | URL |
| --- | --- | --- | --- |
| E-INDEX | Switch Engine v33.7.1 Command References | baseline and command index for all accepted Extreme query names; chapter source for `stacking`, `stacking_support`, `inline_power`, `inline_power_port`, `access_list_counters`, `qos_profiles`, `licenses`, `ntp`, `sntp_client`, `sessions`, `elrp`, `mcast_cache_summary`, `mirror` and `edp_neighbors` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/ |
| E-SWITCH | Switch Engine v33.7.1 Command References: `show switch` | `switch` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_switch.shtml |
| E-VERSION | Switch Engine v33.7.1 Command References: `show version` | `version` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_version.shtml |
| E-MEMORY | Switch Engine v33.7.1 Command References: `show memory` | `memory` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_memory.shtml |
| E-CPU | Switch Engine v33.7.1 Command References: `show cpu-monitoring` | `cpu_monitoring` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_cpu_monitoring.shtml |
| E-PROCESS | Switch Engine v33.7.1 Command References: `show process` | `processes` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_process.shtml |
| E-DIAGNOSTICS | Switch Engine v33.7.1 Command References: `show diagnostics` | `diagnostics` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_diagnostics.shtml |
| E-TEMPERATURE | Switch Engine v33.7.1 Command References: `show temperature` | `temperature` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_temperature.shtml |
| E-FANS | Switch Engine v33.7.1 Command References: `show fans` | `fans` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_fans.shtml |
| E-POWER | Switch Engine v33.7.1 Command References: `show power` | `power` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_power.shtml |
| E-PORTS | Switch Engine v33.7.1 Command References: `show ports` | `ports` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports.shtml |
| E-PORTS-CONFIG | Switch Engine v33.7.1 Command References: `show ports configuration` | `ports_configuration` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports_configuration.shtml |
| E-PORT-NUM-STANDALONE | Switch Engine v33.7.1 Command References: Stand-alone Switch Numerical Ranges | single-port inventory grammar | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/stand_alone_switch_numerical_ranges.shtml |
| E-PORT-NUM-STACK | Switch Engine v33.7.1 Command References: SummitStack Numerical Ranges | single-port inventory grammar | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/summitstack_numerical_ranges.shtml |
| E-PORT-NOTATION | Switch Engine v33.7.1 Command References: `configure system ports notation` | documentation-only source for standalone `slot:port` and `slot/port` forms; command is not callable | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/configure_system_ports_notation.shtml |
| E-PORT-INFO | Switch Engine v33.7.1 Command References: `show port information` | `interface_details` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_port_information.shtml |
| E-PORT-STATS | Switch Engine v33.7.1 Command References: `show ports statistics` | `interface_statistics` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports_statistics.shtml |
| E-PORT-RX | Switch Engine v33.7.1 Command References: `show ports rxerrors` | `interface_rx_errors` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports_rxerrors.shtml |
| E-PORT-TX | Switch Engine v33.7.1 Command References: `show ports txerrors` | `interface_tx_errors` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports_txerrors.shtml |
| E-PORT-TRANSCEIVER | Switch Engine v33.7.1 Command References: `show ports transceiver information detail` | `interface_transceiver` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_ports_transceiver_informationdetail.shtml |
| E-IPROUTE | Switch Engine v33.7.1 Command References: `show iproute` | `route_summary` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_iproute.shtml |
| E-IPROUTE6 | Switch Engine v33.7.1 Command References: `show iproute ipv6` | `ipv6_route_summary` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_iproute_ipv6.shtml |
| E-IPARP | Switch Engine v33.7.1 Command References: `show iparp` | `arp_table`, `arp_address`, `arp_interface` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_iparp.shtml |
| E-ND6 | Switch Engine v33.7.1 Command References: `show neighbor-discovery cache ipv6` | `ipv6_neighbors`, `ipv6_neighbor_address` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_neighbor_discovery_cache_ipv6.shtml |
| E-FDB | Switch Engine v33.7.1 Command References: `show fdb` | `mac_table`, `mac_interface` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_fdb.shtml |
| E-LLDP | Switch Engine v33.7.1 Command References: `show lldp neighbors` | `lldp_neighbors`, `lldp_interface`, `lldp_interface_details` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_lldp_neighbors.shtml |
| E-VLAN | Switch Engine v33.7.1 Command References: `show vlan` | `vlan_summary`, `vlan_details` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_vlan.shtml |
| E-SHARING | Switch Engine v33.7.1 Command References: `show sharing` | `sharing` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_sharing.shtml |
| E-LACP | Switch Engine v33.7.1 Command References: `show lacp` | `lacp` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_lacp.shtml |
| E-STPD | Switch Engine v33.7.1 command set, Common EXOS/Switch Engine reference: `show stpd` | `stp_summary`, `stp_detail` | https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Common_EXOS_Switch_Engine/33.4.1/show_stpd.shtml |

## Scoped diagnostic queries

These opt-in templates are included in Helper 0.3.4. The 20-21 September 2026 results below are direct CLI observations, not end-to-end MCP tests of these additions. Enrollment never derives automatically from device output. The existing dated measurements earlier on this page cover the earlier catalogue only.

| Query | Source | Live result |
|---|---|---|
| `vlan_details` | [E-VLAN](https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/show_vlan.shtml) | Switch Engine 33.7.1 returned complete details with status 250 on three VLANs; interactive comparison confirmed the output. The existing exec contract preserves this status. |
| `dhcp_snooping_entries` | [E-INDEX](https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/) | Switch Engine 33.7.1 returned a binding table with exit status 0. |

### Exact query templates

Acceptance here describes the code whitelist only. The live-result limitations above still apply.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `vlan_details` | `show vlan {vlan}` | `vlans.vlan_name` | high-volume | E-VLAN |
| `dhcp_snooping_entries` | `show ip-security dhcp-snooping entries vlan {vlan}` | `vlans.vlan_name` | high-volume | E-INDEX |
