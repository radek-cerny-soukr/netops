# Arista EOS CLI references

Baseline: Arista EOS 4.36.x, audited primarily against the EOS 4.36.2F command documentation.

Audit date: 2026-09-09.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

## Profile

The profile key is `arista_eos`. It is a conservative common EOS profile. Availability of a documented command can still depend on the switch family, installed agents, licensed feature, and whether the corresponding protocol is enabled.

## Accepted Phase-1 queries and source mapping

| Query names | Primary source |
|---|---|
| `version` | [EOS standard upgrades and downgrades](https://www.arista.com/en/um-eos/eos-standard-upgrades-and-downgrades?print=1&tmpl=component) |
| `clock`, `hostname` | [EOS switch administration commands](https://www.arista.com/en/um-eos/eos-switch-administration-commands) |
| `inventory` | [EOS session management commands](https://www.arista.com/en/um-eos/eos-session-management-commands) |
| `environment` | [Configuring and viewing environment settings](https://www.arista.com/en/um-eos/eos-configuring-and-viewing-environment-settings) |
| `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `interface_details`, `interface_errors`, `interface_optics` | [EOS Ethernet ports](https://www.arista.com/en/um-eos/eos-ethernet-ports), [EOS IPv4](https://www.arista.com/en/um-eos/eos-ipv4), and [EOS IPv6](https://www.arista.com/en/um-eos/eos-ipv6?tmpl=component) |
| `vlans` | [EOS VLANs](https://www.arista.com/en/um-eos/eos-virtual-lans-vlans) |
| `mac_table` | [EOS data transfer](https://www.arista.com/en/um-eos/eos-data-transfer) |
| `arp_table`, `arp_entry`, `route_summary`, `route_lookup` | [EOS IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `ipv6_neighbors`, `ipv6_neighbor`, `ipv6_route_summary`, `ipv6_route_lookup` | [EOS IPv6](https://www.arista.com/en/um-eos/eos-ipv6?tmpl=component) |
| `lldp_neighbors`, `lldp_neighbors_interface` | [EOS LLDP](https://www.arista.com/en/um-eos/eos-link-layer-discovery-protocol) |
| `lag_summary`, `lacp_peers`, `lacp_peer_interface` | [EOS Port Channels and LACP](https://www.arista.com/en/um-eos/eos-port-channels-and-lacp) |
| `stp_root`, `stp_interface` | [EOS Spanning Tree Protocol](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol) |
| `bgp_summary`, `ipv6_bgp_summary` | [EOS BGP](https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp) |
| `ospf_neighbors`, `ospf_neighbors_interface` | [EOS OSPFv2](https://www.arista.com/en/um-eos/eos-open-shortest-path-first-version-2) |
| `ospfv3_neighbors` | [EOS OSPFv3](https://www.arista.com/en/um-eos/eos-open-shortest-path-first-version-3) |
| `route_table` | [EOS IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `ospf_interfaces` | [EOS OSPFv2](https://www.arista.com/en/um-eos/eos-open-shortest-path-first-version-2) |
| `stp_tree`, `stp_blocked`, `stp_vlan` | [EOS Spanning Tree Protocol](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol) |
| `interfaces_errdisabled`, `interfaces_description`, `interfaces_counters_errors`, `interfaces_counters_discards`, `interface_poe` | [EOS Ethernet ports](https://www.arista.com/en/um-eos/eos-ethernet-ports) |
| `interfaces_trunk`, `interface_switchport`, `vlan_details` | [EOS VLANs](https://www.arista.com/en/um-eos/eos-virtual-lans-vlans) |
| `lldp_neighbors_detail` | [EOS LLDP](https://www.arista.com/en/um-eos/eos-link-layer-discovery-protocol) |
| `mlag_detail`, `mlag_config_sanity` | [EOS Multi-Chassis Link Aggregation](https://www.arista.com/en/um-eos/eos-multi-chassis-link-aggregation) |
| `mlag_interfaces` | [Arista ATD Lab Guides 2026.2 – Data Center VXLAN (MLAG verification)](https://labguides.testdrive.arista.com/2026.2/data_center/vxlan/) and [EOS Multi-Chassis Link Aggregation](https://www.arista.com/en/um-eos/eos-multi-chassis-link-aggregation); the ATD output is a lab guide 2026.2 documentation example, not a live measurement and not an EOS firmware or hardware qualification |
| `ntp_status`, `ntp_associations`, `cpu`, `log_messages` | [EOS switch administration commands](https://www.arista.com/en/um-eos/eos-switch-administration-commands) |
| `reload_cause` | [EOS Switch booting commands](https://www.arista.com/en/um-eos/eos-switch-booting-commands) |

| `dot1x`, `dot1x_interface`, `dot1x_clients` | [EOS Control Plane Security](https://www.arista.com/en/um-eos/eos-control-plane-security) |
| `snmp_status`, `snmp_targets` | [EOS SNMP](https://www.arista.com/en/um-eos/eos-snmp) |
| `dns_lookup` | [EOS IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `dns_hosts`, `dns_name_servers`, `logging_status` | [EOS switch administration commands](https://www.arista.com/en/um-eos/eos-switch-administration-commands) |
| `log_messages_last`, `log_messages_range` | [EOS switch administration commands](https://www.arista.com/en/um-eos/eos-switch-administration-commands); `last`, `time-range` and `threshold` keywords verified with `?` on cEOS 4.36.1F (2026-11-18) |
| `users`, `aaa_sessions`, `radius`, `radius_status`, `tacacs` | [EOS User Security](https://www.arista.com/en/um-eos/eos-user-security) |
| `dhcp_relay`, `dhcp_relay_counters`, `dhcp_snooping`, `dhcp_server`, `dhcp_server_leases` | [EOS DHCP configuration](https://www.arista.com/en/um-eos/eos-configuring-dhcp) |
| `ipv4_access_lists_summary`, `ipv6_access_lists_summary`, `ipv4_access_lists_interface`, `ipv6_access_lists_interface`, `ipv4_access_lists`, `ipv6_access_lists` | [EOS ACLs and route maps](https://www.arista.com/en/um-eos/eos-acls-and-route-maps) |
The rows added in NetOps 1.0.7 were run on a cEOS 4.36.1F lab node on 2026-11-08; the outputs are stored in `tests/fixtures/real/arista_eos/ceos_4.36.1F`. `interface_poe` was not measurable (a virtual platform answers `% Invalid input`) and is `verified: docs-only`; `mlag_detail` and `mlag_config_sanity` were measured only in the inactive state.

The complete [EOS User Manual PDF](https://www.arista.com/en/assets/data/pdf/user-manual/um-books/EOS-User-Manual.pdf) is retained as a cross-reference. It is not copied into this repository.

Parameterized entries require exact enrollment and platform-specific slot kinds. IPv4 and IPv6 addresses are distinct canonical literal types. Interface contexts distinguish general, physical, LLDP, LACP, STP, and OSPF interface grammars. The LACP context of `lacp_peer_interface` accepts only member `Ethernet` interfaces: for a Port-Channel, `show lacp interface Port-ChannelN peer` returns only `Interface Port-ChannelN is not a member of a port channel.` (Arista EOS container image 4.36.1F).

## EOS virtual-image compatibility

Compatibility is scoped to EOS 4.36.1F container and virtual images with the documented network-operator role. Interface authorization distinguishes member Ethernet interfaces from Port-Channels and Management interfaces. Feature-absence replies can remain successful reads; privilege and invalid-command refusals are reported as device_cli_error. This virtual-image profile does not establish hardware, licensed-feature or AAA-command compatibility.

## Explicit exclusions

- Running/startup/full configuration, configuration sessions, files, logs, debug, support/tech-support, packet capture, Bash, and commands that clear, test, reload, restart, or write state are prohibited.
- `show processes top once` (`cpu`), `show lldp neighbors detail` (`lldp_neighbors_detail`; the manual disagrees between `detailed` and `detail`, 4.36.1F accepts `detail`) and the two MLAG reads were first left out because their spelling was not established; NetOps 1.0.7 added them after a measurement on cEOS 4.36.1F. `show lldp neighbors` stays as the summary.
- Logs are excluded except the fixed slotless templates `log_messages` (`show logging 200`, newest 200 lines) and `logging_status` (status and destination fields from `show logging`, selected by its fixed `include` filter), and the typed windows `log_messages_last` (`show logging last {minutes} minutes threshold {severity}`) and `log_messages_range` (`show logging time-range {begin_date} {begin_time} {end_date} {end_time} threshold {severity}`); any other filter or a caller-supplied pipe stays refused.
- Global full routing-table dumps are excluded; the catalog exposes summaries and inventory-bound single-address lookups.
- OSPFv3 interface scoping is excluded because the source review established the global neighbor command but not a sufficiently unambiguous common interface-filter form.
- Free-form CLI and arbitrary pipe/redirection syntax are never accepted.

## Deferred live-wire candidates

- MLAG summary and peer state.
- Scoped OSPFv3 neighbors.
- A detailed LLDP variant after the exact accepted keyword is proven on supported 4.36.x targets.
- Model-specific power, fan, temperature, transceiver, supervisor, and fabric diagnostics.
- Scoped MAC/VLAN views where output scale justifies an additional typed slot.

A candidate becomes eligible only after source confirmation and a wire test of the exact target models. The test must also establish bounded output, privilege behavior, paging, command echo, and absence of configuration-mode or terminal-setting writes.

## High-volume and operational limitations

High-volume queries are `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `vlans`, `mac_table`, `arp_table`, `ipv6_neighbors`, `lldp_neighbors`, `lag_summary`, `lacp_peers`, `stp_root`, `bgp_summary`, `ipv6_bgp_summary`, `ospf_neighbors`, and `ospfv3_neighbors`.

`high-volume` is only a maintainer scheduling advisory; it changes no authorization, policy opt-in, rate accounting, timeout, snapshot or cache behavior, or the 2,000,000-byte capture cap. A query not listed as high-volume is not promised to be small, cheap, or bounded.

- Table size depends on platform scale and deployed topology. High-volume responses require pagination/snapshot handling and conservative timeouts.
- Hardware SKU, modular chassis role, EOS extension availability, and feature licensing can change command availability or output fields.
- RBAC roles and AAA command authorization must explicitly permit only the catalogued EXEC commands. A command being documented or locally present does not guarantee TACACS+/RADIUS authorization.
- Inventory, neighbor, routing, BGP, and optics output can expose serial numbers, topology, addressing, peer identities, and interface descriptions. These are sensitive operational data, not permission to expose credentials.
- Documentation review is not a substitute for wire verification of prompt handling, paging, output standard, and exact bytes sent to the device.

## Lab measurements (GNS3 lab, 2026-11-08)

Every template was run on the lab images with the read-only account; the stored outputs are in `tests/fixtures/real`. Regenerated by `tests/support/render_lab_measurements.py`.

<!-- lab-measurements:begin -->

| Template | Command | cEOS 4.36.1F | verified |
|---|---|---|---|
| `version` | `show version` | ok, 19 lines | live |
| `clock` | `show clock` | ok, 3 lines | live |
| `hostname` | `show hostname` | ok, 2 lines | live |
| `inventory` | `show inventory` | ok, 16 lines | live |
| `environment` | `show system environment all` | ok, 13 lines, exit status 1 | live |
| `interfaces` | `show interfaces status` | ok, 19 lines | live |
| `ip_interfaces` | `show ip interface brief` | ok, 8 lines | live |
| `ipv6_interfaces` | `show ipv6 interface brief` | ok, 3 lines, exit status 1 | live |
| `interface_details` | `show interfaces {interface}` | ok, 20 lines | live |
| `interface_errors` | `show interfaces {interface} counters errors` | ok, 2 lines | live |
| `interface_optics` | `show interfaces {interface} transceiver` | empty | live |
| `vlans` | `show vlan` | ok, 7 lines | live |
| `mac_table` | `show mac address-table` | ok, 19 lines | live |
| `arp_table` | `show ip arp` | ok, 9 lines | live |
| `arp_entry` | `show ip arp {address}` | ok, 5 lines | live |
| `ipv6_neighbors` | `show ipv6 neighbors` | ok, 4 lines | live |
| `ipv6_neighbor` | `show ipv6 neighbors {address}` | ok, 4 lines | live |
| `lldp_neighbors` | `show lldp neighbors` | ok, 18 lines | live |
| `lldp_neighbors_interface` | `show lldp neighbors {interface}` | ok, 10 lines | live |
| `lag_summary` | `show port-channel dense` | ok, 19 lines | live |
| `lacp_peers` | `show lacp peer` | empty | live |
| `lacp_peer_interface` | `show lacp interface {interface} peer` | ok, 1 line | live |
| `stp_root` | `show spanning-tree root` | ok, 4 lines | live |
| `stp_interface` | `show spanning-tree interface {interface}` | ok, 3 lines | live |
| `route_summary` | `show ip route summary` | ok, 34 lines | live |
| `ipv6_route_summary` | `show ipv6 route summary` | ok, 30 lines | live |
| `route_lookup` | `show ip route {address}` | ok, 23 lines | live |
| `ipv6_route_lookup` | `show ipv6 route {address}` | not configured | live |
| `bgp_summary` | `show ip bgp summary` | not configured | live |
| `ipv6_bgp_summary` | `show ipv6 bgp summary` | not configured | live |
| `ospf_neighbors` | `show ip ospf neighbor` | ok, 4 lines | live |
| `ospf_neighbors_interface` | `show ip ospf neighbor {interface}` | ok, 4 lines | live |
| `ospfv3_neighbors` | `show ipv6 ospf neighbor` | empty | live |
| `route_table` | `show ip route` | ok, 39 lines | live |
| `ospf_interfaces` | `show ip ospf interface brief` | ok, 3 lines | live |
| `stp_tree` | `show spanning-tree` | ok, 28 lines | live |
| `stp_blocked` | `show spanning-tree blockedports` | ok, 4 lines | live |
| `stp_vlan` | `show spanning-tree vlan {vlan_id}` | ok, 19 lines | live |
| `interfaces_errdisabled` | `show interfaces status errdisabled` | empty | live |
| `interfaces_description` | `show interfaces description` | ok, 21 lines | live |
| `interfaces_trunk` | `show interfaces trunk` | ok, 27 lines | live |
| `interfaces_counters_errors` | `show interfaces counters errors` | ok, 17 lines | live |
| `interfaces_counters_discards` | `show interfaces counters discards` | ok, 22 lines | live |
| `interface_switchport` | `show interfaces {interface} switchport` | ok, 19 lines | live |
| `interface_poe` | `show poe interface {interface}` | not supported by the image | docs-only |
| `lldp_neighbors_detail` | `show lldp neighbors detail` | ok, 236 lines | live |
| `vlan_details` | `show vlan id {vlan_id}` | ok, 4 lines | live |
| `mlag_detail` | `show mlag detail` | ok, 54 lines | live |
| `mlag_interfaces` | `show mlag interfaces` | ok, 1 line | live |
| `mlag_config_sanity` | `show mlag config-sanity` | ok, 2 lines | live |
| `ntp_status` | `show ntp status` | ok, 1 line | live |
| `ntp_associations` | `show ntp associations` | ok, 3 lines | live |
| `cpu` | `show processes top once` | ok, 88 lines | live |
| `reload_cause` | `show reload cause` | ok, 7 lines | live |
| `log_messages` | `show logging 200` | ok, 200 lines | live |
| `vrfs` | `show vrf` | ok, 6 lines | live |
| `ipv6_route_table` | `show ipv6 route` | not configured | live |
| `route_table_vrf` | `show ip route vrf {vrf}` | ok, 41 lines | live |
| `ipv6_route_table_vrf` | `show ipv6 route vrf {vrf}` | not configured | live |
| `route_lookup_vrf` | `show ip route vrf {vrf} {address}` | ok, 25 lines | live |
| `ipv6_route_lookup_vrf` | `show ipv6 route vrf {vrf} {address}` | not configured | live |
| `arp_table_vrf` | `show ip arp vrf {vrf}` | ok, 12 lines | live |
| `ipv6_neighbors_vrf` | `show ipv6 neighbors vrf {vrf}` | ok, 4 lines | live |
| `bgp_peer` | `show ip bgp neighbors {address}` | not configured | live |
| `bgp_peer_vrf` | `show ip bgp neighbors {address} vrf {vrf}` | not configured | live |
| `bgp_peer_routes` | `show ip bgp neighbors {address} routes` | not configured | live |
| `bgp_peer_routes_vrf` | `show ip bgp neighbors {address} routes vrf {vrf}` | not configured | live |
| `bgp_peer_advertised_routes` | `show ip bgp neighbors {address} advertised-routes` | not configured | live |
| `bgp_peer_advertised_routes_vrf` | `show ip bgp neighbors {address} advertised-routes vrf {vrf}` | not configured | live |
| `ospf_neighbors_detail` | `show ip ospf neighbor detail` | ok, 48 lines | live |
| `ospf_neighbors_detail_vrf` | `show ip ospf neighbor detail vrf {vrf}` | ok, 48 lines | live |
| `ospf_interface_detail` | `show ip ospf interface {interface}` | ok, 11 lines | live |
| `ospf_interface_detail_vrf` | `show ip ospf interface {interface} vrf {vrf}` | ok, 11 lines | live |
| `ospf_database` | `show ip ospf database` | ok, 17 lines | live |
| `ospf_database_vrf` | `show ip ospf database vrf {vrf}` | ok, 17 lines | live |
| `ospfv3_interface_detail` | `show ipv6 ospf interface {interface}` | empty | live |
| `ospfv3_interface_detail_vrf` | `show ipv6 ospf interface {interface} vrf {vrf}` | not configured | live |
| `ospfv3_database` | `show ipv6 ospf database` | empty | live |
| `ospfv3_database_vrf` | `show ipv6 ospf database vrf {vrf}` | not configured | live |
| `vrrp` | `show vrrp` | refused to the read-only account, answered to admin | live |
| `varp` | `show ip virtual-router` | ok, 1 line | live |
| `bfd_peers` | `show bfd peers` | empty | live |
| `ospfv3_neighbors_vrf` | `show ipv6 ospf neighbor vrf {vrf}` | not configured | live |
| `bgp_summary_vrf` | `show ip bgp summary vrf {vrf}` | not configured | live |
| `ipv6_bgp_summary_vrf` | `show ipv6 bgp summary vrf {vrf}` | not configured | live |
| `ping` | `ping vrf {vrf} {address} source {source} repeat 5` | refused to the read-only account, answered to admin | live |
| `traceroute` | `traceroute vrf {vrf} {address}` | ok, 2 lines | live |
| `traceroute_source` | `traceroute vrf {vrf} {address} source {source}` | ok, 2 lines | live |
| `vrrp_vrf` | `show vrrp vrf {vrf}` | refused to the read-only account, answered to admin | live |
| `varp_vrf` | `show ip virtual-router vrf {vrf}` | ok, 1 line | live |
| `bfd_peers_vrf` | `show bfd peers vrf {vrf}` | empty | live |
| `ipv6_rib` | `show rib route ipv6` | ok, 16 lines | live |
| `ipv6_rib_vrf` | `show rib route ipv6 vrf {vrf}` | ok, 16 lines | live |
| `interfaces_counters_rates` | `show interfaces counters rates` | ok, 18 lines | live |
| `interface_counters_rates` | `show interfaces {interface} counters rates` | ok, 2 lines | live |
| `mac_table_interface` | `show mac address-table interface {interface}` | ok, 15 lines | live |
| `mac_table_vlan` | `show mac address-table vlan {vlan_id}` | ok, 18 lines | live |
| `mac_table_address` | `show mac address-table address {mac}` | ok, 15 lines | live |
| `poe` | `show poe` | not supported by the image | docs-only |
| `stp_detail` | `show spanning-tree detail` | ok, 162 lines | live |
| `stp_interface_detail` | `show spanning-tree interface {interface} detail` | ok, 11 lines | live |
| `stp_counters` | `show spanning-tree counters` | ok, 16 lines | live |
| `interface_qos` | `show qos interfaces {interface}` | ok, 31 lines | live |
| `interface_queue_counters` | `show interfaces {interface} counters queue` | empty | live |
| `igmp_snooping` | `show ip igmp snooping` | ok, 55 lines | live |
| `igmp_snooping_groups` | `show ip igmp snooping groups` | ok, 8 lines | live |
| `igmp_snooping_mrouter` | `show ip igmp snooping mrouter` | ok, 4 lines | live |
| `igmp_snooping_counters` | `show ip igmp snooping counters` | ok, 22 lines | live |
| `ipv4_access_lists_summary` | `show ip access-lists summary` | refused to the read-only account, answered to admin | live |
| `ipv6_access_lists_summary` | `show ipv6 access-lists summary` | refused to the read-only account, answered to admin | live |
| `ipv4_access_lists_interface` | `show ip access-lists interface {interface}` | refused to the read-only account, answered to admin | live |
| `ipv6_access_lists_interface` | `show ipv6 access-lists interface {interface}` | refused to the read-only account, answered to admin | live |
| `ipv4_access_lists` | `show ip access-lists {name}` | refused to the read-only account, answered to admin | live |
| `ipv6_access_lists` | `show ipv6 access-lists {name}` | refused to the read-only account, answered to admin | live |
| `dhcp_relay` | `show ip dhcp relay` | ok, 1 line | live |
| `dhcp_relay_counters` | `show ip dhcp relay counters` | ok, 5 lines | live |
| `dhcp_snooping` | `show ip dhcp snooping` | ok, 1 line | live |
| `users` | `show users` | refused to the read-only account, answered to admin | live |
| `aaa_sessions` | `show users detail` | refused to the read-only account, answered to admin | live |
| `radius` | `show radius` | ok, 1 line | live |
| `radius_status` | `show monitor server radius` | ok, 1 line | live |
| `tacacs` | `show tacacs` | ok, 1 line | live |
| `dns_hosts` | `show hosts` | ok, 9 lines | live |
| `dns_name_servers` | `show ip name-server` | ok, 2 lines | live |
| `dns_lookup` | `ping {name} repeat 1` | refused to the read-only account, answered to admin | live |
| `snmp_status` | `show snmp` | ok, 2 lines | live |
| `snmp_targets` | `show snmp notification host` | empty | live |
| `logging_status` | `show logging \| include ^(Syslog\|Buffer\|Console\|Monitor\|Persistent\|Trap\|Logging to)` | ok, 5 lines | live |
| `dot1x` | `show dot1x all` | ok, 10 lines | live |
| `dot1x_interface` | `show dot1x interface {interface}` | empty | live |
| `dot1x_clients` | `show dot1x hosts interface {interface} detail` | ok, 1 line | live |
| `dhcp_server` | `show dhcp server` | ok, 15 lines | live |
| `dhcp_server_leases` | `show dhcp server leases` | empty | live |
| `log_messages_last` | `show logging last {minutes} minutes threshold {severity}` | ok, 14 lines | live |
| `log_messages_range` | `show logging time-range {begin_date} {begin_time} {end_date} {end_time} threshold {severity}` | ok, 11 lines | live |

<!-- lab-measurements:end -->

The `logging_status` cell comes from the earlier read-only run of plain `show logging`; the current fixed `| include` form was verified later in a CLI read with the admin account.

## Routing redundancy source additions

- `bfd_peers`, `bfd_peers_vrf`: [EOS BFD](https://www.arista.com/en/um-eos/eos-bidirectional-forwarding-detection).
- `vrrp`, `vrrp_vrf`, `varp`, `varp_vrf`: [EOS VRRP and VARP](https://www.arista.com/en/um-eos/eos-vrrp-and-varp).

## Port, STP, QoS and IGMP source additions

- `interfaces_counters_rates`, `interface_counters_rates`, `poe`: [EOS Ethernet ports](https://www.arista.com/en/um-eos/eos-ethernet-ports).
- `mac_table_interface`, `mac_table_vlan`, `mac_table_address`: [EOS data transfer](https://www.arista.com/en/um-eos/eos-data-transfer).
- `stp_detail`, `stp_interface_detail`, `stp_counters`: [EOS Spanning Tree Protocol](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol).
- `interface_qos`, `interface_queue_counters`: [EOS Quality of Service](https://www.arista.com/en/um-eos/eos-quality-of-service).
- `igmp_snooping`, `igmp_snooping_groups`, `igmp_snooping_mrouter`, `igmp_snooping_counters`: [EOS IGMP and IGMP Snooping](https://www.arista.com/en/um-eos/eos-igmp-and-igmp-snooping).

