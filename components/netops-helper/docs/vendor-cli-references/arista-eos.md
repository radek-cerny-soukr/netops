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

The complete [EOS User Manual PDF](https://www.arista.com/en/assets/data/pdf/user-manual/um-books/EOS-User-Manual.pdf) is retained as a cross-reference. It is not copied into this repository.

Parameterized entries require exact enrollment and platform-specific slot kinds. IPv4 and IPv6 addresses are distinct canonical literal types. Interface contexts distinguish general, physical, LLDP, LACP, STP, and OSPF interface grammars.

## Explicit exclusions

- Running/startup/full configuration, configuration sessions, files, logs, debug, support/tech-support, packet capture, Bash, and commands that clear, test, reload, restart, or write state are prohibited.
- `show processes top once` was removed because the exact Phase-1 spelling was not established across the 4.36.x reference baseline.
- Detailed LLDP is excluded. The audited manual's syntax and example disagree between `detailed` and `detail`; the accepted query is the unambiguous summary `show lldp neighbors`.
- MLAG queries are not included merely because EOS commonly supports MLAG. A sufficiently precise, common 4.36.x read-only command and output bound were not established in this audit.
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
