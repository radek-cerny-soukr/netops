# Juniper Junos CLI references

Baseline: Junos OS 23.4R2 across the product families listed by Juniper, with an explicit EX/QFX ELS extension.

Audit date: 2026-09-09.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

## Profiles

- `juniper_junos`: common operational profile. It excludes switching commands that are not portable across the Junos 23.4R2 ACX, cSRX, EX, MX, NFX, QFX, SRX, vRR, and vSRX release scope.
- `juniper_junos_els` explicitly selects the ELS superset for supported EX/QFX targets. It must not be selected through silent model guessing.

The audited release scope is recorded in the [Junos 23.4R2 release notes](https://www.juniper.net/documentation/us/en/software/junos/release-notes/23.4/junos-release-notes-23.4r2/index.html).

## Accepted common Phase-1 queries and source mapping

Every accepted Junos command includes the fixed ` | no-more` output suffix. Juniper documents this as an operational output modifier; no other pipe or redirection is accepted.

| Query names | Primary source |
|---|---|
| `version` | [show version](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-version.html) |
| `uptime` | [show system uptime](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-uptime.html) |
| `system_alarms` | [show system alarms](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-alarms.html) |
| `chassis_alarms` | [show chassis alarms](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-alarms.html) |
| `hardware` | [show chassis hardware](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-hardware.html) |
| `environment` | [show chassis environment](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-environment.html) |
| `interfaces` | [show interfaces terse](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-interfaces-terse.html) |
| `interface_details` | [show interfaces extensive](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-interfaces-extensive.html) |
| `interface_optics` | [show interfaces diagnostics optics](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-interfaces-diagnostics-optics-10-gigabit-ethernet.html) |
| `route_summary` | [show route summary](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-summary.html) |
| `route_lookup`, `ipv6_route_lookup` | [show route](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route.html); the [Segment Routing guide](https://www.juniper.net/documentation/us/en/software/junos/segment-routing/segment-routing.pdf) contains an official IPv6 destination example |
| `arp_table`, `arp_interface` | [show arp](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-arp.html); the [data-center validated design](https://www.juniper.net/documentation/us/en/software/nce/sg-005-data-center-fabric/sg-005-data-center-fabric.pdf) corroborates the exact no-resolve/interface combination |
| `ipv6_neighbors`, `ipv6_neighbors_interface` | [show ipv6 neighbors](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ipv6-neighbors.html) |
| `lldp_neighbors`, `lldp_neighbors_interface` | [show lldp neighbors](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lldp-neighbors.html) |
| `lacp_interfaces`, `lacp_interface` | [show lacp interfaces](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lacp-interfaces.html) |
| `bgp_summary` | [show bgp summary](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-summary.html) |
| `ospf_neighbors`, `ospf_neighbors_interface`, `ospfv3_neighbors`, `ospfv3_neighbors_interface` | [show OSPF/OSPF3 neighbor](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ospf-ospf3-neighbor.html) |

The [Junos CLI reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/), [pipe command reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/pipe.html), and [operational-output filtering guide](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/filtering-operational-command.html) define the wider source context.

## Accepted EX/QFX ELS extension

The ELS catalogue is an explicit superset of the common catalogue:

| Query name | Primary source |
|---|---|
| `vlans` | [show vlans](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vlans-bridging-qfx-series.html) |
| `mac_table` | [show ethernet-switching table](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table-qfx-series.html) |
| `stp_bridge` | [show spanning-tree bridge](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-stp-bridge-command.html) |
| `virtual_chassis` | [show virtual-chassis](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-virtual-chassis.html) |

These commands must not appear in the common profile merely because a target reports `juniper_junos`.

## Live measurements, 25 September 2026

Both profiles were run query by query through the released helper 0.3.6 and again through the source of helper 0.3.7 deployed as a candidate runner against vJunos-switch 26.2R1.7 (it reports the model `ex9214`), with an account of the built-in login class `read-only` holding an ed25519 key. The per-query tables, the lab and the device configuration are in [Live lab measurements](../../../../docs/lab-measurements-2026-09-25.md#junos-juniper_junos).

| Profile | Released 0.3.6 | 0.3.7 candidate |
| --- | --- | --- |
| `juniper_junos` | 25 of 25 with exit status 0 | 25 of 25 with exit status 0 |
| `juniper_junos_els` | 29 of 29 with exit status 0 | 28 with exit status 0, `virtual_chassis` `device_cli_error` |

- `arp_interface`, `ipv6_neighbors_interface`, `ospf_neighbors_interface` and `ospfv3_neighbors_interface` take a logical interface. Asked for the physical `ge-0/0/0` they are refused by the proxy before any connection (MCP error `-32009`); enrolled as `irb.10` they answered. Enroll the unit (`ge-0/0/0.0`, `irb.10`), not the port, for these four.
- `show virtual-chassis` on a switch that is not a virtual chassis member answers `error: the virtual-chassis-control subsystem is not running` with exit status 0. Helper 0.3.6 returned it as a successful read; 0.3.7 reports it as `device_cli_error`.
- Junos answers a refusal with exit status 0: `configure` gives `error: unknown command: configure`, `show configuration system login` gives `error: permission denied: system`, an unknown command `error: syntax error, expecting <command>: ...`. Helper 0.3.7 reports these `error:` lines as `device_cli_error`; 0.3.6 returned them as successful reads.

The measured target is a switch image. The claim of `juniper_junos` for routing platforms (MX, SRX, PTX) and every hardware model remain unmeasured, as does AAA command authorization.

## Explicit exclusions

- `show configuration` and abbreviated configuration families, configuration rollback/history, rescue/backup configuration, and configuration database exports are prohibited.
- `show log`, trace output, core dumps, support information, request commands, file display, shell/start-shell, debug, monitor, packet capture, and operational writes are prohibited.
- Only the exact final ` | no-more` suffix is accepted. `save`, `match`, `find`, redirection, chained pipes, and user-provided pipe text are excluded.
- Global `show interfaces extensive` is excluded. Juniper documents a material CPU spike on an EX4300 with thousands of logical interfaces; only an inventory-bound interface form is accepted.
- Full route-table output is excluded; only a summary and typed, inventory-bound single-address lookup are accepted.
- The common profile excludes ELS MAC, VLAN, STP, and Virtual Chassis queries.
- Free-form routing instance, table, interface, peer, and prefix text is not accepted.

## Deferred live-wire candidates

- Routing-instance- or table-scoped route summaries and lookups.
- Per-VLAN MAC, ARP, and neighbor filters.
- Additional chassis/FPC/PIC environmental and optics views.
- Redundancy, cluster, MC-LAG, EVPN/VXLAN, and model-specific fabric summaries.
- Richer Virtual Chassis member diagnostics.

These remain deferred until exact model scope, privilege, output bounds, typed slots, and bytes-on-wire behavior are proven.

## High-volume and operational limitations

High-volume common queries are `interfaces`, `arp_table`, `arp_interface`, `ipv6_neighbors`, `ipv6_neighbors_interface`, `lldp_neighbors`, `lacp_interfaces`, `bgp_summary`, `ospf_neighbors`, and `ospfv3_neighbors`. High-volume ELS additions are `vlans`, `mac_table`, and `stp_bridge`.

`high-volume` is only a maintainer scheduling advisory; it changes no authorization, policy opt-in, rate accounting, timeout, snapshot or cache behavior, or the 2,000,000-byte capture cap. A query not listed as high-volume is not promised to be small, cheap, or bounded.

- Junos 23.4R2 covers materially different hardware and virtual products. Chassis sensors, optics, LLDP/LACP, switching, routing protocols, and Virtual Chassis support vary by model, line card, license, and feature configuration.
- CLI reference privilege is commonly `view`, but a login class can further restrict command regexes. Local RBAC and TACACS+/RADIUS authorization must allow only the exact catalogue plus the fixed no-more suffix.
- AAA rejection, absent hierarchy, an inactive protocol, or an unsupported PIC must be surfaced as such; the runtime must not broaden the query as a fallback.
- Hardware inventory, alarms, topology, peer identities, interface descriptions, routing data, and optical levels are operationally sensitive.
- Source validation does not prove SSH transport behavior. Live-wire tests must verify prompt and banner handling, command echo, the exact pipe suffix, absence of configuration mode, pagination behavior, output size, and timeout handling.
