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
| `route_table` | [show route](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route.html) |
| `route_instances` | [show route instance](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-instance.html) |
| `ospf_interfaces` | [show OSPF/OSPF3 interface](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ospf-ospf3-interface.html) |
| `lldp_neighbors_detail` | [show lldp neighbors](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lldp-neighbors.html) (`detail`) |
| `interfaces_descriptions` | [show interfaces (descriptions option)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-interfaces-m-series-and-t-series-management-and-internal-ethernet.html) |
| `routing_engine` | [show chassis routing-engine](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-routing-engine.html) |
| `fpc` | [show chassis fpc](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-fpc.html) |
| `storage` | [show system storage](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-storage.html) |
| `licenses` | [show system license](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-license-security.html) |
| `commit_history` | [show system commit](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-commit.html) |
| `ntp_status` | [show ntp status](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ntp-status.html) |
| `ntp_associations` | [show ntp associations](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ntp-associations.html) |
| `vrrp_summary` | [show vrrp](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vrrp.html) |
| `bfd_sessions` | [show bfd session](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bfd-session.html) |
| `log_messages`, `log_interactive_commands` | [show log](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-log.html); the fixed `| last 200` pipe in front of ` | no-more` is the only other pipe accepted |

The [Junos CLI reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/), [pipe command reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/pipe.html), and [operational-output filtering guide](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/filtering-operational-command.html) define the wider source context.

## Accepted EX/QFX ELS extension

The ELS catalogue is an explicit superset of the common catalogue:

| Query name | Primary source |
|---|---|
| `vlans` | [show vlans](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vlans-bridging-qfx-series.html) |
| `mac_table` | [show ethernet-switching table](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table-qfx-series.html) |
| `stp_bridge` | [show spanning-tree bridge](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-stp-bridge-command.html) |
| `virtual_chassis` | [show virtual-chassis](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-virtual-chassis.html) |
| `virtual_chassis_ports` | [show virtual-chassis vc-port](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-virtual-chassis-vc-port.html) |
| `ethernet_switching_interfaces`, `ethernet_switching_interface` | [show ethernet-switching interfaces](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-interfaces-qfx-series.html) |
| `mac_table_interface`, `mac_table_address` | [show ethernet-switching table](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table-qfx-series.html) |
| `stp_interfaces` | [show spanning-tree interface](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-stp-interface-command.html) |
| `poe_interfaces` | [show poe interface](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-poe-interface.html) |
| `poe_controller` | [show poe controller](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-poe-controller.html) |
| `dot1x_interfaces` | [show dot1x interface](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-dot1x-interface-802-1x-security.html) |
| `dhcp_security_bindings` | [show dhcp-security binding](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-dhcp-security-binding.html) |

These commands must not appear in the common profile merely because a target reports `juniper_junos`.

## Junos virtual-image compatibility

Compatibility is scoped to vJunos-switch 26.2R1.7 and its documented read-only role. LACP, spanning-tree and routing reads depend on the configured features and permissions; a virtual-image profile does not establish behavior for every physical model. See [compatibility boundaries](../../../../docs/compatibility-boundaries.md).

| Profile | Measured with the Helper engine before NetOps 1.0 |
| --- | --- |
| `juniper_junos` | 25 of 25 with exit status 0 |
| `juniper_junos_els` | 28 with exit status 0, `virtual_chassis` `device_cli_error` |

- `arp_interface`, `ipv6_neighbors_interface`, `ospf_neighbors_interface` and `ospfv3_neighbors_interface` take a logical interface. Asked for the physical `ge-0/0/0` they are refused by the proxy before any connection (MCP error `-32009`); enrolled as `irb.10` they answered. Enroll the unit (`ge-0/0/0.0`, `irb.10`), not the port, for these four.
- `show virtual-chassis` on a switch that is not a virtual chassis member answers `error: the virtual-chassis-control subsystem is not running` with exit status 0 (measured before NetOps 1.0). Helper reports it as `device_cli_error`, not as a successful read.
- Junos answers a refusal with exit status 0: `configure` gives `error: unknown command: configure`, `show configuration system login` gives `error: permission denied: system`, an unknown command `error: syntax error, expecting <command>: ...` (measured before NetOps 1.0). Helper reports these `error:` lines as `device_cli_error`, not as successful reads.

The rows added in NetOps 1.0.7 were run, with every other template, on a vJunos-switch 26.2R1.7 lab node on 2026-11-09 (outputs in `tests/fixtures/real/juniper_junos_els/vjunosswitch_26.2R1.7`, generated tables below). `verified: docs-only` are the four templates the virtual platform refuses: Virtual Chassis (`virtual_chassis`, `virtual_chassis_ports`: `virtual-chassis-control` subsystem not running) and PoE (`poe_interfaces`, `poe_controller`: PoE subsystem not running). Measured but empty or "not configured" on the image, so only their empty answer is verified: `dot1x_interfaces`, `dhcp_security_bindings`, `bfd_sessions` (0 sessions), `interface_optics`, `lacp_interfaces` (an aggregate whose member is down prints nothing) and `bgp_summary` (`BGP is not running`, no licence key); the populated layouts of the last two come from the Juniper CLI reference pages cited above (`tests/fixtures/docs/juniper_junos*/bgp_summary.txt`, `lacp_interfaces.txt`). VRRP, NTP, RSTP and an aggregate were configured temporarily during the capture and removed afterwards. MX bridge-domain and SRX session reads of the design are not in the catalogue.

The measured target is a switch image. The claim of `juniper_junos` for routing platforms (MX, SRX, PTX) and every hardware model remain unmeasured, as does AAA command authorization.

## Explicit exclusions

- `show configuration` and abbreviated configuration families, configuration rollback/history, rescue/backup configuration, and configuration database exports are prohibited.
- `show log` is prohibited except the two fixed bounded templates `log_messages` (`show log messages | last 200 | no-more`) and `log_interactive_commands` (`show log interactive-commands | last 200 | no-more`); trace output, core dumps, support information, request commands, file display, shell/start-shell, debug, monitor, packet capture, and operational writes are prohibited. The built-in `read-only` class returns `permission_denied` for these logs, a known limitation. Reading a specific log file requires command permission (`trace`) and file-read access beyond that class; NetOps does not recommend the broader permissions or a class with `maintenance`. Keep the built-in class and forward logs through syslog (see [read-only accounts](../read-only-accounts.md#junos-os)).
- Only the exact final ` | no-more` suffix is accepted, after the one fixed `| last 200` of the two log templates. `save`, `match`, `find`, redirection, other chained pipes, and user-provided pipe text are excluded. `show configuration`, `show system rollback compare` and `| display json` are not used: every template reads the text output.
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

## Lab measurements (GNS3 lab, 2026-11-08/09)

Every template was run on the lab images with the read-only account; the stored outputs are in `tests/fixtures/real`. Regenerated by `tests/support/render_lab_measurements.py`.

### Junos OS (ELS)

<!-- lab-measurements:begin -->

| Template | Command | vJunos-switch 26.2R1.7 | verified |
|---|---|---|---|
| `version` | `show version | no-more` | ok, 73 lines | live |
| `uptime` | `show system uptime | no-more` | ok, 6 lines | live |
| `system_alarms` | `show system alarms | no-more` | ok, 3 lines | live |
| `chassis_alarms` | `show chassis alarms | no-more` | ok, 3 lines | live |
| `hardware` | `show chassis hardware | no-more` | ok, 10 lines | live |
| `environment` | `show chassis environment | no-more` | empty | live |
| `interfaces` | `show interfaces terse | no-more` | ok, 68 lines | live |
| `interface_details` | `show interfaces {interface} extensive | no-more` | ok, 87 lines | live |
| `interface_optics` | `show interfaces diagnostics optics {interface} | no-more` | empty | live |
| `route_summary` | `show route summary | no-more` | ok, 19 lines | live |
| `route_lookup` | `show route {address} detail | no-more` | ok, 16 lines | live |
| `ipv6_route_lookup` | `show route {address} detail | no-more` | empty | live |
| `arp_table` | `show arp no-resolve | no-more` | ok, 10 lines | live |
| `arp_interface` | `show arp no-resolve interface {interface} | no-more` | ok, 7 lines | live |
| `ipv6_neighbors` | `show ipv6 neighbors | no-more` | empty | live |
| `ipv6_neighbors_interface` | `show ipv6 neighbors interface {interface} | no-more` | empty | live |
| `lldp_neighbors` | `show lldp neighbors | no-more` | ok, 2 lines | live |
| `lldp_neighbors_interface` | `show lldp neighbors interface {interface} | no-more` | ok, 59 lines | live |
| `lacp_interfaces` | `show lacp interfaces | no-more` | empty | live |
| `lacp_interface` | `show lacp interfaces {interface} | no-more` | empty | live |
| `bgp_summary` | `show bgp summary | no-more` | not configured | live |
| `ospf_neighbors` | `show ospf neighbor | no-more` | ok, 5 lines | live |
| `ospf_neighbors_interface` | `show ospf neighbor interface {interface} | no-more` | ok, 5 lines | live |
| `ospfv3_neighbors` | `show ospf3 neighbor | no-more` | ok, 1 line | live |
| `ospfv3_neighbors_interface` | `show ospf3 neighbor interface {interface} | no-more` | ok, 1 line | live |
| `route_table` | `show route | no-more` | ok, 41 lines | live |
| `route_instances` | `show route instance | no-more` | ok, 18 lines | live |
| `ospf_interfaces` | `show ospf interface brief | no-more` | ok, 3 lines | live |
| `lldp_neighbors_detail` | `show lldp neighbors detail | no-more` | ok, 59 lines | live |
| `interfaces_descriptions` | `show interfaces descriptions | no-more` | empty | live |
| `routing_engine` | `show chassis routing-engine | no-more` | ok, 36 lines | live |
| `fpc` | `show chassis fpc | no-more` | ok, 14 lines | live |
| `storage` | `show system storage | no-more` | ok, 4 lines | live |
| `licenses` | `show system license | no-more` | ok, 3 lines | live |
| `commit_history` | `show system commit | no-more` | ok, 9 lines | live |
| `ntp_status` | `show ntp status | no-more` | ok, 9 lines | live |
| `ntp_associations` | `show ntp associations no-resolve | no-more` | ok, 3 lines | live |
| `vrrp_summary` | `show vrrp summary | no-more` | ok, 3 lines | live |
| `bfd_sessions` | `show bfd session | no-more` | ok, 3 lines | live |
| `log_messages` | `show log messages | last 200 | no-more` | refused to the read-only account, answered to admin | live |
| `log_interactive_commands` | `show log interactive-commands | last 200 | no-more` | refused to the read-only account, answered to admin | live |
| `vlans` | `show vlans brief | no-more` | ok, 9 lines | live |
| `mac_table` | `show ethernet-switching table | no-more` | ok, 20 lines | live |
| `stp_bridge` | `show spanning-tree bridge | no-more` | ok, 16 lines | live |
| `virtual_chassis` | `show virtual-chassis status | no-more` | feature off or not supported by the image | docs-only |
| `virtual_chassis_ports` | `show virtual-chassis vc-port | no-more` | feature off or not supported by the image | docs-only |
| `ethernet_switching_interfaces` | `show ethernet-switching interface | no-more` | ok, 15 lines | live |
| `ethernet_switching_interface` | `show ethernet-switching interface {interface} detail | no-more` | ok, 41 lines | live |
| `mac_table_interface` | `show ethernet-switching table interface {interface} | no-more` | ok, 33 lines | live |
| `mac_table_address` | `show ethernet-switching table {mac} | no-more` | ok, 11 lines | live |
| `stp_interfaces` | `show spanning-tree interface | no-more` | ok, 6 lines | live |
| `poe_interfaces` | `show poe interface | no-more` | feature off or not supported by the image | docs-only |
| `poe_controller` | `show poe controller | no-more` | feature off or not supported by the image | docs-only |
| `dot1x_interfaces` | `show dot1x interface | no-more` | empty | live |
| `dhcp_security_bindings` | `show dhcp-security binding | no-more` | empty | live |

<!-- lab-measurements:end -->
