# Cisco CLI references

Baseline: Catalyst IOS 15.2(7)E, Catalyst IOS-XE 17.15.x, and Nexus 9000 NX-OS 10.5(x).

Audit date: 2026-09-09.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

## Profiles

- `cisco_ios`: conservative Catalyst switch profile audited against IOS 15.2(7)E on Catalyst 2960-X. It is not a generic profile for every IOS router.
- `cisco_xe`: conservative Catalyst switch profile audited against IOS-XE 17.15.x on Catalyst 9300.
- `cisco_nxos`: Nexus 9000 profile audited separately against NX-OS 10.5(x). Similar command names do not imply identical syntax or output across IOS and NX-OS.

IOS probe source links: [IOS ping and ping vrf reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/monitor_event-trace_through_Q.html), [IOS IPv6 ping reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-m1.html), [IOS traceroute reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/Cisco_IOS_Configuration_Fundamentals_Command_Reference/test_cable-diagnostics_through_xmodem.html).

## Accepted Phase-1 queries and source mapping

| Profile | Query names | Primary source |
|---|---|---|
| `cisco_ios` | `version`, `clock`, `inventory`, `environment` | [IOS 15.2(7)E consolidated command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html), [complete PDF](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.pdf), and [interface/hardware commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/consolidated_guide/command_reference/b_consolidated_2960x_1522e_cr/b_consolidated_152ex_2960-X_cr_chapter_01010.html) |
| `cisco_ios` | `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `interface_details`, `interface_errors` | [IOS 15.2(7)E command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) and [interface/hardware PDF](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/int_hw_components/command/reference/b_int_1522e_2960x_cr.pdf) |
| `cisco_ios` | `route_summary`, `route_lookup`, `ipv6_route_lookup`, `arp_table`, `ipv6_neighbors` | [IOS 15.2(7)E IPv6 unicast routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/m_ipv6_152ex_ipv6unirt_cg.html) and [IOS 15.2(2)E IPv6 guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/ipv6/configuration_guide/b_ipv6_1522e_2960x_cg/b_ipv6_1522e_2960x_cg_chapter_010.html) |
| `cisco_ios` | `mac_table`, `vlans`, `lag_summary`, `lacp_neighbors`, `stp_summary`, `lldp_neighbors`, `cdp_neighbors` | [IOS 15.2(7)E consolidated reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) and [Cisco IOS LACP reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cether/command/ce-cr-book/ce-s1.html) |
| `cisco_ios` | `cpu`, `memory`, `bgp_summary`, `ospf_neighbors`, `hsrp_summary`, `vrrp_summary` | [IOS 15.2(7)E consolidated reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html); availability still depends on image and enabled feature |
| `cisco_xe` | Same query names as `cisco_ios`; `environment` deliberately uses its IOS-XE spelling | [IOS-XE 17.15 command-reference index](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html), [complete PDF](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr.pdf), [IP routing commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/unicast_routing_commands.html), and [IP addressing services](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/ip_addressing_services_commands.html) |
| `cisco_nxos` | `version`, `clock`, `inventory`, `environment`, `cpu`, `memory` | [NX-OS 10.5(x) show-command index](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/n9k_show_commands_1051_CLT_chapter.html) and [complete PDF](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `interface_details`, `interface_errors`, `vlans`, `mac_table`, `arp_table`, `ipv6_neighbors` | [NX-OS 10.5(x) show-command index](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/n9k_show_commands_1051_CLT_chapter.html) and [I show commands](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/m_i_showcmds.html) |
| `cisco_nxos` | `lag_summary`, `lacp_neighbors`, `stp_summary`, `lldp_neighbors`, `cdp_neighbors`, `route_summary`, `route_lookup`, `ipv6_route_lookup`, `bgp_sessions`, `ospf_neighbors`, `hsrp_summary`, `vrrp_summary` | [NX-OS 10.5(x) complete show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `vpc_status`, `vpc_peer_keepalive`, `vpc_role` | [NX-OS 10.5(x) show-command index](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/n9k_show_commands_1051_CLT_chapter.html); older [Nexus 9000 vPC guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/7-x/interfaces/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_Interfaces_Configuration_Guide_7x/configuring_vpcs.html) is retained only as command-lineage corroboration |

The NetOps 1.0.7 additions are the same on `cisco_ios` and `cisco_xe` (the IOS rows cite the IOS 15.2(7)E consolidated command reference, the XE rows the IOS-XE 17.15 complete command reference): `route_table`, `ospf_interfaces`, `stp_tree`, `stp_root`, `stp_inconsistent`, `stp_vlan`, `err_disabled`, `errdisable_recovery`, `interfaces_description`, `interfaces_trunk`, `interface_switchport`, `interface_transceiver`, `power_inline`, `vtp_status`, `vlan_details`, `ntp_status`, `ntp_associations`, `stack_members`, `stack_ports`, `log_messages` (the fixed `show logging`, bounded by the device's log buffer) and, XE only, `platform_resources`. They were run on IOSv 15.9(3)M12, IOSvL2 15.2(20200924) in the lab; `interface_transceiver`, `power_inline`, `stack_members`, `stack_ports`, `platform_resources` and the environment reads cannot be answered by those images and are `verified: docs-only`. Their output is in `tests/fixtures/real/cisco_ios`. On a router image (IOSv) the switch-only reads (`interfaces`, `mac_table`, `vlans`, STP, trunk, err-disable, PoE) are answered `Line has invalid autocommand "..."`, which the Helper classifies like a refused command (`permission_denied`).

The NetOps 1.0.7 additions for `cisco_nxos` (all cite the [NX-OS 10.5(x) complete show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf)): `route_table`, `ospf_interfaces`, `bgp_summary`, `stp_tree`, `stp_root`, `stp_blocked`, `stp_inconsistent`, `stp_vlan`, `err_disabled`, `errdisable_recovery`, `interfaces_description`, `interfaces_trunk`, `interfaces_counters_errors`, `interface_switchport`, `interface_transceiver`, `vlan_details`, `ntp_status`, `ntp_associations` (`show ntp peer-status`), `system_resources`, `reset_reason`, `modules`, `license_usage`, `redundancy_status`, `features`, `vrfs`, `bfd_neighbors`, `vpc_consistency`, `vpc_orphan_ports`, `dhcp_snooping_binding`, `access_lists` and `log_messages` (the fixed `show logging last 200`, newest 200 lines). They were run on the Nexus 9300v 9.3(12) lab node with the built-in `network-operator` role; the outputs are in `tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12`. Features that are off answer `Syntax error while parsing` (`unsupported`: `hsrp_summary`, `vrrp_summary`, `dhcp_snooping_binding`, `bgp_summary` and `bfd_neighbors` until the feature is enabled); `show boot` and `show accounting log` are refused to `network-operator` (`% Permission denied for the role`) and are therefore not in the catalogue. The NX-OS rows are `verified: lab` (measured) except those listed as `docs-only` in the generated tables below. `show running-config diff` stays out of the catalogue, because configuration text can carry secrets.

Additional official Cisco references retained from the audit are the [Catalyst 9300 command-reference release list](https://www.cisco.com/c/en/us/support/switches/catalyst-9300-series-switches/products-command-reference-list.html), the [IOS-XE 17.15 IP Routing Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/rtng/b_1715_rtng_9300_cg.pdf), and the earlier [IOS-XE 17.3 interface and hardware command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-3/command_reference/b_173_9300_cr/interface_and_hardware_commands.html) used only to check command lineage.

### Management diagnostics (G56/G74/G95)

Each query is independently enrolled. Source IDs and URLs below are the existing
per-query records in `query-sources.json`.

| Profile | Query | Exact command | Sources |
|---|---|---|---|
| `cisco_ios` | `aaa_servers` | `show aaa servers` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `radius_statistics` | `show radius statistics` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `tacacs_statistics` | `show tacacs` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `snmp_statistics` | `show snmp` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `snmp_engine_id` | `show snmp engineID` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `dns_hosts` | `show hosts` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `users` | `show users` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `ssh_sessions` | `show ssh` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_ios` | `lines` | `show line` | [C-FFD149196371](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) |
| `cisco_xe` | `aaa_servers` | `show aaa servers` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `radius_statistics` | `show radius statistics` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `tacacs_statistics` | `show tacacs` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `snmp_statistics` | `show snmp` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `snmp_engine_id` | `show snmp engineID` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `dns_hosts` | `show hosts` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `users` | `show users` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `ssh_sessions` | `show ssh` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_xe` | `lines` | `show line` | [C-861E8F0777A1](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/1715_9300_cr_CLT_chapter.html) |
| `cisco_nxos` | `dns_hosts` | `show hosts` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `snmp_statistics` | `show snmp` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `snmp_engine_id` | `show snmp engineID` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `aaa_authentication` | `show aaa authentication` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `radius_statistics` | `show radius-server statistics {address}` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `tacacs_statistics` | `show tacacs-server statistics {address}` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `users` | `show users` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `ssh_server` | `show ssh server` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |
| `cisco_nxos` | `configuration_sessions` | `show configuration session summary` | [C-845C68D3A01D](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf) |

For `cisco_nxos`, `radius_statistics` and `tacacs_statistics` require one IPv4
`address` enrolled in `addresses`. `configuration_sessions` reads only session
metadata through the exact `show configuration session summary` command; it does
not display configuration contents. Other configuration commands, suffixes and
abbreviations remain excluded.

#### Valid empty management output

| Profile | Query | Meaning |
|---|---|---|
| `cisco_ios` | `aaa_servers` | empty output means the device returned no AAA server state; it does not establish server availability. |
| `cisco_ios` | `tacacs_statistics` | empty output means the device returned no TACACS server state or counters; it does not establish server availability. |
| `cisco_xe` | `aaa_servers` | empty output means the device returned no AAA server state; it does not establish server availability. |
| `cisco_xe` | `tacacs_statistics` | empty output means the device returned no TACACS server state or counters; it does not establish server availability. |
| `cisco_xe` | `vrfs` | empty output means no VRFs were returned. |
| `cisco_xe` | `vrf_arp_table` | empty output means no ARP entries were returned; it does not establish whether the named VRF exists. |
| `cisco_xe` | `ospfv3_neighbors` | empty output means no OSPFv3 neighbors were returned. |
| `cisco_xe` | `ipv6_interface_details` | empty output means no IPv6 interface state was returned; an interface without IPv6 can answer this way. |
| `cisco_xe` | `bfd_neighbors` | empty output means no BFD sessions were returned. |
| `cisco_xe` | `route_maps` | empty output means no route maps were returned. |
| `cisco_ios` | `hsrp_detail` | empty output means the device returned no HSRP groups. |
| `cisco_xe` | `hsrp_detail` | empty output means the device returned no HSRP groups. |
| `cisco_ios` | `vrrp_detail` | empty output means the device returned no VRRP groups. |
| `cisco_xe` | `vrrp_detail` | empty output means the device returned no VRRP groups. |
| `cisco_ios` | `object_tracking` | empty output means the device returned no tracked objects. |
| `cisco_xe` | `object_tracking` | empty output means the device returned no tracked objects. |
| `cisco_ios` | `log_history` | empty output means the selected log page has no matching lines. Coverage records how much of the window was available. |
| `cisco_xe` | `log_history` | empty output means the selected log page has no matching lines. Coverage records how much of the window was available. |
| `cisco_xe` | `ip_source_guard` | empty output means no source guard filters were reported. |
| `cisco_ios` | `etherchannel_detail` | empty output means no EtherChannel groups were returned. |
| `cisco_ios` | `lacp_internal` | empty output means no LACP channel groups were returned. |
| `cisco_xe` | `etherchannel_detail` | empty output means no detail for the selected group was returned. |
| `cisco_xe` | `lacp_internal` | empty output means no LACP channel groups were returned. |

These queries have `empty_allowed=True`: an empty response with a successful
exit status is a valid read. CLI errors remain errors.

### Interface-name grammar sources

The following first-party configuration guides constrain the typed interface-name grammar for `interface_details` and `interface_errors`; they also document the interface types named by `interfaces`, `ip_interfaces`, and `ipv6_interfaces`. Configuration examples in these sources do not make any configuration command callable.

| Registry ID | Official document and baseline | Profiles | URL |
|---|---|---|---|
| C-IOS-1527-CONFIG | Catalyst 2960-X IOS 15.2(7)E Consolidated Configuration Guide | `cisco_ios` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg.pdf |
| C-XE-1715-INTERFACE-CMD | Catalyst 9300 IOS-XE 17.15 Interface and Hardware Commands | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/interface_and_hardware_commands.html |
| C-XE-1715-INTERFACE-GUIDE | Catalyst 9300 IOS-XE 17.15 Interfaces and Hardware Configuration Guide | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/int_hw/b_1715_int_and_hw_9300_cg.pdf |
| C-XE-176-LAYER2-CMD | Catalyst 9300 IOS XE Layer 2/3 Commands | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/command_reference/b_176_9300_cr/layer_2_3_commands.html |
| C-XE-1714-POE | Catalyst 9300 IOS XE Power over Ethernet | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/configuration_guide/int_hw/b_1714_int_and_hw_9300_cg/configuring_poe.html |
| C-XE-1715-LLDP | Catalyst 9200 IOS XE LLDP Configuration | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-15/configuration_guide/int_and_hw/b_1715_int_and_hw_9200_cg/configuring_lldp__lldp_med__and_wired_location_service.html |
| C-NXOS-105-BASIC-INTERFACE | Nexus 9000 NX-OS 10.5(x): Configuring Basic Interface Parameters | `cisco_nxos` | https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-105x/m_configuring_basic_interface_parameters_93x.html |
| C-NXOS-105-L3-INTERFACE | Nexus 9000 NX-OS 10.5(x): Configuring Layer 3 Interfaces | `cisco_nxos` | https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-105x/m_configuring_layer_3_interfaces_9x.html |
| C-NXOS-105-PORT-CHANNEL | Nexus 9000 NX-OS 10.5(x): Configuring Port Channels | `cisco_nxos` | https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-105x/m_configuring_port_channels_93x.html |
| C-NXOS-105-IP-TUNNEL | Nexus 9000 NX-OS 10.5(x): Configuring IP Tunnels | `cisco_nxos` | https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-105x/m_configuring_ip_tunnels_9x.html |


Besides the Catalyst names, `cisco_ios` and `cisco_xe` accept `Ethernet<slot>/<port>` (abbreviation `Et`, slot and port 0-15, no leading zeros, no subinterface) as a physical interface: the fixed Ethernet ports of Cisco routers and of the IOL and IOL-L2 images are named this way.

The NX-OS neighbor-table command is `show ipv6 neighbor`. The earlier `show ipv6 icmp neighbor` wording was corrected: the 10.5 I-command reference uses the latter prefix for narrower ICMPv6 subcommands, while the operational neighbor table is documented as `show ipv6 neighbor`.

## Cisco virtual-image compatibility

Cisco virtual-image profiles have distinct firmware, privilege, feature and transport boundaries. They do not establish that every command exists on Catalyst or Nexus hardware. See [compatibility boundaries](../../../../docs/compatibility-boundaries.md).

| Profile | Image | Account | Measured with the Helper engine before NetOps 1.0 |
| --- | --- | --- | --- |
| `cisco_xe` | IOL 17.18.2 (`X86_64BI_LINUX-ADVENTERPRISEK9-M`, router) | privilege 1, RSA 3072 key | 21 of 27 with exit status 0, 6 `device_cli_error` |
| `cisco_xe` | IOL-L2 17.18.2 (`X86_64BI_LINUX_L2-ADVENTERPRISEK9-M`) | the same | 26 of 27 with exit status 0, 1 `device_cli_error` |
| `cisco_ios` | IOSv 15.9(3)M12 (router) | privilege 1, RSA 3072 key, `legacy_ssh: "rsa-sha1-dh14"` | 19 of 27 with exit status 0, 8 `device_cli_error` |
| `cisco_ios` | IOSvL2 15.2(20200924) | the same | 26 of 27 with exit status 0, 1 `device_cli_error` |
| `cisco_nxos` | Nexus 9300v 9.3(12) | role `network-operator`, RSA 3072 key | 30 answered, 29 with exit status 0 and `lldp_neighbors` exit status 244 once the HSRP, VRRP and vPC features were enabled |
| `cisco_nxos` | Nexus 9500v 9.3(12) | the same | 30 of 30 with exit status 0 |

What these runs established:

- **IOS and IOS-XE refuse with exit status 0.** A command the image does not implement, and one above the account's privilege (`show running-config`, `configure terminal`), is answered `Line has invalid autocommand "<command>"` with exit status 0 (measured before NetOps 1.0). Helper reports it as `device_cli_error`. Every `device_cli_error` above is a command the image lacks: the router images have no `show interfaces status`, `show vlan brief`, `show mac address-table`, `show etherchannel summary` or `counters errors` form, IOSv also no `show lacp neighbor` and `show spanning-tree summary`, and none of the four IOS and IOS-XE images has environment sensors.
- **The IOL images have five VTY lines.** A host key scan that opens one connection per key type at once leaves the device still closing them when the real connection comes, and the device resets it. Core therefore scans one key type at a time.
- **IOSv and IOSvL2 offer only SHA-1 key exchange methods** and an `ssh-rsa` host key. The per-device profile `legacy_ssh: "rsa-sha1-dh14"` adds exactly `diffie-hellman-group14-sha1` for such a device; `diffie-hellman-group1-sha1` and `diffie-hellman-group-exchange-sha1` stay refused.
- **IOL names its ports `Ethernet<slot>/<port>`**, which the Helper accepts for `cisco_ios` and `cisco_xe` (see the interface grammar above); `interface_details` for `Ethernet0/1` answered with exit status 0 on both IOL images, and `interface_errors` for it on the L2 image (the router image has no `counters errors` form).
- **NX-OS refuses with a non-zero status.** An unknown command, and an HSRP, VRRP or vPC command while that feature is disabled, gives `Syntax error while parsing '<command>'` with exit status 16; a command above the role, such as `show running-config`, `% Permission denied for the role` with exit status 30 (measured before NetOps 1.0). Helper reports both as `device_cli_error`. `show lldp neighbors detail` without a neighbour ends with `ERROR: No neighbour information` and exit status 244 and stays a successful read. NX-OS 9.3(12) offers current key exchange and an RSA host key with `rsa-sha2-256`; no legacy exception is needed.

Not measured: Catalyst IOS and IOS-XE hardware, NX-OS 10.x, parser views, and AAA or TACACS+ command authorization.

## Explicit exclusions

- All running, startup, full, backup, and abbreviated configuration-display forms are outside Phase 1.
- `show key chain` and every abbreviated key/key-chain form are prohibited. Cisco documents that key-chain output represents configured key material and can offer a decrypt mode; it is not a diagnostic-safe surface. See the [NX-OS 10.5 keychain-management guide](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-105x/m-configuring-keychain-management.html) and [security guide PDF](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-105x.pdf).
- `show tech`, `show tech-support`, support bundles, core files, file display, and crash data are prohibited because they are unbounded, expensive, and can aggregate configurations and credentials. The breadth of this family is visible in the [NX-OS 10.5 T show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/m_t_showcmds.html).
- `show logging`, debug, clear, test, reload, restart, install, guestshell/bash, packet capture, Ethanalyzer, and commands that write or export data are excluded.
- Free-form CLI, arbitrary pipes/redirection, and user-selected VRF/process/neighbor text are not accepted.

## Deferred live-wire candidates

- Scoped ARP/ND/MAC/LLDP/CDP/LACP and routing-protocol queries.
- Optics/transceiver diagnostics, stack/member detail, and model-specific environmental commands.
- IPv6 BGP summaries and additional OSPFv3 summaries.
- Nexus model-specific forwarding and vPC consistency views.

These require exact per-model syntax, typed inventory renderers, bounded-output assessment, AAA behavior, and a wire test proving that only the intended EXEC command is sent.

## High-volume and operational limitations

High-volume in IOS and IOS-XE: `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `cpu`, `memory`, `arp_table`, `ipv6_neighbors`, `mac_table`, `vlans`, `lag_summary`, `lacp_neighbors`, `stp_summary`, `lldp_neighbors`, `cdp_neighbors`, `bgp_summary`, `ospf_neighbors`, `hsrp_summary`, and `vrrp_summary`.

High-volume in NX-OS: `cpu`, `memory`, `interfaces`, `ip_interfaces`, `ipv6_interfaces`, `vlans`, `mac_table`, `arp_table`, `ipv6_neighbors`, `lag_summary`, `lacp_neighbors`, `stp_summary`, `lldp_neighbors`, `cdp_neighbors`, `bgp_sessions`, `ospf_neighbors`, `hsrp_summary`, `vrrp_summary`, and `vpc_status`.

`high-volume` is only a maintainer scheduling advisory; it changes no authorization, policy opt-in, rate accounting, timeout, snapshot or cache behavior, or the 2,000,000-byte capture cap. A query not listed as high-volume is not promised to be small, cheap, or bounded.

- Feature commands can be absent because of hardware model, installed image, license, feature activation, VRF, or stack/vPC role. Absence is not authorization to fall back to a broader command.
- EXEC privilege and local syntax support do not imply AAA authorization. TACACS+/RADIUS command authorization and CLI views can reject individual commands; deployment must grant only the catalogued commands.
- Some detail commands disclose topology, serial numbers, MAC/IP addresses, peer identifiers, and interface descriptions. These are operationally sensitive even though they are not credentials.
- Source review does not replace live-wire verification. Each driver/profile needs testing for privilege prompts, paging behavior, output size, command echo, timeout, and confirmation that no terminal/configuration command is emitted.

## Lab measurements (GNS3 lab, 2026-11-08)

Every template was run on the lab images with the read-only account; the stored outputs are in `tests/fixtures/real`. Regenerated by `tests/support/render_lab_measurements.py`.

<!-- lab-measurements:begin -->

| Template | Command | IOSv 15.9(3)M12 (router) | IOSvL2 15.2(20200924) | verified |
|---|---|---|---|---|
| `aaa_servers` | `show aaa servers` | - | - | docs-only |
| `radius_statistics` | `show radius statistics` | - | - | docs-only |
| `tacacs_statistics` | `show tacacs` | - | - | docs-only |
| `snmp_statistics` | `show snmp` | - | - | docs-only |
| `snmp_engine_id` | `show snmp engineID` | - | - | docs-only |
| `dns_hosts` | `show hosts` | - | - | docs-only |
| `users` | `show users` | - | - | docs-only |
| `ssh_sessions` | `show ssh` | - | - | docs-only |
| `lines` | `show line` | - | - | docs-only |
| `version` | `show version` | ok, 44 lines | ok, 41 lines | live |
| `clock` | `show clock` | ok, 4 lines | ok, 2 lines | live |
| `interfaces` | `show interfaces status` | not supported by the image | ok, 8 lines | live |
| `ip_interfaces` | `show ip interface brief` | ok, 11 lines | ok, 10 lines | live |
| `ipv6_interfaces` | `show ipv6 interface brief` | ok, 17 lines | ok, 17 lines | live |
| `route_summary` | `show ip route summary` | ok, 14 lines | ok, 9 lines | live |
| `cpu` | `show processes cpu` | ok, 360 lines | ok, 285 lines | live |
| `memory` | `show processes memory` | ok, 367 lines | ok, 292 lines | live |
| `interface_details` | `show interfaces {interface}` | ok, 30 lines | ok, 28 lines | live |
| `route_lookup` | `show ip route {address}` | ok, 9 lines | ok, 2 lines | live |
| `ipv6_route_lookup` | `show ipv6 route {address}` | ok, 4 lines | ok, 2 lines | live |
| `inventory` | `show inventory` | ok, 5 lines | empty | live |
| `environment` | `show env all` | not supported by the image | not supported by the image | docs-only |
| `interface_errors` | `show interfaces {interface} counters errors` | not supported by the image | empty | live |
| `arp_table` | `show ip arp` | ok, 12 lines | ok, 17 lines | live |
| `ipv6_neighbors` | `show ipv6 neighbors` | empty | empty | live |
| `mac_table` | `show mac address-table` | not supported by the image | ok, 23 lines | live |
| `vlans` | `show vlan brief` | not supported by the image | ok, 12 lines | live |
| `lag_summary` | `show etherchannel summary` | not supported by the image | ok, 23 lines | live |
| `lacp_neighbors` | `show lacp neighbor` | not supported by the image | empty | live |
| `stp_summary` | `show spanning-tree summary` | refused to the read-only account, answered to admin | ok, 22 lines | live |
| `lldp_neighbors` | `show lldp neighbors detail` | ok, 134 lines | ok, 228 lines | live |
| `cdp_neighbors` | `show cdp neighbors detail` | ok, 80 lines | ok, 74 lines | live |
| `bgp_summary` | `show ip bgp summary` | not configured | not configured | live |
| `ospf_neighbors` | `show ip ospf neighbor` | ok, 8 lines | empty | live |
| `hsrp_summary` | `show standby brief` | empty | empty | live |
| `vrrp_summary` | `show vrrp brief` | ok, 4 lines | ok, 2 lines | live |
| `interfaces_counters_errors` | `show interfaces counters errors` | - | - | docs-only |
| `interfaces_details` | `show interfaces` | ok, 152 lines | ok, 178 lines | live |
| `route_table` | `show ip route` | ok, 31 lines | ok, 22 lines | live |
| `ospf_interfaces` | `show ip ospf interface brief` | ok, 6 lines | empty | live |
| `stp_tree` | `show spanning-tree` | not configured | ok, 78 lines | live |
| `stp_root` | `show spanning-tree root` | not supported by the image | ok, 9 lines | live |
| `stp_inconsistent` | `show spanning-tree inconsistentports` | refused to the read-only account, answered to admin | refused to the read-only account, answered to admin | live |
| `stp_vlan` | `show spanning-tree vlan {vlan_id}` | not supported by the image | ok, 20 lines | live |
| `err_disabled` | `show interfaces status err-disabled` | not supported by the image | empty | live |
| `errdisable_recovery` | `show errdisable recovery` | not supported by the image | ok, 34 lines | live |
| `interfaces_description` | `show interfaces description` | ok, 11 lines | ok, 10 lines | live |
| `interfaces_trunk` | `show interfaces trunk` | not supported by the image | ok, 21 lines | live |
| `interface_switchport` | `show interfaces {interface} switchport` | not supported by the image | ok, 27 lines | live |
| `interface_transceiver` | `show interfaces {interface} transceiver detail` | not supported by the image | not supported by the image | docs-only |
| `power_inline` | `show power inline` | not supported by the image | not supported by the image | docs-only |
| `vtp_status` | `show vtp status` | not supported by the image | ok, 18 lines | live |
| `vlan_details` | `show vlan id {vlan_id}` | not supported by the image | ok, 16 lines | live |
| `ntp_status` | `show ntp status` | ok, 4 lines | ok, 2 lines | live |
| `ntp_associations` | `show ntp associations` | empty | empty | live |
| `stack_members` | `show switch` | not supported by the image | not supported by the image | docs-only |
| `stack_ports` | `show switch stack-ports summary` | not supported by the image | not supported by the image | docs-only |
| `log_messages` | `show logging` | refused to the read-only account, answered to admin | refused to the read-only account, answered to admin | live |
| `vrfs` | `show ip vrf` | - | - | docs-only |
| `vrf_route_lookup` | `show ip route vrf {vrf} {address}` | - | - | docs-only |
| `vrf_arp_table` | `show arp vrf {vrf}` | - | - | docs-only |
| `vrf_ip_interfaces` | `show ip vrf interfaces {vrf}` | - | - | docs-only |
| `bgp_neighbor` | `show ip bgp neighbors {address}` | - | - | docs-only |
| `bgp_prefix` | `show ip bgp {address}` | - | - | docs-only |
| `bgp_advertised_routes` | `show ip bgp neighbors {address} advertised-routes` | - | - | docs-only |
| `bgp_routes` | `show ip bgp neighbors {address} routes` | - | - | docs-only |
| `ospf_neighbor_detail` | `show ip ospf neighbor detail` | - | - | docs-only |
| `ospf_interface` | `show ip ospf interface {interface}` | - | - | docs-only |
| `ospf_database` | `show ip ospf database` | - | - | docs-only |
| `ip_protocols` | `show ip protocols` | - | - | docs-only |
| `ipv6_route_table` | `show ipv6 route` | - | - | docs-only |
| `ospfv3_neighbors` | `show ipv6 ospf neighbor` | - | - | docs-only |
| `bgp_ipv6_summary` | `show bgp ipv6 unicast summary` | - | - | docs-only |
| `ip_interface_details` | `show ip interface {interface}` | - | - | docs-only |
| `ipv6_interface_details` | `show ipv6 interface {interface}` | - | - | docs-only |
| `cef_lookup` | `show ip cef {address} detail` | - | - | docs-only |
| `vrf_cef_lookup` | `show ip cef vrf {vrf} {address} detail` | ok, 7 lines | - | live |
| `adjacency_details` | `show adjacency {interface} detail` | - | - | docs-only |
| `bfd_neighbors` | `show bfd neighbors details` | - | - | docs-only |
| `route_maps` | `show route-map` | - | - | docs-only |
| `ip_policy` | `show ip policy` | - | - | docs-only |
| `ping` | `ping {address} repeat 5 timeout 1` | - | - | docs-only |
| `ping_source` | `ping {address} source {source} repeat 5 timeout 1` | - | - | docs-only |
| `ping_vrf` | `ping vrf {vrf} {address} repeat 5 timeout 1` | - | - | docs-only |
| `ping_vrf_source` | `ping vrf {vrf} {address} source {source} repeat 5 timeout 1` | - | - | docs-only |
| `ping_ipv6` | `ping ipv6 {address} repeat 5 timeout 1` | - | - | docs-only |
| `ping_ipv6_source` | `ping ipv6 {address} source {source} repeat 5 timeout 1` | - | - | docs-only |
| `traceroute` | `traceroute {address} numeric timeout 1 probe 1 ttl 1 5` | - | - | docs-only |
| `traceroute_source` | `traceroute {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | - | - | docs-only |
| `traceroute_vrf` | `traceroute vrf {vrf} {address} numeric timeout 1 probe 1 ttl 1 5` | - | - | docs-only |
| `traceroute_vrf_source` | `traceroute vrf {vrf} {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | - | - | docs-only |
| `stp_detail` | `show spanning-tree detail` | - | - | docs-only |
| `stp_interface_detail` | `show spanning-tree interface {interface} detail` | - | - | docs-only |
| `stp_mst` | `show spanning-tree mst` | - | - | docs-only |
| `etherchannel_detail` | `show etherchannel detail` | - | - | docs-only |
| `lacp_internal` | `show lacp internal` | - | - | docs-only |
| `etherchannel_load_balance` | `show etherchannel load-balance` | - | - | docs-only |
| `power_inline_detail` | `show power inline {interface} detail` | - | - | docs-only |
| `lldp_neighbor_interface` | `show lldp neighbors {interface} detail` | - | - | docs-only |
| `cdp_neighbor_interface` | `show cdp neighbors {interface} detail` | - | - | docs-only |
| `mac_table_address` | `show mac address-table address {mac}` | - | - | docs-only |
| `mac_table_interface` | `show mac address-table interface {interface}` | - | - | docs-only |
| `mac_table_vlan` | `show mac address-table vlan {vlan_id}` | - | - | docs-only |
| `arp_lookup` | `show ip arp {address}` | - | - | docs-only |
| `arp_lookup_vrf` | `show ip arp vrf {vrf} {address}` | - | - | docs-only |
| `arp_table_vrf` | `show ip arp vrf {vrf}` | - | - | docs-only |
| `ipv6_neighbors_interface` | `show ipv6 neighbors {interface}` | - | - | docs-only |
| `ipv6_neighbors_vrf` | `show ipv6 neighbors vrf {vrf}` | - | - | docs-only |
| `ipv6_neighbors_interface_vrf` | `show ipv6 neighbors vrf {vrf} {interface}` | - | - | docs-only |
| `ipv4_access_lists` | `show ip access-lists` | - | - | docs-only |
| `ipv6_access_lists` | `show ipv6 access-list` | - | - | docs-only |
| `dhcp_server_bindings` | `show ip dhcp binding` | - | - | docs-only |
| `dhcp_server_binding_address` | `show ip dhcp binding {address}` | - | - | docs-only |
| `dhcp_server_pools` | `show ip dhcp pool` | - | - | docs-only |
| `dhcp_server_conflicts` | `show ip dhcp conflict` | - | - | docs-only |
| `dhcp_server_statistics` | `show ip dhcp server statistics` | - | - | docs-only |
| `dhcp_snooping_status` | `show ip dhcp snooping` | - | - | docs-only |
| `dhcp_snooping_binding` | `show ip dhcp snooping binding` | - | - | docs-only |
| `dhcp_snooping_statistics` | `show ip dhcp snooping statistics` | - | - | docs-only |
| `port_security_interface` | `show port-security interface {interface}` | - | - | docs-only |
| `port_security_addresses` | `show port-security address` | - | - | docs-only |
| `authentication_sessions_interface` | `show authentication sessions interface {interface} details` | - | - | docs-only |
| `dot1x_interface` | `show dot1x interface {interface} details` | - | - | docs-only |
| `arp_inspection_statistics` | `show ip arp inspection statistics` | - | - | docs-only |
| `ip_source_guard` | `show ip verify source` | - | - | docs-only |
| `hsrp_detail` | `show standby` | - | - | docs-only |
| `vrrp_detail` | `show vrrp` | - | - | docs-only |
| `object_tracking` | `show track` | - | - | docs-only |
| `ip_sla_statistics` | `show ip sla statistics` | - | - | docs-only |
| `log_history` | `show logging` | - | - | docs-only |
| `qos_policy` | `show policy-map interface {interface}` | empty | - | live |
| `nat_translations` | `show ip nat translations` | empty | - | live |
| `nat_statistics` | `show ip nat statistics` | empty | - | live |
| `ikev1_sa` | `show crypto isakmp sa` | refused to the read-only account, answered to admin | - | live |
| `ikev2_sa` | `show crypto ikev2 sa` | refused to the read-only account, answered to admin | - | live |
| `ipsec_sa` | `show crypto ipsec sa` | refused to the read-only account, answered to admin | - | live |
| `qos_queues` | `show mls qos interface {interface} statistics` | not supported by the image | - | docs-only |

<!-- lab-measurements:end -->

### Cisco IOS XE

<!-- lab-measurements:begin cisco_xe -->

| Template | Command | IOL XE 17.18.2 (router) | verified |
|---|---|---|---|
| `aaa_servers` | `show aaa servers` | - | docs-only |
| `radius_statistics` | `show radius statistics` | - | docs-only |
| `tacacs_statistics` | `show tacacs` | - | docs-only |
| `snmp_statistics` | `show snmp` | - | docs-only |
| `snmp_engine_id` | `show snmp engineID` | - | docs-only |
| `dns_hosts` | `show hosts` | - | docs-only |
| `users` | `show users` | - | docs-only |
| `ssh_sessions` | `show ssh` | - | docs-only |
| `lines` | `show line` | - | docs-only |
| `version` | `show version` | ok, 38 lines | live |
| `clock` | `show clock` | ok, 4 lines | live |
| `interfaces` | `show interfaces status` | not supported by the image | docs-only |
| `ip_interfaces` | `show ip interface brief` | ok, 23 lines | live |
| `ipv6_interfaces` | `show ipv6 interface brief` | ok, 41 lines | live |
| `route_summary` | `show ip route summary` | ok, 16 lines | live |
| `cpu` | `show processes cpu` | ok, 389 lines | live |
| `memory` | `show processes memory` | ok, 395 lines | live |
| `interface_details` | `show interfaces {interface}` | ok, 29 lines | live |
| `route_lookup` | `show ip route {address}` | ok, 8 lines | live |
| `ipv6_route_lookup` | `show ipv6 route {address}` | ok, 4 lines | live |
| `inventory` | `show inventory` | empty | live |
| `environment` | `show environment all` | not supported by the image | docs-only |
| `interface_errors` | `show interfaces {interface} counters errors` | not supported by the image | docs-only |
| `arp_table` | `show ip arp` | ok, 13 lines | live |
| `ipv6_neighbors` | `show ipv6 neighbors` | empty | live |
| `mac_table` | `show mac address-table` | not supported by the image | docs-only |
| `vlans` | `show vlan brief` | not supported by the image | docs-only |
| `lag_summary` | `show etherchannel summary` | not supported by the image | docs-only |
| `lacp_neighbors` | `show lacp neighbor` | empty | live |
| `stp_summary` | `show spanning-tree summary` | ok, 17 lines | live |
| `lldp_neighbors` | `show lldp neighbors detail` | ok, 144 lines | live |
| `cdp_neighbors` | `show cdp neighbors detail` | ok, 62 lines | live |
| `bgp_summary` | `show ip bgp summary` | ok, 7 lines | live |
| `ospf_neighbors` | `show ip ospf neighbor` | ok, 9 lines | live |
| `hsrp_summary` | `show standby brief` | empty | live |
| `vrrp_summary` | `show vrrp brief` | ok, 4 lines | live |
| `interfaces_counters_errors` | `show interfaces counters errors` | - | docs-only |
| `interfaces_details` | `show interfaces` | ok, 477 lines | live |
| `route_table` | `show ip route` | ok, 33 lines | live |
| `ospf_interfaces` | `show ip ospf interface brief` | ok, 6 lines | live |
| `stp_tree` | `show spanning-tree` | not configured | live |
| `stp_root` | `show spanning-tree root` | empty | live |
| `stp_inconsistent` | `show spanning-tree inconsistentports` | refused to the read-only account, answered to admin | live |
| `stp_vlan` | `show spanning-tree vlan {vlan_id}` | command failed | live |
| `err_disabled` | `show interfaces status err-disabled` | not supported by the image | docs-only |
| `errdisable_recovery` | `show errdisable recovery` | not supported by the image | docs-only |
| `interfaces_description` | `show interfaces description` | ok, 23 lines | live |
| `interfaces_trunk` | `show interfaces trunk` | not supported by the image | docs-only |
| `interface_switchport` | `show interfaces {interface} switchport` | not supported by the image | docs-only |
| `interface_transceiver` | `show interfaces {interface} transceiver detail` | not supported by the image | docs-only |
| `power_inline` | `show power inline` | not supported by the image | docs-only |
| `vtp_status` | `show vtp status` | not supported by the image | docs-only |
| `vlan_details` | `show vlan id {vlan_id}` | not supported by the image | docs-only |
| `ntp_status` | `show ntp status` | ok, 11 lines | live |
| `ntp_associations` | `show ntp associations` | ok, 7 lines | live |
| `stack_members` | `show switch` | not supported by the image | docs-only |
| `stack_ports` | `show switch stack-ports summary` | not supported by the image | docs-only |
| `log_messages` | `show logging` | refused to the read-only account, answered to admin | live |
| `platform_resources` | `show platform resources` | not supported by the image | docs-only |
| `log_history` | `show logging` | refused to the read-only account, answered to admin | live |
| `hsrp_detail` | `show standby` | empty | live |
| `vrrp_detail` | `show vrrp` | empty | live |
| `object_tracking` | `show track` | empty | live |
| `ip_sla_statistics` | `show ip sla statistics` | ok, 12 lines | live |
| `vrfs` | `show ip vrf` | empty | live |
| `vrf_route_lookup` | `show ip route vrf {vrf} {address}` | not configured | live |
| `vrf_arp_table` | `show arp vrf {vrf}` | empty | live |
| `vrf_ip_interfaces` | `show ip vrf interfaces {vrf}` | not configured | live |
| `bgp_neighbor` | `show ip bgp neighbors {address}` | not configured | live |
| `bgp_prefix` | `show ip bgp {address}` | not configured | live |
| `bgp_advertised_routes` | `show ip bgp neighbors {address} advertised-routes` | not configured | live |
| `bgp_routes` | `show ip bgp neighbors {address} routes` | not configured | live |
| `ospf_neighbor_detail` | `show ip ospf neighbor detail` | ok, 53 lines | live |
| `ospf_interface` | `show ip ospf interface {interface}` | ok, 32 lines | live |
| `ospf_database` | `show ip ospf database` | ok, 19 lines | live |
| `ip_protocols` | `show ip protocols` | ok, 35 lines | live |
| `ipv6_route_table` | `show ipv6 route` | ok, 17 lines | live |
| `ospfv3_neighbors` | `show ipv6 ospf neighbor` | empty | live |
| `bgp_ipv6_summary` | `show bgp ipv6 unicast summary` | not configured | live |
| `ip_interface_details` | `show ip interface {interface}` | ok, 46 lines | live |
| `ipv6_interface_details` | `show ipv6 interface {interface}` | empty | live |
| `cef_lookup` | `show ip cef {address} detail` | ok, 7 lines | live |
| `vrf_cef_lookup` | `show ip cef vrf {vrf} {address} detail` | ok, 8 lines | live |
| `adjacency_details` | `show adjacency {interface} detail` | ok, 59 lines | live |
| `bfd_neighbors` | `show bfd neighbors details` | empty | live |
| `route_maps` | `show route-map` | empty | live |
| `ip_policy` | `show ip policy` | ok, 4 lines | live |
| `ping` | `ping {address} repeat 5 timeout 1` | ok, 4 lines | live |
| `ping_source` | `ping {address} source {source} repeat 5 timeout 1` | refused to the read-only account, answered to admin | live |
| `ping_vrf` | `ping vrf {vrf} {address} repeat 5 timeout 1` | ok, 4 lines | live |
| `ping_vrf_source` | `ping vrf {vrf} {address} source {source} repeat 5 timeout 1` | ok, 5 lines | live |
| `ping_ipv6` | `ping ipv6 {address} repeat 5 timeout 1` | ok, 4 lines | live |
| `ping_ipv6_source` | `ping ipv6 {address} source {source} repeat 5 timeout 1` | ok, 5 lines | live |
| `traceroute` | `traceroute {address} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `traceroute_source` | `traceroute {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | ok, 5 lines | live |
| `traceroute_vrf` | `traceroute vrf {vrf} {address} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `traceroute_vrf_source` | `traceroute vrf {vrf} {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | refused to the read-only account, answered to admin | live |
| `ping_ipv6_vrf` | `ping vrf {vrf} ipv6 {address} repeat 5 timeout 1` | ok, 4 lines | live |
| `ping_ipv6_vrf_source` | `ping vrf {vrf} ipv6 {address} source {source} repeat 5 timeout 1` | refused to the read-only account, answered to admin | live |
| `traceroute_ipv6` | `traceroute ipv6 {address} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `traceroute_ipv6_source` | `traceroute ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `traceroute_ipv6_vrf` | `traceroute vrf {vrf} ipv6 {address} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `traceroute_ipv6_vrf_source` | `traceroute vrf {vrf} ipv6 {address} source {source} numeric timeout 1 probe 1 ttl 1 5` | ok, 4 lines | live |
| `qos_policy` | `show policy-map interface {interface}` | empty | live |
| `nat_translations` | `show ip nat translations` | empty | live |
| `nat_statistics` | `show ip nat statistics` | empty | live |
| `ikev1_sa` | `show crypto isakmp sa` | refused to the read-only account, answered to admin | live |
| `ikev2_sa` | `show crypto ikev2 sa` | refused to the read-only account, answered to admin | live |
| `ipsec_sa` | `show crypto ipsec sa` | refused to the read-only account, answered to admin | live |
| `qos_queues` | `show platform hardware fed switch active qos queue stats interface {interface}` | not supported by the image | docs-only |
| `stp_detail` | `show spanning-tree detail` | - | docs-only |
| `stp_interface_detail` | `show spanning-tree interface {interface} detail` | - | docs-only |
| `stp_mst` | `show spanning-tree mst` | - | docs-only |
| `etherchannel_detail` | `show etherchannel {group_id} detail` | - | docs-only |
| `lacp_internal` | `show lacp internal` | - | docs-only |
| `etherchannel_load_balance` | `show etherchannel load-balance` | - | docs-only |
| `power_inline_detail` | `show power inline {interface} detail` | - | docs-only |
| `lldp_neighbor_interface` | `show lldp neighbors {interface} detail` | - | docs-only |
| `cdp_neighbor_interface` | `show cdp neighbors {interface} detail` | - | docs-only |
| `mac_table_address` | `show mac address-table address {mac}` | - | docs-only |
| `mac_table_interface` | `show mac address-table interface {interface}` | - | docs-only |
| `mac_table_vlan` | `show mac address-table vlan {vlan_id}` | - | docs-only |
| `arp_lookup` | `show ip arp {address}` | ok, 2 lines | live |
| `arp_lookup_vrf` | `show ip arp vrf {vrf} {address}` | ok, 2 lines | live |
| `arp_table_vrf` | `show ip arp vrf {vrf}` | ok, 3 lines | live |
| `ipv6_neighbors_interface` | `show ipv6 neighbors {interface}` | ok, 3 lines | live |
| `ipv6_neighbors_vrf` | `show ipv6 neighbors vrf {vrf}` | ok, 1 line | live |
| `ipv6_neighbors_interface_vrf` | `show ipv6 neighbors vrf {vrf} {interface}` | empty | live |
| `ipv4_access_lists` | `show ip access-lists` | - | docs-only |
| `ipv6_access_lists` | `show ipv6 access-list` | - | docs-only |
| `dhcp_server_bindings` | `show ip dhcp binding` | ok, 4 lines | live |
| `dhcp_server_binding_address` | `show ip dhcp binding {address}` | ok, 1 line | live |
| `dhcp_server_pools` | `show ip dhcp pool` | empty | live |
| `dhcp_server_conflicts` | `show ip dhcp conflict` | ok, 1 line | live |
| `dhcp_server_statistics` | `show ip dhcp server statistics` | ok, 70 lines | live |
| `dhcp_snooping_status` | `show ip dhcp snooping` | - | docs-only |
| `dhcp_snooping_binding` | `show ip dhcp snooping binding` | - | docs-only |
| `dhcp_snooping_statistics` | `show ip dhcp snooping statistics` | - | docs-only |
| `port_security_interface` | `show port-security interface {interface}` | - | docs-only |
| `port_security_addresses` | `show port-security address` | - | docs-only |
| `authentication_sessions_interface` | `show access-session interface {interface} details` | - | docs-only |
| `dot1x_interface` | `show dot1x interface {interface} details` | - | docs-only |
| `arp_inspection_statistics` | `show ip arp inspection statistics` | - | docs-only |
| `ip_source_guard` | `show ip verify source` | - | docs-only |
| `c9800_aps` | `show ap summary` | - | docs-only |
| `c9800_ap_joins` | `show wireless stats ap join summary` | - | docs-only |
| `c9800_clients` | `show wireless client summary` | - | docs-only |
| `c9800_client_detail` | `show wireless client mac-address {mac} detail` | - | docs-only |
| `c9800_client_stats` | `show wireless stats client detail` | - | docs-only |
| `c9800_radio_24` | `show ap dot11 24ghz summary` | - | docs-only |
| `c9800_radio_5` | `show ap dot11 5ghz summary` | - | docs-only |
| `c9800_ap_load` | `show ap summary load-info` | - | docs-only |
| `c9800_wlans` | `show wlan summary` | - | docs-only |
| `c9800_ap_tags` | `show ap tag summary` | - | docs-only |
| `c9800_ap_tag_detail` | `show ap name {ap_name} tag detail` | - | docs-only |
| `c9800_policy_profiles` | `show wireless profile policy summary` | - | docs-only |
| `c9800_client_deletes` | `show wireless stats client delete reasons` | - | docs-only |
| `c9800_exclusions` | `show wireless exclusionlist` | - | docs-only |
| `c9800_rogue_aps` | `show wireless wps rogue ap summary` | - | docs-only |
| `c9800_redundancy` | `show redundancy` | - | docs-only |
| `c9800_chassis_rmi` | `show chassis rmi` | - | docs-only |
| `qfp_drops` | `show platform hardware qfp active statistics drop` | - | docs-only |
| `qfp_utilization` | `show platform hardware qfp active datapath utilization` | - | docs-only |

<!-- lab-measurements:end cisco_xe -->

### Cisco NX-OS

<!-- lab-measurements:begin cisco_nxos -->

| Template | Command | Nexus 9300v 9.3(12) | verified |
|---|---|---|---|
| `dns_hosts` | `show hosts` | - | docs-only |
| `snmp_statistics` | `show snmp` | - | docs-only |
| `snmp_engine_id` | `show snmp engineID` | - | docs-only |
| `aaa_authentication` | `show aaa authentication` | - | docs-only |
| `radius_statistics` | `show radius-server statistics {address}` | - | docs-only |
| `tacacs_statistics` | `show tacacs-server statistics {address}` | - | docs-only |
| `users` | `show users` | - | docs-only |
| `ssh_server` | `show ssh server` | - | docs-only |
| `configuration_sessions` | `show configuration session summary` | - | docs-only |
| `version` | `show version` | ok, 39 lines | live |
| `clock` | `show clock` | ok, 2 lines | live |
| `inventory` | `show inventory` | ok, 9 lines | live |
| `environment` | `show environment` | ok, 16 lines | live |
| `cpu` | `show processes cpu` | ok, 175 lines | live |
| `memory` | `show processes memory` | ok, 172 lines | live |
| `interfaces` | `show interface status` | ok, 90 lines | live |
| `ip_interfaces` | `show ip interface brief` | ok, 6 lines | live |
| `ipv6_interfaces` | `show ipv6 interface brief` | ok, 3 lines | live |
| `interface_details` | `show interface {interface}` | ok, 44 lines | live |
| `interface_errors` | `show interface {interface} counters errors` | ok, 20 lines | live |
| `vlans` | `show vlan` | ok, 41 lines | live |
| `mac_table` | `show mac address-table` | ok, 18 lines | live |
| `arp_table` | `show ip arp` | ok, 18 lines | live |
| `ipv6_neighbors` | `show ipv6 neighbor` | ok, 12 lines | live |
| `lag_summary` | `show port-channel summary` | ok, 13 lines | live |
| `lacp_neighbors` | `show lacp neighbor` | ok, 13 lines | live |
| `stp_summary` | `show spanning-tree summary` | ok, 18 lines | live |
| `lldp_neighbors` | `show lldp neighbors detail` | ok, 22 lines | live |
| `cdp_neighbors` | `show cdp neighbors detail` | ok, 63 lines | live |
| `route_summary` | `show ip route summary` | ok, 17 lines | live |
| `route_lookup` | `show ip route {address}` | ok, 8 lines | live |
| `ipv6_route_lookup` | `show ipv6 route {address}` | ok, 6 lines | live |
| `bgp_sessions` | `show bgp sessions` | ok, 8 lines | live |
| `ospf_neighbors` | `show ip ospf neighbors` | ok, 7 lines | live |
| `hsrp_summary` | `show hsrp summary` | feature off or not supported by the image | docs-only |
| `vrrp_summary` | `show vrrp summary` | feature off or not supported by the image | docs-only |
| `vpc_status` | `show vpc brief` | ok, 21 lines | live |
| `vpc_peer_keepalive` | `show vpc peer-keepalive` | ok, 16 lines | live |
| `vpc_role` | `show vpc role` | ok, 13 lines | live |
| `route_table` | `show ip route` | ok, 28 lines | live |
| `ospf_interfaces` | `show ip ospf interface brief` | ok, 6 lines | live |
| `bgp_summary` | `show bgp ipv4 unicast summary` | ok, 9 lines | live |
| `stp_tree` | `show spanning-tree` | ok, 56 lines | live |
| `stp_root` | `show spanning-tree root` | ok, 7 lines | live |
| `stp_blocked` | `show spanning-tree blockedports` | empty | live |
| `stp_inconsistent` | `show spanning-tree inconsistentports` | empty | live |
| `stp_vlan` | `show spanning-tree vlan {vlan_id}` | ok, 17 lines | live |
| `err_disabled` | `show interface status err-disabled` | ok, 4 lines | live |
| `errdisable_recovery` | `show errdisable recovery` | ok, 43 lines | live |
| `interfaces_description` | `show interface description` | ok, 90 lines | live |
| `interfaces_trunk` | `show interface trunk` | ok, 27 lines | live |
| `interfaces_counters_errors` | `show interface counters errors` | ok, 276 lines | live |
| `interface_switchport` | `show interface {interface} switchport` | ok, 21 lines | live |
| `interface_transceiver` | `show interface {interface} transceiver details` | ok, 3 lines | live |
| `vlan_details` | `show vlan id {vlan_id}` | ok, 18 lines | live |
| `ntp_status` | `show ntp status` | ok, 2 lines | live |
| `ntp_associations` | `show ntp peer-status` | ok, 6 lines | live |
| `system_resources` | `show system resources` | ok, 10 lines | live |
| `reset_reason` | `show system reset-reason` | ok, 34 lines | live |
| `modules` | `show module` | ok, 22 lines | live |
| `license_usage` | `show license usage` | ok, 42 lines | live |
| `redundancy_status` | `show redundancy status` | ok, 23 lines | live |
| `features` | `show feature` | ok, 195 lines | live |
| `vrfs` | `show vrf` | ok, 3 lines | live |
| `bfd_neighbors` | `show bfd neighbors` | empty | live |
| `vpc_consistency` | `show vpc consistency-parameters global` | empty | live |
| `vpc_orphan_ports` | `show vpc orphan-ports` | command failed, exit status 244 | live |
| `dhcp_snooping_binding` | `show ip dhcp snooping binding` | feature off or not supported by the image | docs-only |
| `access_lists` | `show ip access-lists` | ok, 104 lines | live |
| `log_messages` | `show logging last 200` | ok, 200 lines | live |
| `processes_cpu` | `show processes cpu` | - | docs-only |
| `log_history` | `show logging last {count}` | - | docs-only |
| `logging_info` | `show logging info` | - | docs-only |
| `hsrp_detail` | `show hsrp detail` | - | docs-only |
| `vrrp_detail` | `show vrrp detail` | - | docs-only |
| `vrrpv3_detail` | `show vrrpv3 detail` | - | docs-only |
| `object_tracking` | `show track` | - | docs-only |
| `stp_detail` | `show spanning-tree detail` | ok, 54 lines | live |
| `stp_interface_detail` | `show spanning-tree interface {interface} detail` | ok, 9 lines | live |
| `stp_mst` | `show spanning-tree mst` | command failed, exit status 244 | live |
| `port_channel_database` | `show port-channel database` | ok, 19 lines | live |
| `lacp_interface` | `show lacp interface {interface}` | ok, 36 lines | live |
| `port_channel_load_balance` | `show port-channel load-balance` | ok, 7 lines | live |
| `vpc_member_consistency` | `show vpc consistency-parameters vpc {vpc_id}` | ok, 30 lines | live |
| `vpc_interface_consistency` | `show vpc consistency-parameters interface {interface}` | ok, 30 lines | live |
| `lldp_neighbor_interface` | `show lldp neighbors interface {interface} detail` | ok, 22 lines | live |
| `cdp_neighbor_interface` | `show cdp neighbors interface {interface} detail` | ok, 23 lines | live |
| `route_prefix_lookup` | `show ip route {prefix}` | - | docs-only |
| `route_map_counters` | `show route-map {route_map} pbr-statistics` | - | docs-only |
| `bgp_neighbor_detail` | `show bgp ipv4 unicast neighbors {address}` | - | docs-only |
| `bgp_prefix_detail` | `show bgp ipv4 unicast {prefix}` | - | docs-only |
| `bgp_advertised_routes` | `show bgp ipv4 unicast neighbors {address} advertised-routes` | - | docs-only |
| `bgp_received_routes` | `show bgp ipv4 unicast neighbors {address} routes` | - | docs-only |
| `ospf_process` | `show ip ospf` | - | docs-only |
| `ospf_neighbors_detail` | `show ip ospf neighbors detail` | - | docs-only |
| `ospf_interface_detail` | `show ip ospf interface {interface}` | - | docs-only |
| `ospf_database` | `show ip ospf database` | - | docs-only |
| `ipv6_route_table` | `show ipv6 route` | - | docs-only |
| `bgp_ipv6_summary` | `show bgp ipv6 unicast summary` | - | docs-only |
| `ospfv3_neighbors` | `show ipv6 ospfv3 neighbors` | - | docs-only |
| `bfd_neighbors_detail` | `show bfd neighbors details` | - | docs-only |
| `forwarding_ipv4_route` | `show forwarding ipv4 route` | - | docs-only |
| `ip_adjacency` | `show ip adjacency` | - | docs-only |
| `route_maps` | `show route-map` | - | docs-only |
| `ip_policy` | `show ip policy` | - | docs-only |
| `route_lookup_vrf` | `show ip route {address} vrf {vrf}` | - | docs-only |
| `route_prefix_lookup_vrf` | `show ip route {prefix} vrf {vrf}` | - | docs-only |
| `route_table_vrf` | `show ip route vrf {vrf}` | - | docs-only |
| `arp_table_vrf` | `show ip arp vrf {vrf}` | - | docs-only |
| `ipv6_neighbors_vrf` | `show ipv6 neighbor vrf {vrf}` | - | docs-only |
| `ip_interfaces_vrf` | `show ip interface brief vrf {vrf}` | - | docs-only |
| `bgp_summary_vrf` | `show bgp ipv4 unicast summary vrf {vrf}` | - | docs-only |
| `ospf_neighbors_vrf` | `show ip ospf neighbors vrf {vrf}` | - | docs-only |
| `ospf_interfaces_vrf` | `show ip ospf interface brief vrf {vrf}` | - | docs-only |
| `ipv6_route_lookup_vrf` | `show ipv6 route {address} vrf {vrf}` | - | docs-only |
| `ipv6_route_table_vrf` | `show ipv6 route vrf {vrf}` | - | docs-only |
| `bgp_ipv6_summary_vrf` | `show bgp ipv6 unicast summary vrf {vrf}` | - | docs-only |
| `ospfv3_neighbors_vrf` | `show ipv6 ospfv3 neighbors vrf {vrf}` | - | docs-only |
| `ping` | `ping {address} vrf {vrf} count 5` | - | docs-only |
| `ping_source` | `ping {address} vrf {vrf} source {source} count 5` | - | docs-only |
| `traceroute` | `traceroute {address} vrf {vrf}` | - | docs-only |
| `traceroute_source` | `traceroute {address} source {source} vrf {vrf}` | - | docs-only |
| `ping6` | `ping6 {address} vrf {vrf} count 5` | - | docs-only |
| `ping6_source` | `ping6 {address} vrf {vrf} source {source} count 5` | - | docs-only |
| `traceroute6` | `traceroute6 {address} vrf {vrf}` | - | docs-only |
| `traceroute6_source` | `traceroute6 {address} source {source} vrf {vrf}` | - | docs-only |
| `mac_table_address` | `show mac address-table address {mac}` | - | docs-only |
| `mac_table_vlan` | `show mac address-table vlan {vlan_id}` | - | docs-only |
| `arp_lookup` | `show ip arp {address}` | - | docs-only |
| `arp_lookup_vrf` | `show ip arp {address} vrf {vrf}` | - | docs-only |
| `ipv6_neighbor_lookup` | `show ipv6 neighbor {address}` | - | docs-only |
| `ipv6_neighbor_lookup_vrf` | `show ipv6 neighbor {address} vrf {vrf}` | - | docs-only |
| `ipv4_access_lists` | `show ip access-lists {name}` | - | docs-only |
| `ipv6_access_lists` | `show ipv6 access-lists {name}` | - | docs-only |
| `mac_access_lists` | `show mac access-lists {name}` | - | docs-only |
| `ipv4_access_lists_summary` | `show ip access-lists summary` | - | docs-only |
| `ipv6_access_lists_summary` | `show ipv6 access-lists summary` | - | docs-only |
| `mac_access_lists_summary` | `show mac access-lists summary` | - | docs-only |
| `ip_interface_details` | `show ip interface {interface}` | - | docs-only |
| `dhcp_snooping_status` | `show ip dhcp snooping` | - | docs-only |
| `dhcp_snooping_statistics` | `show ip dhcp snooping statistics` | - | docs-only |
| `dhcp_relay_status` | `show ip dhcp relay` | - | docs-only |
| `dhcp_relay_statistics` | `show ip dhcp relay statistics` | - | docs-only |
| `arp_inspection_statistics` | `show ip arp inspection statistics` | - | docs-only |
| `arp_inspection_statistics_vlan` | `show ip arp inspection statistics vlan {vlan_id}` | - | docs-only |
| `qos_queues` | `show queuing interface {interface}` | - | docs-only |
| `qos_policy` | `show policy-map interface {interface}` | - | docs-only |
| `priority_flow_control` | `show interface priority-flow-control` | - | docs-only |
| `tcam_utilization` | `show hardware access-list resource utilization` | - | docs-only |
| `hardware_capacity` | `show hardware capacity` | - | docs-only |
| `nve_peers` | `show nve peers` | feature off or not supported by the image | docs-only |
| `nve_vni` | `show nve vni` | feature off or not supported by the image | docs-only |
| `nve_interface_detail` | `show nve interface nve1 detail` | feature off or not supported by the image | docs-only |
| `evpn_bgp_summary` | `show bgp l2vpn evpn summary` | feature off or not supported by the image | docs-only |
| `evpn_bgp_prefix` | `show bgp l2vpn evpn {prefix}` | feature off or not supported by the image | docs-only |
| `evpn_mac_ip` | `show l2route evpn mac-ip all` | ok, 5 lines | live |

<!-- lab-measurements:end cisco_nxos -->

### IOS router source references

- C-G51-BGP: [IOS BGP command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/command/irg-cr-book/bgp-s1.html).
- C-G51-IP: [IOS IP addressing reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-r1.html).
- C-G51-VRF: [IOS show ip vrf reference](https://www.cisco.com/c/en/us/td/docs/ios/qos/command/reference/qos_book/qos_s3.html).
- C-G51-ROUTING: [IOS protocol-independent routing reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_pi/command/reference/iri_book/iri_pi2.html).
- C-G51-IPV6-RIB: [IOS IPv6 RIB reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s5.html).
- C-G51-IPV6-IF: [IOS IPv6 interface reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s2.html).
- C-G51-OSPFV3: [IOS OSPFv3 reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s4.html).
- C-G51-BGPV6: [IOS IPv6 BGP reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s1.html).
- C-G51-CEF: [IOS CEF and adjacency command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipswitch/command/isw-cr-book/isw-s1.html).
- C-G51-OSPF: [IOS OSPF command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/ospf-s1.html).

### IOS port, STP, EtherChannel, PoE and neighbor detail

`stp_detail`, `stp_interface_detail`, `stp_mst`, `etherchannel_detail`, `lacp_internal`, `etherchannel_load_balance`,
`power_inline_detail`, `lldp_neighbor_interface` and `cdp_neighbor_interface` follow the
[IOS 15.2(7)E consolidated command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html)
and the [Cisco IOS LACP reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cether/command/ce-cr-book/ce-s1.html);
`lacp_internal` and `power_inline_detail` also the
[Cisco IOS interface and hardware command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/command/ir-cr-book/ir-s5.html).
The syntax was verified on IOSvL2 15.2(20200924); that image has no PoE or optics,
so `power_inline_detail` and the IOS DOM parser of `interface_transceiver` rest on the documented outputs only.

### NX-OS probe syntax reference

- https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/troubleshooting/guide/b-cisco-nexus-9000-nx-os-troubleshooting-guide-93x/b-cisco-nexus-9000-nx-os-troubleshooting-guide-93x_chapter_010001.html

`ping`, `ping_source`, `traceroute`, `traceroute_source`, `ping6`, `ping6_source`, `traceroute6`, `traceroute6_source`

NX-OS forwarding and security diagnostics use the [Nexus 9000 NX-OS show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf). The targeted table reads are `mac_table_address`, `mac_table_vlan`, `arp_lookup`, `arp_lookup_vrf`, `ipv6_neighbor_lookup` and `ipv6_neighbor_lookup_vrf`. ACL and interface diagnostics add `ipv4_access_lists`, `ipv6_access_lists`, `mac_access_lists`, `ipv4_access_lists_summary`, `ipv6_access_lists_summary`, `mac_access_lists_summary` and `ip_interface_details`. First-hop security diagnostics add `dhcp_snooping_status`, `dhcp_snooping_statistics`, `dhcp_relay_status`, `dhcp_relay_statistics`, `arp_inspection_statistics` and `arp_inspection_statistics_vlan`.

### IOS forwarding and client security

| Profile | Query names | Source |
|---|---|---|
| `cisco_ios` | `mac_table_address`, `mac_table_interface`, `mac_table_vlan`, `dhcp_snooping_status`, `dhcp_snooping_binding`, `dhcp_snooping_statistics`, `port_security_interface`, `port_security_addresses`, `arp_inspection_statistics`, `ip_source_guard` | [Catalyst 3750-X and 3560-X IOS security and MAC commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750x_3560x/software/release/15-2_4_e/command/reference/CR_3750X/cli2.html) |
| `cisco_ios` | `arp_lookup`, `arp_lookup_vrf`, `arp_table_vrf` | [IOS IP addressing reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-r1.html) |
| `cisco_ios` | `ipv6_neighbors_interface`, `ipv6_neighbors_vrf`, `ipv6_neighbors_interface_vrf` | [IOS IPv6 interface reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s2.html) |
| `cisco_ios` | `ipv4_access_lists`, `ipv6_access_lists` | [Cisco IOS ACL counters and IPv4/IPv6 examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/15-0_2_se/configuration/guide/scg2960/swv6acl.html) |
| `cisco_ios` | `dhcp_server_bindings`, `dhcp_server_binding_address`, `dhcp_server_pools`, `dhcp_server_conflicts`, `dhcp_server_statistics` | [Cisco IOS DHCP server verification](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_dhcp/configuration/15-mt/dhcp-15-mt-book.pdf) |
| `cisco_ios` | `authentication_sessions_interface` | [Cisco IOS authentication session commands](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s2.html) |
| `cisco_ios` | `dot1x_interface` | [Catalyst 2960-L 802.1X command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960l/software/15-2_7_e/command_reference/b_1527_2960l_cr/security_commands.html) |

### Operational QoS, NAT, and VPN

- IOS and IOS XE `qos_policy` uses `show policy-map interface {interface}`. [IOS modular QoS command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos/command/qos-cr-book/qos-s4.html)
- IOS `qos_queues` uses `show mls qos interface {interface} statistics` on Catalyst switches with MLS egress counters. [Catalyst 2960-X IOS 15.2(6)E QoS command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15_2_6_e/command_reference/b_1526_2960x_cr/qos_commands.html)
- IOS and IOS XE `nat_translations` and `nat_statistics` use `show ip nat translations` and `show ip nat statistics`. [IOS 15.2S NAT guide](https://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr_nat/configuration/15-2s/iadnat-monmain.html), [IOS XE NAT exhaustion example](https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/226027-troubleshoot-nat-on-cat8000-platforms.html)
- IOS and IOS XE `ikev1_sa`, `ikev2_sa`, and `ipsec_sa` use `show crypto isakmp sa`, `show crypto ikev2 sa`, and `show crypto ipsec sa`. [IOS security command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s3.html)

### IOS health source references

- C-G54-FHRP · [Cisco IOS First Hop Redundancy Protocols Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/command/fhp-cr-book.pdf).
- C-G54-TRACK · [Cisco IOS 15M&T Enhanced Object Tracking](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/configuration/15-mt/iap-15-mt-book/iap-eot.pdf).

### IOS XE health source references

IOS XE diagnostics use `hsrp_detail` (`show standby`), `vrrp_detail` (`show vrrp`),
`object_tracking` (`show track`), `ip_sla_statistics` (`show ip sla statistics`)
and `log_history` (the existing fixed `show logging` buffer command with client-side filters).

- C-G72-HSRP: [IOS XE 17.x HSRP guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fhp-hsrp-0.html).
- C-G72-SLA: [Cisco IOS IP SLAs show commands reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipsla/command/sla-cr-book/sla_s1.html).
- C-G72-TRACK: [IOS XE Enhanced Object Tracking guide](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-addressing/ip-addressing/m_iap-eot-xe.html).
- C-G72-VRRP: [IOS XE 17.x VRRP guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fhp-vrrp-0.html).
### IOS XE forwarding and client security

The [IOS XE forwarding and client security captures](../../tests/fixtures/real/cisco_xe/iolxe_17.18.2_g73/PROVENANCE.md)
include the IOL XE router and IOL-L2 switch. The IOS XE table above has a router column.

- [IOS XE 17.18 access sessions and 802.1X](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/command_reference/b_1718_9300_cr/security_commands.html)
- [IOS XE 17 IPv4 ACLs and interface attachment](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/security/acls/acls-configuration-guide/access-control-lists.html)
- [IOS XE 17 IPv6 ACLs](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_ip6-acls-xe.html)
- [IOS XE 17.18 dynamic ARP inspection](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-18/configuration_guide/sec/b_1718_sec_9200_cg.pdf)
- [IOS XE 17 DHCP server verification](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-dhcp-server-xe.html)
- [IOS XE 17.18 IP Source Guard](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_ip_source_guard.html)
- [IOS XE 17 MAC forwarding and port security](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html)
- [IOS XE 17 DHCP snooping](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/fhs-sisf/fhs-and-sisf-configuration-guide/dhcp-snooping.html)

### IOS XE operational source references

- C-G75-XE-FED [Catalyst 9300 hardware QoS command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/qos_commands.html)
- C-G75-XE-FED-AVB [Catalyst 9300 AVB hardware QoS examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/audio_video_bridging.html)
- C-G75-XE-IKEV1 [IOS XE DMVPN verification](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-conn-dmvpn-dmvpn-0.html)
- C-G75-XE-IKEV2 [IOS XE IKEv2 HSRP verification](https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/222200-configure-ipsec-redundancy-with-hsrp-for.html)
- C-G75-XE-IPSEC [IOS XE GRE over IPsec verification](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-gre-over-ipsec-tunnels.html)
- C-G75-XE-POLICING [IOS XE QoS packet policing](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/qos/b-quality-of-service/m_qos-policing.html)

### NX-OS QoS and hardware resources

- `qos_queues` uses the [Nexus 9000 NX-OS 10.3(x) Show Commands: Q](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/command-reference/show/b_n9k_show_commands_103x/m_q_showcmds.html).
- `qos_policy` uses the [Nexus 9000 NX-OS 9.3(x) QoS: Monitoring QoS Statistics](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/qos/configuration/guide/b-cisco-nexus-9000-nx-os-quality-of-service-configuration-guide-93x/b-cisco-nexus-9000-nx-os-quality-of-service-configuration-guide-93x_chapter_01100.html).
- `priority_flow_control` uses the [Nexus 9000 NX-OS 9.3(x) Show Commands: I](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/show/b_N9K_Show_Commands_93x/b_N9K_Show_Commands_93x_chapter_01001.html).
- `tcam_utilization` uses the [Nexus 9000 NX-OS 9.3(x) Show Commands: A](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/show/b_N9K_Show_Commands_93x/b_N9K_Show_Commands_93x_chapter_01.html).
- `hardware_capacity` uses the [Nexus 9000 NX-OS 10.5(x) Show Commands: H](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/m_h_showcmds.html).

### NX-OS VXLAN and EVPN

| Query | Cisco sources |
|---|---|
| `nve_peers` | [C-G97-NXOS-VXLAN](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m-configuring-vxlan-bbgp-evpn.html), [C-G97-NXOS-VXLANV6](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/vxlan/configuration/guide/b-cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-93x_chapter_010011.html) |
| `nve_vni` | [C-G97-NXOS-VXLAN](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m-configuring-vxlan-bbgp-evpn.html) |
| `nve_interface_detail` | [C-G97-NXOS-VXLAN](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m-configuring-vxlan-bbgp-evpn.html), [C-G97-NXOS-VXLANV6](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/vxlan/configuration/guide/b-cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-93x_chapter_010011.html) |
| `evpn_bgp_summary` | [C-G97-NXOS-BGP](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/label-switching/b-cisco-nexus-9000-series-nx-os-label-switching-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-label-switching-configuration-guide-93x_chapter_01000.html) |
| `evpn_bgp_prefix` | [C-G97-NXOS-BGP](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/label-switching/b-cisco-nexus-9000-series-nx-os-label-switching-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-label-switching-configuration-guide-93x_chapter_01000.html), [C-G97-NXOS-B](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/show/b_N9K_Show_Commands_93x/b_N9K_Show_Commands_93x_chapter_010.html) |
| `evpn_mac_ip` | [C-G97-NXOS-L](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/show/b_N9K_Show_Commands_93x/b_N9K_Show_Commands_93x_chapter_01011.html), [C-G97-NXOS-VXLAN](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m-configuring-vxlan-bbgp-evpn.html) |

### NX-OS health, local logging and gateway detail

[C-G93-NXOS-SHOW](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/show/b_N9K_Show_Commands_93x/b_N9K_Show_Commands_93x.pdf)

| Query | Command |
|---|---|
| `processes_cpu` | `show processes cpu` |
| `log_history` | `show logging last {count}` |
| `logging_info` | `show logging info` |
| `hsrp_detail` | `show hsrp detail` |
| `vrrp_detail` | `show vrrp detail` |
| `vrrpv3_detail` | `show vrrpv3 detail` |
| `object_tracking` | `show track` |


### Catalyst 9800 wireless controller

| Profile | Query | Command | Source |
|---|---|---|---|
| `cisco_xe` | `c9800_aps` | `show ap summary` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_ap_joins` | `show wireless stats ap join summary` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_clients` | `show wireless client summary` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_client_detail` | `show wireless client mac-address {mac} detail` | [Catalyst 9800 AP Configuration](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_enabling_ap_console.html) |
| `cisco_xe` | `c9800_client_stats` | `show wireless stats client detail` | [Catalyst 9800 AP Configuration](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_enabling_ap_console.html) |
| `cisco_xe` | `c9800_radio_24` | `show ap dot11 24ghz summary` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_radio_5` | `show ap dot11 5ghz summary` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_ap_load` | `show ap summary load-info` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_wlans` | `show wlan summary` | [Catalyst 9800 Configuration Model](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/newconfigmodel/b_catalyst-9800-configuration-model/m_validating_configuration.html) |
| `cisco_xe` | `c9800_ap_tags` | `show ap tag summary` | [Catalyst 9800 Configuration Model](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/newconfigmodel/b_catalyst-9800-configuration-model/m_validating_configuration.html) |
| `cisco_xe` | `c9800_ap_tag_detail` | `show ap name {ap_name} tag detail` | [Catalyst 9800 AP Tag Detail](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/213911-understand-catalyst-9800-wireless-contro.html) |
| `cisco_xe` | `c9800_policy_profiles` | `show wireless profile policy summary` | [Catalyst 9800 Policy Profiles](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/ConfiguringIRCM/b-configuring-inter-release-controller-mobility-in-wireless-deployments-supporting-aireos-and-catalyst-9800-controllers/m-troubleshooting-ircm-configuration.html) |
| `cisco_xe` | `c9800_client_deletes` | `show wireless stats client delete reasons` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_exclusions` | `show wireless exclusionlist` | [Catalyst 9800 Show Commands](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |
| `cisco_xe` | `c9800_rogue_aps` | `show wireless wps rogue ap summary` | [Catalyst 9800 rogue AP and client location](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/221688-identify-and-locate-a-rogue-ap-client-on.html) |
| `cisco_xe` | `c9800_redundancy` | `show redundancy` | [Catalyst 9800 HA SSO](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html) |
| `cisco_xe` | `c9800_chassis_rmi` | `show chassis rmi` | [Catalyst 9800 HA SSO](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html) |


### IOS XE hardware forwarding

| Profile | Query | Command | Source |
|---|---|---|---|
| `cisco_xe` | `qfp_drops` | `show platform hardware qfp active statistics drop` | [Troubleshoot Interface Packet Drops on IOS XE Routers](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-ios-xe-sd-wan/224129-troubleshoot-interface-packet-drops-in.html) |
| `cisco_xe` | `qfp_utilization` | `show platform hardware qfp active datapath utilization` | [Throughput Issues on ASR 1000 Series Router](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/200674-Throughput-issues-on-ASR1000-Series-rout.html) |
