# Cisco CLI references

Baseline: Catalyst IOS 15.2(7)E, Catalyst IOS-XE 17.15.x, and Nexus 9000 NX-OS 10.5(x).

Audit date: 2026-09-09.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

## Profiles

- `cisco_ios`: conservative Catalyst switch profile audited against IOS 15.2(7)E on Catalyst 2960-X. It is not a generic profile for every IOS router.
- `cisco_xe`: conservative Catalyst switch profile audited against IOS-XE 17.15.x on Catalyst 9300.
- `cisco_nxos`: Nexus 9000 profile audited separately against NX-OS 10.5(x). Similar command names do not imply identical syntax or output across IOS and NX-OS.

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

The NetOps 1.0.7 additions are the same on `cisco_ios` and `cisco_xe` (the IOS rows cite the IOS 15.2(7)E consolidated command reference, the XE rows the IOS-XE 17.15 complete command reference): `route_table`, `ospf_interfaces`, `stp_tree`, `stp_root`, `stp_inconsistent`, `stp_vlan`, `err_disabled`, `errdisable_recovery`, `interfaces_description`, `interfaces_trunk`, `interface_switchport`, `interface_transceiver`, `power_inline`, `vtp_status`, `vlan_details`, `ntp_status`, `ntp_associations`, `stack_members`, `stack_ports`, `log_messages` (the fixed `show logging`, bounded by the device's log buffer) and, XE only, `platform_resources`. They were run on IOSv 15.9(3)M12, IOSvL2 15.2(20200924) in the lab (task netops-20261108-23); `interface_transceiver`, `power_inline`, `stack_members`, `stack_ports`, `platform_resources` and the environment reads cannot be answered by those images and are `verified: docs-only`. Their output is in `tests/fixtures/real/cisco_ios`. On a router image (IOSv) the switch-only reads (`interfaces`, `mac_table`, `vlans`, STP, trunk, err-disable, PoE) are answered `Line has invalid autocommand "..."`, which the Helper classifies like a refused command (`permission_denied`).

The NetOps 1.0.7 additions for `cisco_nxos` (all cite the [NX-OS 10.5(x) complete show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.pdf)): `route_table`, `ospf_interfaces`, `bgp_summary`, `stp_tree`, `stp_root`, `stp_blocked`, `stp_inconsistent`, `stp_vlan`, `err_disabled`, `errdisable_recovery`, `interfaces_description`, `interfaces_trunk`, `interfaces_counters_errors`, `interface_switchport`, `interface_transceiver`, `vlan_details`, `ntp_status`, `ntp_associations` (`show ntp peer-status`), `system_resources`, `reset_reason`, `modules`, `license_usage`, `redundancy_status`, `features`, `vrfs`, `bfd_neighbors`, `vpc_consistency`, `vpc_orphan_ports`, `dhcp_snooping_binding`, `access_lists` and `log_messages` (the fixed `show logging last 200`, newest 200 lines). They were run on the Nexus 9300v 9.3(12) lab node with the built-in `network-operator` role (task netops-20261108-28); the outputs are in `tests/fixtures/real/cisco_nxos/nexus9300v_9.3.12`. Features that are off answer `Syntax error while parsing` (`unsupported`: `hsrp_summary`, `vrrp_summary`, `dhcp_snooping_binding`, `bgp_summary` and `bfd_neighbors` until the feature is enabled); `show boot` and `show accounting log` are refused to `network-operator` (`% Permission denied for the role`) and are therefore not in the catalogue. The NX-OS rows are `verified: lab` (measured) except those listed as `docs-only` in the generated tables below. `show running-config diff` stays out of the catalogue, because configuration text can carry secrets.

Additional official Cisco references retained from the audit are the [Catalyst 9300 command-reference release list](https://www.cisco.com/c/en/us/support/switches/catalyst-9300-series-switches/products-command-reference-list.html), the [IOS-XE 17.15 IP Routing Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/rtng/b_1715_rtng_9300_cg.pdf), and the earlier [IOS-XE 17.3 interface and hardware command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-3/command_reference/b_173_9300_cr/interface_and_hardware_commands.html) used only to check command lineage.

### Interface-name grammar sources

The following first-party configuration guides constrain the typed interface-name grammar for `interface_details` and `interface_errors`; they also document the interface types named by `interfaces`, `ip_interfaces`, and `ipv6_interfaces`. Configuration examples in these sources do not make any configuration command callable.

| Registry ID | Official document and baseline | Profiles | URL |
|---|---|---|---|
| C-IOS-1527-CONFIG | Catalyst 2960-X IOS 15.2(7)E Consolidated Configuration Guide | `cisco_ios` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg.pdf |
| C-XE-1715-INTERFACE-CMD | Catalyst 9300 IOS-XE 17.15 Interface and Hardware Commands | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/interface_and_hardware_commands.html |
| C-XE-1715-INTERFACE-GUIDE | Catalyst 9300 IOS-XE 17.15 Interfaces and Hardware Configuration Guide | `cisco_xe` | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/int_hw/b_1715_int_and_hw_9300_cg.pdf |
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

<!-- lab-measurements:end -->

### Cisco IOS XE

<!-- lab-measurements:begin cisco_xe -->

| Template | Command | IOL XE 17.18.2 (router) | verified |
|---|---|---|---|
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

<!-- lab-measurements:end cisco_xe -->

### Cisco NX-OS

<!-- lab-measurements:begin cisco_nxos -->

| Template | Command | Nexus 9300v 9.3(12) | verified |
|---|---|---|---|
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

<!-- lab-measurements:end cisco_nxos -->
