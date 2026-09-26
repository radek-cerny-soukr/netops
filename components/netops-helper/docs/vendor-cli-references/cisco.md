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


Besides the Catalyst names, `cisco_ios` and `cisco_xe` accept `Ethernet<slot>/<port>` (abbreviation `Et`, slot and port 0-15, no leading zeros, no subinterface) as a physical interface: the fixed Ethernet ports of Cisco routers and of the IOL and IOL-L2 images are named this way. Measured on 25 September 2026 on IOS-XE 17.18.2 IOL images, whose ports are `Ethernet0/0` to `Ethernet3/3` and where the Catalyst grammar left no port that could be enrolled.

The NX-OS neighbor-table command is `show ipv6 neighbor`. The earlier `show ipv6 icmp neighbor` wording was corrected: the 10.5 I-command reference uses the latter prefix for narrower ICMPv6 subcommands, while the operational neighbor table is documented as `show ipv6 neighbor`.

## Live measurements, 25 September 2026

All three profiles were run query by query against Cisco's virtual images; the per-query tables, the lab and the device configuration are in [Live lab measurements](../../../../docs/lab-measurements-2026-09-25.md#cisco-ios-xe-cisco_xe). The images are not the Catalyst and Nexus 10.5 baselines above, so these runs show what the transport, the account and the parser of these releases do, not that every command exists on the baseline hardware.

| Profile | Image | Account | Released 0.3.6 | 0.3.7 candidate |
| --- | --- | --- | --- | --- |
| `cisco_xe` | IOL 17.18.2 (`X86_64BI_LINUX-ADVENTERPRISEK9-M`, router) | privilege 1, RSA 3072 key | every call `the device refused the connection` | 21 of 27 with exit status 0, 6 `device_cli_error` |
| `cisco_xe` | IOL-L2 17.18.2 (`X86_64BI_LINUX_L2-ADVENTERPRISEK9-M`) | the same | every call `the device refused the connection` | 26 of 27 with exit status 0, 1 `device_cli_error` |
| `cisco_ios` | IOSv 15.9(3)M12 (router) | privilege 1, RSA 3072 key, `legacy_ssh: "rsa-sha1-dh14"` | host key scan refused (SHA-1 key exchange only) | 19 of 27 with exit status 0, 8 `device_cli_error` |
| `cisco_ios` | IOSvL2 15.2(20200924) | the same | host key scan refused (SHA-1 key exchange only) | 26 of 27 with exit status 0, 1 `device_cli_error` |
| `cisco_nxos` | Nexus 9300v 9.3(12) | role `network-operator`, RSA 3072 key | 30 answered, 29 with exit status 0 and `lldp_neighbors` exit status 244 once the HSRP, VRRP and vPC features were enabled | the same |
| `cisco_nxos` | Nexus 9500v 9.3(12) | the same | 30 of 30 with exit status 0 | 30 of 30 with exit status 0 |

What these runs established:

- **IOS and IOS-XE refuse with exit status 0.** A command the image does not implement, and one above the account's privilege (`show running-config`, `configure terminal`), is answered `Line has invalid autocommand "<command>"` with exit status 0. Helper 0.3.7 reports it as `device_cli_error`. Every `device_cli_error` above is a command the image lacks: the router images have no `show interfaces status`, `show vlan brief`, `show mac address-table`, `show etherchannel summary` or `counters errors` form, IOSv also no `show lacp neighbor` and `show spanning-tree summary`, and none of the four IOS and IOS-XE images has environment sensors.
- **The IOL images have five VTY lines.** The released host key scan opened one connection per key type at once, the device was still closing them when the real connection came, and reset it. Core 0.2.5 scans one key type at a time.
- **IOSv and IOSvL2 offer only SHA-1 key exchange methods** and an `ssh-rsa` host key. The per-device profile `legacy_ssh: "rsa-sha1-dh14"` of Core 0.2.5 adds exactly `diffie-hellman-group14-sha1` for such a device; `diffie-hellman-group1-sha1` and `diffie-hellman-group-exchange-sha1` stay refused.
- **IOL names its ports `Ethernet<slot>/<port>`**, which helper 0.3.7 accepts for `cisco_ios` and `cisco_xe` (see the interface grammar above); `interface_details` for `Ethernet0/1` answered with exit status 0 on both IOL images, and `interface_errors` for it on the L2 image (the router image has no `counters errors` form).
- **NX-OS refuses with a non-zero status.** An unknown command, and an HSRP, VRRP or vPC command while that feature is disabled, gives `Syntax error while parsing '<command>'` with exit status 16; a command above the role, such as `show running-config`, `% Permission denied for the role` with exit status 30. Helper 0.3.7 reports both as `device_cli_error`. `show lldp neighbors detail` without a neighbour ends with `ERROR: No neighbour information` and exit status 244 and stays a successful read. NX-OS 9.3(12) offers current key exchange and an RSA host key with `rsa-sha2-256`; no legacy exception is needed.

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
