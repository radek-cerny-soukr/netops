# Complete outputs from vendor documentation

One file per catalogue query (`<profile>/<query>.txt`; `route_lookup_*` are variants of the
`route_lookup` query, one per routing situation). Each file is the **complete** output of exactly the
command the catalogue renders for that query (`show interfaces status`, `show mac address-table`,
`show ip route <addr>`, `show arp no-resolve | no-more` ...), with all headers, legends, footers and the
rows every real box prints (CPU/SVI rows, pseudo interfaces, continuation lines). They are reproduced
from the layouts and examples of the vendor documents below and use documentation addresses
(RFC 5737 IPv4 such as `198.51.100.x`, RFC 7042 MACs `0000.5e00.53xx`, `2001:db8::`; the vendor examples were renumbered into these ranges, prefix lengths of private example networks shortened to fit). They are **not** captures of a live device. The GNS3 lab replaced them with real output under `../real/<os>` for
IOS (IOSv, IOSvL2) and EOS (cEOS) wherever the lab printed the same command; what stays here for `cisco_ios` and
`arista_eos` is only what the lab images do not produce (IPv6 neighbours, BGP/classful/ECMP/supernet route lookups,
populated BGP, LACP bundles, root/alternate STP ports). IOS XE (the IOL router image replaced `route_lookup_connected` and `route_lookup_none`; the other files are Catalyst 9300 layouts the router image cannot print: switch MAC/VLAN/interface tables, ECMP/BGP/Null0 routes, populated BGP, LACP and spanning tree), NX-OS and Junos are documentation outputs only where the lab Nexus 9300v and vJunos-switch (`../real/cisco_nxos`, `../real/juniper_junos_els`) printed something less than the documented layout (vPC peer-link rows, ECMP, sfpAbsent ports, populated BGP, LACP bundles, Private-VLAN sections).

| Profile | Command references used |
|---|---|
| `cisco_ios` | [Catalyst 2960-X command reference 15.2(7)E](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr.html) (`show interfaces status`, `show mac address-table`, `show vlan brief`), [IP routing](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book.html) (`show ip route`), [ARP](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-r1.html), [LLDP](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/application-services/b-application-services/m_ce-lldp-multivend.pdf) |
| `cisco_xe` | [Catalyst 9300 command reference 17.15](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr.html) (same commands; `Vl10` SVI rows in the MAC table) |
| `cisco_nxos` | [Nexus 9000 show commands 10.5](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051.html) (`show interface status`, `show mac address-table` with `Legend:`, `show vlan`, `show ip arp`, `show ip route`, `show lldp neighbors detail`) |
| `arista_eos` | [EOS manual](https://www.arista.com/en/um-eos/eos-ethernet-ports) chapters Ethernet ports, VLANs, [IPv4](https://www.arista.com/en/um-eos/eos-ipv4), [LLDP](https://www.arista.com/en/um-eos/eos-link-layer-discovery-protocol) (`show interfaces status`, `show mac address-table` with Moves/Last Move, `show vlan` with Cpu/PEt ports, `show ip arp`, `show ip route`) |
| `juniper_junos`, `juniper_junos_els` | [show interfaces terse](https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet/topics/ref/command/show-interfaces-terse.html), [show route detail](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-detail.html), [show ethernet-switching table](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table-qfx-series.html), [show arp](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-arp.html), [show lldp neighbors](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lldp-neighbors.html), [show vlans](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vlans-bridging-qfx-series.html) |

`../tables/<profile>.json` is generated from these files (one entry per normalized table) for the tests that
feed whole outputs through `read_from_device`.

`juniper_junos/lldp_neighbors_detail.txt` follows the `show lldp neighbors detail (l2ng and non-l2ng platform)` example in the linked Juniper LLDP reference, including `Neighbour Information:` and the placement of the Index and Chassis ID fields; site values are synthetic.

## IOS / IOS XE populated IPv6 route lookup (docs only)

`cisco_ios/ipv6_route_lookup.txt` and `cisco_xe/ipv6_route_lookup.txt`
are constructed documentation fixtures, not live captures. They reproduce the
`Routing entry for` / `Known via` / `Route count` / `Routing paths` /
next-hop-and-interface / `Last updated` layout in Cisco's
[IOS IPv6 command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-s5.html)
(`show ipv6 route`, including the directly connected Null0 path) and
[IOS XE 17.3 mGRE verification examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-3/configuration_guide/rtng/b_173_rtng_9500_cg/configuring_unicast_and_multicast_over_point_to_multipoint_gre.html).
The OSPF variant follows the `show ipv6 route` example in Cisco's
[IPv6 hands-on lab](https://www.cisco.com/c/dam/global/en_ca/assets/ciscoconnect/2013/assets/docs/ipv6-hands-on-lab-hritter.pdf);
addresses, prefix length and interface are substituted for the regression case.
Tests also construct ECMP, scoped link-local, connected/static and invalid-row
variants of that layout. All populated IOS/IOS XE IPv6 route lookup evidence is
documentation-only; the live fixtures still contain `% Route not found`.
