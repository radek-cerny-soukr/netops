# Operational text fixtures

`*.json` hold one complete output per normalized table of the profile. The EXOS file is an excerpt
of real output (`../real/exos/x440g2-12p-10g4_33.7.1.6_2`), the IOS and EOS files are one live capture per table of the
lab (IOSvL2 and IOSv for `cisco_ios`, cEOS for `arista_eos`); all others are generated from
`../docs/<profile>`, complete outputs reproduced from the vendor documentation of the command in the
catalogue (see `../docs/README.md`). Unknown lines (including unimplemented legends) must remain in `unparsed`.

Older notes on the public sources of the EXOS layouts follow.

EXOS 22.4/32.x: [ports configuration](https://documentation.extremenetworks.com/exos_30.5/GUID-C8DCE6A8-6B36-4F51-BEE7-7AAF6970A190.shtml),
[FDB](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-D0639798-6958-4EC4-8005-1B492354D2C2.shtml),
[VLAN/ARP/LLDP layouts](https://documentation.extremenetworks.com/PDFs/EXOS/EXOS_Quick_Guide.pdf).
FDB row preserves the published flag layout; other rows are synthetic field
variations of the documented layouts. Summary VLAN does not enumerate ports.

IOS 15.x / IOS XE 17.x: [ARP](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-r1.html),
[LLDP](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/application-services/b-application-services/m_ce-lldp-multivend.pdf),
[interface/VLAN/MAC/route command examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/15-2_2_e/command_reference/b_1522e_2960_cr.html).
Short field-layout variations share a fixture across IOS and XE; they do not
assert administrative state where status only reports link state.

NX-OS 9.x/10.x: [Cisco Nexus show commands](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/command-reference/show/b_n9k_show_commands_103x/m_l_showcmds.html),
[manufacturer LLDP examples](https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/lldp-commands/).
Fixtures use the existing text catalogue, not NX-API or JSON commands; NX-OS
MAC age/security columns and ubest/mbest route paths differ from IOS.

EOS 4.x: [Ethernet ports](https://www.arista.com/en/um-eos/eos-ethernet-ports),
[public EOS manual, ARP/MAC/VLAN/LLDP/route examples](https://www.arista.com/assets/data/docs/Manuals/EOS-4.15.0F-Manual.pdf).
LLDP summary does not include management IP or capabilities; these remain null.

Junos 23.x (including ELS): [VLAN brief](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vlans-bridging-qfx-series.html),
[route detail](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-detail.html),
[Ethernet switching table](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table-qfx-series.html),
[ARP](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-arp.html),
[LLDP](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lldp-neighbors.html).
The common Junos catalogue has no VLAN or MAC template. ELS MAC VLAN names
require joining the VLAN table; a name is never guessed to be an 802.1Q tag.

FortiGate / managed FortiSwitch: [MAC table layout](https://community.fortinet.com/fortiswitch-36/technical-tip-how-to-display-mac-address-table-of-a-managed-fortiswitch-from-fortigate-cli-227557),
[IPv6 cache layout](https://community.fortinet.com/fortigate-3/troubleshooting-tip-increasing-ipv6-neighbor-cache-limit-on-the-fortigate-130059),
[LLDP summary reference](https://community.fortinet.com/support-forum-92/register-cisco-phones-via-lldp-67081).
The short LLDP fixture is a synthetic summary variant, not a live qualification.
Unrecognized FortiSwitch firmware summary layouts remain unparsed.

Additional IPv6 layouts: [EXOS two-line cache](https://documentation.extremenetworks.com/exos_commands_31.7/GUID-685B2415-0402-477F-BBA2-4812D186C9DE.shtml),
[IOS ND](https://www.cisco.com/c/en/us/td/docs/ios/ipv6/command/reference/ipv6_book/ipv6_15.html),
[Junos ND](https://www.juniper.net/documentation/us/en/software/junos/neighbor-discovery/topics/topic-map/ipv6-neighbor-discovery.html).
[EXOS LLDP age column](https://documentation.extremenetworks.com/exos_commands_16/EXOS_16_2/EXOS_Commands_All/r_show-lldp-neighbors.shtml)
and [EOS terse route lookup](https://www.arista.com/en/um-eos/eos-ipv4)
are preserved in the corresponding fixtures. NX-OS/EOS ND test rows are
synthetic variants of the same documented address/MAC/interface column layout.

`../ospf_live20.json` preserves five anonymized successful OSPF CLI captures from live acceptance on 2026-11-10 (timestamps and commands included); engine tests also exercise documented state spellings on those layouts.
