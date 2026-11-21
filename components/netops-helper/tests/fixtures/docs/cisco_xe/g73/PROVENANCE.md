# Cisco IOS XE documentation examples

Selected CLI output lines from the linked Cisco examples. Prompt lines are
omitted and `anonymize_fixture.py --check` anonymized the captures. The access
session example omits unrelated fields and the entire redirect URL. Tests only
inject synthetic redirect values. The snooping total mutation and pager
markers in the tests are derived negative cases.

| Fixture | Cisco source |
|---|---|
| `acl6` | [IOS XE 17.18, Catalyst 9400, Displaying IPv6 ACLs](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/17-18/configuration_guide/sec/b_1718_sec_9400_cg/configuring_ipv6_acls.html) |
| `pool`, `lease` | [IOS XE 17.x, DHCP Server On-Demand Address Pool Manager](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-dhcp-addr-pm-xe.html). Global pool excerpt and the subnet-lease example respectively. |
| `snoop_binding` | [Cisco Catalyst 9000 DHCP snooping troubleshooting](https://www.cisco.com/c/en/us/support/docs/ip/dynamic-host-configuration-protocol-dhcp-dhcpv6/217055-operate-and-troubleshoot-dhcp-snooping.html). |
| `access_session` | [IOS XE 17.18, Catalyst 9300, show access-session](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/command_reference/b_1718_9300_cr/security_commands.html). Detail by MAC prints the same access-session detail fields. Cisco also [shows the detailed interface selector](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ibns/command/ibns-xe-3se-3650-cr-book.pdf). |
| source_guard | [ASR 920 IOS XE 17.1.1, IP Source Guard Verification](https://www.cisco.com/c/en/us/td/docs/routers/asr920/configuration/guide/ipaddr-dhcp/17-1-1/b-dhcp-xe-17-1-asr920.pdf). First two rows of the global inspection example. |
| dot1x | [Catalyst 9800 IOS XE 17.14, Verify 802.1X on the switch port](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-14/config-guide/b_wl_17_14_cg/m_data_dtls.html). Derived per-port excerpt from show dot1x all, with the interface label changed to the enrolled physical port used by the test. [Catalyst 9300 IOS XE 17.18](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/command_reference/b_1718_9300_cr/security_commands.html) documents the scoped command. |

Tests also replay the populated G55 examples of conflicts, violations, secure
MACs and DAI counters as raw output. Their individual provenance remains in
[the G55 fixtures](../../cisco_ios/g55/PROVENANCE.md). Cisco IOS XE 17 documents
the same [DHCP conflict command](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-dhcp-server-xe.html),
[port security reads](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html)
and [DAI counters](https://www.cisco.com/c/en/us/td/docs/IIOT/switches/ie35xx/sw-config-guide/17-18/b_ie3500_1718-cg/m9_1714_sec_dynamic_arp_cg.html).
