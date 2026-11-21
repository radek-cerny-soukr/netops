# Cisco sample output for G55

These are excerpts from published CLI examples, transcribed into line-oriented
output with the prompts removed. The repository's `tests/support/anonymize_fixture.py`
was applied to the set. No fixture in this directory was captured live.

| Fixtures | Cisco source |
|---|---|
| `snoop`, `snoop_binding`, `snoop_stats`, `port_security`, `secure_mac`, `dot1x`, `dai`, `source` | [Catalyst 3750-X and 3560-X IOS 15.2(4)E command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750x_3560x/software/release/15-2_4_e/command/reference/CR_3750X/cli2.html). Cisco's DAI example scopes the same statistics to VLAN 5. |
| `auth` | [Cisco IOS authentication commands, including release 15.2(2)T](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s2.html). Excerpt from the detailed interface example. |
| `acl4` | [Cisco IOS ACL counters](https://sec.cloudapps.cisco.com/security/center/resources/identification_ios_security_mitigations_effectiveness). Two rules from the IPv4 ACL 150 example. |
| `acl6` | [Catalyst 2960 IOS 15.x IPv6 ACL configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/15-0_2_se/configuration/guide/scg2960/swv6acl.html). Excerpt from the inbound IPv6 ACL example. |
| `lease`, `conflict` | [Cisco IOS IP Addressing Services Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-r1.html). A single-address binding and the global conflict table. |
| `pool` | [Cisco IOS 15S DHCP configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_dhcp/configuration/15-s/dhcp-15-s-book/config-dhcp-addr-pm.html). The first sample pool. |
