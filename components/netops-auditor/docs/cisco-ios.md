# Cisco IOS and IOS XE audit

Use catalog key `cisco-ios` for offline runs. Inventory types `cisco_ios` and `cisco_xe` select the same set of rules. SSH collection reads `show running-config`, verifies the host fingerprint from inventory, and uses separate read-only exec commands for privilege, parser view, SNMPv3 users and SSH protocol mode when needed.

The audit accepts explicit findings from readable configuration. An apparent complete response can still contain an account-filtered view. The Auditor requires verified coverage, such as privilege 15 with an unrestricted CLI view, before interpreting missing commands in a rule that relies on them. It reports uncovered checks as `not-evaluated` and retains any separately proved findings. A refused running-config read creates no audit run. An offline export can reproduce direct findings and their fingerprints. Coverage for omitted commands and operational tables depends on the evidence available to the collector.

The VTY checks apply range commands in configuration order and retain per-line overrides. The idle timeout policy is ten minutes, including the seconds field, with zero flagged as unlimited. SSH 1 and 1.99 are flagged only on a path permitting SSH. A quiet period requires `login block-for` or proof of enforcement through external AAA. A missing global `login block-for` for active local login paths produces one finding per device. ACL comparison checks whether an inbound filter permits sources outside the operator's prefixes using the effective entry order and transport. Destination-scoped or otherwise ambiguous ACL syntax is reported as `not-evaluated`. IPv6 management needs IPv6 intent when the configuration shows IPv6 management scope. An inbound IPv4 ACL with `vrf-also` covers the same source prefixes in its VRF scope.

The NTP presence rule counts external `server` and `peer` declarations, including VRF scope. A configured local master supplies only a local reference. The syslog level rule uses the remote `logging trap` threshold and requires an effective target. SNMPv3 evaluates active users from the operational table against the running-config groups. Account, community and key values stay out of findings and their fingerprints.

Activate policy-dependent checks through `audit_intent`. Use exact interface names or conventional IOS abbreviations for `ports` and `trusted_dhcp_ports`. The port checks use declared roles and the visible interface mode. Access and trunk findings require evidence that the relevant mode applies. A routed port, SVI or subinterface does not inherit switched defaults. Native VLAN, the trunk's allowed VLAN list and native tagging are distinct settings. With verified interface coverage and a recognized IOS version, an unused port without `shutdown` is administratively up. Without those conditions, an omitted administrative state yields `not-evaluated`. See [the audit intent fields](management-policy.md) for examples and supported values.

## Source references

- [Cisco IOS XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening)
- [Cisco VTY access-class behavior](https://www.cisco.com/c/en/us/support/docs/ip/telnet/116101-problem-telnet-00.html)
- [Cisco IOS exec-timeout reference](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_d1.html)
- [IOS XE 17.14 Layer 2/3 command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/command_reference/b_1714_9300_cr/layer_2_3_commands.html)
- [IOS XE 17.14 VLAN trunk guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/configuration_guide/vlan/b_1714_vlan_9300_cg/configuring_vlan_trunks.html)
- [Cisco IOS SNMP support command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/command/nm-snmp-cr-book/nm-snmp-cr-s1.html)
- [IOS XE SNMP configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/mgmt/management-configuration-guide/snmp-configuration.html)
