# Cisco IOS and IOS XE audit inputs

The 66 cases under `../rules/cisco-ios.*/` are derived examples. They use documentation IP addresses, invented object labels and `SECRET-DATA` or `ACCESS-DENIED` placeholders. They are individual test bodies. The test supplies configuration framing and separate replies for privilege, CLI view, SNMP user information and SSH status at the SSH transport boundary. A matching running-config header or an `end` line supplies no evidence about account privileges.

- Management, AAA, local credential storage, legacy SNMP, NTP, logging and source-routing cases derive from the Cisco IOS XE Software Hardening Guide. They add explicit `no` forms, replaced VTY ranges, partial definitions and unknown values for negative and incomplete scenarios.
- The extended VTY ACL replay uses the portable `any` destination from Cisco VTY access-class behavior. It changes the source ranges and sequence order to test first-match semantics. The IPv6 cases use documentation prefixes.
- Switchport, PortFast, BPDU guard, discovery and snooping cases use the IOS XE 17.14 Layer 2/3 command reference and the IOS XE 17.14 VLAN trunk guide. The tests replace VLANs, limits and intended port roles, and add explicit port overrides.
- SNMPv3 user rows are derived from the Cisco IOS SNMP support command reference and the IOS XE SNMP configuration guide. The example uses an invented engine ID and user. The privilege and SSH replies model a root view, a restricted view, and disabled or enabled SSH versions.

The vendor URLs are listed in the [source references](../../../docs/cisco-ios.md#source-references).

The regression tests also read the existing redacted running-config baselines under `ios_ios_static_routing`, `ios_ios_access_control` and `ios_c45` from the Admin component. They reuse port-level `spanning-tree portfast edge` from IOSvL2 15.2, change the effective global and port settings in memory, and validate IOSv 15.9 and IOL XE 17.18 against the same catalogue. The `ios_ios_system_services/iosv-changed.txt` NTP command is reused with and without a derived local master. The existing `iosxe_xe_access_control/ro-show-running-config__denied.txt` fixture supplies the unmodified refusal. No new capture of a complete device configuration is stored here.
