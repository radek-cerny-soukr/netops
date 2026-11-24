# EOS eos access control — cEOS 4.36.1F, 2026-11-19 UTC

- ceos-peer-a: `show ip access-lists interface Ethernet5 | json`, `show ipv6 access-lists interface Ethernet5 | json`, `show running-config interfaces Ethernet5` and scoped IPv4/IPv6 ACL configuration sections, captured with the ACLs temporarily bound on the unused Ethernet5 in a timed session.
- ceos-peer-b: `show ip access-lists netops-eos-access-control-empty4 | json`, IPv6 equivalent and scoped ACL configuration sections, with empty configured lists in a timed session.
- ceos-peer-a: `show interfaces Ethernet5 switchport`, `show interfaces Ethernet5 status`, `show lldp neighbors`, `show mac address-table interface Ethernet5`, `show management ssh`.
- Arista cEOS 4.36.1F: `show ip access-lists netops-eos-access-control-v4 | json`, once at privilege 15 (missing ACL) and once as the privilege-1 check account (refused). No writes on ceos.

All captures were processed with `components/netops-helper/tests/support/anonymize_fixture.py --check`. JSON fixtures retain only the fields used by the parser, including EOS rule order, port representation, reported counts, and configured and active attachments. The test-only names were kept. The fake transport derives additional states by selecting measured rule rows with the observed sequence numbers and scoped attachment structure. Negative tests explicitly corrupt or remove selected fields from these fixtures.

- eos access control r2, Arista cEOS 4.36.1F 4.36.1F, 2026-11-19 UTC. `management-route.json` retains the VRF, anonymized prefix, route action and next-hop interface from `show ip route vrf default <peer> | json`. The transport also derives split-VRF and alternate next-hop cases from that response.
- eos access control r2, Arista cEOS 4.36.1F 4.36.1F, 2026-11-19 UTC. `svi-up.json` retains the interface name and line state from `show interfaces Vlan10 | json` and changes the interface name to Vlan200.
