# NX-OS nxos access control fixtures

Nexus 9000v C9300v, NX-OS 9.3(12), SSH exec with strict host-key checking. Collected on 2026-11-19 from Nexus 9300v, NX-OS 9.3(12), switch-pair nexus-peer-a and nexus-peer-b. Anonymized with `components/netops-helper/tests/support/anonymize_fixture.py --check`.

- `v4-acl-shaped` and `v6-acl-shaped` are the read-only captures from `show ip access-lists copp-system-p-acl-auto-rp` and `show ipv6 access-lists copp-system-p-acl-vrrp6`.
- `acl4-summary` and `acl6-summary` are their corresponding `summary` displays.
- `*-missing` and `missing-summary` are successful zero-byte responses for `NETOPS-NXOS-ACCESS-CONTROL-PROBE`.
- `port-switchport`, `port-mac`, and `ip-int-acl` are the switchport, per-port MAC table, and rejected interface-scoped ACL query for Ethernet1/47. The accepted interface-independent query is the named ACL with the `summary` suffix.
- `nexus9300v__cdp` is `show cdp neighbors` with host identifiers anonymized.
- `port_before`, `port_status`, and `port_mac` are the scoped running configuration, status and MAC table of the reserved Ethernet1/64 from the first real run.
- `ipv4-created_*` and `ipv6-created_*` are the exact named ACL and summary readbacks after confirmed Admin writes. The anonymizer maps the test IPv6 prefix to `2001:db8:1::/64` in the fixtures.
- `ipv4-reordered_*` was collected from Nexus 9300v, NX-OS 9.3(12) after the confirmed Admin update from sequences 10 and 30 to sequence 20.
- `ipv4-pacl_interface` and `ipv4-pacl_summary` were captured on Nexus 9300v, NX-OS 9.3(12) after confirmation. The named ACL reports Ethernet1/64 ingress both configured and active.
- `ipv6-pacl_interface` and `ipv6-pacl_summary` are the equivalent confirmed IPv6 readbacks on Ethernet1/64.
- `svi_before` is the confirmed scratch `Vlan3910` before an ACL binding. It comes from `show running-config interface vlan 3910`.
- `ipv4-svi_interface` and `ipv4-svi_summary` were captured after the confirmed IPv4 RACL apply on Vlan3910. The ACL is configured ingress and the active section is empty while the isolated SVI is down.
- `ipv6-svi_interface` and `ipv6-svi_summary` capture the corresponding confirmed IPv6 egress RACL on Vlan3910.
- `ipv6-empty_*` was captured after the confirmed create of an empty IPv6 ACL on nexus9300v. The named ACL has a header and no ACE lines, and the summary reports zero ACEs.
- `ipv6-reordered_*` is the named ACL and summary after the confirmed update of the empty IPv6 ACL to a rule with sequence 20.

## verification (public source gate of 1.0.12)

The lab domain of the CDP device IDs is written as `node1.invalid` like the other rows.
