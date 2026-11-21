GNS3 D-lab captures from 2026-11-20, SSH exec as netops-ro, with the inventory's pinned host keys.
d-iolxe and d-iolxe-l2 both ran IOS XE 17.18.2.
Anonymized with `tests/support/anonymize_fixture.py --check` and stripped trailing horizontal whitespace.
The router has a policy-routing clause that sets Null0, a matching ACL definition and a VRF peer.
The switch has an administratively disabled port and an active STP port.

| File | CLI request |
|---|---|
| version | `show version` |
| interface | `show interfaces Ethernet0/2` on d-iolxe, `show interfaces Ethernet1/0` on d-iolxe-l2 |
| active_interface | `show interfaces Ethernet2/0` on d-iolxe-l2 |
| stp | `show spanning-tree` |
| rib | `show ip route` for the enrolled IPv4 destination |
| vrf_rib | `show ip route vrf blue` for the other end of the link |
| vrf_arp | `show arp vrf blue` |
| sla | `show ip sla statistics` |
| cef | `show ip cef <destination> detail` |
| ip_interface | `show ip interface Ethernet0/1.10` on d-iolxe, `show ip interface Ethernet0/3` on d-iolxe-l2 |
| policy | `show ip policy` |
| route_maps | `show route-map` |
| acl | `show ip access-lists` |
