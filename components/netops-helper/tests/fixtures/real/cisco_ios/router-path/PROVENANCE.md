GNS3 emulated environment captures from 2026-11-20, SSH exec as netops-ro, with the inventory's pinned host keys.
Cisco IOSv 15.9(3)M12 ran IOS 15.9(3)M12 and Cisco IOSvL2 15.2 ran IOS 15.2(20200924:215240).
Anonymized with `tests/support/anonymize_fixture.py --check` and stripped trailing horizontal whitespace.
The captures show an existing IP SLA timeout, a working VRF adjacency, a disabled switchport and an active STP port.

| File | CLI request |
|---|---|
| version | `show version` |
| interface | `show interfaces GigabitEthernet0/2` on Cisco IOSv 15.9(3)M12, `show interfaces GigabitEthernet1/0` on Cisco IOSvL2 15.2 |
| ingress_details | `show interfaces GigabitEthernet0/3` on Cisco IOSvL2 15.2 |
| stp | `show spanning-tree` |
| rib | `show ip route` for the enrolled IPv4 destination |
| vrf_rib | `show ip route vrf blue` for the other end of the link |
| vrf_arp | `show arp vrf blue` |
| sla | `show ip sla statistics` |
| cef | `show ip cef <destination> detail` |
| policy | `show ip policy` |
| ip_interface | `show ip interface GigabitEthernet0/1.10` on Cisco IOSv 15.9(3)M12, `show ip interface GigabitEthernet0/3` on Cisco IOSvL2 15.2 |
