# G67 IOS and IOS XE fixtures

Captured 2026-11-19 in the GNS3 netops-d-lab project. Command bodies use LF
and were anonymized together with `components/netops-helper/tests/support/anonymize_fixture.py --check`.

| Files | Device and version | CLI |
| --- | --- | --- |
| `counters-before.out`, `counters-refused.out` | d-iosv, IOSv 15.9(3)M12 | `show interfaces GigabitEthernet0/2`, `show interfaces GigabitEthernet99/99` |
| `mac-before.out`, `mac-empty.out` | d-iosvl2, IOSvL2 15.2(20200924:215240) | `show mac address-table dynamic`, `show mac address-table dynamic interface GigabitEthernet1/0` |
| `switchport.out` | d-iosvl2, IOSvL2 15.2(20200924:215240) | `show interfaces Gi0/3 switchport` with pager advanced by the client |
| `arp-before.out`, `nd-before.out` | d-iolxe, IOL XE 17.18.2 | `show ip arp vrf blue`, `show ipv6 neighbors vrf blue` |
| `counters-after.out`, `mac-after-interface.out`, `arp-after.out` | d-iosv, d-iosvl2, d-iolxe respectively | The same independent operational queries after the approved clear |
| `nd-after.out` | d-iolxe, IOL XE 17.18.2 | `show ipv6 neighbors vrf blue` after the command outcome was reported as unverified; the entry was still present |
| `nd-global-before.out` | d-iosv, IOSv 15.9(3)M12 | `show ipv6 neighbors` |

The test annotates derived replies used to simulate eviction, truncation or a changed scope.

## Task netops-20261121-749 (public source gate of 1.0.12)

The non-documentation dynamic MAC of the MAC tables is the documentation MAC 0000.5e00.53e1 (same in `ios_g85`).
