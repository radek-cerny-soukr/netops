# IOS XE G85

Odečty GNS3 `netops-d-lab` z 2026-11-20. Výstupy CLI byly anonymizovány společně skriptem
`components/netops-helper/tests/support/anonymize_fixture.py --check`.

| Fixture | Zařízení, OS | Čtení |
| --- | --- | --- |
| `xe-counters-before.out` | d-iolxe-l2, IOL-L2 XE 17.18.2 | `show interfaces Ethernet0/1` |
| `xe-counters-refused.out` | d-iolxe-l2, IOL-L2 XE 17.18.2 | `show interfaces Ethernet99/99` |
| `xe-mac-before.out`, `xe-mac-count.out` | d-iolxe-l2, IOL-L2 XE 17.18.2 | `show mac address-table dynamic`, `show mac address-table count` |
| `xe-switchport.out` | d-iolxe-l2, IOL-L2 XE 17.18.2 | `show interfaces Ethernet0/1 switchport` |
| `xe-arp-before.out` | d-iolxe, IOL XE 17.18.2 | `show ip arp vrf blue` |
| `xe-nd-before.out`, `xe-nd-empty.out` | d-iolxe, IOL XE 17.18.2 | `show ipv6 neighbors vrf blue` |
| `xe-nd-global.out` | d-iolxe, IOL XE 17.18.2 | `show ipv6 neighbors` |

Test označuje odvozené varianty z reálných odečtů. V labu jsou MAC řádky na management portu.
Pro simulaci úspěchu test přesune jediný řádek na existující testovací access port a po clear upraví součet.

- `xe-counters-after.out`, `xe-arp-after.out`, `xe-nd-after.out` jsou nezávislé odečty stejných příkazů po živém běhu. ARP se ihned znovu naučilo, ND položka zůstala.
- `xe-nd-refused.out` je diagnostický řádek z odpovědi na cílený ND clear v EXEC. `xe-nd-empty.out` zachovává samotnou hlavičku pozorovanou při prvním odečtu před diagnostickou sondou.
- `xe-mac-empty-port.out` pochází z `show mac address-table dynamic interface Ethernet0/1`. Nulový globální součet pro případ prázdné tabulky test odvozuje z naměřeného formátu.

## Úkol netops-20261121-749 (veřejná brána zdroje 1.0.12)

- Dynamická MAC z tabulky MAC nahrazena dokumentační `0000.5e00.53e1` (stejně ve fixturách `ios_g67` a v
  `test_ios_g85.py`).
