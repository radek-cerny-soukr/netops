# eos targeted clear — cEOS 4.36.1F

Výstupy z 2026-11-20 (verification), anonymizované přes `components/netops-helper/tests/support/anonymize_fixture.py --check`
(MAC → `00:00:5e:00:53:NN`, IPv4 → dokumentační rozsahy, IPv6 → `2001:db8:…`, názvy uzlů). Zařízení: ceos-peer-a (GNS3 projekt
s dvojicí MLAG, cEOS 4.36.1F) a Arista cEOS 4.36.1F (GNS3 emulated environment, cEOS 4.36.1F). Všechna čtení účtem `netops-ro`, clear příkazy účtem
`netops-admin`. Testovací objekty: Ethernet5 ceos-peer-a v přístupové VLAN 3931 se dvěma dočasnými koncovými uzly (Alpine, GNS3 uzly `eos targeted clear-*`),
dvě eBGP relace ceos-peer-a ↔ ceos-peer-b (AS 65126/65127, VLAN 3930 a 3932 na peer-linku). Surové (neanonymizované) výstupy v repozitáři nejsou.

| soubor | příkaz | stav |
| --- | --- | --- |
| `switch-peer-a__show-interfaces-ethernet5-before.txt` | `show interfaces Ethernet5` | před `clear counters Ethernet5` (`Last clearing … never`) |
| `switch-peer-a__show-interfaces-ethernet5-after-clear.txt` | tentýž | 2 s po `clear counters Ethernet5` (`0:00:02 ago`, čítače nulové) |
| `ceos__show-interfaces-ethernet10.txt` | `show interfaces Ethernet10` | port bez provozu, `never` (druhý port) |
| `switch-peer-a__show-mac-json-before.txt` / `-after-clear` / `-relearned` / `-second` | `show mac address-table address <mac> \| json` | před `clear mac address-table dynamic vlan 3931 address <mac>`, po něm (prázdná tabulka), po opětovném naučení (nový `lastMove`), druhá MAC téhož portu |
| `switch-peer-a__show-ip-arp-json-before.txt` / `-after-clear` / `-relearned` / `-second` / `-static` | `show ip arp [vrf default] <ip> \| json` | před `clear arp <ip>`, po něm, po opětovném naučení (`age` 6), druhá IP, statický záznam (bez `age`) |
| `switch-peer-a__show-ip-arp-vrf-absent.txt` | `show ip arp vrf nosuch <ip> \| json` | neznámé VRF (`errors`, rc 1) |
| `switch-peer-a__show-ipv6-neighbors-json-before.txt` / `-after-clear` / `-second` / `-static` | `show ipv6 neighbors <ip> \| json` | před `clear ipv6 neighbors Vlan3931 <ip>`, po něm, druhý soused, statický |
| `switch-peer-a__show-bgp-neighbor-json-before.txt` / `-after-soft-in` / `-after-soft-out` / `-second` / `-absent` | `show ip bgp neighbors <peer> \| json` | před, po `clear ip bgp <peer> soft in`, po `… soft out`, druhý soused (nedotčený), neexistující soused (`peerList` prázdný) |
| `ceos__show-bgp-neighbor-json-inactive.txt` | `show ip bgp neighbors <peer> \| json` | Arista cEOS 4.36.1F bez BGP: rc 1, `errors: ["BGP inactive"]` |
| `switch-peer-a__show-lldp-neighbors-json.txt`, `switch-peer-a__show-interfaces-ethernet5-switchport.txt`, `switch-peer-a__show-interfaces-invalid.txt` | `show lldp neighbors \| json`, `show interfaces Ethernet5 switchport`, `show interfaces Ethernet99` | kontroly ochran; neexistující rozhraní (`% Invalid input`) |

Změřeno: `clear mac address-table dynamic address <mac>` a `clear ipv6 neighbors <ipv6>` z řádku plánu EOS 4.36.1F nezná (`% Unrecognized command`; adresa
je jen za `vlan <n>`, IPv6 sousedu předchází rozhraní); nápověda `?` je v soukromém záznamu měření. Čas posledního vynulování čítačů je jen
v textu `show interfaces`, JSON ho nemá. ARP/ND záznam bez `age` je statický. U starších záznamů vrací cEOS v labu nesmyslně velký `age`
(hodiny stovek dnů), čerstvě naučený záznam má malý.
