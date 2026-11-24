# ExtremeXOS VM ExtremeXOS VM 33.6.1.14, 33.6.1.14

Čtení přes SSH exec účtem `netops-ro` dne 2026-11-18. Výstupy anonymizoval
`components/netops-helper/tests/support/anonymize_fixture.py --check`. Soubory
s příponou `.out` obsahují samotné odpovědi CLI bez koncových mezer.

| Soubory | Příkaz a měření |
|---|---|
| `stats-wide*`, `stats-error` | `show ports <port> statistics no-refresh wide` pro volné porty 6 a 7 a pro aktivní port 3. Chyba je odpověď pro port 999 bez `wide`. |
| `fdb-{hit,hit-one,one,miss}` | `show fdb <mac>` pro více dynamických řádků, kombinaci dynamického a statického řádku, jediný dynamický řádek a prázdný filtr. |
| `fdb-port*`, `fdb-vlan` | `show fdb ports <port>` pro obsazený a volný port a `show fdb vlan <vlan>` pro obsazenou VLAN. |
| `arp-hit`, `arp-miss-vr` | `show iparp <ip> vr VR-Default` pro přítomný a nepřítomný záznam. |
| `nd`, `nd-miss` | Prázdná tabulka z `show neighbor-discovery cache ipv6`, chyba při filtrování podle IP bez připojené IPv6 sítě. |
| `fdb-static`, `arp-static`, `nd-static` | Výpis podle jednotlivé testovací MAC nebo IP z VLAN g50test (3950), ze samostatného měření `switch maintenance-measure`. FDB má souvislé příznaky `spm` a IPv6 ND zabírá dva řádky. |

## Follow-up capture (2026-11-18)

| Soubory | Původ |
|---|---|
| `fdb-switch-maintenance-a.out`, `fdb-switch-maintenance-port6.out`, `arp-switch-maintenance-a.out`, `nd-switch-maintenance-a.out` | Skutečné výpisy ExtremeXOS VM 33.6.1.14 33.6.1.14 účtem `netops-ro` z živého běhu (soukromý záznam měření, pole `raw` prvního čtení každého příkazu): `show fdb <MAC hosta>`, `show fdb ports 6`, `show iparp 192.0.2.10 vr VR-Default`, `show neighbor-discovery cache ipv6 2001:db8:3950::10 vr VR-Default` pro aktivního labového hosta testovací koncový bod A (VPCS, port 6, dokumentační prefixy). Kromě odstranění koncových mezer je MAC hosta v příkazu i ve výpisech nahrazena dokumentační `00:00:5e:00:53:a4` (verification, viz níže). Testy je používají i jako výpis po clearu, kdy se záznam znovu naučil. |
| `lldp-exosvm.out` | Skutečný výpis `show lldp neighbors` z ExtremeXOS VM 33.6.1.14 (účet `netops-admin`, běh v soukromém záznamu měření). Chassis ID nahrazeny dokumentačními MAC `00:00:5E:00:53:2x` stejné délky a jméno labové domény v System Name nahrazeno `node1.invalid` (verification), jinak beze změny (řádky `mgmt` jsou skutečné). |
| odvozené v `test_exos_switch_maintenance.py` | `LLDP_MGMT_ONLY` (jen řádky `mgmt`), `ARP_A_OTHER_MAC` (jiná MAC na adrese hostu A), `FDB_MGMT` (VLAN `Mgmt(4095)`), `ARP_VR_MGMT` (VR-Mgmt) a `_counters()` (rozložení `stats-wide-active.out` s jinými hodnotami) jsou odvozené, ne měřené. |

## verification (veřejná brána zdroje 1.0.12)

- MAC labového hosta (VPCS) nahrazena dokumentační `00:00:5e:00:53:a4` ve všech fixturách i v `test_exos_switch_maintenance.py`.
  Druhou MAC `…:a5` odvozuje jen test (`ARP_A_OTHER_MAC`), ve fixturách není. Jméno labové domény
  v `lldp-exosvm.out` je `node1.invalid`.
