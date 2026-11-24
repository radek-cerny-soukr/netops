# Výstupy Cisco IOS pro ios port ownership

Zachyceno 2026-11-20 v virtuálním prostředí. `router-*` je Cisco IOSv 15.9(3)M12 15.9(3)M12,
`switch-*` je Cisco IOSvL2 15.2 15.2(20200924:215240). Použity připnuté SSH klíče.
Výstupy byly anonymizovány pomocí `components/netops-helper/tests/support/anonymize_fixture.py --check`.
Soubor `*-configuration.txt` je cílený výřez z `show running-config | include`
obsahující hlavičku, verzi, hostname, rozhraní, podřízené switchport/shutdown
řádky a koncové `end`. Nejde o úplnou konfiguraci.

| Přípona | Účet | Příkaz |
|---|---|---|
| `version` | netops-admin | `show version \| include Cisco IOS Software` |
| `descriptions` | netops-ro | `show interfaces description` |
| `status` | netops-admin | `show interfaces GigabitEthernet0/3` / `GigabitEthernet1/0 \| include ^Gigabit\|Description:` |
| `conflict` | netops-admin | `show archive config differences nvram:startup-config system:running-config` |
| `timer` | netops-admin | `show archive config rollback timer` |
| `privilege-ro` | netops-ro | `show privilege` |
| `acl-absent` | netops-ro | `show ip access-lists NETOPS-ios port ownership-TEST` (prázdný výstup) |
| `unsupported` | netops-admin | `show vlan id 3968` (odmítnutí na routeru) |
| `vlan-brief` | netops-ro | `show vlan brief` |
| `switchport` | netops-ro | `show interfaces GigabitEthernet1/0 switchport` |
| `vtp` | netops-admin | `show vtp status \| include VTP version running\|VTP Operating Mode` |

Záměrně neúplný výstup v regresním testu vzniká odstraněním řádku z
`switch-descriptions.txt`.
