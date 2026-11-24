# Fixtures verification (NX-OS 9.3(12), GNS3 Nexus 9300v, NX-OS 9.3(12))

Zařízení: GNS3 emulated environment `Nexus 9300v, NX-OS 9.3(12)`, Nexus 9000v (C9300v), NX-OS 9.3(12);
host key pin RSA `SHA256:WKyD7HfKyfDdf2Sl8h7C7uJAFWfHDgAPxaBYWfXiz7E`. Zachyceno 2026-11-18 07:3x UTC
samostatným SSH exec (paramiko, RejectPolicy), každý příkaz ve vlastním kanálu, bez změny stránkování.

## raw/ (skutečné výstupy, anonymizované)

| soubor | příkaz | účet | poznámka |
|---|---|---|---|
| `bgp_ipv6_summary.out` | `show bgp ipv6 unicast summary` | netops-ro | během dočasné konfigurace úkolu (feature bgp, `router bgp 65045`, soused `2001:db8:4590::1234:5678` remote-as 65046, Idle); NX-OS adresu zalomil na samostatný řádek |
| `bgp_ipv6_summary_vrf.out` | `show bgp ipv6 unicast summary vrf default` | netops-ro | totéž, VRF dotaz |
| `snmp_statistics_admin.out` | `show snmp` | netops-admin | tabulka komunit prázdná (na zařízení není nakonfigurovaná žádná komunita) |
| `snmp_statistics_ro.out` | `show snmp` | netops-ro | místo tabulky hláška role `User does not have permission to view community strings.` |
| `snmp_community.out` | `show snmp community` | netops-admin | jen hlavička a podtržení (RO: `% Permission denied for the role`) |
| `snmp_statistics_populated.out` | `show snmp` | netops-admin | verification, 2026-11-18 08:45 UTC, během dočasné testovací komunity: místo tabulky řádky `Community name:` / `Community groupname:` / `Context mapped:` |
| `snmp_community_populated.out` | `show snmp community` | netops-admin | totéž, samostatný příkaz |

Anonymizace: `tests/support/anonymize_fixture.py --user netops-ro --user netops-admin` mimo repozitář, jeden běh přes všech
pět souborů; mapa uložena jen mimo repozitář. Změny: BGP router-id → `192.0.2.5`; IPv6 soused
`2001:db8:4590::1234:5678` → `2001:db8:1::10` (nástroj přečísluje i dokumentační IPv6; zalomení řádku zůstalo tak,
jak ho vytiskl přístroj pro 24znakovou adresu); jména SNMP uživatelů → `user01`/`user02`. Jinak beze změny.
SHA256 neanonymizovaných surových výstupů jsou v soukromém záznamu měření.

`*_populated.out` (verification) jsou bajtové kopie anonymizovaných živých záchytů
ze soukromého záznamu měření (tam jsou i původ a hashe); jediná změna je
syntetická hodnota komunity `nx490r2-fixtureXXXXXXXX` nahrazená kanárkem `nx490-populated-canary1` stejné délky.
Skutečná dočasná hodnota z labu v repozitáři není.

## derived/ (přiznaně odvozené z raw/, ne zachycené)

| soubor | odvozeno z | změna |
|---|---|---|
| `snmp_statistics_known_canary.out` | `raw/snmp_statistics_admin.out` | za podtržení známé hlavičky 9.3(12) vložen řádek komunity `"nx490 canary known"  network-operator` (na labu žádná komunita není a konfigurace SNMP úkolem schválena nebyla) |
| `snmp_statistics_unknown_header.out` | `raw/snmp_statistics_admin.out` | hlavička a podtržení tabulky komunit nahrazeny jiným tvarem (`Community Name  Access  Group  ACL`, pomlčky) a přidány dva řádky s kanárky – simulace jiné verze NX-OS |
| `snmp_community_known_canary.out` | `raw/snmp_community.out` | přidán řádek komunity s kanárkem |
| `snmp_community_unknown_header.out` | `raw/snmp_community.out` | hlavička a podtržení jiného tvaru + řádek s kanárkem |
| `bgp_ipv6_summary_long_address.out` | `raw/bgp_ipv6_summary.out` | anonymizovaná adresa vrácena na původní dokumentační `2001:db8:4590::1234:5678` (RFC 3849, neidentifikuje lab) |
| `bgp_ipv6_summary_multi.out` | `raw/bgp_ipv6_summary.out` | přidán druhý zalomený soused (`2001:db8:1::11`, Established, 3 prefixy) a jednořádkový IPv4 soused (Active) |

Tvar neznámé hlavičky není převzatý z žádné konkrétní verze NX-OS; testuje jen to, že redakce je fail-closed.
