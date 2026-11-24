# overview_h3 – původ vzorků pro adaptér `network_overview` Cisco (H3)

`captures.json` má klíče `platforma/ID čtení/scénář`. Hodnota je text výstupu tak, jak ho adaptér dostane od transportu.

| Klíč | Původ | Úprava |
|---|---|---|
| `cisco_xe/power_inline/doc_c9200_poe_troubleshooting` | Dokumentace výrobce, „Troubleshoot Power over Ethernet (PoE)“ na Catalyst 9200/9300, příklad `show power inline module 1`: https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9200-series-switches/215636-troubleshooting-power-over-ethernet-poe.html | Přepsáno z HTML bez poznámek `<++` dokumentu. Mezery řádků převzaté z výpisu stránky. |
| `cisco_xe/power_inline/derived_summary_mismatch` | Odvozeno z předchozího vzorku | **Odvozená negativní kopie:** `Remaining` 848.1 → 748.1, souhrn už nesouhlasí s `Available - Used`. |
| `cisco_xe/stack_members/doc_c9300_stackwise` | Dokumentace výrobce, „Verify and Troubleshoot StackWise on Catalyst 9200/9300“, tabulka členů z `show switch detail`: https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/217684-verify-and-troubleshoot-stackwise-on-cat.html | Stránka sloučila zarovnávací mezery do jedné, parser proto dělí sloupce libovolnými mezerami. MAC adresy jsou ty z dokumentu. |
| `cisco_xe/stack_members/derived_member_removed` | Odvozeno z předchozího vzorku | **Odvozená negativní kopie:** stav člena 3 `Ready` → `Removed`. |
| `cisco_xe/stack_ports/doc_c9300_stackwise` | Stejný dokument výrobce, `show switch stack-ports summary` | Beze změny obsahu. |
| `cisco_xe/stack_ports/derived_port_down` | Odvozeno z předchozího vzorku | **Odvozená negativní kopie:** port 2/2 `OK` → `DOWN`, soused `None`, `Link OK` `No`. |
| `cisco_ios/version/live_iosv_15.9.3M12`, `cisco_ios/interfaces_details/live_iosv_15.9.3M12` | Reálný výstup, emulovaný IOSv 15.9(3)M12, čtecí účet privilege 1, nezávislé SSH čtení `show version` a `show interfaces` při autorském živém průchodu H3 (2026-11-22) | Anonymizováno `tests/support/anonymize_fixture.py --check` (adresy, MAC, jméno hostu, popisy portů). Obsahuje dvě smazaná subrozhraní (`is deleted`). |
| `cisco_xe/version/live_iolxe_17.18.2`, `cisco_xe/interfaces_details/live_iolxe_17.18.2` | Reálný výstup, emulovaný IOL XE 17.18.2 (router), čtecí účet privilege 1, tentýž průchod | Anonymizováno stejně. Cesta souboru obrazu v `show version` zkrácena na `unix:/images/<soubor>` (původní cesta obsahovala adresář labového serveru). Obsahuje dvě smazaná subrozhraní. |
| `cisco_nxos/vpc_status/live_nexus9300v_9.3.12_feature_off` | Reálný výstup, Nexus 9000v 9.3(12) bez zapnuté funkce vPC, čtecí účet, `show vpc brief`, exit status 16, tentýž průchod | Beze změny (výstup neobsahuje identifikátory). |

Ostatní vstupy testů jsou existující archivované fixtury v `real/cisco_ios/`, `real/cisco_xe/` a `real/cisco_nxos/` s jejich vlastním `PROVENANCE.md` nebo `index.json`. Negativní varianty vytvořené přímo v testu (neznámý stav portu, neznámý řádek detailu, stránkovací výzva, rozpor součtu paměti, řádek licence) jsou v `test_network_overview_cisco.py` označené komentářem `Derived`.
