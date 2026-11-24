# xe port ownership · IOS XE 17.18.2

Cílené SSH exec výpisy z GNS3 Cisco IOL XE 17.18.2 a Cisco IOL-L2 XE 17.18.2, verification.
Záznam pořízení je soukromý. Anonymizace použila
`components/netops-helper/tests/support/anonymize_fixture.py --check`.
Příkazy a role účtů odpovídají položkám v ovladači. Výchozí celé snapshoty a
odpovědi pojistky v simulátorech pocházejí z `ios_c45`, `iosxe_xe_access_control` a `ios_xe_system_services`.
Simulace mění řádek popisu ve změřené provozní tabulce podle aktuálního stavu
a odvozený případ neúplného výstupu vynechává řádek cílového portu.

Regrese inventářové ochrany VLAN 20 používá skutečné výpisy `show tcp brief` a
`show ip interface brief` z `ios_c45/iolxe-l2`, kde SSH končí na Vlan99.
Stav zapojeného access portu ve VLAN 20 je odvozený z konfigurace `ios_c45`
a výpisů `description` a `switchport` v této sadě. Simulace odebere `shutdown`,
přidá `switchport access vlan 20` a upraví odpovídající provozní řádky portu.

Regrese vyjednaného trunku odvozuje varianty ze stejného změřeného výpisu
`iol-xe-switch-switchport.txt` a naměřené tabulky `description`. Mění stav linky,
administrativní a provozní mód, DTP a povolené VLANy. SSH stále končí na
změřené Vlan99. Další varianty pokrývají inventářovou VLAN 20, nakonfigurovaný
trunk a chybějící, prázdný, neznámý nebo zdvojený provozní mód.

`iol-xe-switch-ipv4-listing.txt` a `iol-xe-switch-ipv6-listing.txt` jsou provozní
výpisy z 06:37 UTC před konfigurací první ACL. `iol-xe-switch-acl-created.txt`
zachytil účet `netops-ro` v 06:45:50 UTC příkazem `show ip access-lists NETOPS-xe port ownership-713`.
Simulátor přidá tento změřený výpis k provozním ACL po vytvoření testovacího
pravidla. Řádek ` 10 permit ip any any` v nativní konfiguraci potvrdilo
cílené měření (soukromý záznam měření).

`iol-xe-switch-ntp-refused.txt` je řádek CLI `% Invalid address entered` ze
skutečného odmítnutí `ntp server 0.0.0.0` v 06:47:06 UTC. Zachycen na
transportu při veřejném `admin_apply`, po ověření zápisu prvního kroku.
Živý doklad (private measurement record, not published)
