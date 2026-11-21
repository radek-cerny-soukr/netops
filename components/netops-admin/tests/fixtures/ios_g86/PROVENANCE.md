# G86 · IOS XE 17.18.2

Cílené SSH exec výpisy z GNS3 d-iolxe (2257) a d-iolxe-l2 (2258), úkol 713.
Pořídil je `task-evidence/g86/cli_capture.py`. Anonymizace použila
`components/netops-helper/tests/support/anonymize_fixture.py --check`.
Příkazy a role účtů odpovídají položkám v ovladači. Výchozí celé snapshoty a
odpovědi pojistky v simulátorech pocházejí z `ios_c45`, `iosxe_g82` a `ios_g84`.
Simulace mění řádek popisu ve změřené provozní tabulce podle aktuálního stavu
a odvozený případ neúplného výstupu vynechává řádek cílového portu.

Regrese inventářové ochrany VLAN 20 používá skutečné výpisy `show tcp brief` a
`show ip interface brief` z `ios_c45/iolxe-l2`, kde SSH končí na Vlan99.
Stav zapojeného access portu ve VLAN 20 je odvozený z konfigurace `ios_c45`
a výpisů `description` a `switchport` v této sadě. Simulace odebere `shutdown`,
přidá `switchport access vlan 20` a upraví odpovídající provozní řádky portu.

Regrese vyjednaného trunku odvozuje varianty ze stejného změřeného výpisu
`d-iolxe-l2-switchport.txt` a naměřené tabulky `description`. Mění stav linky,
administrativní a provozní mód, DTP a povolené VLANy. SSH stále končí na
změřené Vlan99. Další varianty pokrývají inventářovou VLAN 20, nakonfigurovaný
trunk a chybějící, prázdný, neznámý nebo zdvojený provozní mód.

`d-iolxe-l2-ipv4-listing.txt` a `d-iolxe-l2-ipv6-listing.txt` jsou provozní
výpisy z 06:37 UTC před konfigurací první ACL. `d-iolxe-l2-acl-created.txt`
zachytil účet `netops-ro` v 06:45:50 UTC příkazem `show ip access-lists NETOPS-G86-713`.
Simulátor přidá tento změřený výpis k provozním ACL po vytvoření testovacího
pravidla. Řádek ` 10 permit ip any any` v nativní konfiguraci potvrdilo
cílené měření v `task-evidence/g86/live-diagnose.log`.

`d-iolxe-l2-ntp-refused.txt` je řádek CLI `% Invalid address entered` ze
skutečného odmítnutí `ntp server 0.0.0.0` v 06:47:06 UTC. Zachycen na
transportu při veřejném `admin_apply`, po ověření zápisu prvního kroku.
[Živý doklad](../../../../../task-evidence/g86/live-r3.log)
