# Původ fixtur G62 (IOS-M025 statické routy, IOS-M026 L3 rozhraní)

- Zdroj: živé CLI měření v GNS3 labu netops-d-lab, úkol netops-20261118-517, 2026-11-18 14:00–14:06 UTC,
  skript `task-evidence/g62/measure.py`, log `task-evidence/g62/measure-iosv.jsonl` a `measure-iosvl2.jsonl`.
  - `iosv/`: d-iosv (DNAT 2251), Cisco IOSv 15.9(3)M12 (router, VRF `blue`).
  - `iosvl2/`: d-iosvl2 (DNAT 2252), Cisco IOSvL2 15.2(20200924:215240) (switch, SVI).
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15), `ro-` = kontrolní účet `netops-ro` (privilege 1).
  Přípona `__<stav>` = stav labu při záchytu (baseline, routes, distance, two-hops, empty, objects, overlap,
  same-vid, vrf-moved, vrf-back, two-addresses, updated, lo-shutdown, no-ip, sub-shutdown, deleted, recreated,
  svi-bare, svi-shutdown, no-shutdown, final).
- Anonymizace: `task-evidence/g62/anon.sh` (předtím redakce `secret|password N <hash>` → `<REDIGOVANO>`), nástroj
  `components/netops-helper/tests/support/anonymize_fixture.py` s jednou mapou pro oba uzly (mapa s reálnými hodnotami
  zůstává jen na PC-Radek). Mapa byla předem nasazena tak, že testovací objekty v 198.51.100.0/24 si nechávají adresy
  a vztahy podsítí; síť správy → 192.0.2.0/24, síť VLAN 10 → 203.0.113.0/24, ostatní
  adresy dostaly samostatné dokumentační adresy; IPv6 → 2001:db8:<n>::/64 (testovací 2001:db8:62:900::/64 je
  2001:db8:2::/64 atd.). Jména uzlů → hostNN, MAC → 00:00:5e:00:53:NN.
- Odvozený krok: `show tcp brief` píše `adresa.port`, které anonymizér nemapuje; `anon.sh` je mapuje stejnou mapou
  (Anonymizer._ipv4/_ipv6) a zachová sloupce. V `admin-show-lldp-neighbors__baseline.txt` (oba uzly) anonymizér
  zkrátil Device ID uříznuté na 20 znaků, které IOS tiskne bez mezery před sloupcem Local Intf; sloupec Local Intf byl
  ručně vrácen na pozici z hlavičky (odvozeno, obsah beze změny). Testy navíc přesouvají adresy VLAN 20 (Gi0/1.20,
  Vlan20), které anonymizér umístil do /24 VLAN 10, do volné dokumentační podsítě (`VLAN20` v test_ios_g62.py). Jinak jsou odpovědi beze změny (zarovnání sloupců mohl anonymizér
  rozšířit mezerami).
- Celá running-config byla na konci měření shodná s výchozí (SHA-256 bez hlavičky d-iosv `5aee63bb…`,
  d-iosvl2 `c9a29fed…`) a bez rozdílu proti startup-config.
- Další odvozené úpravy: v `admin-show-lldp-neighbors__baseline.txt` (oba uzly) anonymizér zkrátil Device ID, které
  IOS uřízne na 20 znaků a tiskne bez mezery před sloupcem Local Intf; sloupec Local Intf byl vrácen na pozici
  z hlavičky (obsah beze změny). Testy (`VLAN20` v `test_ios_g62.py`) přesouvají adresy VLAN 20 (Gi0/1.20, Vlan20),
  které anonymizér umístil do /24 VLAN 10, do volné dokumentační podsítě; fake zařízení píše IPv6 velkými písmeny
  a s jednou mezerou jako IOS.

## Odvozené případy revize 517-r2

- Autentizační příkazy se syntetickými hodnotami a `native` jsou doplněné do měřeného bloku `GigabitEthernet0/3.900`. Stav překryvu přebírá přímo měřený blok `admin-show-running-config-interface-Vlan901__overlap.txt`. Anonymizovaná adresa klienta SSH je v této variantě přesunutá mimo testovaný překryv.
- Stav rodiče `up/up` pochází z měřené tabulky IOSv. Vypnuté CDP/LLDP a odmítnutí autorizace jsou odvozené odpovědi. Ostatní odmítnutí přebírají měřené CLI odpovědi IOS C45 se změněným dotazem.
- Varianta Catalyst C3560 nahrazuje identifikátor image ve změřeném `show version` a ponechává verzi a měřený SVI snapshot shodné. Podporu SVI a příkazů VLAN na Catalyst 3560 popisuje [Cisco Catalyst 3560 Switch Command Reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3560/software/release/12-2_50_se/command/reference/cr/cli1.pdf).

## Odvozené případy revize 517-r3

- Smazání používá měřený `Vlan900` se změněným popisem `Hoste, budova A` v konfiguraci i ve výstupu simulovaného zařízení.
- První SVI používá baseline IOSvL2 bez bloků `interface Vlan*`. Managementová adresa z `Vlan99` je přesunuta na routovaný `Gi1/3` v running-config i v `show ip interface brief`. Měřený `show vlan brief` zůstává beze změny. Odpověď `Line has invalid autocommand` je odvozena z měřeného odmítnutí IOS C45 se změněným dotazem.

## Úkol netops-20261121-749 (veřejná brána zdroje 1.0.12)

- Skupiny solicited-node ve výstupech `show ipv6 interface` d-iosv nesly dolních 24 bitů
  skutečné link-local adresy (anonymizér multicast ponechává); nahrazeny skupinou `FF02::1:FF00:12` odvozenou z
  anonymizované link-local `fe80::12` téhož výstupu.
- Jméno labové domény ve sloupci Device ID LLDP (`host04`) nahrazeno `d-lab.invalid` stejně jako u ostatních řádků;
  sloupec Local Intf zůstal na pozici z hlavičky (20 znaků, jako `host06.d-lab.invali`).
