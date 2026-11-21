# Původ fixtur G63 (IOS-M027 členství EtherChannel/LACP, IOS 15.2)

- Zdroj: živé CLI měření v GNS3 labu netops-d-lab, úkol netops-20261119-569, 2026-11-19 05:30–06:10 UTC,
  uzel d-iosvl2 (DNAT 2252), Cisco IOSvL2 15.2(20200924:215240) (switch), testovací porty GigabitEthernet1/1 a
  1/2 (předem nastavené `switchport mode access`), port-channel 41/42/43. Surové transkripty:
  `task-evidence/g63/cap/`, `task-evidence/g63/raw/` (s1–s4 průzkum), rozdělení `task-evidence/g63/tools/split.py`.
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15), `ro-` = kontrolní účet `netops-ro` (privilege 1).
  `config__` = interaktivní řádek konfiguračního režimu s ozvěnou a následným promptem (formát fixtur G81).
- Anonymizace: `task-evidence/g63/tools/anon.sh` (nástroj `components/netops-helper/tests/support/anonymize_fixture.py`
  na PC-Radek; mapa se skutečnými hodnotami zůstává jen tam). Hashe hesel byly před tím nahrazeny `<REDIGOVANO>`
  (jediné hlášené residuum anonymizéru, `credential:username-secret`, je tento už redigovaný zástupce).
- Odvozený krok: `admin-show-tcp-brief.txt` – anonymizér nemapuje tvar `adresa.port`; adresy ručně nahrazeny mapovanou
  adresou správy 203.0.113.52 (Vlan99) a klientem 203.0.113.66, šířky sloupců zachovány. `help__channel-group-41-mode.txt`
  je zkrácen na odpověď nápovědy (bez následující vyzvy „Incomplete command“).
- Odvozený krok: v `admin-show-lldp-neighbors.txt` anonymizér prodloužil zkrácená Device ID, která IOS řeže na 20 znaků a tiskne
  bez mezery před sloupcem Local Intf (`host04.d-lab.invali…`); sloupec Local Intf byl vrácen na pozici z hlavičky
  (obsah beze změny; stejně jako u fixtur G62).
- Neodvozeno z odhadu syntaxe: všechny odpovědi jsou skutečné; stav `member41-passive`, `two-members`, `et02-member`
  jsou konfigurace po skutečných řádcích `channel-group 41 mode passive`, připojení Gi1/2 a odchodu Gi1/1.

## Úkol netops-20261121-749 (veřejná brána zdroje 1.0.12)

- Jméno labové domény (`ip domain-name`, `ip ssh rsa keypair-name host08.…`, Device ID `host01.…` v CDP a LLDP)
  nahrazeno `d-lab.invalid` jako u ostatních řádků; v LLDP zůstal sloupec Local Intf na pozici z hlavičky
  (`host01.d-lab.invalid` má 20 znaků jako `host04.d-lab.invalid`).
