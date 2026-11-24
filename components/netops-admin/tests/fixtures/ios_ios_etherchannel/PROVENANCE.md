# Původ fixtur ios etherchannel (IOS-M027 členství EtherChannel/LACP, IOS 15.2)

- Zdroj: živé CLI měření v GNS3 labu netops-emulated environment, verification, 2026-11-19 05:30–06:10 UTC,
  uzel Cisco IOSvL2 15.2, Cisco IOSvL2 15.2(20200924:215240) (switch), testovací porty GigabitEthernet1/1 a
  1/2 (předem nastavené `switchport mode access`), port-channel 41/42/43. Surové transkripty
  (včetně průzkumu s1–s4 a rozdělení) jsou v soukromém záznamu měření.
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15), `ro-` = kontrolní účet `netops-ro` (privilege 1).
  `config__` = interaktivní řádek konfiguračního režimu s ozvěnou a následným promptem (formát fixtur xe etherchannel).
- Výstupy anonymizoval `components/netops-helper/tests/support/anonymize_fixture.py`. Mapa se skutečnými hodnotami zůstává soukromá. Hashe hesel byly před tím nahrazeny `<REDIGOVANO>`
  (jediné hlášené residuum anonymizéru, `credential:username-secret`, je tento už redigovaný zástupce).
- Odvozený krok: `admin-show-tcp-brief.txt` – anonymizér nemapuje tvar `adresa.port`; adresy ručně nahrazeny mapovanou
  adresou správy 203.0.113.52 (Vlan99) a klientem 203.0.113.66, šířky sloupců zachovány. `help__channel-group-41-mode.txt`
  je zkrácen na odpověď nápovědy (bez následující vyzvy „Incomplete command“).
- Odvozený krok: v `admin-show-lldp-neighbors.txt` anonymizér prodloužil zkrácená Device ID, která IOS řeže na 20 znaků a tiskne
  bez mezery před sloupcem Local Intf (`host04.node1.invali…`); sloupec Local Intf byl vrácen na pozici z hlavičky
  (obsah beze změny; stejně jako u fixtur ios static routing).
- Neodvozeno z odhadu syntaxe: všechny odpovědi jsou skutečné; stav `member41-passive`, `two-members`, `et02-member`
  jsou konfigurace po skutečných řádcích `channel-group 41 mode passive`, připojení Gi1/2 a odchodu Gi1/1.

## verification (veřejná brána zdroje 1.0.12)

- Jméno labové domény (`ip domain-name`, `ip ssh rsa keypair-name host08.…`, Device ID `host01.…` v CDP a LLDP)
  nahrazeno `node1.invalid` jako u ostatních řádků; v LLDP zůstal sloupec Local Intf na pozici z hlavičky
  (`host01.node1.invalid` má 20 znaků jako `host04.node1.invalid`).
