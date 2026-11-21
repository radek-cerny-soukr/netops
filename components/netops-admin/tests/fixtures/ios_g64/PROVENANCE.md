# Původ fixtur G64 (IOS-M028 pravidla ACL, IOS-M029 přiřazení ACL na rozhraní)

- Zdroj: živé CLI měření v GNS3 labu netops-d-lab, úkol netops-20261119-590, 2026-11-19 13:00–13:10 UTC, uzly
  `iosv` = d-iosv (Cisco IOSv 15.9(3)M12, router, DNAT 2251) a `iolxe` = d-iolxe (IOL XE 17.18.2, router, DNAT 2257);
  testovací spoj VRF blue d-iolxe Eth0/2 ↔ d-iosv Gi0/2. Surové transkripty: `task-evidence/g64/raw/{iosv,iolxe}-states/`
  (skript `task-evidence/g64/tools/capture_states.py`), průzkum syntaxe `raw/*-probe*/`, rollback `raw/*-rollback/`.
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15), `ro-` = kontrolní účet `netops-ro` (privilege 1).
  `config__*` = interaktivní řádky konfiguračního režimu s ozvěnou a promptem. Přípona `__<stav>`: `baseline` (výchozí stav
  labu), `acls` (testovací ACL `NETOPS-G64-V4/EMPTY4/REMARK/OPTS`, `NETOPS-G64-V6`, prázdná `EMPTY6`), `bound` (V4 in+out
  a V6 in na rozhraní spoje), `half-bound` (jen V4 in).
- Anonymizace: `task-evidence/g64/tools/anon.sh` (nástroj `components/netops-helper/tests/support/anonymize_fixture.py` na
  PC-Radek; mapa se skutečnými hodnotami zůstává jen tam). Hashe hesel byly před tím nahrazeny `<REDIGOVANO>` (jediné hlášené
  residuum anonymizéru, `credential:username-secret`, je tento už redigovaný zástupce).
- Odvozené kroky (anonymizér je nezná): `admin-show-tcp-brief.txt` – adresy ve tvaru `adresa.port` ručně nahrazeny
  mapovanými adresami správy (203.0.113.51 / .57) a klientem 192.0.2.66, šířky sloupců zachovány; soubory
  `admin-show-lldp/cdp-neighbors.txt` se do fixtur nedostaly (obsahovaly názvy jiných labových uzlů a sériové číslo);
  jméno labové domény v `ip domain name` nahrazeno `host11` v konfiguracích IOSv.
- Artefakty anonymizéru, ne zařízení: IPv6 síť se tiskne `2001:db8:1::0/64` (zařízení tiskne jak bylo zadáno), a za IPv6
  adresu hosta je v ACL někdy dvojitá mezera (zachování sloupců); Admin obě normalizuje.
- Měřeno a testy z toho vychází: IOS 15.9 netiskne čísla sekvence pravidel IPv4 ACL a u IPv6 jen čísla, která se liší od
  automatické číselné řady (`sequence 25 …`), IOS XE tiskne všechna; oba je vypisují `show ip access-lists` /
  `show ipv6 access-list` (u XE i u 15.9 s čítačem `(N matches)`/`(1 match)`). Prázdná IPv4 ACL zůstává v konfiguraci
  (výpis jen hlavička), prázdná IPv6 ACL v konfiguraci vůbec není. Poznámka (`remark`), `log` a `range` jsou mimo profil.
  `show interfaces <port> switchport` na routeru odpovídá `Line has invalid autocommand`.
- Co není z měření: soubor `task-evidence/g64/raw/*-rollback` (návrat časovače přečísluje IPv4 pravidla IOS 15.9 na 10, 20,
  30, …; IPv6 a XE čísla drží) je zdrojem pro test `test_the_return_of_a_timer_renumbers_...`; řádek `access-class` na VTY
  je v testech označen jako ODVOZENÝ (VTY linky labu se nemění).

## Úkol netops-20261121-749 (veřejná brána zdroje 1.0.12)

- Skupiny solicited-node ve výstupech `show ipv6 interface` nesly dolních 24 bitů skutečných link-local adres;
  nahrazeny skupinami odvozenými z anonymizovaných link-local adres téhož výstupu: IOSv `FF02::1:FF00:13`
  (`fe80::13`), IOL-XE `FF02::1:FF00:11` (`fe80::11`).
