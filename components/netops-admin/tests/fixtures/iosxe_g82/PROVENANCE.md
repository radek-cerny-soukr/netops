# Původ fixtur G82 (XE-M029 pravidla IPv4/IPv6 ACL, XE-M030 přiřazení ACL na rozhraní, IOS XE 17.18.2)

- Zdroj: živé CLI měření v GNS3 labu netops-d-lab, úkol netops-20261119-639, 2026-11-19 20:00–21:20 UTC, uzel d-iolxe
  (DNAT 2257), Cisco IOL XE 17.18.2 (router), testovací ACL `NETOPS-G82-*` a rozhraní Ethernet0/2 (spoj VRF blue k d-iosv).
  Měřicí skripty a surové transkripty konfiguračního režimu: `task-evidence/g82/` (`tools/`, `raw/`).
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15, SSH exec bez PTY), `ro-` = kontrolní účet `netops-ro`
  (privilege 1), `config__` = interaktivní řádek konfiguračního režimu s ozvěnou, odpovědí a následným promptem
  (formát fixtur G81). Přípona `__<stav>`: `baseline` (bez testovacích ACL), `acls` (ACL `NETOPS-G82-V4` 19 pravidel,
  `-V4B` 5 pravidel, `-V4C` bez pravidel, `ipv6 -V6` 10 pravidel, nepřipojené), `bound` (`NETOPS-G82-V4` in, `-V4B` out,
  `-V6` in a out na Ethernet0/2).
- Anonymizace: `components/netops-helper/tests/support/anonymize_fixture.py` na PC-Radek (hostname, uživatelé, popis
  portu, adresy správy a sousedů; mapa se skutečnými hodnotami zůstala jen tam). Hashe hesel a tělo self-signed certifikátu
  byly před tím nahrazeny `<REDIGOVANO>` (jediné hlášené residuum anonymizéru, `credential:username-secret`, je tento už
  redigovaný zástupce).
- Anonymizérem záměrně nezpracováno: těla pravidel testovacích ACL (2001:DB8:69::/64, …). Jsou to hodnoty, které jsem
  pro test vymyslel, ne data lokality; anonymizér by z nich udělal jiné adresy a rozbil masky (`0.0.0.254` → adresa)
  a tvar IPv6. Bloky ACL v `admin-show-running-config__*` a výstupy `ro-show-*access*` byly proto při prvním sběru
  ponechány v naměřené podobě (jen bez hashů hesel, ty v nich nejsou). Úkol 749 v nich později přemapoval vybrané
  IPv4 hodnoty do 203.0.113.0/24 se zachováním syntaxe a tvaru wildcard masek (viz poslední oddíl).
- Odvozený krok: `admin-show-tcp-brief.txt` – anonymizér nemapuje tvar `adresa.port`; adresy ručně nahrazeny
  anonymizovanými adresami správy (192.0.2.57 = Ethernet0/0) a sousedů, šířky sloupců zachovány. V `admin-show-version.txt`
  je cesta obrazu nahrazena obecnou cestou.
- `ports-measured.json`: pojmenované porty, které zařízení tiskne místo čísla (měřeno přehledem portů 0..1023 a
  obvyklých vyšších pro tcp/udp v IPv4 i IPv6 ACL; surové: `task-evidence/g82/raw/sweep-*`; `onep-plain`, `onep-tls` a
  `non500-isakmp` z řádku s vyššími porty IPv4 přehledu).
- Odvozené (označené v testech): stav „rozhraní bez přiřazení v jednom směru“ ve výstupech `show ip/ipv6 interface`
  (odvozeno z naměřeného stavu `acls`/`bound` vložením/odebráním naměřených řádků `Inbound/Outgoing access list`),
  přejmenování rozhraní v těchto výstupech, a úprava jednoho řádku ACL (odstranění pravidla mimo profil) při pozitivních
  scénářích IPv6/V4B, protože naměřené `-V6` obsahuje pravidlo `icmp … echo-reply` a `-V4B` nesouvislou masku (obě mimo
  profil, a proto slouží jako negativní scénáře v původním tvaru).
- Neodvozeno z odhadu syntaxe: příkazy, odpovědi na duplicitní číslo/tělo, nesprávný název při odebrání vazby a tvar
  řádků ACL v running-config a `show` jsou skutečné.
- Změřeno pro fake zařízení (`fake_iosxe_acl.py`): bloky `ip access-list extended` a `ipv6 access-list` stojí v running-config
  v pořadí názvů (ASCII; měřeno s `NETOPS-G82-A`, `ZZ-NETOPS-G82-Z`, `AAA-NETOPS-G82` – raw `task-evidence/g82/raw/probes/b10.txt`);
  IPv6 ACL zmizí z konfigurace odebráním posledního pravidla (`raw/probes/b9.txt`); IPv4 ACL zůstane jako prázdná hlavička.

For review 675, `admin-show-ip-cef-default-detail.txt` is the d-iolxe 17.18.2 response to
`show ip cef <destination> detail`, with the gateway mapped to a documentation address.
The fake SSH test adapts the egress interface and local SSH endpoint to model loopback management.

## Úkol netops-20261121-749 (veřejná brána zdroje 1.0.12)

- Vymyšlené IPv4 hodnoty testovacích ACL (soukromé rozsahy) převedeny do 203.0.113.0/24. Souvislé prefixy a hosty
  jsme přemapovali mimo adresy rozhraní fixtury v 203.0.113.0/24 (.7, .252, .253, .254); výjimkou je nesouvislá wildcard níže: síť pravidla SSH → 203.0.113.32/27 (hosty .33, .39, .41), síť PBR ACL →
  203.0.113.96/27 (wildcard 0.0.0.31), pravidla -V4B → 203.0.113.128/26, .128/27, host .129, .160/28 a nesouvislá
  wildcard `203.0.113.176 0.0.0.254` (ta zůstává: měřený tvar nesouvislé masky; pokrývá všechny sudé adresy
  203.0.113.0/24, tedy i adresy rozhraní .252 a .254). Stejná mapa v `admin-show-running-config__*`,
  `ro-show-ip-access-lists-*` i `test_ios_g82.py`.
- Skupina solicited-node s dolními 24 bity skutečné link-local adresy nahrazena `FF02::1:FF00:11` podle
  anonymizované `fe80::11`; cesta k obrazu v `admin-show-version.txt` zapsána jako `/home/<user>/` (jako fixtury C45).
