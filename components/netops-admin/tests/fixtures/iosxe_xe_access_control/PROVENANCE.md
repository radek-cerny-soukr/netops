# Původ fixtur xe access control (XE-M029 pravidla IPv4/IPv6 ACL, XE-M030 přiřazení ACL na rozhraní, IOS XE 17.18.2)

- Zdroj: živé CLI měření v GNS3 labu netops-emulated environment, verification, 2026-11-19 20:00–21:20 UTC, uzel Cisco IOL XE 17.18.2, Cisco IOL XE 17.18.2 (router), testovací ACL `NETOPS-XE-ACCESS-CONTROL-*` a rozhraní Ethernet0/2 (spoj VRF blue k Cisco IOSv 15.9(3)M12).
  Měřicí skripty a surové transkripty konfiguračního režimu jsou v soukromém záznamu měření.
- Prefix `admin-` = zápisový účet `netops-admin` (privilege 15, SSH exec bez PTY), `ro-` = kontrolní účet `netops-ro`
  (privilege 1), `config__` = interaktivní řádek konfiguračního režimu s ozvěnou, odpovědí a následným promptem
  (formát fixtur xe etherchannel). Přípona `__<stav>`: `baseline` (bez testovacích ACL), `acls` (ACL `NETOPS-XE-ACCESS-CONTROL-V4` 19 pravidel,
  `-V4B` 5 pravidel, `-V4C` bez pravidel, `ipv6 -V6` 10 pravidel, nepřipojené), `bound` (`NETOPS-XE-ACCESS-CONTROL-V4` in, `-V4B` out,
  `-V6` in a out na Ethernet0/2).
- Nástroj `components/netops-helper/tests/support/anonymize_fixture.py` anonymizoval názvy zařízení, uživatele, popisy portů a adresy správy a sousedů. Mapa se skutečnými hodnotami zůstává soukromá. Hashe hesel a tělo self-signed certifikátu
  byly před tím nahrazeny `<REDIGOVANO>` (jediné hlášené residuum anonymizéru, `credential:username-secret`, je tento už
  redigovaný zástupce).
- Anonymizérem záměrně nezpracováno: těla pravidel testovacích ACL (2001:DB8:69::/64, …). Jsou to hodnoty, které jsem
  pro test vymyslel, ne data lokality; anonymizér by z nich udělal jiné adresy a rozbil masky (`0.0.0.254` → adresa)
  a tvar IPv6. Bloky ACL v `admin-show-running-config__*` a výstupy `ro-show-*access*` byly proto při prvním sběru
  ponechány v naměřené podobě (jen bez hashů hesel, ty v nich nejsou). verification v nich později přemapoval vybrané
  IPv4 hodnoty do 203.0.113.0/24 se zachováním syntaxe a tvaru wildcard masek (viz poslední oddíl).
- Odvozený krok: `admin-show-tcp-brief.txt` – anonymizér nemapuje tvar `adresa.port`; adresy ručně nahrazeny
  anonymizovanými adresami správy (192.0.2.57 = Ethernet0/0) a sousedů, šířky sloupců zachovány. V `admin-show-version.txt`
  je cesta obrazu nahrazena obecnou cestou.
- `ports-measured.json`: pojmenované porty, které zařízení tiskne místo čísla (měřeno přehledem portů 0..1023 a
  obvyklých vyšších pro tcp/udp v IPv4 i IPv6 ACL; surové výstupy jsou v soukromém záznamu měření; `onep-plain`, `onep-tls` a
  `non500-isakmp` z řádku s vyššími porty IPv4 přehledu).
- Odvozené (označené v testech): stav „rozhraní bez přiřazení v jednom směru“ ve výstupech `show ip/ipv6 interface`
  (odvozeno z naměřeného stavu `acls`/`bound` vložením/odebráním naměřených řádků `Inbound/Outgoing access list`),
  přejmenování rozhraní v těchto výstupech, a úprava jednoho řádku ACL (odstranění pravidla mimo profil) při pozitivních
  scénářích IPv6/V4B, protože naměřené `-V6` obsahuje pravidlo `icmp … echo-reply` a `-V4B` nesouvislou masku (obě mimo
  profil, a proto slouží jako negativní scénáře v původním tvaru).
- Neodvozeno z odhadu syntaxe: příkazy, odpovědi na duplicitní číslo/tělo, nesprávný název při odebrání vazby a tvar
  řádků ACL v running-config a `show` jsou skutečné.
- Změřeno pro fake zařízení (`fake_iosxe_acl.py`): bloky `ip access-list extended` a `ipv6 access-list` stojí v running-config
  v pořadí názvů (ASCII; měřeno s `NETOPS-XE-ACCESS-CONTROL-A`, `ZZ-NETOPS-XE-ACCESS-CONTROL-Z` a `AAA-NETOPS-XE-ACCESS-CONTROL`; surový záznam měření je soukromý);
  IPv6 ACL zmizí z konfigurace odebráním posledního pravidla (`raw/probes/b9.txt`); IPv4 ACL zůstane jako prázdná hlavička.

For a review, `admin-show-ip-cef-default-detail.txt` is the Cisco IOL XE 17.18.2 17.18.2 response to
`show ip cef <destination> detail`, with the gateway mapped to a documentation address.
The fake SSH test adapts the egress interface and local SSH endpoint to model loopback management.

## verification (veřejná brána zdroje 1.0.12)

- Vymyšlené IPv4 hodnoty testovacích ACL (soukromé rozsahy) převedeny do 203.0.113.0/24. Souvislé prefixy a hosty
  jsme přemapovali mimo adresy rozhraní fixtury v 203.0.113.0/24 (.7,.252,.253,.254); výjimkou je nesouvislá wildcard níže: síť pravidla SSH → 203.0.113.32/27 (hosty.33,.39,.41), síť PBR ACL →
  203.0.113.96/27 (wildcard 0.0.0.31), pravidla -V4B → 203.0.113.128/26,.128/27, host.129,.160/28 a nesouvislá
  wildcard `203.0.113.176 0.0.0.254` (ta zůstává: měřený tvar nesouvislé masky; pokrývá všechny sudé adresy
  203.0.113.0/24, tedy i adresy rozhraní.252 a.254). Stejná mapa v `admin-show-running-config__*`,
  `ro-show-ip-access-lists-*` i `test_ios_xe_access_control.py`.
- Skupina solicited-node s dolními 24 bity skutečné link-local adresy nahrazena `FF02::1:FF00:11` podle
  anonymizované `fe80::11`; cesta k obrazu v `admin-show-version.txt` zapsána jako `/home/<user>/` (jako fixtury C45).
