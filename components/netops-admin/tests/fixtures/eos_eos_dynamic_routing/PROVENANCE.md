# eos dynamic routing — cEOS 4.36.1F

Výstupy z 2026-11-19, anonymizované přes `components/netops-helper/tests/support/anonymize_fixture.py --check`. Časované konfigurační relace vrátily výchozí stav. Kontrolní součty (private measurement record, not published)

- `d-config.txt` — cílené sekce `show running-config` na Arista cEOS 4.36.1F účtem netops-admin pro Loopback126, OSPF 126, prefix-list a route-map. EOS vrátil tutéž route-map dvakrát, protože příkaz pro sekci prefix-listu vypsal také blok s odkazem.
- `d-ospf-interface*.json`, `d-ospf-process.json`, `d-ospfv3-interface-absent.json` — provozní `show ip ospf interface Loopback126 | json`, `show ip ospf | json` a `show ipv6 ospf interface | json` na Arista cEOS 4.36.1F účtem netops-ro. Soubor s příponou `-absent` zachycuje stav po návratu.
- `d-prefix*.json`, `d-map*.json` — `show ip prefix-list NETOPS-EOS-DYNAMIC-ROUTING-P | json` a `show route-map NETOPS-EOS-DYNAMIC-ROUTING-M | json` na Arista cEOS 4.36.1F účtem netops-ro před návratem a po návratu.
- `a-bgp-config.txt`, `a-bgp-neighbor.json`, `a-svi.json` — `show running-config section router bgp` účtem netops-admin, `show ip bgp neighbors <peer> | json` a `show interfaces Vlan3930 | json` účtem netops-ro na ceos-peer-a. Testovací SVI byla nahoře, ale BGP nebylo operativní kvůli `no ip routing`.

- `d-management-route.json` — `show ip route vrf default <adresa> | json` na Arista cEOS 4.36.1F, připojená cesta přes Management0. Fake transport při porovnání s jinou anonymizovanou fixturou volí jiný dokumentační rozsah pro SSH zdroj, aby se nepřekrýval s testovanou OSPF sítí.

- `d-ospf-explicit-active.txt` — cílený výstup `show running-config section router ospf 126` na Arista cEOS 4.36.1F během prvního undo. EOS uložil `no passive-interface Loopback126` jako výslovné nastavení. Identifikátory zpracoval stejný anonymizátor. Běh (private measurement record, not published)

- `duo-bgp-neighbor.json`: selected eBGP identity and route-map fields from the
  `netops-ro` command `show ip bgp neighbors 198.51.100.6 | json` on ceos-peer-a,
  cEOS 4.36.1F, 2026-11-19 14:21 UTC. VLAN 3930, AS 65126/65127 and IPv4
  routing were staged temporarily. Both devices were restored to their initial
  running-config digests and had zero configuration sessions afterward.

## verification (veřejná brána zdroje 1.0.12)

- Testovací BGP /30 (VLAN 3930) a druhá testovací síť ležely mimo dokumentační rozsahy; nyní 198.51.100.4/30
  (lokální.5, peer.6) a 198.51.100.128/25. Pozdější BGP výpis `duo-bgp-neighbor.json` obsahuje anonymizovaného
  souseda 198.51.100.6 a test k němu modeluje lokální 198.51.100.5/30 (`MeasuredBgpEos` v `test_eos_eos_dynamic_routing.py`).
  Prefix 198.51.100.128/25 používají testy prefix-listu a OSPF. Obě sítě se nepřekrývají
  s rozhraními fake zařízení (správa 203.0.113.0/24, Loopback126 192.0.2.0/24, Loopback 198.51.100.3/32); cesta
  k SSH zdroji ve fake odpovědi je proto zúžena na 198.51.100.32/27 (obsahuje zdroj.36).

## BGP readback without route maps and without a BGP process (2026-11-22)

- `bgp-neighbor-without-route-maps.json`: selected fields of `show ip bgp neighbors <peer> | json` read by `netops-ro`
  on the single cEOS 4.36.1F after `router bgp` with one neighbor that has only `remote-as` (no route maps, state
  Active). EOS omits `routeMapInbound`, `routeMapOutbound` and both `...Defined` keys in this case (none of the
  108 keys of the measured row starts with `routeMap`). Peer address and AS numbers are replaced by the values of
  `MeasuredBgpEos` (198.51.100.6, AS 65126/65127). The temporary BGP process was removed afterwards and the
  running = startup configuration digest equalled the one before.
- `bgp-router-without-neighbors.json`: the same command with the empty `router bgp` process.
- `bgp-without-router.json`: the same command without any `router bgp` (also on both switches of the cEOS pair).
- `bgp-inactive.json`: answer `{"errors": ["BGP inactive"]}` recorded by the earlier live measurement of the BGP
  profile on the same cEOS 4.36.1F without a BGP process (the measurement evidence quotes the answer; it was not
  reproduced on 2026-11-22, when the switch answered `bgp-without-router.json`).
