# FortiGate-60F, FortiOS 7.6.8 build3744

Čteno 2026-11-20 na labovém FG-60F účtem `fixture-operator` v jedné relaci SSH s připnutým host key. IP adresy v cílených výstupech nahradil `components/netops-helper/tests/support/anonymize_fixture.py --check`.

- `phase2-source.txt` je cílený oddíl ipsec status z `show vpn ipsec phase2-interface`.
- `phase2-absent.txt` je odpověď na `show vpn ipsec phase2-interface "netops-firewall-cleanup-missing"`.
- `summary-up.txt` je řádek ipsec status z `get vpn ipsec tunnel summary`.
- `selectors-up.txt` jsou dva stavové řádky z `diagnose vpn tunnel list name netops-ipsec status | grep proxyid`.
- `phase2-direct.txt` a `phase2-created.txt` jsou nezávislé výstupy kontrolního účtu `fixture-reader` z `show vpn ipsec phase2-interface "<selektor>"` po potvrzeném apply. Anonymizace všech souvisejících výstupů proběhla v jedné dávce. Stejný cílový subnet zdroje a kopie tak zůstal shodný.
- `execute-refused.txt` je odpověď labového zapisovacího účtu na dokumentovanou variantu `execute vpn ipsec tunnel down "netops-ipsec status" "netops-ipsec status" 1`.
- `selectors-expiry-before.txt` a `selectors-expiry-after.txt` pocházejí z FG-60F při ověření 07:57 UTC. Příkaz `diag vpn tunnel list name netops-ipsec status | grep '^proxyid\|^ *SA:'` ukázal shodný počet a zbylou platnost 42493/42498 s před down, 42930/42930 s po down.
- `selectors-down.txt` je odvozený výstup z měření `08-tunnel-list-down.out` skupiny ipsec status na stejném FortiOS. Obsahuje dvě vyfiltrované stavové řádky a jméno testovaného selektoru místo jména sousedního neaktivního selektoru.
- Jednotková varianta s echo odvozuje mezeru a backspace z terminálového záznamu FG-60F.
