# G147 · d-vjunos

Zachyceno 2026-11-20 pomocí účtu `netops-ro` na vJunos-switch (ex9214, Junos 26.2R1.7). Výstupy prošly `components/netops-helper/tests/support/anonymize_fixture.py --check`.

| Soubor | Příkaz |
| --- | --- |
| `port-terse.txt` | `show interfaces ge-0/0/4 terse \| no-more` |
| `vlans.txt` | `show vlans \| no-more` |
| `irb-absent.json` | `show interfaces irb.3923 terse \| display json \| no-more` |

Fake transport přebírá kostru konfigurace, interaktivní odpovědi commitu a tvary platného IRB i z měření v `junos_26_2R1_7/` a `junos_g139/`. Test mění pole stavů, která by ovlivnily přijímané příkazy. U negativních případů zkracuje naměřený řádek portu nebo používá zachycenou chybu syntaxe.
