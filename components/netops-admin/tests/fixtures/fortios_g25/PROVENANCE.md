# FG-13 – FortiGate-60F, FortiOS 7.6.8 build3744

Zachyceno 2026-11-20 na labovém FG-60F přes připnuté SSH s účtem `netops-test-ro`. Dvě TCP spojení z VM201 mířila na stejný cíl a lišila se zdrojovým portem. Diagnostické výpisy obsahují jen cílený testovací tok nebo prázdný výsledek.

- `00-status.txt` obsahuje čtyři vybrané řádky z `get system status`.
- `filter-initial.txt`, `filter-active.txt` a `filter-empty.txt` pocházejí z `diagnose sys session filter` před nastavením, s testovacím tokem a po volbě nepoužitého zdrojového portu.
- `session-active.txt` a `session-empty.txt` pocházejí z `diagnose sys session list`. `expectation-empty.txt` pochází z `diagnose sys session list expectation`.
- `checksum.txt` pochází z `diagnose sys ha checksum show`.

Anonymizace proběhla skriptem `components/netops-helper/tests/support/anonymize_fixture.py --name FortiGate-60F --check`. Model v řádku Version zůstal zachován a hostname je anonymizovaný. Falešný transport uplatňuje volby nad zachyceným výchozím filtrem. Zobrazení `vd: 0` a masky stavu tvoří odvozený výstup z měření.
