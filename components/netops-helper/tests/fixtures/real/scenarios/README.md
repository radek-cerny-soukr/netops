# Jednotný vstup živých záchytů

Každý `*.json` je jeden scénář `netops-replay/1`; `test_capture_replay.py` přehraje všechny soubory. Starší záchyty a replay testy zůstávají zachovány. `ceos-ospf.json` přebírá existující anonymizovaný živý záchyt; očekávání jsou ruční přepis CLI řádků.

Privátní vstupní manifest má stejnou strukturu jako ukázka, ale místo `stdout` obsahuje `file` s cestou k surovému výstupu relativní k manifestu. Povinná metadata: `scenario`, `expected_source` (jak byly hodnoty ověřeny nezávisle), pro každý záchyt `platform`, `firmware`, `query`, `table`, `command`, `rc`, `expected`. Očekávání musí obsahovat `status`, `record_count`, `unparsed_count`, `records`; pro každý řádek alespoň rozhodující hodnoty. Pořadí řádků je významné. Očekávání zadejte podle CLI/REST nebo ručního čtení, nikdy výstupem testovaného parseru. Nulový počet a prázdný seznam jsou výslovné očekávání, nikoli implicitní úspěch.

Import celého scénáře jedním příkazem (cesty upravte podle privátního pracovního adresáře):

```sh
python3 -B components/netops-helper/tests/support/add_capture.py \
  private-capture/manifest.json \
  components/netops-helper/tests/fixtures/real/scenarios/novy-scenar.json \
  --name site-switch --serial site-serial --ssid site-ssid --user site-user
```

Importer používá existující `Anonymizer`, nejprve načte všechny výstupy do jedné mapy a potom konzistentně anonymizuje výstupy i ručně zadaná očekávání a metadata. Nevolá parser ani nevyrábí očekávání. Neukládá mapu ani vstupní cesty a odmítá přepsat existující soubor. Před importem odstraňte přihlašovací údaje ze soukromého vstupu; detekce běžných credential řádků je pouze pojistka. Před commitem zkontrolujte celý výsledný diff a doplňte `--name/--serial/--ssid/--user` pro neoznačené identifikátory. Hodnoty `--name/--serial/--ssid/--user` mohou zůstat v historii shellu; používejte prostředí bez ukládání historie nebo historii bezpečně spravujte. Surové výstupy a mapa nepatří do repozitáře.

Ověření v engine testovacím obrazu: `python -B -m pytest -q tests/test_capture_replay.py` z `components/netops-helper`. Zachovává se skutečné `rc` i příkaz; `tables.parse` tím ověří také klasifikaci chybového výstupu.
