# G136 r3 · fixtury kandidáta Junosu

Oba výstupy byly zachyceny na d-vjunos (vJunos-switch, ex9214, Junos 26.2R1.7) přes SSH na `gns3-server:2256` s ověřeným host klíčem. Záznam `task-evidence/g136/r2/r3-fixture-live.jsonl` zachycuje příkazy v konfigurační relaci s dočasným popisem na volném portu `ge-0/0/4`. Po `rollback 0` byl kandidát prázdný a hash aktivní konfigurace se shodoval s výchozím hashem.

- `compare_candidate_description_admin.out` je tělo odpovědi na `show | compare | no-more`. Obsahuje hlavičku a tři řádky označené `+`, stejně jako živý scénář r2 v `task-evidence/g136/r2/live.jsonl`.
- `config_display_set_quoted_description_admin.out` je tělo odpovědi na `show interfaces ge-0/0/4 | display set | no-more`. V testu kompatibility je z tohoto řádku odvozena varianta pro `ge-0/0/0`. Test ji vloží do zachyceného `display set` před první příkaz daného rozhraní.
