# G95 Cisco Nexus 9300v NX-OS 9.3(12)

- `configuration-session-one.out` pochází ze stávajícího výstupu Adminu ve stejném repozitáři, `components/netops-admin/tests/fixtures/nxos_9_3_12/show-configuration-session-summary__one.txt`. Jméno sezení a vlastník prošli `tests/support/anonymize_fixture.py --name … --user … --check`.
- Testy v `test_cisco_management_real.py` používají také dřívější živé odpovědi NX-OS v `fixtures/real/management/nxos.json` a jejich odvozeniny. Změněný souhrnný počet, uměle prodloužený výstup a zkušební hodnoty pro redakci jsou derivace, nikoli nové odpovědi z labu.
- `users-d-nxos.out` je čtecí odpověď z d-nxos z 2026-11-20 při otevřené interaktivní SSH relaci účtu s rolí read-only. Zachycená přes NetOps a porovnaná se současným samostatným `show users`. `Anonymizer.text` z `tests/support/anonymize_fixture.py` anonymizoval uživatele a zdrojovou IP. Zařízení opakuje hlavičku i řádek.
- `users-b04-nx-a.out` a `users-b04-nx-b.out` pocházejí ze stejného čtecího běhu na uzlech B04, se stejnou anonymizací.
- `dns-default-vrf.out` a `dns-management-vrf.out` pocházejí ze starších živých výstupů Adminu v `components/netops-admin/tests/fixtures/nxos_g104/`. Uložené doménové jméno a IP prošly `anonymize_fixture.py --check`. Dokládají resolver ve výchozí VRF i směrování DNS přes management VRF.
