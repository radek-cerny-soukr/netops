# ExtremeXOS X21

CLI a SFTP capture z 2026-11-19. `vm` je ExtremeXOS VM 33.6.1.14 33.6.1.14, `vm-b` ExtremeXOS VM peer 33.6.1.14 33.6.1.14 a `x440` labový X440-G2-12p 33.7.1.6. Příkazy běžely přes SSH a SFTP s připnutým klíčem a správcovským účtem. Zaznamenán je výhradně rozsah ACL workflow. Výstupy prošly `components/netops-helper/tests/support/anonymize_fixture.py --check` se zachováním dokumentační adresy 192.0.2.147.

- `absent-acl` a `bound-acl-all` jsou `show access-list`, `absent-policy` a `bound-policy` jsou `show policy`.
- `absent-file` a `checked-file` jsou záporný a úspěšný `check policy netops-switch-ospf-capture access-list`.
- `bound-counters` a `bound-detail` jsou `show access-list counter vlan netops-switch-ospf ingress` a `show access-list vlan netops-switch-ospf ingress detail`.
- `bound-config` je modul z `show configuration acl`. `named-detach` je odmítnutí `unconfigure access-list netops-switch-ospf-capture vlan netops-switch-ospf ingress` na 33.6.1.14. Varianta `unconfigure access-list vlan netops-switch-ospf ingress` vazbu odstranila.
- `list-file`, `sftp-missing` a `sftp-replace` jsou výstupy dávkového SFTP `ls -ln netops-switch-ospf-capture.pol` a `rename netops-switch-ospf-stage.pol netops-switch-ospf-capture.pol`.
- `empty-vlan` je `show vlan netops-switch-ospf`. `netops-switch-ospf-capture.pol` je vstup odeslaný při zachycení, nikoli výstup zařízení. Koncové mezery výpisů byly odstraněny.
- `x440-port-table`, `x440-port-detail` a `x440-port-count` jsou cílené výstupy z druhého běhu na X440-G2-12p v 18:50 UTC. Příkazy byly `show access-list`, `show access-list port 10 ingress detail` a `show access-list counter ports 10 ingress`.
