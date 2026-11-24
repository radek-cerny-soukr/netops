# junos config (verification): Junos backup/restore fixtures

Copies of the REAL vJunos-switch captures (vJunos-switch, Junos 26.2R1.7) from
`components/netops-helper/tests/fixtures/real/juniper_junos_els/junos_config_vjunosswitch_26.2R1.7/` (provenance,
secret replacement and anonymisation: README there).  `config_hierarchical_admin.out` is
`show configuration | no-more` of `netops-admin`; every password hash is the sentinel
`$9$SENTINELSALT$SECRET-HASH-SENTINEL`.
`config_hierarchical_ro.out`: the same command of `netops-ro` (read-only class), REAL, user name replaced by `user01`.
`commits_with_rescue_admin.out`: `show system commit | no-more` right after `request system configuration rescue save` (REAL, user name replaced by `user01`): the last row is `rescue  <time> UTC by <user> via cli`.
