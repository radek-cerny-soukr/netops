# G136 (task 553): Junos configuration captures, d-vjunos

PROVENANCE: REAL output of d-vjunos (vJunos-switch, `Model: ex9214`, `Junos: 26.2R1.7`, GNS3 netops-d-lab,
`gns3-server:2256`), captured 2026-11-19 over SSH exec (pinned host key) by the accounts
`netops-admin` (class super-user, files `*_admin.out`) and `netops-ro` (class read-only, `*_ro.out`).

Secret handling: every password hash (`encrypted-password ...`, any `$<n>$...` token) was replaced by the
sentinel `"$9$SENTINELSALT$SECRET-HASH-SENTINEL"` inside the capture pipe, before anything was written
(`task-evidence/g136/tools/scrub.py`); the raw output was never stored.  The files were then anonymised with
`tests/support/anonymize_fixture.py` (host names, user names, lab addresses, the dhcpv6 vendor-id serial; the map is
kept outside the repository).  The anonymiser widens the space after a shortened user name to keep columns;
in `config_display_set_admin.out` and `config_hierarchical_admin.out` such runs of spaces inside a line were
collapsed back to one space (Junos prints one space between words) — the only edit (DERIVED in that respect).
The capture-time sentinel had the SHA-512 crypt prefix of the real hashes; in the committed files it was then changed to
the Junos `$9$` form (DERIVED in that respect) so that the repository-wide fixture check (`credential:crypt`) stays clean;
the redactor hides both forms.

| File | Command | Note |
|---|---|---|
| `config_display_set_admin.out` | `show configuration \| display set \| no-more` | 54 lines, starts with `set version` |
| `config_display_set_ro.out` | same, `netops-ro` | every section `/* ACCESS-DENIED */`, exit status 0 |
| `config_hierarchical_admin.out` | `show configuration \| no-more` | `## Last commit` header, `## SECRET-DATA` annotations |
| `compare_rollback_1_admin.out` | `show configuration \| compare rollback 1 \| no-more` | empty (no change) |
| `compare_rollback_4_admin.out` | `show configuration \| compare rollback 4 \| no-more` | host-name change |
| `compare_rollback_3_ro.out` | same with rollback 3, `netops-ro` | EMPTY although rollback 3 differs (read-only class) |
| `compare_rollback_99_admin.out` | `... compare rollback 99` | `error: Value 99 is not within range (0..49): 99` |
| `rescue_absent_admin.out` | `show system configuration rescue \| no-more` | `error: No rescue configuration is set.` |
| `version_admin.out` | `show version \| no-more` | identity |

Measured besides (not stored as files): `show system rollback <n> | display set` and
`show configuration | compare rollback <n> | display set` are refused (`error: syntax error, expecting <command>: set`);
`show configuration | display set | match ACCESS-DENIED | count` answers `Count: 0 lines` for netops-admin and
`Count: 8 lines` for netops-ro.  SFTP is not enabled on the device (subsystem request closed).
