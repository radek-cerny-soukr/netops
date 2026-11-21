# d-vjunos, GNS3 DNAT 2256, 2026-11-20 UTC

These replay fixtures are derived from the masked capture in
`task-evidence/souhrn-junos/r2/live.txt`. Both commands ran with `| no-more`
using `netops-admin`.

- `log_repeated.out` preserves the body shape shared by the 44 unrecognized
  rows of `show log messages | last 2000`. The timestamp, hostname and
  repetition count are substitutions because the discovery capture masked
  individual fields.
- `traceroute_interface.out` preserves the banner and the single hop with
  three measured responses from `traceroute <lab address> no-resolve ttl 30 wait 1`.
  The target is substituted with the enrolled `192.0.2.1` used by the G132
  tests. Numeric fields masked during capture use values from the G132
  Junos banner and local three-response capture.
