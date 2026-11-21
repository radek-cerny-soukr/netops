# G33 documentation excerpts

These are answer bodies, not new live captures. set.out/unset.out are literal
7.6.7 build0676 replies measured 2026-11-02, recorded in
`docs/vendor-cli-references/fortinet-fortiadc.md`, Environment findings, Forced failover.
The same replies are in the official 7.6.0 New Features Guide, page 251331
(New and enhanced CLI commands to force HA nodes into standby mode).
refused.out is the measured generic 7.6.7 -284 refusal in that reference,
Limitations; it does not claim a refusal from the standby command specifically.
All three files must pass tests/support/anonymize_fixture.py on PC-Radek.
Truncated/unknown replies in the tests are deliberate corruptions of these excerpts.
No live HA pair was changed or tested by G33.

Integration 461 (2026-11-17): the fixture files were renamed from `*.txt` to `*.out` (repository convention; contents unchanged).
