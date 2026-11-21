# G39 EXOS service captures (task 442)

Copied unchanged from `task-evidence/g39/fixtures/` of `worker/netops-20261117-442` (`a8fb1682^2`) during
integration task 457, because the dev-1.0.12 tree carries no `task-evidence/` and `test_g39_exos.py` read them there.
Captures were renamed `*.txt` -> `*.out` (convention of task 448) so they are not historical classifier captures
(`output_status_baseline.json`); `commands.json` is unchanged.

`x440-admin/commands.json` keeps only `command`, `rc` and `bytes` (what the test reads, as in `x435`/`x440`).
Its capture metadata (device, firmware, account, capture time, anonymisation note) stays in the original file on the
442 branch; it named lab addressing that `test_anonymize_fixture.py` correctly refuses in committed fixtures.
