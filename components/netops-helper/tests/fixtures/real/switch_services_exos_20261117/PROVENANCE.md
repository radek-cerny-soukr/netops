# switch services EXOS service captures (verification)

Copied unchanged from a private measurement record during
integration, because `test_switch_services_exos.py` reads them and the private record is not part of the tree.
Captures were renamed `*.txt` -> `*.out` (convention of verification) so they are not historical classifier captures
(`output_status_baseline.json`); `commands.json` is unchanged.

`x440-admin/commands.json` keeps only `command`, `rc` and `bytes` (what the test reads, as in `x435`/`x440`).
Its capture metadata (device, firmware, account, capture time, anonymisation note) stays in the original file on the
442 branch; it named lab addressing that `test_anonymize_fixture.py` correctly refuses in committed fixtures.
