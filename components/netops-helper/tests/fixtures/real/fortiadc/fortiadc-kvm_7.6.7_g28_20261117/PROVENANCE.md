Captured 2026-11-17 from FortiADC-KVM VM220 7.6.7 build0676 via VM201,
built-in admin enrolled conceptually as admin-bounded/catalogue. No ADC settings changed.
Commands and capture transport: task-evidence/g28/adc_read.py and RESULT.md.
The native `diagnose server-load-balance vs_stat vdom root` returned five VS;
`... vs VS_APP_HTTP rs 1` returned member ID 1 (RS_A as a name returned no member).
All VS were DEAD, all observed members DOWN; counters are snapshots, not traffic tests.
Content-routing table and session/persistence tables had no entries. No objects created.
Anonymized on PC-Radek with tests/support/anonymize_fixture.py --keep FortiADC-KVM --check.
Terminal captures retain echo/prompt/control characters; exec captures may interleave
stdout/stderr prompts, so runtime statistics tests use the terminal captures only.

Integration 461 (2026-11-17): the fixture files were renamed from `*.txt` to `*.out` (repository convention); contents unchanged.
