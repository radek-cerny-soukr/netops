# G13 RO captures, 2026-11-17 (IT-case)

FortiGate 80F HA primary, FortiOS 8.0.2 build0251. SSH account `netops-test-ro` (read-only, one exec read per
command). Nothing on the device was changed.

- `captures.json` key `hardware_sensors`: `execute sensor detail`, the five sensors this model reports (two PSU
  slots, the second absent; three temperatures, two of them printed without an `Alarm` line). Verbatim.
- `captures.json` key `crash_log`: `diagnose debug crashlog read`, 606 numbered lines and the two trailer lines.
  Projection: 18 hexadecimal tokens of 12-16 digits with letters (register/stack values of a crash dump and one
  JavaScript chunk hash) are replaced by zeros of the same length, because the fixture MAC guard reads them as
  bare MAC addresses; the user name in two `Signal ... by user <...>` lines is anonymized.
- `captures.json` key `config_error_log`: `diagnose debug config-error-log read` on the same device: empty output
  (one newline), the real "no error recorded" answer.

SSH framing is removed the way `netops_core.prompt.cleaned` removes it (prompt prefix of the first line,
trailing prompt). Anonymized with `tests/support/anonymize_fixture.py --check` (user name; host name and serial
appear only in the removed prompt). The mapping file stayed on the lab test host and is not in the repository.
The CLI text is in JSON, not in `.txt` files, for the same reason as `g08_20261117` (historical classifier baseline).
