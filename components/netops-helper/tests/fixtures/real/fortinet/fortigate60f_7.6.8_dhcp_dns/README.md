# dhcp dns RO captures, 2026-11-20 (lab FG-60F)

FortiGate 60F, FortiOS 7.6.8 build3744 (lab, not a customer device). SSH account `fixture-reader`, one held session,
strict host key pin; nothing on the device was changed.

- `captures.json` key `lease_list_all`: `execute dhcp lease-list` (no interface), two sections (`_default`,
  `fortilink`) with one lease each; SSH framing removed the way `netops_core.prompt.cleaned` removes it.
- `lease_list_fortilink`: `execute dhcp lease-list fortilink` (one section).
- `lease_list_internal_empty`: `execute dhcp lease-list internal` – an interface with a DHCP server but no lease prints
  nothing at all (empty output, rc 0).
- `lease_list_bad_interface`: the answer for an interface that does not exist: `Interface name "..." does not exist.`
  (the name is replaced by `nonexistent9`, it was an invented name).
- `lease_list_refused_cli_exec`: the answer of `fixture-operator` (no `cli-exec`) to `execute dhcp lease-list`:
  `Unknown action 0`.

The RO account sees `execute dhcp` with `lease-list` only; `lease-clear` needs an account with `cli-exec`
(`fixture-operator` has none, it answers `command parse error before 'execute'`).

Anonymized with `tests/support/anonymize_fixture.py --check` (MAC, IPv4, host names); the column alignment is kept.
The mapping file stayed on the worker (not in the repository). The CLI text is stored in `captures.json` rather than
as `.txt` for the same reason as in `firewall_inventory_20261117/README.md`.
