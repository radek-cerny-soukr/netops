# FortiGate-60F, FortiOS 7.6.8 build3744 (A2: service group, schedules)

Captured on 2026-11-23 in one pinned SSH session per account (FortiGate anti-DDoS rule: no series of connections).

- The read-only check account answered `show` and `show full-configuration` of
  `firewall service group` (`service-group-show.txt`, `service-group-full.txt`),
  `firewall schedule recurring` (`schedule-recurring-show.txt`, `schedule-recurring-full.txt`),
  `firewall schedule onetime` (`schedule-onetime-show.txt`, `schedule-onetime-full.txt`; the lab had no one-time
  schedule) and `firewall schedule group` (`schedule-group-show.txt`; empty). The objects are the FortiOS factory
  objects. The answers hold no `ENC` value and no secret.
- The write account opened new objects with `edit` and left them with `abort`, which saves nothing
  (`probe-onetime-recurring-group.txt`, `probe-onetime-unquoted.txt`, `probe-policy-inspection-mode.txt`, the whole transcripts with the prompts; the
  final `show` of each table proves that nothing was saved). They record the defaults `get` lists for a new object,
  that `show` prints only the UUID of a new object, that `set start "10:00 2026/12/01"` fails with return code -160
  while the unquoted words are accepted, that FortiOS accepts a one-time end before its start, that a recurring
  schedule takes quoted weekday names and quoted times and normalizes `8:5` to `08:05`, and that `show` prints the day
  list in week order. A new firewall policy took `set inspection-mode proxy` and `flow` (`get` lists them) and
  `show firewall policy 231399` after `abort` answered `entry is not found in table`.

Edits: the prompt line and the echoed command were removed from the `show` answers (not from the probe transcripts),
and every UUID was replaced consistently with a documentation value `00000000-0000-4000-8000-0000000000NN`. Host
names in the files are the factory host name, which equals the model. `anonymize_fixture.py --check`
(`components/netops-helper/tests/support/anonymize_fixture.py`) finds no identifier left (run on the test host).

The live run of the A2 group (preview, apply with the approved hash, independent readback, undo; see the result of
the group) added the scoped answers of the created test objects to a private measurement record; the unit tests use the
captured layout through `fake_fortios_a2.py`.
