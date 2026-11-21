# FortiGate-60F, FortiOS 7.6.8 build3744

The task 647 lab run captured scoped CLI responses from the independent
`netops-test-ro` account on 2026-11-20.

- `absent.txt` is the response to `show firewall policy "220061"` before creation.
- `disabled.txt` is the response to the same command after creating the disabled test rule.
- `sequence.txt` is the G22 fragment of `show firewall policy` after appending
  the three test policies. The original device rows were omitted.

The export script uses `components/netops-helper/tests/support/anonymize_fixture.py`.
Policy UUIDs were replaced consistently with documentation values.

- `enabled.txt` is the response to `show firewall policy "220064"` after
  publication with NAT, UTM, certificate inspection and the default web filter.
- `restored.txt` is the response to `show firewall policy "220061"` after the
  undo of its deletion. It has the same settings and a regenerated UUID.
