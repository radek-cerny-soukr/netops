# G120 cEOS 4.36.1F captures

Real output of GNS3 `netops-d-lab` cEOS (DNAT 2253, EOS 4.36.1F engineering build `4.36.1F-48405728.4361F`),
captured 2026-11-18 between 12:23 and 12:30 UTC over pinned SSH (`netops-ro`, one case `netops-admin`) with
`task-evidence/g120/cli.py`, anonymized with `tests/support/anonymize_fixture.py` by
`task-evidence/g120/make_fixture.py` (no residual identifiers). The Ethernet12 messages come from the approved
test flap (shutdown / no shutdown, running-config hash unchanged), see `task-evidence/g120/flap-1.jsonl`.
The `command` field of the route lookups names the anonymized address (as the parameters do); nothing else is
derived or edited by hand; unit tests derive cut and malformed variants from these texts.
