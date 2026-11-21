# Junos G140 captures

Targeted output from d-vjunos (vJunos-switch 26.2R1.7, ELS), 2026-11-19 UTC. The PC-Radek probe in `task-evidence/g140/probe.py complete` applied a temporary candidate with an exclusive confirmed commit and returned it. The pre/post configuration SHA-256 was identical. Fixture names follow the probe commands. The four `enabled-*-config/count` captures are configuration scopes read as netops-admin. All other fixtures are operational reads as netops-ro. Anonymized and checked with `components/netops-helper/tests/support/anonymize_fixture.py`.

Tests derive truncated answers from these captures. The collecting/distributing variant uses the form in the [Junos show lacp interfaces reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lacp-interfaces.html) and the repository's Junos ELS LACP documentation fixture. Live ge-0/0/8 reported Detached.
