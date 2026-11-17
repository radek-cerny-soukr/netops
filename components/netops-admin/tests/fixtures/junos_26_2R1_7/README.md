# Juniper vJunos-switch 26.2R1.7 (ELS) outputs

Command outputs measured on vJunos-switch 26.2R1.7 (ELS, model ex9214, GNS3 lab node, test port ge-0/0/2) for the
Junos adapter of netops-admin. All files except `show-configuration-display-set__reconstructed.txt` are copied from the
measurement of task netops-provoz-20261116-308 (`fixtures/` of that measurement: the clean answer without the echo of
the command and without the prompt; files named `exec__*` are ssh exec answers).

Anonymisation while copying: the host names are `host01` (the switch) and `host02` (its LLDP neighbour), addresses
are in the documentation ranges (the management address 192.0.2.56, the measuring client 192.0.2.36, the IPv6 address
of fxp0 2001:db8::56/64), the MAC address of the LLDP neighbour is 00:00:5e:00:53:01, the XML namespace of the JSON
answer names `xml.example.invalid`, and the lab prefix of commit comments is shortened. Account names `netops-admin`
and `netops-ro` are kept.

`show-configuration-display-set__reconstructed.txt` is NOT a copy: the full configuration of the lab switch was read
for this task only as a structure (the first words of each line, the number of lines, the version, host-name, login
classes and the ge-0/0/2 lines), never stored, because it holds password hashes. The file rebuilds that structure with
documentation addresses and invented values where the structure did not show them (syslog, DHCP trace options,
static route); the password hashes are `<REDIGOVANO>`. The ge-0/0/0 (trunk D10/D20), ge-0/0/1 (access D20) and
ge-0/0/2 (access, VLAN default, the lab preparation of the measurement) lines and the VLANs D10 and D20 match the lab.

`tests/fake_junos.py` builds every answer from these files; the full `show version` (only the `Hostname`, `Model` and
`Junos` rows were measured with `| match`), a populated MAC table row and the commit history rows written by the
simulation (same layout as the measured rows) are derived from measured layouts rather than measured themselves.

Task netops-20261116-378 added the files named `*__t378-*`: the timer after an immediate return on the same lab switch
(2026-11-16 19:31-19:56 UTC, test port ge-0/0/2, `commit confirmed 2` for speed, the adapter's command sequence).
S1: empty safeguard, description change and the inverse committed with `commit confirmed`, then the session ended
without a confirmation; the expiry returned the configuration to the state before the LAST `commit confirmed` (the
inverse), so the change came back (`show-system-commit__t378-s1-after-expiry-change-back.txt`,
`show-system-rollback-compare-*__t378-s1-*`). S2: the same without the inverse commit (the session ended before it);
the expiry returned the state before the change commit, which equals the state before the empty safeguard. They are
copied from `task-evidence/378/surove/` by `task-evidence/378/nastroj/fixtures378.py` (exec header, echo, `[edit]`
and prompt removed, commit histories cut below the safeguard row of the measurement); the anonymiser
(`components/netops-helper/tests/support/anonymize_fixture.py`) changed nothing and `--check` passes.
