# Juniper vJunos-switch 26.2R1.7 (ELS) outputs

Command outputs measured on vJunos-switch 26.2R1.7 (ELS, model ex9214, in the virtual topology node, test port ge-0/0/2) for the
Junos adapter of netops-admin. All files except `show-configuration-display-set__reconstructed.txt` are copied from the
measurement of verification (`fixtures/` of that measurement: the clean answer without the echo of
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

verification added the files named `*__t378-*`: the timer after an immediate return on the same lab switch
(2026-11-16 19:31-19:56 UTC, test port ge-0/0/2, `commit confirmed 2` for speed, the adapter's command sequence).
S1: empty safeguard, description change and the inverse committed with `commit confirmed`, then the session ended
without a confirmation; the expiry returned the configuration to the state before the LAST `commit confirmed` (the
inverse), so the change came back (`show-system-commit__t378-s1-after-expiry-change-back.txt`,
`show-system-rollback-compare-*__t378-s1-*`). S2: the same without the inverse commit (the session ended before it);
the expiry returned the state before the change commit, which equals the state before the empty safeguard. They are
copied from a private measurement record (exec header, echo, `[edit]`
and prompt removed, commit histories cut below the safeguard row of the measurement); the anonymiser
(`components/netops-helper/tests/support/anonymize_fixture.py`) changed nothing and `--check` passes.

## 1.0.12 junos vlan admin (verification): files named `*__junos_vlan_admin-*` and `show-vlans-junos vlan admin-*`

Measured on the same lab switch (vJunos-switch 26.2R1.7, GNS3 `netops-emulated environment`) on 2026-11-18 09:52-10:41 UTC under the
measurement's own `commit confirmed 30` with an explicit return (configuration SHA-256 before = after). Test objects:
VLANs `junos vlan admin-data` 3901 (with a UTF-8 description and `l3-interface irb.3901`), `junos vlan admin-voice` 3902, `junos vlan admin-trunk` 3903,
port ge-0/0/2 (access with voice VLAN, then trunk with native VLAN, UTF-8 descriptions up to 240 characters),
ge-0/0/7 (access from the group `junos vlan admin-grp` applied at the top level), ge-0/0/8 (VLAN member from the wildcard group
`junos vlan admin-grpw` `"<ge-0/0/[89]>"` applied at the port), ge-0/0/9 (from the interface-range `junos vlan admin-rng`) and the renames
`junos vlan admin-trunk` -> `junos vlan admin-trunk2`, `junos vlan admin-data` -> `junos vlan admin-data2`. Answers of the write account (`netops-admin`) and of the
check account (`netops-ro`, files with `ro`) come from interactive sessions; the copy
keeps the answer between the echo of the command and the prompt and drops the banner of the pending commit confirmed.
`anonymize_fixture.py --name vJunos-switch --check` changed nothing (no address, MAC or host name in these answers).

`show-configuration-display-set__junos_vlan_admin-composite.txt` is NOT a single measured answer: it is the reconstructed baseline
above with the measured junos vlan admin statements put in (ge-0/0/2, switch-options and the VLAN junos vlan admin-data from the answers of
the first stage; groups, apply-groups, interface-range, ge-0/0/8 and the other VLANs from
`show-configuration-display-set-match-junos_vlan_admin__junos_vlan_admin-renamed.txt` with the two renames undone, plus the measured
`set interfaces ge-0/0/8 unit 0 family ethernet-switching interface-mode access`, which `| match junos vlan admin` does not list).
It is the configuration of the first stage, for which the `display inheritance | display set` answers were measured.
