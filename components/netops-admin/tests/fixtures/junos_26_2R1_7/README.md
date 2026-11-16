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
