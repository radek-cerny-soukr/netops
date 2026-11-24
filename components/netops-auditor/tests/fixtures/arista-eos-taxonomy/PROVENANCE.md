# Arista EOS audit fixture provenance

Every file in `../rules/arista-eos.*` is a synthetic, derived command excerpt. The
envelope, including the `! device:` header line, follows the cEOS 4.36.1F capture
below. The fixtures use documentation addresses, generic names and the literal
`NETOPS_REDACTED` in secret positions. Like `show running-config`, they omit
commands that only restate an EOS default, such as `no shutdown`, `lldp transmit`,
`idle-timeout 0`, `logging on`, `snmp-server vrf default` or
`no ntp authenticate`. The test replays positive and negative files with a
derived `username` line for the collecting account with the `network-admin`
role, in the form of the capture. It replays not-evaluated files without that
line, as for an account authenticated only by a server.

| Rules | Source and derivation |
| --- | --- |
| Management listeners, SSH timer and ACL | Arista EOS 4.37.0F Session Management Commands and ACLs and Route Maps. Changed ports, names, prefixes and states to cover active, inactive and unproven paths. |
| Lockout, local credentials and external login | Arista EOS User Manual and User Security. Normalized names and keys. The `sha512` form and role ordering come from the 4.36.1F baseline. |
| SNMP | Arista EOS 4.37.0F SNMP. Adapted community and v3 examples. The masked user and rejected auxiliary command exercise ambiguous input. The positive auxiliary response follows the documented field layout. |
| NTP | Arista EOS 4.37.0F System Clock and Time Protocols. Replaced source, VRF and key, and varied enablement and trust. |
| Syslog | Arista EOS User Manual, logging trap. Replaced the collector and varied the trap level and logging state. |
| LLDP, BPDU and storm control | Arista EOS 4.37.0F LLDP, Spanning Tree and Data Transfer. Used a generic access port and varied the port/global switches and the broadcast limit. |
| DHCP snooping | Arista EOS 4.37.0F IPv4. Adapted the bridging setup and changed VLAN range and port trust. |
| Access VLAN, native VLAN, physical port state | Arista EOS 4.37.0F Virtual LANs, EOS User Manual and the 4.36.1F trunk/interface captures. Varied explicit access, tagged and shutdown states. |

The [vendor references](../../../docs/arista-eos.md#vendor-references) provide the source URLs.

The test also replays these existing 4.36.1F Admin captures at the SSH boundary.
The trunk excerpt is wrapped in an EOS envelope for replay. It still represents
only the named interface. The denial is replayed verbatim.

- `components/netops-admin/tests/fixtures/eos_4_36_1F/show-running-config__baseline.txt`
- `components/netops-admin/tests/fixtures/eos_eos_switchport_admin/show-running-config-interfaces-Ethernet12__trunk-dot1x.txt`
- `components/netops-admin/tests/fixtures/eos_eos_mlag_admin/ro-running-config-denied.txt`
