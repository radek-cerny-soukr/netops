# Junos taxonomy fixtures

The three files in each `../rules/juniper-junos.<area>.<check>/` directory are derived examples. They use synthetic names, RFC 5737 documentation addresses and Junos's literal `SECRET-DATA` and `ACCESS-DENIED` markers. Positive and negative refer to whether a finding is expected. The hidden cases are targeted extracts, with visibility supplied separately by the transport or unit test.

| Rules | Source and derivation |
|---|---|
| Telnet, HTTP, root login, retry options, external login | Remote access, SSH, login and retry options, authentication order. Replaced identities and addresses and permuted service, lockout and backend settings. |
| Management ACL | Juniper ordered loopback filter example. Reduced to a source and port match, with an earlier catch-all accept in the positive example. |
| SNMP | Junos SNMPv3 and VACM access privileges. Changed names and masked key values, contrasted authentication with privacy. |
| NTP and syslog | Junos 26.2R1.7 Admin captures `show-configuration-system-{ntp,syslog}-display-set__junos_port_ownership.txt`. Derived key, routing instance and facility permutations from NTP and remote syslog. |
| VLAN, physical disable and inheritance | Junos 26.2R1.7 Admin captures `show-configuration-display-set__junos_vlan_admin-composite.txt`, `show-configuration-interfaces-ge-0-0-2-display-set__junos_vlan_admin-trunk-native.txt`, and `show-configuration-interfaces-ge-0-0-7-display-inheritance-display-set__junos_vlan_admin-group.txt`. Used exact hierarchy and substituted VLAN names and IDs. ELS bridging and VLAN defaults. |
| Discovery, STP, DHCP and storm control | LLDP, BPDU protection, ELS DHCP snooping, ELS storm-control profiles. Built minimal port and profile permutations. |
| Masks, all rules | Junos 26.2R1.7 Admin capture `junos_junos_config/config_display_set_ro.out`. Markers placed on the audited family for each deliberate coverage gap. |

The manufacturer URLs for the named examples are in the [Junos reference list](../../../docs/juniper-junos.md#references).

Admin capture paths are relative to `components/netops-admin/tests/fixtures`, with versioned captures in `junos_26_2R1_7`. The tests also replay the existing redacted captures at those paths.
