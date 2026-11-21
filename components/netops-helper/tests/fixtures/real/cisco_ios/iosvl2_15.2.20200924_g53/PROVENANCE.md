# G53 capture provenance

Captured 2026-11-17 (task netops-20261117-483) from GNS3 `netops-d-lab` d-iosvl2, DNAT 2252, vios_l2
15.2(20200924:215240), host key RSA SHA256:KHSRu76Ucw2SA2xc7xPjAZW468V5Fz0hMgl4SC+B/sk (pinned).
One non-PTY OpenSSH exec channel per command from PC-Radek (as the product transport reads non-PTY queries):
no pager, no terminal or device configuration change. Admin files come from `netops-admin`, `ro/` from
`netops-ro` (privilege 1; only the files that differ are kept: the per-port STP/MST refusals
"Line has invalid autocommand", the whole STP detail with its later BPDU counters, and `show version`).
Commands: task-evidence/g53/tools/commands-fixtures.txt (catalogue renderings with full port names).
Anonymized on PC-Radek with tests/support/anonymize_fixture.py (`--check` clean), names d-iosvl2/d-iosv/d-ceos,
the board serial; addresses to RFC 5737, MACs to RFC 7042. The mapping stays only on PC-Radek.

The lab image has no EtherChannel, PoE or transceivers: `etherchannel_detail` is the real empty
"Channel-group listing" header (with its tab indentation), `lacp_internal` and both counters-errors tables are
blank, `power_inline_detail_gi01` and `interface_transceiver_gi01` are the image's "% Invalid input" answers.
Populated LACP, PoE and DOM come from Cisco documentation (`../../docs/cisco_ios/g53`).
Captures use .out as G51/G52; they are outside the frozen historical .txt corpus.

`stp_interface_detail_gi00.out` (task netops-20261117-483-r4): `show spanning-tree interface GigabitEthernet0/0 detail`
of the same switch, captured 2026-11-17 in the r3 live round (`task-evidence/g53/r2/r3-live/admin2`, `netops-admin`,
one non-PTY exec channel, same pinned host key). Gi0/0 is a portfast edge port: this one-port command prints
`The port is in the portfast edge mode`, the whole `show spanning-tree detail` does not. Anonymized on PC-Radek with
the existing mapping of this directory (the only address, the root bridge MAC, is the `0000.5e00.5302` of
`stp_detail.out`); nothing else identifies the site.

Task netops-20261117-483-r5: tests derive PortFast trunk and BPDU filter variants of `stp_interface_detail_gi00.out` by
replacing its PortFast line with, or adding after `Link type`, the exact line of the Cisco IOS 15.4SY examples in
`../../docs/cisco_ios/g53/stp_interface_detail_{edge_trunk,edge_default,bpdufilter}.out` (source URL:
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-4SY/config_guide/sup6T/15_3_sy_swcg_6T/spanning_tree_features.html,
Optional STP Features). This capture file itself is unchanged.
