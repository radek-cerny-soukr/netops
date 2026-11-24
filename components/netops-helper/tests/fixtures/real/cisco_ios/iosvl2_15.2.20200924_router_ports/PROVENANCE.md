# router ports capture provenance

Captured 2026-11-17 (verification) from GNS3 `netops-emulated environment` Cisco IOSvL2 15.2, vios_l2
15.2(20200924:215240), host key RSA SHA256:KHSRu76Ucw2SA2xc7xPjAZW468V5Fz0hMgl4SC+B/sk (pinned).
One non-PTY OpenSSH exec channel per command (as the product transport reads non-PTY queries):
no pager, no terminal or device configuration change. Admin files come from `netops-admin`, `ro/` from
`netops-ro` (privilege 1; only the files that differ are kept: the per-port STP/MST refusals
"Line has invalid autocommand", the whole STP detail with its later BPDU counters, and `show version`).
Commands: private measurement record (catalogue renderings with full port names).
Anonymized  with tests/support/anonymize_fixture.py (`--check` clean), names Cisco IOSvL2 15.2/Cisco IOSv 15.9(3)M12/Arista cEOS 4.36.1F,
the board serial; addresses to RFC 5737, MACs to RFC 7042. The mapping stays only.

The lab image has no EtherChannel, PoE or transceivers: `etherchannel_detail` is the real empty
"Channel-group listing" header (with its tab indentation), `lacp_internal` and both counters-errors tables are
blank, `power_inline_detail_gi01` and `interface_transceiver_gi01` are the image's "% Invalid input" answers.
Populated LACP, PoE and DOM come from Cisco documentation (`../../docs/cisco_ios/router ports`).
Captures use.out as router routing/router probes; they are outside the frozen historical.txt corpus.

`stp_interface_detail_gi00.out` (verification-r4): `show spanning-tree interface GigabitEthernet0/0 detail`
of the same switch, captured 2026-11-17 in a later live round (private measurement record, `netops-admin`,
one non-PTY exec channel, same pinned host key). Gi0/0 is a portfast edge port: this one-port command prints
`The port is in the portfast edge mode`, the whole `show spanning-tree detail` does not. Anonymized  with
the existing mapping of this directory (the only address, the root bridge MAC, is the `0000.5e00.5302` of
`stp_detail.out`); nothing else identifies the site.

verification-r5: tests derive PortFast trunk and BPDU filter variants of `stp_interface_detail_gi00.out` by
replacing its PortFast line with, or adding after `Link type`, the exact line of the Cisco IOS 15.4SY examples in
[`stp_interface_detail_edge_trunk.out`](../../../docs/cisco_ios/router-ports/stp_interface_detail_edge_trunk.out), [`stp_interface_detail_edge_default.out`](../../../docs/cisco_ios/router-ports/stp_interface_detail_edge_default.out) and [`stp_interface_detail_bpdufilter.out`](../../../docs/cisco_ios/router-ports/stp_interface_detail_bpdufilter.out) (source URL:
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-4SY/config_guide/sup6T/15_3_sy_swcg_6T/spanning_tree_features.html,
Optional STP Features). This capture file itself is unchanged.
