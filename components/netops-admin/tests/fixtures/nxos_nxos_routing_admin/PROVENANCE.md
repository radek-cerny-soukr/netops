# NX-OS nxos routing admin fixtures

SSH exec and interactive CLI on GNS3 Nexus 9300v, NX-OS 9.3(12), Cisco Nexus9000 C9300v, NX-OS 9.3(12), 2026-11-18 UTC. `*-config.txt` is a projection of the running configuration onto the test objects. `*-routes*.txt`, `*-loop*.txt` and `*-svi*.txt` are outputs of the separate read account. `*-write.txt` contains only the related interactive commands and device answers. Hostname, MAC and generated addresses were anonymized with `components/netops-helper/tests/support/anonymize_fixture.py`. The documentation addresses entered for the test were kept.

Both snapshots of the complete running configuration had normalized SHA-256 `41bd2b62945db207fc283cbb35b858bf71525d26a6c59b1686b7e518826684ef`. DHCP was disabled and rejected the relay command on the test SVI. Cisco's Nexus 9000 NX-API CLI reference documents the populated relay display for 7.0(3)I7(4). [Cisco DevNet](https://developer.cisco.com/docs/nx-api-cli-reference-for-the-cisco-nexus-9000-series-platform/dhcp-commands/)

## nxos routing admin r2

The enabled feature, relay table and DHCP configuration fixtures were captured on the same node on 2026-11-18.
The relay fixtures cover empty, default-VRF (blank VRF column) and named-VRF responses for Vlan3900.
The Ethernet1/3 fixtures cover the original L2 defaults, routed IPv4 configuration and its operational state,
the L2 return, and the separate L2 capture with access VLAN 3900 that mode conversion erased.
Trailing whitespace was trimmed and MAC addresses in `show interface` were mapped to locally administered addresses.
The post-return interface detail was read separately. The remaining command outputs and timestamps appear in
the capture (private measurement record, not published). Test snapshots merge the measured interface
stanzas into the anonymized baseline from `nxos_9_3_12`. In-progress fake writes use subsets of the adjacent captures.

## nxos routing admin r3

Captured on the same node on 2026-11-18 13:37–13:38 UTC with
r3_measure.py (private measurement record, not published); full answers in
r3-measure.jsonl (private measurement record, not published).
`port-l3-connected-status.txt` and `port-l3-connected-config.txt` show Ethernet1/3 after `no switchport`,
`ip address 192.0.2.17/28` and `no shutdown` (status `connected routed`).
`relay-use-vrf-default-config.txt` shows that `ip dhcp relay address 192.0.2.249 use-vrf default` is stored without
a VRF. `l3-conflicts-write.txt` lists the probe commands and the device answers verbatim. The capture removed the
prompts because they contain the hostname. The `host01(...)#` prompts and `! probe` comment lines were added
afterwards and are derived. Trailing whitespace was trimmed.
`port-l3-connected-interface.txt` is the check-account `show interface Ethernet1/3` of the same connected routed
state, read in a second scratch cycle at 13:57 UTC
(r3_measure_iface.py (private measurement record, not published),
r3-measure-iface.jsonl (private measurement record, not published)). Its MAC addresses were
mapped to locally administered addresses like the r2 captures. The status answer was identical in both cycles.

## verification

The route-overlap previews reuse the measured Vlan3900 and loopback900 blocks and the static-route tables above.
The SVI previews replay `interfaces-svi`, `interfaces-svi6` and the starred interactive SSH row of
`../nxos_9_3_12/show-users.txt`. The peer addresses and the unstarred foreign session are derived variants.

## verification r2

`svi-up.txt` is the status header from `show interface vlan 20` on Nexus 9300v, NX-OS 9.3(12) (NX-OS 9.3(12), 2026-11-18).
`ssh-sockets-management.txt` comes from `show sockets connection tcp foreign <peer>` in the same interactive
session as the starred `show users` row. The two socket addresses were replaced with documentation addresses,
and the prompt and trailing whitespace were removed. The count covers all sockets before the foreign address
filter. [Cisco NX-OS 9.3 socket command reference](https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/socket-commands/).
The test variants substitute the Vlan3900 name, client addresses, VRF and the SVI address and shutdown stanza.
The IPv6 route update replays the addresses and distance in `interfaces-config.txt`.

## verification (public source gate of 1.0.12)

Solicited-node groups that still held the low 24 bits of the real link-local addresses (`interfaces-svi6.txt`,
`interfaces-loop6.txt`, `update-loop6.txt`) are replaced by the groups of the anonymised link-local addresses of
the same output (`ff02::1:ff00:11` for `fe80::11`, `ff02::1:ff00:10` for `fe80::10`).
