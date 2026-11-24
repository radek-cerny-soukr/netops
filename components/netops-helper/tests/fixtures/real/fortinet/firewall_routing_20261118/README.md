# firewall routing RO captures, 2026-11-18

Real output of read-only CLI commands, one exec read per command (verification, 1.0.12 firewall routing). Nothing on
the devices was changed.

| Key | Device | Account | Captured (UTC) |
|---|---|---|---|
| `60f` | lab FortiGate-60F, FortiOS 7.6.8 build3744, standalone, VDOM disabled, no BGP/OSPF, IPv6 only `::1` | `fixture-reader` | 2026-11-18 07:31 |
| `FortiGate 80F HA` | FortiGate 80F HA FortiGate-80F HA primary, FortiOS 8.0.2 build0251, three iBGP peers over ADVPN tunnels | `fixture-reader` | 2026-11-18 07:32 |
| `FortiGate 80F HA` (`interface_details_wan1`, `lacp_detail_fortilink`) | the same FortiGate 80F HA, CLI side of the live check (both FortiLink members bundled; 8.0.2 prints a `session_count4/6` line) | `fixture-reader` | 2026-11-18 07:51 |
| `80f` | FortiGate-80F, FortiOS 8.0.2 build0251, IPv6 static default via a link-local gateway | read-only use of an admin key | 2026-11-18 07:36 |

Commands (key = member name): `get router info6 routing-table` (`ipv6_routing_table`), `get router info
routing-table all|database`, `get router info6 routing-table database`, `get router info[6] bgp summary`,
`get router info[6] bgp neighbors [<peer>]` (`bgp_neighbors`, `bgp_neighbors_peer`, `bgp_neighbors_peer_absent`),
`get router info ospf neighbor all`, `diagnose netlink interface list [<interface>]`, `diagnose netlink aggregate
name <aggregate> show` (`lacp_detail_*`), `diagnose netlink aggregate list`, `get system interface physical`,
`get system status` (`version`).

Projection: CR removed, the command echo (first line) and the trailing prompt removed the way
`netops_core.prompt.cleaned` removes SSH framing; empty answers stay empty strings. Anonymised per device (the two later FortiGate 80F HA members with a copy of the FortiGate 80F HA mapping) with
`tests/support/anonymize_fixture.py` in one run (serial numbers, host name, MAC and IP addresses; `--check` rc 0);
the mapping files stayed on the lab test host and are not in the repository. Known effects of the anonymiser that
the tests rely on as printed: IPv4 addresses outside the first three /24s each get their own documentation address,
so some printed prefixes have host bits (`203.0.113.232/24`), IPv6 prefixes keep a trailing `::0`, and a shorter
replacement address widens the following spaces (`192.0.2.254   (recursive via`). Every relation the tests check
(same prefix, same gateway, interface names) is kept.
