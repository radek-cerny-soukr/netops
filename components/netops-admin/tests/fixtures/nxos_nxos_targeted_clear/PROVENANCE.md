# nxos targeted clear fixtures (NX-OS targeted clear)

Cisco Nexus 9000v (N9K-C9300v), NX-OS 9.3(12), lab node Nexus 9300v (GNS3 netops-emulated environment), 2026-11-19. Independent read-only SSH
captures with the account `netops-ro`, anonymised with `components/netops-helper/tests/support/anonymize_fixture.py --check`
(MAC and IPv4 addresses mapped to the documentation ranges). No running configuration was captured. Measured detail
that the parser needs: an ARP entry younger than one second prints its age as seconds with a fraction (`0.333114`
in `nexus9300v__arp-all.txt`, `0.965201` in the live readback right after a clear), older entries as `HH:MM:SS`.

- `show-interface-eth1-2`, `show-interface-eth1-48`: `show interface Ethernet1/2` (a host port with traffic) and Ethernet1/48 (idle).
  The counters of this virtual platform are not plausible (the TX counters show 64-bit garbage); the parser takes the
  numbers as printed. `show-interface-eth1-2-counters`: `show interface Ethernet1/2 counters` (not used by the code).
- `mac-address-hit` (`show mac address-table address <mac>`), `mac-address-miss` (an unknown MAC: only legend and header),
  `mac-address-two-vlans` (the same MAC in VLAN 10 and 20), `mac-interface-hit|empty|trunk` (`show mac address-table interface`
  of a host port, an idle port and the uplink), `mac-all`.
- `arp-hit|miss|mgmt|all`: `show ip arp <ip> vrf <vrf>` (hit, no entry, the management VRF) and `show ip arp vrf all`;
  `arp-bad-vrf`: the real refusal `Invalid context` for an unknown VRF.
- `nd-miss`: `show ipv6 neighbor <ip> vrf default` (IPv6 is disabled on every interface of the lab: the table is empty).
- `trunk`, `lldp`: `show interface trunk`, `show lldp neighbors` (reference only).
- `doc__nd-hit.txt`: DERIVED, not measured. The lab has no IPv6 neighbor and the task forbids configuration changes. The
  rows follow the documented layout of `show ipv6 neighbor` (Cisco Nexus 9000 NX-API CLI reference 9.3(x), "IPv6
  commands", https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/ipv6-commands/:
  columns Address, Age, MAC Address, Pref, Source, Interface; Pref 50, Source icmpv6; a long address on its own line)
  with documentation addresses. The header, legend and `Total number of entries` lines are the real ones of `nd-miss`.

The tests derive the answer after a clear by substituting only the changed value of a captured text (counters 0 and
`Last clearing... 00:00:04`, an ARP age, the empty table of a miss); each such place is named in the test.
Live captures of the answers after the real clear are in a private measurement record.

## verification (public source gate of 1.0.12)

`nexus9300v__lldp.txt`: the lab domain is `node1.invalid` (column widths kept). `doc__nd-hit.txt`: the row of the
documentation MAC `0000.5e00.5301` uses the substitute link-local address `fe80::5301`; it is not the EUI-64 address
of that MAC.
