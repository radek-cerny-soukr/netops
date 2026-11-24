# link discovery fixtures, 2026-11-20

Pinned SSH captures with the lab read-only accounts. EXOS output comes from
ExtremeXOS VM 33.6.1.14 and ExtremeXOS VM peer 33.6.1.14 (33.6.1.14) and X440-G2-12p-10G4 (33.7.1.6 patch1-11).
The file suffixes lag, vlan, ports and poe correspond to `show sharing`,
`show vlan detail`, `show ports no-refresh` and `show inline-power info ports 1`.
The EXOS exec channel returned rc 250 with the complete sharing and VLAN output,
including the empty LAG table on the X440, and rc 0 for the other commands.

The FortiGate 80F HA FG-80F (FortiOS 8.0.2 build0251) was read via one interactive
OpenSSH connection as fixture-reader. The `fortigate-ha-ports` and `fortigate-ha-vlan-ids`
fixtures project the balanced CLI blocks from `show switch-controller managed-switch
<serial>` and `show system interface`, retaining only VLAN membership, tags and
parent relationships. VLAN names and the switch serial are replaced consistently.
No raw FortiOS configuration or transcript is included.

All outputs were processed by `tests/support/anonymize_fixture.py --check`.
Tests derive explicitly named negative variants from these captures.
