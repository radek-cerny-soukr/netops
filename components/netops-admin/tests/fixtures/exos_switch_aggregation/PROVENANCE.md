# ExtremeXOS switch aggregation fixtures

- `before__*`, `forced__*`, `jumbo__*`, `stp__*` and `stp-port-set__*`
  are pinned OpenSSH exec captures from EXOS VM ExtremeXOS VM 33.6.1.14 running 33.6.1.14, 2026-11-19 UTC. Configuration output is restricted to the
  relevant lines of the VLAN and STP modules. STP was an isolated domain
  `g44stp` and VLAN `g44probe`, port 10. See live evidence (private measurement record, not published).
- `exosvm__*`, `exosvm-peer__*` are read-only targeted observations of the
  33.6.1.14 switch pair in GNS3. `x440__*` are from the physical
  X440-G2-12p-10G4 on 33.7.1.6-patch1-11. The vault connector redacts device
  identities and may over-redact fragments of unrelated English headings.
- All files went through `components/netops-helper/tests/support/anonymize_fixture.py --check`.
  The two MLAG peer names and ISC/alternate VLAN names use the same mapping
  across peer and port outputs. Authentication values are omitted when set.
- The incomplete answer in the transport test removes the footer of a real capture.

- `x440-sharing-*` records a single-member idle LACP group and the same
  group with a second member and L3_L4. In an idle group EXOS can leave
  the current-master column empty. See the X440 fixture run and restoration
  in the live evidence (private measurement record, not published).
- The fake LAG transport reuses the real X440 port 10 detail with port
  number 8 substituted. Its VLAN Default line is derived from the physical
  difference after releasing port 8 and the fake switch's DATA ports.
- The global jumbo plan uses the default and example value in
  [the command reference](https://documentation.extremenetworks.com/exos_commands_30.6/GUID-2395A165-478E-4F92-B339-99D2D438CCDC.shtml).
- The new-peer transport projects the switch-pair format onto an unbound peer.
  It preserves the measured peer/VLAN/IP fields, sets the checkpoint to
  Up for peer undo and Down for binding changes, adjusts the binding
  count and omits the alternate path.
  Its binding scenario uses the measured MLAG 104 table with port 8
  substituted for the active switch-pair port 5.
- The R2 tagged trunk and active STP port scenarios add a tagged VLAN
  to the measured X440 LAG and substitute Active for Ready in the
  measured ExtremeXOS VM 33.6.1.14 port 10 details, respectively.
- R2 uses the measured ELRP session row from Helper's EXOS X440
  `x440g2-12p-10g4_33.7.1.6_2/elrp.txt`. The action-only mismatch and
  matching row derive from that capture. See the [ELRP column reference](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-F562E00D-0BF8-4116-A3DB-DBE9AA831EED.shtml).
  On ExtremeXOS VM 33.6.1.14 33.6.1.14 the matching configuration renders as
  `configure elrp-client periodic vlan g44r2elrp ports 10 interval 5000 milliseconds log`
  after the Admin command requested five seconds. The matching regression
  uses that rendering with the same V10 name as the readback fixtures.
- R2 projects the header, row 13 and footer from Helper's EXOS X440
  `x440g2-12p-10g4_33.7.1.6/ports_configuration.txt` onto a targeted query.
  `x440__port-13-info.out` is the relevant excerpt from the live
  `show ports 13 information detail` on the lab ExtremeXOS switch (2026-11-19).
