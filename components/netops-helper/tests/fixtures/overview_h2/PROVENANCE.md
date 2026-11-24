# overview_h2 – EXOS captures for `network_overview`

`captures.json` holds anonymized device output under the key `platform/query/scenario`, with the exact catalogue command and its exit status.

| Key | Origin |
|---|---|
| `extreme_exos/mlag_peer/vm-pair-member` | Real output of `show mlag peer` from one member of an existing ExtremeXOS VM 33.6.1.14 MLAG pair, read-only account, captured 2026-11-22 over pinned OpenSSH. |
| `extreme_exos/mlag_ports/vm-pair-member` | Real output of `show mlag ports` from the same member in the same session window: one MLAG group with an active local link and a peer that reports the group up. |
| `extreme_exos/ports/vm-pair-member` | Real output of `show ports no-refresh` from the same member: enabled ports with active and ready links and one port with a display string. |

All three files passed through `tests/support/anonymize_fixture.py --check` without a saved mapping. Peer and VLAN names were passed as explicit names and the port display string as an explicit description. Addresses and MAC addresses were mapped to documentation values. Counters, states and column alignment are unchanged.

Negative samples in `test_network_overview_exos.py` are marked copies of these captures or of the existing EXOS fixtures (`real/exos/x440g2-12p-10g4_33.7.1.6`, `real/exos/x440g2-12p-10g4_33.7.1.6_2`, `real/exos/exosvm_33.6.1.14`, `real/exos/dom_33.7.1.6_20261114`, `real/exos/switch-health`). Each copy changes one documented field: a port state letter, a counter value, a missing table row, a terminal pager line, a fan or power-supply state, a renamed MLAG label or an explicit account refusal. The existing fixture directories are not changed.
