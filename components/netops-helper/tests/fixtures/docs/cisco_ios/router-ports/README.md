# router ports Cisco documentation outputs (not live captures)

The lab IOSvL2 has no EtherChannel members, PoE or optics. These files are the verbatim example outputs
of the Cisco command references below (command echo line removed; nothing else changed except as noted).
Tests that need another state change one documented token and are marked DERIVED in the test code.

| File | Source (example) |
|---|---|
| `interface_transceiver.out` | Catalyst 2960-X Consolidated Platform Command Reference, IOS 15.2(7)E, Interface and Hardware Commands, `show interfaces gigabitethernet1/1/1 transceiver detail` (https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr/interface_and_hardware_commands.html). The HTML example indents every line with two tabs; the tabs were removed. |
| `lacp_internal.out` | Same reference, Layer 2 Commands, `show lacp 1 internal` (https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr/layer_2_commands.html). The catalogue reads `show lacp internal`, which prints the same block for every group. |
| `lacp_internal_group5.out`, `lacp_internal_interval.out` | Cisco IOS Interface and Hardware Component Command Reference, `show lacp 5 internal` and `show lacp 1 internal` (variant with the LACPDUs Interval column) (https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/command/ir-cr-book/ir-s5.html). |
| `power_inline_detail.out` | Same IOS reference, `show power inline gigabitEthernet 0/0/0 detail`. |
| `stp_interface_detail_edge_trunk.out`, `stp_interface_detail_edge_default.out`, `stp_interface_detail_bpdufilter.out` | Catalyst 6500 Release 15.4SY Software Configuration Guide (Supervisor Engine 6T), Optional STP Features, examples of `show spanning-tree interface gi3/13 detail` after `spanning-tree portfast edge trunk` (pgfId-1000879..889), the same command before it (`portfast edge mode by default`, pgfId-1000857..867) and `show spanning-tree interface gigabitethernet 4/4 detail` under PortFast Edge BPDU Filtering on a Nontrunking Port (pgfId-999827..837) (https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-4SY/config_guide/sup6T/15_3_sy_swcg_6T/spanning_tree_features.html). Lines copied from the HTML example spans as published (leading space, trailing spaces and `Timers:message`/`BPDU:sent` spacing kept); verification-r5, retrieved 2026-11-18. |

The documented port names Gi1/1/1 (uplink) and Gi0/0/0 are outside the IOS physical-port slot of the catalogue;
public-path tests rename only that token to Gi1/0/1 (DERIVED), direct parser tests use the files unchanged.
Retrieved 2026-11-17.
