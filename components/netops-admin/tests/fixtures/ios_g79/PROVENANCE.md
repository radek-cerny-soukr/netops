# G79 fixture provenance

The `iosxe-*` files are targeted SSH EXEC responses captured on 2026-11-19 from
the GNS3 nodes d-iolxe and d-iolxe-l2 (IOS XE 17.18.2). The captures omit the SSH
disconnect message and carriage returns and were processed with
`components/netops-helper/tests/support/anonymize_fixture.py --check`.

| File | Account and command |
| --- | --- |
| iosxe-l2-connected.txt | netops-ro, `show interfaces Ethernet2/3 status` |
| iosxe-l2-disabled.txt | netops-ro, `show interfaces Ethernet0/1 status` |
| iosxe-l2-dynamic-access.txt | netops-ro, `show interfaces Ethernet2/3 switchport` |
| iosxe-l2-empty-macs.txt | netops-ro, `show mac address-table interface Ethernet2/3` |
| iosxe-l2-poe-refused.txt | netops-admin, `show power inline Ethernet2/3` |
| iosxe-routed-switchport-refused.txt | netops-admin, `show interfaces Ethernet0/3 switchport` |
| iosxe-routed-poe-refused.txt | netops-admin, `show power inline Ethernet0/3` |

Cisco documents `shutdown`, `no shutdown` and interface readback in the
[Catalyst 9300 IOS XE interface guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/int_hw/b_1715_int_and_hw_9300_cg/configuring_interface_characteristics.html).
The [IOS XE 17.18 configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/int_hw/b_1718_int_and_hw_9300_cg/configuring_poe.html)
and [command reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/command_reference/b_1718_9300_cr.pdf)
document `power inline auto`, `power inline never`, `power inline static max <mW>`
and `show power inline <interface>`. Physical PoE is absent from these GNS3 nodes.

The PoE example comes from Cisco's
[Catalyst 9000 PoE troubleshooting guide](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9200-series-switches/215636-troubleshooting-power-over-ethernet-poe.html).
`show-power-inline-Gi1-0-4__doc-auto-on.txt` transcribes the powered Gi1/0/4
example; the other two PoE tables are derived by substituting documented
Admin and Oper values for disabled or static power with a 15.4 W limit.
