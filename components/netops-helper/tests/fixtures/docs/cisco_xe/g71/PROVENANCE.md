# G71 Cisco Catalyst IOS XE examples

CLI examples from Cisco documentation, with command echo and page formatting
removed. Some examples are excerpts. Unit tests explicitly label variants that
change counters or remove lines.

- `transceiver.out` — Catalyst 9300 IOS XE 17.13, `show interfaces gigabitethernet1/1/1 transceiver detail`.
  [Interface and Hardware Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-13/command_reference/b_1713_9300_cr/interface_and_hardware_commands.html)
- `poe.out` — Catalyst 9300 IOS XE 17.14, `show power inline Te3/0/1 detail`.
  [Configuring Power over Ethernet](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/configuration_guide/int_hw/b_1714_int_and_hw_9300_cg/configuring_poe.html)
- `lacp.out` — Catalyst 9300 IOS XE 17.9, `show lacp 1 internal`. The
  unscoped form uses the same table for each channel group.
  [Layer 2/3 Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/command_reference/b_179_9300_cr/layer_2_3_commands.html)
- `negotiated_speed.out` — IOS XE Cisco Embedded Service 9300, optical-port
  `show interfaces tenGigabitEthernet 1/1` example. MAC anonymized.
  [Cisco Embedded Service 9300 Series Switches Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/embedded/ess9300/config/b-cisco-embedded-service-9300-series-switches-configuration-guide.pdf)
- `etherchannel_group.out` — Catalyst 9300 IOS XE 17.6, excerpt of
  `show etherchannel 1 detail`. Cisco shows one member detail block and reports
  two members, so coverage of the detail blocks is incomplete in the example.
  [Layer 2/3 Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/command_reference/b_176_9300_cr/layer_2_3_commands.html)
