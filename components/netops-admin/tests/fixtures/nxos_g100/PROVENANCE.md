# G100 fixtures

Cisco Nexus 9000v (N9K-C9300v), NX-OS 9.3(12), d-nxos and B04 lab, 2026-11-19. Independent SSH exec captures on PC-Radek with pinned host keys. Capture and write procedure in `task-evidence/g100/live.py`.

- `occupied-mac`, `occupied-status`: `show mac address-table interface Ethernet1/2` and `show interface Ethernet1/2 status`, read-only. Unit tests substitute the target interface number to apply the existing fake transport's operations to its test port.
- The access VLAN undo regression derives the connected VLAN 10 status by substituting the VLAN column in `occupied-status`. It uses the empty `port-mac` capture for the interval before MAC relearning and derives the negative CDP case by substituting the local interface in `cdp`.
- `port-mac`, `port-switchport`: targeted CLI for Ethernet1/48 at baseline. The VLAN MAC table uses the same NX-OS table layout.
- `cdp`, `reserved`: `show cdp neighbors` and `show system vlan reserved`.
- `vlan-absent`, `vlan-created`, `vlan-created-config`: `show vlan id 3900` before and after confirmed Admin create and `show running-config vlan` after create. The fake VLAN database derives its default-name row by substituting only the name field.
- Incomplete answers in tests truncate their corresponding capture.

Fixtures were processed with `components/netops-helper/tests/support/anonymize_fixture.py --check`. No complete running configuration was captured into a fixture.

`b04-nx-a__uplink-switchport` and `b04-nx-b__uplink-switchport` are read-only captures of
`show interface Ethernet1/1 switchport` on the peer pair. The fake transport derives
the test-port response by substituting its port number and the selected VLAN fields.
The default-trunk regression reports `1-4094` when the fake running configuration contains no allowed-VLAN line.
