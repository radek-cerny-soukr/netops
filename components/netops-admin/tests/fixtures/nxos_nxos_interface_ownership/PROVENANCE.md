# NX-OS nxos interface ownership

Captured 2026-11-20 over pinned SSH on the Nexus 9000v nodes Nexus 9300v, NX-OS 9.3(12), nexus-peer-a and nexus-peer-b, all NX-OS 9.3(12). The check identity ran `show vlan id 3966`, `show interface Ethernet1/64 status`, `show interface Ethernet1/64 switchport` and `show version | include NXOS`. The write identity ran `show system vlan reserved`. The version fixture retains the NXOS version row. Outputs passed through `components/netops-helper/tests/support/anonymize_fixture.py --check`. Outer blank lines and trailing blanks were trimmed.
