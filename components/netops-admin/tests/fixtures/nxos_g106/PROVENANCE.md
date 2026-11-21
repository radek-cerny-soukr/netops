# NX-OS G106

Captured 2026-11-20 over pinned SSH on the Nexus 9000v nodes d-nxos, b04-nx-a and b04-nx-b, all NX-OS 9.3(12). The check identity ran `show vlan id 3966`, `show interface Ethernet1/64 status`, `show interface Ethernet1/64 switchport` and `show version | include NXOS`. The write identity ran `show system vlan reserved`. The version fixture retains the NXOS version row. Outputs passed through `components/netops-helper/tests/support/anonymize_fixture.py --check`. Outer blank lines and trailing blanks were trimmed.
