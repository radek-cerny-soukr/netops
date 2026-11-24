# NX-OS 9.3(12) nxos health fixtures

Captured on Nexus 9300v, NX-OS 9.3(12) (Nexus 9000v, NX-OS 9.3(12)) on 2026-11-20 via pinned OpenSSH as netops-ro. File names correspond to the read query and command, except `log.txt` is `show logging last 40`. It preserves captured timestamps, severity, event IDs and any first Ethernet reference. Unstructured message content is withheld. Device serials are replaced. Site identifiers were then transformed by `tests/support/anonymize_fixture.py --check`. Empty NTP/track replies are zero-byte CLI responses with exit status zero. HSRP and both VRRP commands returned exit status 16 on the lab, including as netops-admin.

The VRRPv2 fixture uses the separate `show vrrp detail` capture. `show vrrp` is the vendor's unqualified summary. Both forms returned rc16 with netops-ro on the three NX-OS 9.3(12) lab nodes.
