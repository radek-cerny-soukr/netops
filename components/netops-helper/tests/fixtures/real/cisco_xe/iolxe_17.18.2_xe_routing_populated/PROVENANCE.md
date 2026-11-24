Measured 2026-11-17 ~19:15 UTC (verification), GNS3 Cisco IOL XE 17.18.2, IOS XE 17.18.2,
netops-ro independent OpenSSH exec (a private measurement record, CAPTURE_SET=populated).
The same commands were captured as netops-admin; outputs were identical apart from
timers/counters. No terminal settings changed during capture.

Populated lab scenario configured permanently in verification (see RESULT.md there):
VRF blue (rd 65007:69) on Ethernet0/2 with IPv4/IPv6 and a VRF static route,
eBGP IPv4 and IPv6 with Cisco IOSv 15.9(3)M12 on Ethernet0/1.10 (BFD fall-over), OSPFv3
process 69, secondary IPv4 and IPv6 global/link-local addresses on
Ethernet0/1.10, PBR route-map xe routing-PBR on Ethernet0/1.10 with hit counters.

Anonymized  with `tests/support/anonymize_fixture.py --check`
(rc 0, names Cisco IOL XE 17.18.2/Cisco IOSv 15.9(3)M12, BGP neighbor description replaced). IPv4 /24s
beyond the first three are mapped to single documentation addresses by the
anonymizer, therefore some BGP networks appear as e.g. `203.0.113.253/24`;
IPv6 addresses are lower-cased by the anonymizer. No output was edited by hand.
The empty/not-configured captures from verification remain in `iolxe_17.18.2_xe_routing`.
