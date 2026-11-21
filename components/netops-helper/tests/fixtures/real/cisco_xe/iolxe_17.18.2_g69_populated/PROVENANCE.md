Measured 2026-11-17 ~19:15 UTC (task 473), GNS3 d-iolxe DNAT 2257, IOS XE 17.18.2,
netops-ro independent OpenSSH exec (`task-evidence/g69/capture.py`, CAPTURE_SET=populated).
The same commands were captured as netops-admin; outputs were identical apart from
timers/counters. No terminal settings changed during capture.

Populated lab scenario configured permanently in task 473 (see RESULT.md there):
VRF blue (rd 65007:69) on Ethernet0/2 with IPv4/IPv6 and a VRF static route,
eBGP IPv4 and IPv6 with d-iosv on Ethernet0/1.10 (BFD fall-over), OSPFv3
process 69, secondary IPv4 and IPv6 global/link-local addresses on
Ethernet0/1.10, PBR route-map G69-PBR on Ethernet0/1.10 with hit counters.

Anonymized on PC-Radek with `tests/support/anonymize_fixture.py --check`
(rc 0, names d-iolxe/d-iosv, BGP neighbor description replaced). IPv4 /24s
beyond the first three are mapped to single documentation addresses by the
anonymizer, therefore some BGP networks appear as e.g. `203.0.113.253/24`;
IPv6 addresses are lower-cased by the anonymizer. No output was edited by hand.
The empty/not-configured captures from task 465 remain in `iolxe_17.18.2_g69`.
