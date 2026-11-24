# router probes capture provenance

Captured 2026-11-17 from GNS3 Cisco IOSv 15.9(3)M12, IOSv 15.9(3)M12 fc1.
Independent OpenSSH interactive shell; admin files from netops-admin, ro/ from netops-ro.
No terminal settings changed. Device configuration was changed only by the follow-up measurement described below. The command transcripts are private.
Anonymized  with tests/support/anonymize_fixture.py --name Cisco IOSv 15.9(3)M12; addresses map to RFC 5737 space, Loopback0 kept.
IPv6/VRF positive captures (verification, 2026-11-17 ~19:10 UTC): the lab was then permanently given
`vrf definition blue` (IPv4+IPv6 AF) on Loopback52 and `ipv6 unicast-routing` with a global IPv6 address on
Loopback53 (private measurement record). ping_vrf*, ping_ipv6*, traceroute_vrf* are real replies from those
loopbacks; *_loss / traceroute_vrf*_timeout target an unused address in the same prefix (5/5 lost, 5-hop limit).
Commands: private measurement record (not published). VRF interface addresses map to 192.0.2.0/24
(Loopback52 -> 192.0.2.1), the IPv6 prefix to 2001:db8:1::/64; loopback names and VRF name kept.
unconfigured/ holds the earlier real refusals (464) from the lab without any VRF/IPv6.
ro/ping_vrf*, ro/ping_ipv6*, ro/traceroute_vrf* were re-captured against the configured VRF/IPv6 (still refused to privilege 1).
Long rejected command echoes may contain the IOS caret/scroll artifacts, intentionally retained.
ping_loss is a real five-packet loss; traceroute_timeout reaches the fixed five-hop limit.
Unit tests additionally derive pager/header-only/authorization failures, explicitly labelled in test code.

Captures use.out as router routing does. They are outside the frozen historical.txt corpus (output_status_baseline.json, oracle 1fad86c); the router probes public-path tests exercise these new captures explicitly.
