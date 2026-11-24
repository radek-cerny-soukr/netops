# Real IPsec CLI capture, lab FG-60F (ipsec status, verification)

Date 2026-11-18, about 20:36 UTC. FortiGate-60F v7.6.8 build3744 (GA.M), NAT, VDOM disabled/root, HA standalone.
Account `fixture-reader` (read-only), one SSH exec channel per command (paramiko, strict host key), rc 0.
Permanent lab test tunnels on the 60F: `netops-ipsec status` (IKEv2 PSK to a strongSwan 6.0.4 peer  test jump host,
selectors 203.0.113.253/32 <-> 203.0.113.252/32 after anonymisation, ICMP sent through it just before the capture) and `netops-ipsec status-dn`
(peer address without a host, never answers). Not a qualification of other FortiOS versions, dial-up tunnels,
NAT-T peers or multi-VDOM.

Commands: 01 `get system status`, 02 `get vpn ipsec tunnel summary`, 03 `get router info routing-table all`,
04 `diagnose vpn ike errors`, 05/07 `diagnose vpn ike gateway list name netops-ipsec status` / `netops-ipsec status-dn`,
06/08 `diagnose vpn tunnel list name netops-ipsec status` / `netops-ipsec status-dn`, 09 `diagnose vpn tunnel list name netops-nope`,
10 `diagnose vpn ike gateway list name netops-nope`, 11 `get vpn ipsec tunnel details`.

DERIVED positions: the device printed live key material to the read-only account (`SK_ei/SK_er/SK_ai/SK_ar` in 05,
`key=32 <hex>` in 06, `enc:`/`auth:` hex in 11, two SAs each). At capture, before anything was written to disk, every key value
was replaced by synthetic hex of the same length and separators (sha256 of a fixed label); the capture aborted if
any original value remained. All other bytes are the device text, including the prompt framing (`FortiGate-60F $ `)
and LF line ends of the exec channel. Then all 11 files went through
`tests/support/anonymize_fixture.py --check` in one run (IPv4 to documentation ranges, serial, host name; the map is
kept outside the repository). `--check` flagged only the synthetic key hex of 05 as "residual bare" (looks like a
MAC); those are not identifiers. The anonymiser widened spaces after shortened addresses in 06/08.

Files use the suffix `.out` (as the junos health captures), so the historical output classifier baseline of the `.txt`
captures stays unchanged.

Observed: two IKE SAs and `sa=2` (two ESP SA pairs) after a restart of the peer; counters of NPU-offloaded ICMP
(`rxp=1 txp=4`) show only the packets the kernel saw; `diagnose vpn ike gateway list` prints nothing without an IKE
SA; an unknown name gives only the header line.

SHA256 01-11:
01-system-status.out 73fe299ed24e24cb9f9b78c322986d52fdf1a8f5ebb3fe6804cf179661810aa2
02-ipsec-summary.out 7f921038d6d509d6508a98a3023225fb654d9a6ee2dbca50c0e9f66a499d9cc9
03-routing-table.out 8c664ce734bf7ada130763f2d4e94bacbdca9b9549b0d5d06a370ffe8c220f56
04-ike-errors.out 2946e1ffd9ba4f7b13d9dafa977849622ca60eeee13e667623448ce52d6ae8dc
05-ike-gateway-up.out f7b893fc82aff9e00485bd7949cefc1f239523762048dd17b64dde8fd92750ef
06-tunnel-list-up.out 11641c74510cb3d63661274b03c9a075a117b557f11fecd6b507520f22bca3f4
07-ike-gateway-down.out 66803bd641f6fef5f207d35e3d1a0cbe531559ed367c53f840896481af0c9636
08-tunnel-list-down.out 1045ed645051d42d81f3f83914ab83966217cea42720f21caa189c005c6d297b
09-tunnel-list-unknown.out 0ecedc92f316ff6fe1f2df831813894a2d2de43a7cba9ff84bb75ff818e62751
10-ike-gateway-unknown.out 66803bd641f6fef5f207d35e3d1a0cbe531559ed367c53f840896481af0c9636
11-tunnel-details.out 200c3fca6204180c642fe548cfa787c601e4e1e4047f5a2c4bb563cd147a3344
