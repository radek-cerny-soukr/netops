# Real IPsec CLI capture, lab FG-60F (G14, task netops-20261118-533)

Date 2026-11-18, about 20:36 UTC. FortiGate-60F v7.6.8 build3744 (GA.M), NAT, VDOM disabled/root, HA standalone.
Account `netops-test-ro` (read-only), one SSH exec channel per command (paramiko, strict host key), rc 0.
Permanent lab test tunnels on the 60F: `netops-g14` (IKEv2 PSK to a strongSwan 6.0.4 peer on ProxmoxLAB VM201,
selectors 203.0.113.253/32 <-> 203.0.113.252/32 after anonymisation, ICMP sent through it just before the capture) and `netops-g14-dn`
(peer address without a host, never answers). Not a qualification of other FortiOS versions, dial-up tunnels,
NAT-T peers or multi-VDOM.

Commands: 01 `get system status`, 02 `get vpn ipsec tunnel summary`, 03 `get router info routing-table all`,
04 `diagnose vpn ike errors`, 05/07 `diagnose vpn ike gateway list name netops-g14` / `netops-g14-dn`,
06/08 `diagnose vpn tunnel list name netops-g14` / `netops-g14-dn`, 09 `diagnose vpn tunnel list name netops-nope`,
10 `diagnose vpn ike gateway list name netops-nope`, 11 `get vpn ipsec tunnel details`.

DERIVED positions: the device printed live key material to the read-only account (`SK_ei/SK_er/SK_ai/SK_ar` in 05,
`key=32 <hex>` in 06, `enc:`/`auth:` hex in 11, two SAs each). At capture, before anything was written to disk, every key value
was replaced by synthetic hex of the same length and separators (sha256 of a fixed label); the capture aborted if
any original value remained. All other bytes are the device text, including the prompt framing (`FortiGate-60F $ `)
and LF line ends of the exec channel. Then all 11 files went through
`tests/support/anonymize_fixture.py --check` in one run (IPv4 to documentation ranges, serial, host name; the map is
kept outside the repository). `--check` flagged only the synthetic key hex of 05 as "residual bare" (looks like a
MAC); those are not identifiers. The anonymiser widened spaces after shortened addresses in 06/08.

Files use the suffix `.out` (as the G134 captures), so the historical output classifier baseline of the `.txt`
captures stays unchanged.

Observed: two IKE SAs and `sa=2` (two ESP SA pairs) after a restart of the peer; counters of NPU-offloaded ICMP
(`rxp=1 txp=4`) show only the packets the kernel saw; `diagnose vpn ike gateway list` prints nothing without an IKE
SA; an unknown name gives only the header line.

SHA256 01-11:
01-system-status.out 73fe299ed24e24cb9f9b78c322986d52fdf1a8f5ebb3fe6804cf179661810aa2
02-ipsec-summary.out 05207c19bdf3d1e8e65adae87c0a0f34b5bac6dbe2d0b808242e828b0397d809
03-routing-table.out d2a449c00235071272b3b357363e53b03eb4dea228d2c21727801fd58306ed9d
04-ike-errors.out 2946e1ffd9ba4f7b13d9dafa977849622ca60eeee13e667623448ce52d6ae8dc
05-ike-gateway-up.out e4875b0da44b32120bc184a031ee4312d5a8f76a990e836729f0032e6df78b23
06-tunnel-list-up.out 343b687cbae9397a159df4f30f10ba2f6cd5482728a8ca3f2f33c4f14c9114e4
07-ike-gateway-down.out 66803bd641f6fef5f207d35e3d1a0cbe531559ed367c53f840896481af0c9636
08-tunnel-list-down.out 98950a3e7d148c4fa377af497839b658a7a588de0539b16803d7d521c597f3ad
09-tunnel-list-unknown.out 0ecedc92f316ff6fe1f2df831813894a2d2de43a7cba9ff84bb75ff818e62751
10-ike-gateway-unknown.out 66803bd641f6fef5f207d35e3d1a0cbe531559ed367c53f840896481af0c9636
11-tunnel-details.out ac77baedb9951d8faea553b4a027fbacb0eb92b64f5467eadf3b0394ec08eca2
