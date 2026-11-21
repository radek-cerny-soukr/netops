# G108 fixtures: Ruckus R610 Unleashed and the home EXOS switches it hangs off

Captured 2026-11-18 by task netops-20261118-489, read-only:

- `ruckus-*.out`: R610 on Ruckus Unleashed 200.15.6.212.27 (198.51.100.5 after anonymisation), system ssh in a PTY with the pinned
  RSA host key, privileged `enable` CLI, commands `show sysinfo`, `show ethinfo`, `show ap all`,
  `show current-active-clients all`, `ping <gateway>` (`ruckus-ping_reachable.out`) and `ping 192.0.2.1` (an unanswered address, `ruckus-ping_unanswered.out`). `\r` removed
  like the Helper `_pty_body`, trailing prompt line removed, first line is the device echo of the command.
- `sw2-*.out` / `sw3-*.out`: home X440G2 switches 198.51.100.2 / 198.51.100.3 after anonymisation (EXOS 33.7.1.6), ssh exec of `show`
  commands only (`show version`, `show switch`, `show fdb`, `show lldp neighbors detailed`, `show ports no-refresh`,
  `show vlan detail`, `show sharing`); no CLI setting changed. The R610 is the LLDP neighbour of SW2 port 3
  (Enabled Capabilities "Bridge, WLAN AP"), its MAC is learned there in VLAN LAN(0010) and on SW3 port 13 (uplink to SW2).
- All files passed through `tests/support/anonymize_fixture.py` in one run with one mapping (kept outside the
  repository): MACs -> 00:00:5e:00:53:NN (AP 00:00:5e:00:53:01), IPv4 -> RFC 5737 (the home /24 -> 198.51.100.0/24; 192.0.2.1 stayed itself),
  client host names / system names / locations -> hostNN, SSIDs -> ssidNN, AP description -> port-desc-01.
  `--check` passes. The capture file names held the real gateway address and were renamed after anonymisation.
- Extension `.out` like `ruckus_g107`: these captures are replayed by `test_g108_ruckus.py` only and stay outside the `*.txt` output-status classification oracle (`test_classification_baseline.py`).

The follow-up ping tests derive alternate counts and sequence numbers from `ruckus-ping_reachable.out`.
The iputils-style variants adapt the captured header and replies to the
[IPv4 grammar](https://github.com/iputils/iputils/blob/20221126/ping/ping.c)
and use the upstream [totals and RTT grammar](https://github.com/iputils/iputils/blob/20221126/ping/ping_common.c),
including fractional loss when one reply is removed. Both variants are derived fixtures.
The no-data AP and Ethernet cases remove rows or fields from the R610 captures.

The 525-r2 ICMP-error cases derive from `ruckus-ping_unanswered.out`: the header, router error lines and
error count follow the upstream [IPv4 error output](https://github.com/iputils/iputils/blob/20221126/ping/ping.c#L1376-L1386)
and [totals](https://github.com/iputils/iputils/blob/20221126/ping/ping_common.c#L828-L843). The endpoint is
renumbered to the address enrolled by the fake inventory. The missing rows, out-of-range sequence and
absent totals are intentional mutations for completeness checks.
