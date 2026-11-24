# fixtures/fortios_a3 – FortiOS 7.6.8 (FortiGate-60F, build3744), 2026-11-23

Real output of the read-only check account of the lab FortiGate-60F, one held SSH session per read. No output holds
`ENC` or an excluded attribute; no secret is part of these tables.

| File | Command | Notes |
|---|---|---|
| `show-firewall-address6.txt` | `show firewall address6` | before the live run; uuid values replaced |
| `show-full-configuration-firewall-address6-all.txt` | `show full-configuration firewall address6 all` | defaults: `type ipprefix`, `ip6 ::/0`, `color 0`, `fabric-object disable` |
| `show-firewall-addrgrp6.txt` | `show firewall addrgrp6` | empty table: show prints the empty wrapper |
| `show-router-static6.txt`, `show-full-configuration-router-static6.txt` | `show [full-configuration] router static6` | the IPv6 default route (show omits `dst ::/0`) through `wan1`; gateway anonymised, comment replaced (derived) |
| `show-system-interface-wan1-ipv6-excerpt.txt` | `show system interface` | **derived**: only the `wan1` lines vdom/mode/type and its `config ipv6` section kept; address anonymised |
| `show-firewall-policy-7-excerpt.txt` | `show firewall policy` | **derived**: only policy 7 (srcaddr6/dstaddr6 `all`); uuid and comment replaced |
| `show-firewall-address6-created.txt`, `show-full-configuration-firewall-address6-created.txt` | `show [full-configuration] firewall address6 "netops-a3-net"` | after the Admin create of 2001:db8:a3::/64 (live run); uuid replaced |
| `show-firewall-address6-iprange.txt`, `show-full-configuration-firewall-address6-iprange.txt` | same for `netops-a3-net2` | iprange: `set type iprange` is shown, no `ip6` |
| `show-firewall-addrgrp6-created.txt`, `show-full-configuration-firewall-addrgrp6-created.txt` | `show [full-configuration] firewall addrgrp6 "netops-a3-grp"` | full configuration: `exclude disable` (profile `fixed`) |
| `show-firewall-policy-ipv6-disabled.txt` | `show firewall policy 230363` | disabled IPv6 policy created by Admin (existing profile) with the A3 objects; uuid replaced |
| `show-router-static6-blackhole.txt`, `show-full-configuration-router-static6-blackhole.txt` | `show [full-configuration] router static6 63` | blackhole route created disabled by Admin: FortiOS prints `set vrf 0` also in the short show (profile `fixed`), no `device`/`gateway` |

Addresses: the lab uses documentation prefixes 2001:db8:a3::/48 for its test objects; the provider prefix of `wan1`
and its gateway were mapped to 2001:db8:1::/64 by `components/netops-helper/tests/support/anonymize_fixture.py
--check` (residual check clean). The anonymiser mapping stays outside the repository.

## A3 follow-up captures, 2026-11-23

Live run on the same FortiGate-60F 7.6.8 build3744 (check account, held sessions).

| File | Command | Notes |
|---|---|---|
| `next-firewall-address6-default-prefix-dialog.txt` | `next` of `edit "netops-a3r2-any"` with only a comment (write account) | FortiOS asks for a confirmation of an entry at ::/0; the same answer without a prompt was read for `set ip6 ::/0` (probe) |
| `show-firewall-address6-default-prefix.txt`, `show-full-configuration-firewall-address6-default-prefix.txt` | `show [full-configuration] firewall address6 "netops-a3r2-any"` | saved at ::/0 with a comment after the confirmation (outside Admin): show prints uuid and comment only, the full configuration `type ipprefix` and `ip6 ::/0`; uuid replaced |
| `show-firewall-local-in-policy6.txt`, `show-full-configuration-firewall-local-in-policy6.txt` | `show [full-configuration] firewall local-in-policy6 63` | temporary disabled accept rule naming the address group `netops-a3r2-outer` in srcaddr (written outside Admin, removed after the run); interface name mapped by `anonymize_fixture.py --name` (lab name → `host01`), uuid replaced |
