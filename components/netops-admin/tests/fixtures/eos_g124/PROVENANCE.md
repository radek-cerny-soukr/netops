# EOS G124 fixtures

Direct SSH exec reads of d-ceos on GNS3 DNAT 2253, cEOSLab 4.36.1F. The
timed fixture session used the reserved Ethernet12 and temporary g124
objects. See `task-evidence/g124/fixture-probe.log` for command return codes
and matching running-config digests. The snapshots of individual interfaces
are outputs of `show running-config interfaces <name>`. The empty
`missing-svi.txt` is the successful privileged configuration read for an
absent SVI. The separate operational answer is a refusal with status 1.

`configured-global.txt` comes from the running-config include filter for IP
routing, static routes and the VARP MAC. `routes-v4.txt` and
`routes-v6.txt` are the operational FIB replies for the same VRF. They
contain no installed routes while the next hops are unresolved. `vrf.txt`
is the operational VRF response. `varp.txt` and `empty-varp.txt` are the
operational VARP responses. `vrrp-ro-refused.txt` records the actual denial
for `show vrrp | json` from privilege 1.

Outputs were processed with
`components/netops-helper/tests/support/anonymize_fixture.py --check`.
The task's documentation addresses listed explicitly as `--keep` are the
addresses configured on the temporary lab objects.

`vrf-routing-preview.txt` is a pair of actual EOS session diffs for the same
named VRF with forwarding enabled and disabled. EOS keeps the explicit
`no ip routing vrf` line after disabling IPv4 and drops the IPv6 line.
The staged session was aborted.

`varp-vlan-cpu-mac.txt` comes from `show mac address-table vlan 3985` after
configuring the global VARP MAC in the live run. EOS added a STATIC CPU entry
for the MAC before the SVI had a virtual IP. The test that replaces Cpu with
Et1 documents a derived negative case for both apply and undo. The undo
tests derive two incomplete replies from this fixture by removing either
the unicast row or its total line. Fake transport errors cover an unavailable
read and a timeout.

`svi-utf8-description.txt` is derived from `routed-svi.txt` with a Czech
description and with `no autostate` and VRRP removed so the SVI contains
only settings managed by the L3 profile. UTF-8 descriptions are measured
in the G122 cEOS fixtures. The VRRP undo test uses the G122 measured dynamic
MAC output from `show-mac-address-table-vlan-10__learned.txt`, retargeted
to VLAN 3984 by `FakeEos`.
