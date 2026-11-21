# exos_g45 fixtures (1.0.12 G45: X12 static route, X13 VLAN IP and forwarding, X39 VRRP)

Real answers of EXOS-VM 33.6.1.14 (GNS3 netops-d-lab, node d-exos), measured 2026-11-17 (task
netops-20261117-479, evidence task-evidence/g45/live/02-mereni-m1.md) on the test VLAN g45m tag 3945 only.

* `exosvm__config-<state>.out`: the modules vlan, rtmgr and vrrp of `show configuration` (account netops-admin),
  verbatim, after the measurement step named by the state (base = before the measurement; vlan = create vlan g45m
  tag 3945 + description; ipv4; ipv4-fwd; ipv6; l3 = IPv4 + IPv4 forwarding + IPv6 + IPv6 forwarding; ipv6-two;
  ipv4-removed; ipv6-removed; linklocal; routes; routes-two-gw; vrrp-created; vrrp; vrrp-vip2;
  routes-vlan-deleted).
* `exosvm__<command>__<state>.out`: answers of the check account netops-ro.

Anonymised with tests/support/anonymize_fixture.py (task-evidence/g45/tools/anon.sh): the management network
-> 192.0.2.0/24, MAC and link-local addresses replaced; the test networks 198.51.100.0/24, 203.0.113.0/24 and
2001:db8:45..::/64 are documentation addresses chosen for the test and kept; the constant `eui64 fe80::/64` and
`fe80::%g45m/64` forms are kept. The anonymiser pads replaced addresses to keep table columns; in the two
configuration lines with the management address the padding is collapsed to one space as the switch prints it.

Task netops-20261121-749 (public source gate of 1.0.12) re-mapped the addresses that the first anonymisation had
kept: the lab-private networks of the other lab VLANs and the client network of the tests are now documentation
addresses in 192.0.2.128/25 (D10 192.0.2.128/27 with .132, D20 192.0.2.160/27 with .164, B04-ISC 192.0.2.192/30,
B04-KA 192.0.2.196/30, the session client network of the tests 192.0.2.224/27 with the client 192.0.2.241), and the
management VLAN Mgmt is narrowed to 192.0.2.0/25 to make room (192.0.2.54 255.255.255.128). The same map was applied
to every file of this directory and to `test_exos_g45.py`; the IPv4 rows and the `Mask distribution` lines of the
`show iproute` answers follow the new prefix lengths. The mapping to the real values is not kept in the repository.

## Task netops-20261117-479-r2 (measurement M2, 2026-11-18, task-evidence/g45/r2/live/m2/README.md)

Same device, accounts and anonymisation (management network -> 192.0.2.0/24, since task 749 192.0.2.0/25, the
MAC-derived link-local address -> fe80::10), test VLAN g45m/g45r tag 3945 only, extracted by ~/g45tools/extract2.py (outside the repository):
`exosvm__config-default6.out` (VLAN g45m with 2001:db8:4545::1/64 and the IPv6 default route via 2001:db8:4545::fe),
`exosvm__show-iproute-ipv6-vr-VR-Default__default6.out` (its `Default route` row),
`exosvm__config-ipv6-two-renamed.out` and `exosvm__show-vlan-g45r__ipv6-two-renamed.out` (two IPv6 addresses after
`configure vlan g45m name g45r`), `exosvm__config-vrrp-novip-priority.out`,
`exosvm__show-vrrp-vlan-g45m__vrrp-novip-priority.out` and `exosvm__show-vrrp__vrrp-novip-priority.out` (VRRP g45m:45
without a virtual address, priority 200), `exosvm__show-iproute-ipv6-vr-VR-Mgmt__base.out` (VR-Mgmt without IPv6
routes, before M2). The M2 configuration files keep the blank lines the switch prints before the module headers.
