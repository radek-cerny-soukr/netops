# Fixtures of 1.0.12 G138 (Junos port bounce, PoE, link parameters)

Measured on d-vjunos (vJunos-switch 26.2R1.7, ELS, GNS3 lab, task netops-20261119-559, 2026-11-19, test port ge-0/0/9,
no LLDP neighbour and no MAC address); raw transcripts in `task-evidence/g138/znalost` and `live`. Anonymised while
copying (host01, documentation addresses, MAC 00:00:5e:00:53:0a):

- `show-interfaces-terse__lab.txt`, `show-interfaces-ge-0-0-9-terse__up.txt`, `show-interfaces-ge-0-0-9-terse__admin-down.txt`
  (after `set interfaces ge-0/0/9 disable` + `commit confirmed`: Admin down), `show-interfaces-ge-0-0-9__up-mtu-1514.txt`,
  `show-interfaces-ge-0-0-9-match-mtu__9000.txt` (after `set interfaces ge-0/0/9 mtu 9000`: `MTU: 9000`),
  `show-lldp-neighbors__lab.txt`, `show-system-commit__bounce-revert.txt` (the bounce: commit confirmed 3 and the plain
  revert commit).
- `show-poe-interface-ge-0-0-9__vjunos-no-controller.txt`: the real answer of vJunos (no PoE controller): only the warning.

NOT measured (vJunos has no PoE, no physical ports); layout from the Juniper documentation "show poe interface" (EX
Series, Junos 12.2; https://www.juniper.net/documentation/en_US/junos12.2/topics/reference/command-summary/show-poe-interface.html,
sample ge-0/0/3):
- `show-poe-interface-ge-0-0-3__ex-doc-on.txt`: the sample as documented (Administrative status Enabled, Operational
  status ON). DOCUMENTATION.
- `show-poe-interface-ge-0-0-3__derived-off.txt` (Operational status OFF) and `__derived-disabled.txt` (Disabled /
  Disabled): DERIVED from the documented value lists (Administrative: Enabled|Disabled, Operational: ON|OFF|Disabled).

Configuration syntax (`set poe interface <if> disable`, `set interfaces <if> speed 10m|100m|1g|10g|auto`,
`ether-options [no-]auto-negotiation`, `mtu 256..9192`) was read by `?` on the lab device (znalost/s3-help.txt) and
accepted into a discarded private candidate (znalost/s5-private.txt).

## Task netops-20261121-749 (public source gate of 1.0.12)

`show-interfaces-terse__lab.txt`: the internal em1/jsrv addresses of vJunos are written as documentation addresses
with their prefix lengths, exactly as in the Helper fixture of the same switch
(`netops-helper/tests/fixtures/real/juniper_junos_els/vjunosswitch_26.2R1.7/interfaces.txt`).
`show-lldp-neighbors__lab.txt`: the container MAC of d-ceos is the documentation MAC 00:00:5e:00:53:b4.
