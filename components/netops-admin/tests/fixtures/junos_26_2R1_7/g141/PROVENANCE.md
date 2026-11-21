The JSON and set-format files in this directory were captured on d-vjunos
(vJunos-switch ex9214, Junos 26.2R1.7) on 2026-11-19 from PC-Radek. See
[the fixture capture commands and restoration hash](../../../../../../task-evidence/g141/probe-irb.log).
The control account ran the operational commands. The administrator account ran
only scoped configuration reads for the saved fixtures. The lab probe used
irb.3920, which had no Layer 2 link. The OSPFv2 response was empty even with the
interface configured. The OSPFv3 response displayed the configured passive
interface, area and metric. Captures were anonymized with
`components/netops-helper/tests/support/anonymize_fixture.py --check` on PC-Radek.

`bgp-neighbor-vendor.txt` is an adapted excerpt of the Juniper CLI Reference
example for an established neighbor with import policy. Addresses, ASNs, type
and names are replaced and irrelevant fields are omitted.
[show bgp neighbor](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-neighbor.html)

`management-route.json` came from the administrator's targeted
`show route <management peer> active-path | display json` on the same device,
with the management subnet redacted by the same anonymizer.

`bgp-group-vendor.txt` is an adapted excerpt of the documented group display,
with the name, type, counts and ASNs substituted. Unit replay of the neighbor
for the group import and neighbor override tests varies the configured policies
and uses Active state. [show bgp group](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-bgp-group.html)

## Task netops-20261121-749 (public source gate of 1.0.12)

The dotted test area is written as `0.0.0.7` and the test /32 prefixes as 203.0.113.x/32 (same host numbers)
in these captures and in `test_junos_g141.py`; the earlier values were refused by the public source gate.
