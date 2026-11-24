# junos_junos_srx_security – provenance (1.0.12 junos srx security: SRX zones, address book, policies, NAT)

There is no SRX in the lab. The positive fixtures are **documentation-derived**, not captured from a device.

| File | Origin |
|---|---|
| `srx-base-set.txt` | DERIVED (documentation): set-format statements assembled from the Juniper examples below. `display set` shows logical interfaces with the unit (`ge-0/0/6.0`) and a single address as `/32`, as in the "show security zones" and "show security address-book" examples. The zone `description` line and the bare `security-zone untrust` line are the documented hierarchy forms. |
| `show-security-zones-abc.txt` | VERBATIM sample output of `show security zones abc` from https://juniper.net/documentation/en_US/junos12.1x47/topics/reference/command-summary/show-security-zones.html (same layout in the current CLI reference, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-zones.html). |
| `ex9214-show-security-zones-refused.txt` | REAL: vJunos-switch (vJunos-switch, Model ex9214, Junos 26.2R1.7), `show security zones | no-more` as `netops-admin` on 2026-11-19: `error: syntax error, expecting <command>: zones`. Same for `show security policies` and `show security nat...`; `show configuration security | display set` is empty (a private measurement record). |

Statements and outputs used for the object model (the raw pages and their extraction are in a private measurement record):

- zones and address book: https://juniper.net/documentation/en_US/junos/topics/topic-map/security-address-books-sets.html (`set security zones security-zone trust interfaces ge-0/0/0`, `set security address-book Eng-dept address-set sw-eng address a1`, `set security address-book global address g1 198.51.100.2`; `show security address-book` prints `address g1 198.51.100.2/32;`), https://juniper.net/documentation/en_US/junos/topics/topic-map/security-zone-configuration.html (`set security zones security-zone ABC host-inbound-traffic system-services all`, interface-level `host-inbound-traffic`).
- policies: https://juniper.net/documentation/en_US/junos12.1x47/topics/example/security-srx-device-zone-and-policy-configuring.html (`set security policies from-zone trust to-zone DMZ policy permit-mail-trust-DMZ match source-address PC-Trust`, `... match destination-address Server-SMTP`, `... match application junos-smtp`, `... then permit`); `show security policies` output https://juniper.net/documentation/en_US/junos12.1x46/topics/reference/command-summary/show-security-policies.html.
- source NAT: https://juniper.net/documentation/en_US/junos/topics/topic-map/nat-security-source-and-source-pool.html (`set security nat source rule-set rs1 from zone trust`, `... to zone untrust`, `... rule r1 match source-address 0.0.0.0/0`, `... rule r1 then source-nat interface`, `... then source-nat off`).
- destination NAT: https://juniper.net/documentation/en_US/junos/topics/topic-map/security-nat-destination.html (`set security nat destination pool dst-nat-pool-1 address <private address>/32`, `set security nat destination rule-set rs1 from zone untrust`, `... rule r1 match destination-address 203.0.113.200/32`, `... then destination-nat pool dst-nat-pool-1`).
- outputs of `show security nat source rule`, `show security nat destination rule|pool`: https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/ (show-security-nat-source-rule.html, show-security-nat-destination-rule.html, show-security-nat-destination-pool.html) – NOT used by the readback (see RESULT.md).

`show-security-flow-ssh.txt` adapts the Juniper CLI reference sample for
`show security flow session web-filtering` to an SSH connection terminating on
an SRX loopback. The selectors, names, and counters are test data. The sample
provides the `In`, `Out`, `If`, and total session fields.
https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session.html

## verification (public source gate of 1.0.12)

The private example networks of the Juniper pages (in `srx-base-set.txt`, `show-security-flow-ssh.txt` and the
tests) are written as documentation addresses: the five source /24s were mapped to /27 blocks of 198.51.100.0/24.
The fixture assigns four of those blocks to interfaces (ge-0/0/5 in zone DMZ 198.51.100.32/27, ge-0/0/6 in zone trust
198.51.100.64/27, ge-0/0/7.96/27, ge-0/0/8.128/27) and uses 198.51.100.0/27 for the PC-Trust address and the
source NAT match; the spare addresses are.169/.170. Their summary is 198.51.100.0/24 and the other summary of the
tests is 192.0.2.128/25. Host numbers keep their order and subnet membership.
