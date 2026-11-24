# EOS 4.36.1F captures for eos mlag admin

Captured on 2026-11-19 with SSH exec. The fixture anonymizer in
`components/netops-helper/tests/support/anonymize_fixture.py` replaced names,
descriptions, MACs and IP addresses in one pass across devices. Trailing
spaces and CR were stripped. Full running-config output was hashed in memory
and excluded from fixtures.

| Files | Lab | Commands |
| --- | --- | --- |
| empty-member, lacp-member, lacp-channel | Arista cEOS 4.36.1F | `show running-config interfaces Ethernet12`, `... Ethernet14`, `... Port-Channel104` |
| missing-channel | Arista cEOS 4.36.1F | `show interfaces Port-Channel900 \| json` (exit 1) |
| empty-macs, ethernet-status, ethernet-switchport | Arista cEOS 4.36.1F | `show mac address-table interface Ethernet12`, `show interfaces Ethernet12 status`, `show interfaces Ethernet12 switchport` |
| lldp | Arista cEOS 4.36.1F | `show lldp neighbors` |
| stp-port, stp-global | Arista cEOS 4.36.1F | `show spanning-tree interface Ethernet12 detail \| json`, `show running-config \| include ^spanning-tree` |
| a-mlag-channel | ceos-peer-a | `show running-config interfaces Port-Channel128` |
| a/b-mlag-peer, a/b-mlag, a/b-mlag-interfaces | ceos-peer-a/b | `show running-config section ^mlag.configuration`, `show mlag \| json`, `show mlag interfaces \| json` |

`lldp.json`, `ethernet.json`, `channel.json`, `disabled-mlag.json` and
`no-mlag-interfaces.json` are Arista cEOS 4.36.1F replies to `show lldp neighbors | json`,
`show interfaces Ethernet12 | json`, `show interfaces Port-Channel104 | json`,
`show mlag | json` and `show mlag interfaces | json`. Fake transport changes
only the relevant fields and statuses when simulating configuration changes.
The Rapid-PVST fixture scenario is derived from the `spanning-tree priority`
example in the [Arista EOS STP manual](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol).

`peer-switchport.txt` comes from `show interfaces Port-Channel200 switchport`
on ceos-peer-a. `vlan.json` is the `vlans` sub-object of the reply to
`show vlan id 1 | json` on ceos. The Rapid-PVST test models a spare VLAN
using that row with a new ID and the selected port membership.

For the inactive peer staging test, the fake trunk derived from
`peer-switchport.txt` restricts its allowed list to VLAN 4094.

`lab-lacp-passive.txt` and `mlag-test-channel.json` were captured during
confirmed eos mlag admin changes on Arista cEOS 4.36.1F and ceos-peer-a. The commands were
`show running-config interfaces Ethernet12` and `show mlag interfaces | json`.

`ro-running-config-denied.txt` is the SSH reply from Arista cEOS 4.36.1F as
`netops-ro` to `show running-config interfaces Ethernet12` on 2026-11-19
(exit 1). The fake substitutes the echoed command for the other denied config
queries.

R3 captures from `netops-ro` on Arista cEOS 4.36.1F, EOS 4.36.1F, on 2026-11-19.
`stp-port-inactive.json` is the reply to `show spanning-tree interface Ethernet12 detail | json`
with the test port shut down and STP settings configured. `ethernet-member-status.json`
is `show interfaces Ethernet12 status | json` with that port in Po900.
`channel-dense-passive.json` and `channel-dense-static.json` are
`show port-channel dense | json` during the passive and static member trials.
The fake derives active mode and attachment changes from these captures.

`stp-vlan-bridge.json` is the local bridge subset of `show spanning-tree vlan 1 detail | json`
on Arista cEOS 4.36.1F, with the MAC anonymized. The Rapid-PVST scenario derives the VLAN,
bridge priority and system ID extension from the [Arista EOS STP manual](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol)
and the protocol name from [Arista ANTA VerifySTPMode](https://anta.arista.com/stable/api/tests/stp/#verifystpmode).
