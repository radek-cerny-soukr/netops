# NX-OS nxos ports captures

The file name prefixes identify the Nexus 9000v (N9K-C9300v) with NX-OS 9.3(12) that
answered: `single-` is the single node, `peer-a-` the primary and `peer-b-` the secondary
GNS3 vPC peer. The nxos ports show commands ran as `netops-ro` over pinned SSH on
2026-11-18 UTC. See the index files for commands and exit statuses; the collection and
vPC preflight record is private.

The collection script invokes `tests/support/anonymize_fixture.py` through
its `Anonymizer` API. NX-OS abbreviated MACs in LACP and vPC are converted
through the same mapping, preserving column widths. Host names, addresses,
serials and lab usernames are anonymized. Trailing whitespace and leading
and trailing blank lines are removed. nxos ports fixtures use the same `.out` convention as
router ports and have dedicated replay tests.

`dom-sfp.out` is the diagnostics excerpt for Ethernet1/5 from a
N9K-C93180YC-FX. The source reports all five readings within their limits.
The article does not identify the software version of that excerpt.
[Cisco Troubleshoot Link Flap Issue on Nexus 9000](https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221572-troubleshoot-link-flap-issue-on-nexus-90.html).

`dom-pon.out` is the Ethernet1/33 excerpt with unavailable measurements.
It comes from the NX-OS 10.6(x) Interfaces Configuration Guide. Both DOM
excerpts omit hardware identifiers and keep the device readings and units.
[Cisco NX-OS 10.6(x) basic interface parameters](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-106x/m_configuring_basic_interface_parameters_93x.html).

## Multi-lane DOM (verification)

`dom-qsfp-sr4.out` is the `show interface e2/2 transceiver details` output for
a QSFP-40G-SR4 from the Cisco DevNet guide. The guide prints the block of
`Lane Number:1 Network Lane` and marks further lanes with `...`. The fixture
writes out lanes 2 to 4 as copies of the documented lane 1 block, so it is
composed by the documented format, not a single device capture. The command
echo, the `...` elision, the part and serial number lines and the one-column
page indent were removed.
[Cisco Nexus 3000 and 9000 Series NX-API REST SDK User Guide and API Reference, Release 10.6(x) – Monitoring the Environment](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/monitoring-the-environment/).

verification adds the declared `number of lanes 4` line from the Cisco TAC
example for the same module type. The tests derive incomplete captures by
cutting this fixture between lane blocks and vary the readings of lane 3.
[Cisco TAC – Nexus DOM optical levels](https://community.cisco.com/t5/tkb-%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%B3%E3%82%BF%E3%83%BC-sr-%E3%83%89%E3%82%AD%E3%83%A5%E3%83%A1%E3%83%B3%E3%83%88/nexus-%E3%82%B7%E3%83%AA%E3%83%BC%E3%82%BA-dom-%E3%81%AE%E5%85%89%E3%83%AC%E3%83%99%E3%83%AB%E3%81%8C%E8%A1%A8%E7%A4%BA%E3%81%95%E3%82%8C%E3%81%AA%E3%81%84/ta-p/4115187).

`dom-qsfp-dr.out` is the Ethernet1/11 part (QSFP-100G-DR, one lane) of the
`show interface ethernet 1/11-12 transceiver details` example. The part
number, serial number, Cisco part number and version lines were removed.
[Cisco Nexus 3000 Series NX-OS Interfaces Configuration Guide, Release 9.3(x) – Configuring Layer 2 Interfaces](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus3000/sw/interfaces/93x/configuration/guide/b-cisco-nexus-3000-nx-os-interfaces-configuration-guide-93x/b-cisco-nexus-3000-nx-os-interfaces-configuration-guide-93x_chapter_010.html).

The NX-OS ages of `Last link flapped` over a week use the two-word form
`1week(s) 0day(s)`; shorter ages are `6d12h`, `hh:mm:ss` or `never`.
The tests write this documented value into the `single-interface` capture.
[Cisco Nexus 3500 Series NX-API CLI Reference, Release 9.2(x) – Interface Commands](https://developer.cisco.com/docs/nexus-3500-series-nx-api-cli-reference/latest/interface-commands/).

## Live vPC type-1 mismatch (verification)

The secondary Nexus 9300v returned the captured `show vpc brief` output (`peer-b-vpc-brief-mtu.out`) on 2026-11-18 UTC, read as `netops-admin`, while `mtu 9216`
was set for 25 s on port-channel128 of the primary peer and then removed again
(`no mtu`). NX-OS wraps the `Reason` column (`Compatibility check` /
`failed for MTU`). The capture has no host names, addresses or MACs; only
trailing blanks were removed. The primary peer's brief of the same moment is
identical to `peer-a-vpc-brief.out`. The two `show vpc consistency-parameters
vpc 128` tables of that moment differ from `peer-a-vpc-member.out` and
`peer-b-vpc-member.out` only in the MTU row (primary `9216`/`1500`, secondary
`1500`/`9216`) and in the anonymized lag-id; the test writes these MTU values
into the existing fixtures. The raw record is private.
# Doplňující reprodukce (subrozhraní Ethernet1/48.521)

Na Nexus 9300v s NX-OS 9.3(12) příkaz `show interface Ethernet1/48.521 counters errors`
pro dočasné administrativně vypnuté subrozhraní vrátil rc 0 bez řádků čítačů.
Test přehrává prázdné tělo odpovědi. Zachycení a návrat jsou v soukromém záznamu měření.
Testy DOM odvozují neúplné odpovědi odebráním bloků z `dom-qsfp-sr4.out`.
Test stáří změny linky nahrazuje jediný řádek v `single-interface.out`, včetně
varianty se zdvojenou mezerou. `never` byl potvrzený na Ethernet1/48.
