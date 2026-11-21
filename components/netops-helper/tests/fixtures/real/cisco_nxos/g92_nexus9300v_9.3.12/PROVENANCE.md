# NX-OS G92 captures

The numeric prefixes identify the SSH ports for Nexus9000 C9300v with
NX-OS 9.3(12). Port 2255 is d-nxos and ports 2261 and 2262 are the two
GNS3 vPC peers. The G92 show commands ran as `netops-ro` from PC-Radek on
2026-11-18 UTC. See the index files for commands and exit statuses and
`task-evidence/g92/` for collection and the vPC preflight.

The collection script invokes `tests/support/anonymize_fixture.py` through
its `Anonymizer` API. NX-OS abbreviated MACs in LACP and vPC are converted
through the same mapping, preserving column widths. Host names, addresses,
serials and lab usernames are anonymized. Trailing whitespace and leading
and trailing blank lines are removed. G92 fixtures use the same `.out` convention as
G53 and have dedicated replay tests.

`dom-sfp.out` is the diagnostics excerpt for Ethernet1/5 from a
N9K-C93180YC-FX. The source reports all five readings within their limits.
The article does not identify the software version of that excerpt.
[Cisco Troubleshoot Link Flap Issue on Nexus 9000](https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221572-troubleshoot-link-flap-issue-on-nexus-90.html).

`dom-pon.out` is the Ethernet1/33 excerpt with unavailable measurements.
It comes from the NX-OS 10.6(x) Interfaces Configuration Guide. Both DOM
excerpts omit hardware identifiers and keep the device readings and units.
[Cisco NX-OS 10.6(x) basic interface parameters](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-106x/m_configuring_basic_interface_parameters_93x.html).

## Multi-lane DOM (task 498-r2)

`dom-qsfp-sr4.out` is the `show interface e2/2 transceiver details` output for
a QSFP-40G-SR4 from the Cisco DevNet guide. The guide prints the block of
`Lane Number:1 Network Lane` and marks further lanes with `...`. The fixture
writes out lanes 2 to 4 as copies of the documented lane 1 block, so it is
composed by the documented format, not a single device capture. The command
echo, the `...` elision, the part and serial number lines and the one-column
page indent were removed.
[Cisco Nexus 3000 and 9000 Series NX-API REST SDK User Guide and API Reference, Release 10.6(x) – Monitoring the Environment](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/monitoring-the-environment/).

Task 498-r3 adds the declared `number of lanes 4` line from the Cisco TAC
example for the same module type. The tests derive incomplete captures by
cutting this fixture between lane blocks and vary the readings of lane 3.
[Cisco TAC – Nexus DOM optical levels](https://community.cisco.com/t5/tkb-%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%B3%E3%82%BF%E3%83%BC-sr-%E3%83%89%E3%82%AD%E3%83%A5%E3%83%A1%E3%83%B3%E3%83%88/nexus-%E3%82%B7%E3%83%AA%E3%83%BC%E3%82%BA-dom-%E3%81%AE%E5%85%89%E3%83%AC%E3%83%99%E3%83%AB%E3%81%8C%E8%A1%A8%E7%A4%BA%E3%81%95%E3%82%8C%E3%81%AA%E3%81%84/ta-p/4115187).

`dom-qsfp-dr.out` is the Ethernet1/11 part (QSFP-100G-DR, one lane) of the
`show interface ethernet 1/11-12 transceiver details` example. The part
number, serial number, Cisco part number and version lines were removed.
[Cisco Nexus 3000 Series NX-OS Interfaces Configuration Guide, Release 9.3(x) – Configuring Layer 2 Interfaces](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus3000/sw/interfaces/93x/configuration/guide/b-cisco-nexus-3000-nx-os-interfaces-configuration-guide-93x/b-cisco-nexus-3000-nx-os-interfaces-configuration-guide-93x_chapter_010.html).

The NX-OS ages of `Last link flapped` over a week use the two-word form
`1week(s) 0day(s)`; shorter ages are `6d12h`, `hh:mm:ss` or `never`.
The tests write this documented value into the `2255-interface` capture.
[Cisco Nexus 3500 Series NX-API CLI Reference, Release 9.2(x) – Interface Commands](https://developer.cisco.com/docs/nexus-3500-series-nx-api-cli-reference/latest/interface-commands/).

## Live vPC type-1 mismatch (task 498-r2)

`2262-vpc-brief-mtu.out` is `show vpc brief` of b04-nx-b (secondary,
GNS3 port 2262) on 2026-11-18 UTC, read as `netops-admin` while `mtu 9216`
was set for 25 s on port-channel128 of b04-nx-a and then removed again
(`no mtu`). NX-OS wraps the `Reason` column (`Compatibility check` /
`failed for MTU`). The capture has no host names, addresses or MACs; only
trailing blanks were removed. The b04-nx-a brief of the same moment is
identical to `2261-vpc-brief.out`. The two `show vpc consistency-parameters
vpc 128` tables of that moment differ from `2261/2262-vpc-member.out` only in
the MTU row (b04-nx-a `9216`/`1500`, b04-nx-b `1500`/`9216`) and in the
anonymized lag-id; the test writes these MTU values into the existing
fixtures. Raw record: `task-evidence/g92/r2/live/`.
# Doplňující reprodukce 521

Na d-nxos 9.3(12) příkaz `show interface Ethernet1/48.521 counters errors`
pro dočasné administrativně vypnuté subrozhraní vrátil rc 0 bez řádků čítačů.
Test přehrává prázdné tělo odpovědi. Zachycení a návrat jsou uvedené v
`task-evidence/nx-souhrn/live-subinterface.jsonl`.
Testy DOM odvozují neúplné odpovědi odebráním bloků z `dom-qsfp-sr4.out`.
Test stáří změny linky nahrazuje jediný řádek v `2255-interface.out`, včetně
varianty se zdvojenou mezerou. `never` byl potvrzený na Ethernet1/48.
