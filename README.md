# NetOps

NetOps is a self-hosted MCP server for network diagnostics, audits and changes on enrolled devices. Clients use **MCP Streamable HTTP over HTTPS only**, with a bearer token and TLS verification.

This README describes NetOps 1.0.13, the source version prepared for release.

## What's new in 1.0.13

This version updates runtime dependencies, adds the `network_overview` Helper tool, Auditor rules for Cisco IOS/IOS XE, NX-OS, Arista EOS and Juniper Junos, FortiOS Admin tables for DHCP servers and ranges, DNS, syslog, service groups, schedules, IPv6 addresses and address groups and IPv6 static routes, and a configurable memory limit; every Admin apply requires the approved preview hash, and Admin profiles require live evidence. Admin returns `profile_not_measured` on every firmware for the PoE cycle on FortiOS, IOS, IOS XE, EOS and Junos, persistent PoE on IOS, IOS XE and Junos, MLAG peer settings on EOS and ExtremeXOS, the ExtremeXOS global jumbo frame size and NTP process state, and the Junos SRX profiles for address books, destination NAT pools and rules, source NAT rules, security policies and zones. [Disabled Admin profiles](docs/admin-configuration.md#live-verification-required-for-admin-profiles) · [Release notes](release/notes-1.0.13.md) · [Changelog](CHANGELOG.md)

## Roles

- **Helper** diagnoses enrolled devices with fixed queries, normalized tables and endpoint location. [Helper configuration](docs/helper-configuration.md#helper-capability-overview)
- **Admin** previews and applies bounded changes with independent readback and safeguards. [Admin configuration](docs/admin-configuration.md)
- **Auditor** evaluates configurations and serves stored findings with per-rule coverage: FortiOS, FortiADC and ExtremeXOS; from 1.0.13 also Cisco IOS/IOS XE, NX-OS, Arista EOS and Juniper Junos. [Auditor workflows](docs/quickstart-1.0.md#auditor-operator-workflows)
- **Core** provides shared inventory, private vaults and pinned SSH/SFTP. [Architecture](docs/architecture-1.0.md#core-inventory-and-transport)

`netops selftest` lists **32 Helper, 8 Auditor and 10 Admin tools**. Requests are audited before dispatch. [Security model](docs/architecture-1.0.md#security-model)

## Minimum requirements

64-bit Linux, Docker Engine with Compose, **2 vCPU, 2 GiB RAM and 2 GiB free disk**. Allow space for backups and audit. [Resource and network requirements](docs/quickstart-1.0.md#resource-limits)

## Supported platforms

| Host | Architecture |
|---|---|
| Ubuntu 24.04.5 / 26.04.1 LTS | amd64 |
| Debian 13 | amd64, arm64 |
| Fedora 44 with SELinux enforcing | amd64, arm64 |
| Raspberry Pi OS 64-bit | arm64 |

[Verified platform support](docs/verified-support.md) covers Docker modes, hardware and SELinux setup.

## Quick start

1. Download [compose.yaml](https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.13/compose.yaml) and the other files listed in the quickstart. Verify the signature with `netops-1.0.13-SHA256SUMS.sigstore.json` and check the files against netops-1.0.13-SHA256SUMS before installing.
2. Keep the release image digest, configure the bind address and DNS name, then initialize and start with Compose.
3. Export the instance CA and bearer token, connect a client and enroll devices.

[Step-by-step quickstart](docs/quickstart-1.0.md)

#### Tested MCP clients

**NetOps 1.0.13:** client acceptance with Codex CLI and Claude Code is pending. It runs on the release candidate image before the maintainer signs the release checksum list. The results will be published in the [release notes](release/notes-1.0.13.md#acceptance).
Codex CLI 0.171.0 and Claude Code 2.1.330 passed the client acceptance of the NetOps 1.0.12 image on Linux (Debian 13 VM); the result is recorded in the [release notes](release/notes-1.0.12.md#acceptance).

## Releases and upgrades

Restore a backup of a 1.0.12 instance into a clean 1.0.13 installation. For the upgrade from 1.0.12 to 1.0.13, re-enroll every Admin device (`admin enroll`) before making changes with Admin. The updated Admin profiles invalidate the binding of the restored enrollment. [Upgrade and rollback](docs/quickstart-1.0.md#upgrade-from-the-previous-release)

## Verification and release

**Acceptance of 1.0.13:** [release notes](release/notes-1.0.13.md) and [signature and qualification](docs/testing-1.0.md#release-verification-and-acceptance).

## Documentation

[Documentation index](docs/README.md) · [Release history](docs/release-history.md) · [Security policy](SECURITY.md)

## Known limitations

[Operational limits](docs/compatibility-boundaries.md#known-limitations)

## Supported releases and distribution

Only NetOps 1.0.x is supported. NetOps is distributed exclusively through GitHub: the source repository, GitHub Releases, and container images in GitHub Container Registry (GHCR). It is not distributed through PyPI.

## License

[MIT license](LICENSE) · Radek Černý

## Disclaimer

[Warranty, support and vendor independence](docs/compatibility-boundaries.md#disclaimer)

## Supported devices and firmware

| Platform | Documented builds |
|---|---|
| FortiOS | FortiGate 60F: 7.6.8 build3744. FortiGate 80F: 8.0.2 build0251 |
| FortiSwitch | 108E series and 224E-POE, managed through FortiLink |
| FortiADC | FortiADC-KVM 7.6.7 build0676 |
| ExtremeXOS | EXOS-VM 33.6.1.14, X435/X440-G2 33.7.1.6-patch1-11 |
| Cisco IOS / IOS XE | IOSv 15.9(3)M12, IOSvL2 15.2(20200924), IOL XE and IOL-L2 XE 17.18.2 |
| Cisco NX-OS | Nexus 9000v 9.3(12) |
| Arista EOS | cEOSLab 4.36.1F |
| Juniper Junos | vJunos-switch 26.2R1.7 |
| Ruckus Unleashed | R610 200.15.6.212.27 |
| Linux | Ubuntu 24.04.5, Debian 13.7, Proxmox VE on Debian 13.7 |

Live verification of NetOps 1.0.13 on 2026-11-23: development builds measured the new Admin tables on FortiOS 7.6.8 build3744 (FortiGate 60F). [Measured operations and limits](docs/verified-support.md#admin-profiles-awaiting-live-verification-in-netops-1013)

Live verification of NetOps 1.0.12 on 2026-11-21: selected development-build checks included FortiOS 7.6.8 build3744 and FortiOS 8.0.2 build0251, and standalone FortiADC 7.6.7 build0676. [Exact scope and firmware limits](docs/verified-support.md#live-verification-of-netops-1012)

### Coverage by vendor and operating system

**✓** the command's output was captured live from that OS with a read-only account, and the tests parse that output · **docs** the output layout comes from the vendor documentation only, because the measured device had nothing to show (feature not configured, empty table, or command missing on the virtual image) · **–** not provided. Unless a cell or its lettered note names a later date, live captures used development builds of the 1.0.7 source on 2026-11-08 and 2026-11-09, and the Linux row comes from the 1.0.8 checks described below the table; virtual images do not establish hardware behavior (PoE, optics, stacking, forwarding), and no hardware Cisco, Arista or Juniper device was tested. A check mark records a dated capture or live acceptance result, not the current lab configuration; the endpoint column has the narrower scope in note ⁵. **replay** means offline replay of live captures; **transit** means a transit hop in a completed live endpoint search; **ARP** means captured IPv4 router/firewall input, without an end-to-end endpoint result. Measurement quality limits are in note ⁷.

Normalized tables (`switch_read`) and endpoint location:

| OS (profile) | Verified live on | Interfaces | VLAN | Port VLAN | MAC | ARP | LLDP | Routes | OSPF | BGP | LAG | STP | Errors / flaps | IP interfaces | `locate_endpoint` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ExtremeXOS (`extreme_exos`) | X435-8P-4S and three X440G2-12p-10G4 with 33.7.1.6-patch1-11; EXOS-VM 33.6.1.14 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | –ᶜ | –ᶜ | ✓ `aggregate`, `lag`⁴⁶ | ✓ domain `s0`ᶜ | ✓ CRC/TX | ✓ | live located: 13 physical end hosts on X440G2 by MAC; 11 also by IP (24/24 executed searches matched CLI; two IP searches not run because no ARP mapping was available) and an end host on EXOS-VM port 2, VLAN 10, 2026-11-11⁵ |
| Cisco IOS (`cisco_ios`) | IOSv 15.9(3)M12 (router), IOSvL2 15.2(20200924) (switch) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | live MCP fallback: show interfaces (2026-11-11) | ✓ | live located: end host on IOSvL2 Gi0/3, VLAN 10 untagged, 2026-11-11⁵ |
| Cisco IOS XE (`cisco_xe`) | IOL XE 17.18.2 (router image) | ✓⁹ router | docs | docs⁸ | replay, scoped by MAC, port or VLANᵇ | ✓ | ✓ | ✓ | ✓ | ✓¹ | docs⁶ | replay, IOL-L2 XEᵇ | live MCP fallback: show interfaces (2026-11-11) | ✓ | ARP in completed live search, 2026-11-10⁵ |
| Cisco NX-OS (`cisco_nxos`) | Nexus 9300v, NX-OS 9.3(12) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓² | ✓ | ✓ | ✓¹ | ✓⁶ | ✓ | prior canonical replay; new capture refused | ✓ | live located, 2026-11-11⁵ |
| Arista EOS (`arista_eos`) | cEOS 4.36.1F | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | ✓ errors; discards prior replay | ✓ | live transit, 2026-11-11⁵ |
| Junos ELS, EX/QFX (`juniper_junos_els`) | vJunos-switch 26.2R1.7 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | docs⁶ | ✓⁶ | ✓ extensive | ✓ | live located: end host on ge-0/0/1, VLAN 20 untagged, 2026-11-11⁵ |
| Junos, other platforms (`juniper_junos`) | the same commands on vJunos-switch 26.2R1.7³ | ✓³ | –ᵈ | –ᵈ | –ᵈ | ✓³ | ✓³ | ✓³ | ✓³ | docs | docs⁶ | –ᵈ | replay on ELS switch | ✓³ | ARP³⁵ |
| FortiOS (`fortinet`) | FortiGate 80F, FortiOS 8.0.2 build0251; FortiGate 60F, FortiOS 7.6.8 build3744 (captures of 2026-11-18)ᵃ | ✓ link/speed/duplex | ✓ interface configuration | ✓ local hardware switch, no VLAN set, 2026-11-18ᵃ | empty local bridge only | ✓ | ✓ local summary | ✓ IPv4 | docsᵃ | ✓ three iBGP peers, 2026-11-18ᵃ | ✓ FortiLink aggregate, 2026-11-18ᵃ | ✓ ports down only, 2026-11-18ᵃ | ✓ one enrolled interface, 2026-11-18ᵃ | ✓⁹ | ARP / own interface, 2026-11-10⁵ |
| FortiSwitch 224E-POE managed by a FortiGate | FortiGate 80F, FortiOS 8.0.2 build0251; switch firmware 8.0.1 recorded on 2026-11-07, not captured in the 2026-11-10 run | ✓ link/speed | ✓ interface configuration on FortiGate | ✓ configuration | ✓ | – | ✓ (summary, no management IP) | – | – | – | – | – | ✓ errors/drops | – | live located: AP port3, VLAN 100 untagged, 2026-11-10⁵ |
| Linux (`linux`) | Ubuntu 24.04.5; Debian 13.7 cloud; Proxmox VE on Debian 13.7 (CLI captures, 2026-11-13) | ✓ links, MAC; MTU of one enrolled interface | – | – | ✓ bridge FDB (static entries only on the Ubuntu host) | ✓ neighbors, ARP and ND | – | ✓ IPv4 | – | – | – | – | – | ✓ with MAC and default gateway | neighbors and bridge FDB on captured outputs; a bridge port stays `unverified` (`incomplete`) |

**Additional EXOS acceptance (2026-11-13).** The read-only EXOS acceptance of source `ad4ff3c` (2026-11-13), carried forward by the final 1.0.8 acceptance, compared eleven `switch_read` tables on one X435-8P-4S and three X440G2-12p-10G4, all 33.7.1.6-patch1-11: 44/44 independent table comparisons and 8/8 IP/MAC endpoint searches passed. LAG and aggregate were empty on two switches and populated on two X440G2 (sharing group 13, members 13–16, active 13 and 15). This adds live `port_vlan` evidence to the earlier replays; it does not qualify Admin writes, PoE, DOM or active MLAG.

**FortiSwitch qualification.** Only two 224E-POE managed through the FortiGate above were measured. The 29 port-state/error rows and 28 configured VLAN rows are the captured scope of these switches; port counts and naming on other models are unmeasured. MCLAG ICL, trunk and consistency were measured on one pair in one topology (2026-11-07, build 1.0.6); other peer counts, stacks and standalone FortiSwitch operation are unqualified. The dated 2026-11-10 endpoint evidence is one FortiAP on port3; the later 1.0.8 development-build reads (source 96ea561, 2026-11-12) located two hosts by IP and MAC on EXOS edge ports against fresh CLI. Neither result qualifies endpoint location behind a FortiSwitch trunk or in MCLAG. Other FortiSwitch models and firmware remain unmeasured.

1.0.8 additions (development builds before the release candidate, read-only accounts): `table="cdp_neighbor"` (CDP neighbours of Cisco IOS, IOS XE and NX-OS from the opt-in `cdp_neighbors` query) returned the correct local and remote port, neighbour name and management IP for the CDP output of IOS (two images), IOS XE and NX-OS lab images (4, 4, 3 and 3 neighbours, compared with the CLI). The five Linux tables above matched independent CLI reads on the Ubuntu host (3, 6, 4, 17 and 13 rows), and six further checks of the per-address default gateway also passed; that build read `ip_interface` from `ip address show`, and the released `ip -brief address` form is covered by the CLI captures of 2026-11-13. The forwarding database of that host held only static entries; in the tests a bridge port from a synthetic dynamic FDB row is returned as `unverified` with the result `incomplete`, never as a located edge. Linux has no VLAN, LLDP, OSPF, BGP, LAG or STP table and no IPv6 routes. FortiOS routes with recursive BGP next hops and summary/Null routes, the route code legends of FortiOS 7.6 and 8.0 and VLAN interfaces with a nested `config ipv6` node are parsed from the stored CLI captures of a FortiGate 60F (FortiOS 7.6.8; 13 routes, 9 VLAN interfaces) and an 80F (FortiOS 8.0.2; 32 routes, 7 VLAN interfaces) with no unparsed line; this is replay, not a new live run, and the 80F VLAN capture is reconstructed from its independent `get system interface` output.

Fortinet verification on 2026-11-10: acceptance of candidate source `51840b1`
returned FortiSwitch MAC, LLDP, 29 port-state/error rows and 28 configured
port-VLAN rows per switch. The AP was live `located` on port3, VLAN 100
untagged, with link up and 1000 Mb/s, in eight reads (about 45 s); the second
switch was transit over the ICL. VLAN membership is `source: configuration`,
not forwarding evidence. FortiSwitch firmware was not captured in that run; the separate 2026-11-07 measurement records 8.0.1 on both 224E-POE units.
The local interface, VLAN and LLDP tables were verified through live MCP on
2026-11-11: 11 physical interfaces, eight VLAN interfaces and two LLDP neighbors,
compared with independent CLI reads on the same 80F/build. The enrolled local
`internal` bridge read succeeded but was empty; populated local FDB layouts
remain unparsed. Without an enabled and enrolled bridge, local `mac_entry` is
`not_applicable` (clients: ARP/FortiSwitch). Local LLDP has no management
IP/capabilities. Managed FortiSwitch `interface_errors` reads errors and drops
only, so its CRC and flap fields stay null. The FortiGate-local
`interface_errors` table, added in 1.0.12, reads RX/TX errors, CRC (`rxc`) and
discards of one enrolled interface (`diagnose netlink interface list
<interface>`, note ᵃ); its flap fields (`last_flap`, `link_flaps`,
`carrier_transitions`) stay null.

⁸ `port_vlan` is tested by offline replay of read-only captures: IOSvL2 15.2(20200924), Nexus 9300v 9.3(12), cEOS 4.36.1F, vJunos-switch 26.2R1.7, EXOS-VM 33.6.1.14, X435-8P-4S 33.7.1.6 (booted secondary image) and X440G2 33.7.1.6. The 2026-11-09 PTY captures add EXOS `show vlan detail`; transport echo, prompt and pager artefacts were removed before anonymization. NX-OS and Junos success uses the existing captures of the exact catalogue commands (`show interface trunk`, `show ethernet-switching interface | no-more`); the new plural-command refusals are negative fixtures. IOL XE 17.18.2 is a router image that refuses the switching commands, so positive IOS XE membership remains a shared-parser synthetic test, not live evidence. Membership describes allowed VLANs, independently of forwarding or link state.


`interface_errors` evidence added on 2026-11-09: live captures replayed in
`test_port_errors.py` verify cEOS 4.36.1F (16 error-counter rows), EXOS-VM
33.6.1.14 and physical X435-8P-4S / X440G2-12p-10G4 33.7.1.6 (CRC and TX Errors),
and vJunos-switch 26.2R1.7 (extensive errors/drops, CRC/Align, Last flapped,
Carrier transitions). Common Junos replays the same switch output; no Junos
router was measured. Earlier stored canonical NX-OS 9.3(12) and EOS 4.36.1F discard captures
are also replayed; they are distinct from the supplied captures. On 2026-11-10,
new read-only `show interfaces` captures from IOSv 15.9(3)M12 (7 interfaces),
IOSvL2 15.2(20200924) (7) and IOL XE 17.18.2 (19) verify offline replay of the
authorized whole-port fallback, including RX/CRC/TX and queue/total output
drops. Refused or empty counter-table sources remain negative fixtures; the
authorized fallback was also verified through live MCP on IOSv, IOSvL2 and
IOL XE on 2026-11-11. Nonzero IOS/XE counters remain synthetic coverage. The NX-OS 9.3(12) supplied capture refused the plural
command; the catalogue uses singular `show interface counters errors`.
The new cEOS 4.36.1F LLDP capture verifies all nine neighbors, including seven
with day-old discovery/change ages, with complete parser coverage. EXOS direct
routes replay with `next_hop: null` and their VLAN interface, while static
routes keep their gateway. These parser replays do not establish support for
other firmware or hardware; device configuration was unchanged.


¹ Earlier SSH captures on 2026-11-09 recorded IOL XE Active and NX-OS Idle under temporary lab configuration (real fixtures). In the later MCP run, 14:10–14:20 UTC that day, NX-OS BGP was disabled (`show feature`; summary returned `unsupported`). IOSv, IOSvL2, IOL XE (without a CLI comparison), cEOS and vJunos returned inactive BGP (`not_applicable`); vJunos also reported a missing BGP licence. EXOS has no normalized BGP table. No BGP peer or established session with prefix counts was verified in that later run; established output remains docs. ² Only the neighbour on the management port appeared; LLDP neighbours on data ports were not shown by the Nexus 9300v and are docs. ³ The common Junos commands were captured earlier on vJunos-switch only; `juniper_junos` was not separately enrolled in the later MCP run. MX, SRX and PTX are not measured. In the 1.0.7 switch/router measurements described here, populated IPv6 ND layouts were documentation-only and the later MCP run verified no populated returned ND record. The later Ubuntu 24.04.5 Linux capture includes a populated IPv6 neighbour and is replayed by the tests; this does not establish a live IPv6 endpoint-location result on a dynamic Linux bridge port.

⁴ EXOS provides `table="aggregate"` using `show lacp` (`name`, `member_count`) and `table="lag"` using the explicitly enrolled `lag_summary` query (`show sharing`; `name`, `protocol`, `status`, `members`). The empty EXOS-VM case replays the empty output of the physical X435 with the EXOS-VM identity; a later EXOS-VM 33.6.1.14 `show sharing` capture of 2026-11-20 with one LACP group and one active member is replayed through `switch_read` by the intent checks. A populated physical X440G2 33.7.1.6 sharing group with members was captured on 2026-11-10 and is replayed by the engine tests. Populated LACP aggregates were also captured on physical EXOS switches on 2026-11-08.

⁵ Live acceptance on 2026-11-11 located GNS3 end hosts behind IOSvL2 Gi0/3 (VLAN 10), NX-OS Ethernet1/2 (VLAN 20), EXOS-VM port 2 (VLAN 10) and vJunos ge-0/0/1 (VLAN 20), each by IP and MAC in two rounds across all seven enrolled targets, and 13 physical end hosts on ExtremeXOS X440G2 switches by MAC; 11 also by IP. All 24 executed searches matched the CLI forwarding table; two IP searches were not run because no ARP mapping was available. cEOS was observed as transit in a completed live search; IOSv and IOL XE were included as router ARP readers. No access-host result on these router images is claimed. Endpoint parsers are also tested on real captures. The physical NAS case was live located behind X440G2; the enrolled inter-switch link is transit. FortiLink acceptance on candidate source `51840b1` located the AP on port3, VLAN 100 untagged (`edge_behind_ap`, eight reads), and the second switch MAC as `own_interface_of_target` (three reads). An enrolled device's own address is not an access-host result. No live result behind a phone is claimed; the `edge_behind_phone` role is covered by offline replay of a physical X440G2 capture. Common Junos was not separately enrolled. IOS XE endpoint location on a switch is tested only on documentation outputs; the IOL-L2 XE captures of note ᵇ cover the scoped MAC and STP tables, not an endpoint search.

⁶ Earlier IOS/EOS/NX-OS LAG captures remain dated evidence. In the later MCP run, LAG was empty on IOSvL2, NX-OS and cEOS, refused (`permission_denied`) on IOSv and IOL XE, and LACP was not running on vJunos; EXOS-VM `aggregate` was empty. No populated LAG/aggregate table was verified on any of the seven OS in that 2026-11-09 run; this does not negate the later physical EXOS sharing capture. The 2026-11-10 acceptance also exercised OSPF/LAG; exact per-OS populated row counts are unavailable, so no additional per-OS positive LAG claim is made here. vJunos RSTP port output was captured earlier on 2026-11-09 with temporary configuration; in the later run STP was disabled (`Spanning-tree is not enabled at global level.`, `not_applicable`).

⁷ Measurement quality: sequential reads are not an atomic snapshot (cEOS FDB changed from 10 to 7 rows); IOL XE reports normalized `model=null`; identity responses based only on `ssh_read version` carry warnings because the restricted inventory did not enable the additional identity queries; IOSvL2 is an experimental image and cEOS an engineering build. These limits bound the evidence above.

⁹ `ip_interface` (IPv4 address, prefix length, SVI VLAN, state) was added on 2026-11-09 and is parsed from the anonymised live outputs of `show ip interface brief` with `show ip route` (IOS, IOS XE, NX-OS), `show ip interface brief` (EOS), `show ipconfig` with `show vlan` (EXOS), `show interfaces terse` (Junos) and `get system interface` (FortiGate 80F, FortiOS 8.0.2 build0251, read-only account, 2026-11-09); FortiOS gives no link state, so `oper_status` stays null there. On the IOL XE router image the `interface` table comes from `show ip interface brief` (name, status, protocol) when the target declares `device_types: ["router"]` without `switch`; the IOSv router uses the same rule.

ᵃ FortiGate-local tables of 1.0.12 (`switch_read` without `managed_switch`): read-only CLI captures of 2026-11-18 from a FortiGate 60F (FortiOS 7.6.8 build3744, without BGP or OSPF) and a FortiGate 80F HA primary (FortiOS 8.0.2 build0251) are replayed by the tests. `bgp_peer` returned three established iBGP peers with prefix counts on the 80F (IPv4 and IPv6 summaries) and an empty table on the 60F. `ospf_neighbor` was empty on both, so the populated layout comes from the vendor documentation. `lag` and `interface_errors` read one enrolled aggregate or interface (`interface` is required): the FortiLink aggregate with its members on both, and zero error, drop and CRC counters of `wan1`; nonzero counters are a mutation of the real capture. `stp_port` (`get system stp list`) and `port_vlan` (`show system virtual-switch` with `get system interface`) cover the local hardware switch only: its ports were down and no VLAN was set on it, so an active STP port and a VLAN of a virtual switch come from the vendor documentation. Ports of a managed FortiSwitch are in the next row.

ᵇ IOS XE switch image: IOL-L2 XE 17.18.2 outputs captured on 2026-11-19 (MAC table scoped by address, port and VLAN, privileged EXEC) and on 2026-11-20 (`show spanning-tree`, read-only account) are replayed by the tests, the scoped `mac_entry` reads through `switch_read` and the spanning-tree output through the same `stp_tree` parser in the port triage. The whole MAC table and the VLAN, port VLAN and LAG layouts of IOS XE remain documentation; `show etherchannel summary` was empty on that image.

ᶜ ExtremeXOS `stp_port` reads `show stpd s0 ports` (the default domain `s0`; another enrolled domain through `stp_domain_ports`). Captures of 2026-11-08 and 2026-11-09 (X440G2-12p-10G4 33.7.1.6, EXOS-VM 33.6.1.14) and the 1.0.12 port captures of physical 33.7.1.6-patch1-11 switches and EXOS-VM 33.6.1.14, replayed through `switch_read`, include forwarding and disabled ports. EXOS has no normalized OSPF or BGP table: `ssh_read` returns the catalogue reads of OSPF, OSPFv3 and BGP without normalization, captured on 2026-11-17 without an OSPF neighbor or a BGP peer.

ᵈ Common Junos (`juniper_junos`) has no VLAN, port VLAN, MAC or STP template; those commands exist only in the ELS form. EX and QFX switches are enrolled as `juniper_junos_els`.

IOS / IOS XE IPv4 route lookups use the authorized whole routing table as a fallback when the direct lookup is empty.

Catalogue, triage, Wi-Fi, Auditor and Admin details are in the [support guide](docs/verified-support.md#helper-coverage-by-os-netops-108).
