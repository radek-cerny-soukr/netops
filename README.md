# NetOps

**Let your AI assistant work on your network — with guardrails, not a root shell.**

NetOps is a self-hosted MCP server that gives Claude Code, Codex or any other MCP client controlled access to your network devices. The assistant can troubleshoot, audit configurations and make small, reversible changes. It never sees a device password, never gets a free-form CLI and never touches a device you did not enroll.

- **Troubleshoot faster.** Read-only checks on FortiGate, FortiADC, Cisco, Juniper, Arista, ExtremeXOS, Ruckus Unleashed and Linux: a vetted query catalogue, the same normalized tables (interfaces, VLANs, MAC, ARP, LLDP, routes, OSPF, BGP, LAG, STP) on the switches and routers of six operating systems, endpoint location across several devices, FortiGate Wi-Fi client and flow diagnostics, and guided triage of FortiGate health, routing and IPsec VPN and of FortiADC load balancing. Every finding cites the device output it came from.
- **Audit configurations.** Rule catalogues for FortiOS (including CIS FortiGate Benchmark checks), ExtremeXOS and FortiADC, with text, JSON or SARIF output.
- **Change safely.** Admin changes on FortiOS (firewall policies, addresses, DHCP reservations) and ExtremeXOS (VLANs, ports) run behind an on-device safeguard that undoes the change by itself if NetOps cannot confirm it.
- **Know what happened.** Every request is written to the audit before it reaches a device; if the audit cannot be written, nothing runs.
- **Trust what you install.** One image for amd64 and arm64 with a Sigstore-signed checksum list, SBOMs and written vulnerability assessments.

NetOps is an independent, open-source, multi-vendor tool. It is not a product of any vendor whose devices, software or MCP clients it supports or names, and it is not affiliated with, endorsed by or supported by any of them; see the [disclaimer](#disclaimer).

The image contains no AI agents. Any MCP client that verifies TLS normally can connect; the quickstart covers Claude Code and Codex. See [Tested MCP clients](#tested-mcp-clients) for the clients and models tested for 1.0.1, 1.0.4, 1.0.6 and 1.0.7.

**Start here:** [NetOps 1.0 quickstart](docs/quickstart-1.0.md)

## What's new in 1.0.7

NetOps 1.0.7 is the largest extension of the Helper since 1.0: until 1.0.6 its guided diagnostics covered FortiGate and FortiADC, while the Cisco, Arista, Juniper and ExtremeXOS profiles offered raw catalogue reads only. 1.0.7 lets the assistant work with the switches and routers of six operating systems in one common data model, find where a device is connected, and diagnose FortiGate Wi-Fi clients and flows. Everything new is read-only and keeps the existing guardrails: enrolled targets only, fixed catalogue commands, pinned host keys, and every request written to the audit before it reaches a device.

- **Multi-vendor switches and routers.** The query catalogue grows from 380 to 547 templates. ExtremeXOS, Cisco IOS, IOS XE and NX-OS, Arista EOS and Junos (including EX/QFX ELS) gain the reads of daily operations: whole routing tables, OSPF interfaces, spanning tree, trunks, err-disabled ports, detailed LLDP, NTP, bounded logs, and vPC/MLAG, PoE and stack state where the platform has them.
- **One table format for every vendor (`switch_read`).** Interfaces, interface error counters, port VLAN membership, IP interfaces (address, prefix length, SVI VLAN), VLANs, MAC table, ARP/ND, LLDP neighbours, routes, OSPF neighbours, BGP peers, LAG and STP ports come back as the same records whatever the vendor prints. Every result names its source commands with a hash of their output; lines the parser does not recognize are returned in `unparsed`, never dropped, and `coverage` says which fields the device did not supply.
- **Find a device on the network (`locate_endpoint`).** One IP or MAC address across 1–64 enrolled targets (including managed-switch slots): ARP/ND on routers and firewalls gives the MAC, MAC tables on switches give the port and VLAN, LLDP tells an access port from an uplink, and an IP phone or Wi-Fi access point on the port is named. A MAC seen only on an uplink to a device you did not enroll is reported as such, never as "not found". Up to 8 concurrent readers, 40 reads for at most 8 aliases and otherwise 8 reads per alias, with a shared 59.5-second deadline.
- **FortiGate Wi-Fi diagnostics.** Seven Wi-Fi reads that work with a read-only account, and `wifi_triage` for one client by MAC, IP or exact hostname `name` (`identity_trust: client_supplied`): significant client history, access point, radio, SSID and RF state, with findings. An optional read-only REST token, enrolled separately, adds live clients with RSSI/SNR (`wifi_clients`), managed AP state (`wifi_aps_live`) and rogue and interfering APs (`wifi_rogue`): fixed GET requests, certificate pin or CA, no writes ([administrator checklist](docs/fortios-wifi-rest.md#create-access-on-fortigate)).
- **Is this flow allowed? (`triage_flow`).** For one IPv4 flow through a FortiGate: the route to the destination and back to the source, the firewall policy lookup and, when enrolled, the sessions of the flow, with a verdict such as `allowed_and_session_seen` or `denied_by_policy`. Accepted only on the measured identity, FortiGate 80F with FortiOS 8.0.2 and VDOMs disabled.
- **Also new:** MCP progress notifications during triage, an authenticated `GET /healthz`, a `coverage` report in the Auditor, reason codes in Admin refusals, and a fix for a session or transport secret that could be rebuilt from two pages of `ssh_read`/`schema_read` ([security note](release/notes-1.0.7.md#security)).

Examples of questions an administrator can ask the assistant once the devices are enrolled:

- "Where is the device with MAC 00:00:5e:00:53:10 connected?" or "Which switch port and VLAN does 192.0.2.10 use?" (`locate_endpoint`)
- "Why does the Wi-Fi client 00:00:5e:00:53:21 have a weak signal or keep disconnecting?" (`wifi_triage`; live RSSI/SNR needs the [optional REST token](docs/fortios-wifi-rest.md#create-access-on-fortigate))
- "Are there rogue access points stronger than -70 dBm?" (`wifi_rogue`)
- "Is HTTPS from 192.0.2.10 to 198.51.100.20 allowed through the FortiGate, and is there a session?" (`triage_flow`)
- "Which OSPF neighbours does the core router have, and which ports are blocking in spanning tree on the access switch?" (`switch_read`)
- "Compare the VLANs and the LLDP neighbours of the two distribution switches." (`switch_read`)

The assistant answers from the device output it read and lists what it could not read; none of these tools changes the device configuration.

### Coverage by vendor and operating system

**✓** the command's output was captured live from that OS with a read-only account, and the tests parse that output · **docs** the output layout comes from the vendor documentation only, because the measured device had nothing to show (feature not configured, empty table, or command missing on the virtual image) · **–** not provided. Live captures used development builds of the 1.0.7 source on 2026-11-08 and 2026-11-09; virtual images do not establish hardware behavior (PoE, optics, stacking, forwarding), and no hardware Cisco, Arista or Juniper device was tested. A check mark records a dated capture or live acceptance result, not the current lab configuration; the endpoint column has the narrower scope in note ⁵. **replay** means offline replay of live captures; **transit** means a transit hop in a completed live endpoint search; **ARP** means captured IPv4 router/firewall input, without an end-to-end endpoint result. Measurement quality limits are in note ⁷.

Normalized tables (`switch_read`) and endpoint location:

| OS (profile) | Verified live on | Interfaces | VLAN | Port VLAN | MAC | ARP | LLDP | Routes | OSPF | BGP | LAG | STP | Errors / flaps | IP interfaces | `locate_endpoint` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ExtremeXOS (`extreme_exos`) | X435-8P-4S and three X440G2-12p-10G4 with 33.7.1.6; EXOS-VM 33.6.1.14 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | – | – | ✓ `aggregate`, `lag`⁴⁶ | – | ✓ CRC/TX | ✓ | live located: 13 end hosts on physical X440G2/X440 (24/24) and an end host on EXOS-VM port 2, VLAN 10, 2026-11-11⁵ |
| Cisco IOS (`cisco_ios`) | IOSv 15.9(3)M12 (router), IOSvL2 15.2(20200924) (switch) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | replay: show interfaces | ✓ | live located: end host on IOSvL2 Gi0/3, VLAN 10 untagged, 2026-11-11⁵ |
| Cisco IOS XE (`cisco_xe`) | IOL XE 17.18.2 (router image) | ✓⁹ router | docs | docs⁸ | docs | ✓ | ✓ | ✓ | ✓ | ✓¹ | docs⁶ | docs | replay: show interfaces | ✓ | ARP in completed live search, 2026-11-10⁵ |
| Cisco NX-OS (`cisco_nxos`) | Nexus 9300v, NX-OS 9.3(12) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓² | ✓ | ✓ | ✓¹ | ✓⁶ | ✓ | prior canonical replay; new capture refused | ✓ | live located, 2026-11-10⁵ |
| Arista EOS (`arista_eos`) | cEOS 4.36.1F | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | ✓ errors; discards prior replay | ✓ | live transit, 2026-11-10⁵ |
| Junos ELS, EX/QFX (`juniper_junos_els`) | vJunos-switch 26.2R1.7 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | docs⁶ | ✓⁶ | ✓ extensive | ✓ | live located: end host on ge-0/0/1, VLAN 20 untagged, 2026-11-11⁵ |
| Junos, other platforms (`juniper_junos`) | the same commands on vJunos-switch 26.2R1.7³ | ✓³ | – | – | – | ✓³ | ✓³ | ✓³ | ✓³ | docs | docs⁶ | – | replay on ELS switch | ✓³ | ARP³⁵ |
| FortiOS (`fortinet`) | FortiGate 80F, FortiOS 8.0.2 build0251 | ✓ link/speed/duplex | ✓ interface configuration | – | empty local bridge only | ✓ | ✓ local summary | ✓ IPv4 | – | – | – | – | – | ✓⁹ | ARP / own interface, 2026-11-10⁵ |
| FortiSwitch managed by a FortiGate | FortiGate 80F, FortiOS 8.0.2 build0251 (FortiSwitch firmware not captured) | ✓ link/speed | ✓ interface configuration on FortiGate | ✓ configuration | ✓ | – | ✓ (summary, no management IP) | – | – | – | – | – | ✓ errors/drops | – | live located: AP port3, VLAN 100 untagged, 2026-11-10⁵ |

Fortinet verification on 2026-11-10: acceptance of candidate source `51840b1`
returned FortiSwitch MAC, LLDP, 29 port-state/error rows and 28 configured
port-VLAN rows per switch. The AP was live `located` on port3, VLAN 100
untagged, with link up and 1000 Mb/s, in eight reads (about 45 s); the second
switch was transit over the ICL. VLAN membership is `source: configuration`,
not forwarding evidence. FortiSwitch firmware was not captured. FortiGate-local
reads added afterward were independently executed with `netops-test-ro` on the
same 80F/build: 11 physical interfaces, eight VLAN interfaces with ID/parent/IP,
and two local LLDP neighbors via `diagnose lldp rx neighbor summary`. Those new
normalized tables are tested through the engine with a fake transport, not a
new live MCP run. The enrolled local `internal` bridge read succeeded but was
empty; populated local FDB layouts remain unparsed. Without an enabled and
enrolled bridge, local `mac_entry` is `not_applicable` (clients: ARP/FortiSwitch).
Local LLDP has no management IP/capabilities; CRC and flap counters stay null.

⁸ `port_vlan` is tested by offline replay of read-only captures: IOSvL2 15.2(20200924), Nexus 9300v 9.3(12), cEOS 4.36.1F, vJunos-switch 26.2R1.7, EXOS-VM 33.6.1.14, X435 31.7.3.37 and X440G2 33.7.1.6. The 2026-11-09 PTY captures add EXOS `show vlan detail`; transport echo, prompt and pager artefacts were removed before anonymization. NX-OS and Junos success uses the existing captures of the exact catalogue commands (`show interface trunk`, `show ethernet-switching interface | no-more`); the new plural-command refusals are negative fixtures. IOL XE 17.18.2 is a router image that refuses the switching commands, so positive IOS XE membership remains a shared-parser synthetic test, not live evidence. Membership describes allowed VLANs, independently of forwarding or link state.


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
corrected fallback was not measured through live MCP. Nonzero IOS/XE counters
remain synthetic coverage. The NX-OS 9.3(12) supplied capture refused the plural
command; the catalogue uses singular `show interface counters errors`.
The new cEOS 4.36.1F LLDP capture verifies all nine neighbors, including seven
with day-old discovery/change ages, with complete parser coverage. EXOS direct
routes replay with `next_hop: null` and their VLAN interface, while static
routes keep their gateway. These parser replays do not establish support for
other firmware or hardware; device configuration was unchanged.


¹ Earlier SSH captures on 2026-11-09 recorded IOL XE Active and NX-OS Idle under temporary lab configuration (real fixtures). In the later MCP run, 14:10–14:20 UTC that day, NX-OS BGP was disabled (`show feature`; summary returned `unsupported`). IOSv, IOSvL2, IOL XE (without a CLI comparison), cEOS and vJunos returned inactive BGP (`not_applicable`); vJunos also reported a missing BGP licence. EXOS has no normalized BGP table. No BGP peer or established session with prefix counts was verified in that later run; established output remains docs. ² Only the neighbour on the management port appeared; LLDP neighbours on data ports were not shown by the Nexus 9300v and are docs. ³ The common Junos commands were captured earlier on vJunos-switch only; `juniper_junos` was not separately enrolled in the later MCP run. MX, SRX and PTX are not measured. Populated IPv6 ND layouts are documentation-only across all OS: every real IPv6 neighbour fixture is empty; the later MCP run likewise verified no populated returned ND record.

⁴ EXOS provides `table="aggregate"` using `show lacp` (`name`, `member_count`) and `table="lag"` using the explicitly enrolled `lag_summary` query (`show sharing`; `name`, `protocol`, `status`, `members`). The EXOS-VM sharing capture is empty. A populated physical X440G2 33.7.1.6 sharing group with members was captured on 2026-11-10 and is replayed by the engine tests; it is distinct from the empty VM capture. Populated LACP aggregates were also captured on physical EXOS switches on 2026-11-08.

⁵ Live acceptance on 2026-11-11 located GNS3 end hosts behind IOSvL2 Gi0/3 (VLAN 10), NX-OS Ethernet1/2 (VLAN 20), EXOS-VM port 2 (VLAN 10) and vJunos ge-0/0/1 (VLAN 20), each by IP and MAC in two rounds across all seven enrolled targets, and 13 end hosts on physical ExtremeXOS X440G2/X440 switches (24/24 searches matching the CLI forwarding table); cEOS and the router images were searched live as transit. Endpoint parsers are also tested on real captures. The physical NAS case was live located behind X440G2; the enrolled inter-switch link is transit. FortiLink acceptance on candidate source `51840b1` located the AP on port3, VLAN 100 untagged (`edge_behind_ap`, eight reads), and the second switch MAC as `own_interface_of_target` (three reads). An enrolled device's own address is not an access-host result. Phones and populated IPv6 ND remain unverified. Common Junos was not separately enrolled; IOS XE switch layouts remain documentation-only.

⁶ Earlier IOS/EOS/NX-OS LAG captures remain dated evidence. In the later MCP run, LAG was empty on IOSvL2, NX-OS and cEOS, refused (`permission_denied`) on IOSv and IOL XE, and LACP was not running on vJunos; EXOS-VM `aggregate` was empty. No populated LAG/aggregate table was verified on any of the seven OS in that 2026-11-09 run; this does not negate the later physical EXOS sharing capture. The 2026-11-10 acceptance also exercised OSPF/LAG; exact per-OS populated row counts are unavailable, so no additional per-OS positive LAG claim is made here. vJunos RSTP port output was captured earlier on 2026-11-09 with temporary configuration; in the later run STP was disabled (`Spanning-tree is not enabled at global level.`, `not_applicable`).

⁷ Measurement quality: sequential reads are not an atomic snapshot (cEOS FDB changed from 10 to 7 rows); IOL XE reports normalized `model=null`; identity responses based only on `ssh_read version` carry warnings because the restricted inventory did not enable the additional identity queries; IOSvL2 is an experimental image and cEOS an engineering build. These limits bound the evidence above.

⁹ `ip_interface` (IPv4 address, prefix length, SVI VLAN, state) was added on 2026-11-09 and is parsed from the anonymised live outputs of `show ip interface brief` with `show ip route` (IOS, IOS XE, NX-OS), `show ip interface brief` (EOS), `show ipconfig` with `show vlan` (EXOS), `show interfaces terse` (Junos) and `get system interface` (FortiGate 80F, FortiOS 8.0.2 build0251, read-only account, 2026-11-09); FortiOS gives no link state, so `oper_status` stays null there. On the IOL XE router image the `interface` table comes from `show ip interface brief` (name, status, protocol) when the target declares `device_types: ["router"]` without `switch`; the IOSv router uses the same rule.

Catalogue, triage, Wi-Fi, Auditor and Admin:

FortiLink capacity is bounded by the 5-second connection spacing on each FortiGate: at the observed ~5.6 seconds per read, an IP lookup with all edge queries fits roughly four managed switches (N + 6 reads) into 59.5 seconds; larger sites can return partial findings with incomplete coverage. Startup, latency and multiple matching switches reduce this capacity.

| Platform | `ssh_read` templates 1.0.6 → 1.0.7 | Run live for 1.0.7⁴ | Triage and Wi-Fi | Auditor | Admin |
|---|---|---|---|---|---|
| FortiOS (FortiGate) | 108 → 119 | the 7 new Wi-Fi reads, `system_interfaces`, local physical/VLAN/LLDP and empty bridge reads (2026-11-10), the 3 FortiSwitch port/VLAN reads and the `triage_routing` and `triage_flow` reads, FortiGate 80F 8.0.2 | new: `triage_flow` (FortiGate 80F 8.0.2, VDOMs disabled), `wifi_triage`, `wifi_clients`, `wifi_aps_live`, `wifi_rogue` (FortiGate 80F 8.0.2 with two FortiAP; live Wi-Fi needs [optional REST token](docs/fortios-wifi-rest.md#create-access-on-fortigate)); `triage_routing`, `triage_health`, `triage_vpn` | 37 rules | address, address group, DHCP reservation, firewall policy (unchanged) |
| FortiADC | 33 → 33 | – | `triage_slb` (FortiADC-KVM 7.6.7) | 8 rules on an exported configuration | pool member, command line only (unchanged) |
| FortiSwitch (FortiLink) | existing FortiOS catalogue reads | MAC/LLDP, port-stats and configured VLANs; live AP located, 2026-11-10, through FortiGate 80F 8.0.2 build0251 | `switch_read` with `managed_switch` | – | – |
| ExtremeXOS | 48 → 65 | 63 earlier catalogue reads plus VLAN detail on EXOS-VM; VLAN detail also on physical X435/X440G2; `lag_summary` replays empty VM and populated physical X440G2 sharing captures (2026-11-10) | – | 9 rules | VLAN, port display string, port VLAN membership (unchanged) |
| Cisco IOS | 27 → 49 | 43, docs-only 6 (error counters, environment, optics, PoE, stack) | – | – | – |
| Cisco IOS XE | 27 → 50 | 32, docs-only 18 (switch and platform reads) | – | – | – |
| Cisco NX-OS | 30 → 61 | 58, docs-only 3 (HSRP, VRRP, DHCP snooping) | – | – | – |
| Arista EOS | 33 → 54 | 53, docs-only 1 (PoE) | – | – | – |
| Junos ELS (EX/QFX) | 29 → 55 | 51, docs-only 4 (Virtual Chassis, PoE) | – | – | – |
| Junos (common) | 25 → 41 | 41, on the vJunos-switch | – | – | – |
| Linux | 16 → 16 | – | – | – | – |
| Ruckus Unleashed | 4 → 4 | – | – | – | – |
| **Total** | **380 → 547** | | | | |

⁴ The template was sent to the device with the read-only account. This includes empty and "not configured" answers and the reads that the built-in read-only role refuses: `show logging` and `stp_inconsistent` on IOS and IOS XE privilege 1, `stp_summary` on the IOSv router, and the two Junos log reads, which need more than the built-in `read-only` class. The per-template results are in the [Cisco](components/netops-helper/docs/vendor-cli-references/cisco.md#lab-measurements-gns3-lab-2026-11-08), [Arista](components/netops-helper/docs/vendor-cli-references/arista-eos.md#lab-measurements-gns3-lab-2026-11-08), [Junos](components/netops-helper/docs/vendor-cli-references/juniper-junos.md#lab-measurements-gns3-lab-2026-11-0809) and [ExtremeXOS](components/netops-helper/docs/vendor-cli-references/extreme-switch-engine.md#exos-vm-336114-compatibility) notes; device roles in [Accounts and least privilege](components/netops-helper/docs/read-only-accounts.md), details in [Verified platform support](docs/verified-support.md#helper-coverage-by-os-netops-107).

## Highlights

- **One product, one image.** A single multi-architecture image for `linux/amd64` and `linux/arm64`, pinned by digest in the release `env.example`. Core, Helper, Auditor and Admin share one dependency closure and one product version.
- **One MCP endpoint.** HTTPS only, bearer token, instance-local certificate authority with name constraints and an automatically renewed short-lived server certificate.
- **Audit before action.** Requests are durably recorded before dispatch and responses before delivery. If the audit cannot be written, the operation is refused (`audit_unavailable`). The audit goes to a TLS syslog receiver (recommended) or to a local, size-limited log.
- **Role isolation.** Gateway and roles run as separate long-running processes under their own UID/GID (51000–51003), with no Linux capabilities, `no-new-privileges`, a read-only root filesystem and CPU, memory and process limits. A short start-up bootstrap uses the capabilities listed in `compose.yaml` and then drops all of them.
- **Explicit device scope.** No device is enrolled implicitly. Each role has its own inventory and credentials; MCP clients pass enrolled aliases, never device credentials.
- **Device output is untrusted data**, never instructions.
- **Safeguarded changes.** Admin changes run behind an on-device safeguard with prediction, independent readback and verified return; unknown writes are never retried automatically.
- **Errors stay visible.** Refused, failed or uncertain operations are MCP errors (`isError`) with their full structured result.
- **Signed releases.** The checksum list is signed with Sigstore; SBOMs, vulnerability scans with written assessments and acceptance reports are covered by it.

## Roles and what they can do

`netops selftest` prints the MCP tool names of each role: **26 Helper, 7 Auditor and 6 Admin tools**. Core has no MCP tools.

### Core

The shared engine used by the other roles: inventory and credential-vault schemas and the SSH/SFTP transport with host-key pinning. See [Core inventory](components/netops-core/docs/inventory.md) and [Core vault](components/netops-core/docs/vault.md).

### Helper — read-only diagnostics

Read-only queries against enrolled targets, using a named query catalogue of **547 query templates across 11 platform profiles** (`linux`, `fortinet`, `extreme_exos`, `cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `juniper_junos_els`, `ruckus_unleashed`, `fortiadc`). The `ssh_read` catalogue excludes running/startup/full configuration, arbitrary CLI, debug activation, packet capture, shells and every write or lifecycle action. The two explicitly enabled FortiSwitch VLAN queries read only the selected managed-switch configuration and the VLAN interface mapping. Separately, `fortios_diagnostics` offers bounded sniffer and flow diagnostics, and `config_read` offers opt-in configuration capture. Query parameters are accepted only when their value is listed in the target's `read_inventory`, except the literal VLAN and MAC parameters and Wi-Fi event line counts (checked for their form), lookup prefixes inside an enrolled `lookup_prefixes` entry, access point ids returned by an earlier `wifi_ap_status`, and the flow of one `triage_flow` call ([exceptions](docs/helper-configuration.md#optional-helper-fields)).

| Tool | Behavior |
|---|---|
| MCP prompts | Five text-only troubleshooting runbooks when Helper is enabled; see [Helper tools](components/netops-helper/docs/tools.md#troubleshooting-prompts) |
| `helper_status` | Enrolled aliases, validation and rate state; no device contact |
| `target_scope` | Public enrollment boundary for one alias; no device contact |
| `read_query_catalog` | Named typed queries and metadata; not automatic authorization |
| `dns_probe` | Enrolled DNS resolution with address scope checks |
| `tcp_probe` | Enrolled TCP port reachability |
| `icmp_probe` | Explicitly permitted bounded diagnostics |
| `tls_probe` | Verified peer certificate and enrolled SNI/port |
| `switch_read` | Normalized interface, IP interface, interface error counters, port VLAN tagging/mode, VLAN, MAC, ARP/ND, LLDP, route, OSPF neighbour, BGP peer, LAG and STP records for EXOS, IOS/IOS XE, NX-OS, EOS and Junos (the tables of each OS in [What's new](#coverage-by-vendor-and-operating-system)), ARP/ND, IPv4 routes and IP interfaces of a FortiGate and managed FortiSwitch MAC/LLDP, link/speed, errors/drops and configured VLANs via an enrolled `managed_switch` serial; source hashes, coverage and explicit unparsed lines ([coverage](components/netops-helper/docs/tools.md#normalized-tables-switch_read)) |
| `locate_endpoint` | One IP/MAC literal across 1–64 enrolled targets (including managed-switch slots), 8 concurrent readers, 40 CLI reads including identity for at most 8 aliases and otherwise 8 per alias, shared 59.5-second deadline; edge/transit port, LLDP, VLAN and vantage, with missing evidence ([guide](components/netops-helper/docs/tools.md#endpoint-location-locate_endpoint)) |
| `ssh_read` | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`) |
| `sftp_stat` | Metadata within enrolled roots; no file content |
| `schema_read` | Not a supported workflow in 1.0 (see [Known limitations](#known-limitations)) |
| `fortios_diagnostics` | Enrolled bounded recipes, no schema registry needed. FortiOS: single-VDOM root only, exact measured identities FortiGate-VM64 8.0.2 build 0251, FortiGate-80F 8.0.2 build 0251, FortiGate-VM64-KVM 7.6.7 build 3704 and 8.0.0 build 0167 (TCP/UDP tuples only on FortiGate-VM64 8.0.2 build 0251, FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251); FortiADC: FortiADC-KVM 7.6.7 build 0676. Needs the target's `system_status` query enabled; see [Helper tools](components/netops-helper/docs/tools.md) |
| `config_read` / `config_diff` | Opt-in redacted configuration capture of a FortiOS or FortiADC target and comparison of two captures; see [Helper tools](components/netops-helper/docs/tools.md) |
| `snmp_get` | SNMPv3 authPriv GET (SHA256, AES128) with the `snmp_credential` of the target, 1 to 20 OIDs, UDP port within the egress scope; SNMPv1, SNMPv2c, noAuthNoPriv and authNoPriv are not supported |
| `ftp_list` | FTP and FTPS refused in the shipped profile |
| `triage_health` | Fixed read-only FortiOS health chain (resources, sessions, HA, NTP, updates, links) with findings and a verdict that never says healthy; FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 only |
| `triage_routing` | Fixed read-only FortiOS route chain for one enrolled IPv4 address (route, policy routes, SD-WAN, ARP) with sourced findings and an explicit list of what is not simulated; FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 (read live on an HA primary); other identities, including FortiGate-VM64 8.0.2 build 0251, are refused |
| `triage_flow` | One IPv4 flow (`src`, `dst`, `port`, `proto`) through a FortiGate: route to the destination and to the source, policy lookup with a fixed probe source port and, when the target enrols the `sessions` recipe, the sessions of the flow; verdict `allowed_and_session_seen`, `allowed_no_session`, `denied_by_policy`, `no_route` or `incomplete`; IPv6 is reported as unsupported; FortiGate-80F 8.0.2 build 0251 with VDOMs disabled only (read live on an HA primary); see [Helper tools](components/netops-helper/docs/tools.md#fortios-flow-triage-triage_flow) |
| `triage_vpn` | One named FortiOS IPsec tunnel: selector state, data and error counters, routes through it and IKE error counters (context), with findings and a verdict that never says healthy; FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251 only |
| `wifi_clients` / `wifi_aps_live` / `wifi_rogue` | Live FortiOS clients with RSSI/SNR, managed AP state and rogue/interfering observations through a separate RO REST token; fixed GETs, certificate pin or CA, no writes; see [setup and security](docs/fortios-wifi-rest.md) |
| `wifi_triage` | One Wi-Fi client by MAC, IPv4 or exact hostname `name` (`identity_trust: client_supplied`) from the read-only controller reads (`wifi_events`, `wifi_ap_status`, `wifi_vap_status`, `wifi_rf_analysis`, `wifi_neighbors`): significant client history, access point, radio, SSID and RF row, with findings and a verdict that is `fault_found`, `rf_concern_found`, `no_rf_fault_found`, `client_not_associated` or `incomplete`, never healthy; optional RO REST enrollment adds live RSSI/SNR and the current AP; the switch port of the client is not correlated, a `next_steps` entry hands it to `locate_endpoint`; FortiGate-80F 8.0.2 build 0251 only; see [Helper tools](components/netops-helper/docs/tools.md#wi-fi-client-triage-wifi_triage) |
| `triage_slb` | One enrolled FortiADC virtual server through pool, members, health checks, TLS, WAF and DoS (configuration and runtime) with sourced findings and a verdict that never says healthy; FortiADC 7.6.7 build 0676 only; see [Helper tools](components/netops-helper/docs/tools.md#fortiadc-load-balancing-triage-triage_slb) |

Each target has its own scope (enabled queries, egress addresses and ports, optional SFTP roots) and a per-target rate limit (default 30 requests per 60 seconds; the triage tools also have a sublimit of the same size; `triage_health`, `triage_routing`, `triage_vpn` and `triage_slb` report progress). The account must be independently verified as read-only on the device; the JSON declaration alone does not restrict it.

Docs: [Helper configuration](docs/helper-configuration.md) · [Helper tools](components/netops-helper/docs/tools.md) · [Query catalogue](components/netops-helper/docs/query-catalog.md) · [Account boundaries](components/netops-helper/docs/read-only-accounts.md)

### Auditor — configuration audit

Evaluates FortiOS, ExtremeXOS and FortiADC configurations against a rule catalogue (**37 FortiOS, 9 EXOS and 8 FortiADC rules**) and stores finished findings in a private store.

Operator commands (run with the instance stopped):

- `auditor run` evaluates a configuration snapshot from standard input offline, without contacting a device; output as text, `--json` or `--sarif`.
- `auditor collect` reads the configuration from an explicitly configured device through one pinned channel (`ssh` or `fortios-rest`, with host-key or TLS fingerprint verification); the Auditor never changes a device, but on FortiOS it collects with a `super_admin` administrator, which can write (see [Known limitations](#known-limitations)).
- `auditor import-snapshot` and `auditor import-policy` place reusable snapshots and operator management policies into private state.
- `--baseline-accept` accepts the findings of a run into the device baseline; later runs report them as `open-known`.

The seven MCP tools only read stored findings; they contact no device, start no collection and write nothing:

| Tool | Behavior |
|---|---|
| `audit_status` | Per device: `fresh`, `stale`, `never` or `incomplete`, finding counts per severity and state |
| `list_rules` | Rules of the configured catalog with ID, version, class, severity, title and references |
| `rule_detail` | One rule with remediation, evidence fields and known false positives |
| `list_findings` | Findings of the last run with state (`new`, `open-known`, `gone`, `not-evaluated`) and optional grouping by object |
| `finding_detail` | One finding with its baseline and suppression record |
| `compare` | `added`, `removed` and `kept` findings between two completely evaluated runs |
| `schema_report` | Refused in 1.0 (no schema report manifest is configured) |

Docs: [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows) · [Auditor tools](components/netops-auditor/docs/tools.md) · [Collection channels](components/netops-auditor/docs/channels.md) · [Management policy](components/netops-auditor/docs/management-policy.md)

### Admin — bounded, reversible changes

Admin is enabled by default (`init --disable-admin` omits its worker and MCP tools) and refuses device changes until it is configured and the device is enrolled. Supported change scope:

- **FortiOS:** firewall address, address group and DHCP reservation; firewall policy as an [opt-in table](docs/admin-configuration.md#opt-in-table-firewall-policy), disabled by default per device.
- **ExtremeXOS:** VLAN, port display string and port VLAN membership.
- **FortiADC:** pool member status, add and remove, as operator commands only ([FortiADC pool member](docs/admin-configuration.md#fortiadc-pool-member)).

Each change runs behind an on-device safeguard (60–900 seconds), with protected objects, per-device/hour and daily limits, an independent check account, a change journal and a notification over trusted HTTPS (ntfy). A device whose operation ends `unknown` or `revert-failed`, or with a blocking reason, stays blocked until a person investigates.

| MCP tool | Behavior |
|---|---|
| `admin_doctor` | Readiness report without a device change; optional `local=true` checks local readiness only |
| `admin_preview` | Every check of apply without a change: proposed commands, prediction and refusal reasons |
| `admin_apply` | One change behind the device safeguard; result `confirmed`, `reverted`, `rejected`, `unknown` or `revert-failed` |
| `admin_status` | The stored operation record by `change_id` or `request_id` |
| `admin_schema_preview` / `admin_schema_apply` | Schema transactions; not a supported workflow in 1.0 |

Operator commands (instance stopped), not MCP tools:

- `admin enroll` performs a real temporary probe change and lets the on-device safeguard return it; `admin doctor` then has to report `"ready": true`. With `admin doctor --local`, exit 0 means only local readiness; remote readiness remains unverified.
- `admin undo` returns a confirmed change as a new safeguarded operation with its own change ID.
- `admin recover` inspects and settles an interrupted or unknown operation using its saved safeguard and original state.
- `admin status`, `admin notify-retry` and `admin unblock` (for a person who has inspected the record and the device).

There is no MCP tool to undo a change, unblock a device, cancel a safeguard or edit a plan.

Docs: [Admin configuration](docs/admin-configuration.md) · [Admin MCP tools](docs/admin-configuration.md#mcp-tools)

## Supported devices and firmware

Compatibility is scoped to the exact platform, firmware build, model, account policy and operation documented by each component. Catalogue presence does not qualify every deployment, and software-image results do not establish physical forwarding or hardware behavior.

| Platform | Documented scope |
|---|---|
| FortiOS | 7.6.8 build3744 and 8.0.2 build0251, the measured FortiOS releases; 7.6.7 build3704 and 8.0.0 build0167 remain only as contracts of earlier measurements ([verified support](docs/verified-support.md)); model scopes FortiGate 60F, FortiGate 80F and FortiGate-VM64-KVM kept separate; Admin profiles `firewall address`, `firewall addrgrp` and `system dhcp server/reserved-address` cover 7.6.7 build3704, 8.0.0 build0167 and 7.6.8 build3744 on FortiGate 60F, `firewall policy` 7.6.8 build3744 and 8.0.2 build0251; on 8.0.2 build0251 only `firewall policy` and `firewall address` |
| FortiADC | FortiADC-KVM 7.6.7 build0676 (virtual image, standalone): Helper catalogue of thirty-three queries; Auditor audits an exported configuration (`auditor run`), `auditor collect` refuses FortiADC; Admin `pool-member` verified live in that scope only (disable and enable of one member, refusal of the last healthy member, 2026-10-31; `pool-member-add` confirmed and `pool-member-remove` of a disabled member confirmed with the pool equal to its initial state, 2026-10-31; a failed `pool-member-remove` after the member was deleted was returned by the inverse create, `rolled_back`, with the pool equal to the state before, 2026-11-01; development builds; [verified support](docs/verified-support.md)) |
| ExtremeXOS | 33.7.1.6, 33.7.1.6-patch1-11 and the 33.6.1.14 virtual-image scope; model identifiers X435-8P-4S, X440-G2-12p and X440-G2-12p-10G4; Helper catalogue, `switch_read` and `locate_endpoint` ([coverage](#coverage-by-vendor-and-operating-system)), Auditor and Admin |
| Arista EOS | 4.36.1F (Helper catalogue, `switch_read`, `locate_endpoint`; [coverage](#coverage-by-vendor-and-operating-system)) |
| Cisco | NX-OS 9.3(12), IOS-XE 17.18.2 (router image; switch reads only from the vendor documentation), IOS 15.9(3)M12 and IOS 15.2(20200924) (Helper catalogue, `switch_read`, `locate_endpoint`; [coverage](#coverage-by-vendor-and-operating-system)) |
| Juniper Junos | 26.2R1.7 on vJunos-switch, ELS (Helper catalogue, `switch_read`, `locate_endpoint`; [coverage](#coverage-by-vendor-and-operating-system)); the common profile for routing platforms (MX, SRX, PTX) is not measured |
| Ruckus Unleashed | Explicit administrator-bounded role and catalogue boundary (Helper) |
| Linux | Documented distribution, architecture and permission requirements (Helper) |

Auditor catalogs cover FortiOS, ExtremeXOS and FortiADC. Admin MCP execution (MCP tools and the profile command `netops-admin apply`) is limited to the FortiOS and ExtremeXOS profiles listed above; on FortiADC, Admin offers only the command-line `pool-member`, `pool-member-add` and `pool-member-remove` commands, with no MCP tool ([FortiADC bounds](docs/verified-support.md#fortiadc-bounds)). A read catalogue on another platform does not imply Admin support there. The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries are unverified on stacking- or PoE-capable hardware. The seven `wifi_*` reads for a read-only FortiOS account (`wifi_ap_status`, `wifi_vap_status`, `wifi_neighbors`, `wifi_controller_status`, `wifi_controller_statistics`, `wifi_rf_analysis`, `wifi_events`) and `wifi_triage` were measured on FortiGate-80F 8.0.2 build0251 with two FortiAP only, on 2026-11-08; the SSH reads list no live client and no client RSSI; optional [read-only Wi-Fi REST enrollment](docs/fortios-wifi-rest.md) adds `wifi_clients`, `wifi_aps_live`, `wifi_rogue` and live RSSI/SNR in triage, and the five `diagnose wireless-controller` queries remain for an `admin-bounded` account ([measurement](components/netops-helper/docs/vendor-cli-references/fortinet-fortios.md#wi-fi-reads-for-a-read-only-account-measured)).

Live verification of NetOps 1.0.7 on 2026-11-08: development builds of the 1.0.7 source before the release candidate, read-only accounts only. A physical FortiGate 80F in active-passive HA mode (primary unit, single VDOM) with FortiOS 8.0.2 build0251: the reads of `triage_routing` and `triage_flow` (routes, policy routes, SD-WAN, ARP, policy lookup, sessions of a flow), the seven Wi-Fi reads for a read-only account, `wifi_triage` and the read-only Wi-Fi REST endpoints of `wifi_clients`, `wifi_aps_live` and `wifi_rogue`; the other HA member was not read. Four physical ExtremeXOS switches (X435-8P-4S and three X440G2-12p-10G4) with 33.7.1.6, and a GNS3 lab with IOSv 15.9(3)M12, IOSvL2 15.2(20200924), cEOS 4.36.1F and EXOS-VM 33.6.1.14: every catalogue template of these profiles. The anonymised outputs are the fixtures of the automated tests of `switch_read`, `locate_endpoint` and the triage tools ([verified support](docs/verified-support.md#live-verification-of-netops-107)).

Live verification of NetOps 1.0.7 on 2026-11-09: earlier SSH captures in the same GNS3 lab, IOL XE 17.18.2, Nexus 9300v with NX-OS 9.3(12) and vJunos-switch 26.2R1.7 (every catalogue template of these profiles, read-only accounts), and on the FortiGate 80F with FortiOS 8.0.2 build0251 the IP range syntax of the `sessions` and `flow` filters (filter set and cleared, no traffic test). Hardware Cisco, Arista and Juniper devices were not tested.

Later that day (14:10–14:20 UTC), direct HTTPS MCP calls measured 67 normalized tables on all seven GNS3 OS. The lab had no independent end host; IP/MAC endpoint runs returned transit evidence and `incomplete`, with seven-target runs reaching the 60-second limit. BGP on NX-OS and STP on vJunos were disabled. Historical fixture samples and these later feature states are distinguished in the coverage notes above and [verified support](docs/verified-support.md#later-gns3-mcp-verification-2026-11-09).

Live verification of NetOps 1.0.6 on 2026-11-07: FortiGate 60F with FortiOS 7.6.8 build3744, standalone (Admin `firewall policy` create, update and undo of an accept policy and of a deny policy, with two `firewall address` objects created and deleted through Admin), a physical FortiGate 80F in active-passive HA mode (primary unit) with FortiOS 8.0.2 build0251, managing two FortiSwitch 224E-POE with 8.0.1 and FortiAP 231K and 23JK with 8.0.0 (Helper `system_status`, FortiSwitch status, `switch_dhcp_bindings` returning an empty binding table, MCLAG ICL, trunk and consistency status, and `wifi_access_points`, `wifi_ap_detail`, `wifi_clients` with no associated station and `wifi_ssid_mapping` under an administrator-bounded account; `wifi_client_detail` was not measured), and SNMPv3 `snmp_get` of the system name on a FortiGate 80F and on FortiADC-KVM 7.6.7, measured with development builds of the 1.0.6 source before the release candidate ([verified support](docs/verified-support.md)).

Live verification of NetOps 1.0.5 on 2026-11-01: FortiGate 60F with FortiOS 7.6.8 build3744 (Admin `firewall policy` create, update and undo; Helper `switch_dhcp_bindings`), a physical FortiGate 80F active-passive HA pair with FortiOS 8.0.2 build0251 (Helper `switch_dhcp_bindings` with a client binding, FortiSwitch MCLAG status and the five Wi-Fi reads under an administrator-bounded account), FortiGate-VM64 with FortiOS 8.0.2 build0251 (Helper ping and sessions in a selected VDOM) and FortiADC-KVM 7.6.7 build0676, standalone (Helper `triage_slb` for a healthy, degraded and recovered pool with WAF deny events, and `tls_probe` with an enrolled certificate authority through a FortiADC virtual server; on 2026-10-31 Admin `pool-member`, disabling and re-enabling one member and refusing to disable the last healthy member), measured with development builds of the 1.0.5 source before the release candidate; the final 1.0.4 image was verified on 2026-10-28 ([verified support](docs/verified-support.md)).

Details: [Verified platform support](docs/verified-support.md) · [Compatibility boundaries](docs/compatibility-boundaries.md)

## Supported platforms

- **Host:** Linux with Docker Engine and the Compose plugin on Ubuntu, Debian, Fedora Server (SELinux enforcing, with SELinux support enabled in the Docker daemon) or Raspberry Pi OS 64-bit, natively or in a Linux virtual machine.
- **Architectures:** `linux/amd64` and `linux/arm64`; Raspberry Pi OS is arm64.
- **Docker Engine:** as root or in rootless mode.
- **Not supported as runtime:** Docker Desktop. Network-backed state storage, including NFS, is not qualified.
- **Clients:** macOS and Windows are supported only as MCP client hosts (Claude Code, Codex), not as NetOps servers. MCP clients connect over the network from any system.

## Security model

- **Endpoint:** HTTPS only with a bearer token. The token is checked before any request body is read; unauthenticated rejections are only counted, not stored.
- **Instance CA:** private, constrained to the configured DNS subtree, all IPv4/IPv6 names excluded (so the server name must be a DNS name). The server leaf lasts seven days and renews automatically; the CA is valid for 730 days from init or its last rotation (`connection` shows the remaining whole days, so 729 right after init) and is rotated explicitly with `netops ca rotate`.
- **Audit boundary:** every supported MCP request, notification, response and connection boundary is audited, with requests durable before dispatch and responses before delivery. A successful authenticated `GET /healthz` is not audited (local state only, no device contact); its query-string rejection and failure (HTTP 503) are. A failed audit refuses the operation; a failed response audit reports that the operation may have completed and forbids automatic retry. Offline operator workflows first record an allowlisted workflow name through a gateway-UID preflight.
- **Redaction:** explicit. Known token values, secret-bearing fields, private-key blocks and documented password forms are redacted; worker-side credentials are removed before reaching the gateway. Audit is parsed protocol content, not a raw byte transcript, and output is escaped for terminals. Device output remains sensitive after redaction.
- **Untrusted device output:** device text is data, never instructions; a diagnostic finding does not authorize a write, retry or another target.
- **UID separation:** gateway, Helper, Auditor and Admin have separate UID/GID, private state and credentials; local IPC authenticates the peer UID in both directions. This is process and filesystem isolation inside one container, not a boundary against the host administrator or the container runtime. The runtime never mounts the Docker socket or uses host networking.
- **TLS probe trust:** `tls_probe` verifies the peer chain and the hostname/SAN with TLS 1.2 or newer, against the system store or, per target, only against a CA file enrolled as `tls_ca_certificate` from a read-only directory; verification cannot be switched off.
- **Syslog over TLS:** the bounded, durable syslog queue sends to a verified TLS receiver. A successful delivery is a TLS transport hand-over, not a receiver acknowledgement; a full queue blocks new operations.
- **Fail-closed:** an unwritable audit, an incomplete final local audit record, a full syslog queue, a second instance on the same state or state of another product version or state schema stops operations instead of continuing silently. The one exception is the state of the immediately preceding release: the first start of the new release converts it under the instance lock and changes only its recorded product version. There is no downgrade.
- **CIS:** the container architecture and the release tests are inspired by the recommendations of the CIS Docker Benchmark; NetOps does not claim compliance with CIS.

Details: [Architecture](docs/architecture-1.0.md) · [Security policy](SECURITY.md) · [CIS Docker Benchmark mapping](docs/security/cis-docker-benchmark.md)

## Quick start

This is a shortened version of the [quickstart](docs/quickstart-1.0.md). Follow the full document for a new host: it installs the prerequisites step by step for Debian, Ubuntu, Fedora Server and Raspberry Pi OS, and covers rootless Docker, syslog receivers, backup, restore, upgrades and removal.

**0. Prerequisites.** Docker Engine with the Compose plugin from [Docker's repository](https://docs.docker.com/engine/install/), and an account that can run `docker info` (root, the `docker` group or rootless Docker); on Fedora, SELinux support enabled in the Docker daemon (`"selinux-enabled": true`) before the first start, so that `docker info` lists `name=selinux`. Further `curl`, `jq` and cosign 2.5 or newer; the quickstart installs the official Sigstore 3.x release (checked with v3.1.4) and says what to do when its download from GitHub fails. See quickstart steps [1–4](docs/quickstart-1.0.md#1-install-docker-engine), which also say how steps [3](docs/quickstart-1.0.md#3-give-your-account-access-to-docker) and [4](docs/quickstart-1.0.md#4-install-curl-jq-and-cosign) run without a terminal.

**1. Download and verify.** In the instance directory `~/netops` download the five release files and verify them. The block stops at the first failed download or check, and it downloads nothing into a directory that already holds the `.env` of an instance. The block sets the instance directory to mode 700, including an existing directory:

```sh
mkdir -p -m 700 ~/netops && cd ~/netops &&
if test -e .env; then echo 'netops: ~/netops already holds .env; nothing downloaded' >&2; false; fi &&
chmod 700 . &&
(
  for f in compose.yaml env.example netops-1.0.7-manifest.json netops-1.0.7-SHA256SUMS netops-1.0.7-SHA256SUMS.sigstore.json; do
    curl -fLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.7/$f" || exit 1
  done
) &&
cosign verify-blob --bundle netops-1.0.7-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.7-SHA256SUMS &&
sha256sum -c --ignore-missing netops-1.0.7-SHA256SUMS
```

cosign must print `Verified OK`, and sha256sum `OK` for `compose.yaml`, `env.example` and the release manifest; cosign authenticates the checksum list using the signature bundle. After a failed download or check, run the same block again: it downloads all five files again and overwrites those of the failed attempt. An empty `~/netops` left by a failed first attempt does no harm: the block reuses the directory, and nothing needs to be deleted.

**2. Configure.** Create `.env` and keep `NETOPS_IMAGE` exactly as pinned by digest in the `env.example` of the release; the `env.example` in the source repository has a placeholder instead, which Compose refuses with `pull access denied` ([step 5](docs/quickstart-1.0.md#5-download-and-verify-the-release)). For an MCP client on the same host, bind to the loopback address and use the name `localhost`:

```sh
umask 077
cp env.example .env
sed -i -e 's/^NETOPS_BIND_IP=.*/NETOPS_BIND_IP=127.0.0.1/' -e 's/^NETOPS_SERVER_NAME=.*/NETOPS_SERVER_NAME=localhost/' .env
```

For clients on other machines, set `NETOPS_BIND_IP` to the host address you explicitly want to expose and `NETOPS_SERVER_NAME` to the exact DNS name the clients will use instead (IP certificate names and the unedited `env.example` placeholders are refused); see [step 6](docs/quickstart-1.0.md#6-configure-env).

**3. Initialize and start.** `docker compose pull --quiet` downloads the image first, without download progress:

```sh
cd ~/netops &&
docker compose pull --quiet && docker compose run --rm netops init && docker compose up -d --wait && docker compose ps
```

`init` asks for the audit target: a TLS syslog receiver (recommended), or, when you leave it blank, local audit, which you accept by typing `LOCAL`. `docker compose ps` must show the service as `healthy`.

Without a terminal, for example in a script or over `ssh` without a terminal, choose the audit explicitly, add `-T` to every `docker compose run` and `docker compose exec`, redirect every other `docker compose` command with `< /dev/null`, and run the commands from a file, not from standard input. For local audit the block is the following; for a TLS syslog receiver replace `--audit local --accept-local-audit` with `--audit syslog --syslog-host <host> [--syslog-port <port>]`:

```sh
cd ~/netops &&
docker compose pull --quiet < /dev/null && docker compose run --rm -T netops init --audit local --accept-local-audit < /dev/null && docker compose up -d --wait < /dev/null && docker compose ps < /dev/null
```

**4. Export the CA and the token.** The block is the same in a terminal and in a script:

```sh
cd ~/netops &&
umask 077 &&
docker compose run --rm -T netops ca < /dev/null > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm -T netops token show < /dev/null)" &&
export NETOPS_TOKEN &&
test -n "$NETOPS_TOKEN" && printf 'NETOPS_TOKEN is set (%s characters)\n' "${#NETOPS_TOKEN}" &&
docker compose run --rm -T netops connection < /dev/null
```

The block prints `NETOPS_TOKEN is set (64 characters)` and the MCP URL, without printing the token. Compose writes its own messages to standard error, so `netops-ca.pem` and `NETOPS_TOKEN` receive only the output of NetOps. The token stays in the shell: in a script, run this block and the token requests of quickstart [step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) in the same script file.

**5. Check without an MCP client.**

```sh
cd ~/netops
docker compose exec -T netops netops health < /dev/null
docker compose exec -T netops netops version < /dev/null
curl -sS -o /dev/null -w '%{http_code}\n' --cacert netops-ca.pem \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST https://localhost:8443/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

They print `ready`, `1.0.7` and `401`: a request without the token is refused. Use the URL printed by `connection` when it is not `https://localhost:8443/mcp`. [Step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) adds requests with the token, including the MCP tool list, and how to find them in the audit.

**6. Connect a client.** Use the URL printed by `connection`.

Claude Code:

```sh
export NODE_EXTRA_CA_CERTS="$PWD/netops-ca.pem"
claude mcp add-json -s user netops '{"type":"http","url":"https://<server-name>:<port>/mcp","headers":{"Authorization":"Bearer ${NETOPS_TOKEN}"}}'
claude mcp list
```

Codex (`~/.codex/config.toml`, token kept in the environment):

```sh
export CODEX_CA_CERTIFICATE="$PWD/netops-ca.pem"
```

```toml
[mcp_servers.netops]
url = "https://<server-name>:<port>/mcp"
bearer_token_env_var = "NETOPS_TOKEN"
```

The [quickstart](docs/quickstart-1.0.md#10-connect-an-mcp-client) adds the Codex settings, the commands for a first non-interactive `helper_status` call with either client and how to find that call in the audit.

Other MCP clients must enable normal CA/SAN verification. Never disable TLS verification.

#### Tested MCP clients

Tested for 1.0.1 against a NetOps 1.0.1 instance, with each call found in the audit as a request and a response record:

| Client | Version | Platform | Models |
|---|---|---|---|
| Claude Code | 2.1.310 | Linux (Ubuntu 26.04, blind run of the quickstart), macOS 26.6.2 arm64, Windows 11 (PowerShell 5.1) as a remote client | Claude models of the client's provider account |
| Open WebUI | v0.12.3 | container image | Laguna XS 2.1 Q4 and gpt-oss-120b MXFP4, local, through llama.cpp `llama-server` (OpenAI-compatible API), 16,384-token context |
| Codex CLI | 0.164.0 | Linux (Debian GNU/Linux 13, amd64) | gpt-6.1-sol (medium reasoning) |

For NetOps 1.0.7, Codex CLI 0.163.0 (gpt-6.1-sol) and Claude Code 2.1.310 (claude-haiku-4-5) were tested on Debian 13 amd64 against the 1.0.7 candidate on 2026-11-10. Each client called `helper_status` through MCP with the instance token and CA; the successful call was matched in the audit. Negative checks covered a wrong token and a missing CA. Newer client versions were not tested for 1.0.7.

For NetOps 1.0.6, Codex CLI 0.167.0 (gpt-6.1-sol, selected with `--model`) and Claude Code 2.1.319 (claude-haiku-4-5) were tested on Linux (Ubuntu 26.04.1 LTS, amd64) against a NetOps 1.0.6 instance on the same host, a development build of the 1.0.6 source: each client listed the tools and made one `snmp_get` call that returned the system name of a FortiADC-KVM over SNMPv3, and each call was found in the audit as a request and a response record. The other clients in the table were not tested again for 1.0.6.

For NetOps 1.0.5, the clients in this table were not tested again against a NetOps 1.0.5 instance. The 1.0.5 live `triage_slb` and `tls_probe` calls of 2026-11-01 were sent to the MCP endpoint as JSON-RPC `tools/call` requests over Streamable HTTP with curl, and each call was found in the audit.

For 1.0.4, Codex CLI 0.164.0 on Linux arm64 was tested against a NetOps 1.0.4 instance on Debian 13 amd64: nine authenticated calls (three Helper, three Auditor and three expected Admin `admin_not_configured` refusals), each matched in the audit as a request and a response record.

In the 1.0.1 test, Codex CLI made three read-only calls per role. The three Admin calls returned the expected `admin_not_configured` refusal on an instance without enrolled devices, so no device changes were tested with Codex.

Other MCP clients with Streamable HTTP, bearer tokens and normal TLS verification can be used; the [quickstart](docs/quickstart-1.0.md#open-webui) has notes for Open WebUI.

**7. Enroll devices.** Start with `helper_status` and `read_query_catalog`. Enrollment is an operator action with the instance stopped, using private JSON files (mode 600) outside the source repository:

```sh
cd ~/netops
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

See [Helper configuration](docs/helper-configuration.md), [Admin configuration](docs/admin-configuration.md) and the [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows).

## Releases and upgrades

This README describes NetOps 1.0.7, the current release. What changed is in the [1.0.7 release notes](release/notes-1.0.7.md) and the [changelog](CHANGELOG.md), which also lists the earlier releases. To upgrade a 1.0.6 instance, follow [Upgrade from the previous release](docs/quickstart-1.0.md#upgrade-from-the-previous-release); to return to the unchanged 1.0.6 instance after an upgrade, follow [Rollback](docs/quickstart-1.0.md#rollback).

Existing inventory and credentials need no manual edits. Wi-Fi REST enrollment, lookup prefixes and switch/router profile options are optional; the [upgrade guide](docs/quickstart-1.0.md#upgrade-from-the-previous-release) explains them, keyboard-interactive authentication and connection spacing. Upgrade to 1.0.7 to fix the session/transport secret disclosure across `ssh_read`/`schema_read` page boundaries described under [Security](release/notes-1.0.7.md#security).


## Verification and release

A release is the maintainer's personally signed checksum list together with the assets it covers. A candidate branch, digest, build or CI run without that signature is not a release.

- **Signature:** `netops-1.0.7-SHA256SUMS` is signed with Sigstore (`netops-1.0.7-SHA256SUMS.sigstore.json`); certificate identity `325383355+radek-cerny-soukr@users.noreply.github.com`, OIDC issuer `https://github.com/login/oauth`.
- **Covered assets:** `compose.yaml`, `env.example`, the release manifest (image index and per-architecture digests), the acceptance manifest, the per-architecture SBOMs, vulnerability scans and scan gate results, the vulnerability assessments and the acceptance reports (`acceptance-*.json`). The signed checksum list itself is the complete list of covered files.
- **Build once:** every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild. The wheel inside the image is built with `SOURCE_DATE_EPOCH` set to the time of the source commit (`git log -1 --format=%ct`), so two builds of the same commit produce a byte-identical wheel; the Dockerfile refuses to build the wheel without it.
- **Building behind TLS inspection:** if a proxy or firewall decrypts TLS (for example FortiGate deep inspection), `docker build` stops at the first download: `apk` prints `TLS: server certificate not trusted` and `ERROR: Not continuing due to stale/unavailable repositories.`, and pip prints `ERROR: Could not find a version that satisfies the requirement <package>==<version> (from versions: none)`. Pass a CA bundle that contains the inspection CA as a BuildKit secret, for example the system bundle of a Debian or Ubuntu host that trusts that CA: `docker build --secret id=extra_ca,src=/etc/ssl/certs/ca-certificates.crt --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" .` The file is added to the image's own bundle only while the download steps run and is not stored in any image layer. Without the secret the build runs the same commands as before, and with or without it the wheel is byte-identical. The tester image of [Qualification](docs/testing-1.0.md) accepts the same secret; see [Source checkout problems](docs/testing-1.0.md#source-checkout-problems).
- **Vulnerabilities:** each architecture is scanned; a fixable High or Critical finding blocks the release and every other finding ships with a written assessment (`netops-1.0.7-vulnerability-assessments.json`). The digests of the latest release are rescanned daily against its assessments.
- **Acceptance of 1.0.7:** the acceptance is proportional to the change, and the [release notes](release/notes-1.0.7.md#acceptance) list its checks. Their results are the acceptance reports (`acceptance-*.json`) covered by the signed checksum list; the maintainer signs only a release whose required reports pass. The acceptance of 1.0.6 is described in its [release notes](release/notes-1.0.6.md#acceptance).

Use the image digest and configuration files from one signed release manifest. Qualification from a source checkout is described in [Qualification](docs/testing-1.0.md).

## Documentation

| Topic | Document |
|---|---|
| Installation, clients, audit, lifecycle, backup and restore | [Quickstart](docs/quickstart-1.0.md) |
| Helper inventory/vault input and first device operation | [Helper configuration](docs/helper-configuration.md) |
| Admin device, safeguard, notification, enrollment, preview, apply and undo | [Admin configuration](docs/admin-configuration.md) |
| MCP tool references | [Helper](components/netops-helper/docs/tools.md) · [Auditor](components/netops-auditor/docs/tools.md) · [Admin](docs/admin-configuration.md#mcp-tools) |
| Role UIDs, peer authentication, audit durability and redaction, certificates, syslog delivery | [Architecture](docs/architecture-1.0.md) |
| Exact host, firmware and model scope | [Verified support](docs/verified-support.md) · [Compatibility boundaries](docs/compatibility-boundaries.md) |
| Security policy and vulnerability reporting | [SECURITY.md](SECURITY.md) |
| CIS Docker Benchmark v1.6.0 self-assessment | [CIS mapping](docs/security/cis-docker-benchmark.md) |
| Qualification from a source checkout | [Testing](docs/testing-1.0.md) |
| Product changes | [CHANGELOG](CHANGELOG.md) |
| Historical 0.x documentation (not current instructions) | [0.x archive](docs/archive/0.x/ARCHIVE.md) |

## Known limitations

- 1.0 starts from a clean installation; it does not upgrade or migrate 0.x installations or data.
- NetOps runs as one instance in one container (`compose.yaml` defines the single service `netops`). There is no high-availability or clustering mode and no state shared between instances, and there is no graphical user interface: access is through MCP clients and the operator commands.
- On FortiOS the Auditor collects with a `super_admin` administrator, which can also write; restrict it with `trusthost`. A read-only profile hides other accounts' entries without saying so. See [account model](docs/account-model.md#auditor).
- Each role reads its device credentials only from its own private vault, a single JSON document (see [Core vault](components/netops-core/docs/vault.md)); the same device login can be enrolled in several roles, and NetOps does not compare them ([account model](docs/account-model.md)).
- The roles are isolated as processes and files inside one container, not against the host administrator or the container runtime.
- Authenticated requests with bodies above 64 KiB or uncertain body framing are processed one at a time across roles, so they can queue behind another large request; other authenticated requests share the remaining slots within the limit of 16.
- The request body has a 60-second receipt deadline. Since 1.0.3 the gateway has a separate 60-second deadline for the whole buffered, audited MCP response send sequence, not for each chunk. This does not bound execution time or prove that the client application read the response. During body delivery a receive watcher also detects ASGI disconnect events. An observed disconnect, timeout, cancellation, receive-channel or send-channel failure attempts an interruption record when the audit is writable, and the operation slot is released. A small buffered send or a close after the monitored phase may go unobserved; inspect `audit pending` before repeating an operation. See the [1.0.3 response-delivery notes](release/notes-1.0.3.md#response-delivery).
- An incomplete local audit write blocks further operations until `netops audit recover` runs while the instance is stopped. A full syslog queue blocks new operations, and an interrupted send can deliver records to the receiver more than once.
- Syslog records remain bounded at 8 MiB and use numbered 1024-byte parts with a persistent record ID and whole SHA256. Messages are at most 1618 bytes including their header. Configure a dedicated receiver archive filtered by RFC5424 APP-NAME `netops`, preserving exact MSG+LF, before the first start. Offline `audit reassemble --record-id` freezes the first complete SHA-valid set in archive order: later conflicts or invalid rows preserve its bytes and produce typed warnings/exit 3; earlier validation or input-read errors give exit 2 without record output. Keep older 1.0 full-record archives separately. Native default-limit storage checks verified rsyslog 8.2504 and 8.2512 with gtls and ossl and syslog-ng 4.12 on arm64 and amd64, each receiver running in a container.
- There is no supported provisioning path for the schema registry/library files of Helper `schema_read`, the extra input files of Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline and schema workflows.
- `ftp_list` is refused before any device contact, and no configuration enables it. Its engine checks the requested path against the target's `sftp_roots` only lexically, as a canonical absolute path equal to a root or below it; unlike `sftp_stat`, it does not let the server resolve the path, so a symbolic link below a root that leads out of it would not be refused.
- The opt-in FortiOS `managed_switch_stacking` and `managed_switch_poe` queries have no positive result on stacking- or PoE-capable hardware. Virtual device images do not establish physical hardware behavior.
- The process-profile acceptance check samples at a nominal 50 ms interval and can miss short-lived processes; see the [1.0.1 release notes](release/notes-1.0.1.md) for the exact attribution rule.

## 0.x releases and packaging

Version 1.0 does not migrate 0.x data or modify 0.x volumes. Previously published component releases remain available and unchanged. NetOps is distributed exclusively through GitHub: the source repository, GitHub Releases, and container images in GitHub Container Registry (GHCR). It is not distributed through PyPI. An inventory written for 0.x needs the 1.0 Helper section and the English device roles `perimeter`, `internal` and `lab`.

## License

NetOps is an open-source project by Radek Černý, distributed under the [MIT license](LICENSE). Compatible MCP clients remain vendor-neutral.

## Disclaimer

NetOps is open-source software provided **"as is", without warranty of any kind**, as stated in the [MIT license](LICENSE). You use it entirely **at your own risk**. The author currently has no plans to offer a commercial NetOps product or paid support. The MIT license permits commercial use, forks and redistribution.

- **No liability.** The [MIT license](LICENSE) disclaims liability for the software's authors or copyright holders for claims, damages or other liability arising from the software or its use, including changes that the Admin role makes to network devices.
- **No obligation to support or fix.** There is no service-level agreement and no commitment to provide support, answer questions, fix defects or security issues, publish updates or keep the project maintained. Any fix or release is voluntary and may never happen.
- **Your responsibility.** Before any production use, you are responsible for evaluating NetOps in your environment, verifying device accounts and permissions, keeping configuration backups, testing changes, and following your organization's policies and applicable law.
- **Not a vendor product.** NetOps is not a product of Fortinet, Extreme Networks, Cisco, Arista, Juniper, Ruckus or any other vendor whose devices or software it supports, nor of the vendors of the MCP clients and models named in this documentation. These vendors bear no responsibility for defects or errors in NetOps or for its effects on their devices, and they provide no support for it. Product and company names are trademarks of their respective owners and are used only to describe compatibility.
- **No certification.** Published tests, qualification results and supported-platform lists describe their documented scope and observations. They are not a guarantee, certification or fitness-for-purpose statement for your deployment.
- **Forks and redistributions.** Anyone may fork or redistribute NetOps under the MIT license, including commercially. Such versions are not provided, endorsed or supported by the author, and they create no obligation on the author's part toward their users.

IOS / IOS XE IPv4 route lookups use the authorized whole routing table as a fallback when the direct lookup is empty.
