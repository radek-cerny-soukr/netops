# NetOps

**Let your AI assistant work on your network — with guardrails, not a root shell.**

NetOps is a self-hosted MCP server that gives Claude Code, Codex or any other MCP client controlled access to your network devices. The assistant can troubleshoot, audit configurations and make small, reversible changes. It never sees a device password, never gets a free-form CLI and never touches a device you did not enroll.

- **Troubleshoot faster.** Read-only checks on FortiGate, FortiADC, Cisco, Juniper, Arista, ExtremeXOS, Ruckus Unleashed and Linux: a vetted query catalogue, the same normalized tables (interfaces, VLANs, MAC, ARP, LLDP, routes, OSPF, BGP, LAG, STP) on the switches and routers of six operating systems, endpoint location across several devices, FortiGate Wi-Fi client and flow diagnostics, and guided triage of FortiGate health, routing and IPsec VPN and of FortiADC load balancing. Every finding cites the device output it came from.
- **Audit configurations.** Rule catalogues for FortiOS (including CIS FortiGate Benchmark checks), ExtremeXOS and FortiADC, with text, JSON or SARIF output.
- **Change safely.** Enrolled Admin profiles cover eight platform families, including Ruckus WLANs. Changes use preview, independent readback and a device safeguard where available. FortiADC and Ruckus use compensating writes. Selected operational clears are irreversible.
- **Know what happened.** Every request is written to the audit before it reaches a device; if the audit cannot be written, nothing runs.
- **Trust what you install.** One image for amd64 and arm64 with a Sigstore-signed checksum list, SBOMs and written vulnerability assessments.

NetOps is an independent, open-source, multi-vendor tool. It is not a product of any vendor whose devices, software or MCP clients it supports or names, and it is not affiliated with, endorsed by or supported by any of them; see the [disclaimer](#disclaimer).

The image contains no AI agents. Any MCP client that supports Streamable HTTP with a bearer token and verifies TLS normally can connect; the quickstart covers Claude Code and Codex. See [Tested MCP clients](#tested-mcp-clients) for the dated results and earlier release history.

**Start here:** [NetOps 1.0 quickstart](docs/quickstart-1.0.md)

## What's new in 1.0.12

- **FortiOS and FortiSwitch.** Helper adds endpoint and managed-switch overviews, policy hit counts, bounded probes, and interface, routing and IPsec detail. Admin adds bounded port and managed-switch changes, routes, firewall objects and policies, IPsec selectors, managed-switch port bounce and PoE cycle, and targeted session clear, DHCP lease release and IPsec selector recovery. Managed-switch port bounce was verified live on the FortiGate 60F with a FortiSwitch 108E-series switch (an unused port, software admin up, down, up), and PoE cycle is covered by automated tests only. Admin refuses both on FortiOS 8.0.1 and later because the webhook safeguard has no REST inverse for either profile.
- **FortiADC.** Helper adds interface, TLS certificate, load-balancing, monitoring and bounded capture reads. Admin adds real-server and virtual-server changes, certificate import and selected session, persistence and WAF blocked-IP clears.
- **ExtremeXOS.** Helper adds health, port, routing and protocol reads. Admin adds link, VLAN, LAG, STP, routing, ACL and management changes, port bounce and configuration save, plus scoped cache and counter clears.
- **Cisco IOS and IOS XE.** Helper adds health, logs, routing, security and switching reads. IOS XE adds bounded probes and Catalyst 9800 and QFP diagnostics. Admin adds VLAN, trunk, EtherChannel, routing, ACL, DHCP and management profiles, combined plans, port bounce and PoE, configuration save, and scoped counter, MAC, ARP and IPv6 neighbor clears. Successful IPv6 neighbor clears are covered by automated tests only. Admin refuses per-address IPv6 neighbor clears on both the IOL XE router and the IOL-L2 XE switch. On IOS XE, Admin can disconnect one Catalyst 9800 wireless client (automated tests only).
- **Cisco NX-OS.** Helper adds vPC, port, routing, health and management reads. Admin adds VLAN and trunk, routing and relay, ACL, port-channel, vPC and management profiles, combined plans, port bounce, configuration save, and scoped counter, MAC, ARP and IPv6 neighbor clears. Successful IPv6 neighbor clears are covered by automated tests only.
- **Arista EOS.** Helper adds port, health, routing, protocol and configuration reads. Admin adds port, VLAN, port-channel, MLAG, STP, routing, ACL, DHCP and management profiles, port bounce and PoE, configuration save, scoped clears and BGP soft refresh.
- **Juniper Junos.** Helper adds routing, firewall-filter, health, configuration and SRX diagnostics. Admin adds VLAN and IRB, LAG and RSTP, routing, filters, DHCP and management profiles, including combined plans, port bounce and PoE, scoped counter, MAC, ARP and IPv6 neighbor clears, and BGP refresh. Successful IPv6 neighbor clears and BGP refreshes are covered by automated tests only. SRX security zones, address books, security policies and NAT are covered by automated tests only.
- **Ruckus Unleashed.** Helper adds client and AP triage, endpoint correlation and controller health and configuration reads. Admin adds WLAN lifecycle, access and DHCP relay settings.
- **Encrypted backups.** Admin operator commands preview and export an encrypted configuration backup of FortiOS, ExtremeXOS, Cisco IOS, IOS XE, NX-OS, Arista EOS and Junos into a private directory, and extract one for a restore. `admin restore-junos` restores a Junos backup under `commit confirmed`, and `admin backup-junos --rescue` also saves the Junos rescue configuration.
- **Across platforms.** For an untested build on a recognized platform, operations that report `firmware_support` can proceed with status `untested` and an explanatory message. Paths such as Helper triage and FortiOS backup export also emit a `firmware_untested` warning. Product identity, permissions and safeguards still apply. FortiOS and FortiADC SSH reuse one pinned session per operation and account. Admin refuses a stale approval with `plan_changed`. If IOS loses a pre-existing `banner exec` during rollback, Admin blocks the device and returns `exec_banner_lost`. Restore the banner manually, unblock the device (`admin unblock`), then retry the operation or enrollment. Admin adds the opt-in MCP tools `admin_undo`, `admin_unblock_preview` and `admin_unblock` (`mcp_undo: true`). `admin_undo` takes the approved `plan_sha256` from `admin_undo_preview` as `expected_plan_sha256`. The read-only `admin_unblock_preview` returns `unblock_sha256`, which `admin_unblock` takes as `expected_unblock_sha256` after approval. `netops check-intent` runs one read-only inventory intent check through the Helper endpoint and can send mismatches to a Discord webhook (`NETOPS_DISCORD_WEBHOOK`); the Discord delivery is covered by automated tests only.
- **Upgrade.** Upgrade only from 1.0.11. Restore its backup into a separate 1.0.12 instance. Follow the [upgrade guide](docs/quickstart-1.0.md#upgrade-from-the-previous-release).

See the [1.0.12 release notes](release/notes-1.0.12.md) and the [changelog](CHANGELOG.md). The sections for 1.0.11, 1.0.10, 1.0.9, 1.0.8 and 1.0.7 below are kept as history.

## What's new in 1.0.11

NetOps 1.0.11 follows NetOps 1.0.10. It removes the remaining conversion paths for data from before NetOps 1.0, returns a failed Junos change at once with a plain commit that the device timer cannot undo and describes an installation without sudo rights. Only 1.0.10 is accepted as the previous release; upgrade 1.0.9 to 1.0.10 first ([upgrade guide](docs/quickstart-1.0.md#upgrade-from-the-previous-release)).

- **Admin Junos immediate return.** After a failed write or readback, Admin commits the inverse lines with a plain commit (`netops-<id>-revert`) instead of `commit confirmed`, so an interrupted return no longer lets the device timer bring the change back. After a Junos operation of 1.0.10 that ended `revert-failed` or `unknown`, check the port as described in the manual check of the [Admin configuration](docs/admin-configuration.md#juniper-junos-interface-description-admin-state-and-access-vlan).
- **Conversions from before NetOps 1.0 removed.** The Auditor commands `auditor migrate-store` and `auditor migrate-suppressions` are removed, and a store or suppression file in the format before NetOps 1.0 is refused before any write. Admin refuses a plan written by Admin 0.x (`plan content does not match its plan_sha256`); run a new preview.
- **Quickstart without sudo.** Docker and `jq` are set up by the host administrator, and cosign is installed as a program of the own account in `~/.local/bin`.
- **Upgrade.** Upgrade only from 1.0.10 by restoring its backup into a separate 1.0.11 instance; do not run `init` on the restored state. Enrollments made with 1.0.10 stay valid: a device needs `admin enroll` again only when its device entry, its accounts, its firmware or the Admin notification or status file settings change.

See the [1.0.11 release notes](release/notes-1.0.11.md) and the [changelog](CHANGELOG.md).

## What's new in 1.0.10

NetOps 1.0.10 follows NetOps 1.0.9. It brings Arista EOS, FortiADC, Cisco IOS, IOS XE, NX-OS and Juniper Junos into the common Admin, makes FortiOS `config_diff` line-based, binds Admin `plan_sha256` to the device and firmware, runs the Auditor store in WAL mode, tightens the ExtremeXOS PoE cycle safeguard budget and recover, and hides typed Cisco-style hashes and whole account values in responses while keeping everything that 1.0.8 hid hidden. Only 1.0.9 is accepted as the previous release; upgrade 1.0.8 to 1.0.9 first ([upgrade guide](docs/quickstart-1.0.md#upgrade-from-the-previous-release)).

- **Admin for Cisco IOS, IOS XE and NX-OS, Juniper Junos and Arista EOS.** Admin supports Cisco IOS 15.x and IOS XE 17.x (platforms `ios` and `iosxe`), Cisco NX-OS 9.3(12) (platform `nxos`), Juniper Junos 26.2R1.7 on ELS switches (platform `junos`) and Arista EOS (cEOSLab 4.36.1F) through the shared Admin path: preview with `plan_sha256`, enrollment, journal and audit, check-account readback, undo, recover and the existing MCP tools (no new tool). Operations: interface description, admin state and access VLAN (on Cisco IOS and IOS XE the access VLAN only on the switch images). Each change runs under a device-side safeguard: the IOS/IOS XE revert timer, an NX-OS checkpoint with a one-time `feature scheduler` job, Junos `commit confirmed 10` and the EOS configuration session `commit timer`. These were measured in the GNS3 lab only, through the operator command line; the MCP tools were not called live ([release notes](release/notes-1.0.10.md#known-limitations)).
- **Admin for FortiADC through MCP.** Admin supports FortiADC (load-balance pool member state, add and remove) through the shared Admin path: preview with `plan_sha256`, enrollment, journal, audit, check-account readback, undo, recover and doctor; Admin MCP execution covers the FortiADC profiles ([FortiADC bounds](docs/verified-support.md#fortiadc-bounds)). FortiADC 7.6.7 has no on-device timed return, so an unconfirmed write is reverted by Admin itself with an inverse write in the same run, or by `admin recover` after an interruption.
- **Response redaction.** Response redaction hides typed Cisco-style hashes and whole account values, for example the hash in Arista EOS `enable password sha512 <hash>`. Every character that the released 1.0.8 redaction hid stays hidden on every path to the AI client, also in diagnostic output cut to `max_bytes`; where the current chain cannot keep a JSON document's structure safely, the output is withheld ([security note](release/notes-1.0.10.md#security)).
- **Admin approvals and ExtremeXOS.** Admin `plan_sha256` of profile plans now includes the device alias, platform and firmware, so a plan approved for one device or firmware is refused (`plan_changed`) on another. An ExtremeXOS PoE cycle needs `safeguard_seconds` of at least 221 with the default margin 45, and enabling an ExtremeXOS port is refused where disabling it is refused.
- **FortiOS `config_diff` and Auditor store.** FortiOS `config_diff` uses the line comparison (Myers) of the other platforms instead of positional comparison; FortiADC keeps positional comparison. The Auditor store runs in SQLite WAL mode; the first writer open converts an existing store once, and `store.sqlite-wal`/`-shm` belong to the store and to its backup.
- **Upgrade and re-enrollment.** Upgrade only from 1.0.9 by restoring its backup into a separate 1.0.10 instance; do not run `init` on the restored state. Re-enroll every Admin device (`admin enroll`), FortiOS and ExtremeXOS included, before its first change after the upgrade: every 1.0.9 enrollment is refused with `enrollment_required`. Approved `plan_sha256` values from a 1.0.9 preview do not pass after the upgrade; run a new preview.
- **Acceptance of the release candidate.** The MCP client checks, the installation by following the quickstart, the upgrade check from 1.0.9 and the release scan are part of the acceptance of the signed release candidate. The release notes describe the required checks and do not assert that publication acceptance has passed.

See the [1.0.10 release notes](release/notes-1.0.10.md) and the [changelog](CHANGELOG.md). The sections for 1.0.9, 1.0.8 and 1.0.7 below are kept as history.

## What's new in 1.0.9

NetOps 1.0.9 follows NetOps 1.0.8. It adds configuration captures and `config_diff` for ExtremeXOS, Cisco and Arista, FortiOS IPv6 route lookup and multi-VDOM reads, NX-OS vPC and EOS/EXOS MLAG views, ExtremeXOS optics and chassis summaries, Wi-Fi AP backhaul correlation and FortiADC schedule-pool triage. The Auditor gains `findings_summary` and collection while NetOps runs; Admin gains `expected_plan_sha256`, `admin_undo_preview`, the measured FortiOS `firewall service custom` profile and ExtremeXOS port admin-state and PoE cycles. Upgrading from 1.0.8 needs no inventory or credential change; only 1.0.8 is accepted as the previous release ([upgrade guide](https://github.com/radek-cerny-soukr/netops/blob/v1.0.9/docs/quickstart-1.0.md#upgrade-from-the-previous-release)).

- **Configuration captures and `config_diff` on ExtremeXOS, Cisco and Arista.** Configuration captures add narrowly gated ExtremeXOS, Cisco IOS, IOS XE, NX-OS and Arista EOS full views; each requires explicit configuration access, a supported live identity and device permission for the fixed command, and device refusal returns `device-refused`, never an empty snapshot ([identities and account requirements](docs/helper-configuration.md#configuration-captures-on-exos-cisco-and-arista)). `config_diff` compares snapshots on those five platforms with a shortest line edit script (Myers), refuses oversized comparisons with `config_diff_limit_exceeded` and does not compare hidden content (`hidden_lines_compared: false`). FortiOS/FortiADC retain positional comparison.
- **FortiOS multi-VDOM reads.** Catalogue, normalized-table and routing/VPN/health triage reads verify the session VDOM and context, label `data_scope`, and fail closed on ambiguous identity, context or interface ownership; only the enrolled current VDOM is read. A per-VDOM administrator logged in through an interface of its VDOM reads that VDOM directly once the device proves the login context (verified live on the FortiGate-60F 7.6.8 build3744 on 2026-11-15, task 222, source 7bec0b7, 112/112 checks passed). Multi-VDOM `config_read` with `redaction="minimal"` and `triage_flow` remain unsupported ([scope and refusals](docs/helper-configuration.md#fortios-multi-vdom-reads)).
- **More Helper reads.** FortiOS `ipv6_route_lookup` adds scoped IPv6 destination lookup. NX-OS vPC and EOS/EXOS MLAG summaries and members accompany the fixed `ssh_read` catalogue queries; they are not `switch_read` tables. ExtremeXOS optics/DOM and chassis summaries expose the measured metrics and partial evidence; physical DOM evidence is limited to the X440G2-12p-10G4 on 33.7.1.6-patch1-11 (two switches, one LX 1310 nm SFP each, read-only capture of 2026-11-13 23:42 UTC, task 64).
- **Wi-Fi backhaul and FortiADC schedules.** Helper can correlate a tunneled Wi-Fi client with its AP/radio and the AP's switch backhaul; the switch port belongs to the AP, not to the tunneled client. FortiADC SLB triage follows `schedule-list` through schedule-pool and schedule-group views and returns sourced candidate pools without claiming an active pool or backend health; schedule-window activity is not calculated.
- **Auditor while NetOps runs.** `collect`, `run` and `status` work through `docker compose exec` while NetOps runs, and a private store lock serializes writers; configuration and imports still require the stopped instance. `findings_summary` returns brief last-run findings across devices with severity/state/rule filters; it has no paging or historical detail.
- **Admin.** `expected_plan_sha256` optionally binds apply to the approved preview, and `admin_undo_preview` and CLI `admin undo --preview` show checks and impact without applying undo. Opt-in FortiOS `firewall service custom` supports create/update/delete and undo, measured end-to-end on 7.6.8 build3744 (`cli-script`) and 8.0.2 build0251 HA (`webhook`) on 2026-11-14 (tasks 168, 177 and 180). ExtremeXOS port `admin-state` updates and operator-only PoE cycles use the persistent UPM safeguard, measured only on 33.7.1.6-patch1-11 on X435-8P-4S/X440G2 (2026-11-14, tasks 171 and 184). Admin writes for Junos, Arista and Cisco are deferred to 1.0.10.
- **Base image and dependencies.** The pinned Python/Alpine base digest and compatible dependencies (FastMCP 4.1.3, PySNMP 7.1.32, cryptography 50.0.2) are refreshed. This does not claim that every dependency vulnerability is fixed or that release scans/signatures are complete.

See the [1.0.9 release notes](release/notes-1.0.9.md) and the [changelog](CHANGELOG.md). The sections for 1.0.8 and 1.0.7 below are kept as history.

## What's new in 1.0.8

NetOps 1.0.8 follows 1.0.7 on the same install, enrollment and audit procedures. It adds two daily-work reads, fixes FortiOS route and VLAN parsing, hardens the Auditor store and the HTTP response readers, and states the minimum requirements and the platforms on which the installation was run. Upgrading from 1.0.7 needs no inventory or credential change ([upgrade guide](https://github.com/radek-cerny-soukr/netops/blob/v1.0.8/docs/quickstart-1.0.md#upgrade-from-the-previous-release)).

- **CDP neighbours.** `switch_read(table="cdp_neighbor")` returns the CDP neighbours of Cisco IOS, IOS XE and NX-OS from the opt-in `cdp_neighbors` query: local port, full Device ID, neighbour port, management IP, platform and capabilities.
- **Linux tables.** `switch_read` returns interfaces (state, MAC; MTU for one enrolled interface), IP addresses with MAC and default gateway, IPv4 routes, ARP/ND neighbours and the bridge forwarding table of a Linux host, and `locate_endpoint` reads the Linux neighbour and bridge tables. A neighbour is never reported as a switch port: when a Linux host has the endpoint as a neighbour but no matching bridge port, the result stays `incomplete` unless another enrolled switch locates the endpoint.
- **FortiOS routes and VLANs.** Recursive BGP next hops, summary and Null routes, the route codes of FortiOS 7.6 and 8.0 and VLAN interfaces with `config ipv6` are parsed instead of reported as unparsed.
- **Tunnel-mode Wi-Fi clients.** A Wi-Fi client of a tunnel-mode SSID (the SSID default) is expected not to be learned on the switches between its access point and controller because its traffic is carried in CAPWAP to the FortiGate; `locate_endpoint` then reports it as not found in the checked data. Use `wifi_clients` or `wifi_triage` to identify the access point, then locate the access point through LLDP or its MAC. In the recorded run the client's MAC was absent from both checked switch FDBs; the cause of that absence was not established.
- **Stricter HTTP response handling and Auditor store.** The Wi-Fi REST reader (Helper) and the FortiOS REST collector (Auditor) refuse a chunk-size line that is not plain hexadecimal, which the Python 3.14.10 standard library still accepts (CVE-2026-103995); the Auditor checks the type of every expected schema object of a store. Admin `doctor` reads the journal once per request in its local checks.
- **Requirements and platforms.** [Minimum requirements](#minimum-requirements) (1 vCPU, 2 GiB RAM, 2 GiB disk, `NETOPS_CPUS=1` on a one-CPU host) and [Supported platforms](#supported-platforms): the quickstart procedure was run on Ubuntu 24.04 and 26.04, on rootless Docker (Ubuntu 24.04, Debian 13) and on Raspberry Pi OS 64-bit, including physical arm64 hardware.
- **Open dependency findings.** Some findings remain in the pinned base image. Depending on the finding, no fixed Python 3.14 release was available, the upstream fix is not yet packaged in Alpine 3.24, or no fix is released at all (the `sqlite3` shell finding). NetOps lists them with written assessments instead of claiming they are gone ([details](release/notes-1.0.8.md#known-dependency-findings)).

See the [1.0.8 release notes](release/notes-1.0.8.md) and the [changelog](CHANGELOG.md). Everything introduced by 1.0.7 (switch and router tables, `locate_endpoint`, Wi-Fi diagnostics, `triage_flow`) remains available and is described below; the 1.0.8 changes to it are listed above.

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

**✓** the command's output was captured live from that OS with a read-only account, and the tests parse that output · **docs** the output layout comes from the vendor documentation only, because the measured device had nothing to show (feature not configured, empty table, or command missing on the virtual image) · **–** not provided. Unless a cell names a later date, live captures used development builds of the 1.0.7 source on 2026-11-08 and 2026-11-09, and the Linux row comes from the 1.0.8 checks described below the table; virtual images do not establish hardware behavior (PoE, optics, stacking, forwarding), and no hardware Cisco, Arista or Juniper device was tested. A check mark records a dated capture or live acceptance result, not the current lab configuration; the endpoint column has the narrower scope in note ⁵. **replay** means offline replay of live captures; **transit** means a transit hop in a completed live endpoint search; **ARP** means captured IPv4 router/firewall input, without an end-to-end endpoint result. Measurement quality limits are in note ⁷.

Normalized tables (`switch_read`) and endpoint location:

| OS (profile) | Verified live on | Interfaces | VLAN | Port VLAN | MAC | ARP | LLDP | Routes | OSPF | BGP | LAG | STP | Errors / flaps | IP interfaces | `locate_endpoint` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ExtremeXOS (`extreme_exos`) | X435-8P-4S and three X440G2-12p-10G4 with 33.7.1.6-patch1-11; EXOS-VM 33.6.1.14 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | – | – | ✓ `aggregate`, `lag`⁴⁶ | – | ✓ CRC/TX | ✓ | live located: 13 physical end hosts on X440G2 by MAC; 11 also by IP (24/24 executed searches matched CLI; two IP searches not run because no ARP mapping was available) and an end host on EXOS-VM port 2, VLAN 10, 2026-11-11⁵ |
| Cisco IOS (`cisco_ios`) | IOSv 15.9(3)M12 (router), IOSvL2 15.2(20200924) (switch) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | live MCP fallback: show interfaces (2026-11-11) | ✓ | live located: end host on IOSvL2 Gi0/3, VLAN 10 untagged, 2026-11-11⁵ |
| Cisco IOS XE (`cisco_xe`) | IOL XE 17.18.2 (router image) | ✓⁹ router | docs | docs⁸ | docs | ✓ | ✓ | ✓ | ✓ | ✓¹ | docs⁶ | docs | live MCP fallback: show interfaces (2026-11-11) | ✓ | ARP in completed live search, 2026-11-10⁵ |
| Cisco NX-OS (`cisco_nxos`) | Nexus 9300v, NX-OS 9.3(12) | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓² | ✓ | ✓ | ✓¹ | ✓⁶ | ✓ | prior canonical replay; new capture refused | ✓ | live located, 2026-11-11⁵ |
| Arista EOS (`arista_eos`) | cEOS 4.36.1F | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | ✓⁶ | ✓ | ✓ errors; discards prior replay | ✓ | live transit, 2026-11-11⁵ |
| Junos ELS, EX/QFX (`juniper_junos_els`) | vJunos-switch 26.2R1.7 | ✓ | ✓ | ✓⁸ | ✓ | ✓ | ✓ | ✓ | ✓ | docs | docs⁶ | ✓⁶ | ✓ extensive | ✓ | live located: end host on ge-0/0/1, VLAN 20 untagged, 2026-11-11⁵ |
| Junos, other platforms (`juniper_junos`) | the same commands on vJunos-switch 26.2R1.7³ | ✓³ | – | – | – | ✓³ | ✓³ | ✓³ | ✓³ | docs | docs⁶ | – | replay on ELS switch | ✓³ | ARP³⁵ |
| FortiOS (`fortinet`) | FortiGate 80F, FortiOS 8.0.2 build0251 | ✓ link/speed/duplex | ✓ interface configuration | – | empty local bridge only | ✓ | ✓ local summary | ✓ IPv4 | – | – | – | – | – | ✓⁹ | ARP / own interface, 2026-11-10⁵ |
| FortiSwitch 224E-POE managed by a FortiGate | FortiGate 80F, FortiOS 8.0.2 build0251; switch firmware 8.0.1 recorded on 2026-11-07, not captured in the 2026-11-10 run | ✓ link/speed | ✓ interface configuration on FortiGate | ✓ configuration | ✓ | – | ✓ (summary, no management IP) | – | – | – | – | – | ✓ errors/drops | – | live located: AP port3, VLAN 100 untagged, 2026-11-10⁵ |
| Linux (`linux`) | Ubuntu 24.04.5; Debian 13.7 cloud; Proxmox VE on Debian 13.7 (CLI captures, 2026-11-13) | ✓ links, MAC; MTU of one enrolled interface | – | – | ✓ bridge FDB (static entries only on the Ubuntu host) | ✓ neighbors, ARP and ND | – | ✓ IPv4 | – | – | – | – | – | ✓ with MAC and default gateway | neighbors and bridge FDB on captured outputs; a bridge port stays `unverified` (`incomplete`) |

**Additional EXOS acceptance (2026-11-13).** The read-only EXOS acceptance of source `ad4ff3c` (2026-11-13), carried forward by the final 1.0.8 acceptance, compared eleven `switch_read` tables on one X435-8P-4S and three X440G2-12p-10G4, all 33.7.1.6-patch1-11: 44/44 independent table comparisons and 8/8 IP/MAC endpoint searches passed. LAG and aggregate were empty on two switches and populated on two X440G2 (sharing group 13, members 13–16, active 13 and 15). This adds live `port_vlan` evidence to the earlier replays; it does not qualify Admin writes, PoE, DOM or active MLAG.

**FortiSwitch qualification.** Only two 224E-POE managed through the FortiGate above were measured. The 29 port-state/error rows and 28 configured VLAN rows are the captured scope of these switches; port counts and naming on other models are unmeasured. MCLAG ICL, trunk and consistency were measured on one pair in one topology (2026-11-07, task 14, build 1.0.6); other peer counts, stacks and standalone FortiSwitch operation are unqualified. The dated 2026-11-10 endpoint evidence is one FortiAP on port3; the later 1.0.8 development-build reads (source 96ea561, 2026-11-12) located two hosts by IP and MAC on EXOS edge ports against fresh CLI. Neither result qualifies endpoint location behind a FortiSwitch trunk or in MCLAG. Other FortiSwitch models and firmware remain unmeasured.

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
IP/capabilities; CRC and flap counters stay null.

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

⁴ EXOS provides `table="aggregate"` using `show lacp` (`name`, `member_count`) and `table="lag"` using the explicitly enrolled `lag_summary` query (`show sharing`; `name`, `protocol`, `status`, `members`). No EXOS-VM `show sharing` output was captured; the empty case replays the empty output of the physical X435 with the EXOS-VM identity. A populated physical X440G2 33.7.1.6 sharing group with members was captured on 2026-11-10 and is replayed by the engine tests. Populated LACP aggregates were also captured on physical EXOS switches on 2026-11-08.

⁵ Live acceptance on 2026-11-11 located GNS3 end hosts behind IOSvL2 Gi0/3 (VLAN 10), NX-OS Ethernet1/2 (VLAN 20), EXOS-VM port 2 (VLAN 10) and vJunos ge-0/0/1 (VLAN 20), each by IP and MAC in two rounds across all seven enrolled targets, and 13 physical end hosts on ExtremeXOS X440G2 switches by MAC; 11 also by IP. All 24 executed searches matched the CLI forwarding table; two IP searches were not run because no ARP mapping was available. cEOS was observed as transit in a completed live search; IOSv and IOL XE were included as router ARP readers. No access-host result on these router images is claimed. Endpoint parsers are also tested on real captures. The physical NAS case was live located behind X440G2; the enrolled inter-switch link is transit. FortiLink acceptance on candidate source `51840b1` located the AP on port3, VLAN 100 untagged (`edge_behind_ap`, eight reads), and the second switch MAC as `own_interface_of_target` (three reads). An enrolled device's own address is not an access-host result. Phones remain unverified. Common Junos was not separately enrolled; IOS XE switch layouts remain documentation-only.

⁶ Earlier IOS/EOS/NX-OS LAG captures remain dated evidence. In the later MCP run, LAG was empty on IOSvL2, NX-OS and cEOS, refused (`permission_denied`) on IOSv and IOL XE, and LACP was not running on vJunos; EXOS-VM `aggregate` was empty. No populated LAG/aggregate table was verified on any of the seven OS in that 2026-11-09 run; this does not negate the later physical EXOS sharing capture. The 2026-11-10 acceptance also exercised OSPF/LAG; exact per-OS populated row counts are unavailable, so no additional per-OS positive LAG claim is made here. vJunos RSTP port output was captured earlier on 2026-11-09 with temporary configuration; in the later run STP was disabled (`Spanning-tree is not enabled at global level.`, `not_applicable`).

⁷ Measurement quality: sequential reads are not an atomic snapshot (cEOS FDB changed from 10 to 7 rows); IOL XE reports normalized `model=null`; identity responses based only on `ssh_read version` carry warnings because the restricted inventory did not enable the additional identity queries; IOSvL2 is an experimental image and cEOS an engineering build. These limits bound the evidence above.

⁹ `ip_interface` (IPv4 address, prefix length, SVI VLAN, state) was added on 2026-11-09 and is parsed from the anonymised live outputs of `show ip interface brief` with `show ip route` (IOS, IOS XE, NX-OS), `show ip interface brief` (EOS), `show ipconfig` with `show vlan` (EXOS), `show interfaces terse` (Junos) and `get system interface` (FortiGate 80F, FortiOS 8.0.2 build0251, read-only account, 2026-11-09); FortiOS gives no link state, so `oper_status` stays null there. On the IOL XE router image the `interface` table comes from `show ip interface brief` (name, status, protocol) when the target declares `device_types: ["router"]` without `switch`; the IOSv router uses the same rule.

IOS / IOS XE IPv4 route lookups use the authorized whole routing table as a fallback when the direct lookup is empty.

Catalogue, triage, Wi-Fi, Auditor and Admin:

FortiLink capacity is bounded by the 5-second connection spacing on each FortiGate: at the observed ~5.6 seconds per read, an IP lookup with all edge queries fits roughly four managed switches (N + 6 reads) into 59.5 seconds; larger sites can return partial findings with incomplete coverage. Startup, latency and multiple matching switches reduce this capacity.

| Platform | `ssh_read` templates 1.0.6 → 1.0.7 | Run live for 1.0.7¹⁰ | Triage and Wi-Fi | Auditor | Admin |
|---|---|---|---|---|---|
| FortiOS (FortiGate) | 108 → 119 | the 7 new Wi-Fi reads, `system_interfaces`, local physical/VLAN/LLDP and empty bridge reads (live MCP, 2026-11-11), the 3 FortiSwitch port/VLAN reads and the `triage_routing` and `triage_flow` reads, FortiGate 80F 8.0.2 | new: `triage_flow` (FortiGate 80F 8.0.2, VDOMs disabled), `wifi_triage`, `wifi_clients`, `wifi_aps_live`, `wifi_rogue` (FortiGate 80F 8.0.2 with two FortiAP; live Wi-Fi needs [optional REST token](docs/fortios-wifi-rest.md#create-access-on-fortigate)); `triage_routing`, `triage_health`, `triage_vpn` | 37 rules | address, address group, DHCP reservation, firewall policy (unchanged) |
| FortiADC | 33 → 33 | Selected catalogue reads, nine diagnostic recipes and `triage_slb` exercised live on FortiADC-KVM 7.6.7, 2026-11-11; not a full 33-template qualification | `triage_slb` (FortiADC-KVM 7.6.7) | 8 rules on an exported configuration | new in 1.0.10: pool member status (enable/disable/maintain), add (created disabled) and remove (disabled/maintain, not the last member) through MCP `admin_preview`/`admin_apply`/`admin_undo_preview`/`admin_doctor`/`admin_status` and CLI `preview`/`apply`/`undo`/`enroll`/`recover`, table `load-balance pool/pool_member`, FortiADC-KVM 7.6.7 build0676 only (standalone); return: compensating write of the inverse in the same run and by `recover`, no on-device timer (none found on 7.6.7); no auditor rules in Admin; `pool-member*` commands deprecated |
| FortiSwitch 224E-POE (FortiLink) | existing FortiOS catalogue reads | MAC/LLDP, port-stats and configured VLANs; live AP located, 2026-11-10, through FortiGate 80F 8.0.2 build0251 | `switch_read` with `managed_switch` | – | – |
| ExtremeXOS | 48 → 65 | 63 earlier catalogue reads plus VLAN detail on EXOS-VM; VLAN detail also on physical X435/X440G2; `lag_summary` replays an empty physical X435 sharing capture (also with the EXOS-VM identity) and populated physical X440G2 sharing captures (2026-11-10) | – | 9 rules | VLAN, port display string, port VLAN membership; new in 1.0.9: port admin state (CLI and MCP) and PoE cycle (CLI only), 33.7.1.6 only (patch level and model are not checked; measured only on 33.7.1.6-patch1-11 on X435-8P-4S/X440G2) |
| Cisco IOS | 27 → 49 | 43, docs-only 6 (error counters, environment, optics, PoE, stack) | – | – | new in 1.0.10: interface description and admin state (IOSv 15.9(3)M12, IOSvL2 15.2(20200924:215240)) and access VLAN (IOSvL2 only), CLI and MCP; GNS3 lab images only; safeguard = `configure terminal revert timer` (whole-minute granularity), whose expiry returns the whole running configuration; archive and privilege-15 write account required ([details](docs/admin-configuration.md#cisco-ios-and-ios-xe-interface-description-admin-state-and-access-vlan)) |
| Cisco IOS XE | 27 → 50 | 32, docs-only 18 (switch and platform reads) | – | – | new in 1.0.10: interface description and admin state (IOL XE and IOL-L2 XE 17.18.2) and access VLAN (IOL-L2 XE only), CLI and MCP; GNS3 lab images only, no hardware platform measured; same safeguard as IOS ([details](docs/admin-configuration.md#cisco-ios-and-ios-xe-interface-description-admin-state-and-access-vlan)) |
| Cisco NX-OS | 30 → 61 | 58, docs-only 3 (HSRP, VRRP, DHCP snooping) | – | – | new in 1.0.10: interface description, admin state and access VLAN (CLI and MCP), Nexus 9000v NX-OS 9.3(12) only, a physical Nexus 9000 is not verified; safeguard = checkpoint and a one-time `feature scheduler` job (enabled once by the administrator) with a granularity of one minute, which returns the whole running configuration; an unverified change is returned at once by `configure replace` ([details](docs/admin-configuration.md#cisco-nx-os-interface-description-admin-state-and-access-vlan)) |
| Arista EOS | 33 → 54 | 53, docs-only 1 (PoE) | – | – | new in 1.0.10: interface description, admin state and access VLAN (CLI and MCP), cEOSLab 4.36.1F only; safeguard = configure session with commit timer, whose expiry returns the whole running configuration; write account with privilege 15 at login ([details](docs/admin-configuration.md#arista-eos-interface-description-admin-state-and-access-vlan)) |
| Junos ELS (EX/QFX) | 29 → 55 | 51, docs-only 4 (Virtual Chassis, PoE) | – | – | new in 1.0.10: interface description, admin state and access VLAN by VLAN name (CLI and MCP), vJunos-switch 26.2R1.7 only (physical EX not measured); safeguard = `commit confirmed 10` in `configure exclusive`, restarted by the change commit, whose expiry returns the whole configuration; write account with `configure`, `view` and `view-configuration` ([details](docs/admin-configuration.md#juniper-junos-interface-description-admin-state-and-access-vlan)) |
| Junos (common) | 25 → 41 | 41, on the vJunos-switch | – | – | – |
| Linux | 16 → 16 | `kernel` (`uname -a`), CLI/MCP comparison, 2026-11-11; not a full 16-template qualification | – | – | – |
| Ruckus Unleashed | 4 → 4 | – | – | – | – |
| **Total** | **380 → 547** | | | | |

¹⁰ The template was sent to the device with the read-only account (on FortiADC, with the `admin-bounded` account for the queries that require it). This includes empty and "not configured" answers and the reads that the built-in read-only role refuses: `show logging` and `stp_inconsistent` on IOS and IOS XE privilege 1, `stp_summary` on the IOSv router, and the two Junos log reads, which need more than the built-in `read-only` class. The per-template results are in the [Cisco](components/netops-helper/docs/vendor-cli-references/cisco.md#lab-measurements-gns3-lab-2026-11-08), [Arista](components/netops-helper/docs/vendor-cli-references/arista-eos.md#lab-measurements-gns3-lab-2026-11-08), [Junos](components/netops-helper/docs/vendor-cli-references/juniper-junos.md#lab-measurements-gns3-lab-2026-11-0809) and [ExtremeXOS](components/netops-helper/docs/vendor-cli-references/extreme-switch-engine.md#exos-vm-336114-compatibility) notes; device roles in [Accounts and least privilege](components/netops-helper/docs/read-only-accounts.md), details in [Verified platform support](docs/verified-support.md#helper-coverage-by-os-netops-108).

## Highlights

- **One product, one image.** A single multi-architecture image for `linux/amd64` and `linux/arm64`, pinned by digest in the release `env.example`. Core, Helper, Auditor and Admin share one dependency closure and one product version.
- **One MCP endpoint.** HTTPS only, bearer token, instance-local certificate authority with name constraints and an automatically renewed short-lived server certificate.
- **Audit before action.** MCP requests are durably recorded before dispatch and responses before delivery. The local diagnostic `/healthz` endpoint remains available during an audit failure; successful health checks are not audited. If the audit cannot be written, the operation is refused (`audit_unavailable`). The audit goes to a TLS syslog receiver (recommended) or to a local, size-limited log.
- **Role isolation.** Gateway and roles run as separate long-running processes under their own UID/GID (51000–51003), with no Linux capabilities, `no-new-privileges`, a read-only root filesystem and CPU, memory and process limits. A short start-up bootstrap uses the capabilities listed in `compose.yaml` and then drops all of them.
- **Explicit device scope.** No device is enrolled implicitly. Each role has its own inventory and credentials; MCP clients pass enrolled aliases, never device credentials.
- **Device output is untrusted data**, never instructions.
- **Safeguarded changes.** Admin uses prediction, readback by an independent check account and verified return; on Ruckus the readback uses a separate session that may use the write account. FortiOS, ExtremeXOS, Cisco IOS, IOS XE, NX-OS, Arista EOS and Junos use device safeguards. FortiADC and Ruckus use compensating writes. An unknown result requires operator review before further changes.
- **Errors stay visible.** Refused, failed or uncertain operations are MCP errors (`isError`) with their full structured result.
- **Signed releases.** The checksum list is signed with Sigstore; SBOMs, vulnerability scans with written assessments and acceptance reports are covered by it.

## Roles and what they can do

`netops selftest` prints the MCP tool names of each role: **31 Helper, 8 Auditor and 10 Admin tools**. Core has no MCP tools.

### Core

The shared engine used by the other roles: inventory and credential-vault schemas and the SSH/SFTP transport with host-key pinning. See [Core inventory](components/netops-core/docs/inventory.md) and [Core vault](components/netops-core/docs/vault.md).

### Helper — read-only diagnostics

Read-only queries against enrolled targets, using a named query catalogue of **1,107 query templates across 11 platform profiles** (`linux`, `fortinet`, `extreme_exos`, `cisco_ios`, `cisco_xe`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `juniper_junos_els`, `ruckus_unleashed`, `fortiadc`). The `ssh_read` catalogue excludes running/startup/full configuration (except Ruckus `config_settings`, which runs a fixed `show config` and returns only allowlisted, redacted settings), arbitrary CLI, debug activation, packet capture, shells and every write or lifecycle action. Selected FortiSwitch queries read enrolled managed-switch state and configuration. Separately, `fortios_diagnostics` offers bounded sniffer and flow diagnostics, and `config_read` offers opt-in configuration capture. Each query accepts its documented parameter types and enrollment scope. See the [query catalogue](components/netops-helper/docs/query-catalog.md) and [parameter exceptions](docs/helper-configuration.md#optional-helper-fields).

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
| `switch_read` | Normalized interface, IP interface, interface error counters, port VLAN tagging/mode, VLAN, MAC, ARP/ND, LLDP, route, OSPF neighbour, BGP peer, LAG and STP records for EXOS, IOS/IOS XE, NX-OS, EOS and Junos (the tables of each OS in [What's new](#coverage-by-vendor-and-operating-system)), CDP neighbour records of IOS, IOS XE and NX-OS, interface, IP interface, IPv4 route, ARP/ND and bridge FDB records of a Linux host, ARP/ND, IPv4 routes, IP interfaces, physical interfaces, VLAN interfaces, LLDP and bridge MAC of a FortiGate and managed FortiSwitch MAC/LLDP, link/speed, errors/drops and configured VLANs via an enrolled `managed_switch` serial; source hashes, coverage and explicit unparsed lines ([coverage](components/netops-helper/docs/tools.md#normalized-tables-switch_read)) |
| `locate_endpoint` | Correlates 1–64 enrolled targets by IP, MAC or exact hostname. The 59.5-second deadline includes up to 40 reads for at most eight targets, or up to 8 reads per alias for a larger search. Reports the port, VLAN, vantage and any missing evidence. See [endpoint location](components/netops-helper/docs/tools.md#endpoint-location-locate_endpoint). |
| `ssh_read` | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`) |
| `sftp_stat` | Metadata within enrolled roots; no file content |
| `schema_read` | Not a supported workflow in 1.0 (see [Known limitations](#known-limitations)) |
| `fortios_diagnostics` | Opt-in bounded FortiOS and FortiADC recipes. Identity, VDOM, account and recipe permissions apply. See [Helper tools](components/netops-helper/docs/tools.md). |
| `config_read` / `config_diff` | Opt-in redacted configuration capture and comparison for FortiOS, FortiADC, ExtremeXOS, Cisco IOS, IOS XE, NX-OS, Arista EOS, Junos and Ruckus. See [Helper tools](components/netops-helper/docs/tools.md). |
| `snmp_get` | SNMPv3 authPriv GET (SHA256, AES128) with the `snmp_credential` of the target, 1 to 20 OIDs, UDP port within the egress scope; SNMPv1, SNMPv2c, noAuthNoPriv and authNoPriv are not supported |
| `ftp_list` | FTP and FTPS refused in the shipped profile |
| `triage_health` | Fixed health reads with sourced findings. Availability and evidence depend on the platform. |
| `triage_routing` | Bounded route diagnostics for an enrolled destination. Platform-specific reads report route, adjacency and probe evidence where available. |
| `triage_flow` | IPv4 flow evidence on FortiOS (route, policy and session) and on IOS and IOS XE (enrolled ingress interface and addresses; RIB, CEF, ingress ACL and policy routing). Incomplete input or a missing device result can limit the verdict. |
| `triage_vpn` | One enrolled FortiOS IPsec tunnel, with selector state, traffic and error counters, routing and IKE context. |
| `wifi_clients` / `wifi_aps_live` / `wifi_rogue` | Live FortiOS clients with RSSI/SNR, managed AP state and rogue/interfering observations through a separate RO REST token; fixed GETs, certificate pin or CA, no writes; see [setup and security](docs/fortios-wifi-rest.md) |
| `wifi_triage` | Bounded client triage for FortiOS, Ruckus Unleashed and Cisco Catalyst 9800. A FortiOS hostname lookup reports `identity_trust: client_supplied`. Available association, RF and history evidence varies with the controller. |
| `triage_slb` | One enrolled FortiADC virtual server through pool, members, health checks, TLS, WAF and DoS with sourced findings. |
| `fortiswitch_overview` | FortiGate-managed switch inventory and runtime state through the enrolled read-only REST scope. |
| `firewall_policy_hits` | FortiOS policy hit counters with an optional unused-only view. |
| `triage_port` | Correlates supported interface, VLAN, neighbour and port-health reads. |
| `triage_nxos_path` | Correlates NX-OS interface and IPv4 path evidence. |
| `vpc_compare` | Compares vPC state across two enrolled NX-OS targets. |

Each target has its own scope (enabled queries, egress addresses and ports, optional SFTP roots) and a per-target rate limit (default 30 requests per 60 seconds; the triage tools also have a sublimit of the same size; `triage_health`, `triage_routing`, `triage_vpn` and `triage_slb` report progress). The account must be independently verified as read-only on the device; the JSON declaration alone does not restrict it.

`netops check-intent <plan>` checks one intent plan from the `helper.intent` entries of the inventory through `switch_read` on the HTTPS MCP endpoint, prints a JSON result and exits `0` for `pass`, `1` for `fail` and `2` for `incomplete`. With `--notify` and a webhook in `NETOPS_DISCORD_WEBHOOK`, a `fail` result makes one attempt to send a summary of the mismatches to Discord; `notification` reports the result. It changes no device.

Docs: [Helper configuration](docs/helper-configuration.md) · [Helper tools](components/netops-helper/docs/tools.md) · [Query catalogue](components/netops-helper/docs/query-catalog.md) · [Account boundaries](components/netops-helper/docs/read-only-accounts.md)

### Auditor — configuration audit

Evaluates FortiOS, ExtremeXOS and FortiADC configurations against a rule catalogue (**37 FortiOS, 9 EXOS and 9 FortiADC rules**) and stores finished findings in a private store.

Operator commands (the running instance also accepts `auditor run`, `collect` and `status` through `docker compose exec`):

- `auditor run` evaluates a configuration snapshot from standard input offline, without contacting a device; output as text, `--json` or `--sarif`.
- `auditor collect` reads the configuration from an explicitly configured device through one pinned channel (`ssh` or `fortios-rest`, with host-key or TLS fingerprint verification); the Auditor never changes a device, but on FortiOS it collects with a `super_admin` administrator, which can write (see [Known limitations](#known-limitations)).
- `auditor import-snapshot` and `auditor import-policy` place reusable snapshots and operator management policies into private state.
- `--baseline-accept` accepts the findings of a run into the device baseline; later runs report them as `open-known`.

The eight MCP tools only read stored findings; they contact no device, start no collection and write nothing:

| Tool | Behavior |
|---|---|
| `audit_status` | Per device: `fresh`, `stale`, `never` or `incomplete`, finding counts per severity and state |
| `list_rules` | Rules of the configured catalog with ID, version, class, severity, title and references |
| `rule_detail` | One rule with remediation, evidence fields and known false positives |
| `list_findings` | Findings of the last run with state (`new`, `open-known`, `gone`, `not-evaluated`) and optional grouping by object |
| `finding_detail` | One finding with its baseline and suppression record |
| `compare` | `added`, `removed` and `kept` findings between two completely evaluated runs |
| `findings_summary` | Brief filtered findings across the devices of the tenant (rule, object, severity, state; no evidence), with counts before and after the filter |
| `schema_report` | Refused in 1.0 (no schema report manifest is configured) |

Docs: [Auditor operator workflows](docs/quickstart-1.0.md#auditor-operator-workflows) · [Auditor tools](components/netops-auditor/docs/tools.md) · [Collection channels](components/netops-auditor/docs/channels.md) · [Management policy](components/netops-auditor/docs/management-policy.md)

### Admin — bounded, reversible changes

Admin is enabled by default (`init --disable-admin` omits its worker and MCP tools) and refuses device changes until it is configured and the device is enrolled. Supported change scope:

- **FortiOS:** firewall addresses, groups, policies, services, VIPs and IP pools, DHCP reservations, DNS, interfaces, managed switch ports, static routes and IPsec selectors; managed-switch port bounce and PoE cycle; targeted session clear, DHCP lease release and IPsec selector recovery. Managed-switch port bounce was verified live on the FortiGate 60F with a FortiSwitch 108E-series switch (an unused port, software admin up, down, up), and PoE cycle is covered by automated tests only. Admin refuses both on FortiOS 8.0.1 and later because the webhook safeguard has no REST inverse for either profile.
- **ExtremeXOS:** VLANs, ports, link settings, sharing, MLAG, STP, routing, ACLs, management services, port bounce and PoE cycle, configuration save and scoped clears.
- **FortiADC:** pool members, real and virtual servers, certificate import and selected session, persistence and WAF blocked-IP clears.
- **Cisco IOS and IOS XE:** interfaces, VLANs, trunks, EtherChannel, routes, ACLs, DHCP, management settings, combined plans, port bounce and PoE, configuration save, and scoped counter, MAC, ARP and IPv6 neighbor clears. Successful IPv6 neighbor clears are covered by automated tests only. Admin refuses per-address IPv6 neighbor clears on both the IOL XE router and the IOL-L2 XE switch. On Catalyst 9800, Admin can disconnect one wireless client (automated tests only).
- **Cisco NX-OS:** interfaces, VLANs, trunks, port channels, vPC, routes, DHCP relay, ACLs, management settings, combined plans, port bounce, configuration save, and scoped counter, MAC, ARP and IPv6 neighbor clears. Successful IPv6 neighbor clears are covered by automated tests only.
- **Arista EOS:** interfaces, VLANs, trunks, port channels, MLAG, STP, routing, ACLs, DHCP, management settings, port bounce and PoE, configuration save, scoped clears and BGP soft refresh.
- **Juniper Junos:** interfaces, VLANs, IRB, LAG, RSTP, routing, filters, DHCP, management settings, combined plans, port bounce and PoE, scoped counter, MAC, ARP and IPv6 neighbor clears, and BGP refresh. Successful IPv6 neighbor clears and BGP refreshes are covered by automated tests only. SRX security zones, address books, security policies and NAT are covered by automated tests only.
- **Ruckus Unleashed:** WLAN lifecycle, security, VLAN, isolation, limits and DHCP relay for enrolled WLANs.

Device safeguards include FortiOS automation, ExtremeXOS UPM, IOS and IOS XE revert timers, NX-OS scheduled checkpoints, EOS configuration sessions and Junos confirmed commits. FortiADC and Ruckus Admin return eligible changes with a verified compensating write or operator recovery. Changes require enrollment, protected-object checks, a journal, audit and readback. Ruckus can use one account for writes and checks. A blocked device requires operator review. Scoped clears require explicit confirmation and have no undo. Configuration saves, port bounces, PoE cycles and IPsec selector recovery have no undo either.

| MCP tool | Behavior |
|---|---|
| `admin_doctor` | Readiness report without a device change; optional `local=true` checks local readiness only |
| `admin_preview` | The planning checks of apply without applying the change (a FortiOS session-clear preview temporarily sets and resets the diagnostic session filter): proposed commands, prediction and refusal reasons |
| `admin_apply` | Executes the approved change, combined plan or scoped clear. Results include `confirmed`, `reverted`, `rejected`, `unknown` and `revert-failed`. |
| `admin_undo_preview` | The planning checks of `admin undo` for a confirmed `change_id` without a device change: proposed inverse commands, prediction and refusal reasons |
| `admin_undo` / `admin_unblock_preview` / `admin_unblock` | Opt-in with `mcp_undo: true`. `admin_undo` takes the approved `plan_sha256` from `admin_undo_preview` as `expected_plan_sha256`. The read-only `admin_unblock_preview` returns `unblock_sha256`, which `admin_unblock` takes as `expected_unblock_sha256` after approval. |
| `admin_status` | The stored operation record by `change_id` or `request_id` |
| `admin_schema_preview` / `admin_schema_apply` | Schema transactions; not a supported workflow in 1.0 |

Operator commands (instance stopped), not MCP tools:

- `admin enroll` performs a real temporary probe change and lets the on-device safeguard return it (on FortiADC, the compensating delete of a disabled probe member); `admin doctor` then has to report `"ready": true`. With `admin doctor --local`, exit 0 means only local readiness; remote readiness remains unverified.
- `admin undo` returns a confirmed change as a new safeguarded operation with its own change ID.
- `admin recover` inspects and settles an interrupted or unknown operation using its saved safeguard and original state.
- `admin status`, `admin notify-retry` and `admin unblock` (for a person who has inspected the record and the device).
- `admin poe-cycle` and `admin port-bounce` power-cycle or bounce one port behind a rollback safeguard, without undo. For FortiGate-managed ports, port bounce was verified live on the FortiGate 60F with a FortiSwitch 108E-series switch (an unused port) and PoE cycle is covered by automated tests only. Admin refuses both on FortiOS 8.0.1 and later because the webhook safeguard has no REST inverse for either profile. `admin certificate-import` previews or imports a new FortiADC certificate from private files.
- `admin backup` (FortiOS), `backup-exos`, `backup-ios`, `backup-xe`, `backup-nxos`, `backup-eos` and `backup-junos` preview a backup and, with the approved `plan_sha256`, export it encrypted with `NETOPS_BACKUP_KEY` into a private directory. `backup-unseal`, `backup-exos-unseal` and `backup-junos-unseal` authenticate a backup and extract it to a private file for a restore. `restore-junos` previews and restores a Junos backup with `load override` under `commit confirmed`.

By default, a person runs `admin undo` or `admin unblock` at the operator console. With `mcp_undo: true`, `admin_undo` and `admin_unblock` require the digest of their respective approved previews. `admin_unblock_preview` is read-only and supplies the unblock digest.

Docs: [Admin configuration](docs/admin-configuration.md) · [Admin MCP tools](docs/admin-configuration.md#mcp-tools)

## Supported devices and firmware

The exact model, build, account and operation define the evidence. For an untested build on a recognized platform, operations that report `firmware_support` can proceed with status `untested` and an explanatory message. Paths such as Helper triage and FortiOS backup export also emit a `firmware_untested` warning. Permissions, readback and safeguard checks still apply.

| Platform | Documented scope |
|---|---|
| FortiOS | FortiGate 60F on 7.6.8 build3744 and FortiGate 80F HA primary on 8.0.2 build0251. Live 1.0.12 development checks include interface and routing reads, IPsec detail, firewall policy hit counts, endpoint data and bounded probes. Admin apply, readback and return for selected profiles were measured on the 60F. Earlier virtual-image evidence covers 7.6.7 build3704 and 8.0.0 build0167. |
| FortiSwitch | Two FortiGate-managed 224E-POE switches on 8.0.1 build0069. Live Helper checks cover switch inventory and endpoint correlation through the FortiGate 80F. Positive managed-switch PoE and stacking results remain unmeasured. Managed-switch port bounce was verified live on the FortiGate 60F with a FortiSwitch 108E-series switch (an unused port, software admin up, down, up), and PoE cycle is covered by automated tests only. Admin refuses both on FortiOS 8.0.1 and later because the webhook safeguard has no REST inverse for either profile. |
| FortiADC | Standalone FortiADC-KVM 7.6.7 build0676. Live Helper checks include interface and load-balancing reads, certificate inventory and bounded capture. Live Admin checks include pool-member changes, certificate import with fingerprint verification, and the replacement of a certificate-group member with undo; an import alone has no Admin undo. HA pair synchronization and changes have automated coverage only. Auditor evaluates exported text with identity metadata. |
| ExtremeXOS | EXOS-VM 33.6.1.14 and physical X435/X440-G2 on 33.7.1.6-patch1-11. Live checks cover selected Helper reads and Admin scenarios on virtual and physical switches. Physical switches returned optical telemetry. Measured PoE reads showed searching or zero draw. |
| Cisco IOS | IOSv 15.9(3)M12 and IOSvL2 15.2(20200924:215240) lab images. Live checks cover selected Helper health, port and service reads and Admin change and return scenarios. Catalyst PoE and DOM are covered by automated tests only. |
| Cisco IOS XE | IOL XE router and IOL-L2 XE switch, both 17.18.2. Live checks cover selected Helper reads and Admin change and return, including combined plans. Catalyst 9800 wireless and HA reads, Catalyst 9800 client disconnect, QFP diagnostics and physical PoE are covered by automated tests only. |
| Cisco NX-OS | Nexus 9000v (N9K-C9300v) on 9.3(12). Live checks cover selected port, switching and management reads and Admin change and return, including combined plans. Positive DOM telemetry is covered by automated tests only. |
| Arista EOS | cEOSLab 4.36.1F. Live checks cover selected Helper reads and Admin change and return. Physical PoE changes have automated coverage only. Hardware DOM remains unqualified. |
| Juniper Junos | vJunos-switch ELS (reported model ex9214) on 26.2R1.7. Live checks cover selected switch and firewall-filter reads and Admin change and return, including combined plans. SRX-specific diagnostics and security changes, and physical PoE, are covered by automated tests only. |
| Ruckus Unleashed | R610 on Ruckus Unleashed 200.15.6.212.27. Live checks cover selected controller and client reads, Wi-Fi triage and WLAN Admin configuration readback. The live WLAN checks verify configuration. Client association and security updates to an active WLAN remain unmeasured. |
| Linux | Earlier Helper evidence for Ubuntu 24.04.5, Debian 13.7 and Proxmox VE on Debian 13.7. |

Live verification of NetOps 1.0.12 on 2026-11-21: this summary covers selected development-build checks from 2026-11-17 through 2026-11-21 on physical devices and lab images, including FortiOS 7.6.8 build3744 and FortiOS 8.0.2 build0251, and standalone FortiADC 7.6.7 build0676. See [verified platform support](docs/verified-support.md#live-verification-of-netops-1012) for the scope of the evidence and hardware limits.

Live verification of NetOps 1.0.11 on 2026-11-16: a locally built image of the development 1.0.11 source before the release candidate, Admin with its separately enrolled write and check accounts; no other change of 1.0.11 was verified live. On vJunos-switch 26.2R1.7 (ELS) in the GNS3 lab (test port ge-0/0/2), the expiry of `commit confirmed` after an immediate return and after an interrupted session was measured through the device command line: it returns the configuration before the newest `commit confirmed`. After the fix, Admin passed the operator command line scenarios on the same switch, including a forced readback failure returned at once with a plain commit (`reverted`), with the configuration equal before and after; the MCP tools were not called in these runs. The quickstart cosign block without sudo was run once on Debian 13 lab machines (amd64 and arm64) under an account that also had sudo rights; an account without them was not used. Details are in [verified support](docs/verified-support.md#live-verification-of-netops-1011) and the [release notes](release/notes-1.0.11.md#changes-in-1011).

Live verification of NetOps 1.0.10 on 2026-11-16: development builds of the 1.0.10 source before the release candidate, Admin with its separately enrolled write and check accounts, measured on 2026-11-15 and 2026-11-16 as dated in each sentence. On 2026-11-15, Admin on cEOSLab 4.36.1F in the GNS3 lab passed the operator command line scenarios. On 2026-11-16, Admin on IOSv 15.9(3)M12, IOSvL2 15.2(20200924:215240), IOL XE 17.18.2 and IOL-L2 XE 17.18.2, on a Nexus 9000v with NX-OS 9.3(12) and on vJunos-switch 26.2R1.7 (ELS) in the GNS3 lab passed the operator command line scenarios and, after the safeguard fixes, repeated runs including a forced readback failure (IOS and IOS XE on IOSvL2 and IOL XE); the MCP tools were not called in these runs. On 2026-11-16, Admin on FortiADC-KVM 7.6.7 build0676 (standalone) changed pool members through the common Admin path, including MCP `admin_preview`, `admin_apply` with `expected_plan_sha256` and `admin_undo_preview`, SIGKILL and `admin recover`, with the full configuration equal before and after. Details, and later fixes covered by automated tests only, are in [verified support](docs/verified-support.md#live-verification-of-netops-1010) and the [release notes](release/notes-1.0.10.md#changes-in-1010).

Live verification of NetOps 1.0.9 on 2026-11-15: development builds of the 1.0.9 source before the release candidate, measured from 2026-11-13 to 2026-11-15 as dated in each sentence. On 2026-11-15, a lab FortiGate-60F with FortiOS 7.6.8 build3744 in multi-VDOM mode: per-VDOM ARP, routing and IPsec matched independent CLI reads, reads beyond that account's VDOM were refused, and root-scoped reads and global health triage passed their control checks (112/112, source `7bec0b7`). On 2026-11-14, FortiADC 7.6.7 build0676 on FortiADC-KVM: `triage_slb` schedule-list references, candidate pools and the unavailable/recovered virtual-server states matched CLI reads (76/76, source `6d50417`), without claiming the active pool or calculating schedule-window activity. On 2026-11-13 at 23:42 UTC, two physical X440G2-12p-10G4 switches with ExtremeXOS 33.7.1.6-patch1-11 supplied read-only DOM captures, one LX 1310 nm SFP each; X435 optics and virtual hardware sensors remain unqualified. On 2026-11-14, IOSv 15.9(3)M12, IOL XE 17.18.2, N9300v 9.3(12) and cEOS 4.36.1F passed the corrected configuration-diff scenarios; X440G2 33.7.1.6-patch1-11 and IOSv 15.9(3)M12 passed the later hidden-line diff checks (33/33, source `2984f96`). On 2026-11-14, cEOS 4.36.1F supplied inactive MLAG and empty member results, and N9300v 9.3(12) refused vPC commands with the feature disabled; these results do not verify active peers ([verified support](docs/verified-support.md#live-verification-of-netops-109)).

Live verification of NetOps 1.0.8 on 2026-11-12: development builds of the 1.0.8 source before the release candidate, read-only device accounts, and Admin with its separately enrolled accounts. The CDP output of IOSv 15.9(3)M12, IOSvL2 15.2(20200924), IOL XE 17.18.2 and Nexus 9300v with NX-OS 9.3(12) in the GNS3 lab (`table="cdp_neighbor"`), and the five Linux tables of an Ubuntu 24.04.5 host (`ip_interface` then from `ip address show`; the released `ip -brief address` form is covered by CLI captures of 2026-11-13), compared with independent CLI reads. A FortiGate with two FortiAP: the Wi-Fi REST reads and `wifi_triage`, and two FortiSwitch 224E-POE behind it. FortiOS routes and VLANs of a FortiGate 60F with FortiOS 7.6.8 build3744 and a FortiGate 80F with FortiOS 8.0.2 build0251 were read live; the fixes of their parsing are verified on the stored CLI captures, not on a new live run ([verified support](docs/verified-support.md#live-verification-of-netops-108)). Admin `doctor --local` and full `doctor` passed on runtime 1.0.8 configured for a FortiGate 60F.

Live verification of NetOps 1.0.7 on 2026-11-08: development builds of the 1.0.7 source before the release candidate, read-only accounts only. A physical FortiGate 80F in active-passive HA mode (primary unit, single VDOM) with FortiOS 8.0.2 build0251: the reads of `triage_routing` and `triage_flow` (routes, policy routes, SD-WAN, ARP, policy lookup, sessions of a flow), the seven Wi-Fi reads for a read-only account, `wifi_triage` and the read-only Wi-Fi REST endpoints of `wifi_clients`, `wifi_aps_live` and `wifi_rogue`; the other HA member was not read. Four physical ExtremeXOS switches (X435-8P-4S and three X440G2-12p-10G4) with 33.7.1.6-patch1-11 (X435 booted the secondary image), and a GNS3 lab with IOSv 15.9(3)M12, IOSvL2 15.2(20200924), cEOS 4.36.1F and EXOS-VM 33.6.1.14: the catalogue templates available on that date, with gaps. Physical EXOS `ipv6_neighbor_address` was not run because no IPv6 neighbour was available. EXOS `vlan_detail` and `lag_summary`, and IOS `interfaces counters errors`, were captured on 2026-11-09/10. The anonymised outputs are the fixtures of the automated tests of `switch_read`, `locate_endpoint` and the triage tools ([verified support](docs/verified-support.md#live-verification-of-netops-107)).

Live verification of NetOps 1.0.7 on 2026-11-09: earlier SSH captures in the same GNS3 lab, IOL XE 17.18.2, Nexus 9300v with NX-OS 9.3(12) and vJunos-switch 26.2R1.7 (read-only accounts; IOL XE `interfaces counters errors` was captured on 2026-11-09/10), and on the FortiGate 80F with FortiOS 8.0.2 build0251 the IP range syntax of the `sessions` and `flow` filters (filter set and cleared, no traffic test). Hardware Cisco, Arista and Juniper devices were not tested.

Later that day (14:10–14:20 UTC), direct HTTPS MCP calls measured 67 normalized tables on all seven GNS3 OS. The lab had no independent end host; IP/MAC endpoint runs returned transit evidence and `incomplete`, with seven-target runs reaching the 59.5-second limit. Later runs with lab end hosts on 2026-11-10/11 located them on the correct edge port and VLAN ([verified support](docs/verified-support.md#release-candidate-acceptance-2026-11-10)). BGP on NX-OS and STP on vJunos were disabled. Historical fixture samples and these later feature states are distinguished in the coverage notes above and [verified support](docs/verified-support.md#later-gns3-mcp-verification-2026-11-09).

Live verification of NetOps 1.0.6 on 2026-11-07: FortiGate 60F with FortiOS 7.6.8 build3744, standalone (Admin `firewall policy` create, update and undo of an accept policy and of a deny policy, with two `firewall address` objects created and deleted through Admin), a physical FortiGate 80F in active-passive HA mode (primary unit) with FortiOS 8.0.2 build0251, managing two FortiSwitch 224E-POE with 8.0.1 and FortiAP 231K and 23JK with 8.0.0 (Helper `system_status`, FortiSwitch status, `switch_dhcp_bindings` returning an empty binding table, MCLAG ICL, trunk and consistency status, and `wifi_access_points`, `wifi_ap_detail`, `wifi_clients` with no associated station and `wifi_ssid_mapping` under an administrator-bounded account; `wifi_client_detail` was not measured), and SNMPv3 `snmp_get` of the system name on a FortiGate 80F and on FortiADC-KVM 7.6.7, measured with development builds of the 1.0.6 source before the release candidate ([verified support](docs/verified-support.md)).

Live verification of NetOps 1.0.5 on 2026-11-01: FortiGate 60F with FortiOS 7.6.8 build3744 (Admin `firewall policy` create, update and undo; Helper `switch_dhcp_bindings`), a physical FortiGate 80F active-passive HA pair with FortiOS 8.0.2 build0251 (Helper `switch_dhcp_bindings` with a client binding, FortiSwitch MCLAG status and the five Wi-Fi reads under an administrator-bounded account), FortiGate-VM64 with FortiOS 8.0.2 build0251 (Helper ping and sessions in a selected VDOM) and FortiADC-KVM 7.6.7 build0676, standalone (Helper `triage_slb` for a healthy, degraded and recovered pool with WAF deny events, and `tls_probe` with an enrolled certificate authority through a FortiADC virtual server; on 2026-10-31 Admin `pool-member`, disabling and re-enabling one member and refusing to disable the last healthy member), measured with development builds of the 1.0.5 source before the release candidate; the final 1.0.4 image was verified on 2026-10-28 ([verified support](docs/verified-support.md)).

Details: [Verified platform support](docs/verified-support.md) · [Compatibility boundaries](docs/compatibility-boundaries.md)

## Minimum requirements

- **Host:** 64-bit Linux on `linux/amd64` or `linux/arm64` with Docker Engine and the Compose plugin ([Supported platforms](#supported-platforms)).
- **CPU:** 1 vCPU. `compose.yaml` limits the container to `NETOPS_CPUS` CPUs (default 2); on a host with one CPU Docker refuses the default, so set `NETOPS_CPUS=1` in `.env` (see `env.example`).
- **Memory:** 2 GiB RAM. In the measurement NetOps used about 295 MiB idle and up to about 350 MiB during MCP calls and the self-test, within the container limit of 1 GiB; the rest is for the host and Docker.
- **Disk:** 2 GiB free. The image is about 53 MB compressed and 166–170 MB unpacked per architecture (`docker image ls` shows about 240 MB); the state volume starts at about 116 KiB and grows with the audit and the stores. Backups, the audit history and the syslog queue need additional space.
- **Network:** the host reaches `github.com` for the release files and `ghcr.io` for the image. MCP clients connect to the published HTTPS port (default 8443, bound to the address in `NETOPS_BIND_IP`). The enrolled devices must be reachable from the host on the ports their enrolled reads and operations use (SSH; HTTPS for REST, such as the optional Wi-Fi REST token; SNMP for `snmp_get`). With syslog audit the host connects out to the receiver, by default on TCP 6514 (TLS).
- **Qualification tests (optional):** the qualification in [docs/testing-1.0.md](docs/testing-1.0.md) is more demanding than operation: its engine containers run with a memory limit of 2 GiB and a 2 GiB `/pytmp` tmpfs (the Admin suite), one role after another.

Measured on an Ubuntu 24.04.5 virtual machine with 1 vCPU and 2 GiB or 1 GiB RAM (Docker Engine 29.9.3, a Compose copy with `cpus: 1`), where the instance started and passed the measurement run, and on amd64 with Docker Engine 29.1.3 for the memory figures. This is not a throughput or long-run load test; a deployment with many concurrent clients or many targets needs more.

## Supported platforms

- **Host:** Linux with Docker Engine and the Compose plugin. The complete quickstart installation (Docker installation, signature and checksum verification, `init`, `up`, MCP and audit checks, refusal of foreign UIDs with an unchanged volume, host restart except in the rootless Ubuntu run) was exercised with the released NetOps 1.0.7 image, and every run passed, on the virtual-machine platforms below. The physical arm64 run is described separately.
  - Ubuntu 26.04.1 LTS and Ubuntu 24.04.5 LTS (amd64), Docker Engine;
  - Ubuntu 24.04.5 LTS (amd64) and Debian 13 (amd64) with rootless Docker; the Debian run includes a restart of the host (lingering user session);
  - Raspberry Pi OS Lite 64-bit (arm64) userland in a virtual machine with a Debian kernel;
  - Raspberry Pi OS 64-bit on physical arm64 hardware, a single-board computer (vendor kernel 6.12, 4 KiB pages): a separate run verified signature/checksum validation, initialization, MCP/authentication/audit checks, UID refusals and project recreation. Docker 29.8.0 was already installed; Compose 2.39.4 and cosign 3.1.4 were supplied locally for the test. Docker installation, group setup and a host reboot were not exercised on this host.
- **Also qualified for 1.0.7:** Debian 13 (amd64, arm64) and Fedora 44 (amd64 Server, arm64 Cloud Edition), with local state volumes. Fedora requires SELinux enforcing and SELinux support enabled in the Docker daemon.
- **Not verified:** kernels with 16 KiB pages, 32-bit Raspberry Pi OS, and the Docker installation steps on physical hardware (run in the virtual machine only). The runs were performed by the maintainer's test workflow, without an independent tester.
- **Architectures:** `linux/amd64` and `linux/arm64`.
- **Not supported as runtime:** Docker Desktop. Network-backed state storage, including NFS, is not qualified.
- **Clients:** macOS and Windows are MCP client hosts only. Claude Code was tested there for 1.0.1; Codex was tested on Linux only. MCP clients connect over the network.

## Security model

- **Endpoint:** HTTPS only with a bearer token. The token is checked before any request body is read; unauthenticated rejections are only counted, not stored.
- **Instance CA:** private, constrained to the configured DNS subtree, all IPv4/IPv6 names excluded (so the server name must be a DNS name). The server leaf lasts seven days and renews automatically; the CA is valid for 730 days from init or its last rotation (`connection` shows the remaining whole days, so 729 right after init) and is rotated explicitly with `netops ca rotate`.
- **Audit boundary:** every supported MCP request, notification, response and connection boundary is audited, with requests durable before dispatch and responses before delivery. A successful authenticated `GET /healthz` is not audited (local state only, no device contact); its query-string rejection and failure (HTTP 503) are. A failed audit refuses the operation; a failed response audit reports that the operation may have completed and forbids automatic retry. Helper, Auditor and Admin configuration workflows, Admin operator workflows, Auditor imports and Auditor `run` and `collect` record an allowlisted intent through a gateway-UID preflight; `run` and `collect` also record their result (exit code and `run_id`) and may run inside the running instance via `docker compose exec` under an interprocess audit lock; Auditor `status` and token rotation do not emit that preflight event, and CA rotation and audit recovery use their own audit records.
- **Redaction:** explicit. Known token values, secret-bearing fields, private-key blocks and documented password forms are redacted; worker-side credentials are removed before reaching the gateway. Audit is parsed protocol content, not a raw byte transcript, and output is escaped for terminals. Device output remains sensitive after redaction.
- **Untrusted device output:** device text is data, never instructions; a diagnostic finding does not authorize a write, retry or another target.
- **UID separation:** gateway, Helper, Auditor and Admin have separate UID/GID, private state and credentials; local IPC authenticates the peer UID in both directions. This is process and filesystem isolation inside one container, not a boundary against the host administrator or the container runtime. The runtime never mounts the Docker socket or uses host networking.
- **TLS probe trust:** `tls_probe` verifies the peer chain and the hostname/SAN with TLS 1.2 or newer, against the system store or, per target, only against a CA file enrolled as `tls_ca_certificate` from a read-only directory; verification cannot be switched off. After failed verification, a second, unverified handshake only retrieves certificate details for diagnosis. No application data is sent, and the result stays `certificate_verified: false`.
- **Syslog over TLS:** the bounded, durable syslog queue sends to a verified TLS receiver. A successful delivery is a TLS transport hand-over, not a receiver acknowledgement; a full queue blocks new operations.
- **Fail-closed:** an unwritable audit, an incomplete final local audit record, a full syslog queue, a second instance on the same state or state of another product version or state schema stops operations instead of continuing silently. The one exception is the state of the immediately preceding release: the first start of the new release converts it under the instance lock and changes only its recorded product version. There is no downgrade.
- **CIS:** the container architecture and the release tests are inspired by the recommendations of the CIS Docker Benchmark; NetOps does not claim compliance with CIS.

Details: [Architecture](docs/architecture-1.0.md) · [Security policy](SECURITY.md) · [CIS Docker Benchmark mapping](docs/security/cis-docker-benchmark.md)

## Quick start

This is a shortened version of the [quickstart](docs/quickstart-1.0.md). Follow the full document for a new host: it installs the prerequisites step by step for Debian, Ubuntu, Fedora Server and Raspberry Pi OS, and covers rootless Docker, syslog receivers, backup, restore, upgrades and removal.

**0. Prerequisites.** The host meets the [minimum requirements](#minimum-requirements). Docker Engine with the Compose plugin from [Docker's repository](https://docs.docker.com/engine/install/), and an account that can run `docker info` (root, the `docker` group or rootless Docker); on Fedora, SELinux support enabled in the Docker daemon (`"selinux-enabled": true`) before the first start, so that `docker info` lists `name=selinux`. Further `curl`, `jq` and cosign 2.5 or newer; the quickstart installs the official Sigstore 3.x release (checked with v3.1.4) and says what to do when its download from GitHub fails. See quickstart steps [1–4](docs/quickstart-1.0.md#1-install-docker-engine), which also say how steps [3](docs/quickstart-1.0.md#3-give-your-account-access-to-docker) and [4](docs/quickstart-1.0.md#4-install-curl-jq-and-cosign) run without a terminal. Without sudo rights, the host administrator prepares Docker and `jq`, and cosign runs as a program of your account ([step 4](docs/quickstart-1.0.md#4-install-curl-jq-and-cosign)). The Debian, Debian arm64 and Fedora blind installations of NetOps 1.0.11 used accounts with sudo; the path without sudo has not been run with an account without sudo rights.

**1. Download and verify.** In the instance directory `~/netops` download the five release files and verify them. The block stops at the first failed download or check, and it downloads nothing into a directory that already holds the `.env` of an instance. The block sets the instance directory to mode 700, including an existing directory:

```sh
mkdir -p -m 700 ~/netops && cd ~/netops &&
if test -e .env; then echo 'netops: ~/netops already holds .env; nothing downloaded' >&2; false; fi &&
chmod 700 . &&
(
  for f in compose.yaml env.example netops-1.0.12-manifest.json netops-1.0.12-SHA256SUMS netops-1.0.12-SHA256SUMS.sigstore.json; do
    curl -fsSLO "https://github.com/radek-cerny-soukr/netops/releases/download/v1.0.12/$f" || exit 1
  done
) &&
cosign verify-blob --bundle netops-1.0.12-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.12-SHA256SUMS &&
sha256sum -c --ignore-missing netops-1.0.12-SHA256SUMS
```

cosign must print `Verified OK`, and sha256sum `OK` for `compose.yaml`, `env.example` and the release manifest; cosign authenticates the checksum list using the signature bundle. After a failed download or check, run the same block again: it downloads all five files again and overwrites those of the failed attempt. An empty `~/netops` left by a failed first attempt does no harm: the block reuses the directory, and nothing needs to be deleted. A pre-publication TEST bundle can share the release filename and use a separate test key. See the [release verification step](docs/quickstart-1.0.md#5-download-and-verify-the-release) for how the signature and covered files differ.

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

`init` asks for the audit target: a TLS syslog receiver (recommended), or, when you leave it blank, local audit, which you accept by typing `LOCAL`. `docker compose ps` must show the service as `healthy`. If GHCR reports `content descriptor ... from remote: not found`, wait about a minute and run the same block again; the image digest in `.env` stays the same.

Without a terminal, for example in a script or over `ssh` without a terminal, choose the audit explicitly, add `-T` to every `docker compose run` and `docker compose exec`, redirect every other `docker compose` command with `< /dev/null`, and run the commands from a file, not from standard input. For local audit the block is the following; for a TLS syslog receiver replace `--audit local --accept-local-audit` with `--audit syslog --syslog-host <host> [--syslog-port <port>]`:

```sh
cd ~/netops &&
docker compose pull --quiet < /dev/null && docker compose run --rm -T netops init --audit local --accept-local-audit < /dev/null && docker compose up -d --wait < /dev/null && docker compose ps < /dev/null
```

**4. Export the CA and the token.** The block is the same in a terminal and in a script. Compose messages between its lines go to standard error and do not enter `netops-ca.pem` or `NETOPS_TOKEN`:

```sh
cd ~/netops &&
umask 077 &&
docker compose run --rm -T netops ca < /dev/null > netops-ca.pem &&
NETOPS_TOKEN="$(docker compose run --rm -T netops token show < /dev/null)" &&
export NETOPS_TOKEN &&
test -n "$NETOPS_TOKEN" && printf 'NETOPS_TOKEN is set (%s characters)\n' "${#NETOPS_TOKEN}" &&
docker compose run --rm -T netops connection < /dev/null
```

The block prints `NETOPS_TOKEN is set (64 characters)` and the MCP URL, without printing the token. The token stays in the shell: in a script, run this block and the token requests of quickstart [step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) in the same script file.

**5. Check without an MCP client.**

```sh
cd ~/netops
docker compose exec -T netops netops health < /dev/null
docker compose exec -T netops netops version < /dev/null
curl -sS -o /dev/null -w '%{http_code}\n' --cacert netops-ca.pem \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST https://localhost:8443/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

They print `ready`, `1.0.12` and `401`: a request without the token is refused. Use the URL printed by `connection` when it is not `https://localhost:8443/mcp`. [Step 9](docs/quickstart-1.0.md#9-check-the-instance-without-an-mcp-client) adds requests with the token, including the MCP tool list, and how to find them in the audit.

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

**NetOps 1.0.12:** the client acceptance (Codex CLI and Claude Code) runs once on the signed release candidate image; its results are in the [release notes](release/notes-1.0.12.md#acceptance).
Until 1.0.12 is released, this acceptance is deferred to the release candidate: the release notes describe the required checks and hold no client results yet; the results are added there with the release.

**Tested for NetOps 1.0.9 (2026-11-15)** against a local amd64 build of the 1.0.9 source at commit 243c14f, which differs from the final source only in tests, documentation and the evidence text of one Admin profile; the release image is checked again by the release acceptance:

| Client | Version | Platform | Model | Result |
|---|---|---|---|---|
| Codex CLI | 0.169.0 | Linux (Debian 13, amd64) | Client default (no model override) | PASS: Helper, Auditor and Admin roles, 9 calls matched in the audit, wrong token and missing CA rejected |
| Claude Code | 2.1.325 | Linux (Debian 13, amd64) | claude-haiku-4-5-20251001 | PASS: Helper, Auditor and Admin roles, 9 calls matched in the audit, wrong token and missing CA rejected |

**Tested for NetOps 1.0.8 (2026-11-13)** against pre-release builds of the 1.0.8 source; the release image is checked again by the release acceptance:

| Client | Version | Platform | Model | Result |
|---|---|---|---|---|
| Codex CLI | 0.168.0 | Linux (Debian 13, amd64) | Client default (no model override) | PASS: Helper, Auditor and Admin roles, 9 calls matched in the audit, wrong token and missing CA rejected |
| Claude Code | 2.1.323 | Linux (Ubuntu 24.04.5 LTS, amd64) | claude-haiku-4-5-20251001 | PASS: Helper, Auditor and Admin roles, 9 calls matched in the audit, wrong token and missing CA rejected |

**Tested for NetOps 1.0.7 (2026-11-12)** against the released image `ghcr.io/radek-cerny-soukr/netops@sha256:e04b19091819897e1bb4dec11416253b1dd598c18d5567325583b7e7e5fb8dfc`:

| Client | Version | Platform | Model | Result |
|---|---|---|---|---|
| Codex CLI | 0.167.2 | Linux (Debian 13, amd64) | Client default (no model override) | PASS 69/69 |
| Claude Code | 2.1.322 | Linux (Ubuntu 24.04.5 LTS, amd64) | claude-haiku-4-5-20251001 | PASS 2/2 |

Each listed client called `helper_status` over MCP with the instance bearer token and CA; its successful request and response were matched in the audit. Negative checks verified rejection of a wrong token and a missing CA.

Tests of NetOps 1.0.1–1.0.6 are documented in the [release history](https://github.com/radek-cerny-soukr/netops/releases); Open WebUI v0.12.3 was last tested with 1.0.1.

Other MCP clients supporting Streamable HTTP, bearer tokens and normal TLS verification can be used; see the [quickstart](docs/quickstart-1.0.md#open-webui).

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

This README describes NetOps 1.0.12, the current release. What changed is in the [1.0.12 release notes](release/notes-1.0.12.md) and the [changelog](CHANGELOG.md), which also lists the earlier releases. To upgrade a 1.0.11 instance, follow [Upgrade from the previous release](docs/quickstart-1.0.md#upgrade-from-the-previous-release); to return to the unchanged 1.0.11 instance after an upgrade, follow [Rollback](docs/quickstart-1.0.md#rollback). Only 1.0.11 is accepted as the previous release: upgrade 1.0.10 to 1.0.11 first.

Add `host_key` (the OpenSSH public key matching `host_key_fingerprint`) to every FortiOS and FortiADC device in the Helper inventory and the Admin configuration, and to every FortiOS device in the Auditor collection inventory; without it, SSH operations on that device stop. Other inventory and credentials need no manual edits. For the upgrade from 1.0.11 to 1.0.12, re-enroll every Admin device (`admin enroll`) before making changes with Admin. The [upgrade guide](docs/quickstart-1.0.md#upgrade-from-the-previous-release) explains keyboard-interactive authentication and connection spacing; the [1.0.12 release notes](release/notes-1.0.12.md#changes-in-1012) list the changes.


## Verification and release

A release is the maintainer's personally signed checksum list together with the assets it covers. A candidate branch, digest, build or CI run without that signature is not a release.

- **Signature:** `netops-1.0.12-SHA256SUMS` is signed with Sigstore (`netops-1.0.12-SHA256SUMS.sigstore.json`); certificate identity `325383355+radek-cerny-soukr@users.noreply.github.com`, OIDC issuer `https://github.com/login/oauth`.
- **Covered assets:** `compose.yaml`, `env.example`, the release manifest (image index and per-architecture digests), the acceptance manifest, the per-architecture SBOMs, vulnerability scans and scan gate results, the vulnerability assessments and the acceptance reports (`acceptance-*.json`). The signed checksum list itself is the complete list of covered files.
- **Build once:** every release candidate is built once in GitHub Actions and the same digests are tested, accepted and published without a rebuild. The wheel inside the image is built with `SOURCE_DATE_EPOCH` set to the time of the source commit (`git log -1 --format=%ct`), so two builds of the same commit produce a byte-identical wheel; the Dockerfile refuses to build the wheel without it.
- **Building behind TLS inspection:** if a proxy or firewall decrypts TLS (for example FortiGate deep inspection), `docker build` stops at the first download: `apk` prints `TLS: server certificate not trusted` and `ERROR: Not continuing due to stale/unavailable repositories.`, and pip prints `ERROR: Could not find a version that satisfies the requirement <package>==<version> (from versions: none)`. Pass a CA bundle that contains the inspection CA as a BuildKit secret, for example the system bundle of a Debian or Ubuntu host that trusts that CA: `docker build --secret id=extra_ca,src=/etc/ssl/certs/ca-certificates.crt --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" .` The file is added to the image's own bundle only while the download steps run and is not stored in any image layer. Without the secret the build runs the same commands as before, and with or without it the wheel is byte-identical. The tester image of [Qualification](docs/testing-1.0.md) accepts the same secret; see [Source checkout problems](docs/testing-1.0.md#source-checkout-problems).
- **Vulnerabilities:** each architecture is scanned; a fixable High or Critical finding blocks the release unless a dated assessment records that the fixed version is not yet released, and every other finding ships with a written assessment (`netops-1.0.12-vulnerability-assessments.json`). The release notes ([Known dependency findings](release/notes-1.0.12.md#known-dependency-findings)) name the baseline assessments; the exact findings of the image and their assessments are in the signed scan results and assessments. The digests of the latest release are rescanned daily against its assessments.
- **Acceptance of 1.0.12:** the acceptance is proportional to the change, and the [release notes](release/notes-1.0.12.md#acceptance) list its checks. Their results are the acceptance reports (`acceptance-*.json`) covered by the signed checksum list; the maintainer signs only a release whose required reports pass. The acceptance of 1.0.11 is described in its [release notes](release/notes-1.0.11.md#acceptance).

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
- FortiExtender modem queries, Catalyst 9800, SRX diagnostics and the physical PoE or DOM cases identified in the support matrix have automated coverage only. FortiGate optics are not part of 1.0.12. The matrix lists the measured hardware and software-image scope.
- The process-profile acceptance check samples at a nominal 50 ms interval and can miss short-lived processes; see the [1.0.1 release notes](release/notes-1.0.1.md) for the exact attribution rule.

## Supported releases and distribution

Only the shared NetOps 1.0.x product is supported. The earlier standalone 0.x components have no support, no migration path and no security monitoring; NetOps 1.0.x does not migrate 0.x data or modify 0.x volumes. NetOps is distributed exclusively through GitHub: the source repository, GitHub Releases, and container images in GitHub Container Registry (GHCR). It is not distributed through PyPI.

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
