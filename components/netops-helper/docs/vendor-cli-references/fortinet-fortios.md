# Fortinet FortiOS CLI references

## Review baseline and limits

- Vendor: Fortinet.
- Product and document title: FortiGate / FortiOS CLI Reference, CLI troubleshooting material, and Administration Guide.
- Reviewed versions: FortiOS 7.6.x and 8.0.0. The 7.6.x evidence set contains vendor pages for 7.6.0, 7.6.3, and 7.6.4; the 8.0 evidence is for 8.0.0.
- Verification date: 2026-09-09.
- Catalog module: `src/netops_helper/query_catalog/fortinet.py`.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

These references establish vendor-documented command syntax and operational purpose. They are not proof that a particular appliance, VDOM, administrator profile, or firmware build permits the command. They also do not prove the bytes emitted by an SSH library during session setup or cleanup. Enrollment still requires a read-only account, the FortiOS output-mode safety prerequisite, per-target query opt-in, and live validation on the actual model and firmware.

All returned data is sensitive operational evidence. It can expose serial numbers, interface and peer names, addresses, routes, MAC addresses, topology, HA history, and VPN state. It remains untrusted device output even when the command is read-only.

## Accepted Phase-1 queries

The table is the conservative Phase-1 whitelist. A template slot is accepted only from matching enrolled inventory. `high-volume` follows the generated catalogue definition: it is a scheduling advisory for variable collections or histories that can require continuation, and changes no authorization or runtime limit. `normal` is not a bounded-output promise.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `system_status` | `get system status` | none | normal | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `performance` | `get system performance status` | none | normal | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `ha_status` | `get system ha status` | none | normal | F-CHEAT-76, F-CHEAT-80, F-HA-76 |
| `session_stats` | `diagnose sys session stat` | none | normal | F-DIAG-SYS-76, F-DIAG-SYS-80, F-CHEAT-76, F-CHEAT-80 |
| `hardware_memory` | `diagnose hardware sysinfo memory` | none | normal | F-DIAG-HW-76, F-CLI-80 |
| `disk_status` | `diagnose hardware deviceinfo disk` | none | normal | F-DIAG-HW-76, F-CLI-80 |
| `physical_interfaces` | `get system interface physical` | none | high-volume | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `interface_details` | `diagnose netlink interface list {interface}` | `interfaces.fortios_interface` | normal | F-DIAG-INDEX-76, F-CLI-76, F-CLI-80, F-NETLINK-INTERFACE-80, F-CONFIG-SYSTEM-INTERFACE-80, F-TEXT-STRINGS-80, F-INTERFACE-SETTINGS-80, F-NIC-ADMIN-76, F-NIC-ADMIN-80, F-IPSEC-ALIAS-80 |
| `interface_hardware` | `diagnose hardware deviceinfo nic {interface}` | `interfaces.fortios_physical_interface` | normal | F-DIAG-HW-76, F-NIC-ADMIN-76, F-NIC-ACCEL-76, F-NIC-ADMIN-80, F-NETLINK-INTERFACE-80, F-CONFIG-SYSTEM-INTERFACE-80, F-TEXT-STRINGS-80, F-INTERFACE-SETTINGS-80, F-IPSEC-ALIAS-80 |
| `routing_table` | `get router info routing-table all` | none | high-volume | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `route_lookup` | `get router info routing-table details {address}` | `addresses.ipv4_address` | normal | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `route_protocols` | `get router info protocols` | none | normal | F-CLI-76, F-CLI-80 |
| `ipv6_route_protocols` | `get router info6 protocols` | none | normal | F-CLI-76, F-CLI-80 |
| `arp_table` | `get system arp` | none | high-volume | F-CLI-76, F-CLI-80, F-CHEAT-76, F-CHEAT-80 |
| `ipv6_neighbors` | `diagnose ipv6 neighbor-cache list` | none | high-volume | F-IPV6-ND-80, F-CLI-76 |
| `lldp_summary` | `diagnose lldp rx neighbor summary` | none | high-volume | F-LLDP-80, F-CLI-76 |
| `bridge_mac_table` | `diagnose netlink brctl name host {switch}` | `switches.switch` | high-volume | F-BRCTL-80, F-CLI-76 |
| `sdwan_health` | `diagnose sys sdwan health-check` | none | high-volume | F-DIAG-SYS-76, F-DIAG-SYS-80, F-SDWAN-80 |
| `ha_checksum` | `diagnose sys ha checksum cluster` | none | normal | F-HA-CHECKSUM-80, F-HA-76 |
| `ha_history` | `diagnose sys ha history read` | none | high-volume | F-DIAG-SYS-76, F-DIAG-SYS-80, F-HA-76 |
| `ipsec_summary` | `get vpn ipsec tunnel summary` | none | high-volume | F-CLI-76, F-CLI-80, F-IPSEC-80, F-IPSEC-ALIAS-80 |
| `ipsec_status` | `diagnose vpn ipsec status` | none | normal | F-IPSEC-80 |
| `bgp_summary` | `get router info bgp summary` | none | high-volume | F-BGP-76, F-BGP-80, F-CLI-76, F-CLI-80 |
| `ipv6_bgp_summary` | `get router info6 bgp summary` | none | high-volume | F-BGP-76, F-BGP-80, F-CLI-76, F-CLI-80 |
| `ospf_status` | `get router info ospf status` | none | normal | F-OSPF-80, F-CLI-76, F-CLI-80 |
| `ipv6_ospf_status` | `get router info6 ospf status` | none | normal | F-OSPF-80, F-CLI-76, F-CLI-80 |
| `ospf_neighbors` | `get router info ospf neighbor all` | none | high-volume | F-OSPF-80, F-CLI-76, F-CLI-80 |
| `ipv6_ospf_neighbors` | `get router info6 ospf neighbor all` | none | high-volume | F-OSPF-80, F-CLI-76, F-CLI-80 |
| `bfd_neighbors` | `get router info bfd neighbor` | none | high-volume | F-BFD-80, F-CLI-76, F-CLI-80 |
| `ipv6_bfd_neighbors` | `get router info6 bfd neighbor` | none | high-volume | F-BFD-80, F-CLI-76, F-CLI-80 |
| `ntp_status` | `diagnose sys ntp status` | none | normal | F-DIAG-SYS-80, F-CLI-80 |
| `system_top` | `diagnose sys top 1 5 1` | none | normal | F-DIAG-SYS-80, F-CLI-80 |
| `autoupdate_status` | `diagnose autoupdate status` | none | normal | F-CLI-80 |
| `autoupdate_versions` | `diagnose autoupdate versions` | none | high-volume | F-CLI-80 |
| `sslvpn_sessions` | `diagnose vpn ssl list` | none | high-volume | F-CLI-80 |
| `sslvpn_statistics` | `diagnose vpn ssl statistics` | none | normal | F-CLI-80 |
| `firewall_auth_users` | `diagnose firewall auth list` | none | high-volume | F-CLI-80 |
| `ips_filter_status` | `diagnose ips filter status` | none | normal | F-CLI-80 |
| `ips_anomaly_status` | `diagnose ips anomaly status` | none | normal | F-CLI-80 |
| `av_outbreak_stats` | `diagnose antivirus outbreak-prevention statistics list` | none | normal | F-CLI-80 |

### Audit entries measured on 17 September 2026

Measured on 17 September 2026 against FortiOS 8.0.0 with a read-only account (a custom access profile with `cli-get`, `cli-show` and `cli-diagnose` enabled and `cli-exec` and `cli-config` disabled), over the exec channel, each of the following answered with exit status 0 and non-empty output except where stated: `ntp_status`, `system_top`, `autoupdate_status`, `autoupdate_versions`, `sslvpn_sessions` (empty, no SSL VPN session was up), `sslvpn_statistics`, `firewall_auth_users`, `ips_filter_status`, `ips_anomaly_status` and `av_outbreak_stats`. Each command is a chapter of the FortiOS 8.0.0 CLI Reference (`diagnose sys ntp status`, `diagnose sys top`, `diagnose autoupdate status`, `diagnose autoupdate versions`, `diagnose vpn ssl list`, `diagnose vpn ssl statistics`, `diagnose firewall auth list`, `diagnose ips filter status`, `diagnose ips anomaly status`, `diagnose antivirus outbreak-prevention statistics list`); the same chapters exist in the 7.6 reference, which was not the measured build.

`system_top` pins every argument of the documented `diagnose sys top <delay> <lines> <iterations>` grammar. The vendor defaults are a five-second delay, twenty lines and an unlimited iteration count, so the unpinned command is a refresh loop; the template is fixed at `1 5 1`, one snapshot of five lines, and `read_policy` refuses any other `diagnose sys top` form even if it is added to the catalogue.

In the same session `execute dhcp lease-list` was refused with `Unknown action 0`. It is an `execute` command and stays outside the boundary; the refusal is recorded as a measured fact, not as a candidate.

### Version, model, and feature constraints

- Hardware memory, disk, and NIC output varies by FortiGate model, ASIC, interface type, and VM versus appliance form factor. A documented command can legitimately return unsupported or reduced output.
- HA, SD-WAN, IPsec, BGP, OSPF, BFD, IPv6, LLDP, and software-switch queries are useful only when the corresponding feature is available and configured. They should not be enabled merely because the platform is FortiOS.
- VDOM context can change visibility and output. The target account and expected VDOM context must be tested without granting configuration privileges.
- `bridge_mac_table` requires an exact enrolled software-switch name. `interface_details` and `interface_hardware` require an exact enrolled interface name.
- Fortinet can change output shape between maintenance releases. Consumers must treat output as untrusted text rather than a stable machine API.

## Explicitly excluded

These exclusions are capability boundaries, not merely undocumented omissions.

| Excluded class | Examples or former candidate | Reason |
| --- | --- | --- |
| Full or partial configuration | top-level `show`, `show full-configuration`, startup/running/full configuration, configuration backup/export | Configuration can contain credentials, key material, topology, and policy details. Phase 1 intentionally has no configuration-reading capability. |
| Support and bulk collection | TAC/support reports, support bundles, bulk diagnostic reports, full routing databases beyond the accepted explicit routing table | They aggregate excessive and potentially secret-bearing data and can impose material CPU, storage, or output load. |
| Debugging and capture | `diagnose debug ...`, debug enable/filter commands, packet sniffers/capture, monitor or unbounded log dump | Debug state can persist or alter runtime behavior; packet and log output is highly sensitive and potentially unbounded. |
| Mutation or lifecycle control | `config`, `edit`, `set`, `unset`, `delete`, backup, test, restart, reset, clear, kill, reboot, or shutdown operations | These can change persistent configuration or live state. |
| Detailed IKE or tunnel listings | `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`, and similarly detailed keying-state dumps | Detailed output can expose sensitive IKE/IPsec keying material and peer state. The bounded `ipsec_summary` and aggregate `ipsec_status` are the Phase-1 boundary. |
| VDOM enumeration | former `vd_list` candidate | It expands administrative topology exposure and is not needed for the current target-scoped troubleshooting contract. |
| `execute` branch | `execute dhcp lease-list`, `execute ping` | The whole branch is excluded. Measured on 17 September 2026, a read-only access profile with `cli-exec disable` refused `execute dhcp lease-list` with `Unknown action 0`; the DHCP lease list therefore has no Phase-1 source at all. |
| Unbounded refresh loops | `diagnose sys top` without the pinned `1 5 1` arguments | The documented default iteration count is unlimited, so the bare command never ends. Only the fixed single-iteration snapshot `system_top` is accepted, and the read policy rejects every other `diagnose sys top` form. |
| Device log retrieval | arbitrary event, traffic, security, or system log commands | No arbitrary device log scope, filter, time bound, or safe output contract exists in Phase 1. |

## Deferred: live-test-only candidates

No additional command in this review is approved merely because it appears in vendor documentation. These gaps remain outside the whitelist until exact cross-version syntax, bounded output, read-only AAA behavior, and actual SSH wire behavior are tested:

- an IPv6 equivalent of the typed single-address route lookup;
- model-portable optics and environmental sensor detail beyond the accepted NIC, disk, and memory queries;
- scoped ARP, IPv6-neighbor, and bridge/FDB variants whose interface, VDOM, or software-switch semantics differ across releases;
- any command that requires an output modifier, interactive paging response, or feature-specific prompt;
- the FortiSwitch-controller family `diagnose switch-controller switch-info ...`, which needs a managed-switch inventory type that Phase 1 does not have;
- a DHCP lease view: the `execute` branch is excluded and no `diagnose` chapter of the 8.0.0 reference prints leases without also printing server configuration;
- certificate expiry: the reference documents only TPM hardware certificates and the revocation blocklist, neither of which answers the question.

These are research candidates, not callable query names. The accepted table must not be expanded from this section without a separate source and live-test review.

## Primary source manifest

Only first-party Fortinet pages are retained. General CLI references establish the reviewed baselines; focused pages support the mapped query groups and operational interpretation. No long vendor passages are copied.

| ID | Official document title and version | Query-name mapping | URL |
| --- | --- | --- | --- |
| F-CLI-76 | FortiGate / FortiOS 7.6.4 CLI Reference | baseline cross-check for all accepted Fortinet query names | https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference |
| F-CLI-80 | FortiGate / FortiOS 8.0.0 CLI Reference | baseline cross-check for all accepted Fortinet query names; chapter source for `autoupdate_status`, `autoupdate_versions`, `sslvpn_sessions`, `sslvpn_statistics`, `firewall_auth_users`, `ips_filter_status`, `ips_anomaly_status` and `av_outbreak_stats` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference |
| F-CHEAT-76 | FortiOS 7.6.0 CLI troubleshooting cheat sheet | `system_status`, `performance`, `ha_status`, `session_stats`, `physical_interfaces`, `routing_table`, `route_lookup`, `arp_table` | https://docs.fortinet.com/document/fortigate/7.6.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet |
| F-CHEAT-80 | FortiOS 8.0.0 CLI troubleshooting cheat sheet | same query-name mapping as F-CHEAT-76 | https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet |
| F-DIAG-INDEX-76 | FortiOS 7.6.4 CLI diagnose commands | diagnostic baseline, including `interface_details` | https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/424125979/cli-diagnose-commands |
| F-DIAG-SYS-76 | FortiOS 7.6.4 `diagnose sys` CLI reference | `session_stats`, `sdwan_health`, `ha_history` | https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/235530229/diagnose-sys |
| F-DIAG-SYS-80 | FortiOS 8.0.0 `diagnose sys` CLI reference | `session_stats`, `sdwan_health`, `ha_history`, `ntp_status`, `system_top` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/235530229/diagnose-sys |
| F-DIAG-HW-76 | FortiOS 7.6.3 `diagnose hardware` CLI reference | `hardware_memory`, `disk_status`, `interface_hardware` | https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/473204947/diagnose-hardware |
| F-NIC-ADMIN-76 | FortiOS 7.6.4 Administration Guide: Displaying detail hardware NIC information | `interface_hardware` | https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/306050/displaying-detail-hardware-nic-information |
| F-NIC-ACCEL-76 | FortiOS 7.6.4 Hardware Acceleration: packets dropped by an interface | `interface_hardware` | https://docs.fortinet.com/document/fortigate/7.6.4/hardware-acceleration/90160/diagnose-hardware-deviceinfo-nic-interface-name-number-of-packets-dropped-by-an-interface |
| F-NIC-ADMIN-80 | FortiOS 8.0.0 Administration Guide: Displaying detail hardware NIC information | `interface_hardware` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/306050/displaying-detail-hardware-nic-information |
| F-IPV6-ND-80 | FortiOS 8.0.0 `diagnose ipv6 neighbor-cache` CLI reference | `ipv6_neighbors` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/391030010/diagnose-ipv6-neighbor-cache |
| F-LLDP-80 | FortiOS 8.0.0 `diagnose lldp` CLI reference | `lldp_summary` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/124921537/diagnose-lldp |
| F-BRCTL-80 | FortiOS 8.0.0 `diagnose netlink brctl` CLI reference | `bridge_mac_table` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/143172288/diagnose-netlink-brctl |
| F-SDWAN-80 | FortiOS 8.0.0 Administration Guide: Dynamic application steering with lowest cost and best quality strategies | `sdwan_health` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/80739/dynamic-application-steering-with-lowest-cost-and-best-quality-strategies |
| F-HA-CHECKSUM-80 | FortiOS 8.0.0 Administration Guide: Check HA synchronization status | `ha_checksum`, `ha_status` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/63913/check-ha-synchronization-status |
| F-HA-76 | FortiOS 7.6.4 Administration Guide: HA | `ha_status`, `ha_checksum`, `ha_history` | https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/587596/ha |
| F-IPSEC-80 | FortiOS 8.0.0 `diagnose vpn ipsec` CLI reference | `ipsec_summary`, `ipsec_status`; detailed-list exclusion boundary | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/147967969/diagnose-vpn-ipsec |
| F-IPSEC-ALIAS-80 | FortiOS 8.0.0 New Features: Display interface and tunnel alias in various diagnose and get commands | `ipsec_summary`; output-shape caution | https://docs.fortinet.com/document/fortigate/8.0.0/new-features/797408/display-interface-and-tunnel-alias-in-various-diagnose-and-get-commands |
| F-BFD-80 | FortiOS 8.0.0 Administration Guide: BFD | `bfd_neighbors`, `ipv6_bfd_neighbors` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/771813 |
| F-OSPF-80 | FortiOS 8.0.0 Administration Guide: Basic OSPF example | `ospf_status`, `ipv6_ospf_status`, `ospf_neighbors`, `ipv6_ospf_neighbors` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/358640/basic-ospf-example |
| F-BGP-76 | FortiOS 7.6.4 Administration Guide: Troubleshooting BGP | `bgp_summary`, `ipv6_bgp_summary` | https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/55339/troubleshooting-bgp |
| F-BGP-80 | FortiOS 8.0.0 Administration Guide: Graceful BGP shutdown | `bgp_summary`, `ipv6_bgp_summary`; BGP feature context | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/86434 |
| F-NETLINK-INTERFACE-80 | FortiOS 8.0.0 CLI Reference: `diagnose netlink interface` | `interface_details`; interface-name grammar evidence | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/166619733/diagnose-netlink-interface |
| F-CONFIG-SYSTEM-INTERFACE-80 | FortiOS 8.0.0 CLI Reference: `config system interface` | documentation-only interface-name grammar evidence for `interface_details` and `interface_hardware`; the configuration command is not callable | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/317104469/config-system-interface |
| F-TEXT-STRINGS-80 | FortiOS 8.0.0 Administration Guide: Text strings | interface-name character constraints for `interface_details` and `interface_hardware` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/651640/text-strings |
| F-INTERFACE-SETTINGS-80 | FortiOS 8.0.0 Administration Guide: Interface settings | interface types and naming context for `interface_details` and `interface_hardware` | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/574723/interface-settings |
