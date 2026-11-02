# Fortinet FortiOS CLI references

## Review baseline and limits

- Vendor: Fortinet.
- Product and document title: FortiGate / FortiOS CLI Reference, CLI troubleshooting material, and Administration Guide.
- Reviewed versions: FortiOS 7.6.x, 8.0.0 and 8.0.2. The 7.6.x evidence set contains vendor pages for 7.6.0, 7.6.3, and 7.6.4; the 8.0 evidence is for 8.0.0, and the 8.0.2 CLI Reference, CLI troubleshooting cheat sheet and Administration Guide were re-checked against every accepted Phase-1 command. Each command found in the 8.0.0 documents is present in the 8.0.2 documents and the 8.0.2 text shows no syntax change; `get system interface physical` appears there only as `get system interface`, and `diagnose sys top 1 5 1` only as `diagnose sys top 1`, both as in 8.0.0.
- Verification date: 2026-10-27. The 7.6.x and 8.0.0 evidence was first verified on 2026-09-09.
- Catalog module: `src/netops_helper/query_catalog/fortinet.py`.

The exact machine-checked templates and per-query source links are in the [generated query catalog](../query-catalog.md); the source-ID records are in [`query-sources.json`](../query-sources.json).

These references establish vendor-documented command syntax and operational purpose. They are not proof that a particular appliance, VDOM, administrator profile, or firmware build permits the command. They also do not prove the bytes emitted by an SSH library during session setup or cleanup. Enrollment still requires a read-only account, the FortiOS output-mode safety prerequisite, per-target query opt-in, and live validation on the actual model and firmware.

All returned data is sensitive operational evidence. It can expose serial numbers, interface and peer names, addresses, routes, MAC addresses, topology, HA history, and VPN state. It remains untrusted device output even when the command is read-only.

## Accepted Phase-1 queries

The table is the conservative Phase-1 whitelist. A template slot is accepted only from matching enrolled inventory. `high-volume` follows the generated catalogue definition: it is a scheduling advisory for variable collections or histories that can require continuation, and changes no authorization or runtime limit. `normal` is not a bounded-output promise.

The nat_pool_assignments CLI reference documents a pool-name argument but does not specify its character grammar or length. The helper accepts one exact enrolled name using its local 1-79 character ASCII pattern [A-Za-z0-9][A-Za-z0-9_.-]{0,78}; this is a helper constraint, not a Fortinet syntax or length claim.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `route_cache` | `diagnose ip rtcache list` | none | high-volume | F-CLI-768, F-CLI-802 |
| `ospf_database_brief_ipv4` | `get router info ospf database brief` | none | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `ospf_database_ipv6` | `get router info6 ospf database` | none | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `system_status` | `get system status` | none | normal | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `performance` | `get system performance status` | none | normal | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `ha_status` | `get system ha status` | none | normal | F-CHEAT-76, F-CHEAT-80, F-CHEAT-802, F-HA-76 |
| `session_stats` | `diagnose sys session stat` | none | normal | F-DIAG-SYS-76, F-DIAG-SYS-80, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `conserve_state` | `diagnose hardware sysinfo conserve` | none | normal | F-CLI-768, F-CLI-802 |
| `cpu_cores` | `diagnose hardware sysinfo cpu` | none | normal | F-CLI-768, F-CLI-802 |
| `fortiguard_communication` | `diagnose sys service-communication` | none | high-volume | F-CLI-768, F-CLI-802 |
| `hardware_memory` | `diagnose hardware sysinfo memory` | none | normal | F-DIAG-HW-76, F-CLI-80, F-CLI-802 |
| `disk_status` | `diagnose hardware deviceinfo disk` | none | normal | F-DIAG-HW-76, F-CLI-80, F-CLI-802 |
| `dhcp_leases` | `execute dhcp lease-list {interface}` | `interfaces.fortios_interface` | high-volume | F-CLI-768, F-CLI-802 |
| `physical_interfaces` | `get system interface physical` | none | high-volume | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `interface_details` | `diagnose netlink interface list {interface}` | `interfaces.fortios_interface` | normal | F-DIAG-INDEX-76, F-CLI-76, F-CLI-80, F-CLI-802, F-NETLINK-INTERFACE-80, F-CONFIG-SYSTEM-INTERFACE-80, F-TEXT-STRINGS-80, F-INTERFACE-SETTINGS-80, F-NIC-ADMIN-76, F-NIC-ADMIN-80, F-IPSEC-ALIAS-80 |
| `interface_hardware` | `diagnose hardware deviceinfo nic {interface}` | `interfaces.fortios_physical_interface` | normal | F-DIAG-HW-76, F-NIC-ADMIN-76, F-NIC-ACCEL-76, F-NIC-ADMIN-80, F-NETLINK-INTERFACE-80, F-CONFIG-SYSTEM-INTERFACE-80, F-TEXT-STRINGS-80, F-INTERFACE-SETTINGS-80, F-IPSEC-ALIAS-80 |
| `routing_table` | `get router info routing-table all` | none | high-volume | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `route_lookup` | `get router info routing-table details {address}` | `addresses.ipv4_address` | normal | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `policy_routes_ipv4` | `diagnose firewall proute list` | none | high-volume | F-CLI-768, F-ADMIN-CHEAT-768, F-CHEAT-76, F-CLI-802, F-CHEAT-802 |
| `policy_routes_ipv6` | `diagnose firewall proute6 list` | none | high-volume | F-CLI-768, F-CLI-802 |
| `fqdn_object_detail` | `diagnose firewall fqdn get-ip {name}` | `firewall_addresses.fortios_address_object` | normal | F-CLI-768, F-CLI-802 |
| `policy_lookup_ipv4` | `diagnose firewall iprope lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}` | `device -> interfaces.fortios_interface, dst_ip -> addresses.ipv4_address, dst_port -> flow_ports.flow_port, pol_type -> policy_types.fortios_policy_type, protocol -> ip_protocols.ip_protocol, src_ip -> addresses.ipv4_address, src_port -> flow_ports.flow_port` | normal | F-CLI-768, F-CLI-802 |
| `policy_lookup_ipv6` | `diagnose firewall iprope6 lookup {src_ip} {src_port} {dst_ip} {dst_port} {protocol} {device} {pol_type}` | `device -> interfaces.fortios_interface, dst_ip -> addresses.ipv6_address, dst_port -> flow_ports.flow_port, pol_type -> policy_types.fortios_policy_type, protocol -> ip_protocols.ip_protocol, src_ip -> addresses.ipv6_address, src_port -> flow_ports.flow_port` | normal | F-CLI-768, F-CLI-802 |
| `route_protocols` | `get router info protocols` | none | normal | F-CLI-76, F-CLI-80, F-CLI-802 |
| `ipv6_route_protocols` | `get router info6 protocols` | none | normal | F-CLI-76, F-CLI-80, F-CLI-802 |
| `arp_table` | `get system arp` | none | high-volume | F-CLI-76, F-CLI-80, F-CLI-802, F-CHEAT-76, F-CHEAT-80, F-CHEAT-802 |
| `ipv6_neighbors` | `diagnose ipv6 neighbor-cache list` | none | high-volume | F-IPV6-ND-80, F-CLI-76 |
| `lldp_summary` | `diagnose lldp rx neighbor summary` | none | high-volume | F-LLDP-80, F-CLI-76 |
| `bridge_mac_table` | `diagnose netlink brctl name host {switch}` | `switches.switch` | high-volume | F-BRCTL-80, F-CLI-76 |
| `sdwan_health` | `diagnose sys sdwan health-check` | none | high-volume | F-DIAG-SYS-76, F-DIAG-SYS-80, F-SDWAN-80 |
| `sdwan_interface_quality` | `diagnose sys sdwan intf-sla-log {interface}` | `interfaces.fortios_interface` | high-volume | F-CLI-768, F-CLI-802 |
| `sdwan_sla_history` | `diagnose sys sdwan sla-log {health_check} {member}` | `health_check -> sdwan_health_checks.fortios_sdwan_health_check, member -> sdwan_members.fortios_sdwan_member` | high-volume | F-CLI-768, F-CLI-802 |
| `link_monitor_status` | `diagnose sys link-monitor status {monitor}` | `link_monitors.fortios_link_monitor` | normal | F-CLI-768, F-CLI-802 |
| `sdwan_member_detail` | `diagnose sys sdwan member {member}` | `sdwan_members.fortios_sdwan_member` | normal | F-CLI-768, F-CLI-802 |
| `sdwan_service_ipv4` | `diagnose sys sdwan service4 {rule}` | `sdwan_rules.fortios_sdwan_rule` | normal | F-CLI-768, F-CLI-802 |
| `sdwan_service_ipv6` | `diagnose sys sdwan service6 {rule}` | `sdwan_rules.fortios_sdwan_rule` | normal | F-CLI-768, F-CLI-802 |
| `sdwan_routes_ipv4` | `diagnose sys sdwan route {member}` | `sdwan_members.fortios_sdwan_member` | high-volume | F-CLI-768, F-CLI-802 |
| `sdwan_routes_ipv6` | `diagnose sys sdwan route6 {member}` | `sdwan_members.fortios_sdwan_member` | high-volume | F-CLI-768, F-CLI-802 |
| `sdwan_zone` | `diagnose sys sdwan zone` | none | high-volume | F-CLI-768, F-CLI-802 |
| `ha_checksum` | `diagnose sys ha checksum cluster` | none | normal | F-HA-CHECKSUM-80, F-HA-76 |
| `ha_nonsync_checksum` | `diagnose sys ha checksum show-nonsync` | none | high-volume | F-CLI-768, F-CLI-802 |
| `ha_sync_statistics` | `diagnose sys ha sync-stats` | none | high-volume | F-CLI-768, F-CLI-802 |
| `ha_history` | `diagnose sys ha history read` | none | high-volume | F-DIAG-SYS-76, F-DIAG-SYS-80, F-HA-76 |
| `ipsec_summary` | `get vpn ipsec tunnel summary` | none | high-volume | F-CLI-76, F-CLI-80, F-CLI-802, F-IPSEC-80, F-IPSEC-ALIAS-80 |
| `ipsec_status` | `diagnose vpn ipsec status` | none | normal | F-IPSEC-80 |
| `ipsec_tunnel_statistics` | `diagnose vpn tunnel stat` | none | normal | F-CLI-768, F-CLI-802 |
| `nat_pool_assignments` | `diagnose firewall ippool list nat-ip {pool}` | `nat_pools.fortios_nat_pool` | high-volume | F-CLI-768, F-CLI-802 |
| `nat_pool_usage` | `diagnose firewall ippool stats` | none | normal | F-CLI-768, F-CLI-802 |
| `fqdn_resolved_addresses` | `diagnose firewall fqdn list-ip` | none | high-volume | F-CLI-768, F-CLI-802 |
| `dns_cache` | `diagnose test application dnsproxy 7` | none | high-volume | F-ADMIN-DNS-768, F-ADMIN-DNS-802, F-CLI-768, F-CLI-802 |
| `fqdn_cache` | `diagnose test application dnsproxy 6` | none | high-volume | F-ADMIN-DNS-768, F-ADMIN-DNS-802, F-CLI-768, F-CLI-802 |
| `ike_object_counts` | `diagnose vpn ike counts` | none | normal | F-CLI-768, F-CLI-802 |
| `ike_errors` | `diagnose vpn ike errors` | none | normal | F-CLI-768, F-CLI-802 |
| `ike_statistics` | `diagnose vpn ike stats` | none | normal | F-CLI-768, F-CLI-802 |
| `wifi_clients` | `diagnose wireless-controller wlac -c sta` | none | high-volume | F-CHEAT-76, F-CLI-768, F-CLI-802 |
| `wifi_client_detail` | `diagnose wireless-controller wlac -d sta {mac}` | `wireless_clients.fortios_station_mac` | normal | F-CHEAT-76, F-CLI-768, F-CLI-802 |
| `wifi_access_points` | `diagnose wireless-controller wlac -c wtp` | none | high-volume | F-CHEAT-76, F-CLI-768, F-CLI-802 |
| `wifi_ap_detail` | `diagnose wireless-controller wlac -d wtp` | none | high-volume | F-CHEAT-76, F-CLI-768, F-CLI-802 |
| `wifi_ssid_mapping` | `diagnose wireless-controller wlac -c vap` | none | high-volume | F-CHEAT-76, F-CLI-768, F-CLI-802 |
| `bgp_summary` | `get router info bgp summary` | none | high-volume | F-BGP-76, F-BGP-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `bgp_advertised_ipv4` | `get router info bgp neighbors {peer} advertised-routes` | `addresses.ipv4_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `bgp_received_ipv4` | `get router info bgp neighbors {peer} received-routes` | `addresses.ipv4_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `bgp_accepted_ipv4` | `get router info bgp neighbors {peer} routes` | `addresses.ipv4_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `bgp_advertised_ipv6` | `get router info6 bgp neighbors {peer6} advertised-routes` | `addresses.ipv6_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `bgp_received_ipv6` | `get router info6 bgp neighbors {peer6} received-routes` | `addresses.ipv6_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `bgp_accepted_ipv6` | `get router info6 bgp neighbors {peer6} routes` | `addresses.ipv6_address` | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `ospf_interfaces_ipv4` | `get router info ospf interface` | none | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `ospf_interfaces_ipv6` | `get router info6 ospf interface` | none | high-volume | F-ADMIN-CHEAT-768, F-CHEAT-76, F-CHEAT-802 |
| `ipv6_bgp_summary` | `get router info6 bgp summary` | none | high-volume | F-BGP-76, F-BGP-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ospf_status` | `get router info ospf status` | none | normal | F-OSPF-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ipv6_ospf_status` | `get router info6 ospf status` | none | normal | F-OSPF-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ospf_neighbors` | `get router info ospf neighbor all` | none | high-volume | F-OSPF-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ipv6_ospf_neighbors` | `get router info6 ospf neighbor all` | none | high-volume | F-OSPF-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `bfd_neighbors` | `get router info bfd neighbor` | none | high-volume | F-BFD-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ipv6_bfd_neighbors` | `get router info6 bfd neighbor` | none | high-volume | F-BFD-80, F-CLI-76, F-CLI-80, F-CLI-802 |
| `ntp_status` | `diagnose sys ntp status` | none | normal | F-DIAG-SYS-80, F-CLI-80, F-CLI-802 |
| `system_top` | `diagnose sys top 1 5 1` | none | normal | F-DIAG-SYS-80, F-CLI-80, F-CLI-802 |
| `autoupdate_status` | `diagnose autoupdate status` | none | normal | F-CLI-80, F-CLI-802 |
| `autoupdate_versions` | `diagnose autoupdate versions` | none | high-volume | F-CLI-80, F-CLI-802 |
| `sslvpn_sessions` | `diagnose vpn ssl list` | none | high-volume | F-CLI-80, F-CLI-802 |
| `sslvpn_statistics` | `diagnose vpn ssl statistics` | none | normal | F-CLI-80, F-CLI-802 |
| `firewall_auth_users` | `diagnose firewall auth list` | none | high-volume | F-CLI-80, F-CLI-802 |
| `ips_filter_status` | `diagnose ips filter status` | none | normal | F-CLI-80, F-CLI-802 |
| `ips_anomaly_status` | `diagnose ips anomaly status` | none | normal | F-CLI-80, F-CLI-802 |
| `av_outbreak_stats` | `diagnose antivirus outbreak-prevention statistics list` | none | normal | F-CLI-80, F-CLI-802 |

### FortiOS query grammar and permissions

The FortiOS 8.0.0 catalogue entries ntp_status, system_top, autoupdate_status, autoupdate_versions, sslvpn_sessions, sslvpn_statistics, firewall_auth_users, ips_filter_status, ips_anomaly_status and av_outbreak_stats use the exact listed vendor CLI grammar. Configure only the permissions required by enabled reads and independently deny full configuration export and mutation. A chapter in another firmware reference does not establish compatibility with that build or account.

`system_top` pins every argument of the documented `diagnose sys top <delay> <lines> <iterations>` grammar. The vendor defaults are a five-second delay, twenty lines and an unlimited iteration count, so the unpinned command is a refresh loop; the template is fixed at `1 5 1`, one snapshot of five lines, and `read_policy` refuses any other `diagnose sys top` form even if it is added to the catalogue.

In the same session `execute dhcp lease-list` was refused with `Unknown action 0` because the profile had `cli-exec disable`. The later catalogue query `dhcp_leases` uses this command and needs `cli-exec enable` ([Accounts and least privilege](../read-only-accounts.md#fortios)).

### SSL VPN queries on models without SSL VPN

SSL VPN query availability depends on build, model and feature. The documented FortiOS 8.0.1 60F profile lacks the SSL VPN commands/configuration branch; other models can differ. The [FortiOS 8.0.0 release notes](https://docs.fortinet.com/document/fortigate/8.0.0/fortios-release-notes) define model-specific feature removals. A CLI-reference chapter does not override a feature restriction: do not enable sslvpn_sessions or sslvpn_statistics where the model/build lacks them; unsupported responses remain device_cli_error.

### Version, model, and feature constraints

- Hardware memory, disk, and NIC output varies by FortiGate model, ASIC, interface type, and VM versus appliance form factor. A documented command can legitimately return unsupported or reduced output.
- HA, SD-WAN, IPsec, BGP, OSPF, BFD, IPv6, LLDP, and software-switch queries are useful only when the corresponding feature is available and configured. They should not be enabled merely because the platform is FortiOS.
- VDOM context affects visibility and output. Verify target account and scope without granting configuration privileges. FortiOS 8.0.0 build0167 and 7.6.7 build3704 distinguish VDOM-level reads from global autoupdate_status, autoupdate_versions, disk_status, ha_status, hardware_memory, interface_hardware, ntp_status, performance and session_stats reads. An unavailable scope must be refused rather than used to broaden account privileges.
- `bridge_mac_table` requires an exact enrolled software-switch name. `interface_details` and `interface_hardware` require an exact enrolled interface name.
- Product identity check: before a fresh `ssh_read` of a FortiOS target the Helper runs `get system status` and requires one well-formed `Version:` record whose hardware field begins `FortiGate-` or `FortiWiFi-`; a FortiADC (or any other product) behind the alias is refused as `product_identity` before the requested query is sent. Cost: every fresh query other than `system_status` takes one more SSH connection and, because of the five-second lane spacing, at least five more seconds; `system_status` itself is the probe and costs nothing extra. The account therefore needs the right to run `get system status`. `FortiGateRugged-` and `FortiFirewall-` hardware is not identified in this release and is refused until measured `Version:` samples are reviewed. See `docs/fortiadc-f1-contract.md`, section `Transport wiring of ssh_read`.
- Fortinet can change output shape between maintenance releases. Consumers must treat output as untrusted text rather than a stable machine API.
- Auto-script in FortiOS 8.0 (Admin safeguard, not a Helper query): the automation-stitch `cli-script` action runs on auto-script (FortiOS Administration Guide, CLI script action: [7.6.8](https://docs.fortinet.com/document/fortigate/7.6.8/administration-guide/639044/cli-script-action), [8.0.2](https://docs.fortinet.com/document/fortigate/8.0.2/administration-guide/639044/cli-script-action)). The Fortinet Community knowledge base article [Technical Tip: Automated scripts (auto-script)](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Automated-script-execution/ta-p/193685) (not Release Notes) states that from FortiOS 8.0.1 build 0185 auto-script allows only information-gathering commands (get, diagnose) and refuses others with `unknown action or command is unavailable in auto-script`. On FortiOS 7.6.8 build3744 the Admin safeguard reverted changes (verified, works); on 8.0.2 build0251 it refused every configuration line with that message, also with `accprofile super_admin`. This is a FortiOS behaviour change, not a NetOps fault; the 8.0.0 to 8.0.2 Release Notes and the CLI Reference (`config system automation-action` and `config system auto-script` have the same fields in 7.6.8 and 8.0.2) do not mention it. From FortiOS 8.0.1 the Admin safeguard therefore uses an automation-action `webhook` that calls the REST API of the same device. See [verified support](../../../../docs/verified-support.md#admin-safeguard-on-fortios-76-and-80).

## Explicitly excluded

These exclusions are capability boundaries, not merely undocumented omissions.

| Excluded class | Examples or former candidate | Reason |
| --- | --- | --- |
| Full or partial configuration | top-level `show`, `show full-configuration`, startup/running/full configuration, configuration backup/export | Configuration can contain credentials, key material, topology, and policy details. The ssh_read catalog provides no configuration-reading capability. The separate schema_read tool requires its measured schema binding and explicit path/context grants. |
| Support and bulk collection | TAC/support reports, support bundles, bulk diagnostic reports, full routing databases beyond the accepted explicit routing table | They aggregate excessive and potentially secret-bearing data and can impose material CPU, storage, or output load. |
| Debug activation and capture | Debug enable/filter/application controls, packet sniffers/capture, monitor or unbounded log dump | Debug state can persist or alter runtime behavior; packet and log output is highly sensitive and potentially unbounded. |
| Mutation or lifecycle control | `config`, `edit`, `set`, `unset`, `delete`, backup, test, restart, reset, clear, kill, reboot, or shutdown operations | These can change persistent configuration or live state. |
| Detailed IKE or tunnel listings | `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`, and similarly detailed keying-state dumps | Detailed output can expose sensitive IKE/IPsec keying material and peer state. The bounded `ipsec_summary`, aggregate `ipsec_status`, and the exact aggregate IKE views below do not authorize detailed keying-state dumps. |
| VDOM enumeration | former `vd_list` candidate | It expands administrative topology exposure and is not needed for the current target-scoped troubleshooting contract. |
| `execute` branch | `execute ping` and every other action | Only the exact catalogue reads `ping_options`, `traceroute_options` and `dhcp_leases` (one enrolled interface) use `execute`; Helper ping and traceroute run only as bounded `fortios_diagnostics` recipes. An account with `cli-exec disable` refuses `execute` commands with `Unknown action 0`; the account requirements are in [Accounts and least privilege](../read-only-accounts.md#fortios). |
| Unbounded refresh loops | `diagnose sys top` without the pinned `1 5 1` arguments | The documented default iteration count is unlimited, so the bare command never ends. Only the fixed single-iteration snapshot `system_top` is accepted, and the read policy rejects every other `diagnose sys top` form. |
| Device log retrieval | arbitrary event, traffic, security, or system log commands | No arbitrary device log scope, filter, time bound, or safe output contract exists in Phase 1. |

## Deferred: live-test-only candidates

No additional command in this review is approved merely because it appears in vendor documentation. These gaps remain outside the whitelist until exact cross-version syntax, bounded output, read-only AAA behavior, and actual SSH wire behavior are tested:

- an IPv6 equivalent of the typed single-address route lookup;
- model-portable optics and environmental sensor detail beyond the accepted NIC, disk, and memory queries;
- scoped ARP, IPv6-neighbor, and bridge/FDB variants whose interface, VDOM, or software-switch semantics differ across releases;
- any command that requires an output modifier, interactive paging response, or feature-specific prompt;
- FortiSwitch-controller operations beyond the five exact, enrolled `managed_switches` templates documented below;
- a DHCP lease view: this `execute` action is excluded and no `diagnose` chapter of the 8.0.0 reference prints leases without also printing server configuration;
- certificate operations beyond the enrolled `certificate_details` metadata query below, including all private-key export.

These are research candidates, not callable query names. The accepted table must not be expanded from this section without a separate source and live-test review.

## Primary source manifest

Only first-party Fortinet pages are retained. General CLI references establish the reviewed baselines; focused pages support the mapped query groups and operational interpretation. No long vendor passages are copied.

| ID | Official document title and version | Query-name mapping | URL |
| --- | --- | --- | --- |
| F-CLI-76 | FortiGate / FortiOS 7.6.4 CLI Reference | baseline cross-check for all accepted Fortinet query names | https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference |
| F-CLI-768 | FortiGate / FortiOS 7.6.8 CLI Reference | `conserve_state`, `cpu_cores`, `fortiguard_communication`, selected SD-WAN reads including `sdwan_interface_quality`, `link_monitor_status`, `lacp_detail`, `policy_routes_ipv4`, `policy_routes_ipv6` and `fqdn_object_detail`, `switch_loop_guard`, `switch_bpdu_guard`, `switch_flap_guard`, `switch_dhcp_snooping`, `switch_dhcp_bindings`, `switch_fan_health` and `switch_source_guard`, `policy_lookup_ipv4`, `policy_lookup_ipv6`, `ipsec_tunnel_statistics`, `ha_nonsync_checksum`, `ha_sync_statistics`, `dns_cache`, `dhcp_leases`, plus generic WLAC option/value syntax for `wifi_access_points`, `wifi_ap_detail` and `wifi_ssid_mapping`, `switch_lldp_port` and `switch_mac_limit` | https://docs.fortinet.com/document/fortigate/7.6.8/cli-reference |
| F-ADMIN-DNS-768 | FortiOS 7.6.8 Administration Guide: DNS troubleshooting | dns_cache; level 7 dump cache (dns_cache), level 6 dump FQDN (fqdn_cache); this view does not establish reachability | https://docs.fortinet.com/document/fortigate/7.6.8/administration-guide/126629/dns-troubleshooting |
| F-ADMIN-DNS-802 | FortiOS 8.0.2 Administration Guide: DNS troubleshooting | dns_cache; level 7 dump cache (dns_cache), level 6 dump FQDN (fqdn_cache); this view does not establish reachability | https://docs.fortinet.com/document/fortigate/8.0.2/administration-guide/126629/dns-troubleshooting |
| F-ADMIN-CHEAT-768 | FortiOS 7.6.8 Administration Guide: CLI troubleshooting cheat sheet | `policy_routes_ipv4`; page links the shared FortiOS 7.6.0 sheet | https://docs.fortinet.com/document/fortigate/7.6.8/administration-guide/574215/cli-troubleshooting-cheat-sheet |
| F-CLI-80 | FortiGate / FortiOS 8.0.0 CLI Reference | baseline cross-check for all accepted Fortinet query names; chapter source for `autoupdate_status`, `autoupdate_versions`, `sslvpn_sessions`, `sslvpn_statistics`, `firewall_auth_users`, `ips_filter_status`, `ips_anomaly_status` and `av_outbreak_stats` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference |
| F-CHEAT-76 | FortiOS 7.6.0 CLI troubleshooting cheat sheet | `system_status`, `performance`, `ha_status`, `session_stats`, `physical_interfaces`, `routing_table`, `route_lookup`, `policy_routes_ipv4`, `arp_table` | https://docs.fortinet.com/document/fortigate/7.6.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet |
| F-CHEAT-80 | FortiOS 8.0.0 CLI troubleshooting cheat sheet | `system_status`, `performance`, `ha_status`, `session_stats`, `physical_interfaces`, `routing_table`, `route_lookup`, `arp_table` | https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet |
| F-CLI-802 | FortiGate / FortiOS 8.0.2 CLI Reference | 8.0.2 cross-check for the same query names as F-CLI-80, plus `sdwan_interface_quality` `lacp_detail`, `policy_routes_ipv4`, `policy_routes_ipv6` and `fqdn_object_detail`, `switch_loop_guard`, `switch_bpdu_guard`, `switch_flap_guard`, `switch_dhcp_snooping`, `switch_dhcp_bindings`, `switch_fan_health` and `switch_source_guard`, `policy_lookup_ipv4`, `policy_lookup_ipv6`, `ipsec_tunnel_statistics`, `ha_nonsync_checksum`, `ha_sync_statistics`, `dns_cache`, `dhcp_leases`, plus generic WLAC option/value syntax for `wifi_access_points`, `wifi_ap_detail` and `wifi_ssid_mapping`, `switch_lldp_port` and `switch_mac_limit` | https://docs.fortinet.com/document/fortigate/8.0.2/cli-reference |
| F-CHEAT-802 | FortiOS 8.0.2 CLI troubleshooting cheat sheet | shared 8.0 sheet linked from the 8.0.2 page; includes `policy_routes_ipv4` | https://docs.fortinet.com/document/fortigate/8.0.2/cli-troubleshooting-cheat-sheet |
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

## Scoped diagnostic queries

These opt-in templates are included in NetOps 1.0. The 20-21 September 2026 results below are direct CLI observations made before 1.0, not end-to-end MCP tests of these additions, except where a later end-to-end MCP observation is explicitly cited in a row. Enrollment never derives automatically from device output. The existing dated measurements earlier on this page cover the earlier catalogue only.

| Query | Source | Live result |
|---|---|---|
| `certificate_details` | [F-CERT-LOCAL](https://docs.fortinet.com/document/fortigate/latest/administration-guide/822087/automatically-provision-a-certificate) | FortiOS 8.0.0 read-only account returned public certificate details including expiry. |
| `managed_switch_status` | [F-CHEAT-80, F-CHEAT-802](https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet) | FortiOS 8.0.1 controller returned data for an enrolled managed switch. The controller test used an administrator account; restricted-profile permissions require separate deployment validation. |
| `managed_switch_poe` | [F-CHEAT-80, F-CHEAT-802](https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet) | FortiOS 8.0.1 controller returned data for an enrolled managed switch under an administrator account; restricted-profile permissions required separate validation. A later end-to-end MCP call (2026-10-15, before 1.0.0) exercised this exact query through Helper's own read-only account against a physical FortiGate and its enrolled FortiSwitch on FortiOS 7.6.7, and received a device CLI refusal: `switch:{managed_switch} is not PoE capable` / `Command fail. Return code -7622` (`device_cli_error`). The enrolled switch model has no PoE hardware; a positive result on PoE-capable hardware remains unverified. |
| `managed_switch_mac` | [F-CHEAT-80, F-CHEAT-802](https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet) | FortiOS 8.0.1 controller returned data for an enrolled managed switch. The controller test used an administrator account; restricted-profile permissions require separate deployment validation. |
| `managed_switch_stacking` | [F-CHEAT-80, F-CHEAT-802](https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet) | FortiOS 8.0.0 and 8.0.1 CLI references define this command; FortiOS 7.6.7 does not. The FortiOS 8.0.1 controller test (administrator account) received a feature refusal, return code -7622, because the tested model is not a stacking switch. The same 2026-10-15 end-to-end MCP call above exercised this query on FortiOS 7.6.7 instead, through Helper's own read-only account, and received a different CLI refusal because the command itself is absent from that build's privileged CLI help -- not an account-permission effect: `command parse error before 'stacking'` / `Command fail. Return code -61` (`device_cli_error`). Neither firmware produced a positive stacking result; a positive test requires stacking-capable hardware and remains unverified. |
| `managed_switch_lldp` | [F-CHEAT-80, F-CHEAT-802](https://docs.fortinet.com/document/fortigate/8.0.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet) | FortiOS 8.0.1 controller returned data for an enrolled managed switch. The controller test used an administrator account; restricted-profile permissions require separate deployment validation. |

Query enrollment does not add firmware or hardware capabilities. The catalogue does not automatically filter entries by firmware: verify the exact firmware, model and account before opting in. A stacking command rejected by FortiOS 7.6.7, or a PoE command rejected by a non-PoE model, is an error result rather than a successful measurement.

### Exact query templates

Acceptance here describes the code whitelist only. The live-result limitations above still apply.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `certificate_details` | `get vpn certificate local details {certificate}` | `certificates.certificate_name` | normal | F-CERT-LOCAL |
| `managed_switch_status` | `diagnose switch-controller switch-info status {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CHEAT-80, F-CHEAT-802 |
| `managed_switch_poe` | `diagnose switch-controller switch-info poe summary {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CHEAT-80, F-CHEAT-802 |
| `managed_switch_mac` | `diagnose switch-controller switch-info mac-table {managed_switch}` | `managed_switches.managed_switch_serial` | high-volume | F-CHEAT-80, F-CHEAT-802 |
| `managed_switch_stacking` | `diagnose switch-controller switch-info stacking status {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CHEAT-80, F-CHEAT-802 |
| `managed_switch_lldp` | `diagnose switch-controller switch-info lldp neighbors-summary {managed_switch}` | `managed_switches.managed_switch_serial` | high-volume | F-CHEAT-80, F-CHEAT-802 |
| `switch_loop_guard` | `diagnose switch-controller switch-info loop-guard {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_bpdu_guard` | `diagnose switch-controller switch-info bpdu-guard-status {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_flap_guard` | `diagnose switch-controller switch-info flapguard status {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_dhcp_snooping` | `diagnose switch-controller switch-info dhcp-snooping database {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_dhcp_bindings` | `diagnose switch-controller switch-info dhcp-snooping status {managed_switch}` | `managed_switches.managed_switch_serial` | high-volume | F-CLI-768, F-CLI-802 |
| `switch_fan_health` | `diagnose switch-controller switch-info fan {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_source_guard` | `diagnose switch-controller switch-info ip-source-guard violations {managed_switch}` | `managed_switches.managed_switch_serial` | high-volume | F-CLI-768, F-CLI-802 |
| `switch_lldp_port` | `diagnose switch-controller switch-info lldp neighbors-detail {managed_switch} {port}` | `managed_switch -> managed_switches.managed_switch_serial, port -> managed_switch_ports.managed_switch_port` | normal | F-CLI-768, F-CLI-802 |
| `switch_mac_limit` | `diagnose switch-controller switch-info mac-limit-violations interface {managed_switch} {port}` | `managed_switch -> managed_switches.managed_switch_serial, port -> managed_switch_ports.managed_switch_port` | normal | F-CLI-768, F-CLI-802 |
| `switch_mclag_icl` | `diagnose switch-controller switch-info mclag icl {managed_switch}` | `managed_switches.managed_switch_serial` | normal | F-CLI-768, F-CLI-802 |
| `switch_trunk_status` | `diagnose switch-controller switch-info trunk status {managed_switch} {mclag_trunk}` | `managed_switch -> managed_switches.managed_switch_serial, mclag_trunk -> managed_switch_trunks.managed_switch_trunk` | normal | F-CLI-768, F-CLI-802 |
| `switch_mclag_consistency` | `diagnose switch-controller switch-info mclag peer-consistency-check {managed_switch} {mclag_trunk}` | `managed_switch -> managed_switches.managed_switch_serial, mclag_trunk -> managed_switch_trunks.managed_switch_trunk` | normal | F-CLI-768, F-CLI-802 |
| `lacp_detail` | `diagnose netlink aggregate name {aggregate} show` | `interfaces.fortios_interface` | normal | F-CLI-768, F-CLI-802 |

For `switch_lldp_port` and `switch_mac_limit`, the fixed commands address the named managed switch and port. The CLI references do not define a port-name grammar or maximum. Helper accepts only the conservative `port[1-9][0-9]{0,2}` form (port1 through port999) and requires the exact value in `managed_switch_ports`; this is a Helper input constraint, not a vendor limit.

For `switch_mclag_icl`, `switch_trunk_status` and `switch_mclag_consistency`, F-CLI-802 documents `diagnose switch-controller switch-info mclag icl <switch>` (printed page 3519), `mclag peer-consistency-check <switch> <mclag-trunk-name>` (page 3520) and `trunk status <switch> <trunk-port>` (page 3526); F-CLI-768 documents the same entries on pages 3341 and 3347. `<switch>` is the managed FortiSwitch device ID. The references do not define a trunk-name grammar or maximum; Helper accepts only `[A-Za-z0-9_][A-Za-z0-9_-]{0,34}` (no leading hyphen) and requires the exact value in `managed_switch_trunks`, which is a Helper input constraint, not a vendor limit. For these three queries `ssh_read` adds a `mclag` object parsed from the device output with only grammar-checked values (port names, switch serials, fixed state words; no MAC addresses); the states, their order and the `incomplete` rule for unreadable output are described in [Helper tools](../tools.md#fortiswitch-mclag-state). `switch_mclag_icl` shows only configuration; ICL link health comes from `switch_trunk_status` on the ICL trunk. A switch that answers `does not support MCLAG feature!` returns `ok: true` with `mclag.state` `not_supported` instead of a CLI error. The trunk toward an HA secondary FortiGate is normally inactive on one MCLAG peer (STP `DISCARDING` without active LAG ports), so `degraded` with an empty `stp_blocked` there is expected and not a member failure.

#### What the managed-switch guard reads answer

Measured on FortiOS 8.0.2 build 0251 (FortiGate-80F with two managed FortiSwitch units, 2026-11-01):

- `switch_dhcp_bindings` (`dhcp-snooping status`) returns the per-switch `Client db`, `Server db`, `Client6 db` and `Server6 db` tables, that is the learned DHCP clients (MAC address, VLAN, client IP, lease, expiry, port, DHCP server IP) and servers, not an on/off state. With a client on a snooping VLAN the `Client db` row matched the DHCP lease of the FortiGate (same MAC address, IP, VLAN 52 and port18). FortiOS 7.6.8 build 3744 on FortiGate 60F prints the same tables.
- `switch_dhcp_snooping` (`dhcp-snooping database`) returns the snooping settings and no per-client row, contrary to the CLI Reference wording that it shows database details: `snoop-enabled-vlans`, `verifysrcmac-enabled-vlans`, the trusted and untrusted ports, the maximum and current client and server database entries, and the DHCP global configuration. An empty `snoop-enabled-vlans` means snooping is enabled on no VLAN of that switch.
- Vendor documentation error: the FortiOS CLI Reference (8.0.2, pages 3512–3513, and the same entries in 7.6.7) describes `dhcp-snooping database` as "DHCP snooping database details" and `dhcp-snooping status` as "DHCP snooping status". On physical devices it is the other way round: `status` prints the client and server binding tables and `database` prints the settings and counts. Verified by reading both commands on a FortiGate-80F HA pair with FortiOS 8.0.2 build 0251 (FortiSwitch S224EP with a wired DHCP client) and on a FortiGate-60F with FortiOS 7.6.8 build 3744 (FortiSwitch S224EP and S108EN). NetOps follows the device output.

`switch_source_guard` lists only violations the switch records. Recording is set in `config switch-controller ip-source-guard-log`: `log-violations` (default `disable`) and `violation-timer` (0-1500 s, default `0`) (F-CLI-768 p. 1251, F-CLI-802 p. 1290). With these defaults the command prints `log-violation is globally disabled or violation timer is zero.` and nothing else, so its output does not say whether IP source guard drops traffic. Whether a port enforces IP source guard is the per-port `set ip-source-guard [disable|enable]` under `config switch-controller managed-switch` > `config ports` (default `disable`; F-CLI-768 p. 1271, F-CLI-802 p. 1305). Read it with the opted-in `config_read` described in [tools.md](../tools.md#reading-the-whole-fortios-configuration-config_read): `section="switch-controller managed-switch"`, `redaction="full"`, `include_defaults=true`, `contains="set ip-source-guard"`. A filtered line does not name its switch or port, so answer for a specific port: repeat the same read without `contains`, collect every page (`next_offset` until `null`), and take the `set ip-source-guard` line inside that switch's `edit "<port>"` block. The answer covers only switches and ports inside the account scope reported with the capture. On the 8.0.2 test switches every port read showed `disable`. The `ip-source-guard-log` settings are not in a section read; read them with `section="all"`, `include_all=true`, `redaction="full"`, `include_defaults=true`, `contains="ip-source-guard-log"`, `context=3`. An empty violation list means only that the result holds no recorded violation; it is meaningful only for a port with `ip-source-guard enable` while `log-violations` is `enable` and `violation-timer` is above 0, and it does not prove that no violation ever occurred.

`switch_mac_limit` lists violations of the per-port `learning-limit` (1-128 dynamic MAC addresses; `0` = no limit, the default; F-CLI-768 p. 1293, F-CLI-802 p. 1330). An empty table on a port with `learning-limit 0` means that no limit is configured, not that the port is within a limit. Check a specific port the same way: the section read without `contains`, all pages, and the `set learning-limit` line inside that port's `edit "<port>"` block, within the reported account scope. On the 8.0.2 test switches every port read showed `set learning-limit 0`.

For `lacp_detail`, both CLI References document `diagnose netlink aggregate name <name> <action>`; `show` displays details and `clear` clears LACPDUs counters. The fixed query permits only `show`. The command entries describe `<name>` as an aggregate name string but do not specify a length or character grammar. Helper reuses its existing FortiOS interface validator for the enrolled `aggregate` slot (ASCII interface form, at most 15 characters, with reserved selectors refused); these are Helper constraints, not a vendor-documented name limit.


### Policy-route data-plane view

The 7.6.8 Administration Guide page links the shared FortiOS 7.6.0 troubleshooting sheet; its `diagnose firewall proute list` row describes SD-WAN rules and policy routes in the data plane. The sheet available from the 8.0.2 page is branch-shared FortiOS 8.0 content, not a separately versioned 8.0.2 sheet. This view can help investigate policy-route or SD-WAN steering alongside the routing table, but it does not establish which policy or route applies to a particular packet. No device output sample or runtime result is claimed.

### FQDN address object lookup

The 7.6.8 and 8.0.2 CLI References document `diagnose firewall fqdn get-ip <name>` as getting and displaying one IP FQDN address; the argument is an Address Name string. The `config firewall address` field table documents address-object `name` with maximum length 79, and separately exposes an `fqdn` field. Helper requires the supplied name to be enrolled in `firewall_addresses` and applies its ASCII name pattern as a Helper constraint, not vendor-documented character grammar. The command description does not say it validates the object's configured type or that a returned result means the FQDN is healthy.

### IPv6 policy-route view

The 7.6.8 and 8.0.2 CLI References list `diagnose firewall proute6 list` with the description "List IPv6 policy routing." The corresponding `proute list` entry has a separate optional <number> form, while `proute6 list` is shown without that parameter. No default or numeric range is specified. This query is limited to the documented IPv6 policy-route listing. No device output or runtime result is claimed.

### Managed FortiSwitch guard and status views

The FortiOS 7.6.8 and 8.0.2 CLI References document each command with a <switch> argument described as Managed FortiSwitch device ID. string. They do not define serial grammar, length, defaults, port selectors, or VDOM selectors. NetOps reuses the managed_switches.managed_switch_serial enrollment slot and existing Helper validator; that is a Helper constraint, not vendor-defined syntax. The four guard and status views and the fan status query are normal-volume; IP source guard violations and the DHCP snooping database are marked high-volume as pagination advisories because they may return variable collections. The references describe the database command as DHCP snooping database details but do not list its columns or give an output sample; IP, MAC, port, and lease fields are not promised. The fan command reports fan status only; fanless hardware or an unsupported model must not be treated as a health pass. No runtime success is claimed.

## Diagnostic state views

The following exact diagnostic-state queries are version-bound to their FortiOS catalogue and FortiGate-VM64-KVM 7.6.7 build3704 or 8.0.0 build0167 scope. Verify the configured account's permission for each query independently; a catalogue entry does not establish availability through every restricted read role. Helper requires a separate enabled query for each view.

| Query name | Exact command template | Inventory slot | Volume | Primary references |
| --- | --- | --- | --- | --- |
| `ping_options` | `execute ping-options view-settings` | none | normal | F-PING-OPTIONS-76 |
| `traceroute_options` | `execute traceroute-options view-settings` | none | normal | F-TRACE-OPTIONS-80 |
| `debug_state` | `diagnose debug info` | none | high-volume | F-DEBUG-80 |
| `session_filter_state` | `diagnose sys session filter` | none | normal | F-DIAG-SYS-80 |

These state views authorize no option setters, filter setters, debug enable/disable, reset, traffic probe or capture. Bounded recipes remain separately enrolled operations with their own permission and cleanup contracts.
- F-PING-OPTIONS-76: [FortiOS 7.6.4 CLI Reference: execute ping-options](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/221756471/execute-ping-options).

- F-TRACE-OPTIONS-80: [FortiOS 8.0.0 CLI Reference: execute traceroute-options](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/113792463/execute-traceroute-options).

- F-DEBUG-80: [FortiOS 8.0.0 CLI Reference: diagnose debug](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/159376337/diagnose-debug).


## FortiOS 7.6.8 and 8.0.2 resource diagnostics

The following three fixed reads were checked against the exact CLI Reference for both versions. They use the existing per-target query grants, identity and SSH checks, output limits, pagination and credential redaction. Source references establish syntax; they do not establish measured output or read-only account permissions on a particular device.


F-CLI-768: [FortiGate / FortiOS 7.6.8 CLI Reference](https://docs.fortinet.com/document/fortigate/7.6.8/cli-reference), printed pages 3080–3081 and 3539.
F-CLI-802: [FortiGate / FortiOS 8.0.2 CLI Reference](https://docs.fortinet.com/document/fortigate/8.0.2/cli-reference), printed pages 3241–3242 and 3729.

### Selected SD-WAN member and rule reads

The added templates were checked against the exact FortiOS 7.6.8 and 8.0.2 CLI References on 2026-10-30. This is source qualification; actual firmware/account validation is separate. Enroll canonical decimal member IDs 1–512 in helper.read_inventory.sdwan_members and rule IDs 1–4000 in helper.read_inventory.sdwan_rules, then grant each query individually. Zero/all selectors are outside these selected-object reads. No device configuration changes are performed.

The member detail explains the selected WAN member state; service4/service6 explain rule path selection for the corresponding address family; route/route6 show that member's SD-WAN routes. These observations do not prove delivery of a particular packet. Empty IPv6/SD-WAN results remain empty evidence. The existing sdwan_health summary remains available.


The selected SD-WAN reads use F-CLI-768 and F-CLI-802 from the primary source manifest.


### Selected SLA history and link-monitor status

These two reads were checked against the exact FortiOS 7.6.8 and 8.0.2 CLI References on 2026-10-30 (F-CLI-768 and F-CLI-802). Their runtime/account qualification is separate. Grant each query individually.

For sdwan_interface_quality, enroll the interface in helper.read_inventory.interfaces. The CLI references describe interface quality details but do not specify output fields or a retention interval.

For sdwan_sla_history, enroll the health-check name in helper.read_inventory.sdwan_health_checks, and the selected member ID in sdwan_members. Every argument must match enrolled inventory exactly. The Helper uses the two-argument form shown in the FortiOS 8.0.2 Administration Guide (Performance SLA log examples on pages 1218 and 1806). The optional third CLI argument, a dial-up child tunnel name (page 1221), is not offered; with a regular member interface it returned no lines on FortiOS 7.6.8. The result describes health-check quality in the last ten minutes: latency, jitter and packet loss. It is not durable history or proof of delivery for a particular packet.

For link_monitor_status, enroll one name in helper.read_inventory.link_monitors. It shows that monitor's status without restart or configuration changes. The all selector is excluded.

The resource-section page references above apply only to conserve_state, cpu_cores and fortiguard_communication. For these two monitor reads, see the FortiOS 7.6.8 CLI Reference pages 3451 (link-monitor status) and 3539 (sla-log), and FortiOS 8.0.2 pages 3636 and 3728–3729 respectively.

Find the names and IDs in the captured configuration: system sdwan / health-check gives the health-check name; members gives the member seq-id and its interface; service gives the rule ID. system link-monitor gives the monitor name. Enroll those exact values. The Helper checks each argument against inventory individually; it does not verify that a particular health-check/member combination belongs together. Empty output for a mismatched combination is not evidence of a healthy link.

Health-check and link-monitor names are limited to 1–35 ASCII characters, starting with a letter or digit and followed only by letters, digits, underscore, dot or hyphen. Names containing spaces, quotes or Unicode are not supported by these query templates; there is no free CLI fallback. Vendor configurations using those names must not be silently normalized or widened to all monitors. The existing member ID and FortiOS interface restrictions also apply.


### BGP peer routes and OSPF interfaces

The exact [FortiOS 7.6.8 Administration Guide chapter](https://docs.fortinet.com/document/fortigate/7.6.8/administration-guide/574215/cli-troubleshooting-cheat-sheet) explicitly directs readers to the shared [FortiOS 7.6.0 CLI troubleshooting cheat sheet](https://docs.fortinet.com/document/fortigate/7.6.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet). That vendor link is the 7.6.8 applicability evidence; there is no separately labeled patch-specific 7.6.8 cheat sheet in this source chain. The eight command forms also appear in the shared FortiOS 8.0 cheat sheet served from the [FortiOS 8.0.2 document page](https://docs.fortinet.com/document/fortigate/8.0.2/cli-troubleshooting-cheat-sheet). Source review date: 2026-10-30. Actual firmware/build/account validation remains separate.

Enable each query individually. BGP IPv4 queries require one canonical IPv4 peer address and IPv6 queries one canonical IPv6 peer address, exactly enrolled in helper.read_inventory.addresses. Prefixes, hostnames and all-peer selectors are outside these queries. The vendor IPv6 placeholder includes /m, but its description explicitly calls for the IPv6 address of the peer; these templates retain the existing address-only scope.

Advertised routes show what this device exports to that peer; received routes provide the pre-policy input view when already available; routes shows the accepted view. Compare received and accepted only when both are available. An unavailable received-routes view must remain unavailable: retain the device response/error and do not enable soft reconfiguration, reset a session or silently substitute accepted routes. Accepted or advertised routes alone do not prove FIB installation or packet delivery.

The two OSPF interface views show interface state and protocol parameters for the corresponding address family, complementing the existing neighbor summaries. Empty route/interface output is not evidence of a working path. All eight views use the existing pagination, output limits, redaction and audit behavior.


The exact unavailable message is documented by the generic official [BGP soft-reconfiguration Technical Tip](https://community.fortinet.com/fortigate-3/technical-tip-bgp-routing-process-when-soft-reconfiguration-is-enabled-117793): IPv4 without a leading percent sign and IPv6 with one. The existing FortiOS CLI error guard recognizes this message even when SSH returns zero, returns device_cli_error, and retains redacted device evidence without caching it. This generic note establishes the refusal text, not exact-version runtime support. The [received-routes versus routes Technical Tip](https://community.fortinet.com/fortigate-3/technical-tip-difference-between-bgp-received-routes-and-routes-commands-143929) explains the pre-policy versus post-policy distinction. No configuration-enabling steps from those notes are executed.

### Fixed NAT, resolved FQDN and aggregate IKE reads

The five exact commands above are documented without arguments by both FortiOS 7.6.8 and 8.0.2 CLI References (F-CLI-768 and F-CLI-802). Enroll each query individually for the target. No inventory selectors or trailing CLI arguments are accepted. NAT pool statistics help investigate resource exhaustion; resolved FQDN addresses help explain firewall object matching. The FQDN table uses the existing high-volume pagination path.

The IKE counts view reports object counts. The vendor gives both errors and stats the same general description, "IKE statistics." The catalogue preserves their distinct CLI views without claiming distinct counters or measured account support. Compare actual device output before deciding whether both views add diagnostic value. Neither view authorizes IKE restart, gateway clear, secrets or detailed keying-state dumps. Source qualification is separate from runtime and account validation.

### DNS cache reads on a terminal

`dns_cache` (`diagnose test application dnsproxy 7`) and `fqdn_cache` (`diagnose test application dnsproxy 6`) are the only FortiOS queries read through an interactive terminal session (`transport` `pty` in the result). FortiOS writes the output of these two commands only to a terminal: on the exec channel it sends neither standard output nor standard error, only the prompt, so the Helper would report `empty` for a full cache. Measured on a FortiGate-80F HA primary with FortiOS 8.0.2 build 0251 on 2 November 2026 with a super_admin test account: through the terminal `dnsproxy 7` returned 33 lines (1743 bytes) beginning with `worker idx: 0` and `dnsproxy 6` returned 17 lines (1646 bytes); the same `dnsproxy 7` on the exec channel 98 seconds later returned 57 bytes of standard output, only two prompts, and no standard error. The identity probe `get system status` stays on the exec channel. Then the Helper opens a terminal, verifies the `<hostname> # ` prompt, also with the HA role `<hostname>(Primary) # ` or `<hostname>(Secondary) # `, sends the one catalogue command and reads up to the next prompt. The FortiOS enrollment prerequisites are unchanged: `fortios_output_standard_verified: true` (a pager would stop the answer before the prompt), the query enabled in `enabled_queries`, the same refusal classifier, the 60-second read timeout and the 2,000,000-byte capture cap. An answer that does not reach the prompt within 60 seconds, or that exceeds the cap, ends with `ok: false` and an error that names the timeout or the cap; no partial cache is returned. `dnsproxy 7` dumps the cache of the first DNS worker only (FortiOS 8.0.2 Administration Guide, DNS troubleshooting). The measured cache used about 125 bytes per entry, so a cache at the `dns-cache-limit` of 5000 entries is expected to stay well below the cap; entries with very long names or many addresses can still exceed it.

### WLAC WTP and VAP views

The FortiOS 7.6.8 and 8.0.2 CLI References document only generic WLAC option/value syntax. The WTP and VAP forms are attributed to the shared FortiOS 7.6.0 troubleshooting sheet linked from the 7.6.8 guide, rather than claimed as exact-version CLI Reference entries. Stored 8.0.2 build 0251 raw admin help also lists the control-plane WTP, data-plane WTP, control-plane VAP, and station `-c sta [mac]` / `-d sta [mac]` forms. The station queries require an exact enrolled colon-separated MAC under the Helper grammar, use only the list/detail forms, and exclude reset, kick, and stateful `sta_filter` operations. The generic CLI references do not specify the MAC grammar. Exact 7.6.8/8.0.2 installed-Helper acceptance and per-account authorization remain unverified; returned output is device-observed rather than a complete inventory guarantee.


### Routing cache and OSPF database summaries

The route_cache view uses exactly diagnose ip rtcache list, documented as listing
the routing cache in the FortiOS 7.6.8 CLI Reference (page 3134) and 8.0.2 CLI
Reference (page 3306). It does not clear entries or substitute cache statistics.
Cached decisions do not prove packet delivery or current forwarding state.

The IPv4 OSPF database brief command is documented by the shared FortiOS 7.6.0
troubleshooting sheet explicitly linked from the FortiOS 7.6.8 Administration
Guide chapter 574215, and by the branch-shared FortiOS 8.0 sheet served from the
8.0.2 troubleshooting-sheet URL. The same sheets list the IPv6 form with brief,
but FortiGate-60F 7.6.8 and FortiGate-VM64 8.0.2 reject it with parse error
before brief (-61); their help for the IPv6 prefix lists only LSA selectors, and
the bare get router info6 ospf database was accepted on both (rc 0, no refusal). Brief database entries complement status, interfaces
and neighbors; they do not prove route installation or traffic forwarding.

All three queries require their individual existing enabled-query grant, accept
no parameters, and reuse output redaction, bounded paging, cache and audit.
No debug, database reset, full database dump or configuration change is enabled.
Installed Helper and actual device/account qualification remain pending.

## Bounded TCP/UDP tuple diagnostics

The tuple-bearing sessions, flow and sniffer recipes use exact identity gates: FortiGate-VM64 / FortiOS 8.0.2 build 0251 keeps scalar flow and session selectors; FortiGate-60F / FortiOS 7.6.8 build 3744 uses the 7.6.8 range grammar. The helper represents each enrolled address and port as an equal from/to pair. For flow, saddr, daddr, sport and dport are ranges but proto remains one value. For sessions, src, dst, sport, dport and proto are range pairs. Protocol is limited by the helper to TCP (6) or UDP (17), although the vendor syntax accepts other protocol numbers.

F-CLI-768 documents these forms in printed pages 2927 and 2929 for diagnose debug flow filter, pages 3543, 3544, 3549 and 3551 for diagnose sys session filter, pages 2926 and 2935–2936 for flow clear/trace cleanup, and page 3319 for diagnose sniffer packet. F-CLI-802 documents scalar flow/session selectors on pages 3078, 3080–3081 and 3733–3741. The sniffer filter argument is a flexible logical filter; the 7.6.8 example uses protocol, port, host and parenthesized OR terms. Its frame size defaults to interface MTU. The existing bounded sniffer expression stays unchanged and does not set persistent filter state.

Session and flow recipes first refuse non-empty filters, then clear their own temporary filter and require exact readback equality with the captured baseline. Flow also refuses pre-existing enabled debug, then disables debug, stops the trace, clears the filter and verifies debug is disabled. The 7.6.8 session/flow empty-filter output shape and cleanup readback have not yet been qualified on the device; actual 7.6.8 runtime/account qualification remains NOT RUN. Source syntax does not establish account permissions or a match/result on live traffic.
