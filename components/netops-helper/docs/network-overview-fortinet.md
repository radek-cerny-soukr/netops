# Network overview on FortiOS

This page describes what [`network_overview`](network-overview.md) reports for a FortiGate enrolled with `ssh_platform: fortios`, including the FortiSwitch units it manages over FortiLink and the FortiAP units it manages as a wireless controller. The FortiGate row carries the controller facts. Switches and access points appear under it in `managed`, sorted by kind and identifier.

## Reads and order

All CLI reads of one call share one held, pinned SSH session to the FortiGate. The connection pacing of the Helper applies, and no host key is scanned when a pin is enrolled. Each read is an existing catalogue query. When the budget is short, the reads that come first are kept.

| Order | Read | Reported fields |
|---|---|---|
| 1 | `system_status` (identity) | `version`, `model`, `firmware_support`, `licenses`, `poe` |
| 2 | `performance` | `uptime_seconds`, `cpu`, `memory` |
| 3–4 | `system_interfaces` with `interface_list` (or `physical_interfaces`) | `interfaces.admin_up_down` |
| 5 | `ha_status` | `redundancy` |
| 6 | `hardware_sensors` | `temperatures`, `fans`, `power` |
| 7 | `autoupdate_versions` | `fortiguard` |
| 8 | With an enrolled FortiOS REST token: fixed monitors `switch_status`, `switch_health`, `managed_ap`, `ap_status`. Without it: `managed_switch_status` and `managed_switch_poe` per enrolled switch, and `wifi_ap_status`. | `managed` |
| 9 | `managed_switch_port_stats` once per enrolled switch, without a port | `managed[i].interfaces` |
| 10 | `interface_details` (or `interface_hardware`) per enrolled interface | `interfaces.with_errors` |
| 11 | With an enrolled REST token, only for opted-in queries: `managed_switch_status` and `managed_switch_poe` per enrolled switch, and `wifi_ap_status` | `managed` when a monitor is refused |
| 12 | Only for opted-in queries, per enrolled switch: `managed_switch_stacking`, `switch_mclag_icl`, and `switch_trunk_status` for each enrolled trunk (`managed_switch_trunks`) after the ICL read | `managed[i].redundancy` |

Up to eight enrolled switches and eight enrolled interfaces are planned. Enrolled switches or interfaces beyond that get no read: `missing` then has `source_limit` with `omitted_count` for `managed` or `interfaces.with_errors`. If the account has not opted in to a query of steps 1–10, the step is reported as `policy_scope`. The overview never sends a read to an address, name, or credential printed by the controller.

## Controller fields

- `version` is `<version> build<NNNN>` and `model` is the FortiGate product name. The serial number and host name are not published.
- `cpu.used_pct` is 100 minus the aggregate idle share. FortiOS prints no sampling interval, so `sample_seconds` is null. `memory` comes from the same `performance` output. `uptime_seconds` has minute resolution.
- `admin_up_down` lists physical, aggregate, redundant, and hardware switch interfaces that are configured `up` and that the kernel reports without carrier. Other interface types are not evaluated. An admin-up interface of these types without a row in the link listing is not counted as up: `missing` has `interfaces.admin_up_down` with `source_limit` and the number of such interfaces in `omitted_count`. `get system interface physical` has no row for a hardware switch or an aggregate.
- The device-wide interface list on the measured firmware has no error counters. `with_errors` therefore covers only the enrolled interfaces, `interfaces.scope` is `enrolled_interfaces`, and `missing` records `source_limit`. Drop counters are reported as drops. A row lists a port only when it has error counts.
- `redundancy` reports `standalone` when the status shows standalone mode. In a cluster it reports `ok` only when `HA Health Status` is `OK` without warnings. Otherwise it reports `degraded`. It also includes the local role and the member count. It does not compare peers.
- Sensors are mapped by their type. An absent optional power supply slot is omitted. A voltage alone does not confirm a working supply. When a model prints no sensor of a kind, that field is `not_applicable`.
- `fortiguard` has one entry per package that prints `Contract Expiry Date`. A date gives `valid`, `expiring` (30 days or fewer), or `expired`. `n/a` gives `unknown` with no date. Packages without a contract line are omitted.
- `licenses` is `not_applicable` on hardware models. The local `poe` budget is `not_applicable` unless the product name contains `POE`. A VM licence and the local budget of a PoE model are not parsed and are reported as `source_limit`.

## FortiSwitch over FortiLink

With HTTPS monitors, switches that the controller lists are reported, including switches that are not enrolled, subject to the duplicate-serial rule below and to the detail and response size limits of the overview (at most 64 `managed` entries per row). Status and health are joined by serial number. Duplicate serials in the status monitor are omitted from its switch list and make the status read `unparsed`. An enrolled switch with such a serial has a null `reported_state` with reason `unparsed` in `missing`. Duplicate matching health rows make the health read `unparsed` and leave the switch's status entry intact. `model` is the platform code in the image string, for example `S224EP`. `reported_state` is the controller's connection state. Uptime, CPU, memory, temperatures, fans, supplies, and the PoE budget and draw come from the health monitor. A temperature takes the switch's overall temperature rating. Licences and FortiGuard are `not_applicable`.

If the status monitor is refused or unusable, the enrolled switches are listed with model, version and PoE from the opted-in `managed_switch_status` and `managed_switch_poe` reads. If only the health monitor fails for a switch, its PoE budget comes from `managed_switch_poe` when that read is opted in.

Without HTTPS, only enrolled switches appear. Model and version come from `managed_switch_status`. The PoE budget and draw come from `managed_switch_poe`. State and health metrics are `source_limit`.

`redundancy` of an enrolled switch comes from opted-in operational reads. `switch_mclag_icl` shows whether an ICL is configured: without one, the entry is `{kind: mlag, state: standalone}`. With one, `switch_trunk_status` of the ICL trunk gives `ok` when the trunk and all members are up, and `degraded` (finding `redundancy_degraded`) when the trunk or a member is down. If the ICL trunk is not enrolled, the state is `unknown` with `source_limit`. The stack status of a stacking switch has not been measured, so a readable `managed_switch_stacking` answer is `unparsed`. A switch that answers `is not a stacking switch` or does not support MCLAG is reported with the refused read and the reason `unparsed`, because the overview frame does not pass the text of a refused CLI read to the adapter. Without these opted-in reads, `redundancy` is `source_limit`.

The ports of enrolled switches come from one full `port-stats` listing: `admin_up_down` contains ports that are administratively up with line protocol down. `with_errors` lists ports that have input or output errors. If the listing is cut short, the result is `unparsed` instead of a partial port list.

## FortiAP

With HTTPS monitors, `managed_ap` provides the access point list. If `wtp_active + wtp_down` does not match that list, or `wtp_active` differs from the number of connected access points, both reads are reported as `unparsed`. `model` is the platform code in the image string. `uptime_seconds` is the GET sample time minus the UTC epoch of the last reboot. The memory monitor does not document its unit, so `memory` contains only the used share. CPU use and temperatures come from the same document. Wired error counters fill `with_errors`. The source has no administrative port state. For disconnected access points, CPU, memory, temperatures, uptime, and interfaces are reported as `unreachable` because those fields contain only placeholders or old samples. An access point is a PoE consumer, so `poe` is `not_applicable`, as are `redundancy`, `licenses`, and `fortiguard`.

Without HTTPS, or when `managed_ap` is refused and `wifi_ap_status` is opted in, `wifi_ap_status` provides identifier, model, version, and connection state. An access point identifier that appears more than once in `managed_ap` is not reported, and the read is `unparsed`.

## Coverage and limits

The FortiGate row stays `partial` while any child is partial or any field has a reason other than `not_applicable`. A refused HTTPS monitor (`permission_denied`, `rest_unavailable`, or an envelope outside the root VDOM) keeps the SSH facts, the enrolled switches, and what the opted-in CLI reads of step 11 show. A lost terminal stops the remaining CLI reads of that call without a reconnect.

The adapter was measured on a FortiGate-80F with FortiOS 8.0.2 build0251, two FortiSwitch 224E-POE units running 8.0.1 build0069, and FortiAP units running 8.0.1 build0085. Other FortiOS versions return `firmware_support: untested` (finding `firmware_untested`) and are still read.
