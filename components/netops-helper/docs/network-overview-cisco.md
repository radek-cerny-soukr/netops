# Network overview: Cisco IOS, IOS XE and NX-OS

This page describes what `network_overview` reads on `cisco_ios`, `cisco_xe` and `cisco_nxos` targets and how the fields are filled. The general contract, paging and limits are in [Network overview](network-overview.md). Call the tool on the Helper's HTTPS MCP endpoint. Every read is an existing catalogue query and needs the matching entry in `enabled_queries`; a planned query that is not enabled is reported as `policy_scope` for its fields.

## Reads

| Platform | Reads in priority order |
|---|---|
| IOS, IOS XE | `version` (identity); on IOS XE with `platform_resources` enabled that read first and `cpu`, `memory` only as an enabled fallback, otherwise `cpu`, `memory`; `interfaces_details`; with `device_types` `switch` or no type also `stack_members`, then `stack_ports` after a usable member table; `environment`; for a switch `power_inline`; on IOS XE `c9800_redundancy` and then `c9800_chassis_rmi` last, only when both are enabled |
| NX-OS | `version` (identity), `system_resources`, `interfaces`, `vpc_status`, `redundancy_status`, `interfaces_counters_errors`, `environment`, `license_usage` |

The order decides which fields remain when the read budget is short; the reads after the budget are reported as `read_limit` or `rate_limited`. The two Catalyst 9800 reads come after every other read, so they never take the budget of another approved read. The plan is fixed before the identity read, so on an IOS XE image that is not a controller they can still run when budget is left; their output is then discarded and `redundancy` names them `not_applicable`. IOS and IOS XE are told apart by the `show version` signature: an IOS XE answer on an `cisco_ios` enrollment (or the opposite) stops the plan with `identity_unverified` before any further read.

## Fields

| Field | IOS and IOS XE | NX-OS |
|---|---|---|
| `version`, `model`, `uptime_seconds` | From `show version`. Uptime is converted to seconds at the printed resolution (minutes). A missing model line is `source_limit`. | From `show version`; kernel uptime in seconds. |
| `cpu` | IOS XE with `platform_resources`: the `Control Processor` row of `show platform resources`, `sample_seconds` null (no interval printed). Otherwise, or when that row is missing, the one-minute value of `show processes cpu`, `sample_seconds: 60`. | 100 minus the aggregate idle share of `show system resources`; the output has no interval, so `sample_seconds` is null. |
| `memory` | IOS XE with `platform_resources`: the `DRAM` row (used and maximum MB as binary megabytes; the printed percent must agree with used / maximum). Otherwise the Processor pool of `show processes memory`; the pool must satisfy used + free = total. A refused or incomplete preferred read stays listed in `missing` even when the fallback filled the value. | `Memory usage` of `show system resources`; used + free must equal total. |
| `interfaces.admin_up_down` | Ports whose `show interfaces` header says `is down` (not `administratively down`). Deleted subinterfaces are left out. | Ports with status `notconnect` in `show interface status`. A status outside the known values marks the read incomplete. |
| `interfaces.with_errors` | Non-zero input/output errors, CRC and input/output drops of `show interfaces`, `counter_kind: cumulative`. Drops keep their own names. | Non-zero FCS, receive and transmit errors and discards of `show interface counters errors`. |
| `temperatures`, `fans`, `power` | `show env all` (IOS) or `show environment all` (IOS XE). A supply with `No Input Power`, `Bad` or another failure state is `failed` (`hardware_degraded`); a slot or fan `NOT PRESENT` is left out; a printed state outside the known values is `unknown` and marks the read incomplete. A read-only account on a virtual image is refused; the fields are then `permission_denied`. | `show environment`. Sections the virtual Nexus prints without hardware rows are `not_applicable`; on other models `source_limit`. |
| `poe` | Sum of the module table of `show power inline` (budget, used, available). A row that contradicts Available − Used = Remaining leaves `poe` null with `unparsed`. Routers: `source_limit`. | `not_applicable` (no PSE ports). |
| `redundancy` | StackWise members and stack ports: `standalone` for one member; `ok` when every member is Ready and the port table lists exactly both stack ports of every member, each OK with link OK, link active and sync OK; `degraded` when a member is not Ready or a listed port fails one of these; `unknown` with an incomplete `stack_ports` read when a member's ports are missing. Catalyst 9800 controller HA from the two controller reads when the image is a controller. Routers: `source_limit`. HSRP and VRRP are not redundancy here. | `vpc` from `show vpc brief`: `ok` only with a formed peer adjacency, a live keep-alive, successful global consistency, every peer link `up` and every local vPC `up` with consistency `success`; otherwise `degraded` (for example a vPC `down*` with `failed` consistency). `ha` from `show redundancy status`: `standalone` for an active supervisor without standby. |
| `licenses` | `source_limit`: the supported images print no license state in `show version`. | Installed features and features used without an installed license (`unlicensed`, also under the honor model) from `show license usage`. An expiry date column is not interpreted yet; such a row is `unknown` and the read incomplete. |
| `fortiguard`, `managed` | `not_applicable` / null. | `not_applicable` / null. |

A null field the plan should have filled has a `missing` entry with its cause. Optional values the source does not print are null without a `missing` entry and do not change completeness, for example `cpu.sample_seconds` on NX-OS and from `show platform resources`; `managed` is null without an entry because these platforms have no managed children. Interface counters are cumulative since the last clear; a non-zero value says that errors were counted, not that they are increasing now.

## Known limits

- NX-OS rejects `show vpc brief` with `Syntax error while parsing` when the vPC feature is disabled. On the virtual Nexus 9000v this measured answer (exit status 16) is an `empty` read with `not_applicable` redundancy; on any other NX-OS model the same error stays incomplete (`unparsed`), the supervisor state is kept and the row stays partial.
- A read-only account on emulated IOS and IOS XE images is refused `environment`, `stack_members` and `power_inline`. These rows are partial with `permission_denied` while identity, CPU, memory and interfaces remain.
- The PoE and StackWise parsers follow the documented Catalyst output; they were not measured on physical hardware in this release.
