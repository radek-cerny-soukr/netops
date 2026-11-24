# Network overview for Arista EOS and Junos

Call `network_overview` on the Helper HTTPS MCP endpoint with enrolled
`targets` or a device `groups` filter. For each target, enable the queries
that its enrolled account can run. The result carries an evidence reference
for each configured read and reports incomplete coverage per field.

| Platform | Identity and resources | Interfaces | Redundancy and hardware |
| --- | --- | --- | --- |
| Arista EOS | `version` supplies model, version and uptime. `cpu` supplies CPU idle and memory totals from the top headers. The CPU sample interval is unspecified. | `interfaces` distinguishes an administratively disabled port from `notconnect` or `errdisabled`. Use `interfaces_counters_errors` for cumulative RX, TX and CRC error counters. | `mlag_detail` gives local state and role. Opt in to `mlag_interfaces` for local members and the reported state of their peer ports. A disagreement between the reported state counts and the member table leaves the read incomplete. |
| Junos and Junos ELS | `version` and `uptime` supply identity and age. When multiple members are printed, selection requires a matching member from `routing_engine`. An explicit five-minute CPU header gives `sample_seconds: 300`. | `interfaces` reports administratively up physical Ethernet ports whose link is down. For physical Ethernet ports listed in `read_inventory.interfaces`, `interface_details` supplies the cumulative RX, TX and CRC counters used for `with_errors` and `interface_errors_present`. This is `enrolled_interfaces` coverage. | ELS uses `virtual_chassis`, `virtual_chassis_ports` and `poe_controller`. The `firewall` group on Junos uses `chassis_cluster_status` and reports each redundancy group individually. |

cEOSLab 4.36.1F supplies zone or system status where the environment data is
parseable. A zone status gives no individual fan speed or sensor temperature.
A device-wide EOS PoE budget and EOS license status require further source
evidence. Junos ELS can report PoE usage and budget from the controller
table. An explicit response that the PoE subsystem is unneeded is recorded
as `not_applicable`. Junos 26.2R1.7 can explicitly report empty license
usage and inventory, which yields `licenses: []`.

The captured virtual Junos output has an inactive Virtual Chassis subsystem
and an empty environment reply. Coverage of active Virtual Chassis,
populated license tables and physical hardware is limited by the available
captures. FortiGuard and managed Fortinet children are `not_applicable` for
these platforms.

Traffic and cumulative counters can change between two independent reads.
Use `reads` and `missing` to check the source and coverage before drawing
a conclusion about the entire device.
