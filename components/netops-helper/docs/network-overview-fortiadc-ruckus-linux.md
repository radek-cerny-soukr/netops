# FortiADC, Ruckus Unleashed and Linux in Network Overview

Call `network_overview` on the existing HTTPS MCP endpoint. The tool reads only the enrolled aliases and the catalogue entries enabled for each alias. A partial result can contain usable facts alongside the reason that another field could not be read. A confirmed empty detail list is shown as `[]`. A missing measurement is shown as `null` with a coverage reason.

| Platform | Reads and coverage |
|---|---|
| FortiADC | System status supplies model and firmware. Performance supplies CPU and memory percentages and minute-resolution uptime. The interface summary pairs configured state and NIC link in one held SSH session. The kernel interface listing can supply the link state of configured logical ports. Interface counters are cumulative. A restricted account can refuse `diagnose` while status, uptime, and other permitted reads remain available. HA state is based on the local mode, peer count and synchronization evidence. The virtual-appliance license uses the documented registration response. Date extraction for update contracts requires a verified response. Physical sensors and PoE have limited coverage on hardware. |
| Ruckus Unleashed | Controller uptime and memory come from the same system overview. Memory uses the printed used and free quantities. The AP is correlated by MAC within the source data, and the result can report its Master or Member role. A redundancy state of `ok` requires explicit Smart Redundancy evidence. A down Ethernet link requires separate administrative-state evidence before it can trigger the finding. Ethernet errors and CPU remain unknown on the measured output. |
| Linux | The kernel version comes from `uname -a`, and RAM totals and used memory come from `free -m` in MiB. The brief link table distinguishes the `UP` flag from operational `DOWN`. Kernel link statistics, DMI product name, second-resolution uptime and a pair of aggregate CPU samples require the four separately approved catalogue entries. The CPU calculation uses differences in clock ticks. The current read frame does not supply monotonic sample times or a sampling delay, so the sample interval is reported as unavailable. |

The Linux declarations and capture references are in [Linux overview query sources](overview-linux-query-sources.json). Deployment enrolment must opt into each additional read after catalogue activation.

## Suggested release note

- Helper extends the HTTPS MCP `network_overview` to FortiADC, Ruckus Unleashed and Linux. The summary reports verified identity, resource and link facts, with explicit coverage for refused and unavailable reads. FortiADC groups related reads in one SSH session. Linux can report cumulative interface errors and CPU use when the corresponding catalogue entries are active and enrolled.
