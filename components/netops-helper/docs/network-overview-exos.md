# Network overview: ExtremeXOS

The `extreme_exos` adapter of `network_overview` reads one switch through the Helper's HTTPS MCP endpoint. It uses only existing catalogue queries, each of which must be opted in for the target. It reads nothing from the configuration and resets no counters. The general contract, selection and missing reasons are described in [network-overview.md](network-overview.md) and [tools.md](tools.md).

## Reads and order

The plan is fixed for an enrollment. Identity, port state and errors, environment, and PoE come first. When the time or request budget runs out, later reads report `timeout`, `read_limit`, or `rate_limited`.

| Order | Catalogue query | Fields |
|---|---|---|
| 1 | `version` (identity) | `version`, `firmware_support` |
| 2 | `switch` | `model`, `uptime_seconds` |
| 3 | `ports` | `interfaces.admin_up_down` |
| 4–5 | `ports_rx_errors`, `ports_tx_errors` | `interfaces.with_errors` |
| 6–9 | `temperature`, `fans`, `power`, `inline_power` | `temperatures`, `fans`, `power`, `poe` |
| 10–11 | `cpu_monitoring`, `memory` | `cpu`, `memory` |
| 12–15 | `stacking`, `stacking_support`, `mlag_peer`, `mlag_ports` (after a successful `mlag_peer`), when redundancy is in scope | `redundancy` |
| Next | `licenses` | `licenses` |
| Last | Enabled `interface_transceiver` on up to eight enrolled ports with known optical modules | `temperatures` (optical modules) |

Each EXOS read opens a separate SSH connection. A target has at most 30 seconds per call. If selected reads exceed this budget, the row is `partial` and reports the missing reads.

### Enrollment for standalone switches and optics

The EXOS overview reads these optional declarations from `helper.read_inventory.switches`:

- `redundancy-disabled` when the running configuration confirms both stacking and MLAG are absent. The overview omits the four redundancy reads and marks `redundancy` as `not_applicable`. Update this declaration when the configuration changes.
- `optical-port:13` for a port with a known optical module, and likewise `optical-port:1:49` for a slot and port. Also enroll the port in `helper.read_inventory.interfaces` and enable `interface_transceiver`. Only ports listed in both places are read, in interface enrollment order. Additional optical ports beyond eight report `temperatures` with `source_limit` and `omitted_count`. When optics is enabled and only general interface enrollment is present, `source_limit` counts those unclassified ports.

## Field mapping

- **Identity.** `version` is the ExtremeXOS version from the verified identity. `model` is `System Type` from `show switch`. `uptime_seconds` converts `System UpTime` (days, hours, minutes, seconds). An unknown uptime format marks the read as incomplete. `firmware_support` compares the version, including a patch level, with the tested versions. An untested version is an `info` finding and does not block the read.
- **CPU.** `cpu.used_pct` is the `System` row in the column whose interval matches the explicit `Monitored every N seconds` header. `sample_seconds` is that interval. Without a matching header the value is not reported.
- **Memory.** Memory comes from `Total DRAM` and `Free` (KB). The `System`, `User` and `Free` values must add up to the total. `used_bytes` is total minus free.
- **Port state.** `admin_up_down` lists ports with `Port State` E (enabled) whose `Link State` carries no link: R (ready), or the ELSM, OAM or MACsec wait states. A disabled port (D, F, L) with the same link is not listed. A port that is not present (NP) or in loopback (L) is not a down link.
- **Errors.** `with_errors` lists ports with a non-zero cumulative counter. The receive table gives `rx_crc`, `rx_over`, `rx_under`, `rx_frag`, `rx_jabber`, `rx_align` and `rx_lost`. The transmit table gives `tx_late_collisions`, `tx_errors`, `tx_lost` and `tx_parity`. Collisions and deferrals are normal half-duplex events and are not error counters. Both tables must list the same ports as the port summary. Otherwise the table is incomplete and its values carry no claim about the missing ports.
- **Redundancy.** A live read with `stacking-support` disabled produces a `stack` entry with state `standalone`. An active stack is `ok` only when every node is Active and in the same topology. An MLAG peer with a down checkpoint or a down member is `degraded`. An `ok` peer requires an up checkpoint and matching group count with verified member link states from `show mlag ports`. A peer header without peers proves the absence of MLAG only together with an explicit group count of zero.
- **Environment.** Sensors, fan trays and fans (with RPM when printed) and power supplies (with watts when printed) map to `ok`, `warning` or `failed`. An unknown state is `unknown` and marks the read incomplete. An empty fan or power-supply bay is not a member and is not a failure. ExtremeXOS VM prints simulated sensors and supplies; on that model the hardware fields and PoE are `null` with `not_applicable`.
- **PoE.** `poe` uses the operational budget and the measured power from `show inline-power`, both in watts. `available_w` is budget minus measured power. PoE firmware that is not operational on a physical switch gives no budget and marks the read incomplete.
- **Optics.** A port without a module and a copper port without DOM add no entry. A module with DOM adds a temperature with `kind: optic` and the port. A DOM alarm is `failed`, a warning is `warning`.
- **Licenses.** The license level and every feature pack are `valid` with `expires_on: null`, because ExtremeXOS does not print an expiry for them. `fortiguard` and `managed` are `null` with `not_applicable`.

## Known limits

- On a verified ExtremeXOS VM, the recognized no-stacking answer of `show stacking` with exit status 250 is `empty` with `not_applicable` coverage. When that answer establishes that stacking is absent, the recognized answer of `show stacking-support` with exit status 254 is also `empty`. An unrecognized CLI answer remains `unparsed`; other failures, such as permission denial or timeout, keep their own reasons. These reads leave the row `partial`; they are not passed on as a proven missing capability.
- Counters are cumulative since the last clear on the device. The overview makes no claim about current growth.
