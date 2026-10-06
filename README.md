# netops

Tools that give an AI agent the narrowest possible hands and usable eyes on network devices, and a configuration auditor that is useful without any agent at all. Four components live in this one repository; each is released on its own, under its own tag and its own maturity.

## Start here

| You want to | Use | What it takes |
|---|---|---|
| Check a FortiGate or ExtremeXOS configuration for known problems | [`netops-auditor`](components/netops-auditor/) | Python 3.13 and a configuration file; no device access for a first try |
| Let an AI agent troubleshoot the network without being able to change it | [`netops-helper`](components/netops-helper/) | A read-only account on each device, a Docker host, and an MCP client |
| Let an agent make small changes that roll themselves back unless the result is confirmed | [`netops-admin`](components/netops-admin/) | A dedicated write account and a check account per device, a one-time enrollment test on each device and firmware build, and the auditor |

### Try the auditor in one minute

No device, no credentials, no database. The auditor reads a sample FortiGate configuration that ships with its tests:

```sh
git clone https://github.com/radek-cerny-soukr/netops
cd netops/components/netops-auditor
PYTHONPATH=src:../netops-core/src python3 -m netops_auditor run \
  --platform fortios --tenant demo --device fw1 \
  --config tests/fixtures/secret_canary.conf
```

It reports nine findings, two of them high: administrative access on a WAN interface and a policy that references an object which does not exist. Each finding names the rule, the object and the line, and never quotes the configuration. The sample carries twenty marked fake secrets; none of them reaches the report, in text, with `--json` or with `--sarif`. Twelve of the FortiOS rules are hardening checks mapped to the CIS FortiGate 7.4.x Benchmark; the [CIS mapping](components/netops-auditor/docs/cis-mapping.md) says what each one checks and which recommendations no rule covers.

On your own device, save the output of `show` on a FortiGate (or `show configuration` on an ExtremeXOS switch, with `--platform exos`) to a file and pass it with `--config`. To track change over time, add `--store audit.db`; accept the current findings once with `--baseline-accept --accepted-by <name> --note <text>`, and later runs report them as `open-known` and anything that appears as `new`. Without the repository, download the `netops-auditor` and `netops-core` source archives from their release pages (linked under [Components](#components)), verify them as described in [Verifying a release](docs/README.md#verifying-a-release), and install both into one Python 3.13 environment; that puts the same command on the path as `netops-auditor`. The rule catalogue, suppressions with expiry, collection straight from the device and the read-only MCP surface are described in the [auditor README](components/netops-auditor/README.md).

### Audit configuration backups in CI

If your configuration backups live in a Git repository, the auditor runs as a GitHub Action with no device, credential or network access and uploads its findings to code scanning as SARIF:

```yaml
- id: audit
  uses: radek-cerny-soukr/netops/components/netops-auditor@c1eff3aed172d3dd865a767de5b290170b6fb1b1 # netops-auditor 0.2.9
  with:
    platform: fortios
    configs: |
      backups/**/*.conf
- uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
  with:
    sarif_file: ${{ steps.audit.outputs.sarif-file }}
```

The workflow needs `security-events: write`. Inputs, outputs and the SARIF mapping are in the [auditor README](components/netops-auditor/README.md#sarif-and-github-code-scanning).

### An agent with bounded reads and diagnostics

[`netops-helper`](components/netops-helper/) is an MCP server with a fixed catalogue of named queries, optional measured FortiOS configuration-path reads and separately enrolled bounded diagnostic recipes. The agent chooses a query and its parameters; it supplies no raw command line or persistent configuration-write tool. Optional recipes can change temporary diagnostic state and must verify cleanup. The server runs in an isolated container on a runner host that the client reaches over pinned SSH, host-side egress rules are applied before the container starts, and every device is reached with an account the device itself keeps read-only. Setup is nine steps: [installation](components/netops-helper/docs/installation.md).

### An agent that can change a little, and undo it

[`netops-admin`](components/netops-admin/) changes one object of a supported table per request. Before writing it arms a rollback on the device itself (a FortiOS automation stitch or an ExtremeXOS Universal Port Manager timer), then compares the result with its prediction through a separate check account, and disarms the rollback only when everything matches. If the check cannot be completed, the timer on the device restores the previous state on its own. Six single-object profiles cover FortiOS addresses, address groups and DHCP reservations and EXOS VLANs, port display strings and membership. Admin 0.2.5 also supports up to 32-operation FortiOS schema transactions, only with exact operator-pinned libraries and rollback calibration. Two read-only commands help before the first change: `netops-admin doctor` reports every condition a device still lacks, and `netops-admin preview` shows the plan of a request and every reason it would be refused, without changing anything. [Start here](components/netops-admin/docs/operations-020.md).

## Components

| Component | What it does | Released |
|---|---|---|
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself or reads a file | [`netops-auditor/v0.2.9`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.9) (2026-10-06) |
| [`netops-helper`](components/netops-helper/) | Read-only MCP server for bounded network troubleshooting | [`netops-helper/v0.3.8`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.8) (2026-10-06) |
| [`netops-admin`](components/netops-admin/) | Bounded device changes, mandatory rollback enrollment and predicted/observed audit | [`netops-admin/v0.2.5`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-admin%2Fv0.2.5) (2026-10-06) |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | [`netops-core/v0.2.6`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.6) (2026-10-06) |

Every release carries a source archive, an SBOM, a checksum manifest and a Sigstore signature; install from those assets after [verifying them](docs/README.md#verifying-a-release). The release page is authoritative. PyPI is a delayed, secondary channel: publication is a separate workflow after GitHub and does not install the Helper server; check exact-version availability before using the index. On 1 October 2026 PyPI carries `netops-core` 0.2.4, `netops-auditor` 0.2.7 and `netops-admin` 0.2.2; Helper was absent on that date. Earlier versions keep their release pages and tags; the table above links the current one. How releases are cut and signed, and what the repository gate enforces, is in the [documentation map](docs/README.md#releases).

## What has been tested

Every entry below is a dated run of this code against a device over the network. "Image" means the vendor's virtual appliance in a lab; hardware is named as such. The table retains dated September measurements; current additions from 3–4 October are summarized below. The per-query and per-scenario detail, including every refusal and failure, is in [verified platform support](docs/verified-support.md) and [live lab measurements](docs/lab-measurements-2026-09-25.md).

| Platform and build | Device | `netops-helper` (reads) | `netops-auditor` | `netops-admin` (writes) |
|---|---|---|---|---|
| FortiOS 8.0.0 build0167 | FortiGate 60F and 80F (hardware) | 40 catalogue queries under a read-only profile, 17 Sep | `ssh` collection from both, `fortios-rest` from the 80F, 12–20 Sep | address table: create, update, delete, `undo` and return by the on-device stitch, over the command line and MCP, 23, 24 and 28 Sep; with 0.2.5 address group member and DHCP reservation with `undo` and stitch return, and a change by someone else during the confirmation, 29 Sep |
| FortiOS 7.6.7 build3704 | FortiGate 60F (hardware) | 45 queries with released 0.3.7: 43 exit 0, 2 `device_cli_error`, 26 Sep | - | address, address group member and DHCP reservation with `undo` and stitch return, 24 Sep; address and group again with 0.2.3, 26 Sep |
| ExtremeXOS 33.7.1.6 | Extreme X440-G2-12p (hardware, two units) | 47 queries under a user-level account, 17–18 Sep; SNMPv2c, 20 Sep | collection and rules, 20 Sep; again with 0.2.8, 26 Sep | VLAN, port display string and port VLAN membership with `undo` and UPM timer return, 23–24 Sep (0.2.0); `doctor` and `preview` with 0.2.3, 26 Sep; with 0.2.5 port display string and `undo`, changes by someone else before the confirmation and during the save, the port list, 29 Sep |
| ExtremeXOS 33.6.1.14 | EXOS-VM image | 49 queries with released 0.3.7: 40 exit 0, 6 exit 250 with a complete answer, 3 `device_cli_error`, 26 Sep | collection, one finding, 25 Sep | the same three profiles with 0.2.4: command line and MCP, `undo`, timer return and refusals, 28 Sep; with 0.2.5 changes by someone else in all three confirmation windows, `recover` after a killed process, the port list, 29 Sep |
| Arista EOS 4.36.1F | cEOS-lab and vEOS-lab images | 33 queries with released 0.3.7, 26 Sep; with the 0.3.7 candidate, traffic, VLAN and trunk isolation, inter-VLAN routing, DHCP, LLDP, restart persistence and an SSH outage checked against the helper's answers, 25 Sep; with the 0.3.8 candidate, `lacp_peer_interface` on a member and on a port channel, 29 Sep | - | - |
| Cisco NX-OS 9.3(12) | Nexus 9300v and 9500v images | 30 queries with released 0.3.7 (9500v 30 exit 0; 9300v 29 exit 0, `lldp_neighbors` exit 244), 26 Sep; with the candidate, cross-host traffic, trunk failure and recovery, and LLDP through the 9300v, 25 Sep | - | - |
| Cisco IOS-XE 17.18.2 | IOL router and IOL L2 images | 27 queries with released 0.3.7: 21 and 26 exit 0, the rest `device_cli_error`, 26 Sep | - | - |
| Cisco IOS 15.9(3)M12 and 15.2 | IOSv and IOSvL2 images | 27 queries with released 0.3.7: 19 and 26 exit 0, the rest `device_cli_error`, 26 Sep | - | - |
| Junos 26.2R1.7 | vJunos-switch image | released 0.3.7: `juniper_junos` 25 exit 0 of 25, `juniper_junos_els` 28 exit 0 and 1 `device_cli_error` of 29, 26 Sep | - | - |
| Linux | a small ARM host | `kernel` and `hostname` live, 20 Sep; the rest wire-simulated | - | - |
| Ruckus Unleashed 200.13 | one access point (hardware) | wire mechanics live, 16 Sep; the platform cannot have a read-only account | - | - |

### New candidate validation, 3–4 October 2026

- FortiGate-VM64-KVM 7.6.7 build3704 and 8.0.0 build0167: exact-bound schema reads, nested/conditional/reference measurements, scoped Auditor reports, the first calibrated Admin schema wave and five bounded Helper recipes with interruption and cleanup checks.
- EXOS-VM and retained ExtremeXOS evidence: command-tree validation and default-port fixes. Changed save/confirmation paths retain their individual measured and synthetic boundaries.
- vJunos-switch 26.2R1.7/cEOS: LACP/MSTP scenarios; actual Helper/Core Junos reads during OSPF/eBGP state and route failure/recovery against FRR 11. These runs do not measure a physical forwarding plane, preferred BGP forwarding or every convergence condition.

See [current candidate validation](docs/verified-support.md#candidate-validation-3-4-october-2026) and [GitHub issue resolution](docs/README.md#github-issue-resolution).

Current gaps: full signed-installation/runtime qualification on macOS and Linux amd64 for these candidates; physical 60F/FortiSwitch/FortiAP schema/recipe validation; physical Arista, Juniper or Cisco platforms; NX-OS 10.x; Junos routing hardware; AAA/TACACS+ command authorization; failed-save behavior on EXOS hardware and complete forwarding/convergence coverage. Unmeasured FortiOS neighbor references and the SLA health-check key remain unknown. VM libraries grant no physical-model write support. Earlier hardware measurements remain historical evidence for their named versions.

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

MIT licensed.
