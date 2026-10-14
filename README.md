# netops

**Let an AI agent work on your network without handing it the keys.** netops gives an agent a fixed catalogue of named read-only queries instead of a shell, lets it change a little only behind a rollback that the device itself enforces, and ships a configuration auditor that is useful on its own, with no agent at all. Four components live in this one repository; each is released on its own, under its own tag and its own maturity.

## Why netops

- **No raw commands.** The agent chooses a named query and its parameters; it never writes a command line. Targets use device-enforced read-only accounts, with the documented [Ruckus Unleashed exception](components/netops-helper/docs/read-only-accounts.md#ruckus-unleashed).
- **Changes that undo themselves.** Before it writes, `netops-admin` arms a rollback on the device (a FortiOS automation stitch or an ExtremeXOS Universal Port Manager timer). Only when a separate check account confirms the predicted result is the rollback disarmed; otherwise the device restores the previous state on its own.
- **Useful without AI.** `netops-auditor` checks FortiGate and ExtremeXOS configurations from a file, straight from the device or in GitHub Actions with SARIF code scanning. Twelve FortiOS rules are hardening checks mapped to the CIS FortiGate 7.4.x Benchmark, and reports never quote the configuration.
- **Verifiable releases.** Every release carries a source archive, an SBOM, a checksum manifest and a Sigstore signature; Helper server images come with their SBOM and Grype report.
- **Explicit platform boundaries.** Platform, model, firmware and account requirements are documented under [Platform compatibility](#platform-compatibility). A query catalogue does not establish support for every deployment.

## What's new - 14 October 2026

This source tree contains Core 0.2.9, Auditor 0.2.12, Admin 0.2.8 and Helper 0.3.11. Helper's Ruckus Unleashed enrollment uses the explicit administrator-bounded role and catalogue boundary. Admin's optional strict audit-file binding setting defaults to false and, when enabled, requires export status to identify the configured audit file. These contracts do not extend device-account privileges or compatibility beyond their documented scope.

## What's new - 11 October 2026 (previous release)

Core 0.2.8, Auditor 0.2.11, Admin 0.2.7 and Helper 0.3.10 fix the points of the follow-up audit in [GitHub issue #4](docs/README.md#issue-4).

- **Helper on Linux AMD64.** Next to the ARM64 image, a server image built and self-tested natively on an AMD64 builder.
- **Safer ExtremeXOS rollbacks.** Admin requires proof from the complete listing for its own timer before confirming return. Missing or incomplete proof leaves the operation unknown and the device blocked.
- **One change at a time.** Processes that share a state directory admit operations one at a time, so the daily budget and request IDs hold across devices; notifications no longer follow redirects.
- **Quiet start.** The MCP servers of Auditor, Admin and Helper no longer ask PyPI for a newer FastMCP when they start.
- **Breaking change in Helper 0.3.10:** the EXOS query `sharing` (`show sharing`) is removed because of inconsistent completion status (STATUS=-6 / SSH250 with a complete table). Remove `sharing` from `enabled_queries` before upgrading. [Reason and upgrade migration](components/netops-helper/docs/vendor-cli-references/extreme-switch-engine.md#unsupported-show-sharing).

Release notes: [Core 0.2.8](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.8), [Auditor 0.2.11](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.11), [Admin 0.2.7](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-admin%2Fv0.2.7), [Helper 0.3.10](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.10).

## Start here

| You want to | Use | What it takes |
|---|---|---|
| Check a FortiGate or ExtremeXOS configuration for known problems | [`netops-auditor`](components/netops-auditor/) | Python 3.13 and a configuration file; no device access for a first try |
| Give an AI agent bounded, named network troubleshooting | [`netops-helper`](components/netops-helper/) | Device-enforced read-only accounts; for Ruckus Unleashed, an administrator account explicitly declared `admin-bounded` with `role_boundary: "catalogue"` under the [Ruckus privilege exception](components/netops-helper/docs/read-only-accounts.md#ruckus-unleashed); a Linux Docker host and an MCP client |
| Let an agent make small changes that roll themselves back unless the result is confirmed | [`netops-admin`](components/netops-admin/) | A dedicated write account and a check account per device, a one-time enrollment test on each device and firmware build, and the auditor |

**Host operating system.** NetOps runs on Linux only. Windows is not a supported host: the components rely on POSIX interfaces and their console scripts fail to start there. macOS is not a supported deployment target either; where [the record below](#test-resource-limits) mentions macOS, it is a client machine on which the native test suites were exercised, not a host the components are released for.

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

If your configuration backups live in a Git repository, the auditor runs as a GitHub Action with no device access or device credentials. The audit logic runs locally over the files; Python setup, action downloads and SARIF upload need network access. It uploads its findings to code scanning as SARIF:

```yaml
- id: audit
  uses: radek-cerny-soukr/netops/components/netops-auditor@5e4ec7fbb09df478e8837421dfff6aa6fcd8f0f6 # netops-auditor 0.2.12
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

[`netops-helper`](components/netops-helper/) is an MCP server with a fixed catalogue of named queries, optional measured FortiOS configuration-path reads and separately enrolled bounded diagnostic recipes. The agent chooses a query and its parameters; it supplies no raw command line or persistent configuration-write tool. Optional recipes can change temporary diagnostic state and must verify cleanup. The server runs in an isolated container on a runner host that the client reaches over pinned SSH, host-side egress rules are applied before the container starts, and targets use device-enforced read-only accounts, with the documented [Ruckus Unleashed 200.13 exception](components/netops-helper/docs/read-only-accounts.md#ruckus-unleashed). Setup is nine steps: [installation](components/netops-helper/docs/installation.md).

### An agent that can change a little, and undo it

[`netops-admin`](components/netops-admin/) changes one object of a supported table per request. Before writing it arms a rollback on the device itself (a FortiOS automation stitch or an ExtremeXOS Universal Port Manager timer), then compares the result with its prediction through a separate check account, and disarms the rollback only when everything matches. If the check cannot be completed, the timer on the device restores the previous state on its own. Six single-object profiles cover FortiOS addresses, address groups and DHCP reservations and EXOS VLANs, port display strings and membership. Admin 0.2.8 also supports up to 32-operation FortiOS schema transactions, only with exact operator-pinned libraries and rollback calibration. Two read-only commands help before the first change: `netops-admin doctor` reports every condition a device still lacks, and `netops-admin preview` shows the plan of a request and every reason it would be refused, without changing anything. [Start here](components/netops-admin/docs/operations-020.md).

## Components

| Component | What it does | Released |
|---|---|---|
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself or reads a file | [`netops-auditor/v0.2.12`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.12) (2026-10-14) |
| [`netops-helper`](components/netops-helper/) | Bounded troubleshooting MCP server; installed client command: `netops-helper-proxy` | [`netops-helper/v0.3.11`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.11) (2026-10-14) |
| [`netops-admin`](components/netops-admin/) | Bounded device changes, mandatory rollback enrollment and predicted/observed audit | [`netops-admin/v0.2.8`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-admin%2Fv0.2.8) (2026-10-14) |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | [`netops-core/v0.2.9`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.9) (2026-10-14) |

Every release carries a source archive, an SBOM, a checksum manifest and a Sigstore signature; install from those assets after [verifying them](docs/README.md#verifying-a-release). The release page is authoritative. Third-party directories, mirrors and hosted deployments of these servers (for example automated MCP catalogues that index this repository) are neither endorsed nor verified by this project; the only verified sources are the GitHub release pages with their Sigstore signatures and, as a secondary channel, PyPI. PyPI is a delayed, secondary channel: publication is a separate workflow after GitHub and does not install the Helper server; check exact-version availability before using the index. On 14 October 2026 PyPI carries the current releases: `netops-core` 0.2.9, `netops-auditor` 0.2.12, `netops-admin` 0.2.8 and the `netops-helper` 0.3.11 client proxy. Earlier versions keep their release pages and tags; the table above links the current one. How releases are cut and signed, and what the repository gate enforces, is in the [documentation map](docs/README.md#releases).

## Platform compatibility

NetOps documents version-specific platform contracts, account privileges and execution limits in [verified platform support](docs/verified-support.md) and [compatibility boundaries](docs/compatibility-boundaries.md). A catalogue entry or a software-image result does not establish support for every device model, firmware build, hardware forwarding path or account policy. Enroll and verify each deployment against its exact platform and build before use.

| Platform family | Helper | Auditor | Admin |
|---|---|---|---|
| FortiOS | Bounded catalogue and schema reads under the documented account policy | SSH configuration collection and the documented REST channel | Enrolled address, address-group, DHCP-reservation and explicitly bounded schema operations |
| ExtremeXOS | Bounded catalogue reads; platform-specific diagnostic exclusions apply | SSH configuration collection and configuration rules | Enrolled VLAN, port display-string and port-membership profiles |
| Arista EOS, Cisco IOS/IOS-XE/NX-OS, Junos | Platform-specific read catalogues; software-image coverage does not qualify physical forwarding hardware | Only explicitly documented collector channels | No Admin execution support is inferred from read or timer behavior |
| Linux | Documented read and diagnostic paths; distribution and architecture limits apply | Only explicitly documented collector channels | No device-change support is inferred |
| Ruckus Unleashed | Explicit administrator-bounded role and catalogue boundary; the catalogue does not reduce device-account privileges | Only explicitly documented collector channels | No device-change support is inferred |

### Clock and rollback limits

A safeguard's scheduling behavior is platform-specific. Admin requires its own safeguard proof before confirming return; missing or unverified proof leaves the operation unknown and the device blocked. FortiOS one-shot safeguards follow the device clock, and a safeguard not loaded before a forward jump may fail to return the change. ExtremeXOS confirmation uses its own timer identity and complete listings. Host-side elapsed budgets use monotonic time within a boot; this does not provide trusted elapsed time across reboot.

### Verification boundaries

Read results, configuration checks, synthetic tests and software-image scenarios establish different scopes. They do not prove hardware forwarding, DHCP lease acquisition, sensor behavior, every convergence condition, AAA/TACACS+ policy, complete corpus coverage or production exploitability. Account privilege, egress, safeguard behavior and the exact model/build must satisfy the component's deployment contract independently.

## Test resource limits

The repository and GitHub source release archives ship each component's malformed-input suites and standard-library test guard. PyPI source distributions omit test support and are not standalone pytest trees; see [the distribution boundary](components/netops-core/docs/releasing.md#pypi-source-distributions-and-tests). On Linux, the guards retain the address-space limit and wall-clock timer. On Darwin, in-process calls use an independent supervisor that reads resident memory through Apple's `proc_pidinfo` API every 10 ms and terminates an over-budget test process. Subprocess probes are sampled every 20 ms and are terminated on excess memory or observation failure. Brief memory overshoot between samples remains possible. Supervisor readiness is checked before the guarded call and its control pipe closes at cleanup.

Each component includes negative tests for memory exhaustion, timeouts, normal return values and signal-handler restoration. Test-guard behavior on another platform does not extend deployment support beyond the documented [Linux host requirements](docs/verified-support.md#host-operating-system).

## How this project is built

NetOps is conceived and directed by its author, who decides which features the tools offer, which platforms and devices they support and how they behave, and who uses NetOps actively and deploys it in real projects; that practice drives what comes next. The author builds it with two AI coding agents, Claude Code (Anthropic) and Codex (OpenAI). The agents implement that design: they write code, tests and documentation, run the acceptance and red-team passes against each other’s work, and record the limits of what was actually measured. The author reviews and accepts the result, and signs and publishes every release; nothing in the verified-support record is inferred.

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

MIT licensed.
