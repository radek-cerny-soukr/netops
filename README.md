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

On your own device, save the output of `show` on a FortiGate (or `show configuration` on an ExtremeXOS switch, with `--platform exos`) to a file and pass it with `--config`. To track change over time, add `--store audit.db`; accept the current findings once with `--baseline-accept --accepted-by <name> --note <text>`, and later runs report them as `open-known` and anything that appears as `new`. Without the repository, `pip install netops-auditor` (Python 3.13) puts the same command on the path as `netops-auditor`. The rule catalogue, suppressions with expiry, collection straight from the device and the read-only MCP surface are described in the [auditor README](components/netops-auditor/README.md).

### Audit configuration backups in CI

If your configuration backups live in a Git repository, the auditor runs as a GitHub Action with no device, credential or network access and uploads its findings to code scanning as SARIF:

```yaml
- id: audit
  uses: radek-cerny-soukr/netops/components/netops-auditor@8a7c0bc504c9e7bb46b0937807c05293add2c019 # netops-auditor 0.2.7
  with:
    platform: fortios
    configs: |
      backups/**/*.conf
- uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
  with:
    sarif_file: ${{ steps.audit.outputs.sarif-file }}
```

The workflow needs `security-events: write`. Inputs, outputs and the SARIF mapping are in the [auditor README](components/netops-auditor/README.md#sarif-and-github-code-scanning).

### An agent that can look but not touch

[`netops-helper`](components/netops-helper/) is an MCP server with a fixed catalogue of named diagnostic queries per platform. The agent chooses a query and its parameters; it never writes a command line, and there is no write tool. The server runs in an isolated container on a runner host that the client reaches over pinned SSH, host-side egress rules are applied before the container starts, and every device is reached with an account the device itself keeps read-only. Setup is nine steps: [installation](components/netops-helper/docs/installation.md).

### An agent that can change a little, and undo it

[`netops-admin`](components/netops-admin/) changes one object of a supported table per request. Before writing it arms a rollback on the device itself (a FortiOS automation stitch or an ExtremeXOS Universal Port Manager timer), then compares the result with its prediction through a separate check account, and disarms the rollback only when everything matches. If the check cannot be completed, the timer on the device restores the previous state on its own. Six profiles: FortiOS addresses, address group members and DHCP reservations; ExtremeXOS VLANs, port display strings and port VLAN membership. Two read-only commands help before the first change: `netops-admin doctor` reports every condition a device still lacks, and `netops-admin preview` shows the plan of a request and every reason it would be refused, without changing anything. [Start here](components/netops-admin/docs/operations-020.md).

## Components

| Component | What it does | Released |
|---|---|---|
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself or reads a file | [`netops-auditor/v0.2.8`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.8) (2026-09-26) |
| [`netops-helper`](components/netops-helper/) | Read-only MCP server for bounded network troubleshooting | [`netops-helper/v0.3.7`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.7) (2026-09-26) |
| [`netops-admin`](components/netops-admin/) | Bounded device changes, mandatory rollback enrollment and predicted/observed audit | [`netops-admin/v0.2.3`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-admin%2Fv0.2.3) (2026-09-26) |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | [`netops-core/v0.2.5`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.5) (2026-09-26) |

Every release carries a source archive, an SBOM, a checksum manifest and a Sigstore signature. All four are also published on PyPI (`pip install netops-auditor`, `pip install netops-admin`; `pip install netops-helper` installs only the helper's client-side proxy, its server runs as a container image). Earlier versions keep their release pages and tags; the table above links the current one. How releases are cut and signed, and what the repository gate enforces, is in the [documentation map](docs/README.md#releases).

## What has been tested on real devices

FortiOS (7.6.x and 8.0.0) and ExtremeXOS (33.7.x) have been exercised end to end against real devices. The helper's Arista EOS, Junos, Cisco IOS, IOS-XE and NX-OS catalogues have been run query by query against the vendors' virtual images (cEOS and vEOS 4.36.1F, vJunos-switch 26.2R1.7, IOL 17.18.2, IOSv 15.9(3)M12, IOSvL2 15.2, Nexus 9300v and 9500v 9.3(12)) and ExtremeXOS also against EXOS-VM 33.6.1.14; no physical device of those three vendors has been measured yet. Cisco IOS-XE and classic IOS need `netops-core` 0.2.5 and `netops-helper` 0.3.7, see [live lab measurements](docs/lab-measurements-2026-09-25.md). [Verified platform support](docs/verified-support.md) states, per platform, firmware, transport, authentication and account privilege, what was measured and what was not.

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

MIT licensed.
