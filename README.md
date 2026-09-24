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

It reports six findings, two of them high: administrative access on a WAN interface and a policy that references an object which does not exist. Each finding names the rule, the object and the line, and never quotes the configuration. The sample carries twenty marked fake secrets; none of them reaches the report, in text or with `--json`.

On your own device, save the output of `show` on a FortiGate (or `show configuration` on an ExtremeXOS switch, with `--platform exos`) to a file and pass it with `--config`. To track change over time, add `--store audit.db`; accept the current findings once with `--baseline-accept --accepted-by <name> --note <text>`, and later runs report them as `open-known` and anything that appears as `new`. The rule catalogue, suppressions with expiry, collection straight from the device and the read-only MCP surface are described in the [auditor README](components/netops-auditor/README.md).

### An agent that can look but not touch

[`netops-helper`](components/netops-helper/) is an MCP server with a fixed catalogue of named diagnostic queries per platform. The agent chooses a query and its parameters; it never writes a command line, and there is no write tool. The server runs in an isolated container on a runner host that the client reaches over pinned SSH, host-side egress rules are applied before the container starts, and every device is reached with an account the device itself keeps read-only. Setup is nine steps: [installation](components/netops-helper/docs/installation.md).

### An agent that can change a little, and undo it

[`netops-admin`](components/netops-admin/) changes one object of a supported table per request. Before writing it arms a rollback on the device itself (a FortiOS automation stitch or an ExtremeXOS Universal Port Manager timer), then compares the result with its prediction through a separate check account, and disarms the rollback only when everything matches. If the check cannot be completed, the timer on the device restores the previous state on its own. Six profiles: FortiOS addresses, address group members and DHCP reservations; ExtremeXOS VLANs, port display strings and port VLAN membership. [Start here](components/netops-admin/docs/operations-020.md).

## Components

| Component | What it does | Released |
|---|---|---|
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself or reads a file | [`netops-auditor/v0.2.5`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.5) (2026-09-24) |
| [`netops-helper`](components/netops-helper/) | Read-only MCP server for bounded network troubleshooting | [`netops-helper/v0.3.6`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.6) (2026-09-21) |
| [`netops-admin`](components/netops-admin/) | Bounded device changes, mandatory rollback enrollment and predicted/observed audit | [`netops-admin/v0.2.0`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-admin%2Fv0.2.0) (2026-09-24) |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | [`netops-core/v0.2.3`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.3) (2026-09-21) |

Every release carries a source archive, an SBOM, a checksum manifest and a Sigstore signature. The repository keeps exactly one release page and one tag per component; how releases are cut, signed and retired, and what the repository gate enforces, is in the [documentation map](docs/README.md#releases).

## What has been tested on real devices

FortiOS (7.6.x and 8.0.0) and ExtremeXOS (33.7.x) have been exercised end to end against real devices. The Cisco, Arista and Juniper catalogues of the helper are reviewed against vendor references and simulated on the wire, but have not yet been run against a device. [Verified platform support](docs/verified-support.md) states, per platform, firmware, transport, authentication and account privilege, what was measured and what was not.

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

MIT licensed.
