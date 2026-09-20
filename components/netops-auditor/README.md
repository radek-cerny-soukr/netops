# netops-auditor

Configuration audit for network devices. The auditor collects the configuration from the device itself, evaluates it against a catalogue of rules, and reports findings without ever carrying the configuration or a credential into its answers.

The current release is `netops-auditor/v0.2.1` (2026-09-20), which pins `netops-core==0.2.0`; `netops-auditor/v0.2.0` (2026-09-19) preceded it. The component is usable from the CLI, and its shape is fixed by its gates rather than by its documentation.

## What it does

- **Rules as data.** One catalogue per platform, as JSON: identifier, version, check, class (`fakt` or `usudek`), severity, evidence fields, remediation, and optional compliance references. A rule without a positive and a negative fixture does not enter the catalogue - the gate rejects it.
- **Two audited platforms.** FortiOS (6 rules over the tree of `config` / `edit` / `set`) and, since 0.2.0, ExtremeXOS and Switch Engine (4 rules over the flat command list of `show configuration`). The platform picks the parser and the catalogue; there is no shared model between them and none is planned until a rule needs one.
- **Collects its own configuration.** One channel per device, pinned in the `auditor` section of the inventory: `file`, `fortios-rest`, or `ssh`. There is no fallback ladder; a failing channel fails the collection and says why. What each channel cannot do is written down in [`docs/channels.md`](docs/channels.md), and the `auditor` section of the inventory - including what each channel requires of the shared device entry - in [`docs/inventory.md`](docs/inventory.md).
- **Reaches a device through [`netops-core`](../netops-core/README.md).** Since 0.2.0 the inventory (file version 2), the credential store (file version 2), the host key trust and the SSH transport are the shared access layer of the family, pinned as `netops-core==0.2.0`; the auditor keeps the policy - the `auditor` section of an entry, which kind of credential a channel takes, the step table of a platform and the audit itself.
- **Never changes a device.** Not a policy, not an interface, not even a console setting. With an active FortiOS pager the collection refuses instead of disabling it.
- **Keeps secrets out of findings.** A finding carries an object reference and line numbers, never the configuration text. A canary fixture per platform - twenty marked secrets on FortiOS, eleven on EXOS - must not leak a single one into a finding, an MCP answer, or a CLI report.
- **Knows what changed.** Baseline in the database, suppressions with a mandatory expiry in a reviewed JSON file, four finding states, and a freshness threshold. The credential store, the suppression file, the exit codes and the two refusals that end a run before the catalogue is reached are in [`docs/configuration.md`](docs/configuration.md).
- **Read-only MCP surface.** Six tools over a store opened read-only. The server cannot reach a device: it imports neither the collection, nor the credential store, nor the inventory.
- **The gate reads what is released.** `scripts/check_gates.py` scans the whole released file set, not only the fixtures, and it runs inside an exported archive where no repository is left. What may appear in that set is an allowlist: RFC 5737 and loopback addresses, `2001:db8::/32`, RFC 7042 MAC addresses, RFC 2606 names, `example.invalid`, and the vendor domains of the documentation. Anything else stops the release. Outside a repository - which is what an exported archive is - the gate also holds the file set itself: every file present must be in the release selection and in `release-manifest.json`, and every file those two name must be present, so neither an added nor a removed file survives it.

## Running it

The auditor needs `netops-core` and nothing else from outside the standard library; in this repository it is taken from the tree. `fastmcp` is needed by the MCP surface alone and is pinned in `requirements-mcp.txt`; the CLI runs without it.

```sh
PYTHONPATH=src:../netops-core/src python3 -m netops_auditor --help
python3 -m pytest -q                         # the test suite
python3 scripts/check_gates.py               # the gate of a release
```

## Boundaries

The auditor is not a compliance product: rules may carry `refs` to the vendor command reference or to CIS, ZKB, or DORA, but no profile is built and no compliance is claimed. Rules exist for FortiOS and for EXOS, and the EXOS catalogue is four rules wide - time, logging, SNMP communities and Telnet - which is a beginning, not coverage; what each of them cannot see is in [`docs/channels.md`](docs/channels.md). The EXOS rules have not been measured end to end against a switch with this code: they were verified over a `show configuration` backup, not over a snapshot this collector pulled. A finding of class `usudek` is a judgement and is never emitted at high severity.

The auditor ships no image of its own either, so the `ssh` channel runs the OpenSSH client already installed on the host and inherits that client's own vulnerabilities, unfiltered by any isolating container. Keeping that client current is the operator's responsibility, not this component's.

MIT licensed. Part of the [`netops`](../../README.md) family.
