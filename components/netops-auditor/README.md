# netops-auditor

Configuration audit for network devices. The auditor collects the configuration from the device itself, evaluates it against a catalogue of rules, and reports findings without ever carrying the configuration or a credential into its answers.

This component has not been released yet. It is usable from the CLI today, and its shape is fixed by its gates rather than by its documentation.

## What it does

- **Rules as data.** The catalogue is JSON: identifier, version, check, class (`fakt` or `usudek`), severity, evidence fields, remediation, and optional compliance references. A rule without a positive and a negative fixture does not enter the catalogue - the gate rejects it.
- **Collects its own configuration.** One channel per device, pinned in the inventory: `file`, `fortios-rest`, or `ssh`. There is no fallback ladder; a failing channel fails the collection and says why. What each channel cannot do is written down in [`docs/channels.md`](docs/channels.md), and the schema of the inventory file - including how a device gets an exception for old SSH algorithms - in [`docs/inventory.md`](docs/inventory.md).
- **Never changes a device.** Not a policy, not an interface, not even a console setting. With an active FortiOS pager the collection refuses instead of disabling it.
- **Keeps secrets out of findings.** A finding carries an object reference and line numbers, never the configuration text. A canary fixture with twenty marked secrets must not leak a single one into a finding, an MCP answer, or a CLI report.
- **Knows what changed.** Baseline in the database, suppressions with a mandatory expiry in a reviewed JSON file, four finding states, and a freshness threshold. The credential store, the suppression file, the exit codes and the two refusals that end a run before the catalogue is reached are in [`docs/configuration.md`](docs/configuration.md).
- **Read-only MCP surface.** Six tools over a store opened read-only. The server cannot reach a device: it imports neither the collection, nor the vault, nor the inventory.
- **The gate reads what is released.** `scripts/check_gates.py` scans the whole released file set, not only the fixtures, and it runs inside an exported archive where no repository is left. What may appear in that set is an allowlist: RFC 5737 and loopback addresses, `2001:db8::/32`, RFC 7042 MAC addresses, RFC 2606 names, `example.invalid`, and the vendor domains of the documentation. Anything else stops the release. Outside a repository - which is what an exported archive is - the gate also holds the file set itself: every file present must be in the release selection and in `release-manifest.json`, and every file those two name must be present, so neither an added nor a removed file survives it.

## Running it

The auditor is standard library only. `fastmcp` is needed by the MCP surface alone and is pinned in `requirements-mcp.txt`; the CLI runs without it.

```sh
PYTHONPATH=src python3 -m netops_auditor --help
PYTHONPATH=src python3 -m pytest -q          # the test suite
python3 scripts/check_gates.py               # the gate of a release
```

## Boundaries

The auditor is not a compliance product: rules may carry `refs` to CIS, ZKB, or DORA, but no profile is built and no compliance is claimed. Rules exist for FortiOS only. The `ssh` channel can pull an EXOS configuration and the completeness of that snapshot is measured, but `collect` refuses a device whose platform is `exos` before it opens a session, because there is no catalogue to evaluate it against - so from the command line EXOS cannot be collected at all, and the library call `collect.collect_ssh()` is the only way in. That is a gap, not support. A finding of class `usudek` is a judgement and is never emitted at high severity.

MIT licensed. Part of the [`netops`](../../README.md) family.
