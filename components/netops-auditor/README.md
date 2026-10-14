# netops-auditor

This source tree contains netops-auditor/v0.2.12. Its metadata pins netops-core==0.2.9.

Configuration audit for network devices. The auditor collects the configuration from the device itself, parses it with a platform-specific parser, evaluates the parsed configuration against a catalogue of deterministic rules, and reports findings - never the configuration itself, and never a credential.

Published release context (14 October 2026): the published release is `netops-auditor/v0.2.12` (2026-10-14); it pins `netops-core version 0.2.9`. The current release of every component is linked from the [repository release table](https://github.com/radek-cerny-soukr/netops/blob/main/README.md#components). **Install from the release assets:** the source archives of this component and of the pinned `netops-core`, each verified against its release `SHA256SUMS` and Sigstore bundle as [Verifying a release](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#verifying-a-release) describes. The [installation guide](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/installation.md) gives the commands. `netops-auditor` 0.2.12 has a separate PyPI publication step after GitHub; check exact-version index availability before choosing that installation channel: on 14 October 2026 PyPI carries `netops-auditor` 0.2.12 and `netops-core` 0.2.9. Every version keeps its own release page and tag, and every release stays in the history of `main` as its own signed commit - see [`docs/releasing.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/releasing.md). The component is usable from the CLI, and its shape is fixed by its gates rather than by its documentation.

## Fixes in 0.2.12

- Audit runs and collection events are recorded together; refusal paths retain earlier collection events.
- Future-dated audits are stale in both CLI and MCP views.
- Advisory findings remain visible as not evaluated until a later audit evaluates them; skipping a rule does not mark its finding gone.
- Zero-progress output writes fail through the existing error path. Refused preflight output does not echo unknown device-supplied text, and channel events retain write order.

See the [changelog](CHANGELOG.md) and [collection boundaries](docs/channels.md).

## Fixes in 0.2.11

- MCP `initialize` announces the auditor's own version; 0.2.9 and 0.2.10 announced the FastMCP version (4.0.5).
- U+001F, the separator of the finding fingerprint, is refused in a tenant, a device name, a suppression file and a catalogue rule id instead of joining two different identities into one fingerprint; fingerprints of other values are unchanged, so no migration is needed.
- `merge-sarif` reads the rule descriptions of all inputs before it checks their results, so the order of the inputs no longer decides whether a merge succeeds.

These answer points 5, 10 and 7 of [issue #4](https://github.com/radek-cerny-soukr/netops/issues/4); see the [changelog](CHANGELOG.md) and the [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#issue-4).

## Installation fixes in 0.2.10

Archive supply-chain tests accept exactly the pinned versioned Core sibling, with package identity checks and no rename or symlink. See the [changelog](CHANGELOG.md) and installation/release instructions for the exact procedure.

## New in 0.2.9

- Measured `schema-check` reference integrity and upgrade differences, with explicit unknown coverage.
- Scoped catalogue evaluation on complete global/VDOM snapshots and pinned `schema_report` reads through MCP.
- Per-rule evaluation states carried into JSON, SARIF and stored history; incomplete evaluation cannot silently resolve old findings.
- Controlled numeric/SARIF input failures, consistent FortiOS quoting, active EXOS context filtering and serialized policy-history writes; the application version in MCP initialization followed only in 0.2.11.

The [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#github-issue-resolution) maps these corrections to reported items. Setup and limits are in [Measured schema audit](#measured-schema-audit), [configuration](docs/configuration.md) and [current compatibility boundaries](https://github.com/radek-cerny-soukr/netops/blob/main/docs/compatibility-boundaries.md#deployment-verification).

## What it does

- **Rules as data.** One catalogue per platform, as JSON under `src/netops_auditor/catalog/`: identifier, version, check, class (`fakt` or `usudek`), severity, evidence fields, remediation, and optional compliance references. A rule without a positive and a negative fixture does not enter the catalogue - the gate rejects it.
- **Two audited platforms.** FortiOS carries 18 rules over the tree of `config` / `edit` / `set`: VDOM scope, dangling policy references, WAN administrative access, UTM inspection without an SSL profile, a missing syslog target, no NTP sync, and twelve hardening rules taken from the CIS FortiGate 7.4.x Benchmark v1.0.1 and the hardening chapter of the FortiOS 8.0.0 Best Practices - see [`docs/cis-mapping.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/cis-mapping.md). ExtremeXOS and Switch Engine carry 4 rules over the flat command list of `show configuration`: no SNTP or NTP sync, a missing syslog target, a default SNMP community, and Telnet left enabled. The platform picks the parser and the catalogue; there is no shared model between them and none is planned until a rule needs one.
- **Collects its own configuration through a pinned channel.** The inventory selects `file`, `fortios-rest`, or `ssh`; there is no fallback ladder. SSH supports FortiOS and EXOS, REST is FortiOS-only, and `file` reads a dump collected elsewhere. Live measurements through 20 September 2026 cover FortiOS SSH, EXOS SSH collection followed by all four rules, and FortiOS REST collection followed by all six rules. The EXOS measurement includes local mutations producing the expected findings; the REST measurement includes a deliberately absent required section producing an incomplete-snapshot finding. These are dated measurements, not coverage of every firmware and access profile. See [`docs/channels.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/channels.md), [`docs/inventory.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/inventory.md) and the family's [verified platform support](https://github.com/radek-cerny-soukr/netops/blob/main/docs/verified-support.md).
- **Reaches a device through [`netops-core`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/README.md), and does not vendor it.** The inventory (file version 2), the credential store (file version 2), the host key trust and the SSH transport are the shared access layer of the family, pinned as `netops-core==0.2.9`. Unlike `netops-helper`, whose release archive vendors a copy of `netops-core` inside itself, the auditor carries none: the operator installs the verified `netops-core` source archive of exactly that version beside it (see [`docs/releasing.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/releasing.md)). What stays here is the policy - the `auditor` section of an entry, which kind of credential a channel takes, the step table of a platform and the audit itself.
- **Never changes a device - though the account behind it is not read-only either.** Not a policy, not an interface, not even a console setting: with an active FortiOS pager the collection refuses instead of disabling it. Reaching the device at all still needs an elevated account: a `super_admin` administrator on FortiOS - a profile that could write to the device, chosen because a weaker one silently returns an incomplete configuration instead of an error - and an administrator account on ExtremeXOS, because a user-level account there is refused `show configuration` outright. What keeps the collector itself from writing is the fixed step table and the absence of any other command on the channel, not the account; see [`docs/channels.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/channels.md).
- **Keeps secrets out of findings.** A finding carries an object reference and line numbers, never the configuration text. A canary fixture per platform - twenty marked secrets on FortiOS, eleven on EXOS - must not leak a single one into a finding, an MCP answer, or a CLI report.
- **Knows what changed, and never across tenants.** Baseline in the database, suppressions with a mandatory expiry in a reviewed JSON file, four evaluated finding states, an explicit `not-evaluated` state for findings carried across an incomplete audit, and a freshness threshold - every command that touches them takes a required `--tenant`. The tenant is part of a finding's identity: the fingerprint is the sha256 of rule id, rule version, **tenant**, device name and object key, computed by one shared function, so the same device audited for two tenants produces two different fingerprints and one tenant's waiver cannot reach the other. A suppression file therefore names its `tenant` as a required field at file version 2, and the CLI and the read-only MCP surface refuse a file bound elsewhere through the same function rather than one warning where the other is silent. The store carries a schema version for the same reason. Both older shapes are refused fail-closed with the migration command in the message, and both migrations - `migrate-suppressions` and `migrate-store` - are explicit steps that never run on the side. The credential store, the suppression schema, the two migrations, the byte budget of the REST channel, the exit codes and the two refusals that end a run before the catalogue is reached are in [`docs/configuration.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/configuration.md).
- **Read-only MCP surface - a different and smaller boundary than the collector's.** Seven tools (`audit_status`, `list_rules`, `rule_detail`, `list_findings`, `finding_detail`, `compare`, `schema_report`) over a SQLite store and optional pinned schema reports, opened read-only for one configured tenant. It imports neither the collection code, nor the credential store, nor the inventory, so it cannot reach a device and needs none of the collector's privilege: the collector needs a `super_admin` or administrator account *on the device itself*, the server needs only local filesystem read access to a store somebody else already wrote.
- **The gate reads what is released.** `scripts/check_gates.py` scans the whole released file set, not only the fixtures, and it runs inside an exported archive where no repository is left. What may appear in that set is an allowlist: RFC 5737 and loopback addresses, `2001:db8::1/32`, RFC 7042 MAC addresses, RFC 2606 names, `example.invalid`, and the vendor domains of the documentation. Anything else stops the release. Outside a repository - which is what an exported archive is - the gate also holds the file set itself: every file present must be in the release selection and in `release-manifest.json`, and every file those two name must be present, so neither an added nor a removed file survives it.

## Management rules and operator policy

The catalogue also carries seven FortiOS and five EXOS management checks, released in 0.2.5. These cover the Admin change scope and accept an optional operator policy. See [management policy](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/management-policy.md) for scope, configuration, coverage reporting and limitations.

## Running it

The auditor needs `netops-core` and nothing else from outside the standard library; from the release archives the two verified source archives are installed side by side (see [`docs/releasing.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/releasing.md)), and in this repository the core is taken from the tree. `fastmcp` is needed by the MCP surface alone and is pinned in `requirements-mcp.txt`; the CLI runs without it, and `python -m netops_auditor.mcp_server` started without `fastmcp` says so in one line instead of raising an import error. Installing the distribution puts the command line on the path as `netops-auditor`, with the rule catalogues inside the package.

```sh
PYTHONPATH=src:../netops-core/src python3 -B -m netops_auditor --help
PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider  # the test suite
python3 -B scripts/check_gates.py            # the gate of a release
```

Run them with an interpreter that has the dependencies of `requirements-release.lock`, such as the environment of the [installation guide](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/installation.md); in an unpacked release archive that environment also provides `netops_core`, because `../netops-core/src` exists only in the repository. `-B` and `-p no:cacheprovider` keep `__pycache__` and `.pytest_cache` out of the tree, whose gate refuses them in an unpacked archive; `PYTHONDONTWRITEBYTECODE=1` does the same for the interpreters the tests start.

Three subcommands, each taking `--tenant`: `run` evaluates a configuration file already on disk, `collect` reaches a device through the inventory and evaluates what comes back, and `status` reports the freshness of the last audit. `merge-sarif` combines SARIF reports of `run --sarif`; the two migrations are described in [`docs/configuration.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/configuration.md).

## SARIF and GitHub code scanning

`run --sarif` writes the report as one SARIF 2.1.0 run instead of text or JSON (`--json` and `--sarif` exclude each other). The run describes every rule of the catalogue, and each finding becomes a result with the configuration file and line, the object key as a logical location, the finding fingerprint under `partialFingerprints` (`netopsFingerprint/v2`) and a suppressed finding marked as an accepted external suppression. Severity maps to the SARIF level (`high` to `error`, `medium` to `warning`, `low` and `info` to `note`) and, for GitHub, to `security-severity` 8.0, 5.0 and 3.0. The evidence fields travel as result properties exactly as in the JSON report, never the configuration text. `merge-sarif --output FILE INPUT...` combines several such files of the same auditor version into one run, so that one upload to code scanning carries all of them. A result may refer to a rule described by any of the inputs, whatever their order; two inputs that describe the same rule differently are refused.

```sh
netops-auditor run --platform fortios --tenant example --device fw-a --config backups/fw-a.conf --sarif > fw-a.sarif
netops-auditor merge-sarif --output all.sarif fw-a.sarif fw-b.sarif
```

The repository ships the same path as a composite GitHub Action in [`action.yml`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/action.yml). It audits configuration files already committed to the repository - no device, credential or network access - and writes one SARIF file. It sets up Python 3.13 without changing the environment of later steps and runs the auditor and `netops-core` from the sources at the referenced commit, so pin it to the full commit SHA of an auditor release. Every file becomes a device named by its path, so renaming a file changes the fingerprints of its findings. A pattern that matches nothing, an unreadable file or an unusable policy fails the step.

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      - id: audit
        uses: radek-cerny-soukr/netops/components/netops-auditor@<commit of an auditor release>
        with:
          platform: fortios
          configs: |
            backups/**/*.conf
      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        with:
          sarif_file: ${{ steps.audit.outputs.sarif-file }}
          category: netops-auditor-fortios
```

Inputs: `platform` (`fortios` or `exos`, one catalogue per step), `configs` (one glob pattern per line), `tenant-name` (default `default`), `policy-file` (optional operator policy) and `output-file` (default `netops-auditor.sarif`). Outputs: `sarif-file` and `results`, the number of findings. The step does not fail on findings; code scanning decides what blocks a pull request. Uploading needs code scanning enabled for the repository.

## Boundaries

The auditor is not a compliance product: rules may carry `refs` to the vendor command reference or to CIS, ZKB, or DORA, but no profile is built and no compliance is claimed. The CIS references name the recommendation a rule checks and, in `known_false_positives`, the part of it the rule does not check; [`docs/cis-mapping.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/cis-mapping.md) also lists the recommendations no rule covers. Rules exist for FortiOS and for EXOS, and the EXOS catalogue is four rules wide - time, logging, SNMP communities and Telnet - which is a beginning, not coverage; what each of them cannot see is in [`docs/channels.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-auditor/docs/channels.md). The dated live EXOS measurement and its reciprocal local mutations are recorded in the [support matrix](https://github.com/radek-cerny-soukr/netops/blob/main/docs/verified-support.md); they do not establish coverage beyond the four catalogue rules. A finding of class `usudek` is a judgement and is never emitted at high severity.

The auditor ships no image of its own either, so the `ssh` channel runs the OpenSSH client already installed on the host and inherits that client's own vulnerabilities, unfiltered by any isolating container. Keeping that client current is the operator's responsibility, not this component's.

MIT licensed. Part of the [`netops`](https://github.com/radek-cerny-soukr/netops/blob/main/README.md) family.

## Measured schema audit

The schema-check command checks saved FortiOS configurations against a format-1 library:

    netops-auditor schema-check --library library.json --schema-sha256 REPLACE_WITH_SHA256 --hardware FortiGate-VM64-KVM --os-version 7.6.7 --build 3704 --config snapshot.conf --tenant example --device example-device --full-snapshot --upgrade-library target-library.json

The hardware, version and build must match the library exactly. Identity is declared by the operator; this command does not contact a device to verify it. A complete snapshot must be declared explicitly before a missing reference is reported. Partial snapshots, unresolved references and unknown VDOM scope are reported as not evaluated.

References are checked for every measured reference attribute that is present in the snapshot, including nested tables. Parent table keys and VDOMs remain separate. Measured built-in and special values are accepted. Global interfaces are filtered by their configured VDOM assignment.

An optional target library compares configured paths, attributes, options, ranges, text lengths, scope and availability for the same hardware. These are schema differences requiring vendor upgrade guidance; this command does not simulate a firmware migration. Unmeasured source data and target availability remain visible in coverage, and so does a configured attribute whose target visibility depends on a referenced object. Exit codes are 0 for no detected differences, 1 for findings, 2 for an invalid input, and 3 for incomplete evaluation.

The existing run catalogue and its CIS mapping remain a separate audit. Schema reference integrity and upgrade differences do not establish CIS compliance. The ordinary run command evaluates a single scope. Use schema-check with --catalog-vdoms and --full-snapshot for explicit global and VDOM wrappers, as described below.

### Read finished schema reports through MCP

The optional schema_report tool reads finished schema-check JSON from an operator manifest named by NETOPS_AUDITOR_SCHEMA_REPORTS. It starts no collection and reaches no device. Its device argument selects one manifest entry, with a relative report filename and a SHA-256 pin. The report and manifest must match the MCP server's configured tenant, and the report must match the selected device. Duplicate fields, traversal, changed files and invalid coverage states are refused.

The manifest has format 1, tenant and reports fields. Each reports entry contains file and sha256. Generate the report with schema-check before pinning its bytes. Use view findings, reference, upgrade or catalog to page findings, reference-field coverage, unmeasured upgrade data or scoped catalog rule statuses, with offset and limit (1–100). Digests, identity assurance and coverage counts accompany every page; a report with no measured reference fields does not prove integrity. Report data remains untrusted configuration data.


### Catalog checks on explicit VDOM snapshots

Add `--catalog-vdoms --full-snapshot` to `schema-check` to evaluate the
existing FortiOS catalog on explicit global and VDOM wrappers. Rule applicability
uses the pinned library's measured scope and availability. Global configuration
is preserved, interfaces are bound to their VDOM, and findings with identical
object keys in different VDOMs have distinct fingerprints.

The optional `catalog_coverage` lists a status and reason for each context and
rule. Unknown interface ownership prevents dependent checks from claiming a
result. An unevaluated mandatory check produces exit 3. The `catalog` view of
`schema_report` reads this coverage from a pinned finished report; an older
report explicitly reports that catalog coverage is unavailable.
The ordinary `run` command retains its existing single-scope behavior.

## Starting the read-only MCP server

Set `NETOPS_AUDITOR_STORE` to an existing current-schema SQLite store, `NETOPS_AUDITOR_TENANT` to its tenant and `NETOPS_AUDITOR_CATALOG` to `fortios` or `exos`. `NETOPS_AUDITOR_SUPPRESSIONS` is optional and must bind to that tenant when supplied. See [MCP environment](docs/configuration.md#mcp-environment) for the launch example, seven tools and optional pinned schema reports.

## PyPI source distributions and tests

PyPI wheels and source distributions are installation packages. The PyPI sdist is not a standalone pytest test tree: it omits the test-support `conftest.py` and the component's test guard. The Helper sdist also omits `scripts/` and `config/`. Running pytest over an unpacked sdist can therefore fail during collection or lack required test support. Run the documented suite from a repository checkout or the verified GitHub source release archive, with its pinned development dependencies and any required sibling components. The signed GitHub source archive and the PyPI sdist are different artifacts.

## Offline audit boundary in GitHub Actions

Auditing existing configuration files does not contact a device or need device credentials, and the audit logic needs no network access. The complete GitHub Actions job is not offline: action downloads, `actions/setup-python` and uploading SARIF to GitHub depend on network access. This boundary applies to the local audit step, not runner setup or the reporting service.
