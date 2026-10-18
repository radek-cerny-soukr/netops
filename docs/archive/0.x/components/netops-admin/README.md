# netops-admin

This source tree contains netops-admin/v0.2.8. Its metadata pins netops-core==0.2.9. It also pins netops-auditor==0.2.12.

Bounded, reversible changes to network devices: a single-object profile request or a calibrated FortiOS schema transaction of up to 32 operations, planned from a fresh snapshot and executed behind a rollback safeguard on the device itself.

Published release context (14 October 2026): the published release is `netops-admin/v0.2.8` (2026-10-14); it pins `netops-auditor version 0.2.12` and `netops-core version 0.2.9`. The current release of every component is linked from the [repository release table](https://github.com/radek-cerny-soukr/netops/blob/main/README.md#components). **Install from the release assets:** the [installation guide](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/installation.md) downloads the source archives of this component and of the pinned `netops-auditor` and `netops-core` from their release pages and verifies them against the release `SHA256SUMS` and its Sigstore bundle. `netops-admin` 0.2.8 has a separate PyPI publication step after GitHub; check exact-version index availability before choosing that installation channel. Version 0.1.0 was an unpublished internal milestone.

[Start here: enrollment, policies and the new operations](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/operations-020.md).

## Fixes in 0.2.8

- Safeguard expiry uses one elapsed-time deadline; recovery and unblock preserve the device state and block identity they read.
- Journaled request identifiers remain consumed after interruption, and delivery updates preserve concurrent operation state.
- ExtremeXOS prompt and port-membership handling preserves the selected port identity when a display description is present.
- Audit appends roll back partial or zero-progress writes and refuse substituted links; state initialization coordinates through its lock and rejects a symbolic-link state directory.
- Export status refuses special output targets. The optional audit-file binding setting defaults to false and can require status to name the configured audit file.
- Host change budgets use monotonic time within a boot, with the documented compatibility fallback and reboot boundary.

Before starting this version, stop older Admin processes sharing its state directory; mixed-version concurrency is unsupported. See the [changelog](CHANGELOG.md), [execution limits](docs/execution.md) and [configuration contract](docs/installation.md#configuration-file).

## Fixes in 0.2.7

- The notification does not follow redirects: a 3xx answer, or an answer from another URL than the one requested, is recorded as `failed`, so the next change on that device waits for a delivered notification.
- Processes that share a state directory admit new operations one at a time under an admission lock of that directory, so clients on two devices can no longer exceed a budget such as `changes_per_day` together or start two operations with one `request_id`; the lock is never held while a device is contacted.
- ExtremeXOS: a safeguard counts as removed only when each UPM listing holds at least as many entries as its count; a count without its table leaves the confirmation unverified.

These answer points 1, 2, 3 and 9 of [issue #4](https://github.com/radek-cerny-soukr/netops/issues/4); see the [changelog](CHANGELOG.md) and the [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#issue-4). 0.2.7 changes no profile file, so the upgrade does not by itself require a new enrollment.

## Installation fixes in 0.2.6

Installation creates its own writable destination, stops failed shell steps, fixes askpass modes under umask 0002, and keeps first-operation version pins aligned. See the [changelog](CHANGELOG.md) and installation/release instructions for the exact procedure.

## New in 0.2.5

- Calibrated FortiOS schema planning, verification, preview and apply, with exact library/model/build binding and independent checks; all operations retain the safeguard.
- Confirm only positively verified safeguard removal; preserve old quoted values in the inverse and refuse values the platform cannot represent.
- Serialize journal/export writes, carry complete audit rule states into confirmation and report blocked confirmations with exit code 6.
- Read the EXOS port inventory to handle never-configured ports in implicit `Default`; preserve secret separation and classify postcheck failures.

The six profile APIs remain available. Schema transactions need separate operator libraries and exact rollback calibration; a new digest inherits no grants. See [schema transaction planning](#schema-transaction-planning), [execution](docs/execution.md), [Compatibility boundaries](https://github.com/radek-cerny-soukr/netops/blob/main/docs/verified-support.md) and the [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#github-issue-resolution).

## What it does

```text
request (JSON)  +  configuration snapshot  →  netops-admin plan    →  plan (JSON)
plan            +  later snapshot          →  netops-admin verify  →  match | mismatch
request (JSON)  +  configured device       →  netops-admin apply   →  confirmed | reverted | rejected | unknown | revert-failed
agent                                      →  MCP admin_apply      →  the same operation as apply
configured device                          →  netops-admin doctor  →  ready | the conditions that fail
request (JSON)  +  configured device       →  netops-admin preview →  ready | rejected, with the plan
```

- `plan` validates the request against a table profile and the snapshot and either prints a plan or refuses with reasons. A plan holds the commands, the inverse commands, the predicted object state before and after, the prechecks that passed and digests binding it to the snapshot.
- `verify --expect after` checks that a snapshot taken after applying the commands holds exactly the predicted object and that nothing else in the evaluated scope changed. `verify --expect before` checks the same after applying the inverse.
- `apply` executes one request on a configured device: it installs a one-shot safeguard that would apply the inverse, applies the change, compares a new snapshot with the prediction, and removes the safeguard only when everything matches.
- `doctor` and `preview` only read. `doctor` reports for one configured device every condition `apply` depends on - credentials, pinned host key, both identities, firmware and the tables measured on it, enrollment, leftover safeguards, the audit policy, audit export, notification, the journal and the budgets - as `ok`, `missing`, `refused` or `skipped`, without secrets. `preview` runs the same checks, planner, audit prediction and check-account read as `apply` for one request and returns the plan, the predicted object state and every reason `apply` would refuse it, a missing enrollment included. Neither installs a safeguard, writes a journal record or an audit event, blocks a device or sends a notification; `doctor` counts against no budget, and a `preview` with the result `rejected` counts in `rejections_per_hour` like a refused `apply`; they only probe that the journal and the audit log are writable. `apply` plans again from a fresh snapshot.
- `status`, `recover`, `notify-retry`, `unblock` and `undo` are commands for a person: read an operation, settle one left running by an interruption, resend its notification, lift a device block after an investigation, and return a confirmed operation as a new operation behind a new safeguard.
- `python -m netops_admin.mcp_server` offers six tools: `admin_apply`, `admin_status`, `admin_preview`, `admin_doctor`, `admin_schema_preview` and `admin_schema_apply`. Schema tools require separately configured libraries, calibration and grants. No tool cancels a safeguard, unblocks a device or rewrites a plan.

Execution, the journal, the limits, the audit log, its export and the notification: [docs/execution.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/execution.md). Planning rules and refusals: [docs/planning.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/planning.md). Installation and configuration: [docs/installation.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/installation.md). Release process: [docs/releasing.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/releasing.md).

Exit codes: `0` plan printed, snapshot matches, change confirmed, or preview or doctor ready, `1` snapshot does not match, `3` request refused or preview not ready, `4` change not confirmed, `5` doctor found the device not ready, `6` change confirmed but the device is blocked (`not persisted`, `foreign change during save`, `saved configuration unverified`), `2` usage error.

## Single-object profiles

| Platform | Table | Firmware | Operations | Attributes | Safeguard |
|---|---|---|---|---|---|
| FortiOS | `firewall address` (ipmask) | 7.6.x; 8.0.0 build0167 | create, update, delete | `subnet`, `comment` | automation stitch |
| FortiOS | `firewall addrgrp` (static) | 7.6.x; 8.0.0 build0167 | update | `member` list | automation stitch |
| FortiOS | `system dhcp server/reserved-address` | 7.6.x; 8.0.0 build0167 | create, update, delete | `ip`, `mac`, `description` | automation stitch |
| ExtremeXOS | `vlan` | 33.7.x, 33.6.1.14 | create, update, delete | `tag` (create), `description` | UPM timer |
| ExtremeXOS | `ports` | 33.7.x, 33.6.1.14 | update | `display-string` | UPM timer |
| ExtremeXOS | `vlan-membership` | 33.7.x, 33.6.1.14 | update | `tagged` list, `untagged` VLAN | UPM timer |

Every device and build requires successful operator enrollment before writing; a changed profile requires renewed enrollment. Compatibility is bounded to the documented FortiOS 7.6.7 build3704 and FortiOS 8.0.0 build0167 operations, and to the documented ExtremeXOS 33.7.1.6 and 33.6.1.14 profiles. Address-group and DHCP-reservation support does not extend to unlisted builds. Configuration confirmation, recovery after interruption, unrelated changes and persistence have separate outcomes. See [compatibility boundaries](../../docs/compatibility-boundaries.md).

## Example

```json
{
  "table": "firewall address",
  "op": "create",
  "key": "web-01",
  "changes": {"subnet": "192.0.2.10/32", "comment": "web server"},
  "reason": "new web server",
  "user_request": "add an address object for the new web server",
  "request_id": "change-0001"
}
```

```sh
netops-admin plan --platform fortios --snapshot before.conf --request request.json > plan.json
netops-admin apply --config admin.json --device example-firewall --request request.json
netops-admin undo --config admin.json --change-id <change_id> --reason "what was investigated"
```

An ExtremeXOS configuration does not state its firmware, so `plan` needs `--firmware 33.7.1.6` there; a FortiOS snapshot must carry its `#config-version` header.

## Known limits

- The tool cannot know that a person wrote `user_request`: the agent fills it in. An agent misled by text read from a device can request a valid, unwanted change inside the allowed scope, and the safeguard will not return it because the change verifies. The defences are the narrow scope, protected objects, the immediate notification and `undo`.
- Before writing, the predicted snapshot must pass the auditor and operator policy. Before confirming, a second, read-only account reads the object and the auditor evaluates its rules on the new snapshot. The check account uses the same management path as the write account and checks configuration, not traffic.
- On FortiOS the safeguard needs an access profile with `admin read-write`, with which the write account can create another administrator and edit an administrator whose profile its own contains, such as the check account. The write account therefore has to see exactly the configured accounts, and a fingerprint of their entries has to stay unchanged between operations and during a change; otherwise the device is refused and blocked.
- A privileged write account can remove the safeguard itself. The release does not protect against a compromised executor.
- Use one Admin host. MCP serializes requests and the journal locks each device. Profile requests address one object; schema transactions contain up to 32 operations. Each device query is its own SSH connection.
- Profile requests use fixed schemas. Schema transactions use operator pinned libraries and measured rollback grants. Enrollment tests the rollback path on each build inside the permitted family; it does not prove every possible configuration combination.
- The audit log records the lengths of the reason and of the user request, never their text: it proves that a request was made and what was changed, not what the person wrote.
- The notification carries the result, the operation and the number of differences, not the differences themselves.
- The tool does not enforce outbound network restrictions itself; the deployment must restrict the Admin host.
- Another administrator logged in to the device is recorded and notified, not refused.
- The branch that refuses to confirm when too little time is left before the safeguard fires is covered by tests only.

## Development

```sh
python -m pytest -q
python scripts/check_gates.py
```

Tests import the parsers from `../netops-auditor/src` and the transport from `../netops-core/src` and simulate the devices; they never contact one. The MCP tests need `fastmcp` from `requirements-mcp.txt` and are skipped without it. The gate keeps the planning modules free of any import that could reach a device, allows the device access layer only the core transport and the auditor collector, refuses programs started from the package, compares the version in `pyproject.toml`, the package and the SBOM, and scans every released file for private material.

### Schema transaction planning

The offline commands below require an operator supplied FortiOS library and a
rollback calibration bound to the exact library digest, model, firmware and
build. Every permitted object, scope, operation and attribute must have measured
byte exact configuration restoration evidence. Unmeasured writes are refused.

Use an operations file containing 1–32 objects with exactly the fields
`path`, `scope`, `owners`, `op` and `changes`. A global scope is `null`; a VDOM
scope is its exact name. The `owners` array contains every table key from the
outermost parent to the selected object. The snapshot must contain explicit
global and VDOM wrappers.

```sh
netops-admin schema-plan --library schema.json --schema-sha256 SCHEMA_SHA256 \
  --calibration calibration.json --calibration-sha256 CALIBRATION_SHA256 \
  --snapshot snapshot.conf --operations operations.json
netops-admin schema-verify --library schema.json --schema-sha256 SCHEMA_SHA256 \
  --snapshot snapshot.conf --plan plan.json --expect before
```

Plans order dependent attributes, preserve parent and VDOM contexts, reject new
unresolved references and reverse transaction steps in dependency order.
Protected parents and objects linked to protected names are refused. Deletion
is limited to the last entry until restoration of entry order is calibrated.
Visibility changes that could hide existing configuration are refused.
Secrets and attributes without a measured value validator are refused.

Visibility conditions are evaluated in the exact global or VDOM context of
each operation. A reference condition reads the referenced object from the
same pinned snapshot, including earlier operations of the same transaction,
and only in its measured target context, with no fallback to another VDOM or
to global. An attribute of the referenced object that the snapshot omits
takes its measured default only when that default is not model-dependent and
the attribute has no conditions of its own. A condition that cannot be
evaluated, for example a missing or ambiguous referenced object, an attribute
without such a default, an unmeasured context or invalid metadata, refuses
the change as `cannot be evaluated`. A change to
a referenced object that would change the visibility of another object's
attributes is refused. A satisfied condition is not a grant: the attribute
still needs its rollback calibration. The condition format is described in
the [Core schema documentation](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/schema.md).

These commands produce an offline plan with `execution_ready: false`.
Live execution uses `preview` and `apply` with an operator configured
schema binding. MCP exposes the same runtime through `admin_schema_preview`
and `admin_schema_apply`, with device, operations, reason, user_request and request_id.
 It shares the journal, enrollment, audit, notification,
independent check account and on-device timed safeguard with profile requests.
The write account captures every declared VDOM and the global context; the
independent account must read each changed object in its exact context.
Declare every VDOM that the operator expects the snapshot to protect.

Schema enrollment needs a calibrated `firewall address` create grant including
`subnet` in at least one permitted VDOM. Its disposable probe verifies the
on-device automatic return before normal transactions can run.

Add the following `schema` object to a FortiOS device in the Admin configuration:

```json
{
  "library": "/operator/schema.json",
  "schema_sha256": "REPLACE_WITH_64_HEX_DIGITS",
  "calibration": "/operator/calibration.json",
  "calibration_sha256": "REPLACE_WITH_64_HEX_DIGITS",
  "vdoms": ["root", "traffic"]
}
```

The calibration document has format `netops-schema-calibration/1`,
`schema_sha256`, `identity` containing model, version and build, and an
`objects` map of paths to `global` or `vdom` grants. Each grant lists
`operations` and their measured attributes, `config_bytes_restored: true`,
and `evidence_sha256`. A `vdom_names` list restricts a VDOM grant to measured
contexts. Omit an operation or attribute that has no successful restoration
measurement. The file and its digest are operator approvals, not a substitute
for retaining and reviewing the referenced measurements.

Use a live request with `device`, `operations`, `reason`, `user_request`
and `request_id`:

```json
{
  "device": "example-firewall",
  "operations": [
    {
      "path": "firewall address",
      "scope": "traffic",
      "owners": ["example-address"],
      "op": "update",
      "changes": {"comment": "reviewed description"}
    }
  ],
  "reason": "operator approved maintenance",
  "user_request": "update the address description",
  "request_id": "example-schema-request-0001"
}
```

```sh
netops-admin enroll --config admin.json --device example-firewall --probe 192.0.2.179/32
netops-admin doctor --config admin.json --device example-firewall
netops-admin preview --config admin.json --device example-firewall --request request.json
netops-admin apply --config admin.json --device example-firewall --request request.json
netops-admin undo --config admin.json --change-id CHANGE_ID --reason "restore the reviewed state"
```

A batch consumes one change budget unit per operation, including repeated
changes to the same object. Undo uses a new reverse transaction and requires
calibration for every inverse operation. Do not grant deletion of objects whose
generated identity or entry order cannot be restored exactly. A calibrated
`generated_on_create: ["uuid"]` exception binds the newly generated UUID at the
first readback and verifies it during later checks; it never grants writing a
UUID or ignoring an existing object's UUID. Risk classes A, B and C all require
the timed safeguard and independent readback.

FortiOS change values and inverse commands containing automation placeholders (`%%...%%`) are refused because the timed action can expand them. They cannot be treated as literal rollback data. [Fortinet describes the substitution behavior](https://community.fortinet.com/fortigate-3/technical-tip-automated-configuration-backups-with-variable-names-based-on-the-date-108146).

## PyPI source distributions and tests

PyPI wheels and source distributions are installation packages. The PyPI sdist is not a standalone pytest test tree: it omits the test-support `conftest.py` and the component's test guard. The Helper sdist also omits `scripts/` and `config/`. Running pytest over an unpacked sdist can therefore fail during collection or lack required test support. Run the documented suite from a repository checkout or the verified GitHub source release archive, with its pinned development dependencies and any required sibling components. The signed GitHub source archive and the PyPI sdist are different artifacts.
