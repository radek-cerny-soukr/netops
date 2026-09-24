# netops-admin

Bounded, reversible changes to network devices: one object of a supported table per request, planned from a fresh snapshot and executed behind a rollback safeguard on the device itself.

This source tree targets `netops-admin/v0.2.2` (2026-09-24) and pins `netops-auditor==0.2.7` and `netops-core==0.2.4`; `pip install netops-admin` installs all three from PyPI. Version 0.1.0 was an unpublished internal milestone.

[Start here: enrollment, policies and the new operations](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/operations-020.md).

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
- `doctor` and `preview` only read. `doctor` reports for one configured device every condition `apply` depends on - credentials, pinned host key, both identities, firmware and the tables measured on it, enrollment, leftover safeguards, the audit policy, audit export, notification, the journal and the budgets - as `ok`, `missing`, `refused` or `skipped`, without secrets. `preview` runs the same checks, planner, audit prediction and check-account read as `apply` for one request and returns the plan, the predicted object state and every reason `apply` would refuse it, a missing enrollment included. Neither installs a safeguard, writes a journal record or an audit event, blocks a device, counts against a budget or sends a notification; they only probe that the journal and the audit log are writable. `apply` plans again from a fresh snapshot.
- `status`, `recover`, `notify-retry`, `unblock` and `undo` are commands for a person: read an operation, settle one left running by an interruption, resend its notification, lift a device block after an investigation, and return a confirmed operation as a new operation behind a new safeguard.
- `python -m netops_admin.mcp_server` offers an agent four tools: `admin_apply`, `admin_status` and the read-only `admin_preview` and `admin_doctor`. There is no tool to cancel a safeguard, unblock a device, undo a change or edit a plan.

Execution, the journal, the limits, the audit log, its export and the notification: [docs/execution.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/execution.md). Planning rules and refusals: [docs/planning.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/planning.md). Installation and configuration: [docs/installation.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/installation.md). Release process: [docs/releasing.md](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-admin/docs/releasing.md).

Exit codes: `0` plan printed, snapshot matches, change confirmed, or preview or doctor ready, `1` snapshot does not match, `3` request refused or preview not ready, `4` change not confirmed, `5` doctor found the device not ready, `2` usage error.

## Profiles

| Platform | Table | Firmware | Operations | Attributes | Safeguard |
|---|---|---|---|---|---|
| FortiOS | `firewall address` (ipmask) | 7.6.x; 8.0.0 build0167 | create, update, delete | `subnet`, `comment` | automation stitch |
| FortiOS | `firewall addrgrp` (static) | 7.6.x | update | `member` list | automation stitch |
| FortiOS | `system dhcp server/reserved-address` | 7.6.x | create, update, delete | `ip`, `mac`, `description` | automation stitch |
| ExtremeXOS | `vlan` | 33.7.x | create, update, delete | `tag` (create), `description` | UPM timer |
| ExtremeXOS | `ports` | 33.7.x | update | `display-string` | UPM timer |
| ExtremeXOS | `vlan-membership` | 33.7.x | update | `tagged` list, `untagged` VLAN | UPM timer |

Every device and build requires a successful operator enrollment before writing. The new FortiOS profiles were measured on 7.6.7 build3704; EXOS profiles on 33.7.1.6.

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
netops-admin apply --config admin.json --device fw-lab --request request.json
netops-admin undo --config admin.json --change-id <change_id> --reason "what was investigated"
```

An ExtremeXOS configuration does not state its firmware, so `plan` needs `--firmware 33.7.1.6` there; a FortiOS snapshot must carry its `#config-version` header.

## Known limits

- The tool cannot know that a person wrote `user_request`: the agent fills it in. An agent misled by text read from a device can request a valid, unwanted change inside the allowed scope, and the safeguard will not return it because the change verifies. The defences are the narrow scope, protected objects, the immediate notification and `undo`.
- Before writing, the predicted snapshot must pass the auditor and operator policy. Before confirming, a second, read-only account reads the object and the auditor evaluates its rules on the new snapshot. The check account uses the same management path as the write account and checks configuration, not traffic.
- On FortiOS the safeguard needs an access profile with `admin read-write`, with which the write account can create another administrator and edit an administrator whose profile its own contains, such as the check account. The write account therefore has to see exactly the configured accounts, and a fingerprint of their entries has to stay unchanged between operations and during a change; otherwise the device is refused and blocked.
- A privileged write account can remove the safeguard itself. The release does not protect against a compromised executor.
- One admin host, one operation at a time per server, one object per request. Each device query is its own SSH connection.
- Profiles are fixed schemas, not schemas learned from a device. Enrollment tests the rollback path on each build inside the permitted family; it does not prove every possible configuration combination.
- The audit log records the lengths of the reason and of the user request, never their text: it proves that a request was made and what was changed, not what the person wrote.
- The notification carries the result, the operation and the number of differences, not the differences themselves.
- The tool does not restrict its own network egress; the admin host has to be limited by the deployment.
- Another administrator logged in to the device is recorded and notified, not refused.
- The branch that refuses to confirm when too little time is left before the safeguard fires is covered by tests only.

## Development

```sh
python -m pytest -q
python scripts/check_gates.py
```

Tests import the parsers from `../netops-auditor/src` and the transport from `../netops-core/src` and simulate the devices; they never contact one. The MCP tests need `fastmcp` from `requirements-mcp.txt` and are skipped without it. The gate keeps the planning modules free of any import that could reach a device, allows the device access layer only the core transport and the auditor collector, refuses programs started from the package, compares the version in `pyproject.toml`, the package and the SBOM, and scans every released file for private material.
