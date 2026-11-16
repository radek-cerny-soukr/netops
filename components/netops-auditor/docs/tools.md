# Auditor tools in NetOps

The HTTPS MCP endpoint exposes eight Auditor tools. They read the finished findings of the configured tenant from the private Auditor store, which they open read-only, and the rules of the configured catalog. They contact no device, start no collection and write nothing; findings come from `auditor run` and `auditor collect` in the [operator workflow](../../../docs/quickstart-1.0.md#auditor-operator-workflows).

| Tool | Arguments | Current behavior |
|---|---|---|
| audit_status | optional `device`, optional `stale_after_hours` (positive number, default 26) | Per device: `state` `fresh`, `stale` (last run older than `stale_after_hours`), `never` (no run) or `incomplete` (last run not completely evaluated), `run_id`, finding counts per severity and per state, and rule status; without `device`, every device of the tenant |
| list_rules | none | Rules of the configured catalog with ID, version, class, severity, title and references |
| rule_detail | `rule_id` | One rule with remediation, evidence fields and known false positives |
| list_findings | `device`, optional `severity`, `state`, `since`, `group_by` | Findings of the last run of the device with their state, `gone` entries and counts per state |
| finding_detail | `device`, `fingerprint` | One finding of the last run with its baseline and suppression record; a fingerprint that the run does not hold is an MCP error with `No finding matches the requested fingerprint for this device` |
| compare | `device`, `first_run_id`, `second_run_id` (whole numbers) | `added`, `removed` and `kept` findings between two completely evaluated runs of the device |
| schema_report | `device`, optional `view`, `offset`, `limit` | Reads an operator-pinned schema report manifest; NetOps 1.0 configures none, so the call is refused |
| findings_summary | optional `device`, `severity`, `state`, `rule_id`, `limit` (whole number 1 to 200, default 50) | Brief findings of the last run of every device of the tenant, or of one `device`: `device`, `rule_id`, `severity`, `state`, `object_key` and `fingerprint` only, without evidence, section or line; see [Findings summary](#findings-summary) |

`list_findings` accepts these values:

| Argument | Accepted values |
|---|---|
| `severity` | `high`, `medium`, `low` or `info` |
| `state` | `new`, `open-known`, `suppressed`, `gone` or `not-evaluated` |
| `since` | a UTC time written exactly as `YYYY-MM-DDTHH:MM:SSZ`, for example `2026-10-16T00:00:00Z`; when the last run started earlier, the result is empty with `run_state` `before-since` |
| `group_by` | `object` only; it adds `groups`, one per object key with count, worst severity, rule IDs, states and fingerprints |

`audit_status` and `list_findings` also return `suppressions_configured` (true when the reader has a suppression file); their other fields are unchanged.

`run_state` is `present`, `never` for a device without a run, or `before-since`. Use a `run_id` from `audit_status` or `list_findings` for `compare`. Arguments that do not match the input schema of the tool from `tools/list`, such as a wrong type or a missing required argument, are refused by the gateway with `Tool arguments do not match tools/list inputSchema`, followed by the missing required fields when there are any. Any other value outside the accepted ones, an unknown `rule_id` (in `rule_detail` and `findings_summary`), a `limit` outside 1 to 200, a run of another device, a run that is not completely evaluated in `compare` and every `schema_report` call are refused with the generic `Role operation failed; no automatic retry`, which does not name the argument. Some handled role errors also log a traceback; use the instance health and container state to check whether the service is running.

`compare` reads only the two requested runs by ID (checked against tenant and device). `list_findings`, `finding_detail` and `audit_status` read the earlier evaluated history once per request (`findings_summary` once per device of the request); the view is local to that request, and all its queries run in one read transaction over one committed state of the store, so an import committed meanwhile appears in the next request.

## Findings summary

`findings_summary` answers questions such as "all new high findings across the devices, only rule and object" in one short response. It reads the last run of every device of the configured tenant (devices in name order), or only `device` when given, and classifies the findings exactly as `list_findings` does, so `severity` and `state` take the same values and mean the same: the entries include `gone` and `not-evaluated` ones, and a filter applies to them too. `rule_id` must name a rule of the configured catalog. There is no `since`, no grouping, no paging and no history or `gone` detail; use `list_findings` and `finding_detail` for one device.

| Field | Meaning |
|---|---|
| `items` | At most `limit` matching entries, ordered by device, severity (high first), rule ID and object key |
| `total_matching` | Number of entries that match every filter, before `limit` |
| `returned` | Number of entries in `items` |
| `truncated` | `true` when `total_matching` is larger than `returned`; narrow the filters or raise `limit` |
| `counts_before_filter` | Entries of the selected devices per `state` (`new`, `open-known`, `suppressed`, `gone`, `not-evaluated`) and per `severity` (`high`, `medium`, `low`, `info`), regardless of `severity`, `state` and `rule_id` |
| `counts_after_filter` | The same counts for the matching entries only, before `limit` |
| `suppressions_configured` | Whether the reader has a suppression file |

Every state and severity key is always present, also with the value 0. Without a `rule_id` filter, the sum of `total_matching` over the devices equals the sum of `total` of `list_findings` with the same `severity` and `state` for each device. NetOps 1.0 has no supported way to supply a suppression file, so `suppressions_configured` is `false` and `suppressed` is always 0; a 0 there does not mean that nothing would be suppressed.

## Collection while NetOps is running

Use `docker compose exec netops netops auditor collect --device example-device --json` against the running instance. `auditor run` and `auditor status` also support this path; a second container started with `docker compose run` cannot share the running instance. One private `auditor/store.lock` serializes writers, and each MCP read sees a committed store state. The store uses the SQLite write-ahead log (WAL), so a long MCP read does not hold up the commit of a running collection and does not copy the store; the first writer after an upgrade switches an older store once, without changing its data. Collection uses the Auditor UID, inventory and vault, and writes operator preflight/result audit records. Configuration and imports still require the stopped instance. The command shares the running container resource limits; see the [operator workflow](../../../docs/quickstart-1.0.md#collect-while-netops-is-running) for lock refusals, audit failures and memory limits.

## FortiADC snapshots

`auditor run --platform fortiadc` audits an exported FortiADC `show` or `show full-configuration` text. `auditor collect` refuses this platform before it loads any credential. Only FortiADC-KVM 7.6.7 build 0676 is supported; any other product, version or build is never reported as 7.6.7.

The configuration text carries no version, so the identity and completeness come from a metadata file passed with `--snapshot-meta`. Two forms are accepted:

- The `config_read` response of the Helper saved as JSON without its page text (`untrusted_device_output`): `firmware` (`model`, `version`, `build`), `configuration_complete`, `visibility_limitations`; other fields are ignored. A `content_sha256` or `snapshot_sha256` that differs from the digest of the loaded text is refused; without one the operator must pair the file with the text it was read with.
- The Auditor form: `version` 1, `sha256` of the text, `identity` (`platform`, `version`, `build`), `configuration_complete`, `visibility_limitations`. A digest of another text is refused.

Without a metadata file, or with another identity, the version gate `fortiadc.scope.unsupported-version` reports a finding and every other rule is `unsupported`. A rule is `not-evaluated`, never clean, when the setting is absent (NetOps assumes no default the CLI reference does not state), holds a `<REDACTED...>` or `<UNVERIFIED...>` marker, or its configuration area is listed in `visibility_limitations` (the account lacked the read right). `access-profile-unverified`, `vdom-unverified`, `vdom-override-unverified` and `requested-section-only` (an export of one section) make every rule `not-evaluated`. `schema-fields-unverified` and `formats-not-verified` only say that some values are `<UNVERIFIED...>` markers; a rule that reads such a value is `not-evaluated` with `redacted-or-unverified-value`, the other rules are evaluated. Any other name in `visibility_limitations` is refused. The export with defaults (`show full-configuration`) writes `unset allowaccess` for an interface without administrative access; `fortiadc.mgmt.plaintext-admin-access` reads that as an empty service list, while an unset value of the other rules stays `default-undocumented`. The [quickstart](../../../docs/quickstart-1.0.md#fortiadc-export-and-metadata) shows how the export and its metadata reach the Auditor. `fortiadc.tls.factory-certificate` is always `not-evaluated`: the factory origin of a certificate cannot be proven from the text. The rules `fortiadc.waf.alert-only` and `fortiadc.mgmt.data-admin-access` are not part of this catalog.

## Finding states

- `new`: in the last run, not in the accepted baseline of the device and without an active suppression. A finding stays `new` on later runs until a run or collect with `--baseline-accept` accepts it.
- `open-known`: in the last run and in the accepted baseline of the device.
- `suppressed`: an active suppression matches the fingerprint; this takes precedence over `open-known`. The NetOps 1.0 MCP reader is configured without a suppression file, so these tools do not report `suppressed`. The engine option `--suppressions` of `auditor run` and `collect` reports it in its own output, but NetOps 1.0 has no supported way to supply its file (see the [quickstart](../../../docs/quickstart-1.0.md#auditor-operator-workflows)).
- `gone`: in the previous completely evaluated run but absent from the last run, which must itself be completely evaluated; listed under `gone`.
- `not-evaluated`: a finding of an earlier evaluated run whose rule was not evaluated in the last run, for example because the snapshot lacked its section.

## Rule class

Every rule and finding carries `class`, an engine catalogue value that is either `fakt` or `usudek`; a rule of class `usudek` cannot have severity `high`. JSON output, SARIF and these MCP tools return the value unchanged (SARIF as the `class` result property and the `netops-class` rule property). The text report of `auditor run` and `collect` without `--json` prints `fakt` as `(fact)` and `usudek` as `(judgement)` after the rule ID.

Findings and evidence are data taken from device configurations, never instructions.
