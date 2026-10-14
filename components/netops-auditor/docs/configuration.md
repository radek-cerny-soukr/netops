# Configuration

Three files decide what the auditor does: the inventory, the credential store and the suppression
file. All three are read fail-closed - a missing field, an unknown field or a wrong value stops the
run instead of falling back to a default - and none of them is ever written by the tool. The inventory
and the credential store are the shared documents of `netops-core`, both at file version
`2`; this page says what the auditor adds to the credential store, holds the schema of the suppression
file, and lists the exit codes and the two refusals that end a run before the rule catalogue is
reached. The inventory has a page of its own: [`inventory.md`](inventory.md).

## The credential store (`vault.json`)

The inventory names a credential, the store holds its value. The store is **the shared
document of `netops-core`, file version 2**, and its schema is
[`../../netops-core/docs/vault.md`](../../netops-core/docs/vault.md). This document ships in the
`netops-core` archive, not in the auditor archive: that relative path resolves in a repository
checkout; from a standalone auditor archive the same file is published at
[`netops-core/v0.2.9`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.9/components/netops-core/docs/vault.md).
What follows is what the auditor adds to it.

```json
{
  "version": 2,
  "credentials": {
    "fw-a-audit-ro": {"kind": "ssh-key",   "login": "audit-ro", "value": "replace-me"},
    "fw-b-audit-ro": {"kind": "password",  "login": "audit-ro", "value": "replace-me"},
    "fw-c-audit-ro": {"kind": "api-token", "value": "replace-me"}
  }
}
```

| field | value |
|---|---|
| `version` | `2`; a legacy version `1` store is refused with `vault file <path>: version must be 2` |
| `credentials` | an object; the key is the record name an inventory entry refers to in `credential` |
| `credentials.<name>.kind` | one of `password`, `ssh-key`, `api-token`, `snmp-community` |
| `credentials.<name>.login` | the account name, **required** for `password` and `ssh-key`, **forbidden** for the other two |
| `credentials.<name>.value` | the secret itself; for `ssh-key` the whole private key text, header line and all, newlines written as `\n` - the example above is a placeholder, and the real shape is in [`../../netops-core/docs/vault.md`](../../netops-core/docs/vault.md) (from a standalone archive, published at [`netops-core/v0.2.9`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.9/components/netops-core/docs/vault.md)) |

The file is read at mode `0600` or `0400` and at no other mode, and a vault path that is a symbolic
link is refused before the mode is read.

### A channel takes the kind it can use

The kind is not a free choice: the channel of the device decides it, and a record of another kind ends
the run when the credential is resolved, before anything is sent anywhere.

| channel | kind | what the record gives the session |
|---|---|---|
| `fortios-rest` | `api-token` | the token of the `Authorization: Bearer` header |
| `ssh` | `password` or `ssh-key` | the `login` is the account of the session, the `value` is the password or the private key |
| `file` | none | the entry takes no credential at all, and `--vault` is refused for it |

```
error: device fw-a.example.invalid reads channel ssh with a credential of kind api-token,
channel ssh takes a credential of kind password or ssh-key
```

**The login comes from the credential.** `collect` has no `--profile` option any more: on the `ssh`
channel the login of the session is the `login` of that record, and the report says which account was used in
`collection-profile` and which kind of record opened the session in `collection-credential-kind`. On
`file` and `fortios-rest`, which log in as nobody, `collection-profile` is `unknown`.

The value stays inside the object it was loaded into. A credential prints as
`Credential(name='fw-a-audit-ro', kind='ssh-key', login='audit-ro')` and a store as
`Vault(path=vault.json, names=(fw-a-audit-ro))` - names, never values - and neither channel puts a
secret in `argv`: a key reaches the client as a file of mode 0600 in a throwaway directory, a password
through an askpass script reading a file of mode 0600 in that same directory, and the directory is
removed when the call ends.

## Running the MCP surface

The command line is the whole auditor; the MCP surface is the same queries over the same store for an
agent, and it is started as a module:

```sh
python -m netops_auditor.mcp_server
```

The required environment variables are `NETOPS_AUDITOR_STORE`, `NETOPS_AUDITOR_TENANT` and
`NETOPS_AUDITOR_CATALOG`. `NETOPS_AUDITOR_SUPPRESSIONS` is optional; when supplied it must name
a valid version-2 file bound to that tenant. Missing required variables or invalid supplied
configuration refuse startup, naming the variable. It needs `fastmcp`, which the auditor does not install itself: the pin lives in
`requirements-mcp.txt` (`fastmcp==4.0.5`, the version `netops-helper` ships, so both MCP surfaces of
the family speak one library). Started without it, the module says so in one line and exits with
status 2 rather than raising an import error. Nothing on this surface writes to a device: the seven
tools read the store and the catalogue.

## MCP environment

Before launching `python -B -m netops_auditor.mcp_server`, set all three required variables:

| Variable | Value |
|---|---|
| `NETOPS_AUDITOR_STORE` | Existing readable SQLite audit store at the current schema version; opened read-only |
| `NETOPS_AUDITOR_TENANT` | Tenant whose finished audit results the server may read |
| `NETOPS_AUDITOR_CATALOG` | Catalogue name `fortios` or `exos`, not a filename |
| `NETOPS_AUDITOR_SUPPRESSIONS` | Optional version-2 suppression file bound to that tenant; unset means no suppressions |
| `NETOPS_AUDITOR_SCHEMA_REPORTS` | Optional operator manifest for pinned finished schema reports; required only for `schema_report` |

For example, after the CLI has written the store:

```sh
NETOPS_AUDITOR_STORE=/path/to/audit.sqlite3 \
NETOPS_AUDITOR_TENANT=demo \
NETOPS_AUDITOR_CATALOG=fortios \
python -B -m netops_auditor.mcp_server
```

The server refuses startup if a required variable is empty, the store cannot be opened read-only at the current schema version, the catalogue is unknown or the supplied suppression file is invalid. It requires the pinned FastMCP runtime. Its seven tools are `audit_status`, `list_rules`, `rule_detail`, `list_findings`, `finding_detail`, `compare` and `schema_report`; none collects a configuration or reaches a device.

## Suppressions

A suppression silences one finding of one tenant on one device until a date. The file is JSON,
`version`, `tenant` and `suppressions`, and every item carries all nine fields:

```json
{
  "version": 2,
  "tenant": "tenant-a",
  "suppressions": [
    {
      "fingerprint": "2aa12a59e584e7c28ed33cf55508fa350f8415652984bdaa18dc7ddc072a80d6",
      "rule_id": "fortios.mgmt.wan-admin-access",
      "rule_version": 1,
      "device": "fw-a.example.invalid",
      "object_key": "system interface/port1",
      "reason": "https on the wan interface is the documented out-of-band path, review in Q4",
      "author": "operator@example.invalid",
      "created": "2026-09-01T08:00:00Z",
      "expires": "2026-12-01T08:00:00Z"
    }
  ]
}
```

| field | value |
|---|---|
| `version` | `2`; a version `1` file is refused, naming the migration command - see below |
| `tenant` | the tenant the file belongs to, **required**; a file without it is refused |
| `fingerprint` | 64 hex characters, the fingerprint of the finding - see below |
| `rule_id` | the rule the finding came from |
| `rule_version` | the `version` of that rule, an integer |
| `device` | the `name` of the device, spelled as the inventory spells it |
| `object_key` | the object the finding points at, copied from the report |
| `reason` | why the finding is accepted, a non-empty text |
| `author` | who accepted it, a non-empty text |
| `created` | `YYYY-MM-DDTHH:MM:SSZ`, UTC, and before `expires` |
| `expires` | the same format; there is no suppression without an end |

### What it binds to

A suppression does not match by rule or by device. It matches one fingerprint, and that fingerprint
is the sha256 over five values joined by the unit separator `\x1f`, in this order: `rule_id`,
`rule_version`, `tenant`, `device`, `object_key`. Raise the rule version, move the finding to another
interface, meet the same rule on another device **or run the same device for another tenant**, and
the suppression stops applying - by construction, not by policy.

None of the five values may hold that separator itself, or two identities would join into the same
text: tenant `a\x1fb` on device `c` and tenant `a` on device `b\x1fc` would share every fingerprint.
`fingerprint_of` raises an error instead of joining such a value, and the auditor refuses it where it
enters - `--tenant` and `--device` of every command, `NETOPS_AUDITOR_TENANT`, the tenant and the items
of a suppression file, the `name` of a device the auditor reads from the inventory and a rule id of the
catalogue - with one error line and exit code `2`, before anything is written to the store. A
configuration whose finding would carry the separator in its object key is refused the same way, as
`cannot parse configuration`; the separator anywhere else in a configuration is audited as before:

```
error: argument tenant holds U+001F, the separator of the finding fingerprint
error: cannot parse configuration: rule fortios.mgmt.wan-admin-access, line 10: object_key holds U+001F, the separator of the finding fingerprint
```

A fingerprint of values without the separator is byte for byte the one earlier versions computed, so
neither a suppression file nor the store needs a migration.

The tenant sits inside the fingerprint, and that is the whole point of file version 2:
before it, two tenants that happened to name a device the same way computed the same fingerprint for
the same finding, so one file could silence a finding for both. One function computes it,
`netops_auditor.findings.fingerprint_of`, and both the report and the file reader call that one -
there is no second copy to drift. The version of the rule catalogue (`rules_version`) is deliberately
**not** part of it: a finding keeps its identity when an unrelated rule is added to the catalogue.

Nobody computes it by hand: every report prints the fingerprint of each finding, so the way to write
a suppression is to run the audit and copy it out. The file is checked against its own components
when it is loaded, so a copied fingerprint next to an edited `object_key` is refused instead of
quietly binding to nothing:

```
error: suppressions: suppression 0: fingerprint '0000000000000000000000000000000000000000000000000000000000000000' does not match components, expected 2aa12a59e584e7c28ed33cf55508fa350f8415652984bdaa18dc7ddc072a80d6
```

Two items with the same fingerprint are an error as well, and so is a key repeated within one JSON
object - the file is refused instead of the last `expires` silently winning.

A run reads only the items whose `device` is the audited device. An item for another device of the
same tenant is not reported as orphaned or expired by that run; the CLI and the MCP surface filter
the same way.

### Tenant binding

A suppression file belongs to exactly one tenant, and says so in `tenant`. Three refusals hold that,
all of them fail-closed and all of them the same for every reader - the CLI and the read-only MCP
surface go through one function, `netops_auditor.suppressions.load_for_tenant`, so neither can be
lenient where the other is strict:

```
error: suppressions: suppression file waivers.json is bound to tenant 'tenant-a', this run is for tenant 'tenant-b'
error: suppressions: suppression file waivers.json: missing document fields: tenant; a suppression file binds to one tenant, which the fingerprint carries; migrate an older file with netops-auditor migrate-suppressions --input <old file> --output <new file> --tenant <tenant>
error: suppressions: suppression file waivers.json: version 1 is refused, a fingerprint carries the tenant since version 2; migrate the file with netops-auditor migrate-suppressions --input <old file> --output <new file> --tenant <tenant>
```

There is no unbound file any more. A file written for two tenants was never one file: migrate it
once per tenant, into two files.

### Migrating a version 1 file

```sh
netops-auditor migrate-suppressions --input waivers.json --output waivers-tenant-a.json --tenant tenant-a
```

The command reads a version 1 document, checks every item against its **old** fingerprint - so an
item that was already edited out of shape is refused rather than carried over - recomputes each
fingerprint with the tenant, and writes a version 2 document. It never writes over its input and
never writes over an existing output - the output is published as a whole under a name that must not
exist yet, so a destination that appears while the migration works is refused instead of truncated,
and a destination that is a symbolic link is refused before anything is read; it prints a count and the path, and nothing out of the
document it read, so a reason or a device name never lands in a log because of a failed migration.
It does not run by itself: no command migrates a file on the side.

```
migrated 3 suppressions of tenant tenant-a into waivers-tenant-a.json
```

### Migrating the store

The database behind `--store` carries a schema version, and the fingerprints inside it are the same
ones. Opening a store without `PRAGMA user_version` set to the current schema is a readable error rather than a silent run, on the CLI
and on the MCP surface alike:

```
error: store: store schema version 1, expected 2: the fingerprint of a finding carries the tenant since version 2; migrate the store with netops-auditor migrate-store --store <file>
```

```sh
netops-auditor migrate-store --store audit.sqlite3
```

The migration recomputes the fingerprint of every stored finding from the tenant of **its own run**
and rewrites the baseline with the same mapping, in one transaction: the number of findings does not
change, a baseline entry keeps pointing at the finding it accepted, and nothing turns up twice
because an old and a new fingerprint met in one store. A finding whose run names no tenant stops the
migration and changes nothing - there is no guess about whose finding it was. Running it twice is an
error, not a second rewrite.

### What expiry does, and what it does not

An active suppression moves a finding into state `suppressed`. It does not remove it: the finding is
still in the report, still counted in the summary by severity, still carrying its evidence. With the
item above, the same run that reported `new 1` reports:

```
findings: 1 (high 1, medium 0, low 0, info 0)
states: new 0, open-known 0, suppressed 1, gone 0
suppressions: orphaned 0, expired 0
```

Expiry is compared against the moment of the run: the item is active while now is **before**
`expires`, so at `expires` it is already gone. An expired item stops suppressing - the finding is
back in `new` or `open-known` - and is listed under `expired suppressions` with its author and
reason, so a review has something to work from. An item whose fingerprint matches no finding of this
run is listed under `orphaned suppressions`, which is how a waiver for a problem somebody fixed
becomes visible. The two lists are independent and an item can be on both.

## The inventory

Not repeated here. The `auditor` section field by field, what each channel requires of the common
device, and the `legacy_ssh` exception are in [`inventory.md`](inventory.md); the common part of the
document is in [`../../netops-core/docs/inventory.md`](../../netops-core/docs/inventory.md), which
ships in the `netops-core` archive, not the auditor archive: from a standalone auditor archive the
same file is published at
[`netops-core/v0.2.9`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.9/components/netops-core/docs/inventory.md).

## The platform picks the parser and the catalogue

`--platform` of `run`, and the `platform` field of the entry for `collect`, choose two things at once:
the L1 parser that reads the text and the rule catalogue that is evaluated over it. There are two of each.

| `--platform` | what the parser reads | catalogue | rules |
|---|---|---|---|
| `fortios` | the tree of `config` / `edit` / `set` / `next` / `end` | `catalog/fortios.json` | 25 |
| `exos` | the flat list of commands of `show configuration`, one record per command with its line, its module and its tokens | `catalog/exos.json` | 9 |

There is no detection: a dump handed to the wrong platform is parsed by the wrong parser, and what
comes back is findings about commands that are not there rather than an error. The platform of a
device belongs in the inventory, where `collect` reads it, and `run` is the command that asks for it
on the command line.

## How much of an answer the REST channel accepts

The `fortios-rest` collector assembles the answer block by block, and a budget bounds the total
**before** each block is kept, so an answer that will not fit is dropped while it is still arriving
rather than after it is whole. The budget is the option `--max-response-bytes` of
`collect`, a whole number of bytes, and its default is `8388608` - 8 MiB. A value that is not a
positive whole number ends the command before the inventory is opened.

The number is sized for a configuration export, not copied from elsewhere: the largest dump measured
in [`channels.md`](channels.md) is `show full-configuration` at 57,258 lines, and the REST backup of
a `super_admin` token is a superset of the CLI dump, so even at a generous hundred bytes per line the
answer stays under 6 MB. 8 MiB leaves room over that and still bounds what one collection can hold in
memory; `netops-helper`'s 2 MB cap is not the right number here, because that one bounds the output of
a command, not a whole configuration backup carrying private key material. Raise it for a device
whose export is genuinely bigger, and raise it knowingly - the limit is what keeps a device, or
something answering in its place, from filling the collector's memory.

An oversized answer is refused with the limit and nothing of the peer's words:

```
error: channel fortios-rest: POST https://192.0.2.20 answered with more than 8388608 bytes, the collector read no further
```

An answer whose HTTP status is not `200` never reaches the budget at all, because its body is never
assembled: the collector reads at most a small head of it, throws that away and reports the status
alone, so an error page cannot grow large and cannot reach a log. The `ssh` channel is not bounded here - its cap is
the bounded receive of `netops_core.ssh`, described in the core's own documentation - and the `file`
channel reads a local file the operator already has.

## Input files and their limits

Every input file named on the command line, in the environment of the MCP surface or as the source
of the `file` channel is opened without blocking and read only when it is a regular file, and never
further than its limit plus one byte. A pipe, a device such as `/dev/zero` or a directory is refused as `not a regular file`, and a longer file as `larger than <limit> bytes`,
before anything in it is parsed; both end the command with exit code `2`:

```
error: cannot read configuration /dev/zero: not a regular file
error: suppressions: cannot read suppression file /run/netops/waivers: not a regular file
```

| file | limit | constant |
|---|---|---|
| `run --config`, the source of the `file` channel | 64 MiB (67108864 bytes) | `collect.MAX_SNAPSHOT_BYTES` |
| `--suppressions`, `NETOPS_AUDITOR_SUPPRESSIONS` | 4 MiB (4194304 bytes) | `suppressions.MAX_SUPPRESSIONS_BYTES` |
| `--policy` | 256 KiB (262144 bytes) | `management.MAX_POLICY_BYTES` |
| each `merge-sarif` input | 64 MiB (67108864 bytes) | `sarif.MAX_SARIF_BYTES` |
| `--inventory` | 4 MiB (4194304 bytes) | `netops_core.inventory.INVENTORY_MAX_BYTES` (from netops-core 0.2.6) |
| `--vault` | 1 MiB (1048576 bytes) | `netops_core.vault.VAULT_MAX_BYTES` (from netops-core 0.2.6) |

The inventory and the vault are read by netops-core; the auditor pins `netops-core==0.2.9`. The limits were introduced in Core 0.2.6 (0.2.5 read them whole).

The output of `merge-sarif` is opened the same way, without blocking, and must be a regular file or
not exist yet; a pipe nobody reads is refused instead of blocking the command. Every argument must be
valid UTF-8: an argument whose bytes do not decode (`--tenant $'\xff'`) is refused with
`error: argument tenant is not valid UTF-8` before any file is read, because the report would carry
it into output a UTF-8 terminal cannot write. A FortiOS dump whose `config` and `edit` blocks nest
deeper than 64 levels (`l1_fortios.MAX_DEPTH`) is refused as `cannot parse configuration`; real
dumps nest a handful of levels, and the parser's memory grows with the square of the depth. A JSON
string with an unpaired surrogate escape (`"\ud800"`) makes a suppression file or a SARIF input
invalid JSON. All of these end the command with exit code `2`.

## The store under concurrent use

Several `run` or `collect` processes may open one `--store` at the same moment, also a file that does
not exist yet. The schema is created and stamped with its version in one write transaction
(`BEGIN IMMEDIATE`), so a second process waits for the first and then finds the whole schema; it
never sees the tables without the version, which it would refuse as schema version 1. Opening a store
that already holds the whole current schema writes nothing.
A newly created database file is mode 0600. The auditor does not automatically change permissions on an existing database file.

An SQLite error after the store was opened - another writer that keeps the lock longer than the five
seconds SQLite waits (`database is locked`), a damaged page (`database disk image is malformed`) -
ends `run`, `collect` and `status` with one line naming the store and exit code `2`, never with a
traceback:

```
error: store audit.sqlite3: database disk image is malformed
```

`run` and `collect` write the run, its findings, its rule status, the events of its collection and,
with `--baseline-accept`, the accepted baseline in one transaction. When that write fails - a store
error, a lock held past the wait, a refused baseline acceptance - nothing of the run stays in the
store, and the line ends with `no run was recorded`:

```
error: store audit.sqlite3: database is locked; no run was recorded
```

On the MCP surface the same error, an unreadable suppression file and a store that cannot be opened
are a tool error whose text names the store or the file; the server keeps serving. A tool error
repeats at most 500 characters of its message, so an oversized argument is not echoed back whole.

## Exit codes

For a stored device history, the latest audit means the run with the greatest committed run ID, and history is listed by run ID in descending order. The reported rules_version also comes from that latest run ID; wall-clock timestamps do not choose the latest run. Stored channel events are listed in the order they were written as well, newest first. Timestamps are used only to calculate age and to compare the latest run with the `since` boundary of MCP `list_findings` (an older run is never taken instead), and CLI `status` and MCP `audit_status` judge it by the same rule: an age from zero up to the threshold is fresh, a larger one is stale, and a negative age (a future timestamp) is never fresh - it is stale, `status` exits with code 1 and `audit_status` counts the device as stale, however far the clock moves on. An incomplete latest run takes precedence over its age and is reported as incomplete, also with code 1.

| code | when |
|---|---|
| `0` | `run` and `collect` finished and every mandatory rule was evaluated; `status` found the last audit fresh |
| `1` | `status` only: the last audit is older than `--stale-after-hours` (26 by default), or there is none, or the latest audit is incomplete |
| `2` | the run was refused - a bad argument, an unreadable file, a fail-closed schema, a failed channel, a rule named in `required_rules` that was not evaluated, a `--baseline-accept` of an unevaluated audit, a store that could not take the run; no run is recorded |
| `3` | `run` and `collect` only: the report was printed (and recorded with `--store`), but at least one mandatory rule was not evaluated - `evaluation_complete` is `false`, see [Rule status](#rule-status) |

**`run` and `collect` return `0` with findings of severity high.** The code says whether the audit
ran, not whether the device is in order. A pipeline that reads a zero as "clean" reports a device
with an administrative interface open to the WAN as passing:

```
$ PYTHONPATH=src python3 -m netops_auditor run --platform fortios --tenant demo --device fw-a.example.invalid --config fw-a.conf
...
findings: 1 (high 1, medium 0, low 0, info 0)
states: new 1, open-known 0, suppressed 0, gone 0
...
$ echo $?
0
```

To gate a pipeline on findings, read the report - `--json` prints `summary` and `states` as fields -
and decide there. `status` is the one command whose code carries a verdict, and that verdict is about
freshness and evaluation: `fresh` is `0`; `stale`, `never` and `incomplete` are `1`. The one verdict
`run` and `collect` carry in their code is about evaluation, not about findings: `3` says the audit
did not read everything it is required to read, so an empty finding list is not a clean result.

## Rule status

Every report of `run` and `collect` names the state of every rule of the catalogue in `rule_status`,
next to the findings, so that "the rule found nothing" and "the rule could not read its input" are
two different answers:

```json
{
"evaluation_complete": false,
"rule_status": {
  "exos.management.port-policy": {"status": "not-evaluated", "reason": "unresolved-port-list", "required": false},
  "exos.mgmt.telnet-enabled": {"status": "evaluated", "reason": "", "required": true}
}
}
```

| `status` | meaning |
|---|---|
| `evaluated` | the rule read the input it needs; no finding of it means it found nothing |
| `not-evaluated` | the rule could not read this input; it reports no finding, and its absence of findings means nothing |
| `unsupported` | the input is in a scope the catalogue does not read (the reason names the scope gate, `fortios.scope.vdom-unsupported`); it reports no finding |

The `reason` is a short code: `snapshot-incomplete` (the `collect` completeness gate),
`fortios.scope.vdom-unsupported` (a `config vdom` or a top-level `config global` block),
`unterminated-upm-profile` (an EXOS UPM profile body without its closing `.`), `section-missing`
and `no-vlan-content` (a management rule whose tables are not in the snapshot), `unresolved-port-list`
and `unsupported-membership-form` (EXOS VLAN membership the model cannot expand),
`policy-not-configured` (a management rule whose operator-policy field is absent) and
`value-not-numeric` (a FortiOS `admintimeout` or `admin-lockout-threshold` under
`config system global` that is not written in the ASCII digits `0`-`9`, such as `thirty`, `-1`, `1.5`
or `²`; the rule cannot compare it with its limit, so `fortios.mgmt.idle-timeout` or
`fortios.mgmt.lockout-threshold` is `not-evaluated` and the run exits with `3`; an absent value is the
device default and stays `evaluated`).

`required` says whether the rule is mandatory. Every rule of the original catalogues is; a
management rule is mandatory only when the operator policy names it in `required_rules` - otherwise
it is advisory, and its `not-evaluated` state is reported without failing the run.
`evaluation_complete` is `false` as soon as one mandatory rule is not `evaluated`; the report then
also carries the older marker `evaluation: "not-evaluated"`, and the run exits with `3`. A mandatory
management rule that cannot be evaluated refuses the run before the catalogue (`2`), as before.

The earlier findings of a rule that is not evaluated in the latest run are listed in `not_evaluated`,
never in `gone`, and a suppression of such a rule is not reported as orphaned. This holds for an
advisory rule as well, whose `not-evaluated` state leaves the run complete: its findings are carried
from the last complete run that evaluated the rule across the complete runs that did not, so they stay
in `not_evaluated` for as many such runs as follow, and an absent one becomes `gone` in the first later
run that evaluates the rule again. The same states are
recorded in the store (table `rule_status`, written with each run; runs recorded before 0.2.9 carry
none and are judged by their marker findings alone), and they reach the SARIF run as the device
properties `rule_status` and `evaluation_complete`, and the read-only MCP surface as `rule_status` of
each device in `audit_status` and `not_evaluated_rules` of `compare`. `compare` leaves out of
`added`, `removed` and `kept` the findings of rules that one of the two runs did not evaluate.
`rule_coverage` stays as it was (`evaluated`, `not-evaluated`, `not-configured` per management rule).

## Two refusals that end the audit

Both are deliberate, and both are easy to miss, because the report looks in each case like a finished
audit that found exactly one thing.

### An incomplete snapshot replaces the audit

`collect` measures the snapshot against `required_sections` of the entry before it evaluates
anything. If one section is missing, the run emits a single finding, `<platform>.snapshot.incomplete`
of class `fakt` and severity high, **and the rule catalogue is not evaluated at all** - not one rule
of it. `findings: 1` in that report is not the statement "this device has one problem":

```
[high] fortios.snapshot.incomplete (fakt)
  object: snapshot/fw-a.example.invalid
  section: snapshot
  line: 0
  fingerprint: 3335636531940adb768f40b7834fdb2cdcdb3e94ae8e138cbd2568a3c421da4e
  evidence: missing_count=1 missing_sections="system global"
```

The trade is on purpose: an audit of a dump that is missing a section is an audit of a device that
does not exist. The evidence carries the names and the count, never a line of configuration. How a
section is recognized per platform, and why this is a presence check in which an empty section counts
as present, is in [`channels.md`](channels.md).

A FortiOS dump that stops inside a block or inside a quoted value - a `config` or `edit` without its
`end` or `next`, a quote that is never closed, a last line cut off in the middle of its statement
such as a bare `set` - was cut off on the way, and `collect` reports it the
same way: one `<platform>.snapshot.incomplete` finding, the catalogue not evaluated, exit code `3`.
Its evidence adds `unterminated_line`, the number of the line where the open block or quote starts
(`missing_count` is then `0` unless a section is missing as well); it still carries no configuration
text. Before 0.2.9 such a dump ended the run with `error: policy cannot be evaluated (ParseError)`.
Once the gate has fired the catalogue is not evaluated, so a statement the parser cannot read does
not refuse the run; a dump that holds every required section and still cannot be parsed ends with
`cannot parse configuration` (`2`).
A mandatory management rule of the operator policy still refuses the run (`2`), because a cut-off dump
evaluates none of them. `run` reads a file it was handed and has no completeness gate; it refuses a
cut-off file and names the file and the line:

```
error: cannot parse configuration fw-a.conf: unterminated block opened at line 62
```

A section written the way the dump opens it is refused rather than reported as missing, and that
refusal lands **after** the snapshot has been taken, not when the inventory is loaded - so a typo in
`required_sections` fails on the run against the device, not on the file. The message and the rule
are in [`inventory.md`](inventory.md).

### A device with VDOMs takes the whole run

One rule of the FortiOS catalogue, `fortios.scope.vdom-unsupported`, is marked `scope_gate`. When it
fires, its finding is the **only** finding the run returns and every other rule is skipped. Its own
title says why: the configuration is organized into VDOMs, a scope this catalogue does not read, so
no other rule was evaluated over it. It fires on any dump that carries a `vdom` section, a
single-VDOM one included, and on a dump wrapped in a top-level `config global` block without a
`vdom` block (object `global`, `vdoms=0`): the settings inside such a wrapper are not read, so the
run is not evaluated rather than clean. Every other rule then has the state `unsupported`.

The same dump with and without that section shows the whole effect. `fw-c.conf` is `fw-a.conf` with
a `config vdom` block in front of it. The ordinary finding is absent from this evaluation; that
is not evidence that the underlying problem was resolved:

```
$ PYTHONPATH=src python3 -m netops_auditor run --platform fortios --tenant demo --device fw-c.example.invalid --config fw-c.conf
...
findings: 1 (high 1, medium 0, low 0, info 0)
states: new 1, open-known 0, suppressed 0, gone 0
suppressions: orphaned 0, expired 0

state new: 1

[high] fortios.scope.vdom-unsupported (fakt)
  object: vdom
  section: vdom
  line: 1
  evidence: vdoms=1
...
```

Until the catalogue learns to descend into VDOM scopes, the remedy the rule names is to export and
audit each VDOM separately.

### History across an unevaluated audit

An incomplete snapshot or `fortios.scope.vdom-unsupported` means the ordinary catalogue was not
evaluated. Such a report includes `evaluation: "not-evaluated"` and never reports earlier findings
as `gone`. The `not_evaluated` list carries identities from the last evaluated audit, even across
several incomplete runs. An absent finding becomes `gone` only after a subsequent complete audit.
Absence during an incomplete audit also does not mark a suppression as orphaned.

CLI and MCP status report `incomplete` for the latest such run. MCP `list_findings` and
`finding_detail` expose the carried findings with state `not-evaluated`; these are historical evidence,
not findings observed in the latest snapshot. Every finding the two tools return carries
`rule_status`, the `status` and `reason` of its rule in the latest run - `not-evaluated` and
`snapshot-incomplete` for a finding carried across an incomplete snapshot; for a run recorded before
0.2.9 the state is derived from its marker finding. Baseline acceptance refuses an unevaluated run without
changing the existing baseline; with `run` or `collect --baseline-accept` the run itself is not
recorded either (exit code `2`). MCP comparison refuses either unevaluated endpoint. This also
applies to existing stored runs identified by their incomplete-snapshot or unsupported-scope finding;
no database migration is needed.

`run` and `collect` exit with `3` when they record such a run (before 0.2.9 they exited with `0`).
The report is printed and recorded in full; the code only says that it is not a completed
evaluation of the catalogue.

## What is not a configuration file

The store behind `--store` is a SQLite database the auditor writes and nobody edits by hand. A file
that is not such a database is refused with `error: store: ...` (exit code `2`). The rule
catalogue is data but not configuration: it ships inside the package, it is not read from a path you
choose, and a rule without a positive and a negative fixture does not enter it - the gate rejects it.


### EXOS SNMP identity version 2

The `exos.snmp.default-community` rule now uses a digest of the tokenized community object identity instead of its position in the configuration. Unrelated insertion and reordering preserve its fingerprint. Review a fresh report and recreate affected baseline entries and suppressions after upgrading: version 1 ordinal keys cannot be safely mapped without the original configuration and are not automatically reassigned to new objects.

JSON suppression migration creates its output with owner-only permissions (0600); it never widens the temporary file permissions or replaces an existing destination.

Human-readable finding headers use `fact` and `judgement`. The catalogue, stored data, JSON and MCP `class` values remain `fakt` and `usudek` for compatibility.
