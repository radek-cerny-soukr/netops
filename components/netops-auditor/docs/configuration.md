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
[the Core 0.2.1 source commit](https://github.com/radek-cerny-soukr/netops/blob/2caf06ffd9df8d51a509d400c657c80db582ad82/components/netops-core/docs/vault.md).
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
| `credentials.<name>.value` | the secret itself; for `ssh-key` the whole private key text, header line and all, newlines written as `\n` - the example above is a placeholder, and the real shape is in [`../../netops-core/docs/vault.md`](../../netops-core/docs/vault.md) (from a standalone archive, published at [the Core 0.2.1 source commit](https://github.com/radek-cerny-soukr/netops/blob/2caf06ffd9df8d51a509d400c657c80db582ad82/components/netops-core/docs/vault.md)) |

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
error: device fw-a.example.invalid reads channel ssh under credential fw-a-audit-ro of kind
api-token, channel ssh takes a credential of kind password or ssh-key
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

The tenant sits inside the fingerprint since 0.2.2, and that is the whole point of file version 2:
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

Two items with the same fingerprint are an error as well.

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
never writes over an existing output; it prints a count and the path, and nothing out of the
document it read, so a reason or a device name never lands in a log because of a failed migration.
It does not run by itself: no command migrates a file on the side.

```
migrated 3 suppressions of tenant tenant-a into waivers-tenant-a.json
```

### Migrating the store

The database behind `--store` carries a schema version, and the fingerprints inside it are the same
ones. Opening a store written before 0.2.2 is a readable error rather than a silent run, on the CLI
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
[the Core 0.2.1 source commit](https://github.com/radek-cerny-soukr/netops/blob/2caf06ffd9df8d51a509d400c657c80db582ad82/components/netops-core/docs/inventory.md).

## The platform picks the parser and the catalogue

`--platform` of `run`, and the `platform` field of the entry for `collect`, choose two things at once:
the L1 parser that reads the text and the rule catalogue that is evaluated over it. There are two of each.

| `--platform` | what the parser reads | catalogue | rules |
|---|---|---|---|
| `fortios` | the tree of `config` / `edit` / `set` / `next` / `end` | `catalog/fortios.json` | 6 |
| `exos` | the flat list of commands of `show configuration`, one record per command with its line, its module and its tokens | `catalog/exos.json` | 4 |

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

## Exit codes

| code | when |
|---|---|
| `0` | `run` and `collect` finished; `status` found the last audit fresh |
| `1` | `status` only: the last audit is older than `--stale-after-hours` (26 by default), or there is none |
| `2` | the run was refused - a bad argument, an unreadable file, a fail-closed schema, a failed channel |

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
freshness only: `fresh` is `0`, `stale` and `never` are both `1`.

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

A section written the way the dump opens it is refused rather than reported as missing, and that
refusal lands **after** the snapshot has been taken, not when the inventory is loaded - so a typo in
`required_sections` fails on the run against the device, not on the file. The message and the rule
are in [`inventory.md`](inventory.md).

### A device with VDOMs takes the whole run

One rule of the FortiOS catalogue, `fortios.scope.vdom-unsupported`, is marked `scope_gate`. When it
fires, its finding is the **only** finding the run returns and every other rule is skipped. Its own
title says why: the configuration is organized into VDOMs, a scope this catalogue does not read, so
no other rule was evaluated over it. It fires on any dump that carries a `vdom` section, a
single-VDOM one included.

The same dump with and without that section shows the whole effect. `fw-c.conf` is `fw-a.conf` with
a `config vdom` block in front of it, and the finding that `fw-a.conf` produced is gone:

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

## What is not a configuration file

The store behind `--store` is a SQLite database the auditor writes and nobody edits by hand. The rule
catalogue is data but not configuration: it ships inside the package, it is not read from a path you
choose, and a rule without a positive and a negative fixture does not enter it - the gate rejects it.
