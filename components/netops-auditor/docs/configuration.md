# Configuration

Three files decide what the auditor does: the inventory, the credential store and the suppression
file. All three are read fail-closed - a missing field, an unknown field or a wrong value stops the
run instead of falling back to a default - and none of them is ever written by the tool. The inventory
and the credential store are the shared documents of `netops-core` since 0.2.0, both at file version
`2`; this page says what the auditor adds to the credential store, holds the schema of the suppression
file, and lists the exit codes and the two refusals that end a run before the rule catalogue is
reached. The inventory has a page of its own: [`inventory.md`](inventory.md).

## The credential store (`vault.json`)

The inventory names a credential, the store holds its value. Since 0.2.0 the store is **the shared
document of `netops-core`, file version 2**, and its schema is
[`../netops-core/docs/vault.md`](../netops-core/docs/vault.md). What follows is what the auditor adds
to it.

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
| `version` | `2`; a version `1` store - the shape the auditor read until 0.1.0 - is refused with `vault file <path>: version must be 2` |
| `credentials` | an object; the key is the record name an inventory entry refers to in `credential` |
| `credentials.<name>.kind` | one of `password`, `ssh-key`, `api-token`, `snmp-community` |
| `credentials.<name>.login` | the account name, **required** for `password` and `ssh-key`, **forbidden** for the other two |
| `credentials.<name>.value` | the secret itself; for `ssh-key` the whole private key text, header line and all, newlines written as `\n` - the example above is a placeholder, and the real shape is in [`../netops-core/docs/vault.md`](../netops-core/docs/vault.md) |

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

A suppression silences one finding on one device until a date. The file is JSON, `version` and
`suppressions`, and every item carries all nine fields:

```json
{
  "version": 1,
  "suppressions": [
    {
      "fingerprint": "33ada9e38cd292f102d92833ae24ae3366f45eb5462f307b9edd31f6993034a1",
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
is the sha256 over four values joined by the unit separator `\x1f`: `rule_id`, `rule_version`,
`device`, `object_key`. Raise the rule version, move the finding to another interface or meet the
same rule on another device, and the suppression stops applying - by construction, not by policy.

Nobody computes it by hand: every report prints the fingerprint of each finding, so the way to write
a suppression is to run the audit and copy it out. The file is checked against its own components
when it is loaded, so a copied fingerprint next to an edited `object_key` is refused instead of
quietly binding to nothing:

```
error: suppressions: suppression 0: fingerprint '0000000000000000000000000000000000000000000000000000000000000000' does not match components, expected 33ada9e38cd292f102d92833ae24ae3366f45eb5462f307b9edd31f6993034a1
```

Two items with the same fingerprint are an error as well.

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
document is in [`../netops-core/docs/inventory.md`](../netops-core/docs/inventory.md).

## The platform picks the parser and the catalogue

`--platform` of `run`, and the `platform` field of the entry for `collect`, choose two things at once:
the L1 parser that reads the text and the rule catalogue that is evaluated over it. Since 0.2.0 there
are two of each.

| `--platform` | what the parser reads | catalogue | rules |
|---|---|---|---|
| `fortios` | the tree of `config` / `edit` / `set` / `next` / `end` | `catalog/fortios.json` | 6 |
| `exos` | the flat list of commands of `show configuration`, one record per command with its line, its module and its tokens | `catalog/exos.json` | 4 |

There is no detection: a dump handed to the wrong platform is parsed by the wrong parser, and what
comes back is findings about commands that are not there rather than an error. The platform of a
device belongs in the inventory, where `collect` reads it, and `run` is the command that asks for it
on the command line.

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
  fingerprint: a50261f4e3c8fd2aeae097d274d8378257a280e9c8fc6b1f88e31338e5450249
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
