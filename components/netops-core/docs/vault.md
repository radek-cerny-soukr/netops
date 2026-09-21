# Credential store

The vault is one JSON document holding the credentials the family uses to reach a device. It is read
by `netops_core.vault` and is fail-closed: a document that does not match this page is refused as a
whole, and no credential from it is used.

`FILE_VERSION = 2`. A document whose `version` is missing or different is refused, naming what was
found and what is expected.

## The file itself

Before the document is parsed, the path is checked with `lstat`:

| Check | Refusal |
|---|---|
| the path is a symbolic link | refused, saying the vault path is a symbolic link; the check happens before the mode is read, so a link to a world-readable file is never opened |
| the file mode | must be `0600` or `0400`; any other mode is refused, naming the mode that was found and the two that are accepted |

## Document

| Field | Type | Rule |
|---|---|---|
| `version` | integer | must be `2` |
| `credentials` | object | keys are record names; an empty object is allowed |

## Entry

| Field | Type | Rule |
|---|---|---|
| `kind` | string | one of `KINDS = ("password", "ssh-key", "api-token", "snmp-community")` |
| `login` | string | **required** for `LOGIN_KINDS = ("password", "ssh-key")` and **forbidden** for `api-token` and `snmp-community`. Both cases are refusals naming the credential and its kind |
| `value` | string | non-empty. For `ssh-key` it must begin with the private key header line, so a public key or a path pasted by mistake is refused |

An unknown field in an entry is refused, naming the credential and the field.

`login` is a plain user name: no leading `-`, and no `@`, `:`, `/` or whitespace anywhere. A name that
breaks the rule is refused naming the credential and the character class that is not allowed. The rule
exists because the login becomes an argument of the SSH client, and a name starting with `-` would be
read as an option.

## Credential

`load(path)` returns the credentials as frozen `Credential` records: `name`, `kind`, `login`
(`str | None`), and the value behind a `_Secret` wrapper. The `repr` of a credential prints the name,
the kind, and the login - never the value - and the `repr` of the wrapper prints a fixed placeholder,
so a credential that reaches a traceback, a log line, or a debugger prompt carries no secret.

## Example document

```json
{
  "version": 2,
  "credentials": {
    "fw-a-ro":  {"kind": "password",       "login": "audit-ro", "value": "replace-me"},
    "sw-a-ro":  {"kind": "ssh-key",        "login": "audit-ro", "value": "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n-----END OPENSSH PRIVATE KEY-----\n"},
    "fw-a-api": {"kind": "api-token",      "value": "replace-me"},
    "fw-a-snmp":{"kind": "snmp-community", "value": "replace-me"}
  }
}
```

Every value above is the placeholder `replace-me`. The document is an example, not a template to ship:
a real vault is never committed, never copied into an image, and never read by anything but the
component that needs it.

## What is refused

| Situation | Refusal |
|---|---|
| the path is a symbolic link | named before the mode check |
| mode other than 0600 or 0400 | names the mode found and the accepted ones |
| `version` missing or not 2 | names the value found and the expected one |
| unknown `kind` | names the credential and lists the four kinds |
| `login` missing for a login kind | names the credential and the kind |
| `login` present for a non-login kind | names the credential and the kind |
| `login` with `@`, `:`, `/`, whitespace, or a leading `-` | names the credential |
| empty or non-string `value` | names the credential |
| `ssh-key` whose value is not a private key text | names the credential |
| unknown field in an entry | names the credential and the field |
| unknown record name asked for | names the name and lists the known ones |


## Selecting credentials

`load(path, names=(...))` returns handles only for the named records present in the store. Unknown names remain unavailable through `credential(name)`; they never select a fallback. Omitting `names` retains full validation and loading. The JSON document is parsed in full before filtering, so this API reduces retained handles rather than establishing a process isolation boundary.

Selection validates the selected records, not every unselected record. An empty selection yields no handles. Malformed selections (including a string instead of a collection or empty/non-string names) are refused. Requesting a missing record with `credential(name)` fails; callers must request each required handle explicitly.
