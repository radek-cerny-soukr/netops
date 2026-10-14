# Credential store

The vault is one JSON document holding the credentials the family uses to reach a device. It is read
by `netops_core.vault` and is fail-closed: a document that does not match this page is refused as a
whole, and no credential from it is used. A key repeated within one JSON object - a second `value`
in a record, a record name written twice - is refused too, and the message names neither the key
nor a value.

`FILE_VERSION = 2`. A document whose `version` is missing or different is refused, naming what was
found and what is expected.

## The file itself

Before the document is parsed, the file is opened once, with `O_NOFOLLOW` and without blocking, and
everything is judged on that open descriptor (`fstat`), never on the path:

A symbolic link substituted at the vault path before that open is refused too.
The resulting `VaultError` is the specified refusal; the loader does not follow
the substituted link to obtain credentials.

| Check | Refusal |
|---|---|
| the path is a symbolic link | refused, saying the vault path is a symbolic link; `O_NOFOLLOW` refuses the open itself, so a link - to a world-readable file or to anything else - is never opened |
| the file type | must be a regular file; a directory, a pipe or a device is refused |
| the owner | must be the effective user of the process; a file of another user is refused, naming both user ids |
| the hard links | the file must have exactly one name; a second hard link is refused, naming the count |
| the file mode | must be `0600` or `0400`; any other mode is refused, naming the mode that was found and the two that are accepted |

The document is then read from the same descriptor, no further than `VAULT_MAX_BYTES` (1 MiB,
1048576 bytes) plus one byte; a longer file is refused as `larger than 1048576 bytes` before anything
is parsed. Because nothing is looked up by name a second time, a file that replaces the vault path
before the open is the one that is judged, and the replacement of a file after it was opened is never
read: the opened file then has no name left (0 hard links) and is refused as well.

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
| `value` | string | non-empty. For `ssh-key` it must begin with a private key header line, `-----BEGIN ` plus optional upper-case words plus `PRIVATE KEY-----` and a line break (`OPENSSH PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, ...), so a public key (`PUBLIC KEY`, `SSH2 PUBLIC KEY`, an `ssh-ed25519 ...` line), a certificate or a path pasted by mistake is refused |

An unknown field in an entry is refused, naming the credential and the field.

`login` is a plain user name: no leading `-`, and no `@`, `:`, `/` or whitespace anywhere. Whitespace
is every character Python's `str.isspace()` answers true for - space, tab, line breaks, vertical tab,
form feed, `\x1c`-`\x1f`, NEL, no-break space and the Unicode spaces and separators - not only space,
tab, CR and LF. Leading and trailing whitespace is stripped before the check. A name that
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
| not a regular file | names the path |
| owned by another user than the effective user of the process | names both user ids |
| more than one hard link | names the count |
| mode other than 0600 or 0400 | names the mode found and the accepted ones |
| `version` missing or not 2 | names the value found and the expected one |
| unknown `kind` | names the credential and lists the four kinds |
| `login` missing for a login kind | names the credential and the kind |
| `login` present for a non-login kind | names the credential and the kind |
| `login` with `@`, `:`, `/`, whitespace, or a leading `-` | names the credential |
| empty or non-string `value` | names the credential |
| `ssh-key` whose value does not begin with a private key header line | names the credential |
| unknown field in an entry | names the credential and the field |
| unknown record name asked for | names the name and lists the known ones |


## Selecting credentials

`load(path, names=(...))` returns handles only for the named records present in the store. Unknown names remain unavailable through `credential(name)`; they never select a fallback. Omitting `names` retains full validation and loading. The JSON document is parsed in full before filtering, so this API reduces retained handles rather than establishing a process isolation boundary.

Selection validates the selected records, not every unselected record. An empty selection yields no handles. Malformed selections (including a string instead of a collection or empty/non-string names) are refused. Requesting a missing record with `credential(name)` fails; callers must request each required handle explicitly.
