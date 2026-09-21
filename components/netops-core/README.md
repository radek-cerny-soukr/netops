# netops-core

The current release is `netops-core/v0.2.3` (2026-09-21); `netops-auditor` 0.2.4 and `netops-helper` 0.3.4/0.3.5 pin exactly that version.

The shared access layer of the `netops` family. It holds every piece a component needs to reach a
device and to record what happened: the inventory of devices, the credential store, host key trust,
the SSH exec transport, the interactive terminal transport, SFTP metadata, prompt cleaning, and the
audit record. Every module here is either a fail-closed document reader, a transport that runs exactly
one command or one call and returns exactly what came back, or a writer of one audit line; none of them
retries, falls back to a weaker setting, or judges whether a result is good enough to act on. It
decides nothing, evaluates nothing, and exposes no server or network listener of its own.

It is deliberately **not** a device driver: the platform names it knows are a closed list used for
prompt cleaning and inventory validation, not a per-vendor command set, and no module here reads or
parses a device's configuration. It is **not** a policy engine: it does not decide whether a read is
safe, whether an account is genuinely read-only, or whether a finding is a violation - those decisions,
and the command or query catalogues that embody them, belong to the two components built on it. And it
is **not** a self-contained deployable: no image, no compose file, no MCP surface of its own; a caller
takes the directory from the tree at build time.

Four properties are enforced by the release gate itself, not just
asserted here: standard library only, so no import outside it may appear anywhere under `src/` (gate
`core_stdlib`); no declared dependency, `pyproject.toml` carries an empty `dependencies` list; Python
3.13 or newer (`requires-python = ">=3.13"`); and no container image of its own, because it is a
library that a runtime takes from the tree, not a runtime itself - see "How the other components use
it" below for what that means in practice.

## Modules

| Module | What it holds |
|---|---|
| `platforms.py` | the canonical platform names, their aliases, and `normalize()` |
| `legacy_ssh.py` | the named exceptions for old SSH algorithms and the OpenSSH options each one expands into |
| `hostkey.py` | host key pins, fingerprints, `ssh-keyscan` invocation, and the `known_hosts` file of a single run |
| `vault.py` | the credential document (file version 2), its four kinds, and a credential whose value never reaches a representation |
| `inventory.py` | the device document (file version 2), the common device fields, and the per-consumer sections |
| `ssh.py` | the OpenSSH subprocess transport with key and password authentication |
| `askpass.py` | the standalone askpass program a deployment names in `NETOPS_ASKPASS_PROGRAM` when its workspace cannot execute a freshly written script; installing the distribution puts it on the path as the command `netops-askpass` |
| `sftp.py` | the OpenSSH `sftp` client: metadata of one remote path, same hardening and same workspace |
| `session.py` | the interactive terminal session on the same client, for devices without an exec channel |
| `prompt.py` | the device prompt removed from a one-shot answer, one rule for every component |
| `audit.py` | the append-only audit record with rotation and a closed field set |

Seven of these have their own page - [`docs/inventory.md`](docs/inventory.md),
[`docs/vault.md`](docs/vault.md), [`docs/ssh.md`](docs/ssh.md), [`docs/sftp.md`](docs/sftp.md),
[`docs/session.md`](docs/session.md), [`docs/prompt.md`](docs/prompt.md),
[`docs/audit.md`](docs/audit.md) - and every refusal is part of the contract and is named on those
pages. `platforms.py`, `legacy_ssh.py`, `hostkey.py` and `askpass.py` are small enough that their
contract is folded into the page that uses them instead: platform names and their aliases in
[`docs/prompt.md`](docs/prompt.md) and [`docs/inventory.md`](docs/inventory.md), the legacy-algorithm
exception in [`docs/inventory.md`](docs/inventory.md#legacy-ssh-is-an-exception-per-device), and host
key trust and the askpass program in [`docs/ssh.md`](docs/ssh.md).

## Guarantees and limits

- **Inventory and the credential store are fail-closed.** A document that breaks any rule in
  [`docs/inventory.md`](docs/inventory.md) or [`docs/vault.md`](docs/vault.md) is refused as a whole;
  there is no partial load where a single bad device or credential is dropped and the rest used
  instead. The vault also refuses a path that is a symbolic link or has a mode other than 0600/0400,
  checked before the document is parsed at all, and a `Credential`'s value is wrapped so it never
  reaches a `repr`, a log line, or a traceback.
- **Host key trust has no first-contact trust.** A live scan is matched against the pin already
  recorded in the inventory; a device that offers no key matching that pin is refused, naming only how
  many keys were offered, never the keys themselves. There is no `known_hosts` file kept on the host -
  one is written fresh, inside the workspace of that one call, every time.
- **Every transport bounds what it will read from a device**, including the host key scan itself:
  `ssh.py`, `sftp.py`, `session.py` and the scan in `hostkey.py` all stop and refuse once a peer sends
  more than that call's own budget, so a device - or anything sitting in front of it - cannot exhaust
  memory or hold a call open by flooding it. See [bounded receive](docs/ssh.md#bounded-receive).
- **A failure names a classified reason, not the peer's own words.** Standard error is written by the
  far side of the connection and can carry attacker-controlled text, including a secret; the message of
  an `SshError` or `SftpError` names one reason from a closed list instead, and the raw text is kept
  separately, on the exception, for a caller with a safe place to put it - an audit record, an
  operator's own log - never for a message that reaches an agent or a report. See
  [the message of a failure names a reason, not the device's words](docs/ssh.md#the-message-of-a-failure-names-a-reason-not-the-devices-words).
- **The audit lock is advisory.** `audit.py` takes a cross-process `flock` on a stable lock file beside
  the log for every write, so writers in different processes cannot interleave a line or race a
  rotation - but the lock only binds callers that go through this module; it does nothing against a
  process that writes to the log file some other way. See [persistence](docs/audit.md#persistence).
- **Prompt cleaning only ever touches the edges.** It matches a marker on the first line and removes
  trailing lines identical to it; a `#` or `$` in the middle of a device's answer - inside a value, a
  comment, or a password prompt caught in a transcript - is never touched, by construction. See
  [the rule](docs/prompt.md#the-rule).

## How the other components use it

`netops-core` is a library in this repository, not a package on an index. A component that needs it
takes it from the tree at build time: the consuming component installs the directory
`components/netops-core` into its own environment or image, or puts
`components/netops-core/src` on `PYTHONPATH`. There is no network fetch, no version range to resolve,
and no published wheel; the version that is built is the version that is in the tree.

The auditor takes the inventory, the credential store, host key trust and the SSH transport, and reads
a device's answer through the same [prompt cleaning](docs/prompt.md) rule before it hashes the cleaned
text into a snapshot. The helper takes the same modules plus the interactive session transport, for the
one platform in its catalogue with no exec channel, and the SFTP metadata call for its read-only
`sftp_stat` tool; its container image installs `askpass.py` on an executable path outside the `noexec`
temporary directories it mounts, and names that path in `NETOPS_ASKPASS_PROGRAM` so password
authentication still works there. Both write through `audit.py`, each under its own name from the
closed list `COMPONENTS` - `"auditor"` or `"helper"`; `"admin"` is the third name, reserved for the
write-capable component that is designed but not yet built.

**This component ships no image.** It has no `Dockerfile`, no compose file, and no MCP surface. An
image belongs to the component that runs, not to the library it links. Because there is no image,
there is no isolating container of its own either: `ssh.py`, `sftp.py`, `session.py` and `hostkey.py`
run the OpenSSH client already installed on the host, and inherit that client's own vulnerabilities.
Keeping that client current is the operator's responsibility, not this library's.

## Verifying it

```sh
python3 -m pytest -q                         # the test suite
python3 scripts/check_gates.py               # the gate of a release
python3 scripts/generate_sbom.py             # regenerates the committed SBOM
python3 scripts/create_release_artifacts.py --output path/to/new-output
```

The gate runs three checks: `core_stdlib` (no third-party import under `src/`), `version_metadata`
(the version in `pyproject.toml`, in `src/netops_core/__init__.py`, and in the root of
`sbom.cdx.json` agree), and `release_content` (every released file is read and held against an
allowlist of addresses, names, paths, and credential shapes). Outside a repository - which is what an
exported archive is - `release_content` also holds the file set itself against the release selection
and `release-manifest.json`, so neither an added nor a removed file survives the gate.

The release process - including how this repository publishes its release pages, one per component,
and what that means for an older version - is in [`docs/releasing.md`](docs/releasing.md).

MIT licensed. Part of the [`netops`](../../README.md) family.
