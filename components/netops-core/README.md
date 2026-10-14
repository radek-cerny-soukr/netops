# netops-core

This source tree contains netops-core/v0.2.9.

Published release context (14 October 2026): the published release is `netops-core/v0.2.9` (2026-10-14); `netops-auditor` 0.2.12, `netops-admin` 0.2.8 and `netops-helper` 0.3.11, released with it, pin exactly that version. Earlier releases keep their pins: `netops-auditor` 0.2.11, `netops-admin` 0.2.7 and `netops-helper` 0.3.10 pin `netops-core/v0.2.8` (2026-10-11); `netops-auditor` 0.2.10, `netops-admin` 0.2.6 and `netops-helper` 0.3.9 pin `netops-core/v0.2.7` (2026-10-06); `netops-auditor` 0.2.9, `netops-admin` 0.2.5 and `netops-helper` 0.3.8 pin 0.2.6; `netops-auditor` 0.2.8, `netops-admin` 0.2.3 and 0.2.4 and `netops-helper` 0.3.7 pin `netops-core/v0.2.5` (2026-09-26); `netops-auditor` 0.2.7 and `netops-admin` 0.2.2 pin 0.2.4, and earlier releases pin 0.2.3 or 0.2.2. `netops-core` 0.2.9 has a separate PyPI publication step after GitHub; check exact-version index availability before choosing that installation channel: on 14 October 2026 PyPI carries `netops-core` 0.2.9. The [installation guide](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/installation.md) installs it on its own from the verified release archive. This version reads the inventory and the vault with a size bound and refuses a key repeated within one JSON object, makes the pinned host key the only one OpenSSH trusts, never opens the audit log through a link and keeps a value that may be a misplaced secret out of its errors; see the [changelog](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/CHANGELOG.md).

The shared access and configuration primitives of the `netops` family: bounded inventory and credential readers, exclusive SSH host-key trust, SSH exec and terminal transports, SFTP metadata, prompt cleaning and audit records. Since version 0.2.6, Core also provides the shared FortiOS configuration parser and measured schema library runtime. Consumers decide authorization, audit policy and whether a result allows a change. Core exposes no server or network listener.

The FortiOS parser reads saved configuration text into a bounded tree. Schema traversal preserves VDOMs and nested parent keys, validates measured types and values, and represents unmeasured scope and availability explicitly. A library requires an exact hardware model, OS version and build; it does not establish device permissions or semantic correctness. Command catalogues, write calibration and rollback policy belong to the consuming components. Operators supply and pin their own measured libraries; this release does not include a universal FortiOS schema database. Core is installed as a library and ships no image, compose service or MCP surface.

Four properties are enforced by the release gate itself, not just
asserted here: standard library only, so no import outside it may appear anywhere under `src/` (gate
`core_stdlib`); no declared dependency, `pyproject.toml` carries an empty `dependencies` list; Python
3.13 or newer (`requires-python = ">=3.13"`); and no container image of its own, because it is a
library that a runtime takes from the tree, not a runtime itself - see "How the other components use
it" below for what that means in practice.

## Fixes in 0.2.9

- Audit writes roll back failed or zero-progress appends, so later records keep their line boundaries; interrupted rotation retains available history.
- PTY writes that make no progress fail through the existing session error path instead of retrying indefinitely.
- Prompt cleaning splits only on LF and preserves carriage returns and other separators inside the answer; the one-shot prompt boundary remains explicit.
- SSH, inventory, credential-store and remote-path inputs reject additional malformed or unsafe values. Audit diagnostics retain their documented metadata allowlist.

See the [changelog](CHANGELOG.md) for the complete change list and the [prompt contract](docs/prompt.md) for input limits.

## Fixes in 0.2.8

The workspace that holds the password or private key of a call killed by `SIGKILL` or an unhandled `SIGTERM` no longer stays behind: each `run_command`, SFTP `stat()` and `Session` holds a lock on an owner file of its workspace, and the next such call of the same user removes the workspaces whose owner is gone, never the workspace of a running call. This answers point 8 of [issue #4](https://github.com/radek-cerny-soukr/netops/issues/4); see the [changelog](CHANGELOG.md), [the workspace](docs/ssh.md#the-workspace) and the [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#issue-4).

## Installation fixes in 0.2.7

Installation uses a local umask 022 for pip-generated programs, and acceptance can require a real installed askpass rather than skip it. See the [changelog](CHANGELOG.md) and installation/release instructions for the exact procedure.

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
| `inputs.py` | bounded regular-file reads without blocking on pipes or devices |
| `fortios.py` | shared configuration lexer and tree parser, escaped/empty values, VDOM and nested context |
| `schema.py` | format-1 measured libraries, digest and exact model/build binding, instance traversal and measured value validation |

Seven of these have their own page - [`docs/inventory.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/inventory.md),
[`docs/vault.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/vault.md), [`docs/ssh.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/ssh.md), [`docs/sftp.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/sftp.md),
[`docs/session.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/session.md), [`docs/prompt.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/prompt.md),
[`docs/audit.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/audit.md) - and every refusal is part of the contract and is named on those
pages. `platforms.py`, `legacy_ssh.py`, `hostkey.py` and `askpass.py` are small enough that their
contract is folded into the page that uses them instead: platform names and their aliases in
[`docs/prompt.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/prompt.md) and [`docs/inventory.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/inventory.md), the legacy-algorithm
exception in [`docs/inventory.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/inventory.md#legacy-ssh-is-an-exception-per-device), and host
key trust and the askpass program in [`docs/ssh.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/ssh.md).

## New in 0.2.6

Measured FortiOS schemas and the shared parser are described in [Schema and configuration primitives](docs/schema.md). Transport and document hardening cover exclusive host-key pins, bounded input, duplicate JSON keys, link-safe audit persistence and classified errors. The family-wide [issue resolution table](https://github.com/radek-cerny-soukr/netops/blob/main/docs/README.md#github-issue-resolution) maps individual findings to regressions.

## Guarantees and limits

- **Inventory and the credential store are fail-closed.** A document that breaks any rule in
  [`docs/inventory.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/inventory.md) or [`docs/vault.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/vault.md) is refused as a whole;
  there is no partial load where a single bad device or credential is dropped and the rest used
  instead. The vault also refuses a path that is a symbolic link, a file of another user, a file with a
  second hard link or a mode other than 0600/0400, judged on the descriptor it is then read from and
  before the document is parsed at all, and a `Credential`'s value is wrapped so it never
  reaches a `repr`, a log line, or a traceback.
- **Host key trust has no first-contact trust.** A live scan is matched against the pin already
  recorded in the inventory; a device that offers no key matching that pin is refused, naming only how
  many keys were offered, never the keys themselves. There is no `known_hosts` file kept on the host -
  one is written fresh, inside the workspace of that one call, every time.
- **Every transport bounds what it will read from a device**, including the host key scan itself:
  `ssh.py`, `sftp.py`, `session.py` and the scan in `hostkey.py` all stop and refuse once a peer sends
  more than that call's own budget, so a device - or anything sitting in front of it - cannot exhaust
  memory or hold a call open by flooding it. See [bounded receive](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/ssh.md#bounded-receive).
- **A failure names a classified reason, not the peer's own words.** Standard error is written by the
  far side of the connection and can carry attacker-controlled text, including a secret; the message of
  an `SshError` or `SftpError` names one reason from a closed list instead, and the raw text is kept
  separately, on the exception, for a caller with a safe place to put it - an audit record, an
  operator's own log - never for a message that reaches an agent or a report. See
  [the message of a failure names a reason, not the device's words](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/ssh.md#the-message-of-a-failure-names-a-reason-not-the-devices-words).
- **The audit lock is advisory.** `audit.py` takes a cross-process `flock` on a stable lock file beside
  the log for every write, so writers in different processes cannot interleave a line or race a
  rotation - but the lock only binds callers that go through this module; it does nothing against a
  process that writes to the log file some other way. See [persistence](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/audit.md#persistence).
- **Prompt cleaning only ever touches the edges.** It matches a marker on the first line and removes
  trailing lines identical to it; a `#` or `$` in the middle of a device's answer - inside a value, a
  comment, or a password prompt caught in a transcript - is never touched, by construction, and the
  answer is split on `\n` only, so a CRLF answer keeps its CRLF. See
  [the rule](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/prompt.md#the-rule).

## How the other components use it

`netops-auditor`, `netops-admin` and, from 0.3.7, `netops-helper` depend on `netops-core` by an exact
pin. From the release archives the operator installs the verified `netops-core` source archive of
that version beside the component, as the installation guide of that component describes. PyPI is a
delayed channel: on 14 October 2026 PyPI carries `netops-core` 0.2.9, the version the current
releases pin; check exact-version availability before installing from there. Inside this
repository a component takes it from the tree instead: the consuming component installs the directory
`components/netops-core` into its own environment or image, or puts `components/netops-core/src` on
`PYTHONPATH`, and the `netops-helper` image carries a copy from the tree. No consumer resolves a
version range; each pins one exact version.

The auditor takes the inventory, the credential store, host key trust and the SSH transport, and reads
a device's answer through the same [prompt cleaning](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/prompt.md) rule before it hashes the cleaned
text into a snapshot. The helper takes the same modules plus the interactive session transport, for the
one platform in its catalogue with no exec channel, and the SFTP metadata call for its read-only
`sftp_stat` tool; its container image installs `askpass.py` on an executable path outside the `noexec`
temporary directories it mounts, and names that path in `NETOPS_ASKPASS_PROGRAM` so password
authentication still works there. Both write through `audit.py`, each under its own name from the
closed list `COMPONENTS` - `"auditor"` or `"helper"`; `"admin"` is the third name on that list.
`netops-admin` takes the credential store, host key trust, the SSH exec and interactive session
transports and prompt cleaning from here, but keeps its own predicted/observed audit log and does not
write through `audit.py`.

**This component ships no image.** It has no `Dockerfile`, no compose file, and no MCP surface. An
image belongs to the component that runs, not to the library it links. Because there is no image,
there is no isolating container of its own either: `ssh.py`, `sftp.py`, `session.py` and `hostkey.py`
run the OpenSSH client already installed on the host, and inherit that client's own vulnerabilities.
Keeping that client current is the operator's responsibility, not this library's.

## Verifying it

```sh
python3 -B -m pytest -q -p no:cacheprovider  # the test suite
python3 -B scripts/check_gates.py            # the gate of a release
python3 scripts/generate_sbom.py             # regenerates the committed SBOM
python3 scripts/create_release_artifacts.py --output path/to/new-output
```

Run them with an interpreter that has the test tools of `requirements-release.lock`, such as the environment of the [installation guide](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/installation.md). `-B` and `-p no:cacheprovider` keep `__pycache__` and `.pytest_cache` out of the tree, so the first two commands also pass in an unpacked release archive; the last two belong to a repository checkout. The gate runs three checks: `core_stdlib` (no third-party import under `src/`), `version_metadata`
(the version in `pyproject.toml`, in `src/netops_core/__init__.py`, and in the root of
`sbom.cdx.json` agree), and `release_content` (every released file is read and held against an
allowlist of addresses, names, paths, and credential shapes). Outside a repository - which is what an
exported archive is - `release_content` also holds the file set itself against the release selection
and `release-manifest.json`, so neither an added nor a removed file survives the gate.

The release process - including how this repository publishes its release pages, one per component,
and what that means for an older version - is in [`docs/releasing.md`](https://github.com/radek-cerny-soukr/netops/blob/main/components/netops-core/docs/releasing.md).

MIT licensed. Part of the [`netops`](https://github.com/radek-cerny-soukr/netops/blob/main/README.md) family.

## Measured FortiOS schemas

The stdlib modules netops_core.schema and netops_core.fortios load a bounded format-1 FortiOS library and parse saved configurations. Library identity is the exact hardware model, firmware version and build; a caller can also pin the SHA-256 digest. Configuration instances preserve VDOM names and every parent table key.

Read commands are derived from measured configuration paths. Write value validation checks measured types, options, ranges and lengths; it rejects unmeasured availability or scope and types without a validator. Value validation alone does not authorize a write or provide rollback. A caller must enforce its account, policy, reference and recovery controls.

## PyPI source distributions and tests

PyPI wheels and source distributions are installation packages. The PyPI sdist is not a standalone pytest test tree: it omits the test-support `conftest.py` and the component's test guard. The Helper sdist also omits `scripts/` and `config/`. Running pytest over an unpacked sdist can therefore fail during collection or lack required test support. Run the documented suite from a repository checkout or the verified GitHub source release archive, with its pinned development dependencies and any required sibling components. The signed GitHub source archive and the PyPI sdist are different artifacts.
