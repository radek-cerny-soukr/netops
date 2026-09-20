# netops-core

The shared access layer of the `netops` family. It holds the parts every component needs to reach a
device: the inventory of devices, the credential store, host key trust, the SSH transport, and the
audit record. It evaluates nothing, decides nothing, and exposes no server; the components above it
bring the policy.

The current release is `netops-core/v0.2.0` (2026-09-20); `netops-auditor` 0.2.1 and `netops-helper` 0.3.1 pin
exactly that version. The component is standard library only, requires Python 3.13 or newer,
and declares no dependency: `pyproject.toml` carries an empty `dependencies` list and the gate
`core_stdlib` refuses any import outside the standard library anywhere under `src/`.

## Modules

| Module | What it holds |
|---|---|
| `platforms.py` | the canonical platform names, their aliases, and `normalize()` |
| `legacy_ssh.py` | the named exceptions for old SSH algorithms and the OpenSSH options each one expands into |
| `hostkey.py` | host key pins, fingerprints, `ssh-keyscan` invocation, and the `known_hosts` file of a single run |
| `vault.py` | the credential document (file version 2), its four kinds, and a credential whose value never reaches a representation |
| `inventory.py` | the device document (file version 2), the common device fields, and the per-consumer sections |
| `ssh.py` | the OpenSSH subprocess transport with key and password authentication |
| `sftp.py` | the OpenSSH `sftp` client: metadata of one remote path, same hardening and same workspace |
| `session.py` | the interactive terminal session on the same client, for devices without an exec channel |
| `prompt.py` | the device prompt removed from a one-shot answer, one rule for every component |
| `audit.py` | the append-only audit record with rotation and a closed field set |

Each module is documented on its own: [`docs/inventory.md`](docs/inventory.md),
[`docs/vault.md`](docs/vault.md), [`docs/ssh.md`](docs/ssh.md), [`docs/sftp.md`](docs/sftp.md),
[`docs/session.md`](docs/session.md), [`docs/prompt.md`](docs/prompt.md),
[`docs/audit.md`](docs/audit.md).
Every refusal is part of the contract and is named in those pages.

## How the other components use it

`netops-core` is a library in this repository, not a package on an index. A component that needs it
takes it from the tree at build time: the consuming component installs the directory
`components/netops-core` into its own environment or image, or puts
`components/netops-core/src` on `PYTHONPATH`. There is no network fetch, no version range to resolve,
and no published wheel; the version that is built is the version that is in the tree.

**This component ships no image.** It has no `Dockerfile`, no compose file, and no MCP surface. An
image belongs to the component that runs, not to the library it links. Because there is no image,
there is no isolating container of its own either: `ssh.py`, `sftp.py`, `session.py` and
`hostkey.py` run the OpenSSH client already installed on the host, and inherit that client's own
vulnerabilities. Keeping that client current is the operator's responsibility, not this library's.

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

The release process is in [`docs/releasing.md`](docs/releasing.md).

MIT licensed. Part of the [`netops`](../../README.md) family.
