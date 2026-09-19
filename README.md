# netops

Tools that give an AI agent the narrowest possible hands and usable eyes on network devices. Each component is released on its own, from this one repository, under its own tag and its own maturity.

| Component | What it does | Released |
|---|---|---|
| [`netops-helper`](components/netops-helper/) | Read-only MCP server for bounded network troubleshooting | `netops-helper/v0.2.3` |
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself | not yet |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | not yet |

`netops-admin` (device writes, refuses to start without the auditor) is designed but not built. It will appear under `components/` when it carries code; an empty directory guarantees nothing.

## Releases

Every component has its own version, its own tag prefix `netops-<component>/vX.Y.Z`, and its own release page with its own assets. The tags `v0.1.0`, `v0.2.0`, and `v0.2.1` without a prefix are netops-helper history and are never moved. A component release archive is self-contained: it carries the component tree, its own `LICENSE`, and its own changelog. Repository-level files (this page, `SECURITY.md`, `CONTRIBUTING.md`, CI) live here and are not part of a component archive.

## Repository gate

`scripts/check_release.py` is the gate for the tree as a whole. It fails closed when a tracked file belongs to no component release and to no reviewed repository file, when a component has no release selector or no gate of its own, when a component `LICENSE` differs from the repository one, when CI does not cover a component, or when any tracked file carries a private address, host name, path, or credential-shaped string. Each component then runs its own gate over its own tree: `components/netops-helper/scripts/check_public_release.py`, `components/netops-auditor/scripts/check_gates.py`, and `components/netops-core/scripts/check_gates.py`.

```sh
python3 scripts/check_release.py                                    # whole repository
python3 tests/test_release_gate.py                                  # tests of this gate
```

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

MIT licensed.
