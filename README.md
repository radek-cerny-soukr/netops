# netops

Tools that give an AI agent the narrowest possible hands and usable eyes on network devices. Each component is released on its own, from this one repository, under its own tag and its own maturity.

| Component | What it does | Released |
|---|---|---|
| [`netops-helper`](components/netops-helper/) | Read-only MCP server for bounded network troubleshooting | [`netops-helper/v0.3.2`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-helper%2Fv0.3.2) (2026-09-20) |
| [`netops-auditor`](components/netops-auditor/) | Configuration audit; collects the configuration from the device itself | [`netops-auditor/v0.2.2`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-auditor%2Fv0.2.2) (2026-09-20) |
| [`netops-core`](components/netops-core/) | Shared access layer the other components build on: inventory, credential store, host key trust, SSH transport, audit records | [`netops-core/v0.2.1`](https://github.com/radek-cerny-soukr/netops/releases/tag/netops-core%2Fv0.2.1) (2026-09-20) |

`netops-admin` (device writes, refuses to start without the auditor) is designed but not built. It will appear under `components/` when it carries code; an empty directory guarantees nothing.

## Releases

Every component has its own version, its own tag prefix `netops-<component>/vX.Y.Z`, and its own release page with its own assets.

**This repository advertises exactly one version per component: one release page and one tag.** When a component is released, the release page and the tag of its previous version are deleted, so at any moment there are exactly three release pages and three tags here - one per component - and they are the ones listed in the table above.

Source history remains reachable on `main` by commit. Superseded release pages, tags, tag signatures and downloadable assets are no longer available from GitHub. Checking out an old commit recovers its source, not its original image, SBOM, scan or artifact signature; preserve verified artifacts locally if rollback or historical verification is required. Changelog entries describe source history, not additional available releases.

A component release archive is self-contained: it carries the component tree, its own `LICENSE`, and its own changelog. Self-contained does not mean identical in shape: the `netops-helper` archive additionally vendors `src/netops_core`, the `netops-auditor` archive pins `netops-core==0.2.1` and needs the core archive installed beside it, and `netops-core` is a library archive with no image of its own. Repository-level files (this page, `SECURITY.md`, `CONTRIBUTING.md`, CI) live here and are not part of a component archive.

## Repository gate

`scripts/check_release.py` is the gate for the tree as a whole. It fails closed when a tracked file belongs to no component release and to no reviewed repository file, when a component has no release selector or no gate of its own, when a component `LICENSE` differs from the repository one, when CI does not cover a component, or when any tracked file carries a private address, host name, path, or credential-shaped string. Each component then runs its own gate over its own tree: `components/netops-helper/scripts/check_public_release.py`, `components/netops-auditor/scripts/check_gates.py`, and `components/netops-core/scripts/check_gates.py`.

```sh
python3 scripts/check_release.py                                    # whole repository
python3 tests/test_release_gate.py                                  # tests of this gate
```

## Security

Read [SECURITY.md](SECURITY.md) before deploying anything from here, and the security model of the component you are deploying. Report a vulnerability privately through GitHub Security Advisories; never include live credentials, addresses, configurations, or command output.

See [Verified platform support](docs/verified-support.md) for which platform, firmware, and account privilege each component has actually been measured against, versus catalogue-only.

MIT licensed.
