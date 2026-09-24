# Documentation map

This directory is mostly a signpost. Documentation lives with the component it describes, so it is released, versioned, and reviewed together with the code it documents; the one exception is a page that is about more than one component and therefore belongs to none of them.

| Component | Documentation |
|---|---|
| `netops-helper` | [`components/netops-helper/docs/`](../components/netops-helper/docs/) — security model, egress control, installation, onboarding, configuration, read-only accounts, tools, query catalogue, vendor CLI references, releasing, known vulnerabilities |
| `netops-auditor` | [`components/netops-auditor/docs/`](../components/netops-auditor/docs/) — collection channels, configuration, inventory, releasing and their documented limits |
| `netops-core` | [`components/netops-core/docs/`](../components/netops-core/docs/) — inventory and credential schemas, the SSH transport, the audit record, releasing |
| `netops-admin` | [`components/netops-admin/docs/`](../components/netops-admin/docs/) — planning rules, value limits, execution with the rollback safeguard, journal, limits, undo, MCP, audit export, installation, release process, measured scenarios and known limits |

Cross-component: [`verified-support.md`](verified-support.md) — per platform, what firmware, transport, authentication and account privilege the family has actually measured against a device, versus catalogue only.

Repository-level policy is in [`../SECURITY.md`](../SECURITY.md) and [`../CONTRIBUTING.md`](../CONTRIBUTING.md); the release shape of the family is described [below](#releases), including the rule that this repository keeps exactly one release page and one tag per component. Superseded release pages, assets and tags are removed; historical source remains accessible by commit. Use the current release links in the root README for downloads and commit permalinks for historical source. Documentation inside a published archive is fixed at the moment that archive was signed; the documentation in this tree is the current one.

## Releases

Every component has its own version, its own tag prefix `netops-<component>/vX.Y.Z`, and its own release page with its own assets.

**This repository advertises exactly one version per component: one release page and one tag.** When a component is released, the release page and the tag of its previous version are deleted, after the replacement artifacts have been verified and the prior artifacts archived. A completed release cycle leaves four release pages and four tags - one per component, as listed above; old and new versions can coexist while publication and retirement are in progress.

Source history remains reachable on `main` by commit. Superseded release pages, tags, tag signatures and downloadable assets are no longer available from GitHub. Checking out an old commit recovers its source, not its original image, SBOM, scan or artifact signature; preserve verified artifacts locally if rollback or historical verification is required. Changelog entries describe source history, not additional available releases.

A component release archive is self-contained: it carries the component tree, its own `LICENSE`, and its own changelog. Self-contained does not mean identical in shape: the `netops-helper` archive additionally vendors `src/netops_core`, the `netops-auditor` archive pins `netops-core==0.2.3` and needs the core archive installed beside it - so does the `netops-helper` archive, whose vendored copy of `netops_core` is there for the image build and does not satisfy that pin for `pip`, and `netops-core` is a library archive with no image of its own. Repository-level files (this page, `SECURITY.md`, `CONTRIBUTING.md`, CI) live here and are not part of a component archive.

## Repository gate

A tag run of CI tests the component that tag names, plus the repository gate; the jobs of the other two components are skipped, and a skipped job is not a test that passed. The state of the whole tree at that commit is what the `main` run of the same commit reports.

`scripts/check_release.py` is the gate for the tree as a whole. It fails closed when a tracked file belongs to no component release and to no reviewed repository file, when a component has no release selector or no gate of its own, when a component `LICENSE` differs from the repository one, when CI does not cover a component, or when any tracked file carries a private address, host name, path, or credential-shaped string. Each component then runs its own gate over its own tree: `components/netops-helper/scripts/check_public_release.py`, `components/netops-auditor/scripts/check_gates.py`, `components/netops-core/scripts/check_gates.py`, and `components/netops-admin/scripts/check_gates.py`.

```sh
python3 scripts/check_release.py                                    # whole repository
python3 tests/test_release_gate.py                                  # tests of this gate
```
