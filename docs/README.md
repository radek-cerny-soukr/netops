# Documentation map

This directory is mostly a signpost. Documentation lives with the component it describes, so it is released, versioned, and reviewed together with the code it documents; the one exception is a page that is about more than one component and therefore belongs to none of them.

| Component | Documentation |
|---|---|
| `netops-helper` | [`components/netops-helper/docs/`](../components/netops-helper/docs/) — security model, egress control, installation, onboarding, configuration, read-only accounts, tools, query catalogue, vendor CLI references, releasing, known vulnerabilities |
| `netops-auditor` | [`components/netops-auditor/docs/`](../components/netops-auditor/docs/) — collection channels, configuration, inventory, releasing and their documented limits |
| `netops-core` | [`components/netops-core/docs/`](../components/netops-core/docs/) — inventory and credential schemas, the SSH transport, the audit record, releasing |
| `netops-admin` | [`components/netops-admin/docs/`](../components/netops-admin/docs/) — planning rules, value limits, execution with the rollback safeguard, journal, limits, undo, MCP, audit export, installation, release process, measured scenarios and known limits |

Cross-component: [`verified-support.md`](verified-support.md) — per platform, what firmware, transport, authentication and account privilege the family has actually measured against a device, versus catalogue only.

Repository-level policy is in [`../SECURITY.md`](../SECURITY.md) and [`../CONTRIBUTING.md`](../CONTRIBUTING.md); the release shape of the family is in [`../README.md`](../README.md), including the rule that this repository keeps exactly one release page and one tag per component. Superseded release pages, assets and tags are removed; historical source remains accessible by commit. Use the current release links in the root README for downloads and commit permalinks for historical source. Documentation inside a published archive is fixed at the moment that archive was signed; the documentation in this tree is the current one.
