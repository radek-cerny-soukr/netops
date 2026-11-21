# NetOps 1.0 documentation

- [Quickstart](quickstart-1.0.md): verified release files, explicit bind, init, HTTPS clients, role configuration, audit, lifecycle, backup, restore and upgrade from the previous release.
- [Helper configuration](helper-configuration.md): complete current inventory/vault input and first device operation.
- [Intent check](helper-configuration.md#intent-check-netops-check-intent): `netops check-intent` plans, exit codes and Discord notification.
- [Admin configuration](admin-configuration.md): device, safeguard, notification and enrollment input, preview, apply and operator undo.
- MCP tool references: [Helper tools](../components/netops-helper/docs/tools.md), [Auditor tools](../components/netops-auditor/docs/tools.md) and [Admin tools](admin-configuration.md#mcp-tools).
- [Troubleshooting by symptom](troubleshooting-by-symptom.md): first Helper calls, how to read their results and their limits for internet/VPN, slowness, FortiADC backend down, TLS errors and Wi-Fi clients.
- [Architecture](architecture-1.0.md): role UID, peer authentication, audit durability/redaction, certificate and token boundaries.
- [Verified platform support](verified-support.md#live-verification-of-netops-1012) records the measured builds and automated-only cases. [Compatibility boundaries](compatibility-boundaries.md#firmware-support-warnings) describes untested-build warnings.
- [Device accounts and roles](account-model.md) describes the Helper, Auditor and Admin account requirements.
- [Auditor configuration](../components/netops-auditor/docs/configuration.md), [collection channels](../components/netops-auditor/docs/channels.md) and [FortiADC snapshots](../components/netops-auditor/docs/tools.md#fortiadc-snapshots) cover operator setup and audit scope.
- [Qualification](testing-1.0.md) (run from a source checkout of the release commit; the release files do not contain it) and [CIS Docker Benchmark mapping](security/cis-docker-benchmark.md).
- [1.0.12 release notes](../release/notes-1.0.12.md) and the [changelog](../CHANGELOG.md).

Existing device/parser/schema contracts continue to apply inside the new product. Core inventory and vault schemas, Admin safeguard/enrollment contracts and Auditor findings are maintained with their engine sources. Installation and release procedures in historical component documentation do not replace the NetOps 1.0 Docker quickstart.
