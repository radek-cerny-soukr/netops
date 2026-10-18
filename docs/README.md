# NetOps 1.0 documentation

- [Quickstart](quickstart-1.0.md): verified release files, explicit bind, init, HTTPS clients, role configuration, audit and lifecycle.
- [Helper configuration](helper-configuration.md): complete current inventory/vault input and first device operation.
- [Admin configuration](admin-configuration.md): device, safeguard, notification and enrollment input, preview, apply and operator undo.
- MCP tool references: [Helper tools](../components/netops-helper/docs/tools.md), [Auditor tools](../components/netops-auditor/docs/tools.md) and [Admin tools](admin-configuration.md#mcp-tools).
- [Architecture](architecture-1.0.md): role UID, peer authentication, audit durability/redaction, certificate and token boundaries.
- [Verified platform support](verified-support.md) and [compatibility boundaries](compatibility-boundaries.md): exact host, firmware and model scope.
- [Qualification](testing-1.0.md) (run from a source checkout of the release commit; the release files do not contain it) and [CIS Docker Benchmark mapping](security/cis-docker-benchmark.md).
- [Current product changes](../CHANGELOG.md).
- [Historical 0.x documentation](archive/0.x/ARCHIVE.md): exact original bytes and hash index; not current installation instructions.

Existing device/parser/schema contracts continue to apply inside the new product. Core inventory and vault schemas, Admin safeguard/enrollment contracts and Auditor findings are maintained with their engine sources. Installation and release procedures in historical component documentation do not replace the NetOps 1.0 Docker quickstart.
