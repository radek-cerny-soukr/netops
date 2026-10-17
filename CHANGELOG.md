# NetOps changelog

## 1.0.0 - 2026-10-17

- Combine Core, Helper, Auditor and Admin in one Docker product with one dependency closure and product version.
- Provide one token-protected HTTPS Streamable HTTP MCP endpoint; no bundled AI clients.
- Isolate role processes and credentials using distinct UID, authenticated local IPC and an unprivileged steady-state runtime.
- Persist every supported request before dispatch and its response before delivery; refuse new operations when the audit cannot be committed.
- Support bounded TLS syslog forwarding or explicit local audit with rotation, retention and safe terminal output. Mark credential redaction visibly.
- Keep audit pending results independent of segment traversal order after backup and restore, including interrupted operations with a recorded response.
- Initialize an instance CA, automatically renewed server certificates, token and protected role data. Preserve identities on repeated init.
- Rotate the instance CA with `netops ca rotate` while the instance is stopped; warn from 30 days before expiry and report unhealthy from 14 days.
- Recover an interrupted local audit write with `netops audit recover`, which quarantines only the incomplete trailing bytes; audit reads, startup and the healthcheck name the condition.
- Refuse concurrent instances and operator configuration over live state; retain safeguards and explicit handling of unknown writes.
- Report refused, failed or uncertain operations as MCP errors (`isError`) and keep their full result content.
- Use English inventory roles `perimeter`, `internal` and `lab` (0.x used `perimetr` and `interni`).
- Name the Compose project `netops`; additional instances need an explicit `docker compose -p`.
- Report role configuration failures using fixed schema fields and reason codes without echoing input values; preserve useful reasons when input contains short words or schema names.
- Import Auditor snapshots and validated policies into private persistent state using create-only names; require a durable operator intent before reading import input.
- Write Auditor SARIF output privately (mode 0600) and refuse links or foreign files as the output path.
- Use digest-pinned Linux images for amd64 and arm64; qualify exact distribution bytes before the user's personal signature.
- Known 1.0 syslog limitation: audit records up to 8 MiB plus framing exceed the RFC 5425 minimum interoperability baseline. Receivers may truncate or discard oversized messages; default settings do not guarantee complete audit. Use explicitly configured rsyslog 8.2512 gtls with `maxMessageSize="9m"` and imtcp `MaxFrameSize="9437184"`; see [Syslog delivery](docs/architecture-1.0.md#syslog-delivery). General interoperability with default RFC-compliant receivers requires a later build.
- Known 1.0 limitation: there is no supported provisioning path for the schema registry/library files of Helper `schema_read` and `fortios_diagnostics`, the extra input files of advanced Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline/schema workflows. See [Helper configuration](docs/helper-configuration.md), [Auditor workflows](docs/quickstart-1.0.md#auditor-operator-workflows) and [Admin workflows](docs/admin-configuration.md).

Historical 0.x documentation and component changelogs are in [the byte-preserved archive](docs/archive/0.x/ARCHIVE.md). No 0.x data migration is provided and previously published releases remain unchanged.
