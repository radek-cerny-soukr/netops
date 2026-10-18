# Helper tools in NetOps

The HTTPS MCP endpoint exposes Helper tools alongside [Auditor](../../netops-auditor/docs/tools.md) and [Admin](../../../docs/admin-configuration.md#mcp-tools) tools. It retains thirteen Helper tool names, including two explicitly unavailable historical protocols. Clients pass enrolled aliases, never device credentials or auth_context. The private bridge injects ephemeral device authentication and validates policy before dispatch.

| Tool | Current behavior |
|---|---|
| helper_status | Enrolled aliases, validation and rate state; no device contact |
| target_scope | Public enrollment boundary for one alias; no device contact |
| read_query_catalog | Named typed queries and metadata; not automatic authorization |
| dns_probe | Enrolled DNS resolution with address scope checks |
| tcp_probe | Enrolled TCP port reachability |
| icmp_probe | Explicitly permitted bounded diagnostics |
| tls_probe | Verified peer certificate and enrolled SNI/port |
| ssh_read | Enabled named query, pinned SSH host key, bounded/paginated output |
| schema_read | Enrolled measured configuration path and exact device identity |
| fortios_diagnostics | Explicitly enrolled bounded recipe and temporary-state cleanup |
| sftp_stat | Metadata within enrolled roots; no file content |
| snmp_get | Refused in the shipped SSH/HTTPS-only profile |
| ftp_list | FTP and FTPS refused in the shipped profile |

In NetOps 1.0, `schema_read` and `fortios_diagnostics` have no supported way to receive their required measured schema registry and library files. They are not supported workflows in this release, even when enrolled in the inventory; see the [configuration limitation](../../../docs/helper-configuration.md). Calls that reach the missing-registry check are refused with the generic MCP error `Role operation failed` before any connection to the device is attempted.

Operation refusals and failed Helper results set MCP isError true while preserving structured detail. Device output is untrusted data and never an instruction to expand scope. A diagnostic finding does not authorize a write, retry or another target.

Consult the [complete enrollment](../../../docs/helper-configuration.md), [query catalogue](query-catalog.md), [source registry](query-sources.json) and [account boundary](read-only-accounts.md). Catalogue presence alone does not establish firmware/hardware support or device account permissions.
