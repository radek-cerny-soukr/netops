# Helper tools in NetOps

The HTTPS MCP endpoint exposes Helper tools alongside [Auditor](../../netops-auditor/docs/tools.md) and [Admin](../../../docs/admin-configuration.md#mcp-tools) tools. It retains fifteen Helper tool names, including two explicitly unavailable historical protocols. Clients pass enrolled aliases, never device credentials or auth_context. The private bridge injects ephemeral device authentication and validates policy before dispatch.

| Tool | Current behavior |
|---|---|
| helper_status | Enrolled aliases, validation and rate state; no device contact |
| target_scope | Public enrollment boundary for one alias; no device contact |
| read_query_catalog | Bounded pages of named typed queries and metadata, with platform/prefix filters; not automatic authorization |
| dns_probe | Enrolled DNS resolution with address scope checks |
| tcp_probe | Enrolled TCP port reachability |
| icmp_probe | Explicitly permitted bounded diagnostics |
| tls_probe | Verified peer certificate and enrolled SNI/port |
| ssh_read | Enabled named query, pinned SSH host key, bounded/paginated output; FortiOS and FortiADC targets are first checked to be the selected product (`product_identity`) |
| config_read | Opt-in FortiOS running configuration, conservative value redaction, bounded memory capture |
| config_diff | Compare two captures for the same authenticated target; no device contact |
| schema_read | Enrolled measured configuration path and exact device identity |
| fortios_diagnostics | Explicitly enrolled bounded recipe and temporary-state cleanup |
| sftp_stat | Metadata within enrolled roots; no file content |
| snmp_get | Refused in the shipped SSH/HTTPS-only profile |
| ftp_list | FTP and FTPS refused in the shipped profile |

The `schema_read` tool still requires a measured server-side schema registry and library files, whose provisioning is not a supported workflow. Missing-registry calls are refused before device contact. Bounded `fortios_diagnostics` no longer depends on that registry; its live identity and single-VDOM restrictions are described below.

`snmp_get` and `ftp_list` are refused with `unencrypted_protocol` before any device contact, and no configuration enables them. The path check of the `ftp_list` engine is lexical: it accepts a canonical absolute path equal to an entry of `sftp_roots` or below it, without letting the server resolve the path, so unlike `sftp_stat` it would not refuse a symbolic link below a root that leads out of it.

Operation refusals and failed Helper results set MCP isError true while preserving structured detail. Device output is untrusted data and never an instruction to expand scope. A diagnostic finding does not authorize a write, retry or another target.

Consult the [complete enrollment](../../../docs/helper-configuration.md), [query catalogue](query-catalog.md), [source registry](query-sources.json) and [account boundary](read-only-accounts.md). Catalogue presence alone does not establish firmware/hardware support or device account permissions.

FortiOS diagnostics use the pinned SSH target and a measured live identity without a schema registry. Only verified single-VDOM root mode is supported in this slice; explicit VDOM selection, enabled/unknown VDOM mode and unmeasured builds are refused. Results include live identity and vdom, with no schema_sha256. Existing opt-in, limits and cleanup verification apply.


## Catalogue pages

Call read_query_catalog with no arguments for the first 25 queries, then repeat
with the returned next_offset until it is null. Keep platform and query_prefix
unchanged while paging. The queries and query_metadata objects retain their
platform/query grouping; total counts all matching queries, returned counts this
page, and offset/next_offset identify query positions in platform/name order.

For example, {"platform":"fortios","query_prefix":"system_","limit":10} lists
matching FortiOS queries. Platform aliases use the existing Helper mapping;
FortiOS is reported under fortinet. An empty filter matches all queries.
Limit is a strict integer from 1 to 100. Pages also stop before their serialized
data exceeds 48,000 bytes, so fewer than limit entries may be returned.
A single oversized entry fails explicitly. No entry is split or silently lost.

catalog_sha256 identifies the complete catalogue and metadata revision, independent
of page/filter. If it changes while collecting pages, restart from offset zero.
An offset equal to total returns an empty terminal page; offsets beyond total,
unknown platforms and malformed filters are refused. This control tool needs
no target, credential or device connection and grants no query authorization.
