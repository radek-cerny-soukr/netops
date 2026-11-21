# Junos 26.2R1.7, vJunos-switch (EX9214)

Captured on GNS3 d-vjunos through the pinned DNAT 2256 endpoint on 2026-11-18.
Each command used a trailing `| no-more` and ended with SSH status 0.
The `_ro` files are from `netops-ro` and the `_admin` files from `netops-admin`.
The fixture anonymizer replaced account names. Output contains no administered credentials.

| Files | CLI |
|---|---|
| dhcp_server_bindings | `show dhcp server binding detail` |
| dhcp_relay_bindings | `show dhcp relay binding` |
| dhcp_server_statistics, dhcp_relay_statistics | `show dhcp server statistics`, `show dhcp relay statistics` |
| system_users | `show system users` |
| dns_lookup | `show host example.org` |
| dns_resolvers, syslog_status, authentication_order, radius_servers, tacacs_servers | `show configuration system {name-server,syslog,authentication-order,radius-server,tacplus-server} \| display xml` |
| snmp_statistics | `show snmp statistics` |

Missing rows, partial sections, and injected redaction canaries in tests are derived from these captures.

The log file is from `show log messages | last 2000 | no-more` with SSH
status 0. Before saving, the capture kept recognized timestamp and source
headers, event tags, and interface tokens. It removed message bodies and any
unrecognized lines. This derived fixture is suitable for checking event
selection, with the original timestamp sequence preserved for retained lines.

`log_forwarding_node_admin.out` retains the anonymized timestamp, host and
forwarding node for 22 records in a second `show log messages | last 2000`
capture. The messages originated on `fpc0`, whose node token has no colon.
The capture kept recognizable event tags and replaced message bodies.
