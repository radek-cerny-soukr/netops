NetOps 1.0.5 follows NetOps 1.0.4. It restricts SNMP to SNMPv3 authPriv, adds literal filtering of configuration captures, four read-only triage tools, the FortiOS log recipe `logs` with a time window, FortiADC pool member add and remove commands and 90 new read queries for FortiOS and FortiADC. The product remains one container with Helper, Auditor and Admin behind one audited HTTPS MCP endpoint. The syslog audit format and receiver requirements are unchanged.

## Breaking changes

- **`snmp_get` accepts only SNMPv3 authPriv** (SHA-256 authentication, AES-128 privacy). SNMP v1, v2c, noAuthNoPriv and authNoPriv are refused before any network access. Targets that used a v2c community must enroll an SNMPv3 authPriv credential before upgrading. The tool name and input schema are unchanged; the tool description states the new requirement. `target_scope` reports the enrolled SNMPv3 security in the new `snmp_security` field (`authPriv` or `null`).

## Changes in 1.0.5

- New read-only triage tools `triage_slb`, `triage_health`, `triage_routing` and `triage_vpn` give one diagnostic overview each, built on the existing enrolled read functions. The complete product exposes 32 tools with Admin enabled (28 in 1.0.4) and 26 with Admin disabled (22 in 1.0.4).
- `config_read` gains literal `contains` and `context` filtering over the redacted capture with fingerprinted continuation (`filter_sha256`, `content_sha256`), without a new SSH session, for FortiOS minimal captures and FortiOS and FortiADC full captures. `config_diff` of two full captures returns `base_capture` and `other_capture`.
- `fortios_diagnostics` gains the FortiOS recipe `logs`, which a target runs only after `logs` is enrolled in its `diagnostic_recipes`, and the optional inputs `since` and `until` (default null) for it. Its description now also covers the FortiADC event, session and persistence recipes.
- Admin adds the FortiADC operator commands `pool-member-add` and `pool-member-remove` (command line only, no MCP tool) beside `pool-member`: add creates one new pool member always disabled, remove deletes one disabled or maintain member and never the last one. Both need a FortiADC system administrator write login and end with exit code 0 (confirmed), 3 (rejected), 4 (rolled_back) or 7 (unknown); see [FortiADC pool member](../docs/admin-configuration.md#fortiadc-pool-member).
- `target_scope` adds `configuration_limits` (optional enrolled limits for configuration bytes, records, SSH idle and command timeouts and memory, with fixed upper bounds) and `snmp_security`.
- `read_query_catalog` grows from 290 to 380 queries (FortiOS +58, FortiADC +32), among them three MCLAG switch queries (`switch_mclag_consistency`, `switch_mclag_icl`, `switch_trunk_status`). No query is removed. Among the new switch queries, `switch_dhcp_bindings` reads `dhcp-snooping status` and `ssh_read` returns its parsed bindings (MAC address, VLAN, client IP, port) as `dhcp_bindings`, while `switch_dhcp_snooping` reads the snooping settings (`dhcp-snooping database`); `switch_mac_limit` and `switch_source_guard` state when an empty result is meaningful. `total` is 380 and `catalog_sha256` is `e172c53c708c03035865aae3b4cf3600c7637617e315560d7b44d22c733275e1`.
- Four typed FortiADC object views (virtual server, pool, health check, WAF profile) are available through `config_read`; the Auditor can audit an exported FortiADC configuration and applies eleven further CIS FortiGate rules. See the CHANGELOG for the complete list including Admin profile changes and fixes.
- The container base image moves to Python 3.14.10 on Alpine 3.24, and `pyasn1` and `joserfc` are updated, which fixes the vulnerabilities listed in `CHANGELOG.md`.

All other tool definitions and role responses are unchanged between 1.0.4 and 1.0.5; the upgrade check compares them field by field against `release/acceptance/api-changes-1.0.4-1.0.5.json`.

## Upgrade from 1.0.4

Follow the upgrade procedure in the quickstart:

1. Check the 1.0.4 instance, stop it and create its backup and state manifest.
2. Download and verify the 1.0.5 release files. Prepare a separate instance directory and a new Compose project with the same server name and port.
3. Restore the backup into an empty target volume and compare it with the source manifest before the first start. Keep the original instance and backup.
4. Start the new instance. The first start converts only the recorded product version from 1.0.4 to 1.0.5 under the instance lock and writes an `instance_start` audit record with `upgrade` from 1.0.4 to 1.0.5. A second start skips conversion. CA, keys, token, role data and connection details are unchanged.

**Before upgrading, enroll SNMPv3 authPriv credentials for every target that uses `snmp_get`.** Do not run `init` on the restored state. State of any other product version is refused; there is no skipped-release upgrade.

For rollback, stop 1.0.5, preserve its audit records written after the backup, and start the unchanged 1.0.4 instance. A direct downgrade of a converted volume is not supported.

## Acceptance

`release/acceptance/upgrade-check.sh` from 1.0.4 to 1.0.5 compares whole tool definitions and role responses per JSON pointer against the declared changes; none is undeclared and none is stale. The BREAKING entry for `snmp_get` is the only one.

## Verify this release

```sh
cosign verify-blob --bundle netops-1.0.5-SHA256SUMS.sigstore.json \
  --certificate-identity 325383355+radek-cerny-soukr@users.noreply.github.com \
  --certificate-oidc-issuer https://github.com/login/oauth netops-1.0.5-SHA256SUMS
sha256sum -c --ignore-missing netops-1.0.5-SHA256SUMS
```
