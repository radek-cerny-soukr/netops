# NetOps 1.0 Helper configuration

Configure devices with the instance stopped. Keep the private input outside the source repository with mode 600. Replace all example values, including the SSH host key pin obtained through an independently trusted channel. The account must be independently verified as read-only; the JSON declaration alone does not restrict the device account.

The input has exactly `inventory` and `vault`. This is a complete schema example for one Linux device:

```json
{
  "inventory": {
    "version": 2,
    "devices": [
      {
        "name": "linux-a.example.invalid",
        "platform": "linux",
        "address": "192.0.2.10",
        "port": 22,
        "role": "lab",
        "credential": "linux-a-ro",
        "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "legacy_ssh": null,
        "auditor": null,
        "helper": {
          "account_role": "read-only",
          "ssh_platform": "linux",
          "enabled_queries": [
            "kernel"
          ],
          "egress": {
            "addresses": [
              "192.0.2.10"
            ],
            "tcp_ports": [
              22
            ],
            "udp_ports": [],
            "tcp_port_ranges": [],
            "udp_port_ranges": [],
            "allow_icmp": false,
            "allow_dns": false,
            "tls_server_names": []
          }
        }
      }
    ]
  },
  "vault": {
    "version": 2,
    "credentials": {
      "linux-a-ro": {
        "kind": "password",
        "login": "read-only",
        "value": "replace-with-secret-outside-repository"
      }
    }
  }
}
```

```sh
docker compose stop
docker compose run -T --rm netops configure helper < helper-private.json
docker compose up -d --wait
```

Call `helper_status` with `{}` and `target_scope` with `{"target":"linux-a.example.invalid"}`, then call `ssh_read` with `{"target":"linux-a.example.invalid","platform":"linux","query":"kernel"}`. A target that is not enrolled is refused with `The target alias is not present in the credential vault.`, also when the alias is missing from the inventory. The MCP caller supplies only the enrolled alias and query; it never supplies a device password or ephemeral authentication context.

Each `helper` section requires `account_role`, `ssh_platform`, `enabled_queries` and all eight `egress` fields shown above. `tcp_ports` and `udp_ports` hold at most 256 unique whole numbers from 1 to 65535. `tcp_port_ranges` and `udp_port_ranges` hold at most 64 non-overlapping `[start, end]` pairs of whole numbers with 1 ≤ start ≤ end ≤ 65535, for example `[[1000, 2000]]`; other forms such as `"1000-2000"` or `{"start": 1000, "end": 2000}` are refused. A port listed in `tcp_ports` or `udp_ports` must not lie inside a range of the same protocol. The device address must be listed in `egress.addresses`; a device named by a DNS name needs `allow_dns` and the explicit IPv4 addresses it may resolve to. The SSH port is taken from the inventory and is not checked against `tcp_ports`; it must not lie inside `tcp_port_ranges` when the device has SSH queries or SFTP roots. The scope limits which enrolled targets and operations the Helper accepts; NetOps 1.0 does not install a host firewall, and it needs no legacy runner or egress-policy file. Choose platform-specific queries from `read_query_catalog`; enable only the required queries. The optional `device_types` list (`switch`, `router`, `firewall`; default empty) names the device type of a target and enables the matching template groups; it is an attribute of the target, not a profile, and is not checked against the device model. `locate_endpoint` also uses it: ARP/ND is read only from targets declaring `router` or `firewall`, MAC tables only from targets declaring `switch` (a layer-3 switch declares both), and FortiLink managed-switch tables through a `firewall` target (see components/netops-helper/docs/normalization.md and tools.md). FortiOS also requires independently verified standard output and `fortios_output_standard_verified: true`. For FortiOS, use `fortios` for `helper.ssh_platform`; `target_scope` reports its query-catalog name `fortinet`.

The common [inventory fields](../components/netops-core/docs/inventory.md), [credential records](../components/netops-core/docs/vault.md) and Helper section fields below remain strict: unknown fields, duplicate JSON keys, invalid types and missing credential references are refused. The configuration command validates the entire input before replacing role files. Validation feedback names the expected schema without echoing credential values.

Credentials, the role home and bounded Helper operation summaries stay in the Helper's private state. The separate mandatory gateway audit records MCP requests and responses; the Helper cannot modify it. Inspect `netops audit` through an explicit operator command. Reconfiguration and offline operator workflows are refused while an instance holds the same state lock.

## Optional Helper fields

A `helper` section may also hold `read_inventory`, `sftp_roots`, `rate_limit`, `fortios_output_standard_verified`, `role_boundary` and `snmp_credential`. Omitted fields take the defaults in the table. The example below is the `helper` object of the Linux example above with `read_inventory`, `sftp_roots` and `rate_limit` added; replace the existing `helper` object with it:

```json
{
  "account_role": "read-only",
  "ssh_platform": "linux",
  "enabled_queries": [
    "kernel",
    "interface_link",
    "service_status"
  ],
  "read_inventory": {
    "interfaces": [
      "eth0"
    ],
    "services": [
      "ssh.service"
    ]
  },
  "sftp_roots": [
    "/var/log"
  ],
  "rate_limit": {
    "requests": 10,
    "window_seconds": 60
  },
  "egress": {
    "addresses": [
      "192.0.2.10"
    ],
    "tcp_ports": [
      22
    ],
    "udp_ports": [],
    "tcp_port_ranges": [],
    "udp_port_ranges": [],
    "allow_icmp": false,
    "allow_dns": false,
    "tls_server_names": []
  }
}
```

`read_inventory` lists the values an MCP caller may pass as query parameters. 136 of the 547 catalogue queries take a parameter; `read_query_catalog` names the kind and the inventory category of each parameter. An inventory-bound parameter (125 queries have one) is accepted only when its value is listed, character for character, in that category of the target. The exceptions below are checked against their own rule instead:

- Literal parameters, checked only for their fixed form and not looked up in the inventory (10 queries): `vlan_id` (a VLAN number from 1 to 4094), `mac_literal` (a MAC address), and the `lines` (1 to 200) and `mac_literal` (lower-case MAC) of `wifi_events`.
- Lookup parameters of the FortiOS `route_lookup`, `policy_lookup_ipv4` and `policy_lookup_ipv6` (3 queries): a single address must be listed in `addresses`; a canonical prefix is accepted when it is equal to or inside an entry of `lookup_prefixes`. A prefix does not enroll the addresses inside it.
- `wtp_id` of `wifi_ap_status` and `wifi_rf_analysis`: listed in `wtp_ids`, or an access point id that an earlier `wifi_ap_status` of the same target returned.
- `triage_flow`: `src`, `dst`, `port` and `proto` need not be enrolled; the Helper allows them for the route, policy and session reads of that one call only, and no other call gains them. This deliberately broadens lookup scope: enabling `system_status`, `route_lookup` and `policy_lookup_ipv4` permits lookups of arbitrary validated IPv4 flow literals, even outside `addresses`, `lookup_prefixes`, `flow_ports` and `ip_protocols`. Ingress for policy lookup is inferred from the route to `src` and checked for safe syntax; it need not be an enrolled interface. Session reads additionally require the `sessions` diagnostic recipe and that ingress in `interfaces`; their source and destination may still be outside enrolled addresses. The temporary scope never persists and does not broaden egress. Grant these queries only when that flow-lookup access is intended; direct `ssh_read` and `fortios_diagnostics` retain their enrolled-value checks.

Any other value is refused with `policy_scope` ("The requested operation is outside the enrolled target scope.") before the device is contacted, and the refusal does not count against `rate_limit`. The error data names the category in `data.field` and the argument in `data.parameter` (every refused argument in `data.parameters`), never the value; a query that is not enabled gives `data.field` `enabled_queries` and a wrong set of parameters gives `parameters`. Pass the values in the `parameters` argument of `ssh_read`, for example `{"target":"linux-a.example.invalid","platform":"linux","query":"interface_link","parameters":{"interface":"eth0"}}`. With the example, `interface_link` with `{"interface":"eth0"}` and `service_status` with `{"service":"ssh.service"}` are accepted; `eth1` or `cron.service` are refused.

Each category holds at most 256 unique, non-empty strings (`schema_paths`: 4096) of at most 128 characters without control characters, written in the form the category accepts:

| Category | Accepted value | Used by |
|---|---|---|
| `interfaces` | letters, digits and `_ . : / -`, starting with a letter or digit, at most 64 characters; it must also be valid for at least one enabled query that takes an interface (for example a FortiOS interface name has at most 15 characters and no `:` or `/`) | 60 catalogue queries; `fortios_diagnostics` |
| `sdwan_members` | canonical decimal member seq-id from 1 to 512, without leading zeros | 4 FortiOS queries |
| `sdwan_rules` | canonical decimal SD-WAN rule ID from 1 to 4000, without leading zeros | 2 FortiOS queries |
| `sdwan_health_checks` | 1–35 ASCII letters, digits, underscore, dot or hyphen, starting with a letter or digit; spaces, quotes and Unicode are unsupported | `sdwan_sla_history` |
| `link_monitors` | same supported name form as `sdwan_health_checks`; `all` is refused regardless of case | `link_monitor_status` |
| `addresses` | an IPv4 or IPv6 address in canonical form: no leading zeros, lowercase compressed IPv6, no zone index | 25 catalogue queries; `fortios_diagnostics` |
| `wtp_ids` | 1–35 ASCII letters, digits, `_` or `-`, starting with a letter or digit; the serial numbers (wtp-id) of the FortiAP the target manages. Optional: an id returned by an earlier `wifi_ap_status` of the same target is accepted without being listed | `wifi_ap_status`, `wifi_rf_analysis` (optional `wtp_id`) |
| `lookup_prefixes` | a CIDR prefix of either family in canonical form: the network address without host bits (`198.51.100.0/24`, not `198.51.100.1/24`), a decimal prefix length from 1, lowercase compressed IPv6, no mask notation, no zone index | prefix operands of the FortiOS `route_lookup`, `policy_lookup_ipv4` and `policy_lookup_ipv6` queries and of the `sessions` and `flow` recipes of `fortios_diagnostics` |
| `managed_switches` | `S` followed by 11 to 15 uppercase letters or digits | 19 FortiOS queries |
| `services` | letters, digits and `_ . @ -`, starting with a letter or digit, at most 128 characters | 2 Linux queries |
| `vlans` | a letter followed by up to 31 letters, digits, `_` or `-`; not `all`, `any`, `none`, `detail`, `ipv4`, `ipv6`, `tag`, `ports`, `virtual-router` or `statistics` | 2 EXOS queries |
| `certificates` | a letter followed by up to 78 letters, digits, `_`, `.` or `-`; not `all`, `any`, `none`, `detail` or `details` | 1 FortiOS query |
| `switches` | letters, digits and `_ . : -`, starting with a letter or digit, at most 64 characters | 1 FortiOS query |
| `schema_paths` | up to 32 words separated by single spaces, each word of letters, digits and `_ . + -` starting with a letter or digit | `schema_read` (FortiOS with `system_status` enabled) |
| `diagnostic_recipes` | `ping`, `traceroute`, `sniffer`, `sessions`, `flow`, `logs`, `nslookup`, `http_probe`, `health_check_verify`, `system_event_logs`, `waf_attack_logs`, `session_list` or `persistence_list` | `fortios_diagnostics` (FortiOS or FortiADC with `system_status` enabled; a FortiOS target accepts `ping`, `traceroute`, `sniffer`, `sessions`, `flow` and `logs`, a FortiADC target `ping`, `traceroute`, `nslookup`, `http_probe`, `health_check_verify`, `system_event_logs`, `waf_attack_logs`, `session_list` and `persistence_list`, any other recipe fails the inventory) |
| `diagnostic_names` | a lowercase DNS name of at least two labels without a trailing dot, the last label starting with a letter | `fortios_diagnostics` `nslookup` (FortiADC) |
| `diagnostic_http_endpoints` | `http://`, a canonical unicast IPv4 address, `:port` only when the port is not 80, and a path of `/`-separated segments of letters, digits and `_ . ~ -` not starting with `.`; no query, fragment or credentials; at most 128 characters | `fortios_diagnostics` `http_probe` (FortiADC) |
| `adc_health_checks` | letters, digits and `_ . -`, starting with a letter or digit, at most 35 characters | `fortios_diagnostics` `health_check_verify` (FortiADC) |
| `diagnostic_vdoms` | VDOM names: a letter or digit followed by up to 30 letters, digits, `_`, `.` or `-` | explicit `vdom` of `fortios_diagnostics` (FortiOS; a FortiADC target refuses a selector) |
| `adc_vdoms` | letters, digits and `_ . -`, starting with a letter or digit, at most 35 characters | 1 FortiADC query (`slb_vs_stat`) |
| `adc_virtual_servers` | letters, digits and `_ . -`, starting with a letter or digit, at most 35 characters | 3 FortiADC queries (`slb_vs_stat`, `tls_handshake_stats`, `tls_session_reuse`) |
| `diagnostic_virtual_servers` | FortiADC only: a letter or digit followed by up to 62 letters, digits, `_`, `.` or `-` | `fortios_diagnostics` `session_list` / `persistence_list` (the virtual server is passed as `address`) |

`lookup_prefixes` lets a lookup or a filter name a whole client network, for example `198.51.100.0/24`, instead of one enrolled address. A prefix is accepted only where nothing connects to it: the FortiOS `route_lookup` and `policy_lookup_ipv4` / `policy_lookup_ipv6` parameters (`address`, `src_ip`, `dst_ip`) and the `address` and `source_address` of the `sessions` and `flow` recipes of `fortios_diagnostics`. The requested prefix must be canonical and equal to or inside an enrolled `lookup_prefixes` entry of the same family; a single address still has to be listed in `addresses` itself, and an address that merely lies inside an enrolled prefix is not enrolled. `ping`, `traceroute`, `sniffer`, `logs`, BGP peers, `triage_routing`, the other vendors' route lookups and `egress` never take a prefix, and `lookup_prefixes` does not widen `egress`. FortiOS `get router info routing-table details` and `diagnose firewall iprope lookup` take one address, so the Helper sends the network address of the prefix (`198.51.100.0/24` becomes `198.51.100.0`): the answer is the route or policy for that address, not for the whole prefix. The `sessions` and `flow` filters take the range of the prefix (`diagnose sys session filter dst 198.51.100.0 198.51.100.255`, `diagnose debug flow filter addr 198.51.100.0 198.51.100.255`). Prefix filters require measured range grammar: FortiGate-60F 7.6.8 build 3744 with a tuple, or FortiGate-80F 8.0.2 build 0251. Other identities return `prefix_not_supported_on_identity` before diagnostic state changes; route and policy lookups still use the network address. A prefix is refused when its first or last address is multicast, unspecified or the limited broadcast address. A refusal names `lookup_prefixes` in `data.field` when the requested value was a prefix, and `addresses` otherwise.

`fortios_diagnostics` requires its recipe, address and interface to be listed in `diagnostic_recipes`, `addresses` and `interfaces`. An explicit `vdom` must also be listed in `diagnostic_vdoms` and must equal the session's verified current VDOM; the Helper never enters `config vdom`, so a multi-VDOM target needs a login scoped to that VDOM.

`logs` never sets a log filter. It reads `execute log filter dump`, refuses a dump whose nine fields differ from the measured FortiOS 8.0.2 shape, runs one bounded `execute log display` under the current device filter, and requires the dump read afterwards to equal the first one. When the dump differs in the same session, the helper reconnects, verifies the same identity and requires the dump of the new session to equal the first one; otherwise cleanup is reported as not verified. The result names that device filter in `filter_applied`; it is not a filter by type, target or time. Only the loaded batch (at most the device `view-lines`) of the current category is searched: records whose `srcip` or `dstip` equals the enrolled `address` are kept, at most `count` of them, and, when the optional `since` and `until` (form `YYYY-MM-DD HH:MM:SS`, `logs` only) are given, only those inside that window, with `found`, `loaded`, `matched`, `returned`, `truncated` and the `time_range` of the loaded batch. `log_state` is `ok`, `empty` (only for complete zero-count headers), `device_refused`, `unsupported` or `incomplete`; timeouts, a loaded-count/parsed-record mismatch, or a record without a valid timestamp are `incomplete`, never `empty`. Only `ok` and `empty` set the result's `ok` flag. A missing or unknown header is `unsupported`.

The `schema_read` tool still needs a measured server-side schema registry and library files, with no supported provisioning workflow. Bounded `fortios_diagnostics` instead verifies its pinned target and measured live identity without a registry; see the diagnostic section below.

The other optional fields:

| Field | Form | Limit | Default | Purpose |
|---|---|---|---|---|
| `read_inventory` | object of the categories above, each a list of strings | 256 values per category, 4096 for `schema_paths`; 128 characters per value | `{}` | values allowed as query parameters |
| `sftp_roots` | list of absolute POSIX paths in canonical form: no trailing `/`, no `//`, no `..`, not `/` itself | 256 unique paths, 2000 characters each | `[]` | `sftp_stat` accepts a root and any path below it whose target, as the SFTP server resolves it, stays below the resolved root |
| `rate_limit` | `{"requests": N, "window_seconds": S}`, both whole numbers, both keys required | `requests` 1–60, `window_seconds` 1–3600 | 30 requests per 60 seconds | per-target limit on accepted device operations; a follow-up page (`offset` > 0) of `ssh_read` or `schema_read` is not counted; an exceeded limit is refused with `rate_limit` and `retry_after_seconds`. The triage tools (`triage_health`, `triage_routing`, `triage_vpn`, `triage_slb`, `triage_flow`, `wifi_triage`) reserve 10, 5, 4, 21, 5 and 7 reads (`wifi_triage` 15 with an enrolled REST token) against this total and a triage sublimit of the same size (`triage_rate_limit` in `target_scope` and `helper_status`); both budgets are checked atomically before acceptance |
| `fortios_output_standard_verified` | `true` or `false` | — | `false` | FortiOS `ssh_read`, `schema_read` and `fortios_diagnostics` are refused while it is `false` |
| `role_boundary` | `"catalogue"` | only with `account_role: "admin-bounded"`, which is accepted only for `ssh_platform: "ruckus_unleashed"`, `"fortios"` or `"fortiadc"` | absent | required companion of `admin-bounded`; refused with `read-only` |
| `snmp_credential` | `null` or the name of a vault record of kind `snmpv3-authpriv` (a legacy `snmp-community` record is refused by `snmp_get` with the replacement instructions) | — | `null` | `target_scope` reports it as `snmp_enrolled`; an `snmpv3-authpriv` record (SHA256, AES128) activates `snmp_get` within the target UDP egress scope and the 1 to 20 OID limit; `snmp_enrolled` is false for a legacy record; SNMPv1, SNMPv2c, noAuthNoPriv and authNoPriv are not supported |
| `tls_ca_certificate` | absolute canonical path of a PEM file below `/etc/netops-helper/certs`, never inline PEM | 64 KiB; only CA certificates (basicConstraints `CA=true`), no private key block | absent | `tls_probe` of this target verifies the chain against this CA instead of the system store; hostname/SAN checking and TLS 1.2 or newer stay mandatory |

`tls_ca_certificate` is for a target whose certificate comes from a private CA. With it, `tls_probe` trusts only that CA file for this target, not the system store as well, so a publicly signed certificate for the same name is not accepted either; without it the probe uses the system store as before. There is no option to skip verification. The file must exist and be readable for the Helper when the inventory is configured: the container file system is read-only and has no such directory, so mount a host directory read-only in a Compose override, for example `volumes: ["./netops-ca:/etc/netops-helper/certs:ro"]`, with the CA file mode 0644; a file that is missing, unreadable, outside that directory (also through a symlink), not a CA certificate or that holds a private key refuses the section. `configure helper` then names `inventory.devices[N].helper.tls_ca_certificate` and the reason, never the file content. The `tls_probe` result names the trust it used as `trust: "system"` or `trust: "inventory_ca"`, never the path or content of the CA.

`sftp_roots` also makes the SSH port of the device an explicit egress port, so that port must not lie inside `tcp_port_ranges`. `target_scope` returns the stored `read_inventory`, `sftp_roots`, `rate_limit`, `triage_rate_limit` and `snmp_enrolled` of a target.

A section that breaks any rule above is refused as a whole. The message names the device by its position in `devices` and the refused field, never a value and never the device name, which could be a misplaced secret, for example `Invalid Helper inventory: inventory.devices[3]: helper.rate_limit is invalid; compare it with docs/helper-configuration.md (values are not repeated)`. A missing required field is reported as `helper.egress is missing`, an undocumented field as `helper contains unknown fields`, and the device fields the section depends on as `credential`, `host_key_fingerprint` or `address` (the address must be listed in `helper.egress.addresses`). Compare the named field with the tables above. A refusal that cannot be tied to one field keeps the general message `Invalid Helper inventory. Each helper section requires account_role, ssh_platform, enabled_queries and egress; check field types, target scope and credential references in docs/helper-configuration.md`.

## Additional enrollment controls

See [Optional Helper fields](#optional-helper-fields). The `admin-bounded` account is accepted only on an explicitly supported platform whose read-only role is missing or refuses part of the catalogue (`ruckus_unleashed`, `fortios`, `fortiadc`), with `role_boundary: "catalogue"`; it remains an administrator on the device. See [account boundaries](../components/netops-helper/docs/read-only-accounts.md). SNMP is accepted only as SNMPv3 authPriv (SHA256, AES128); SNMPv1, SNMPv2c and FTP/FTPS are refused even if historical engine fields are present.

Device roles are exactly `perimeter`, `internal` and `lab`; earlier Czech spellings are refused. A failed/refused Helper operation has MCP `isError: true` and preserves its structured error result. A `switch_read` protocol that is not configured is a valid `not_applicable` answer (`ok: true`, `isError: false`); triage still reports required missing protocol evidence as incomplete. The error flag never authorizes a retry or a wider device scope.

## Optional configuration captures

For a FortiOS target with an enrolled read-only SSH account, pinned host key and
verified standard output, opt in with `"config_access": ["read", "compare"]`
inside its existing `helper.read_inventory` object. Omit the category to disable
both tools. `compare` requires `read`. The existing network egress and audit
requirements apply.
The read-only device profile must permit both CLI get and CLI show for these
tools (on FortiOS 8.0.2: cli-get enable, cli-show enable), with cli-config
disabled and the relevant system/network groups read-only. A get-only profile
can authenticate successfully yet refuse show with Unknown action; this is a
failed capture, never an empty successful configuration.

Call `config_read(target, platform="fortios", section="system interface")` twice, then
`config_diff(target, platform="fortios", base_snapshot="<first snapshot_id>",
other_snapshot="<second snapshot_id>")` through the MCP endpoint. The proxy
injects authentication; clients never supply device credentials.
This first slice supports only the single-VDOM running view. Before each capture,
the fixed `get system status` command must return one FortiGate/FortiWiFi identity
and exactly one `Virtual domain configuration: disable` marker. Missing,
duplicate, unknown or enabled VDOM mode is refused before `show`; a current VDOM
named root alone does not establish single-VDOM mode. The configuration body
also refuses a VDOM wrapper. Only then is the selected fixed command issued.
Required `section` is one of `system interface`, `firewall policy`,
`firewall address`, `router static`, `vpn ipsec phase1-interface`.
It renders `show <section>` from a fixed map. Whole `show` requires
`section="all", include_all=true`. Other combinations are refused before device access.
It has no schema-registry dependency and does not add arbitrary CLI execution.

The parser accepts balanced FortiOS config/edit/set/unset/next/end syntax.
It preserves section and attribute names and only the finite `status up/down`
values; it redacts other values, including edit identifiers. Unknown grammar,
unbalanced quotes or safety limits exceeded are refused entirely. Known leading configuration headers and multiline quoted values are
accepted; multiline values become one redacted record. Unknown headers, headers
inside the configuration body and pagers are withheld without publishing a snapshot.
A FortiOS exec prompt on the first physical line is removed using the existing
prompt format. Only the same trailing prompt after a complete configuration is
accepted; an intervening or mismatched prompt refuses the entire capture.
The stream keeps the existing physical-line and capture memory limits.
It never silently truncates. By default raw input is limited to 64 MiB for a
selected section and 256 MiB for explicit whole configuration; physical lines
are limited to 64 KiB and logical multiline records to 1 MiB. These defaults
are also the maximums; enrolled `configuration_limits` can only lower them.

Captures contain only redacted text and private keyed comparison tokens in
process memory: four captures per authenticated target, sixteen total, TTL24h.
Restart discards them. Authentication changes invalidate access to prior captures.
Captures record actual firmware model/version/build, selected section/command and
redaction profile. Diff refuses different sections, firmware identities or profiles.
The diff text and its hash describe redacted content. `secrets_changed` reports
at most 256 opaque process-local record identifiers per page, derived from section, private object
identity and attribute. Inserting a visible line does not report unrelated hidden
values as changed. A secret-only change therefore has
an empty text diff but `identical=false`. Two equal captures have different IDs.
Reordering otherwise equal objects marks the comparison as different and emits a
record-order notice when the redacted text is unchanged, without claiming their
secret values changed. Duplicate hidden identities are withheld.
This slice does not implement EXOS, persistent captures, or comparison with
an implicit current capture.

### Pages from completed configuration captures

The optional limit is 1–48,000 bytes (default 48,000); offset is a nonnegative
byte offset. Redacted configuration content and diff text contain only ASCII,
so every valid byte offset is also a character boundary. The initial capture must use offset 0. To read the next page,
call config_read with the same target/platform/section, its snapshot_id and
the returned next_offset. A filtered page also needs the same contains and
context plus the returned content_sha256 and filter_sha256. This serves the
completed immutable capture without another device command. For section all, keep include_all=true on every call.
Scope changes, expired/evicted captures and invalid offsets fail explicitly.
This does not extend snapshot TTL.

Both config_read and config_diff return content_sha256 and total_bytes for the
whole completed redacted content (for a filtered config_read, for the filtered
content), returned_bytes/offset for the current page,
and next_offset(null at the end). Config_diff accepts offset/limit for the same
explicit pair of captures; it never rereads the device. Reconstruct text in
page order before comparing its digest. Diff uses a bounded, ordered line
comparison, not a minimal edit script. Insertions may therefore produce several
line changes. Hidden-value comparison remains keyed by private object identity.
The separate secret_offset cursor starts at zero; next_secret_offset advances
through secrets_changed, while secrets_changed_count gives its complete count.

Configuration capture passes SSH stdout bytes directly to a strict incremental UTF-8 redactor. Chunk boundaries may split characters or quoted multiline values. No complete raw stdout is retained. A capture is published only after a successful transport result and complete configuration grammar; errors discard staged state. Redacted content uses bounded ASCII chunks and comparison tokens use packed keyed records. Captures and cached diffs share a fixed 512 MiB process budget, further constrained by available host/container memory with a 64 MiB admission reserve. Only one configuration capture, page or comparison runs at a time; concurrent calls are refused. Each target may lower these limits through its optional helper.configuration_limits policy; the process ceiling and available-memory reserve remain in force. A memory refusal publishes no new capture. Other device read transports retain their existing behavior.

Configuration SSH reads default to a 30-second idle timeout, reset only by received stdout or stderr bytes. The configuration SSH command defaults to a 600-second timeout; this is not a deadline for the complete API call. The proxy allows 670 seconds for configuration tools, including the identity probe and connection pacing; other tools keep their existing pending-response timeout. After the configuration command starts, failures withhold the output and publish no snapshot. Consumer/redaction failures report `redaction-unverifiable` (minimal reads expose MCP `-32602` with a safe category and no partial output); capture limit failures report `capture-limit-exceeded`; a per-target or process memory refusal keeps its own `configuration memory budget exhausted` category in minimal and full reads, also inside a nested auto-script. A consumer or capture-limit failure does not invalidate the pinned host-key cache. Transport failures remain separate, and raw device error details are withheld.
## Registry-free bounded FortiOS diagnostics

The existing fortios_diagnostics tool needs no NETOPS_SCHEMA_REGISTRY. Keep its enrolled recipes, destination addresses and interfaces, verified standard output and pinned host key. Each session must return one measured hardware/version/build identity, one current VDOM and one Virtual domain configuration marker (disable or multiple) before any diagnostic command. In disable mode the current VDOM must be root. In multiple mode an enrolled explicit vdom equal to the current VDOM is required; a missing or different selector returns config_platform_not_supported. Interface ownership is checked in the same session context without switching VDOM. The response exposes the measured identity and vdom; schema_sha256 is removed. Recipe limits, the 30-second session bound, 131072-byte capture bound and verified cleanup are retained. For FortiGate-VM64 on FortiOS 8.0.2 build 0251, the five recipes ping, traceroute, sniffer, sessions and flow have
been exercised on a single-root target, including timer interruption and verified
restoration of diagnostic settings. This does not qualify another model or build,
multi-VDOM, or successful forwarding to an external destination.

The device account must permit CLI get, show, diagnose and execute while CLI
configuration remains disabled. Inventory opt-in does not grant device privileges.

On a FortiADC target the same tool runs one fixed command in a terminal session after
the measured FortiADC-KVM 7.6.7 build 0676 identity: `execute ping <address>`,
`execute traceroute <address>`, `execute nslookup name <name>`, `execute curl <endpoint>`
or `execute health-check-verify health-check <name> dest-address <address> count <count>`.
Another firmware ends
as `config_platform_not_supported`. `interface` must be empty and no remote option is
changed. Except for `health_check_verify`, `count` must stay 3 and is not applied: the
device always sends 5 ping packets, and a ping result says so with `count_applied: false`
and `fixed_ping_packets: 5`. `timeout` is 1-10 seconds for ping, nslookup and `http_probe`
and 1-60 seconds for traceroute and `health_check_verify`; the default is 10 seconds (also for FortiOS recipes). FortiADC nslookup uses this default to allow a cold DNS cache lookup. For FortiADC traceroute use `timeout: 60`; with the default the result
may hold only the header. In the measured run each unanswered traceroute hop took about
20 seconds. At `timeout` the command is interrupted and the partial output is returned
with `deadline_reached: true` and `complete: false`; the audit record then carries
`detail: "deadline_reached"`. The final `^C` echo of the interrupt sent by Helper is omitted from the device output.

`http_probe` sends one plain HTTP request from the appliance to an endpoint listed exactly
in `diagnostic_http_endpoints`; enroll only idempotent endpoints. The caller passes the
enrolled endpoint as `address` and cannot add a method, header, body, credential or other
option. The appliance keeps global `execute curl-option` settings that apply to every
`execute curl`, so before the request the Helper reads `execute curl-option view-settings`
and refuses, without sending the request, unless the current `Header` and `Raw data` are
both `auto`; it does not change these settings. The verbose output echoes the request
headers (`> Host: …`). HTTPS is not offered. `count` must stay 3 and is not applied; the
result says `count_applied: false` and `http_requests: 1`. `health_check_verify` runs a
health check named in `adc_health_checks` against an address in `addresses`; the caller
names it in `health_check` and chooses `count` 1-5, which the appliance applies. The
health check's own protocol and port come from its configuration on the appliance. The
FortiADC 7.6.7 CLI reference gives a default interval of 5 seconds between checks and a
default check timeout of 3 seconds; in the measured run `count 2` against a check in state
UP took about 7 seconds. Pass `timeout` of about 5 × `count` + 5 seconds (for `count 5`
about 30); with the default 10 seconds the result may end with `deadline_reached: true`
before the summary line. For both recipes `complete: true` means the command returned to
the prompt within `timeout`, and the HTTP status, body and health check result are in the
returned device output. Measured on FortiADC 7.6.7 build 0676 are an HTTP 200 response and health checks
in both UP and DOWN states; DOWN returns ordinary device output with `ok: true`
and its health-check state. An unreachable HTTP endpoint and an HTTP error response
were not measured. A `Command fail. Return code is …` line ends the call as a
failed diagnostic without the device output.

The FortiADC device permission is the explicit grant: the recipe in
`diagnostic_recipes` together with the enrolled SSH platform and `system_status`, and
the exact address in `addresses` (ping, traceroute, health_check_verify), name in
`diagnostic_names` (nslookup), endpoint in `diagnostic_http_endpoints` (http_probe) or
health check in `adc_health_checks` (health_check_verify). It permits only that fixed
appliance command; the appliance itself sends the probe. Like traceroute, `http_probe` and
`health_check_verify` need no egress flag or TCP port. The traceroute probe protocol is not documented here and is not claimed; no
egress flag is required or changed for it. Ping and nslookup additionally keep the
Helper host egress checks `allow_icmp` and `allow_dns`; those flags also let the Helper
itself send `icmp_probe` and `dns_probe` and do not by themselves allow any appliance
command.
On FortiOS the diagnostics need, besides the read groups, `cli-diagnose enable` and
`cli-exec enable` in the access profile; an `execute` command without `cli-exec` is
refused with `Unknown action 0`. On FortiADC the device accepted `execute ping`, `execute traceroute`, `execute nslookup` and `execute curl` under a read login (typed in a terminal), and refused `execute health-check-verify` and the log recipes; the Helper recipes themselves were measured under a system administrator enrolled as `admin-bounded`. The measured profiles and the device answers are in
[Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md).


For sessions, sniffer and flow, the optional TCP/UDP tuple uses source_address, source_port,
destination_port and protocol; the existing address argument is the destination
address. The tuple direction is source to destination. Both addresses must be in
the target addresses inventory, ports are canonical integers from 0 through
65535, and protocol is TCP (6) or UDP (17). TCP/UDP tuples are enabled only for
the identities in `TUPLE_IDENTITIES`: FortiGate-VM64 8.0.2 build 0251,
FortiGate-60F 7.6.8 build 3744 and FortiGate-80F 8.0.2 build 0251. On the 60F a
live UDP flow trace with a tuple captured packet trace lines (see the flow
section below); sessions and sniffer with a tuple are not qualified there. On
the FortiGate-80F (HA primary) a live flow call with a UDP tuple filter set and
cleared the filter with verified cleanup but traced no packet, because that
session was offloaded; TCP/UDP capture with a tuple (sessions, sniffer and flow)
is not qualified on that identity. Other identities retain the existing ICMP
behavior and refuse tuples until their syntax/build is qualified.
For sessions, the output is projected per session to one line with proto,
proto_state, duration, expire, policy_id, dev (ingress->egress interface
indexes for original/reply) and the org/reply byte/packet/error counters, followed
by the hook lines that carry the source/destination tuple and any SNAT/DNAT
translation, and a final total session line. Every other device line (gateways,
MAC addresses, serial, shaping, NPU and application fields) is dropped. A session
missing any of these fields, or a list without its total line, gets an
incomplete=<fields> line and the result reports complete false instead of
silently omitting it; sessions beyond count are dropped and reported as
sessions_omitted with truncated true.
This source change does not establish a live TCP/UDP result or 60F/FortiOS 7.6.8
support.

For sniffer, the typed tuple selects both directions of this exact connection.
The fixed filter is TCP or UDP and the OR of the source-to-destination and
destination-to-source host/port pairs. The enrolled interface is always explicit.
The helper fixes verbosity to 1, which prints packet headers without payload;
there is no user-provided filter text or payload verbosity option. Existing
packet count (1–8), timeout (1–10 seconds) and returned-byte limits remain in
force, and the SSH session closes after the bounded operation. Without a tuple,
the existing ICMP host filter remains available. FortiOS 7.6.8 CLI Reference
pages 3319–3320 and FortiOS 8.0.2 CLI Reference page 3498 document the packet
filter, count and timestamp arguments and header-only verbosity 1. These
references establish syntax, not a measured successful target capture.

For flow, the tuple sets only the fixed saddr, daddr, sport, dport and proto
filters for the requested source-to-destination connection. These native filters
do not filter by interface or promise the translated reply direction; the enrolled
interface must still be visible in the verified VDOM. The helper refuses active
debug output before changing a filter or registering cleanup. It also refuses a
nonempty existing filter. The existing bounded trace count and listening window,
interrupt, cleanup readback and same-identity repair remain in force. It does not
reset application debug levels or change the shared debug-duration value.
Enrol flow only where diagnostic use is coordinated: debug enable can start the
shared timer. Cleanup verifies the helper's output/filter state, not that timer's
elapsed value.

The returned bounded, redacted flow text preserves the device's trace messages
for administrator inspection: packet tuple and input interface, route and egress
interface, policy ID, NAT translation, and explicit drop or denial reasons when
emitted. No fixed parser removes these details. A capture without a matching
packet does not establish its policy, route or drop reason.

A flow result carries `trace_state` and `trace_summary`; both name the applied
filter and window. `captured` means the output holds at least one packet trace
line, `id=… trace_id=… func=… line=… msg="…"` or, without the function name,
`id=… trace_id=… msg="…"` (FortiOS 8.0.2 Administration Guide page 5569, 7.6.8
page 4783), at the line start or after the console timestamp prefix described
below; the summary counts the traced packets
(distinct `trace_id`) and trace lines and claims nothing about route, policy or
verdict, which stay in the returned device text. `empty` means no packet trace
line arrived during the window, also when the device returned other text (the
summary then gives its size). An empty trace shows neither that the traffic
passes nor that it is blocked. The summary names the three causes to check: the
filter does not match the real connection; the traffic does not pass through
this FortiGate during the call; or the session is offloaded to the network
processor, while flow debug shows only packets the CPU processes. Start a new
connection with exactly the filtered tuple while the call runs; a client usually
opens each new connection from a new source port, so send it from the filtered
source port. ICMP is not offloaded, so the tuple summary also offers a flow call
without a tuple for ICMP to the address. For ICMP the summary asks for ICMP to
or from the address. With `diagnose debug console timestamp enable` (FortiOS
8.0.2 CLI Reference page 3076) each trace line starts with the measured prefix
`YYYY-MM-DD HH:MM:SS ` (date, one space, time, one space), for example
`2026-11-02 11:13:35 id=65308 trace_id=19 func=print_pkt_detail line=6340
msg="..."`; such lines are counted on FortiGate-60F 7.6.8 build 3744 and
FortiOS 8.0.2 build 0251 (measured live on FortiGate-60F 7.6.8 and
FortiGate-VM64 8.0.2; FortiGate-80F 8.0.2 runs the same build). No other
timestamp shape is counted. On FortiGate-VM64-KVM 7.6.7 and 8.0.0 the shape is
not measured, so when `diagnose debug info` reports `console timestamp: enable`
the flow call is refused before any change and names `diagnose debug console
timestamp disable`. The Helper never changes that setting.
Both states keep `ok` and the verified cleanup. A failure inside the session,
for example output above the capture limit or a missing prompt, is
`bounded FortiOS diagnostic failed; the session was closed` after the debug
output, trace and filter were restored and read back. When that restoration
cannot be verified even after a reconnect, the message adds `the diagnostic
state restoration could not be verified: check 'diagnose debug info' and
'diagnose debug flow filter' on the device; if debug output is enabled or a
filter is set, run 'diagnose debug disable', 'diagnose debug flow trace stop'
and 'diagnose debug flow filter clear'`.

FortiOS 8.0.2 CLI
Reference pages 3078–3081 and 3087 document the scalar filters and trace controls;
Administration Guide pages 5565–5568 show their diagnostic use and policy/route/NAT
messages; page 5566 states that flow monitoring does not work for traffic
offloaded to NP6 or NP7 processors and that ICMP traffic is not offloaded, and
page 5585 that `diagnose debug flow` displays only sessions processed by the CPU. FortiOS 7.6.8 CLI Reference pages
2927 and 2929 instead document address and port from/to bounds, so on
FortiGate-60F 7.6.8 build 3744 the helper sets each tuple bound as the same
from and to value. A live UDP flow trace on that identity with a read-write
diagnostic account returned packet trace lines for the tuple and restored and
verified the debug and filter state; it is listed in `TUPLE_IDENTITIES` for
that reason. Other 7.6.8 builds and models stay refused. On FortiGate-80F 8.0.2
build 0251 the live flow evidence is an ICMP trace with packet lines and a UDP
tuple filter on an offloaded session that traced no packet; tuple capture there
is not qualified.

## Configuration capture limits

An optional `configuration_limits` object in the enrolled device's `helper`
section can lower the configuration capture limits. It is target policy, not
a `config_read` or `config_diff` argument. Omitted values keep the defaults.

| Field | Default and maximum |
|---|---:|
| `section_bytes` | 67108864 |
| `all_bytes` | 268435456 |
| `physical_line_bytes` | 65536 |
| `logical_record_bytes` | 1048576 |
| `idle_seconds` | 30 |
| `total_seconds` | 600 |
| `memory_bytes` | 536870912 |

A deliberately small limit can make a capture impossible; the operation is
refused rather than relaxing the limit. Values must be positive whole numbers;
booleans, fractions, unknown fields and
values above the fixed maximum are rejected. Section bytes cannot exceed all
bytes; a physical line cannot exceed a logical record, which cannot exceed all
bytes. Idle seconds cannot exceed total seconds.

For example, `"configuration_limits": {"section_bytes": 1048576,
"all_bytes": 2097152, "idle_seconds": 5, "total_seconds": 60}` restricts a target
without changing its permissions. The idle timer measures received SSH bytes;
`total_seconds` bounds the SSH configuration command, not DNS, host-key
verification, the identity probe or the complete API call.

A byte or record limit violation returns
`configuration capture-limit-exceeded; output withheld`, publishes no snapshot
and returns no partial configuration. A verified line or configuration section
may accompany the category. Memory admission and the shared retained
snapshot/diff budget remain enforced and can also refuse the operation.
The memory limit counts only the current target's retained captures, filtered
views and diffs plus its staged content; the separate process limit still
counts every target. Another target's captures do not consume this target's quota.
Changing the enrolled limits removes earlier snapshots and comparisons for
that target from the process cache at its next configuration operation; take a fresh capture. The same limits apply to both vendors,
minimal and full captures, and supported embedded configuration scripts.

## Query catalogue pages

read_query_catalog now returns a bounded first page by default, rather than the
entire catalogue. Use next_offset to retrieve the remaining queries, keeping
platform and query_prefix unchanged. The default limit is 25, the maximum is
100, and page data is capped at 48,000 bytes. For example,
{"platform":"fortios","query_prefix":"system_","limit":10} returns a small
platform-specific page. This affects catalogue discovery only; target enrollment
and device query authorization are unchanged. See the
[catalogue page contract](../components/netops-helper/docs/tools.md#catalogue-pages).

### Semantic full configuration redaction

The opt-in full view classifies each field by its exact platform, firmware and
configuration path. A credential classification takes priority over a public
classification. Passwords, authentication and privacy keys, private keys and
credential encodings are removed before snapshots, comparison and output.
A field name containing words such as key, private, password, custom or community
does not by itself identify a credential. Public certificates, fingerprints,
object references and descriptions remain visible when their field semantics have
been verified; SNMP community strings and SNMPv3 auth/priv passwords are credentials
and are hidden in both configuration views. SNMP queries stay SNMPv3 authPriv (SHA256, AES128) only.

Known credentials use occurrence labels such as <REDACTED:credential#1>; these
labels contain no fingerprint of the hidden value. An unclassified field or
object name uses <UNVERIFIED:unclassified-field>. The response reports
credential_redactions, unverified_count, up to 32 unverified_fields paths and
unverified_truncated. This summary contains no original values.
Unclassified fields prevent a claim of configuration completeness. A known field
whose embedded format is not supported uses <UNVERIFIED:unsupported-format>,
reports unsupported_format_count and adds formats-not-verified to visibility
limitations. Unknown schema fields use schema-fields-unverified. Object names
remain visible when their identity semantics have been verified. Neither case
is automatically classified as a credential.

FortiOS auto-script and automation-action script values containing complete
configuration commands are rendered using the same firmware-specific field
classifications. Interface names, routes and peers remain visible; credentials
inside those commands are removed. Scripts are never executed. Unsupported
commands, unclassified fields and scripts nested beyond two levels retain the
explicit unsupported-format marker. The summary counts credential removals
inside a supported script along with other configuration credentials.

The FortiOS script view also recognizes these stored operational commands:
`get system status`, `get system performance status`, `get system arp` and
`get system ha status`;
`diagnose sys session stat`, `diagnose sys session6 stat`,
`diagnose sys vd list`, `diagnose sys cmdb info`,
`diagnose hardware sysinfo memory` and `diagnose hardware sysinfo slab`
without arguments; `diagnose sys top` with up to three decimal arguments;
`diagnose sys mpstat` with up to two decimal arguments;
`diagnose sys top-mem` and `diagnose sys top-fd` with up to one decimal
argument; `diagnose sys profile` followed by exactly one of `cpumask`,
`module`, `report`, `show`, `start`, `stop` or `sysmap`;
`diagnose sys process pidof` with one process name;
`diagnose test application hasync` with exactly one decimal argument, which
the FortiOS 7.6.8 and 8.0.2 CLI references describe as the test level, also
stored as `diagnose test app hasync`;
`fnsysctl date` and `fnsysctl ps` without arguments; `fnsysctl df` with up to
one argument; and `fnsysctl du` with one to four arguments. An `fnsysctl df`
or `du` argument is a path or option of at most 1,024 characters made of
ASCII letters, digits, `_`, `.`, `/`, `+` and `-`; an option may carry one
`=value` in the same characters. The same `diagnose` script shapes accept the
`diag` spelling.
Within the four argument-free `get` forms listed above, a stored abbreviation
is recognized only when its complete sequence of nonempty word prefixes
matches exactly one form. The original stored spelling remains visible.
Public arguments remain visible; a known credential in an argument is
removed without hiding its public neighbors.

This is passive script inspection. The helper does not execute these
commands, does not add them to the enrolled diagnostic catalogue, and does
not establish that a device accepts them. Recognition follows the text that
the script stores: a two-argument `diagnose sys mpstat`, which the FortiOS
8.0.2 CLI reference lists as removed in 8.0.1, is still shown as stored;
`diagnose sys profile start` or `stop` is shown even though executing it
would change profiling state; `diagnose sys profile report` is shown as
stored on a FortiGate-VM 8.0.2 although the FortiOS 7.6.8 and 8.0.2 CLI
references do not list it; and `fnsysctl ps`, `df` and `du` are shown as
stored text, as no vendor CLI reference describing these programs was found.
The `app` spelling is recognized only in `diagnose test app hasync`; other
abbreviated `diagnose` words retain the unsupported-format marker.
Other operational script shapes, including additional arguments,
`diagnose sys profile step`, other `fnsysctl` programs and arguments with
spaces, quotes, pipes, redirections, command substitution or other shell
metacharacters, retain the unsupported-format marker. These FortiOS rules do not
establish support for identically named FortiADC commands; platform-specific
syntax and argument meanings must be verified separately.

Capture failures identify a physical line of the captured output and a known
configuration section when that location can be verified. Object names and
original values are excluded from this diagnostic. A decoding failure before
a line can be identified does not claim a line number.

Full snapshots bind the semantic policy, including credential classifications,
to their full-2 profile. Comparison uses the already redacted content, including
public certificate changes, without password comparison tokens. The minimal
view retains its existing redaction and keyed comparison behavior.

A config_diff of two full captures also returns base_capture and other_capture.
Each lists the fields that config_read returned for that capture: firmware
(model, version, build), section, redaction_profile, include_defaults,
capture_complete, configuration_complete, config_scope, visibility_limitations,
credential_redactions, unverified_count, unsupported_format_count,
unverified_fields and unverified_truncated; FortiOS captures also report
identity_scope_verified. config_diff refuses captures whose section, firmware,
redaction_profile, include_defaults or capture metadata differ, so both objects
always carry the same values. The diff reads no device: the values are the ones
recorded at capture time, and a repeated diff returns them until either capture
expires after 24 hours or is evicted (at most 4 captures per target and 16 in
total are retained). identical=true means only that the visible redacted
content is equal. Redacted credentials and <UNVERIFIED> values are not
compared, even when configuration_complete is true; a change limited to a
password still returns identical=true. identical=true also does not establish
that the account could see the whole configuration: when configuration_complete
is false, changes outside the reported visibility are not compared.
Minimal-view diffs do not return these fields.

FortiOS completeness requires a verified single-VDOM identity and a unique
binding from the enrolled account to a visible global access profile with
cli-show enabled and read access in every documented configuration group.
The assessment uses the captured configuration; paging does not re-read rights
from the device. Missing profiles, custom or partial rights, ambiguous bindings,
remote overrides and uncovered VDOMs prevent a completeness claim. A profile
name alone, including a built-in profile name, is insufficient evidence.
Section captures remain section-only. Available redacted configuration remains
usable when rights or coverage cannot be proved.

## FortiADC object configuration views

On the verified FortiADC-KVM 7.6.7 build0676, config_read accepts
section="load-balance virtual-server NAME", "load-balance pool NAME",
"load-balance real-server NAME",
"system health-check NAME", "security waf profile NAME" or
"system certificate local_cert_group NAME", with platform="fortiadc"
and redaction="full". By default each issues exactly show followed by that section.
NAME is one object name: 1–35 ASCII letters, digits, underscores, dots or hyphens,
starting with a letter or digit. Spaces, wildcards and command syntax are refused.

These SHOW views require the existing config_access read grant and include_all=false.
Set include_defaults=true to read a default object with exactly
show full-configuration followed by the same section; include_defaults=false
keeps the ordinary show command. Explicit whole captures retain their existing options.
The same semantic redaction removes credentials before caching and paging.
Only the requested object may be returned; nested pool members remain visible.
An absent or different object is refused. A successful capture is section-only,
never proof of complete device configuration. Unclassified fields remain hidden
and reported. Continue pages using the same section and snapshot_id.


For the FortiADC TLS profile view, use section="load-balance client-ssl-profile NAME"
with the same full redaction and configuration read grant. This executes exactly
get load-balance client-ssl-profile NAME, which includes the displayed defaults.
Leave include_all and include_defaults false for this named view. The response
marks normalized_from_get=true on every page. Its config/edit/set wrapper is a
normalized representation of the returned colon fields, not raw or replayable
configuration. Values retain TLS versions, cipher lists and certificate references;
the same semantic policy removes secrets and hides unclassified fields.

The wrapper's edit name comes from the typed command selector. The measured GET
response has no independent object-name field, so the wrapper does not prove the
returned object's identity. The existing device-account-visible, incomplete and
requested-section-only metadata still applies. Empty or malformed responses are
refused; unknown fields use the existing redaction metadata. No referenced
certificate or private-key material is fetched.

## Find lines in a redacted configuration

config_read accepts contains and context for FortiOS minimal captures and for
FortiOS and FortiADC full captures (redaction="full", with or without
include_defaults). contains is a literal, case-sensitive substring of 1–64
printable ASCII characters; it is neither a regular expression nor a device
command. context is an integer from 0 to 10 and requires contains. Only already
redacted lines are searched. Hidden original values, removed credentials and
<UNVERIFIED> values cannot be searched or recovered.

For example, use contains="set status" and context=1 with the existing target,
platform, section and capture options. matched_lines counts matching lines;
total_lines counts all lines in the redacted snapshot. Overlapping context
appears once. No match returns an empty successful result.

Follow next_offset with the same snapshot_id, platform, section, redaction,
include_defaults, contains, context, content_sha256 and filter_sha256. Both
fingerprints are required for a filtered continuation. content_sha256 describes
the filtered bytes, while snapshot_sha256 describes the complete redacted
snapshot. filter_sha256 is an opaque keyed fingerprint binding the snapshot and
exact filter settings. A different filter, context, fingerprint, capture option
or expired view is refused; restart at offset 0. content_sha256 or
filter_sha256 without snapshot_id is refused before any device command.

Each snapshot retains at most one filtered view within the shared memory
budget, the target memory limit and the snapshot lifetime. Starting a different filter at offset 0 releases
that view before the new view is built, so a previous filtered continuation
must restart; if building fails, repeat a filter at offset 0 with the same
snapshot_id. Pages of an active
view do not reread the device or rescan the snapshot. Unfiltered pages retain
their existing interface and behavior. Configuration comparison always uses the
whole snapshot and remains independent of a filtered view.

## Optional FortiOS Wi-Fi REST access

Before enrollment complete the [FortiGate administrator checklist](fortios-wifi-rest.md#create-access-on-fortigate):
HTTPS management (`allowaccess https`) on the receiving interface, reachable
`admin-sport` matching `helper.fortios_rest_port` (default 443), source /32 trusthosts after NAT, root VDOM and HA checks,
a separate RO `netops-api-ro` access profile/API user, privately generated token,
and independently verified certificate trust. The recommended minimum, verified
on FortiGate-80F 8.0.2 build0251, is `wifi read` + `loggrp read`, other groups
`none` (including `authgrp`) and all `cli-*` disabled. All-read remains an
alternative. Keep the existing SSH account. Omit `set vdom` in single-VDOM mode;
use `set vdom "root"` only for multi-VDOM provisioning (runtime remains
unqualified there). Token generation requires an administrator with API-user
rights; the runtime read-only account cannot generate it.

| Optional Helper field | Value and validation |
| --- | --- |
| `helper.fortios_rest_port` | Optional whole number 1–65535, default 443; use the FortiGate management `admin-sport`, which may differ from SSL VPN on 443. With REST enrolled, `configure helper` requires this port in `egress.tcp_ports` or a TCP range. |
| `helper.fortios_rest_credential` | Name of an existing private vault record of kind `api-token`, with `login: null`; example reference `fortigate-wifi-api-ro`. Only the vault holds the token value. Valid only for FortiOS targets. |
| `helper.fortios_rest_certificate_sha256` | 64 lowercase hexadecimal digits of the independently verified leaf **DER certificate** SHA-256. Renewals/replacements or firmware certificate regeneration require independent re-verification and a pin update. |
| `helper.tls_ca_certificate` | Alternative trust via the validated public CA path described above, with SAN/hostname and validity verification. If CA and pin are both supplied, both must pass. |
| `helper.egress.tcp_ports` | Include the selected REST port (default 443, or its nonoverlapping allowed range) and preserve SSH access; the target address must also satisfy egress. |

REST uses `fortios_rest_port` throughout DNS resolution, egress checking,
socket connection and HTTPS, independently of inventory SSH `port`. Set it to
`admin-sport` when management HTTPS is not on 443; HTTP redirection cannot
substitute for the correct port. Non-root VDOM selection is also unsupported. Apply changes with the complete private stopped-instance
`configure helper` input; this does not merge a partial JSON fragment.

The proxy injects the token only for `wifi_clients`, `wifi_aps_live`, `wifi_rogue`
and `wifi_triage`; it never returns it. `target_scope` exposes only
`fortios_wifi_rest_enrolled` and the effective `fortios_rest_port`, never the credential value. Existing targets without
a token keep their SSH behavior; the three REST tools return `unsupported`.
See [MCP verification](fortios-wifi-rest.md#verify-access),
[troubleshooting](fortios-wifi-rest.md#troubleshooting) and
[rotation/revocation](fortios-wifi-rest.md#rotate-and-revoke).
