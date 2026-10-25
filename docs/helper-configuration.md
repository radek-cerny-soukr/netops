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

Each `helper` section requires `account_role`, `ssh_platform`, `enabled_queries` and all eight `egress` fields shown above. `tcp_ports` and `udp_ports` hold at most 256 unique whole numbers from 1 to 65535. `tcp_port_ranges` and `udp_port_ranges` hold at most 64 non-overlapping `[start, end]` pairs of whole numbers with 1 ≤ start ≤ end ≤ 65535, for example `[[1000, 2000]]`; other forms such as `"1000-2000"` or `{"start": 1000, "end": 2000}` are refused. A port listed in `tcp_ports` or `udp_ports` must not lie inside a range of the same protocol. The device address must be listed in `egress.addresses`; a device named by a DNS name needs `allow_dns` and the explicit IPv4 addresses it may resolve to. The SSH port is taken from the inventory and is not checked against `tcp_ports`; it must not lie inside `tcp_port_ranges` when the device has SSH queries or SFTP roots. The scope limits which enrolled targets and operations the Helper accepts; NetOps 1.0 does not install a host firewall, and it needs no legacy runner or egress-policy file. Choose platform-specific queries from `read_query_catalog`; enable only the required queries. FortiOS also requires independently verified standard output and `fortios_output_standard_verified: true`. For FortiOS, use `fortios` for `helper.ssh_platform`; `target_scope` reports its query-catalog name `fortinet`.

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

`read_inventory` lists the exact values an MCP caller may pass as query parameters. 71 of the 289 catalogue queries take a parameter; `read_query_catalog` names the inventory category of each parameter. A parameter is accepted only when its value is listed, character for character, in that category of the target; any other value is refused with `policy_scope` ("The requested operation is outside the enrolled target scope.") before the device is contacted, and the refusal does not count against `rate_limit`. Pass the values in the `parameters` argument of `ssh_read`, for example `{"target":"linux-a.example.invalid","platform":"linux","query":"interface_link","parameters":{"interface":"eth0"}}`. With the example, `interface_link` with `{"interface":"eth0"}` and `service_status` with `{"service":"ssh.service"}` are accepted; `eth1` or `cron.service` are refused.

Each category holds at most 256 unique, non-empty strings (`schema_paths`: 4096) of at most 128 characters without control characters, written in the form the category accepts:

| Category | Accepted value | Used by |
|---|---|---|
| `interfaces` | letters, digits and `_ . : / -`, starting with a letter or digit, at most 64 characters; it must also be valid for at least one enabled query that takes an interface (for example a FortiOS interface name has at most 15 characters and no `:` or `/`) | 43 catalogue queries; `fortios_diagnostics` |
| `addresses` | an IPv4 or IPv6 address in canonical form: no leading zeros, lowercase compressed IPv6, no zone index | 17 catalogue queries; `fortios_diagnostics` |
| `managed_switches` | `S` followed by 11 to 15 uppercase letters or digits | 5 FortiOS queries |
| `services` | letters, digits and `_ . @ -`, starting with a letter or digit, at most 128 characters | 2 Linux queries |
| `vlans` | a letter followed by up to 31 letters, digits, `_` or `-`; not `all`, `any`, `none`, `detail`, `ipv4`, `ipv6`, `tag`, `ports`, `virtual-router` or `statistics` | 2 EXOS queries |
| `certificates` | a letter followed by up to 78 letters, digits, `_`, `.` or `-`; not `all`, `any`, `none`, `detail` or `details` | 1 FortiOS query |
| `switches` | letters, digits and `_ . : -`, starting with a letter or digit, at most 64 characters | 1 FortiOS query |
| `schema_paths` | up to 32 words separated by single spaces, each word of letters, digits and `_ . + -` starting with a letter or digit | `schema_read` (FortiOS with `system_status` enabled) |
| `diagnostic_recipes` | `ping`, `traceroute`, `sniffer`, `sessions` or `flow` | `fortios_diagnostics` (FortiOS with `system_status` enabled) |
| `diagnostic_vdoms` | letters, digits and `_ . -`, starting with a letter or digit, at most 31 characters | `fortios_diagnostics` with a `vdom` argument |

`fortios_diagnostics` requires its recipe, address and interface to be listed in `diagnostic_recipes`, `addresses` and `interfaces`, and a VDOM, when given, in `diagnostic_vdoms`.

NetOps 1.0 has no supported way to provision the measured schema registry and library files required by `schema_read` and `fortios_diagnostics`. These two tools are therefore not supported workflows in NetOps 1.0, even when their `read_inventory` scopes are enrolled. Calls that reach the missing-registry check are refused with the generic MCP error `Role operation failed` before any connection to the device is attempted.

The other optional fields:

| Field | Form | Limit | Default | Purpose |
|---|---|---|---|---|
| `read_inventory` | object of the categories above, each a list of strings | 256 values per category, 4096 for `schema_paths`; 128 characters per value | `{}` | values allowed as query parameters |
| `sftp_roots` | list of absolute POSIX paths in canonical form: no trailing `/`, no `//`, no `..`, not `/` itself | 256 unique paths, 2000 characters each | `[]` | `sftp_stat` accepts a root and any path below it whose target, as the SFTP server resolves it, stays below the resolved root |
| `rate_limit` | `{"requests": N, "window_seconds": S}`, both whole numbers, both keys required | `requests` 1–60, `window_seconds` 1–3600 | 30 requests per 60 seconds | per-target limit on accepted device operations; a follow-up page (`offset` > 0) of `ssh_read` or `schema_read` is not counted; an exceeded limit is refused with `rate_limit` and `retry_after_seconds` |
| `fortios_output_standard_verified` | `true` or `false` | — | `false` | FortiOS `ssh_read`, `schema_read` and `fortios_diagnostics` are refused while it is `false` |
| `role_boundary` | `"catalogue"` | only with `account_role: "admin-bounded"`, which is accepted only for `ssh_platform: "ruckus_unleashed"` | absent | required companion of `admin-bounded`; refused with `read-only` |
| `snmp_credential` | `null` or the name of a vault record of kind `snmp-community` | — | `null` | `target_scope` reports it as `snmp_enrolled`; the SSH/HTTPS profile refuses `snmp_get`, so it enables no operation in NetOps 1.0 |

`sftp_roots` also makes the SSH port of the device an explicit egress port, so that port must not lie inside `tcp_port_ranges`. `target_scope` returns the stored `read_inventory`, `sftp_roots`, `rate_limit` and `snmp_enrolled` of a target.

A section that breaks any rule above is refused as a whole with `Invalid Helper inventory. Each helper section requires account_role, ssh_platform, enabled_queries and egress; check field types, target scope and credential references in docs/helper-configuration.md`; the message does not name the field, so compare the section with the tables above.

## Additional enrollment controls

See [Optional Helper fields](#optional-helper-fields). The `admin-bounded` account is accepted only on an explicitly supported platform without a read-only role, with `role_boundary: "catalogue"`; it remains an administrator on the device. See [account boundaries](../components/netops-helper/docs/read-only-accounts.md). The shipped SSH/HTTPS profile refuses SNMPv2c and FTP/FTPS even if historical engine fields are present.

Device roles are exactly `perimeter`, `internal` and `lab`; earlier Czech spellings are refused. A failed/refused Helper operation has MCP `isError: true` and preserves its structured error result. The error flag never authorizes a retry or a wider device scope.
