# Configuration management policy

The management rules complement the original platform rules. FortiOS checks static address-group membership, cycles, visible address references and active MAC-based DHCP reservations. EXOS checks visible VLAN membership and optional operator constraints. The findings contain object identifiers, rule codes and counts, not configuration fragments, reservation addresses or MAC values.

Unused addresses and VLANs without visible ports are informational. They can be legitimate staging objects. Missing descriptions are not findings. A missing native VLAN is a blocking policy finding only on explicitly managed ports; multiple native VLANs are reported as outside the supported single-native-VLAN model.

Both `run` and `collect` accept `--policy /absolute/operator-policy.json`. The optional file is version 1, has a platform, and is validated with unknown and duplicate keys rejected. It must be a regular file of at most 256 KiB: one byte more is refused as `policy is larger than 262144 bytes`, and a pipe or a device such as `/dev/zero` as `policy is not a regular file`, without waiting for a writer - and a refused policy is named with its path and the reason, such as the line and column of a JSON error. The report includes `rule_coverage`: evaluated, not-evaluated or not-configured, and the per-rule `rule_status` described in [`configuration.md`](configuration.md#rule-status). A rule named in `required_rules` must be evaluated, otherwise the run is refused; a management rule outside `required_rules` is advisory, and its `not-evaluated` state is reported without failing the run. A management rule that is not evaluated reports no findings. A changed policy changes the audit rules-version digest. Existing suppressions remain specific to rule and object; they do not authorize changes through Admin.

FortiOS example:

```json
{
  "version": 1,
  "platform": "fortios",
  "required_rules": ["address-policy"],
  "address_networks": ["192.0.2.0/24"],
  "dhcp_networks": {"1": ["192.0.2.0/24"]},
  "protected_groups": ["management"]
}
```

EXOS example:

```json
{
  "version": 1,
  "platform": "exos",
  "required_rules": ["vlan-policy", "port-policy", "port-native"],
  "vlan_tags": [[1, 100], [300, 399]],
  "port_vlans": {
    "10": {"tagged": ["guest"], "untagged": ["users", "staging"]}
  },
  "protected_ports": ["12", "13"],
  "management_vlans": ["management"],
  "description_glob": "user-*"
}
```

An allowlist constrains only its declared scope. Network constraints apply to ipmask address objects. DHCP constraints are per server, and otherwise use its configured gateway and netmask. A missing or invalid subnet is not treated as a clean reservation. Non-reserved actions, option82 entries and disabled DHCP servers are outside the active MAC-reservation checks. This does not prove the absence of conflicts with live leases or other DHCP servers.

The parsers evaluate supported configuration syntax. Unsupported membership forms are never interpreted as an empty membership: the rules that depend on them are `not-evaluated` (`unsupported-membership-form`), and a rule named in `required_rules` refuses the run. Configuration visibility and live forwarding are separate: a successful audit is not a traffic test. FortiOS VDOM scope, including a dump wrapped in a top-level `config global` block, remains unsupported.

EXOS coverage follows the content of the snapshot, not its module headers: the five EXOS rules are evaluated when the snapshot carries at least one active `create vlan`, `configure vlan` or `configure ports ... display-string` command, with or without a `# Module vlan configuration.` header, and a header without such a command is `not-evaluated` (`no-vlan-content`). The script body of a UPM profile, from `create upm profile` to the closing `.`, is not active configuration for any rule; an unterminated profile leaves the whole catalogue `not-evaluated`.

Port lists are expanded as single ports, comma lists and ranges within one slot (`5-8`, `2:1-2:4`). `all` and a range across slots (`1:1-2:4`) need the port list of the switch, which the auditor takes from the snapshot: the union of the lists in `configure vr <name> add ports` and `configure vr <name> delete ports` - the same rendering Admin compares with the live port list. A list that itself uses `all` or a cross-slot range, as a stacked switch may print it, leaves the port list unknown; this has not been measured against a stack. A cross-slot range then covers the ports of that list between its two ends. Where the snapshot carries no such list, or one of the ends is not in it, `port-policy` and `port-native` (for VLAN membership) or `port-description` (for descriptions) are `not-evaluated` with the reason `unresolved-port-list`; the run never ends in a traceback. The VR lists of a switch whose ports are spread over several virtual routers make `all` cover every port of the switch, including ports of another router.

Admin loads this file through each device's `audit_policy` path. MCP change requests cannot supply or modify a policy. Admin audits the predicted configuration before installing a safeguard, then the observed configuration before confirmation. It blocks new blocking findings, changed evidence on existing blocking findings and remaining blocking findings on the affected object under an explicit policy. It checks configured protected objects separately. Unrelated historical findings can remain.

Every new rule has positive and negative configuration fixtures and, where needed, a policy fixture. The management suite evaluates each rule in isolation; the existing platform suites retain isolated regression tests of their original rules. CLI and Admin integration tests exercise the complete catalogues.

Sources: FortiOS 7.6 CLI reference for `config firewall addrgrp` and `config system dhcp server`; Switch Engine 33.7.1 command references for `configure vlan add ports` and `configure vlan untagged-ports auto-move`. Firmware-specific execution support is documented by Admin, independently of static audit coverage.

## Policy history

Stored history for a device is bound to its operator policy digest. Changing, adding or removing that policy requires a separate store for the new policy. A run refuses before recording instead of marking findings under the old policy as gone or reusing its accepted baseline. Run without a store to preview a new policy first.
