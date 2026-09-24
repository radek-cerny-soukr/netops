# Configuration management policy

The management rules complement the original platform rules. FortiOS checks static address-group membership, cycles, visible address references and active MAC-based DHCP reservations. EXOS checks visible VLAN membership and optional operator constraints. The findings contain object identifiers, rule codes and counts, not configuration fragments, reservation addresses or MAC values.

Unused addresses and VLANs without visible ports are informational. They can be legitimate staging objects. Missing descriptions are not findings. A missing native VLAN is a blocking policy finding only on explicitly managed ports; multiple native VLANs are reported as outside the supported single-native-VLAN model.

Both `run` and `collect` accept `--policy /absolute/operator-policy.json`. The optional file is version 1, has a platform, and is validated with unknown and duplicate keys rejected. The report includes `rule_coverage`: evaluated, not-evaluated or not-configured. A rule named in `required_rules` must be evaluated. A changed policy changes the audit rules-version digest. Existing suppressions remain specific to rule and object; they do not authorize changes through Admin.

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

The parsers evaluate supported configuration syntax. Unsupported membership forms fail rather than being interpreted as an empty membership. Configuration visibility and live forwarding are separate: a successful audit is not a traffic test. FortiOS VDOM scope remains unsupported.

Admin loads this file through each device's `audit_policy` path. MCP change requests cannot supply or modify a policy. Admin audits the predicted configuration before installing a safeguard, then the observed configuration before confirmation. It blocks new blocking findings, changed evidence on existing blocking findings and remaining blocking findings on the affected object under an explicit policy. It checks configured protected objects separately. Unrelated historical findings can remain.

Every new rule has positive and negative configuration fixtures and, where needed, a policy fixture. The management suite evaluates each rule in isolation; the existing platform suites retain isolated regression tests of their original rules. CLI and Admin integration tests exercise the complete catalogues.

Sources: FortiOS 7.6 CLI reference for `config firewall addrgrp` and `config system dhcp server`; Switch Engine 33.7.1 command references for `configure vlan add ports` and `configure vlan untagged-ports auto-move`. Firmware-specific execution support is documented by Admin, independently of static audit coverage.

## Policy history

Stored history for a device is bound to its operator policy digest. Changing, adding or removing that policy requires a separate store for the new policy. A run refuses before recording instead of marking findings under the old policy as gone or reusing its accepted baseline. Run without a store to preview a new policy first.
