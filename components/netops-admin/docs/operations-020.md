# Operations and enrollment in 0.2.0

Version 0.2.0 adds enrollment, an audit of the predicted configuration, and three operation profiles. Version 0.1.0 was an internal milestone and was never published.

## From installation to the first confirmed change

1. Install Core 0.2.4, Auditor 0.2.7 and Admin 0.2.2 as described in [installation](installation.md). Create separate write and check credentials and pin the device SSH host key.
2. Configure notification and a working audit exporter. Enrollment requires both. Restrict the device accounts and the admin host network access, and configure protected objects.
3. Put an operator policy in a local file. Set the device's `audit_policy` to its absolute path in `admin.json`. Requests and MCP tools cannot provide or replace this policy.
4. Run the appropriate enrollment command with an unused test subnet or VLAN tag:

   ```sh
   netops-admin enroll --config /etc/netops-admin/admin.json --device fw-lab --probe 192.0.2.254/32
   netops-admin enroll --config /etc/netops-admin/admin.json --device sw-lab --probe 3998
   ```

   Enrollment creates an unreferenced temporary object, verifies it through the check account, deliberately lets the on-device timer restore the original state, and verifies cleanup and notification. It takes at least the configured safeguard interval. An interrupted or failed run never grants permission to write; investigate, recover if needed, and enroll again.
5. Before the first change, `netops-admin doctor --config … --device …` lists every condition that is still missing or refused; `netops-admin preview --config … --device … --request …` shows the plan and the reasons `apply` would refuse a request, without changing anything. Submit one request using `apply` or MCP `admin_apply`. Read `result`, `reason`, notification and audit delivery separately. A configuration change marked `confirmed` with `reason: not persisted` requires investigation and blocks further changes. Use `undo` for a confirmed change that should be returned.

Enrollment binds the actual build, pinned device identity, access configuration, account and access-profile fingerprint, operator policy and profile files. Changing these requires another successful test. The enrollment probe namespace `netops-enroll-` is reserved. Enrollment is an operator CLI command, not an MCP tool. FortiOS 7.6.x and EXOS 33.7.x builds still need enrollment individually; FortiOS 8.0.0 remains limited to the measured address profile and build. FortiOS 7.4 and 8.0.1 or later are not supported.

## FortiOS command compatibility

The snapshot header selects the actual firmware. A configured `firmware` is an assertion that must match it, not a way to select another dialect. An unsupported profile/build is rejected before installing a safeguard or sending mutation commands.

| Command family | FortiOS 7.6.x | FortiOS 8.0.0 build0167 |
|---|---|---|
| Address `edit`, `set subnet`, `set comment`, `unset comment`, `delete` | Supported; measured on 7.6.7 build3704 | Supported; exact build only |
| Automation action, one-time scheduled trigger, stitch, readback and removal | Measured timer mechanism | Same measured timer mechanism |
| Snapshot and object `show`, system status/clock, administrator visibility and session list | Measured check commands | Measured check commands |
| Static address-group membership | Supported after enrollment | Rejected before device writes |
| DHCP MAC reservation create/update/delete | Supported after enrollment | Rejected before device writes |
| Other 8.0 builds or later firmware | Not applicable | Rejected; no fallback to 7.6 commands |

Shared commands are retained only within the tested profiles; one working command does not establish compatibility for the rest of the CLI. Enrollment remains mandatory for every actual device/build. Operator account provisioning has additional interactive confirmations on 8.0.0, described in [installation](installation.md); it is not an Admin operation.

## Operator policies

FortiOS example:

```json
{"version":1,"platform":"fortios","protected_groups":["critical-services"],"dhcp_networks":{"1":["192.0.2.0/24"]},"required_rules":["group-empty","group-dangling","group-cycle","dhcp-conflict","dhcp-subnet"]}
```

EXOS example:

```json
{"version":1,"platform":"exos","protected_ports":["23","24"],"management_vlans":["Mgmt"],"port_vlans":{"10":{"tagged":["guest","voice"],"untagged":["users","staging"]}}}
```

The EXOS membership operation requires an explicit VLAN allowlist for the selected port and exactly one known native VLAN. Protect every management and uplink port, including all aggregation members; protect management VLANs too. Link aggregation membership changes are refused. A native VLAN move accounts for EXOS automatic movement and renders a move back as its inverse.

Policy-dependent rules report when their policy is absent. Mandatory rules that cannot evaluate the snapshot refuse the operation. The predicted configuration is audited before installing a safeguard; the observed configuration is audited again before confirmation. New or changed high/medium findings refuse confirmation. A policy violation on the selected object is refused even if it already existed. The policy format is documented in Auditor's `docs/management-policy.md`.

## Request bodies

All requests also require `reason`, `user_request` and a unique `request_id`.

| Table | Key | Operation and changes |
|---|---|---|
| `firewall addrgrp` | existing static group | `update`, `{"member":["web-a","web-b"]}` replaces the complete member list; empty, missing and cyclic membership is refused |
| `system dhcp server/reserved-address` | server ID and reservation ID, e.g. `1:101` | `create`, `{"ip":"192.0.2.101","mac":"00:00:5e:00:53:01","description":"example"}`; `update` any supported attribute; `delete` with empty changes |
| `vlan-membership` | physical port number | `update`, `{"tagged":["guest"],"untagged":"users"}`; omitted attributes retain their values and an empty tagged list removes all tagged membership |

DHCP supports enabled regular IPv4 servers with MAC reservations and action `reserved`. A reservation must be a usable address in the server subnet and satisfy any narrower operator policy. Conflicting IP or MAC reservations are rejected. Unsupported reservation types are not converted. The inverse preserves numeric IDs; row order is not an identity.

Group and DHCP profiles are enabled only for the measured FortiOS 7.6 family. No profile writes firewall policies, routes, accounts or multiple objects in one request. Configuration verification is not a forwarding or DHCP lease test.

## Snapshot comparison boundary

FortiOS can re-encrypt local certificate password/private-key fields on every export ([vendor explanation](https://community.fortinet.com/fortigate-3/technical-tip-constant-changing-of-password-and-encrypted-private-key-value-in-certificate-section-136613)). Lab reads also observed changing encrypted SAE passwords under wireless-controller VAP. The comparison normalizes only ENC payloads in those exact fields, while checking their presence, surrounding configuration and all administrator entries. A change to the plaintext behind these opaque fields cannot be detected from these snapshots. All other encrypted fields remain compared. Do not interpret a matching snapshot as verification of certificate private keys, Wi-Fi secrets or forwarding.

## EXOS timer persistence

Every rollback UPM profile begins with `configure cli mode persistent`. Without it, timer-driven port/VLAN changes can affect the live port while remaining absent from the persistable configuration ([Extreme profile rules](https://documentation.extremenetworks.com/Switch%20Engine%20v33.4.1%20User%20Guide/content/documents/Switch_Operating_Systems/Switch_Engine/User_Guide/profile_rules.shtml)). The safeguard content check includes this command. Rollback must match the configuration snapshot before cleanup and saving; a live port read alone is insufficient.

The rollback script also sets `configure cli mode scripting ignore-error`, so an inverse delete of a member that was never added by a partially failed write cannot prevent the remaining inverse commands from running. This is best-effort execution only: the unchanged full postcheck must still prove the return before it is reported as successful.
