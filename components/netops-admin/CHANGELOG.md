# Changelog

## 0.2.0 - 2026-09-24

- Regress the exact FortiOS 8.0.0 build0167 address profile on FortiGate 80F, including enrollment and real timer returns. Add execution tests for firmware/profile isolation and document the command compatibility matrix and interactive account-provisioning confirmations.
- Require an operator enrollment that verifies an actual on-device timer return, independent check-account reads, notification and configured audit export. Bind the result to the device, firmware build, account/access-profile fingerprint, policy and profiles.
- Add FortiOS 7.6 static address-group membership and DHCP MAC reservation create/update/delete; add EXOS 33.7 tagged membership and native VLAN movement with complete inverses.
- Audit predicted and observed configurations using Auditor 0.2.5. Support operator-owned network/VLAN allowlists and protected groups, ports and management VLANs; refuse unavailable mandatory rules.
- Compare configuration outside the target across the full parsed snapshot and exclude only the current operation's safeguard. Refuse trailing newline input, preserve changed-finding detection, validate exporter numeric fields, record notification exceptions, save configuration when recovering an interrupted confirmation, handle measured EXOS output variants, and bound audit summaries without address/MAC values.
- Provide enrollment and operation examples. Keep the MCP surface limited to apply and status. Version 0.1.0 remains unpublished.

## 0.1.0 - internal milestone (not published)

Initial internal implementation.

- `netops-admin plan` and `netops-admin verify`: a request validated against a table profile and a snapshot, commands, inverse and predicted state; comparison of a later snapshot with the prediction.
- Profiles: FortiOS 8.0.0 build0167 `firewall address` and ExtremeXOS 33.7.1.6 `vlan`, each with create, update and delete, enabled only on firmware where the rollback was measured on a device. Snapshots are parsed with the netops-auditor parsers.
- `netops-admin apply` behind an on-device safeguard: a one-shot automation stitch on FortiOS, a Universal Port Manager profile and one-shot timer on ExtremeXOS. Journal synced before the first mutation, device lock, `request_id` deduplication, account checks before and after a change, device block after an unknown result, a failed return, a foreign change, an unexpected account or a change that could not be saved.
- Before a confirmation, a read-only check account reads the object and the auditor rules are evaluated on the new snapshot; both are also required to work before the change. A new finding of severity high or medium, an evaluation that does not complete, or a check account that sees another state stops the confirmation and lets the safeguard return the change.
- A new change on a device waits until the notification of its previous operation is delivered; `unblock` can waive it after a check of the channel.
- Other administrator sessions on the device are counted and recorded in the journal, the audit log and the notification.
- Optional `check_address` lets the check account use another management address.
- ExtremeXOS profile `ports`: update of the port display string, measured rollback in both directions.
- A fingerprint of the account entries is kept after each operation and compared before the next one and after the change; `unblock` resets it.
- On ExtremeXOS: refusal when the switch holds unsaved changes, firmware check, `save configuration` after a confirmation or a verified return.
- Commands for a person: `status`, `recover`, `notify-retry`, `unblock` and `undo`, which returns a confirmed operation as a new operation behind a new safeguard and refuses when the object changed since.
- MCP server with two tools, `admin_apply` and `admin_status`; it finishes a running operation when the client disconnects. `fastmcp` is an optional dependency pinned in `requirements-mcp.txt`.
- Limits set by the administrator: changes per device per hour, changes per day, refused requests per hour, plan size and journal capacity, besides the request size and text lengths.
- Audit log with a closed event schema and no free text; export limits read from a shipper status file (`scripts/export_status.py` for syslog-ng); ntfy notification recorded separately from the result.
- Component gate: import allowlist per module, no programs started from the package, version agreement of `pyproject.toml`, package and SBOM, and a content scan of every released file.
