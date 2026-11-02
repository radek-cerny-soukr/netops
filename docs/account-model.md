# Device accounts and roles

NetOps has three roles that reach devices: Helper reads, Auditor collects configuration and Admin changes it. Each role uses its own device account. This page explains which account each role needs and why the account matters as much as NetOps itself. The exact access profiles are in [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md).

A `super_admin` account for every role makes NetOps work, but it is not the recommended way: it has full rights on the device, it removes the separation between reading and changing, and a leaked key or password then acts with every permission of the device. Use a dedicated read-only account for Helper and a separate account for Admin changes.

## The MCP endpoint is not a CLI firewall

NetOps limits what it sends. The MCP scope, the fixed query catalogue, typed parameters, enrolled destinations, egress rules and the pinned host key decide which commands a role issues to which device. They do not change what the device account is allowed to do. If the credential leaks, or a defect lets an unexpected command through, the device enforces only the permissions of that account.

Security therefore comes from two independent layers:

- **NetOps:** catalogue, scope, egress, host-key pin, audit.
- **The device or its AAA service:** the account's role or access profile, `trusthost` or an equivalent source restriction, and a log of authentication and command authorization.

Neither layer replaces the other. A role label such as read-only or `super_admin` is an operator choice recorded in the inventory; NetOps cannot prove what the device enforces. Test the deployed account on the device itself.

## Summary

| Role | Device account | Why | Enforced by NetOps |
|---|---|---|---|
| Helper, catalogue reads | dedicated read-only account with the smallest role that runs the enabled queries | Helper only reads; a read-only account limits the damage of a leaked credential | `account_role: "read-only"` is required, except the `admin-bounded` platform exception; remote enforcement is not proved |
| Helper, opt-in `config_read` / `config_diff` (FortiOS) | the same read-only account, with CLI show allowed | the capture runs `show` | the opt-in `config_access` field |
| Auditor, FortiOS SSH collection | `super_admin` administrator restricted by `trusthost` | only `super_admin` sees every administrator, API user and access profile in `show` | no; the boundary is the fixed command table and the pinned host key |
| Auditor, EXOS collection | administrator | full EXOS configuration needs administrator privilege | no |
| Admin, write | a dedicated administrator for the enrolled operations; on FortiOS 8.0.1 and later it must be `super_admin` with a password credential (webhook safeguard); on FortiADC a system administrator (health precheck) | Admin changes configuration | FortiOS 8.0.1 and later: yes, `super_admin` and the password credential are checked before any write |
| Admin, check | a second account that reads the device independently | identity and readback must not rely on the write account | yes: the check credential must differ from the write credential |

## Helper

Use one dedicated identity for Helper reads. Never reuse an Admin, Auditor, backup or human account. The measured access profiles of every role on FortiOS and FortiADC, the device answers without each right, and the general requirements are in [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md); this page only explains the model.

Two levels of read access exist:

- **Minimum read-only account.** Allows the enabled catalogue queries and nothing more. On FortiOS the catalogue uses `get` and `diagnose` (`cli-get`, `cli-diagnose`); three reads and the diagnostics also use `execute` (`cli-exec`). The catalogue sends no `show`, so leave `cli-show` disabled; with `cli-show enable` a bare `show` returns the full configuration. Some FortiOS reads (Wi-Fi controller, DNS cache, IPsec tunnel statistics) are refused by every read-only profile measured and need a separate `admin-bounded` login.
- **Read-only account with configuration reads.** Needed only when a FortiOS target opts in to `config_read` and `config_diff`. The profile must allow CLI get and CLI show (on FortiOS 8.0.2: `cli-get enable`, `cli-show enable`), with `cli-config` disabled and the relevant system and network groups read-only. Grant this only to targets that enable `config_access`. See [optional configuration captures](helper-configuration.md#optional-configuration-captures).

Ruckus Unleashed has no read-only account. It is enrolled as `account_role: "admin-bounded"` with `role_boundary: "catalogue"`: the account remains an administrator and only the catalogue and session handling limit what Helper sends.

## Auditor

On FortiOS the Auditor collects with a `super_admin` administrator (decision of 17 September 2026). A read-only profile with `cli-show enable` returns the same top-level sections, but `system admin` and `system api-user` list only the account's own entries, `system accprofile` leaves out `super_admin`, and nothing in the output says so. Rules about administrators need the complete list: a snapshot without a `super_admin` administrator leaves them `not-evaluated` (`admin-visibility-unproven`) and the run ends with exit code 3.

The Auditor account can therefore write. Its read boundary is the fixed collection command table (`get system console`, `show`), the pinned host key and the absence of any other command in the channel, not the profile. Restrict the account with `trusthost` to the collector and log its sessions on the device. For REST collection the token's access profile decides both the content and whether the token could write. See [collection channels](../components/netops-auditor/docs/channels.md).

Full EXOS configuration collection requires administrator privilege.

The Auditor MCP tools read stored findings only; they never contact a device.

## Admin

Admin needs two accounts per device:

- a **write account** with permissions for the enrolled operations only (on FortiOS 8.0.1 and later `super_admin`, see below);
- an independent **check account** that verifies device identity and readback.

Admin audits the configuration it reads with the write account. On FortiOS that account sees only the administrators whose profile its own contains, by default only itself, so administrator rules stay `not-evaluated` (`admin-visibility-unproven`). A catalogue rule that is `not-evaluated` before the change for `admin-visibility-unproven` or `section-missing: <section>` does not stop the change when it is `not-evaluated` for the same reason afterwards: `admin_preview` lists it in `audit_unevaluated` and the `audit_passed` step names the reasons. A rule that becomes `not-evaluated` or changes its reason refuses the change or reverts it; any other reason, and every rule the audit policy or the planned table requires, always refuses.

The configuration refuses a check credential equal to the write credential (`different-credential`), and Admin also refuses the same login for both. Configuration alone grants no write authorization: enrollment, request IDs, safeguards, limits, the journal and verified return remain required. See [Admin configuration](admin-configuration.md).

Supported firmware is listed in [verified support](verified-support.md). On FortiOS 8.0.1 and later Admin uses the webhook safeguard: the write account must then be a password credential, because FortiOS asks for the administrator password when it generates the API key, and must have the access profile `super_admin`, because only `super_admin` may create the API user of the safeguard: with any other profile `config system api-user` answers `command parse error before 'api-user'` on FortiOS 8.0.2 build0251, also with every permission group `read-write` and `cli-exec enable`. Limit the account with trusted hosts to the Admin host. Preflight and `admin doctor` refuse a write account without `super_admin` before any device write ([what to check](admin-configuration.md#write-account-for-the-webhook-safeguard-what-to-check)). A write account with an SSH key only is refused before any device write on these builds; this is an accepted limitation of NetOps 1.0.5, approved by the project maintainer. On FortiOS 8.0.2 build0251 only `firewall policy` and `firewall address` are listed.

## Separate credentials across roles

Each role has its own vault, UID/GID and private state inside the container. NetOps does not compare device logins across roles: nothing prevents enrolling one device login for Helper, Auditor and Admin. Keeping the Helper, Auditor and Admin accounts separate on every device is a recommendation that NetOps does not enforce; only the Admin write and check accounts are checked. A Helper credential that could also write would remove the read-only layer.

## Other vendors

The same model applies to every platform. Vendor role names, privilege levels and command authorization differ by platform, release and AAA backend, so this page gives no universal recipe. The documented accounts and their tested scope are in [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md) and [verified support](verified-support.md). A platform appears in the summary above only where NetOps documents a measured account.
