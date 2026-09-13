# Read-only target accounts

NetOps Helper phase 1 assumes that every target account is prevented from mutating the target by authorization enforced on the target or its external AAA service. Client validation, named templates, redaction, and egress rules are additional containment. They are not substitutes for device-side permissions.

No universal vendor configuration recipe is provided here. Role names, privilege semantics, command authorization, and inherited permissions vary by platform, release, feature license, VDOM/virtual system, and AAA backend. Build the role from current vendor guidance, review the effective rules, and test the exact deployed path.

## Required properties

- Use one dedicated identity for NetOps Helper reads; never reuse an administrator, automation writer, backup, or human operator account.
- Bind it to the smallest vendor-native role, access profile, login class, parser view, or external command-authorization policy that permits the enabled named queries.
- Deny configuration mode and all mutation, every file-content upload/download, software installation, reboot, process control, account management, secret export, support bundles, shell escape, privilege escalation, and access to future write-service credentials. Grant only the SFTP metadata and FTP/FTPS directory-list permissions actually required by Phase 1.
- Explicitly deny full running, startup, candidate, committed, saved, backup, and exported configuration reads, plus generic HTTP response-body and remote file-content reads. Phase 1 neither needs nor exposes them.
- Do not grant arbitrary log browsing. The only deliberately log-oriented Phase-1 query is a fixed, opt-in, one-hour Linux service journal query.
- Scope visibility to the smallest operational domain, VDOM, virtual system, routing instance, or tenant that still permits the required troubleshooting.
- Keep Phase-1 credentials separate from every future configuration/write service.
- Log authentication and command authorization success/failure on the target or AAA service, with retention sufficient for deployment tests and incident review.
- Revalidate permissions after firmware, role, AAA, Netmiko, or query-catalog changes.

The local `account_role: "read-only"` field records an operator assertion. The proxy and server reject a target without it, but they cannot prove remote enforcement.

## Platform expectations

### FortiOS

Use a dedicated administrator bound to a reviewed read-only access profile, with administrative domain/VDOM scope restricted where applicable. Do not assume that a profile described as read-only excludes every diagnostic, execute, backup, or secret-bearing operation; test explicit denial of those families.

Before enrollment, a separate administrator must persistently set console output to `standard` in the applicable global context and verify the effective setting. Only then set `fortios_output_standard_verified: true`. NetOps Helper's FortiOS driver deliberately skips Netmiko paging setup and cleanup so it never enters configuration merely to change or restore paging. SHA-1 key exchange and the `ssh-rsa` host key algorithm are refused for every platform, not only FortiOS. Verify both the exact wire session and target AAA log in a controlled test environment.

### Extreme Switch Engine / ExtremeXOS

Use a dedicated read-only role or externally authorized network-login identity. Confirm the role can execute only the enabled `show` and read-only diagnostic commands for the intended switch/slot scope. Deny configuration, save, download/upload, process/debug, support collection, and shell-like facilities.

Role behavior differs across releases and external RADIUS/TACACS policy. Test each enabled catalog command, including typed port forms, and verify that malformed, list, range, wildcard, and broad port selectors remain unavailable through the account.

### Cisco IOS

Use a dedicated low-privilege identity with a parser view or external AAA command authorization that permits the exact enrolled command set. Numeric privilege level alone may be too broad or too narrow and must not be treated as proof.

Confirm there is no path to enable mode, configuration mode, running/startup configuration display, file display/copy, debug, reload, support collection, embedded scripting, or shell escape. Test the exact interface grammar and every enabled query over the same SSH transport.

### Cisco IOS-XE

Use a dedicated identity with exact command authorization, not a reused administrator or broad automation account. IOS-XE adds platform and software-management surfaces beyond classic IOS; deny install/package, guestshell/application hosting, file-system, diagnostic archive, reload, debug, and configuration/export capabilities.

Permit only the catalog commands actually enrolled for the target and validate both positive reads and negative commands through the production AAA policy. Treat a role label or privilege number as insufficient without command logs.

### Cisco NX-OS

Use a dedicated NX-OS RBAC role or external AAA policy with the smallest required show-command rules and VDC/tenant scope. Do not assume a built-in operator role is automatically a perfect match for this catalog.

Deny configuration, checkpoint/rollback, file and bootflash access, guestshell/bash, install, reload, debug, Ethanalyzer/capture, support bundles, and full configuration display/export. Verify rule ordering and inherited permissions, then test every enabled command against the exact VDC and software release.

### Arista EOS

Use a dedicated EOS role or AAA command-authorization policy that permits only the enrolled operational commands. Restrict VRF and tenant visibility where the authorization system permits it.

Deny enable/configuration paths, bash or shell access, file and extension management, event-handler changes, reload, debug, packet capture, support bundles, and configuration display/export. Test role inheritance and command-regex behavior with the actual EOS release instead of relying on a generic read-only label.

### Junos OS

Use a dedicated login class with the minimum operational permissions and explicit allow/deny command policy. Restrict logical-system, routing-instance, or tenant visibility where applicable.

Do not grant configuration or maintenance permissions merely to make operational commands work. Explicitly deny configuration display/export, `configure`, file operations, request/maintenance actions, shell access, support collection, packet capture, and secret-bearing outputs. Validate both classic and ELS target profiles separately because accepted interface syntax and query catalogs differ.

### Linux

Use an unprivileged account with no Docker socket/group access, no writable operational groups, no package/service/process-control rights, and no general sudo. Membership that grants broad journal, network namespace, disk, virtualization, or container visibility must be reviewed as an effective privilege grant.

If an enabled read needs elevation, expose an exact root-owned dispatcher or narrowly parameterized wrapper for that query; do not provide a shell-capable sudo rule. Constrain SSH to the expected command path where practical and deny forwarding, PTY/shell use, arbitrary environment injection, redirection, pipelines, and alternate commands. The fixed one-hour `journalctl -u <enrolled-service>` query must not become general journal access.

## Session-driver caveat

For non-FortiOS network platforms, NetOps Helper currently uses the upstream Netmiko platform driver. A driver can perform platform-specific session preparation, prompt discovery, terminal-width/paging setup, or cleanup in addition to the selected catalog command. Source review and unit tests over project code do not prove what every driver/release/device combination sends on the wire.

The account or external AAA policy must therefore reject any unexpected setup or cleanup command safely. Before production enrollment and after dependency/firmware changes, observe the SSH/AAA command log or a controlled mock or test endpoint and compare the full session with the reviewed expectation. FortiOS has an additional wire-level regression test because its upstream paging behavior required a dedicated no-write subclass; equivalent live denial testing remains necessary for all vendors.

## Enrollment test procedure

Perform these tests with the exact identity, SSH platform selection, AAA path, VDOM/VDC/logical-system scope, and target release intended for deployment.

1. Review the target's enabled query list and typed inventories before connecting.
2. Positively test every enabled named query and required typed value; remove permissions for unused queries.
3. Inspect target/AAA logs for the complete session, including setup and cleanup around the named command.
4. Negatively test configuration entry and mutation, save/commit/copy, reboot/reload, install/package, account and role changes, debug/process controls, packet capture, support bundles, shell escape, file writes, and privilege escalation.
5. Negatively test running/startup/full/backup/candidate/committed configuration display or export and secret-bearing file/support commands.
6. Verify arbitrary CLI, pipes, redirection, command separators, wildcard/range/list selectors, and unenrolled typed inventory values cannot be introduced through NetOps Helper.
7. Verify authentication or authorization failure does not lock out another required operational account and produces a useful target-side audit event.
8. Record the firmware, role/AAA policy revision, Netmiko version, test date, allowed command set, denied families, and reviewer.
9. Repeat the procedure after any relevant change. Do not set `account_role: "read-only"` or the FortiOS output verification flag until the test passes.

A successful read test alone is insufficient. Enrollment is complete only when allowed reads succeed, forbidden actions are demonstrably denied, and the full session matches the reviewed authorization boundary.
