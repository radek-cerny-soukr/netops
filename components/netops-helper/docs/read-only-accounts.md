# Read-only target accounts

The NetOps Helper engine assumes that every target account is prevented from mutating the target by authorization enforced on the target or its external AAA service. Client validation, named templates, redaction, and egress rules are additional containment. They are not substitutes for device-side permissions.

No universal vendor configuration recipe is provided here. Role names, privilege semantics, command authorization, and inherited permissions vary by platform, release, feature license, VDOM/virtual system, and AAA backend. Build the role from current vendor guidance, review the effective rules, and test the exact deployed path.

## Required properties

- Use one dedicated identity for NetOps Helper reads; never reuse an administrator, automation writer, backup, or human operator account.
- Bind it to the smallest vendor-native role, access profile, login class, parser view, or external command-authorization policy that permits the enabled named queries.
- Deny configuration mode and all mutation, every file-content upload/download, software installation, reboot, process control, account management, secret export, support bundles, shell escape, privilege escalation, and access to future write-service credentials. Grant only the SFTP metadata permissions required by enabled queries. FTP/FTPS is refused by the SSH/HTTPS profile.
- Explicitly deny full running, startup, candidate, committed, saved, backup, and exported configuration reads, plus generic HTTP response-body and remote file-content reads. The Helper neither needs nor exposes them.
- Do not grant arbitrary log browsing. The only deliberately log-oriented Helper query is a fixed, opt-in, one-hour Linux service journal query.
- Scope visibility to the smallest operational domain, VDOM, virtual system, routing instance, or tenant that still permits the required troubleshooting.
- Keep Helper credentials separate from every Admin or other write service.
- Log authentication and command authorization success/failure on the target or AAA service, with retention sufficient for deployment tests and incident review.
- Revalidate permissions after firmware, role, AAA, transport, or query-catalog changes.

The local `account_role: "read-only"` field records an operator assertion. For platforms with a read-only role, the proxy and server require this declaration, but they cannot prove remote enforcement. The explicit platform exception below uses a different declaration.

A platform that has no read-only account at all is enrolled truthfully instead: `account_role: "admin-bounded"` together with `role_boundary: "catalogue"` states that the account can do everything on the device and that the only boundary is the Helper's fixed query catalogue and session handling. The inventory accepts it only for an `ssh_platform` on the fixed list of platforms without a read-only account, today only `ruckus_unleashed`; `admin-bounded` without `role_boundary: "catalogue"`, on any other platform, or a `role_boundary` next to `read-only` fails the inventory as `role_rejected`. Every other platform still accepts only `read-only`. The proxy forwards and reports the role exactly as enrolled (`admin-bounded` and `role_boundary` in the authentication context and in `target_scope`), never as `read-only`, and the server accepts `admin-bounded` only with the same boundary and platform. Device output stays untrusted either way.

## Platform expectations

### FortiOS

Use a dedicated administrator bound to a reviewed read-only access profile, with administrative domain/VDOM scope restricted where applicable. Do not assume that a profile described as read-only excludes every diagnostic, execute, backup, or secret-bearing operation; test explicit denial of those families.

Before enrollment, a separate administrator must persistently set console output to `standard` in the applicable global context and verify the effective setting. Only then set `fortios_output_standard_verified: true`. The helper sends no preamble at all on FortiOS - one `ssh` process carries the catalogue command and nothing else - so it never enters configuration to change or restore paging, and it also never restores a pager somebody else changed. Modern defaults refuse SHA-1 key exchange and `ssh-rsa` host keys. An explicitly selected per-device `legacy_ssh` profile with a pinned host key enables only its documented algorithms: `rsa-sha1` permits the host-key algorithm; `rsa-sha1-dh14` additionally permits only `diffie-hellman-group14-sha1`. Verify both the exact wire session and target AAA log in a controlled test environment.

The FortiOS 8.0.0 profile independently restricts permissions for enabled get/diagnose queries; persistent configuration changes and full export must remain denied; separately enrolled diagnostic actions retain their explicit permission boundary. A read-profile prompt can use `$` instead of `#`. FortiOS connections use a per-device lane with five-second spacing and a pinned-key scan cache of ten minutes; those transport limits do not prove read-only permission.

A FortiOS 8.0.1 profile with `cli-show enable` can expose full configuration even when secrets are masked. Helper uses get/diagnose commands rather than show; keep `cli-show disable` and independently verify remaining permissions. A profile label does not establish the deny boundary.

### Extreme Switch Engine / ExtremeXOS

Use a dedicated read-only role or externally authorized network-login identity. Confirm the role can execute only the enabled `show` and read-only diagnostic commands for the intended switch/slot scope. Deny configuration, save, download/upload, process/debug, support collection, and shell-like facilities.

Role behavior differs across releases and external RADIUS/TACACS policy. Test each enabled catalog command, including typed port forms, and verify that malformed, list, range, wildcard, and broad port selectors remain unavailable through the account.

**Unsupported EXOS diagnostic:** the former sharing query (show sharing and its variants) is excluded on both virtual and physical platforms because complete output accompanies native STATUS=-6 and SSH exit-status 250. It is unsafe to treat that output as successful completion. Remove sharing from enabled_queries before upgrading; inventory validation refuses it. See [the measured restriction](vendor-cli-references/extreme-switch-engine.md#unsupported-show-sharing).

The ExtremeXOS 33.7.1 user-level profile excludes show accounts and show configuration. Some catalogue reads can return complete output with status 250; distinguish device CLI errors, command status and answer completeness. Port reads require one enrolled port and feature permissions. This read profile neither grants mutation nor establishes every build's compatibility.

Compatibility scope: ExtremeXOS 33.6.1.14 virtual image with a user-level RSA account and explicit legacy_ssh: "rsa-sha1". Commands absent from the image are reported as device_cli_error; a virtual-image query contract is not universal hardware support.

### Cisco IOS

Use a dedicated low-privilege identity with a parser view or external AAA command authorization that permits the exact enrolled command set. Numeric privilege level alone may be too broad or too narrow and must not be treated as proof.

Confirm there is no path to enable mode, configuration mode, running/startup configuration display, file display/copy, debug, reload, support collection, embedded scripting, or shell escape. Test the exact interface grammar and every enabled query over the same SSH transport.

Compatibility scope: IOSv 15.9(3)M12 and IOSvL2 15.2(20200924), privilege-1 RSA accounts and exec-channel transport. Unsupported or unauthorized commands can return Line has invalid autocommand with exit status 0; Helper reports the refusal as device_cli_error. Their SHA-1-only key exchange requires the explicit per-device legacy exception. Privilege 1 is a bounded profile, not a universal authorization recommendation.

### Cisco IOS-XE

Use a dedicated identity with exact command authorization, not a reused administrator or broad automation account. IOS-XE adds platform and software-management surfaces beyond classic IOS; deny install/package, guestshell/application hosting, file-system, diagnostic archive, reload, debug, and configuration/export capabilities.

Permit only the catalog commands actually enrolled for the target and validate both positive reads and negative commands through the production AAA policy. Treat a role label or privilege number as insufficient without command logs.

Compatibility scope: IOS-XE 17.18.2 IOL router and L2 images with privilege-1 RSA accounts. Feature availability differs by image; privilege and unsupported-command refusals remain device_cli_error even with exit status 0. Account authorization and host-key probing must be verified for each deployment.

### Cisco NX-OS

Use a dedicated NX-OS RBAC role or external AAA policy with the smallest required show-command rules and VDC/tenant scope. Do not assume a built-in operator role is automatically a perfect match for this catalog.

Deny configuration, checkpoint/rollback, file and bootflash access, guestshell/bash, install, reload, debug, Ethanalyzer/capture, support bundles, and full configuration display/export. Verify rule ordering and inherited permissions, then test every enabled command against the exact VDC and software release.

Compatibility scope: Nexus 9300v and 9500v NX-OS 9.3(12), network-operator role and RSA keys. Permission-denied and syntax refusals are device_cli_error. HSRP, VRRP and vPC queries require their features to be enabled; the role and virtual-image profile do not imply every hardware feature.

### Arista EOS

Use a dedicated EOS role or AAA command-authorization policy that permits only the enrolled operational commands. Restrict VRF and tenant visibility where the authorization system permits it.

Deny enable/configuration paths, bash or shell access, file and extension management, event-handler changes, reload, debug, packet capture, support bundles, and configuration display/export. Test role inheritance and command-regex behavior with the actual EOS release instead of relying on a generic read-only label.

Compatibility scope: Arista EOS 4.36.1F container and virtual images, network-operator role and ed25519 keys. Privilege and invalid-command refusals are reported as device_cli_error; feature-absence responses can remain successful reads. The profile does not establish hardware or AAA-command compatibility.

### Junos OS

Use a dedicated login class with the minimum operational permissions and explicit allow/deny command policy. Restrict logical-system, routing-instance, or tenant visibility where applicable.

Do not grant configuration or maintenance permissions merely to make operational commands work. Explicitly deny configuration display/export, `configure`, file operations, request/maintenance actions, shell access, support collection, packet capture, and secret-bearing outputs. Validate both classic and ELS target profiles separately because accepted interface syntax and query catalogs differ.

Compatibility scope: vJunos-switch 26.2R1.7 with the built-in read-only login class and ed25519 keys. Configuration and unknown-command refusals are device_cli_error even when the command exits with status 0. A root account has different credential requirements and is not the read-only profile.

### Ruckus Unleashed

The documented Unleashed 200.13 profile has no read-only device account. Enrolled show commands require the privileged context reached with enable, where the credential can also change the device. Enrollment requires `account_role: "admin-bounded"` and `role_boundary: "catalogue"` only where device-level privilege is acceptable; the catalogue does not reduce that privilege. A restricted external-authentication profile is outside this documented scope.

The helper's own boundary is narrower than the account's: the session never enters `config`, never sends `exit` (which saves in a configuration context), and closes the terminal instead. The exact bytes are pinned by `tests/test_ssh_wire_safety.py`.

The access point asks for the password a second time inside its shell and echoes it on the terminal. The whole login phase is therefore discarded and never reaches an output, an error or an audit record. The device also offers only the `ssh-rsa` host key algorithm, so it needs `legacy_ssh: "rsa-sha1"` and its pin.

### Linux

Use an unprivileged account with no Docker socket/group access, no writable operational groups, no package/service/process-control rights, and no general sudo. Membership that grants broad journal, network namespace, disk, virtualization, or container visibility must be reviewed as an effective privilege grant.

If an enabled read needs elevation, expose an exact root-owned dispatcher or narrowly parameterized wrapper for that query; do not provide a shell-capable sudo rule. Constrain SSH to the expected command path where practical and deny forwarding, PTY/shell use, arbitrary environment injection, redirection, pipelines, and alternate commands. The fixed one-hour `journalctl -u <enrolled-service>` query must not become general journal access.

## Additional diagnostics

The eight added queries have separate [query source records](vendor-cli-references.md). Certificate details and EXOS VLAN diagnostics have direct read-only-account observations. The FortiOS 8.0.1 controller checks used an administrator account; they do not validate a restricted profile or end-to-end MCP access. Positive stacking and PoE behavior was not tested because the observed switch lacks those features. Do not mark an administrator account as read-only to satisfy enrollment. Validate the intended restricted identity for every enabled query, or leave that query disabled.

## What the session sends

Exec-channel ssh_read sends only the reviewed catalogue command through Core's OpenSSH transport, without a paging-setting preamble. FortiOS enrollment retains its output-mode prerequisite. Ruckus Unleashed uses a pseudo-terminal, handles authentication, sends enable and the selected command, then closes it. Each path retains its separate permission/session contract.

`tests/test_ssh_wire_safety.py` substitutes `ssh` and `ssh-keyscan` on `PATH` and asserts, per platform, the exact argument vector, the environment, the known-hosts line and the bytes of the terminal conversation. That removes the old uncertainty about what an upstream driver adds, but it does not remove the need for device-side proof: the test pins what this code sends, not what a particular release, model or AAA policy accepts or logs.

The account or external AAA policy must still reject anything unexpected safely. Before production enrollment and after firmware changes, observe the SSH/AAA command log and compare the full session with the reviewed expectation.

## Enrollment test procedure

Perform these tests with the exact identity, SSH platform selection, AAA path, VDOM/VDC/logical-system scope, and target release intended for deployment.

1. Review the target's enabled query list and typed inventories before connecting.
2. Positively test every enabled named query and required typed value; remove permissions for unused queries.
3. Inspect target/AAA logs for the complete session, including setup and cleanup around the named command.
4. Negatively test configuration entry and mutation, save/commit/copy, reboot/reload, install/package, account and role changes, debug/process controls, packet capture, support bundles, shell escape, file writes, and privilege escalation.
5. Negatively test running/startup/full/backup/candidate/committed configuration display or export and secret-bearing file/support commands.
6. Verify arbitrary CLI, pipes, redirection, command separators, wildcard/range/list selectors, and unenrolled typed inventory values cannot be introduced through NetOps Helper.
7. Verify authentication or authorization failure does not lock out another required operational account and produces a useful target-side audit event.
8. Record the firmware, role/AAA policy revision, OpenSSH client version, test date, allowed command set, denied families, and reviewer.
9. Repeat the procedure after any relevant change. Do not set `account_role: "read-only"` or the FortiOS output verification flag until the test passes. On a platform without a read-only account (`ruckus_unleashed`), set `account_role: "admin-bounded"` with `role_boundary: "catalogue"` instead and never `read-only`; the denial tests above then fail by design, and the enrollment rests on the catalogue boundary alone.

A successful read test alone is insufficient. For a device-enforced read-only account, enrollment requires allowed reads to succeed, forbidden actions to be demonstrably denied, and the full session to match the reviewed authorization boundary. For the explicit `ruckus_unleashed` exception, enrollment instead requires accepting the unrestricted device privilege and reviewing the local catalogue/session boundary; it does not establish denial by the device.
