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
- Revalidate permissions after firmware, role, AAA, transport, or query-catalog changes.

The local `account_role: "read-only"` field records an operator assertion. The proxy and server reject a target without it, but they cannot prove remote enforcement.

## Platform expectations

### FortiOS

Use a dedicated administrator bound to a reviewed read-only access profile, with administrative domain/VDOM scope restricted where applicable. Do not assume that a profile described as read-only excludes every diagnostic, execute, backup, or secret-bearing operation; test explicit denial of those families.

Before enrollment, a separate administrator must persistently set console output to `standard` in the applicable global context and verify the effective setting. Only then set `fortios_output_standard_verified: true`. The helper sends no preamble at all on FortiOS - one `ssh` process carries the catalogue command and nothing else - so it never enters configuration to change or restore paging, and it also never restores a pager somebody else changed. SHA-1 key exchange is refused for every platform. The `ssh-rsa` host key algorithm is refused too unless the device carries the named per-device exception `legacy_ssh: "rsa-sha1"` with its host key pin; that exception exists since 13 September 2026 and no FortiOS device has needed it. Verify both the exact wire session and target AAA log in a controlled test environment.

Measured on 17 September 2026 against FortiOS 8.0.0 with this code: an administrator bound to a custom access profile with every permission group set to `read`, `cli-get enable`, `cli-show enable`, `cli-diagnose enable`, `cli-exec disable` and `cli-config disable` answered all 40 catalogue queries with exit status 0 - the thirty whitelisted before that session and the ten added from it - and `config system global`, `execute ping` and `execute dhcp lease-list` were all refused with `Unknown action 0`. `cli-diagnose` defaults to `disable`; without it the 22 `diagnose` queries of the catalogue are refused. Such an account prints the prompt `$` instead of `#`, and the prompt is part of the one-shot answer. Twenty-six connections in a row (one `ssh-keyscan` and one `ssh` per query) made the device refuse further connections for a while; the helper now queues every FortiOS connection through one lane per device, five seconds apart, and caches the keyscan's host key line for ten minutes so a query after the first usually needs only the `ssh` connection - see [Security model](security-model.md#device-side-authorization).

Measured on 21 September 2026 against FortiOS 8.0.1 on a FortiGate 60F: with `cli-show enable` the same kind of profile answered a bare `show` with the complete configuration (477,127 bytes). FortiOS 8.0.1 masks secrets in that output, but everything else is exposed, which this page requires to deny. No query of the helper catalogue uses `show` - every `fortinet` template is a `get` or `diagnose` command - so **give the helper account `cli-show disable`**. With that profile `show` and `show system interface wan1` were refused with `Unknown action 0`, `get system admin` listed only the account itself, and 43 of the 45 enrolled catalogue queries returned data; the remaining two are the SSL VPN queries described in [Fortinet FortiOS CLI references](vendor-cli-references/fortinet-fortios.md). NetOps Auditor collects the configuration with `show` and therefore needs `cli-show enable`; enrol it with its own identity, never with the helper account.

### Extreme Switch Engine / ExtremeXOS

Use a dedicated read-only role or externally authorized network-login identity. Confirm the role can execute only the enabled `show` and read-only diagnostic commands for the intended switch/slot scope. Deny configuration, save, download/upload, process/debug, support collection, and shell-like facilities.

Role behavior differs across releases and external RADIUS/TACACS policy. Test each enabled catalog command, including typed port forms, and verify that malformed, list, range, wildcard, and broad port selectors remain unavailable through the account.

Measured on 17 September 2026 against ExtremeXOS 33.7.1 with this code: a user-level account (`create account user <name> <password>`) answered 46 of the 47 catalogue queries, byte-identical to an administrator account - the thirty-two whitelisted before that session and the fourteen added from it - and was refused `show accounts` as well as `show configuration`, the latter with `This user does not have permissions for this command.` (exit status 254). Four queries (`show port <port> information detail`, `show iproute ipv6 summary`, `show neighbor-discovery cache ipv6 <address>`, `show sharing`) end with exit status 250 and a complete answer; the helper returns the answer and reports the status. The forty-seventh query, the slotted `inline_power_port`, was measured on 18 September 2026 under the same user-level account through `ssh_read`: exit status 0 and 195 bytes for one enrolled port, so all 47 queries of that dated catalogue had been measured under that account; this does not cover later additions. The factory `user` account ships enabled and without a password: delete it or set one before the switch is enrolled anywhere.

Measured on 25 September 2026 against the EXOS-VM 33.6.1.14 virtual switch with a user-level account holding an RSA key and `legacy_ssh: "rsa-sha1"`: all 49 catalogue queries answered, 2 of them `device_cli_error` for commands the virtual switch lacks and, from helper 0.3.7, `show stacking` a third (`Method is not implemented on this platform.`); see [Extreme Networks Switch Engine](vendor-cli-references/extreme-switch-engine.md#exos-vm-336114-measured-on-25-september-2026).

### Cisco IOS

Use a dedicated low-privilege identity with a parser view or external AAA command authorization that permits the exact enrolled command set. Numeric privilege level alone may be too broad or too narrow and must not be treated as proof.

Confirm there is no path to enable mode, configuration mode, running/startup configuration display, file display/copy, debug, reload, support collection, embedded scripting, or shell escape. Test the exact interface grammar and every enabled query over the same SSH transport.

Measured on 25 September 2026 against the IOSv 15.9(3)M12 and IOSvL2 15.2(20200924) virtual images with a privilege-1 local user holding only an RSA public key: every catalogue command was transported over the exec channel, and a command the image does not implement or the account may not run - `show running-config`, `configure terminal`, an unknown `show` - answered `Line has invalid autocommand "<command>"` with exit status 0, which the helper reports as `device_cli_error` from 0.3.7. Both images offer SHA-1 key exchange only, so helper 0.3.6 does not reach them; from helper 0.3.7 and Core 0.2.5 the per-device exception `legacy_ssh: "rsa-sha1-dh14"` lets it, and with it the catalogue ran on both images (19 and 26 of 27 queries with exit status 0, the rest commands the image lacks). See [verified support](../../../docs/verified-support.md#live-lab-measurements-25-september-2026) and, for the exact account configuration, [device preparation](../../../docs/lab-measurements-2026-09-25.md#device-preparation). Privilege 1 is what was measured, not a recommendation.

### Cisco IOS-XE

Use a dedicated identity with exact command authorization, not a reused administrator or broad automation account. IOS-XE adds platform and software-management surfaces beyond classic IOS; deny install/package, guestshell/application hosting, file-system, diagnostic archive, reload, debug, and configuration/export capabilities.

Permit only the catalog commands actually enrolled for the target and validate both positive reads and negative commands through the production AAA policy. Treat a role label or privilege number as insufficient without command logs.

Measured on 25 September 2026 against IOS-XE 17.18.2 IOL router and L2 images with a privilege-1 local user holding only an RSA public key: the same `Line has invalid autocommand "<command>"` answer with exit status 0 for commands outside the account's privilege and for commands the image lacks (the router image has no `show interfaces status`, `show vlan brief`, `show mac address-table`, `show etherchannel summary` or `show environment all`). The images have five VTY lines; the released helper's host key scan used them all, which Core 0.2.5 fixes. Exact account configuration: [device preparation](../../../docs/lab-measurements-2026-09-25.md#device-preparation).

### Cisco NX-OS

Use a dedicated NX-OS RBAC role or external AAA policy with the smallest required show-command rules and VDC/tenant scope. Do not assume a built-in operator role is automatically a perfect match for this catalog.

Deny configuration, checkpoint/rollback, file and bootflash access, guestshell/bash, install, reload, debug, Ethanalyzer/capture, support bundles, and full configuration display/export. Verify rule ordering and inherited permissions, then test every enabled command against the exact VDC and software release.

Measured on 25 September 2026 against Nexus 9300v and 9500v NX-OS 9.3(12) with `username <name> role network-operator` and an RSA `sshkey`: all 30 catalogue queries answered; `show running-config` was refused with `% Permission denied for the role` (exit status 30) and an unknown command with `Syntax error while parsing '<command>'` (exit status 16), the same answer the HSRP, VRRP and vPC commands give while their feature is disabled. Both are `device_cli_error` from helper 0.3.7. Exact account configuration: [device preparation](../../../docs/lab-measurements-2026-09-25.md#device-preparation).

### Arista EOS

Use a dedicated EOS role or AAA command-authorization policy that permits only the enrolled operational commands. Restrict VRF and tenant visibility where the authorization system permits it.

Deny enable/configuration paths, bash or shell access, file and extension management, event-handler changes, reload, debug, packet capture, support bundles, and configuration display/export. Test role inheritance and command-regex behavior with the actual EOS release instead of relying on a generic read-only label.

Measured on 25 September 2026 against cEOS-lab 4.36.1F with `username <name> privilege 1 role network-operator nopassword` and an ed25519 `ssh-key`: all 33 catalogue queries answered; `show running-config`, `configure` and `bash` were refused with `% Invalid input (privileged mode required) at line 1` and exit status 1, an unknown command with `% Invalid input at line 1`. The same account on the vEOS-lab 4.36.1F virtual machine answered all 33 as well. Exact account configuration: [device preparation](../../../docs/lab-measurements-2026-09-25.md#device-preparation).

### Junos OS

Use a dedicated login class with the minimum operational permissions and explicit allow/deny command policy. Restrict logical-system, routing-instance, or tenant visibility where applicable.

Do not grant configuration or maintenance permissions merely to make operational commands work. Explicitly deny configuration display/export, `configure`, file operations, request/maintenance actions, shell access, support collection, packet capture, and secret-bearing outputs. Validate both classic and ELS target profiles separately because accepted interface syntax and query catalogs differ.

Measured on 25 September 2026 against vJunos-switch 26.2R1.7 with the built-in `read-only` login class and an ed25519 key: all 25 `juniper_junos` and all 29 `juniper_junos_els` queries answered with exit status 0; `configure` was refused with `error: unknown command: configure`, `show configuration system login` with `error: permission denied: system` and an unknown command with `error: syntax error, expecting <command>: ...`, each with exit status 0. The root account on this release requires an encrypted password even when a root SSH key is configured. Exact account configuration: [device preparation](../../../docs/lab-measurements-2026-09-25.md#device-preparation).

### Ruckus Unleashed

**This platform has no read-only account to give, and that is a property of the device, not a gap in this project.** Measured on Unleashed 200.13 on 20 September 2026: the configuration context offers an `admin` sub-context, and everything it knows is `name`, `auth-server`, `show` and the context verbs - there is no command that creates a second administrator and none that assigns a role. Unleashed carries one administrator, and the four enrolled `show` commands live in the privileged context reached with `enable`, the same context as `reboot`, `upgrade` and the configuration commands. An account that can run `show sysinfo` there can also run those. Treat an Unleashed enrollment as an account whose blast radius is the device, and enrol it only where that is acceptable; where it is not, the answer is not a narrower account but a different device or no enrollment. An external authentication server with a restricted role is the one avenue this project has not measured.

The helper's own boundary is narrower than the account's: the session never enters `config`, never sends `exit` (which saves in a configuration context), and closes the terminal instead. The exact bytes are pinned by `tests/test_ssh_wire_safety.py`.

The access point asks for the password a second time inside its shell and echoes it on the terminal. The whole login phase is therefore discarded and never reaches an output, an error or an audit record. The device also offers only the `ssh-rsa` host key algorithm, so it needs `legacy_ssh: "rsa-sha1"` and its pin.

### Linux

Use an unprivileged account with no Docker socket/group access, no writable operational groups, no package/service/process-control rights, and no general sudo. Membership that grants broad journal, network namespace, disk, virtualization, or container visibility must be reviewed as an effective privilege grant.

If an enabled read needs elevation, expose an exact root-owned dispatcher or narrowly parameterized wrapper for that query; do not provide a shell-capable sudo rule. Constrain SSH to the expected command path where practical and deny forwarding, PTY/shell use, arbitrary environment injection, redirection, pipelines, and alternate commands. The fixed one-hour `journalctl -u <enrolled-service>` query must not become general journal access.

## Additional diagnostics in Helper 0.3.4

The eight added queries have separate [CLI evidence](configuration.md#scoped-diagnostic-queries). Certificate details and EXOS VLAN diagnostics have direct read-only-account observations. The FortiOS 8.0.1 controller checks used an administrator account; they do not validate a restricted profile or end-to-end MCP access. Positive stacking behavior was not tested because the observed switch lacks that feature. Do not mark an administrator account as read-only to satisfy enrollment. Validate the intended restricted identity for every enabled query, or leave that query disabled.

## What the session sends

There is no vendor session driver any more. `ssh_read` runs the OpenSSH client of `netops-core`, so what reaches the device is exactly the reviewed catalogue command: no platform in the catalogue sends a preamble. `extreme_exos` used to send `disable cli paging` as its own command first; measured on 19 September 2026 against ExtremeXOS 33.7.1, a non-interactive exec session does not page at all - `show configuration` returned the same 10,728 bytes with zero `--More--` markers whether or not the preamble was sent - so the preamble bought nothing and was removed rather than kept as dead weight. `ruckus_unleashed` is the one platform without an exec channel: it is driven on a pseudo-terminal, answers its own login prompts, sends `enable`, then the command, and ends by closing the terminal.

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
9. Repeat the procedure after any relevant change. Do not set `account_role: "read-only"` or the FortiOS output verification flag until the test passes.

A successful read test alone is insufficient. Enrollment is complete only when allowed reads succeed, forbidden actions are demonstrably denied, and the full session matches the reviewed authorization boundary.
