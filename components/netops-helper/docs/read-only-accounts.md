# Accounts and least privilege

The NetOps Helper engine assumes that every target account is prevented from mutating the target by authorization enforced on the target or its external AAA service. Client validation, named templates, redaction, and egress rules are additional containment. They are not substitutes for device-side permissions. This page is the reference for the device accounts and access profiles that NetOps needs: the FortiOS and FortiADC sections below list every NetOps role, including Admin and Auditor, with the measured profile. Why each role has its own account is explained in the [device account model](../../../docs/account-model.md).

Apart from the measured FortiOS and FortiADC profiles below, no vendor configuration recipe is provided here. Role names, privilege semantics, command authorization, and inherited permissions vary by platform, release, feature license, VDOM/virtual system, and AAA backend. Build the role from current vendor guidance, review the effective rules, and test the exact deployed path.

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

An account whose effective device permissions exceed read-only, on a platform that has no read-only account at all or whose read-only profile refuses part of the catalogue, is enrolled truthfully as `account_role: "admin-bounded"` with `role_boundary: "catalogue"`: the account can do everything on the device and the only boundary is the Helper's fixed query catalogue and session handling. The inventory and server accept this declaration only for `ssh_platform` values `ruckus_unleashed`, `fortios`, or `fortiadc`, for these reviewed uses: Unleashed has no read-only device account; FortiOS may use this boundary when a reviewed read-only profile refuses approved catalogue queries; the reviewed FortiADC exception covers the documented `diagnose` and `get router` query families whose read profile refuses them. On `fortiadc` that boundary also includes five explicitly granted fixed diagnostics outside the query catalogue, `execute ping <address>`, `execute traceroute <address>`, `execute nslookup name <name>`, `execute curl <endpoint>` (preceded by the read `execute curl-option view-settings`) and `execute health-check-verify health-check <name> dest-address <address> count <count>`, which run only for a recipe in `diagnostic_recipes` and an exact enrolled address, name, endpoint or health check (see `fortios_diagnostics` in the [Helper configuration](../../../docs/helper-configuration.md)); the device runs them with the full rights of the enrolled administrator. `admin-bounded` without `role_boundary: "catalogue"`, on any other platform, or a `role_boundary` next to `read-only` fails the inventory as `role_rejected`. Every other platform still accepts only `read-only`. The account retains its actual device privileges. The role itself does not restrict reads to a WLAN or ADC command family: `enabled_queries` is the explicit grant within the existing fixed platform catalogue, and each selected query still requires its typed enrolled inventory. The proxy forwards and reports the role and boundary exactly as enrolled (`admin-bounded` and `role_boundary` in the authentication context and in `target_scope`), never as `read-only`, and the server accepts `admin-bounded` only with the same boundary and platform. Device output stays untrusted either way.

## Platform expectations

### FortiOS

This section is the reference for the FortiOS accounts of every NetOps role. The rows were measured on a FortiGate 60F with FortiOS 7.6.8 build3744 (standalone) and on a FortiGate 80F active-passive HA pair with FortiOS 8.0.2 build0251, between 31 October and 2 November 2026. "Not measured" means that nobody has tried that combination: it is neither a promise that it works nor a statement that it fails. A profile shown below is a profile that was used and read back from the device; it is not proven to be the smallest possible one unless the row says so.

NetOps can run with a `super_admin` or `prof_admin` account for everything, and most functions will then work. We do not recommend it. Such an account has full rights on the device, it gives no separation between reading and changing, and a leaked key or password, or a defect that lets an unexpected command through, then acts with every permission of the device. Use a dedicated read-only account for Helper and a separate account for Admin changes, each limited by trusted hosts to the address NetOps connects from. The only roles that need `super_admin` are listed in the table, with the reason.

All accounts below are local administrators (`config system admin`) with `set vdom "root"` on a device without VDOMs. A login that has to work in another VDOM is not covered here; Helper never enters `config vdom`, see [Helper configuration](../../../docs/helper-configuration.md).

| NetOps role | Account and enrollment | Access profile (as read from the device) | Without this right (what the administrator sees) | Measured |
|---|---|---|---|---|
| Helper catalogue reads (`get`, `diagnose`) | dedicated login, password or SSH key, trusted host /32 of the NetOps host; `account_role: "read-only"` | all ten groups `read` (`secfabgrp`, `ftviewgrp`, `authgrp`, `sysgrp`, `netgrp`, `loggrp`, `fwgrp`, `vpngrp`, `utmgrp`, `wifi`), `cli-get enable`, `cli-diagnose enable` | a `diagnose` command without `cli-diagnose`: `Unknown action 0` (8.0.2) | 7.6.8, 8.0.2; with `cli-show disable` (7.6.8) the catalogue `get` and `diagnose` reads still answer and every `show` command is refused with `Unknown action 0` |
| Helper reads with `execute` (`ping_options`, `traceroute_options`, `dhcp_leases`) | as above | as above plus `cli-exec enable` | without `cli-exec`: `Unknown action 0` | refusal of all three: 7.6.8; `ping_options` and `traceroute_options` with `cli-exec enable`: 7.6.8, 8.0.2; `dhcp_leases` with `cli-exec enable`: 7.6.8, the command is accepted (the interface had no leases, so the answer was empty) |
| Helper diagnostics (`fortios_diagnostics`: ping, traceroute, sniffer, sessions, flow, logs) | as above; `account_role: "read-only"` | all ten groups `read`, `cli-get`, `cli-show`, `cli-diagnose` and `cli-exec enable` | ping, traceroute and logs send `execute` commands; an `execute` command without `cli-exec`: `Unknown action 0` (7.6.8); every recipe also reads the selected interface with `show full-configuration system interface "<interface>"`, which without `cli-show` answers `Unknown action 0` (7.6.8, typed in a terminal) | 8.0.2: every command of the six recipes typed in a terminal, flow also through NetOps; 7.6.8: flow through NetOps |
| Helper Wi-Fi reads (`wifi_access_points`, `wifi_ap_detail`, `wifi_clients`, `wifi_client_detail`, `wifi_ssid_mapping`) | separate login; `account_role: "admin-bounded"`, `role_boundary: "catalogue"` | as the first row, but `wifi read-write`, with `cli-diagnose enable` | `wifi read`: `command parse error before 'wireless-controller'` and `Command fail. Return code -61`; `wifi read-write` without `cli-diagnose`: `Unknown action 0` | refusal: 7.6.8, 8.0.2; data: 8.0.2; 7.6.8 with `wifi read-write`: the four `diagnose wireless-controller wlac` commands are accepted (the device managed no access point, so the answers list 0 WTPs and 0 STAs) |
| Helper `dns_cache`, `fqdn_cache` | separate login; `admin-bounded`/`catalogue`. The cache is read on a terminal, see [DNS cache reads on a terminal](vendor-cli-references/fortinet-fortios.md#dns-cache-reads-on-a-terminal) | the read profile of the first row with `netgrp read-write` instead of `netgrp read` (`sysgrp` stays `read`) and `cli-diagnose enable` | read profile: `command parse error before 'application'` and `Command fail. Return code -61`; with `netgrp read` the answer stays a parse error even with `sysgrp read-write` or with `sysgrp custom` and any one or all of `admin`, `upd`, `cfg`, `mnt` `read-write` (7.6.8: `command parse error before 'dnsproxy'` with `upd`, `cfg` or `mnt`, `command parse error before 'application'` with `admin`; `-61`) | `netgrp read-write` with `sysgrp read`: 7.6.8, 8.0.2 |
| Helper `ipsec_tunnel_statistics` | separate login; `admin-bounded`/`catalogue` | the read profile of the first row with `vpngrp read-write` instead of `vpngrp read` and `cli-diagnose enable` | read profile, and also a write profile with `vpngrp read`: `command parse error before 'stat'` and `Command fail. Return code -61` | `vpngrp read-write` without `super_admin`: 7.6.8 on the read profile of the first row; 8.0.2 on a write test profile with `sysgrp custom` |
| Helper opt-in `config_read`, `config_diff` | the Helper login of the first row | as the first row plus `cli-show enable`; `cli-config` stays disabled | without `cli-show`: `show` commands answer `Unknown action 0` (7.6.8) | 8.0.2; refusal: 7.6.8; the profile then shows the configuration, with secrets masked, so enable it only on targets that use `config_access` |
| Admin write, `firewall policy` (FortiOS 7.6.8, `cli-script` safeguard) | dedicated login, password or SSH key, trusted host /32 of the Admin host | `sysgrp read-write`, `netgrp read-write`, `fwgrp read-write`, other groups (also `vpngrp`) `read`, `cli-diagnose`, `cli-get`, `cli-show`, `cli-config enable` | starting from this profile with `vpngrp read-write`, each of `sysgrp read` and `netgrp read` alone was refused by the enrollment check before any write: `sysgrp read`: `the write account sees other administrators than the configured ones: not visible: netops-check, netops-ro, netops-rw, <read-only-admin>`; `netgrp read`: `the write account sees other administrators than the configured ones: not visible: netops-rw`; two narrower combined profiles, both with `netgrp read`, were also refused by the enrollment check before any write (`vpngrp read` alone passes, see the next column): `fwgrp custom` (`policy` and `address` `read-write`, the rest `read`), `netgrp read`, `vpngrp read`, `cli-diagnose disable`, with `sysgrp custom` (`cfg` `read-write`): `the write account sees other administrators than the configured ones: not visible: netops-check, netops-ro, netops-rw, <read-only-admin>`; the same with `sysgrp read-write`: `... not visible: netops-ro, netops-rw` | 7.6.8 (enrollment self-test reverted by the safeguard; create, update and undo confirmed with `vpngrp read-write`; with `vpngrp read`: enrollment self-test reverted, create and undo confirmed); a smaller profile was not found: the write login must see every administrator of the device, so the smallest profile depends on the profiles of the other administrators |
| Admin write on FortiOS 8.0.1 and later (webhook safeguard) | dedicated login, **password credential**, trusted host /32 of the Admin host | `super_admin` (required) | any other profile: `config system api-user` answers `command parse error before 'api-user'` and `Command fail. Return code 1`, also with every group `read-write` and `cli-exec enable`; creating the safeguard profile with more rights than one's own: `object set operator error, -672 discard the setting` and `Command fail. Return code -672`; NetOps refuses before any write | 8.0.2 |
| Admin check | a second login, never the write credential | the Helper read profile of the first row with `cli-show` and `cli-exec enable` was used | the configuration refuses the same credential (`different-credential`) | 7.6.8, 8.0.2 |
| Webhook safeguard API user (created and deleted by Admin for one change) | `config system api-user` `netops-sg-ID12-u`, trusted host the device address /32, no `vdom` line (8.0.2 refuses it) | `netops-sg-ID12-p`: `fwgrp read-write`, every other group `none` | not applicable: Admin creates it | 8.0.2 |
| Auditor SSH collection | dedicated login, trusted host /32 of the collector | `super_admin` (by design) | a read profile sees in `show system admin` only its own entry and in `show system accprofile` neither `super_admin` nor profiles with write rights; administrator rules end `not-evaluated` (`admin-visibility-unproven`) and the run exits with code 3 | 8.0.2 |

Why some roles need more than read: on both measured builds the read-only groups do not allow the Wi-Fi controller, DNS proxy and IPsec tunnel statistics commands; the grants that worked are `wifi read-write`, `netgrp read-write` (not `sysgrp`) and `vpngrp read-write`, each on top of the read profile, and on 8.0.1 and later only `super_admin` can create the API user of the Admin safeguard. Enroll these Helper queries under a separate `admin-bounded` login only when you need them, and keep the read-only login for everything else. The answer `command parse error before '...'` with `Return code -61` does not name the missing permission: on 7.6.8 it was also returned with `cli-diagnose enable` when the feature group of the command was only `read`.

#### Creating the Helper read-only account

The following commands are derived from the block that was executed on the FortiGate 60F with FortiOS 7.6.8 build3744 on 31 October 2026, through a `super_admin` administrator (the executed block also contained `set cli-show enable` and a `comments` line, and used a generated profile name); `cli-show` is omitted here, see below. The login and the address are placeholders. The same profile lines, read back with `show system accprofile`, exist on the FortiGate 80F with FortiOS 8.0.2 build0251.

~~~
config system accprofile
    edit "netops-read"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wifi read
        set cli-diagnose enable
        set cli-get enable
        set cli-exec enable
        set cli-config disable
    next
end
config system admin
    edit "netops-read"
        set accprofile "netops-read"
        set password <password>
        set force-password-change disable
        set trusthost1 <NetOps host address> 255.255.255.255
    next
end
~~~

Leave out `set cli-exec enable` when you enable neither diagnostics nor the three `execute` reads. The block does not enable `cli-show`; add `set cli-show enable` for `config_read`/`config_diff` and for diagnostics, whose recipes read the interface configuration with `show`. The device asks `Please enter current administrator password:` after `set password` and after `next`; enter the password of the administrator who is signed in. Check the result with `show system accprofile netops-read` and `show system admin | grep "edit \|set accprofile\|set trusthost"`.

For the Admin write account on 8.0.1 and later follow [Admin configuration](../../../docs/admin-configuration.md#write-account-for-the-webhook-safeguard-what-to-check). No creation commands for the 7.6.8 write profile or for the `admin-bounded` profiles are given here: they were set up and read back, but the commands were not recorded exactly as typed.

#### Other FortiOS requirements

Before enrollment, a separate administrator must persistently set console output to `standard` in the applicable global context and verify the effective setting. Only then set `fortios_output_standard_verified: true`. The helper sends no preamble at all on FortiOS - one `ssh` process carries the catalogue command and nothing else - so it never enters configuration to change or restore paging, and it also never restores a pager somebody else changed. Modern defaults refuse SHA-1 key exchange and `ssh-rsa` host keys. An explicitly selected per-device `legacy_ssh` profile with a pinned host key enables only its documented algorithms: `rsa-sha1` permits the host-key algorithm; `rsa-sha1-dh14` additionally permits only `diffie-hellman-group14-sha1`. Verify both the exact wire session and target AAA log in a controlled test environment.

A read-profile prompt can use `$` instead of `#`. FortiOS connections use a per-device lane with five-second spacing and a pinned-key scan cache of ten minutes; those transport limits do not prove read-only permission. Do not assume that a profile described as read-only excludes every diagnostic, execute, backup, or secret-bearing operation; test explicit denial of those families.

The read-only profile must also allow `get system status`: before a fresh `ssh_read` on a FortiOS target the Helper runs it to confirm that the device is a FortiGate or FortiWiFi (`FortiGateRugged-` and `FortiFirewall-` hardware is refused for now). A refusal, a non-zero exit status or another product ends as `product_identity` without device output. Every fresh query other than `system_status` therefore uses one more SSH connection and waits at least five more seconds on the lane spacing. A refused query ends as `device_cli_error`.

Wi-Fi reads under a read-only account: enrollment still accepts the five wireless controller queries for a read-only FortiOS account (inventories of 1.0.4 stay valid), but `configure helper` and `check_operator_config` print one warning per enabled query (`Warning: device NAME: query wifi_clients is enabled for a read-only FortiOS account, which the device refuses with 'Return code -61'; ...`) so the operator can remove it or enroll the `admin-bounded` login of the table. For that login enable only `system_status`, `wifi_access_points`, `wifi_ap_detail`, `wifi_clients`, `wifi_client_detail` and `wifi_ssid_mapping`, and put only the authorized station MACs in `read_inventory.wireless_clients`; these queries need no `config_access` or `diagnostic_recipes` grant. The device-side Wi-Fi write permission stays with that login; the Helper exposes only the selected fixed reads, with the typed MAC constraint, host-key pin, output limits and audit.

### FortiADC

This section is the reference for the FortiADC accounts of every NetOps role. The rows were measured on FortiADC-KVM 7.6.7 build0676 (virtual image, standalone) between 27 October and 2 November 2026; FortiADC HA was not used for these account measurements. "Not measured" means that nobody has tried that combination.

FortiADC reserves part of its CLI for a system administrator (`is-system-admin yes`, as the built-in `admin`): on the measured build no access-profile area grants `diagnose server-load-balance`, the `get router` and other `diagnose` reads of the catalogue, or `execute dos get`. NetOps therefore needs a system administrator for those reads and for Admin `pool-member`. Use it only where the table says so, under its own login limited by trusted hosts, and keep a separate read login for everything else. Running every role with the built-in `admin` works but gives full rights to every NetOps credential, with no separation between reading and changing; we do not recommend it.

| NetOps role | Account and enrollment | Access profile (as read from the device) | Without this right (what the administrator sees) | Measured |
|---|---|---|---|---|
| Helper read login (`system_status` and the reads it allows) | dedicated login; `is-system-admin no` and the trusted host /32 of the NetOps host are the recommended setting, they were not read back in this measurement; `account_role: "read-only"` | `system`, `load-balance`, `log`, `link-load-balance`, `global-load-balance`, `security` `read` | not applicable | 7.6.7: `system_status`, `system_performance`, `firewall_timeouts`, `waf_signature_status`, `log_list_attack`, `log_files`, `ha_status` and `traffic_group_status` answer (`traffic_group_status` prints empty output in standalone); every other catalogue query is refused (rows below); the device refuses configuration changes: `config load-balance real-server` answers `Parsing error at 'load-balance'. err=1` and `Command fail. Return code is -284 (CLI parsing error.)`, and `edit`, `next` and `end` that follow are refused the same way |
| Helper `diagnose`, `get router` and other system reads (`vm_license`, `interface_state`, `interface_counters`, `routing_table`, `arp_table`, `cpu_info`, `nic_detail`, `lldp_neighbors`, `bgp_summary`, `bgp_neighbors`, `ospf_neighbors`, `llb_policy`, `tls_handshake_stats`, `tls_session_reuse`, `waf_block_ip`, `log_list_traffic`, `autoupdate_contract`, `system_date`) | system administrator; `account_role: "admin-bounded"`, `role_boundary: "catalogue"` | `is-system-admin yes` (built-in `admin`, profile `super_admin_prof`, every area `read-write`) | read login: `Parsing error at '...'. err=1` and `Command fail. Return code is -284 (CLI parsing error.)` | 7.6.7 |
| Helper `slb_vs_stat`, `slb_load` (also inside `triage_slb`) | as above | as above | read login: `Parsing error at 'server-load-balance'` and `-284` | 7.6.7 |
| Helper `slb_sessions`, `persistence_sessions` | as above | as above | read login: `Parsing error at 'server-load-balance'` and `Command fail. Return code is -284 (CLI parsing error.)` for `diagnose server-load-balance session list` and `diagnose server-load-balance persistence list` | 7.6.7: refusal under the read login, commands typed in a terminal; not run under the system administrator |
| Helper DoS counts (`dos_access_limit`, `dos_conn_limit`, `dos_req_limit`) | as above | as above | read login: `Parsing error at 'dos'` and `-284` | 7.6.7 |
| Helper diagnostics (`ping`, `traceroute`, `nslookup`, `http_probe`, `health_check_verify`) | as above; the device runs them with the full rights of that login | as above | read login (7.6.7): `execute ping`, `execute traceroute`, `execute nslookup name` and `execute curl` with `execute curl-option view-settings` are accepted, `execute health-check-verify` answers `Parsing error at 'health-check-verify'. err=1`; the log recipes are refused at `execute log filter type` (`Parsing error at 'type'`) and `-284` | 7.6.7 with the system administrator; under the read login the commands were typed in a terminal |
| Admin `pool-member`, `pool-member-add`, `pool-member-remove` (command line only) | system administrator login, trusted host /32 of the Admin host | `is-system-admin yes` | the health precheck reads `vs_stat` with the write login; a login that is not a system administrator, read or with `load-balance read-write`, is refused with `Parsing error at 'server-load-balance'` and `Command fail. Return code is -284 (CLI parsing error.)`, so the change is refused | 7.6.7 with the built-in `admin`; 7.6.7 with a write login whose profile has `load-balance read-write` and that is not a system administrator: the precheck is refused as described |
| Admin check | a second login, never the write credential; `is-system-admin` not set, trusted host /32 of the Admin host | the Helper read profile of the first row (`system`, `load-balance`, `log`, `link-load-balance`, `global-load-balance`, `security` `read`) | the configuration refuses the same credential | 7.6.7: the doctor check reads `show system admin "netops-read"` and `show system accprofile "netops-read"` with the check login and reports `check account rights: ok (access profile netops-read: read only)` |

The read profile above, as read back with `show system accprofile netops-read` on FortiADC-KVM 7.6.7 build0676:

~~~
config system accprofile
  edit "netops-read"
    set system read
    set load-balance read
    set log read
    set link-load-balance read
    set global-load-balance read
    set security read
  next
end
~~~

The administrator that uses it had `is-system-admin no` and a trusted host /32. The commands that created it were not recorded exactly as typed, so no creation block is given; build the profile with the device's own CLI or GUI and compare the readback with the block above.

Before it returns anything, the Helper runs `system_status` (`get system status`) to confirm that the target is a FortiADC (hardware beginning `FortiADC-`); any other product, a refused command or a missing `Version:` record ends as `product_identity`. The FortiADC answer is framed by the shell prompt on the exec channel; the Helper removes it before the check. The 7.6.5 Administration Guide maps `Server Load Balance` only to `config load-balance` and reserves complete access to the account named `admin`. Test the account on a test FortiADC first, see the [FortiADC reference](vendor-cli-references/fortinet-fortiadc.md).

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

The eight added queries have separate [query source records](vendor-cli-references.md). Certificate details and EXOS VLAN diagnostics have direct read-only-account observations. The FortiOS 8.0.1 controller checks used an administrator account; they do not validate a restricted profile or end-to-end MCP access. A later end-to-end MCP test (2026-10-15, before 1.0.0) exercised all five FortiOS controller queries through Helper's own dedicated read-only account against physical hardware on FortiOS 7.6.7: `managed_switch_status`, `managed_switch_mac` and `managed_switch_lldp` returned data. The device refused the other two for different reasons, neither of them a read-only-account effect: `managed_switch_poe` received a hardware refusal (`is not PoE capable`, `Command fail. Return code -7622`) because the enrolled switch has no PoE hardware, and `managed_switch_stacking` received a firmware parse refusal (`command parse error before 'stacking'`, `Command fail. Return code -61`) because FortiOS 7.6.7 lacks the command, which is absent even from its privileged CLI help. In both refusals the MCP call completed and the result's `rc`, the exit status of the SSH command, was 0; Helper reported the refusal with `ok: false`, `error_code` `device_cli_error` and MCP `isError: true`. Neither an `rc` of 0 nor a completed MCP call means that the device query succeeded (see the [FortiOS reference](vendor-cli-references/fortinet-fortios.md#scoped-diagnostic-queries)). Positive stacking and PoE behavior remains untested because the enrolled switch lacks those features. Do not mark an administrator account as read-only to satisfy enrollment. Validate the intended restricted identity for every enabled query, or leave that query disabled.

## What the session sends

Exec-channel ssh_read sends only the reviewed catalogue command through Core's OpenSSH transport, without a paging-setting preamble. FortiOS enrollment retains its output-mode prerequisite. Ruckus Unleashed uses a pseudo-terminal, handles authentication, sends enable and the selected command, then closes it. The FortiOS queries `dns_cache` and `fqdn_cache`, whose output FortiOS writes only to a terminal, and the FortiADC queries marked for a terminal open a pseudo-terminal after the exec-channel identity probe, verify the prompt, send the one catalogue command and close it. Each path retains its separate permission/session contract.

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
9. Repeat the procedure after any relevant change. Do not set `account_role: "read-only"` or the FortiOS output verification flag until its stated checks pass. Use `admin-bounded`/`catalogue` instead, and never `read-only`, for Unleashed devices without a read-only account; for FortiOS only for the catalogue reads that the read-only profile refuses (Wi-Fi, DNS cache and IPsec tunnel statistics, see the FortiOS table); and for FortiADC only for the refused `diagnose` and `get router` query families. The denial tests above then fail by design and the enrollment rests on the catalogue boundary alone. Record the device-side permissions actually observed; this catalogue boundary does not make the account device-enforced read-only.

A successful read test alone is insufficient. For a device-enforced read-only account, enrollment requires allowed reads to succeed, forbidden actions to be demonstrably denied, and the full session to match the reviewed authorization boundary. For the explicit Unleashed exception, the FortiOS reads that a read-only profile refuses, and listed FortiADC query families whose read profile refuses them, enrollment instead requires accepting the actual device privileges and reviewing the local catalogue/session boundary; it does not establish denial by the device.
