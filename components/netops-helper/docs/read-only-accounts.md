# Accounts and least privilege

`port_vlan` adds only the slot-free EXOS catalogue read `vlan_detail` (`show vlan
detail`), measured with the built-in `user`/read-only account on EXOS-VM
33.6.1.14, X435 31.7.3.37 and X440G2 33.7.1.6 (2026-11-09 captures).
It lists all Tag/Untag members without changing a setting. Enable it explicitly
per target; `ports` is optional for link status. Other platforms reuse enabled
`interfaces_trunk` + `interfaces` or Junos ELS `ethernet_switching_interfaces`.
This adds no privilege elevation or new device permission.

The NetOps Helper engine assumes that every target account is prevented from mutating the target by authorization enforced on the target or its external AAA service. Client validation, named templates, redaction, and egress rules are additional containment. They are not substitutes for device-side permissions. This page is the reference for the device accounts and access profiles that NetOps needs: the FortiOS and FortiADC sections below list every NetOps role, including Admin and Auditor, with the measured profile. Why each role has its own account is explained in the [device account model](../../../docs/account-model.md).

The cross-vendor defaults below describe built-in roles and their limits; they are not measured configuration recipes. Role names, privilege semantics, command authorization, and inherited permissions vary by platform, release, feature license, VDOM/virtual system, and AAA backend. Build the role from current vendor guidance, review the effective rules, and test the exact deployed path.

Log reads are capped by the Helper at 200 redacted device lines before byte paging:
EXOS keeps the leading newest messages; IOS/IOS XE, NX-OS, EOS and Junos/ELS
keep the trailing newest lines of `log_messages` and, where available,
`log_interactive_commands`. The Helper adds a truncation notice separately.
`line_limit` (`log_line_limit` in triage reads) reports the window. On IOS/IOS XE,
`show logging` exposes the in-memory buffer; its configuration header can be
outside the returned window. Older lines cannot be recovered by byte paging.
See [Log result window](tools.md#log-result-window).

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

Except for the separate REST API-user row, accounts below are local administrators (`config system admin`) with `set vdom "root"` on a device without VDOMs. A login that has to work in another VDOM is not covered here; Helper never enters `config vdom`, see [Helper configuration](../../../docs/helper-configuration.md).

| NetOps role | Account and enrollment | Access profile (as read from the device) | Without this right (what the administrator sees) | Measured |
|---|---|---|---|---|
| Helper catalogue reads other than the exceptions below (`get`, `diagnose`) | dedicated login, password or SSH key, trusted host /32 of the NetOps host; `account_role: "read-only"` | all ten groups `read` (`secfabgrp`, `ftviewgrp`, `authgrp`, `sysgrp`, `netgrp`, `loggrp`, `fwgrp`, `vpngrp`, `utmgrp`, `wifi`), `cli-get enable`, `cli-diagnose enable` | a `diagnose` command without `cli-diagnose`: `Unknown action 0` (8.0.2) | 7.6.8, 8.0.2; with `cli-show disable` (7.6.8) the catalogue `get` and `diagnose` reads still answer and every `show` command is refused with `Unknown action 0` |
| Helper reads with `execute` (`ping_options`, `traceroute_options`, `dhcp_leases`) | as above | as above plus `cli-exec enable` | without `cli-exec`: `Unknown action 0` | refusal of all three: 7.6.8; `ping_options` and `traceroute_options` with `cli-exec enable`: 7.6.8, 8.0.2; `dhcp_leases` with `cli-exec enable`: 7.6.8, the command is accepted (the interface had no leases, so the answer was empty) |
| Helper diagnostics (`fortios_diagnostics`: ping, traceroute, sniffer, sessions, flow, logs) | as above; `account_role: "read-only"` | all ten groups `read`, `cli-get`, `cli-show`, `cli-diagnose` and `cli-exec enable` | ping, traceroute and logs send `execute` commands; an `execute` command without `cli-exec`: `Unknown action 0` (7.6.8); every recipe also reads the selected interface with `show full-configuration system interface "<interface>"`, which without `cli-show` answers `Unknown action 0` (7.6.8, typed in a terminal) | 8.0.2: every command of the six recipes typed in a terminal, flow also through NetOps; 7.6.8: flow through NetOps |
| Helper Wi-Fi reads (`wifi_access_points`, `wifi_ap_detail`, `wifi_clients`, `wifi_client_detail`, `wifi_ssid_mapping`) | separate login; `account_role: "admin-bounded"`, `role_boundary: "catalogue"` | as the first row, but `wifi read-write`, with `cli-diagnose enable` | `wifi read`: `command parse error before 'wireless-controller'` and `Command fail. Return code -61`; `wifi read-write` without `cli-diagnose`: `Unknown action 0` | refusal: 7.6.8, 8.0.2 (all five rechecked 2026-11-08 with CLI get/show/diagnose/exec enabled); data: 8.0.2; 7.6.8 with `wifi read-write`: the four `diagnose wireless-controller wlac` commands are accepted (the device managed no access point, so the answers list 0 WTPs and 0 STAs) |
| Helper Wi-Fi controller reads for a read-only account (`wifi_ap_status`, `wifi_vap_status`, `wifi_neighbors`, `wifi_controller_status`, `wifi_controller_statistics`, `wifi_rf_analysis`, `wifi_events`, and `wifi_triage` on top of them) | the Helper login of the first row (`account_role: "read-only"`) | measured profile: all ten groups `read`, in particular `wifi read`, with `cli-get enable` and `cli-exec enable`; a profile without `cli-exec` was not measured. Six reads send only `get wireless-controller ...` commands. Only `wifi_events` (and `wifi_triage`, which needs it) sends `execute log ...` commands; on 7.6.8 other `execute` reads were refused without `cli-exec` (row above). If the read-only account must not have `cli-exec`, leave `wifi_events` and `wifi_triage` out of `enabled_queries` | `diagnose wireless-controller ...` stays refused for this profile (`command parse error before 'wireless-controller'`, `Return code -61`); a client list with RSSI and a REST session login were not obtainable with it | 8.0.2 build0251, FortiGate-80F HA with two FortiAP, 2026-11-08: all seven reads answered; `get wireless-controller client-info` answered `count=0` for known clients; REST login of the account returned no session (HTTP 401 on every monitor path), so REST was not measured |
| Helper optional Wi-Fi REST (`wifi_clients`, `wifi_aps_live`, `wifi_rogue`, REST enrichment/history in `wifi_triage`) | separate `config system api-user` identity `netops-api-ro`, root VDOM, source /32 trusthosts; token in private `api-token` vault record `fortigate-wifi-api-ro`, referenced by `helper.fortios_rest_credential`; keep the SSH login | recommended verified minimum: `wifi read` + `loggrp read`, all other groups `none` (including `authgrp`), all five `cli-*` disabled; all ten groups `read` remains an alternative. HTTPS management on receiving interface, `fortios_rest_port` (default 443, match `admin-sport`) allowed by TCP egress, and verified DER SHA-256 pin or CA | no token: `unsupported`; wrong token/source: 401; insufficient profile: 403; non-root responses refused; [administrator checklist](../../../docs/fortios-wifi-rest.md#create-access-on-fortigate) | five Wi-Fi GETs: 8.0.2 build0251, 2026-11-08; all seven GETs including device identity and wireless memory logs: HTTP 200 rechecked 2026-11-09; minimum profile verified 2026-11-09 with seven GETs 200 and PUT/POST/DELETE 403; secondary token/failover not verified |
| Helper `dns_cache`, `fqdn_cache` | separate login; `admin-bounded`/`catalogue`. The cache is read on a terminal, see [DNS cache reads on a terminal](vendor-cli-references/fortinet-fortios.md#dns-cache-reads-on-a-terminal) | the read profile of the first row with `netgrp read-write` instead of `netgrp read` (`sysgrp` stays `read`) and `cli-diagnose enable` | read profile: `command parse error before 'application'` and `Command fail. Return code -61`; with `netgrp read` the answer stays a parse error even with `sysgrp read-write` or with `sysgrp custom` and any one or all of `admin`, `upd`, `cfg`, `mnt` `read-write` (7.6.8: `command parse error before 'dnsproxy'` with `upd`, `cfg` or `mnt`, `command parse error before 'application'` with `admin`; `-61`) | `netgrp read-write` with `sysgrp read`: 7.6.8, 8.0.2 |
| Helper `ipsec_tunnel_statistics` | separate login; `admin-bounded`/`catalogue` | the read profile of the first row with `vpngrp read-write` instead of `vpngrp read` and `cli-diagnose enable` | read profile, and also a write profile with `vpngrp read`: `command parse error before 'stat'` and `Command fail. Return code -61` | `vpngrp read-write` without `super_admin`: 7.6.8 on the read profile of the first row; 8.0.2 on a write test profile with `sysgrp custom` |
| Helper opt-in `config_read`, `config_diff` | the Helper login of the first row | as the first row plus `cli-show enable`; `cli-config` stays disabled | without `cli-show`: `show` commands answer `Unknown action 0` (7.6.8) | 8.0.2; refusal: 7.6.8; the profile then shows the configuration, with secrets masked, so enable it only on targets that use `config_access` |
| Admin write, `firewall policy` (FortiOS 7.6.8, `cli-script` safeguard) | dedicated login, password or SSH key, trusted host /32 of the Admin host | `sysgrp read-write`, `netgrp read-write`, `fwgrp read-write`, other groups (also `vpngrp`) `read`, `cli-diagnose`, `cli-get`, `cli-show`, `cli-config enable` | starting from this profile with `vpngrp read-write`, each of `sysgrp read` and `netgrp read` alone was refused by the enrollment check before any write: `sysgrp read`: `the write account sees other administrators than the configured ones: not visible: netops-check, netops-ro, netops-rw, <read-only-admin>`; `netgrp read`: `the write account sees other administrators than the configured ones: not visible: netops-rw`; two narrower combined profiles, both with `netgrp read`, were also refused by the enrollment check before any write (`vpngrp read` alone passes, see the next column): `fwgrp custom` (`policy` and `address` `read-write`, the rest `read`), `netgrp read`, `vpngrp read`, `cli-diagnose disable`, with `sysgrp custom` (`cfg` `read-write`): `the write account sees other administrators than the configured ones: not visible: netops-check, netops-ro, netops-rw, <read-only-admin>`; the same with `sysgrp read-write`: `... not visible: netops-ro, netops-rw` | 7.6.8 (enrollment self-test reverted by the safeguard; create, update and undo confirmed with `vpngrp read-write`; with `vpngrp read`: enrollment self-test reverted, create and undo confirmed); a smaller profile was not found: the write login must see every administrator of the device, so the smallest profile depends on the profiles of the other administrators |
| Admin write on FortiOS 8.0.1 and later (webhook safeguard) | dedicated login, **password credential**, trusted host /32 of the Admin host | `super_admin` (required) | any other profile: `config system api-user` answers `command parse error before 'api-user'` and `Command fail. Return code 1`, also with every group `read-write` and `cli-exec enable`; creating the safeguard profile with more rights than one's own: `object set operator error, -672 discard the setting` and `Command fail. Return code -672`; NetOps refuses before any write | 8.0.2 |
| Admin check | a second login, never the write credential | the Helper read profile of the first row with `cli-show` and `cli-exec enable` was used | the configuration refuses the same credential (`different-credential`) | 7.6.8, 8.0.2 |
| Webhook safeguard API user (created and deleted by Admin for one change) | `config system api-user` `netops-sg-ID12-u`, trusted host the device address /32, no `vdom` line (8.0.2 refuses it) | `netops-sg-ID12-p`: `fwgrp read-write`, every other group `none` | not applicable: Admin creates it | 8.0.2 |
| Auditor SSH collection | dedicated login, trusted host /32 of the collector | `super_admin` (by design) | a read profile sees in `show system admin` only its own entry and in `show system accprofile` neither `super_admin` nor profiles with write rights; administrator rules end `not-evaluated` (`admin-visibility-unproven`) and the run exits with code 3 | 8.0.2 |

Why some roles need more than read: on both measured builds the read-only groups do not allow the `diagnose wireless-controller` queries (the `get wireless-controller` reads and the wireless event log are allowed, see the Wi-Fi controller row above), the DNS proxy and IPsec tunnel statistics commands; the grants that worked are `wifi read-write`, `netgrp read-write` (not `sysgrp`) and `vpngrp read-write`, each on top of the read profile, and on 8.0.1 and later only `super_admin` can create the API user of the Admin safeguard. Enroll these Helper queries under a separate `admin-bounded` login only when you need them, and keep the read-only login for everything else. The answer `command parse error before '...'` with `Return code -61` does not name the missing permission: on 7.6.8 it was also returned with `cli-diagnose enable` when the feature group of the command was only `read`.

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

The read-only profile must also allow `get system status`: before a fresh `ssh_read` on a FortiOS target the Helper runs it to confirm that the device is a FortiGate or FortiWiFi (`FortiGateRugged-` and `FortiFirewall-` hardware is refused for now). A refusal, a non-zero exit status or another product ends as `product_identity` without device output. The identity is checked on every fresh read and is never cached. Every fresh query other than `system_status` uses one more SSH connection and waits at least five more seconds on the lane spacing; `system_status` itself is the live probe. This check prevents product mix-ups, and the spacing protects the device from connection bursts. Measured on 2026-11-09 on a FortiGate-80F 8.0.2 build 0251: one SSH connection takes 2.9 s, of which 2.2 s is the device checking the password and 0.2 s the command; the client waits for no prompt, end of file or fixed timeout. A fresh query takes 8–10 s (two connections and the lane spacing between them). A refused query ends as `device_cli_error`.

Wi-Fi reads under a read-only account: the replacement for the five `diagnose wireless-controller` queries is the `wifi_*` read set and `wifi_triage` described in [Helper tools](tools.md#wi-fi-reads-for-a-read-only-account); the new queries raise no warning. The five older queries stay in the catalogue for `admin-bounded` accounts only. Enrollment still accepts the five wireless controller queries for a read-only FortiOS account (inventories of 1.0.4 stay valid), but `configure helper` and `check_operator_config` print one warning per enabled query (`Warning: device NAME: query wifi_clients is enabled for a read-only FortiOS account, which the device refuses with 'Return code -61'; ...`) so the operator can remove it or enroll the `admin-bounded` login of the table. For that login enable only `system_status`, `wifi_access_points`, `wifi_ap_detail`, `wifi_clients`, `wifi_client_detail` and `wifi_ssid_mapping`, and put only the authorized station MACs in `read_inventory.wireless_clients`; these queries need no `config_access` or `diagnostic_recipes` grant. The device-side Wi-Fi write permission stays with that login; the Helper exposes only the selected fixed reads, with the typed MAC constraint, host-key pin, output limits and audit.

**FortiOS query added in NetOps 1.0.7 (2026-11-09):** `system_interfaces` (`get system interface`), the source of the `switch_read` table `ip_interface`, is a plain `get` read covered by the first row of the table above (`cli-get enable`); it changes nothing on the device. A read-only account answered it completely on a FortiGate-80F with FortiOS 8.0.2 build0251 on 2026-11-09 (`tests/fixtures/real/fortinet/fortigate80f_8.0.2`); 7.6.x was not measured.

### FortiADC

This section is the reference for the FortiADC accounts of every NetOps role. The rows were measured on FortiADC-KVM 7.6.7 build0676 (virtual image, standalone) between 27 October and 2 November 2026; FortiADC HA was not used for these account measurements. "Not measured" means that nobody has tried that combination.

With the existing `config_access: ["read"]` grant, `config_read` permits the object section `load-balance real-server NAME` (`show` or `show full-configuration`); `triage_slb` uses its IP for enrolled DOWN-member follow-up diagnostics.

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

**EXOS load sharing:** `switch_read table="lag"` uses the opt-in `lag_summary` query (`show sharing`) for static and LACP groups. The former query name `sharing` remains excluded; enroll `lag_summary` in `enabled_queries`. Like the other EXOS reads below, nonempty output with SSH exit status 250 is accepted only without EXOS error markers, preserving `rc: 250` and `exit_status_250`.

The ExtremeXOS 33.7.1 user-level profile excludes show accounts and show configuration. Some catalogue reads can return complete output with status 250; distinguish device CLI errors, command status and answer completeness. Port reads require one enrolled port and feature permissions. This read profile neither grants mutation nor establishes every build's compatibility.

**EXOS queries added in NetOps 1.0.7 (2026-11):** `ports_description`, `ports_rx_errors`, `ports_tx_errors`, `ipconfig`, `route_table`, `ipv6_route_table`, `lldp_neighbors_detail`, `stp_ports`, `mlag_peer`, `mlag_ports`, `inline_power_stats`, `ntp_association`, `log_messages`, `log_warnings` and `log_configuration` returned complete output through a non-administrator SSH account on four physical switches (X435-8P-4S and three X440G2-12p-10G4, all 33.7.1.6, exit status 0). The X435 answers `show mlag` with `%% Unrecognized command` (reported as `unsupported`). `show log` is read-only but its content (login names, source addresses, port events) is as sensitive as the tables; only the three fixed templates exist, with no filter, window or `nvram` variant. The switch keeps at most 1000 messages in memory and every login by this tool is itself logged, so a busy buffer is mostly its own `AAA.LogSsh` lines: prefer `log_warnings` for faults and page `log_messages` from the newest message. The Helper enforces a fixed limit of 200 lines for `log_messages` and `log_warnings`, applied to the redacted output before it is stored or paged and cut at a message boundary; the result then carries `line_limit` (`max_lines`, `total_lines`, `returned_lines`, `truncated`), the warning `log_line_limit` and a closing note line. Older messages are not reachable; the limit is not configurable. Measured on the same switches, `show vlan <name>`, `show port <n> information detail` and `show iproute ipv6 summary` print complete output but end with exit status 250; for the EXOS profile only, exit status 250 is accepted as success when the output is non-empty and contains none of the EXOS error marks (`%% `, `Error:`, `Invalid input`, `Incomplete command`); the result keeps `rc` 250 and carries `warnings: ["exit_status_250"]` (`ssh_read`, `switch_read` and `locate_endpoint` share this rule). Status 250 with an error mark or with empty output remains a `device_cli_error` or `empty`, and other profiles do not normalize 250. The legacy query name `sharing` stays excluded; the fixed `lag_summary` source uses the same exit-status rule.

Compatibility scope: ExtremeXOS 33.6.1.14 virtual image with a user-level RSA account and explicit legacy_ssh: "rsa-sha1". Commands absent from the image are reported as device_cli_error; a virtual-image query contract is not universal hardware support.

### Cisco IOS

Use a dedicated low-privilege identity with a parser view or external AAA command authorization that permits the exact enrolled command set. Numeric privilege level alone may be too broad or too narrow and must not be treated as proof.

Confirm there is no path to enable mode, configuration mode, running/startup configuration display, file display/copy, debug, reload, support collection, embedded scripting, or shell escape. Test the exact interface grammar and every enabled query over the same SSH transport.

Compatibility scope: IOSv 15.9(3)M12 and IOSvL2 15.2(20200924), privilege-1 RSA accounts and exec-channel transport. Unsupported or unauthorized commands can return Line has invalid autocommand with exit status 0; Helper reports the refusal as device_cli_error. Their SHA-1-only key exchange requires the explicit per-device legacy exception. Privilege 1 is a bounded profile, not a universal authorization recommendation.

**IOS measurement (2026-11-08, GNS3 lab, built-in privilege 1 account, exec channel, no pager):** all templates of the catalogue were run on both images (table in [the Cisco notes](vendor-cli-references/cisco.md#lab-measurements-gns3-lab-2026-11-08)). Privilege 1 answered all IOS templates added in 1.0.7 except four reads that need a higher privilege level and are answered `Line has invalid autocommand "..."` with exit status 0: `log_messages` (`show logging`), `stp_inconsistent` (`show spanning-tree inconsistentports`), and, on the router image, `stp_summary`; `show running-config`, `show spanning-tree blockedports`, `show snmp user`, `show port-security`, `show archive ...` and `dir` are refused the same way and are not in the catalogue. The command is the same message on a router image for a command the image does not have (`show interfaces status`, `show mac address-table`, `show vlan brief`, `show etherchannel summary` on IOSv), so the Helper cannot tell "refused" from "not on this image" and reports `permission_denied` for both. A single read can be admitted without a parser view: on IOSvL2, `privilege exec level 1 show logging` made the privilege-1 account read the 81-line log buffer (the account still got `Line has invalid autocommand "show running-config"`); `no privilege exec level 1 show logging` removed it again. The privilege raise applies to every privilege-1 user of that device, so prefer a parser view or TACACS+ command authorization in production. Not answerable by the virtual images (`verified: docs-only`): `show env all`, `show inventory` (IOSvL2 prints nothing), `interface_transceiver`, `power_inline`, `stack_members`, `stack_ports`.

### Cisco IOS-XE

Use a dedicated identity with exact command authorization, not a reused administrator or broad automation account. IOS-XE adds platform and software-management surfaces beyond classic IOS; deny install/package, guestshell/application hosting, file-system, diagnostic archive, reload, debug, and configuration/export capabilities.

Permit only the catalog commands actually enrolled for the target and validate both positive reads and negative commands through the production AAA policy. Treat a role label or privilege number as insufficient without command logs.

Compatibility scope: IOS-XE 17.18.2 IOL router image with privilege-1 RSA accounts. Feature availability differs by image; privilege and unsupported-command refusals remain device_cli_error even with exit status 0. Account authorization and host-key probing must be verified for each deployment.

**IOS XE follow-up (2026-11-09, IOL XE 17.18.2 router image, `netops-ro` privilege 1, `netops-admin` privilege 15):** every template of the `cisco_xe` profile was run (table in [the Cisco notes](vendor-cli-references/cisco.md#cisco-ios-xe)). The lab has no Catalyst 9000 or C8000V, so the switch and platform reads (`interfaces`, `mac_table`, `vlans`, trunk, err-disable, PoE, stack, `platform_resources`, `environment`, `lag_summary`) are refused by the *image* with `Line has invalid autocommand "..."` and exit status 0 for both accounts (the admin account gets the same line, so this is not a privilege finding) and stay `verified: docs-only` (layouts from the Catalyst 9300 17.15 documentation, `tests/fixtures/docs/cisco_xe`). Privilege 1 refused only two reads that the admin account answered: `log_messages` (`show logging`) and `stp_inconsistent`, as on IOS. IOL closes the SSH transport after every exec command, so each read is a new login. `show version` on IOL starts with `Cisco IOS Software [IOSXE], ...` (no `Cisco IOS XE Software` line); Helper recognizes that as IOS XE, never as IOS.

### Cisco NX-OS

Use a dedicated NX-OS RBAC role or external AAA policy with the smallest required show-command rules and VDC/tenant scope. Do not assume a built-in operator role is automatically a perfect match for this catalog.

Deny configuration, checkpoint/rollback, file and bootflash access, guestshell/bash, install, reload, debug, Ethanalyzer/capture, support bundles, and full configuration display/export. Verify rule ordering and inherited permissions, then test every enabled command against the exact VDC and software release.

Compatibility scope: Nexus 9300v and 9500v NX-OS 9.3(12), network-operator role and RSA keys. Permission-denied and syntax refusals are device_cli_error. HSRP, VRRP and vPC queries require their features to be enabled; the role and virtual-image profile do not imply every hardware feature.

**NX-OS measurement (2026-11-09, Nexus 9300v 9.3(12), user `netops-ro` in the built-in `network-operator` role, exec channel):** every template of the catalogue was answered or refused as listed in [the Cisco notes](vendor-cli-references/cisco.md#cisco-nx-os). `network-operator` reads everything the catalogue needs, including `show logging last 200`, `show license usage`, `show module`, `show system reset-reason` and the vPC reads; it is refused `show boot` and `show accounting log` (`% Permission denied for the role`, exit status 30), which are therefore not catalogue templates. A feature that is off answers `Syntax error while parsing` with exit status 16 (HSRP, VRRP, DHCP snooping, BGP and BFD until enabled); `show vpc orphan-ports` without a peer link answers `ERROR: Peer-link not present` with exit status 244. `show running-config diff` is not in the catalogue because configuration text can carry secrets. Enrollment needs `legacy_ssh: "rsa-sha1"` for the RSA2048 host key. A 9300v prints no LLDP neighbour on a data port (only on `mgmt0`), so a data link to it is not identified by LLDP; `locate_endpoint` still finds a host behind it by its MAC table.

### Arista EOS

Use a dedicated EOS role or AAA command-authorization policy that permits only the enrolled operational commands. Restrict VRF and tenant visibility where the authorization system permits it.

Deny enable/configuration paths, bash or shell access, file and extension management, event-handler changes, reload, debug, packet capture, support bundles, and configuration display/export. Test role inheritance and command-regex behavior with the actual EOS release instead of relying on a generic read-only label.

Compatibility scope: Arista EOS 4.36.1F container and virtual images, network-operator role and ed25519 keys. Privilege and invalid-command refusals are reported as device_cli_error; feature-absence responses can remain successful reads. The profile does not establish hardware or AAA-command compatibility.

Password credentials also support SSH keyboard-interactive password authentication.
The Helper tries the SSH password method first, then keyboard-interactive, and
answers only a `Password:` prompt (case-insensitive, with an optional OpenSSH
user/host prefix), once per connection. OTP, passcode, MFA, host-key confirmation
and a second password prompt are refused; the connection fails with an
authentication error. Host-key pinning and `StrictHostKeyChecking=yes` still
apply. Known limitation: a device offering both `password` and keyboard-interactive
can count two failed attempts for one connection with a wrong password, which may
matter for lockout thresholds. This supports a password-only EOS login, not an OTP/MFA exchange.
Measured through the Helper `version` query on 2026-11-09 with an EOS
4.36.1F network-operator account using a stored password: successful exec read.

**EOS measurement (2026-11-08, cEOS 4.36.1F, user in the built-in `network-operator` role, `show privilege` = 1, no AAA command authorization configured):** every template of the catalogue was answered (table in [the Arista notes](vendor-cli-references/arista-eos.md#lab-measurements-gns3-lab-2026-11-08)), with exit status 1 and a `> command` echo line for the notices `% BGP inactive`, `! IPv6 routing not enabled`, `% There seem to be no power supplies connected` and `% No IPv6 configured interfaces`. EOS prints the command and `% Invalid input (privileged mode required) at line 1` (exit status 1) for what privilege 1 may not run: `show aaa methods all`, `show ip access-lists`, `show boot-config`, `show running-config diffs`, `show users`, `show vrrp`, `dir flash:` and the pipe `| tail`; the pipe `| json` is accepted. `show logging` and `show logging 200` are readable by the role (log content is sensitive; `log_messages` is the one fixed template). `interface_poe` is answered `% Invalid input` by the virtual platform (`verified: docs-only`), as are optics (`interface_optics` prints nothing) and power/cooling sensors. MLAG reads answer in the inactive state only.

### Junos OS

Use the built-in `read-only` login class for the dedicated NetOps account. NetOps recommends only manufacturer-provided read-only roles; it does not recommend a custom class with `maintenance`. Restrict logical-system, routing-instance, or tenant visibility where applicable.

Do not grant configuration or maintenance permissions merely to make operational commands work. Explicitly deny configuration display/export, `configure`, file operations, request/maintenance actions, shell access, support collection, packet capture, and secret-bearing outputs. Validate both classic and ELS target profiles separately because accepted interface syntax and query catalogs differ.

Compatibility scope: vJunos-switch 26.2R1.7 with the built-in read-only login class and ed25519 keys. Configuration and unknown-command refusals are device_cli_error even when the command exits with status 0. A root account has different credential requirements and is not the read-only profile.

Password credentials work through SSH keyboard-interactive with the same
single-password-prompt policy described for EOS above. OTP/MFA and repeated
password prompts are unsupported; never supply an OTP or passcode as the stored
password. The `version` query sends `show version | no-more`, without changing
the device's paging configuration.
Measured through the Helper `version` query on 2026-11-09 with a vJunos-switch
26.2R1.7 read-only account using a stored password: successful exec read.

**Junos measurement (2026-11-09, vJunos-switch 26.2R1.7, user `netops-ro` in the built-in `read-only` class, exec channel):** every template was run (table in [the Junos notes](vendor-cli-references/juniper-junos.md#junos-os-els)). `read-only` (permission `view`) answers all of them except the two log reads, which it refuses with `error: permission denied: log` (exit status 0). Reading the specific log file needs both command permission (`trace`) and file-read access; `view trace` alone gave `error: could not open 'messages': Permission denied`. A temporary lab experiment with `maintenance` could read the logs, but also granted broader powers. That experiment was removed after measurement and is not a deployable read-only recipe: rejecting three commands did not establish a complete permission boundary, including alternative configuration reads such as `show system rollback 0`. NetOps does not recommend granting those broader permissions. The log templates `log_messages` and `log_interactive_commands` are therefore `permission_denied` with the built-in `read-only` class; this is a known limitation. Keep that class and send logs to a syslog collector when log access is needed. The `show system commit` history (who committed what and when) is readable with `read-only`. Features that are not configured answer a `warning: ... subsystem not running` notice (VRRP, LACP, PoE, DHCP security, 802.1X) or `BGP is not running` (no licence key), `Spanning-tree is not enabled at global level` (all `not_applicable`/empty, not errors). The `| last 200 | no-more` form leaves a `---(more 100%)---` mark in front of the last line; the Helper removes it from those two reads. Operational note from the measurement: with VRRP, LACP, RSTP and NTP configured the virtual RE (idle 0 %) needed about 65 seconds per exec session, longer than the Helper's 60-second SSH read timeout; after removing them it answered in 5 seconds. A physical platform does not show this.

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

On FortiOS 8.0.2 build0251 a read-only account can use the separately enabled
`wifi_ap_status`, `wifi_vap_status`, `wifi_neighbors`, `wifi_controller_status`,
`wifi_controller_statistics`, `wifi_rf_analysis` and `wifi_events` queries (access
points and radios, SSIDs, scan results, controller counters, RF analysis and the
wireless event log) and the `wifi_triage` tool built on them. The measurement is
described in [the FortiOS reference](vendor-cli-references/fortinet-fortios.md#wi-fi-reads-for-a-read-only-account-measured).
These reads expose no live station list and no station RSSI: the signal of a client
is only the value logged in its last event. Without a REST token `wifi_triage` lists the live
signal as missing (`reason: rest_token_not_enrolled`); an enrolled read-only REST token
([Wi-Fi REST guide](../../../docs/fortios-wifi-rest.md)) adds live RSSI and SNR.
The five older `diagnose wireless-controller` queries (`wifi_clients`,
`wifi_client_detail`, `wifi_access_points`, `wifi_ap_detail`, `wifi_ssid_mapping`)
stay available only for an `admin-bounded` account with `wifi read-write` and
`cli-diagnose enable`; for a read-only account the new set is their replacement.

## Separate read-only API user for live Wi-Fi

The RO SSH refusal above does not apply to the new public REST `wifi_clients`, `wifi_aps_live` and `wifi_rogue` tools. On 2026-11-08, FortiGate-80F 8.0.2 build0251 returned GET 200 with a separate API user and all ten access-profile groups `read`; measured PUT/POST/DELETE attempts returned 403. The API user has a token and narrow trusthosts, independent of the SSH login. `wifi_triage` can add live RSSI/SNR through this optional path. No REST token is needed for the existing SSH diagnostics.

The later 2026-11-09 minimum-profile measurement verified `wifi read` plus
`loggrp read`, all other groups `none` including `authgrp`, and all `cli-*`
disabled; seven GETs returned 200 and PUT/POST/DELETE 403. All-read is an
alternative. In single-VDOM mode omit `set vdom` (FortiOS rejects it); only
multi-VDOM provisioning uses `set vdom "root"`, without qualifying runtime there.
An administrator with API-user rights must generate the token. Set
`helper.fortios_rest_port` to management `admin-sport` when it differs from 443,
and allow that port in TCP egress; inventory `port` controls SSH only.

Follow the [FortiGate administrator checklist](../../../docs/fortios-wifi-rest.md#create-access-on-fortigate) for the exact profile/API-user CLI, source trusthost, certificate pin or CA, private NetOps `api-token` vault record and inventory reference, verification, rotation and revocation. NetOps exposes only fixed Wi-Fi GETs and cannot perform writes with that token. Never raise the SSH account to `wifi read-write` merely to enable this REST feature.

## EXOS, Cisco, Arista and Junos built-in roles

Device-side authorization is the first layer; the explicitly enabled NetOps
catalogue and typed slots form the second layer. The built-in role name alone
is not evidence of effective read-only rights. Verify AAA inheritance on the
enrolled firmware. Identity dependencies are listed in [normalization](normalization.md).
No role is broadened automatically after a refused read. Configuration reading
is a separate per-target opt-in; this foundation adds no new config readers.

| OS | Vendor role / baseline | What it permits and limits |
|---|---|---|
| EXOS | `user` account (`create account user netops-ro`, credentials provisioned separately) | Operational show reads; `show configuration` and `show accounts` are not permitted by the user boundary. Use AAA command authorization for a narrower list. |
| IOS / IOS XE | User EXEC, privilege 1 | Basic show commands, including version and (IOSvL2, IOSv, measured) all IOS templates added in 1.0.7 except `show logging` and `show spanning-tree inconsistentports`, which need a higher privilege level; many other operational diagnostics need additional authorization. Where available, a parser view with explicit catalogue commands or TACACS+ can add only required reads. Never grant `include all show` or assume privilege 15 is read-only. The boundary is the same on a switch and a router. |
| NX-OS | `network-operator` | Built-in read access to operational state; broad visibility can include configuration. Remove inherited write roles and verify any VDC-specific roles and AAA authorization. NetOps exposes only enrolled queries. |
| EOS | `network-operator` | On cEOS 4.36.1F without command authorization the account is at privilege 1 and was refused `show aaa methods all`, `show ip access-lists`, `show boot-config`, `show running-config diffs`, `show users`, `show vrrp` (`privileged mode required`) but read every catalogue template including `show logging 200` and `| json`. Built-in EXEC access is broad: it permits EXEC commands except shell/pipe restrictions, including potentially mutating EXEC operations. It is **not a sufficient read-only boundary by itself**. Without `aaa authorization commands all default local` (or TACACS+/RADIUS command authorization) EOS does not enforce the role at all: every authenticated user keeps the rights of its privilege level. With authorization enabled, `network-operator` refuses the pipe `\|`, so a future `\| json` template (a JSON form of a command) does not pass with it; use a custom role with anchored `^show ...$` rules that allow exactly the enrolled templates, ending in `deny command .*`. NetOps's allowlist remains an additional layer. |
| Junos | Login class `read-only` | The class `read-only` is the permission `view` (operational state) without `view-configuration`; it does not see the configuration. Do not substitute `operator` or grant `network`, `all` or configuration permissions. Future `ping`/`traceroute` templates need `network` or an exact `allow-commands` list; grant them only through exact `allow-commands` entries for the enrolled templates (with `deny-commands` for the rest), never by adding the `network` permission. Any configuration permission must be explicitly approved for the target. |

Sources: [EXOS command reference](https://documentation.extremenetworks.com/exos_32.2/GUID-C9F3FABF-4209-4023-BC5A-0914CCCB91D8.shtml),
[Cisco CLI views](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-17/sec-usr-cfg-xe-17-book/sec-cli-views.html),
[NX-OS RBAC](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-105x/m-configuring-user-accounts-and-rbac.html),
[EOS user security](https://www.arista.com/en/um-eos/eos-user-security),
[Junos login classes](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class-overview.html).


### Wireless log display filters

`execute log filter category event`, `execute log filter field subtype wireless`
and `execute log filter view-lines N` change only log display in the current SSH
session. They do not save device configuration. The enrolled `wifi_events` SSH
query keeps all filters and `execute log display` in one session. This does not
authorize console configuration or pagination changes. With a read-only REST
API enrollment, `wifi_triage` prefers the fixed wireless log GET documented in
[Wi-Fi REST](../../../docs/fortios-wifi-rest.md). Missing/disabled SSH history is
a missing step and does not block live client/AP diagnostics.


The IOS/IOS XE `interfaces_counters_errors` template runs read-only
`show interfaces counters errors`. If the device refuses, lacks or returns no
ports for that command, the separately enabled `interfaces_details` template
runs exactly `show interfaces` (no slots, all interfaces, high-volume). Enroll
both queries for normalized `interface_errors`; the device account/view or
TACACS+ rules must allow exactly those operational reads, without granting a
broader show wildcard or raising privilege. The optional `interface` filter is
applied locally to the whole-port result, with no CLI interpolation. The existing
slotted `interface_details` and `interface_errors` remain available as explicit
catalogue reads and retain their inventory checks. No counter clearing,
configuration, pager setting, restart or write command is used. NX-OS retains
singular `show interface counters errors`. EOS discards and EXOS TX reads need
their own existing enabled-query entries.

### FortiSwitch normalized tables

`switch_read` uses the existing read-only FortiOS catalogue commands
`diagnose switch-controller switch-info mac-table {managed_switch}` and
`diagnose switch-controller switch-info lldp neighbors-summary {managed_switch}`.
Enable only `managed_switch_mac` / `managed_switch_lldp` as needed and enroll the
serial in `read_inventory.managed_switches`; no additional permission or template
is introduced. Read-only FortiGate 80F 8.0.2 build0251 captures from 2026-11-09
contain an all-switch MAC listing and serial-specific LLDP summaries. Their layouts
are replayed through the proxy and worker; this does not qualify every FortiSwitch
firmware or a live MCP read. No console/output setting is changed.

### FortiGate-local normalized tables (2026-11-10)

On FortiGate 80F, FortiOS 8.0.2 build0251, HA primary, `netops-test-ro`
accepted the existing read-only queries below without any account or console change:

| Table without `managed_switch` | Enable query | Device command and observed result |
|---|---|---|
| `interface` | `physical_interfaces` | `get system interface physical`: 11 ports, link up/down, negotiated speed/duplex; no administrative state |
| `vlan` | `interface_vlan_ids` | `show system interface`: 8 VLAN interfaces, ID, parent and configured IPv4 where present; only these fields are returned, no full configuration |
| `lldp_neighbor` | `lldp_summary` | `diagnose lldp rx neighbor summary`: 2 neighbors on a/b; no management IP or capabilities in this layout |
| `mac_entry` | `bridge_mac_table`, with `read_inventory.switches` | `diagnose netlink brctl name host {switch}`: enrolled `internal` hard-switch FDB accepted but empty; populated local FDB layouts remain unqualified and unparsed |

No new catalogue template or privilege is needed. `system_interfaces` remains
the independent `ip_interface` read. Local VLANs describe interface configuration,
not physical port membership. A missing local bridge enrollment/query returns
`not_applicable`: “FortiGate je L3; MAC klientů viz arp a FortiSwitch”.
With `managed_switch`, the existing FortiLink queries and serial enrollment
still apply to `interface`, `mac_entry`, `lldp_neighbor`, `interface_errors` and
`port_vlan`. `diagnose lldprx neighbor summary` and `get system lldp neighbors`
were refused on this exact RO account/build; neither is a fallback.
