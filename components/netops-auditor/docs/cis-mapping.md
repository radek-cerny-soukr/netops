# CIS FortiGate benchmark mapping

The FortiOS catalogue references the **CIS FortiGate 7.4.x Benchmark v1.0.1** by recommendation number. This page lists what each rule checks against that recommendation and which recommendations no rule covers. It is not a compliance profile: a configuration without findings is not CIS compliant, and the benchmark text itself is not reproduced here.

Every rule reads a saved configuration (`show` output) only. A setting that `show` omits is taken at its default, and a rule reports a missing setting only where the CLI Reference of FortiOS 7.4.12, 7.6.7 and 8.0.1 gives the weak value as the default. The hardening rules also cite the hardening chapter of the FortiOS 8.0.0 Best Practices guide where it says the same.

## Covered

| CIS | Rule | What the rule does not check |
|---|---|---|
| 1.3 | `fortios.mgmt.wan-admin-access` | reads http, https, ssh and telnet on interfaces with role wan; ping, snmp and radius-acct are not checked |
| 2.1.4 | `fortios.time.no-ntp-sync` | whether the configured time source is correct |
| 2.1.7 | `fortios.system.usb-auto-install` | an export without the auto-install section |
| 2.1.8 | `fortios.crypto.static-key-ciphers` | an export without the global section |
| 2.1.9 | `fortios.crypto.strong-crypto-disabled` | - |
| 2.1.10 | `fortios.mgmt.gui-legacy-tls` | reports versions below TLS 1.2; the benchmark asks for TLS 1.3 alone |
| 2.2.2 | `fortios.mgmt.lockout-threshold` | the lockout duration |
| 2.3.1 | `fortios.snmp.v1v2c-community` | whether an SNMPv3 user exists and the agent is enabled |
| 2.4.1 | `fortios.mgmt.default-admin-account` | whether the account still has an empty password |
| 2.4.4 | `fortios.mgmt.idle-timeout` | per-profile and per-administrator timeout overrides |
| 2.4.5 | `fortios.mgmt.plaintext-admin-access` | - |
| 3.2 | `fortios.policy.service-all` | - |
| 3.4 | `fortios.policy.logging-disabled` | reports only an explicit disable; the benchmark asks for all sessions on accepting policies |
| 7.2.1 | `fortios.logging.no-syslog-target` | FortiAnalyzer or FortiManager as the central target |

`fortios.auth.ldap-without-tls` has no CIS counterpart; it follows the Encrypted protocols section of the Best Practices guide.

## Not covered

- **Runtime state or an outside source**, not visible in a configuration file: 2.1.6 (latest firmware), 4.2.1 and the other FortiGuard database items, the Security Fabric item of section 5.2, 6.1.1 (trusted certificate for the VPN portal).
- **A judgement about the organisation**: 1.2 (intra-zone traffic), 2.1.1 and 2.1.2 (banners), 2.1.3 (timezone), 2.1.5 (hostname), 2.3.2 (SNMP trusted hosts), 2.4.2 (trusted hosts on every login), 2.4.3 (profiles per administrator), 3.1 (unused policies), 4.5.1 (high-risk application categories).
- **Readable from the configuration, but reporting the default of almost every device**: 2.4.7 (default admin ports) and 7.3.2 and 7.3.3 (encrypted syslog). Not implemented; such a rule would need a way to state an accepted default first.
- **Readable from the configuration, not implemented yet**: 2.1.11 to 2.1.13, 2.2.1 (password policy), 2.3.3 and 2.3.4, 2.4.6 and 2.4.8 (local-in policies and virtual patching), the high-availability items of 2.5, 3.3, the security profile items of section 4, 5.1.1, 6.1.2, 7.1.1 and 7.3.1.
