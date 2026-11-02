# CIS FortiGate benchmark mapping

The FortiOS catalogue references the **CIS FortiGate 7.4.x Benchmark v1.0.1** by recommendation number. This page lists what each rule checks against that recommendation and which recommendations no rule covers. It is not a compliance profile: a configuration without findings is not CIS compliant, and the benchmark text itself is not reproduced here.

Every rule reads a saved configuration (`show` output) only. A setting that `show` omits is taken at its default, and a rule reports a missing setting only where the CLI Reference of FortiOS 7.4.12, 7.6.7, 8.0.0 and 8.0.1 gives the weak value as the default. Where the default differs between those releases, the rule reports `not-evaluated` with `default-differs-by-release` instead of guessing. Some rules (2.1.12, 4.2.5) report the default state of almost every device, because the default value is the weak one. The behaviour of `show` for the default `status` in `system password-policy` is verified only on the releases measured on a device; the behaviour on other releases is not claimed. The hardening rules also cite the hardening chapter of the FortiOS 8.0.0 Best Practices guide where it says the same.

## Covered

| CIS | Rule | What the rule does not check |
|---|---|---|
| 1.3 | `fortios.mgmt.wan-admin-access` | reads http, https, ssh and telnet in allowaccess of the primary and secondary IPv4 addresses and in ip6-allowaccess of interfaces with role wan, each finding with its origin; ping, snmp and radius-acct are not checked |
| 2.1.4 | `fortios.time.no-ntp-sync` | whether the configured time source is correct |
| 2.1.7 | `fortios.system.usb-auto-install` | an export without the auto-install section is read at the default, which `show full-configuration` printed as disable on FortiOS 7.6.8 and 8.0.2 |
| 2.1.8 | `fortios.crypto.static-key-ciphers` | an export without the global section, which leaves the rules of that section `not-evaluated` (`section-missing: system global`) |
| 2.1.9 | `fortios.crypto.strong-crypto-disabled` | - |
| 2.1.10 | `fortios.mgmt.gui-legacy-tls` | reports versions below TLS 1.2; the benchmark asks for TLS 1.3 alone |
| 2.1.12 | `fortios.logging.single-cpu-high` | a deployment that watches CPU load through another channel |
| 2.1.13 | `fortios.mgmt.gui-display-hostname` | Level 2 item; reads only the GUI hostname setting |
| 2.2.1 | `fortios.mgmt.password-policy` | guest-admin password policy; a missing status where the default differs by release is reported not-evaluated |
| 2.2.2 | `fortios.mgmt.lockout-threshold` | the lockout duration |
| 2.3.1 | `fortios.snmp.v1v2c-community` | whether an SNMPv3 user exists and the agent is enabled |
| 2.4.1 | `fortios.mgmt.default-admin-account` | whether the account still has an empty password; a snapshot without a `super_admin` administrator leaves the rule `not-evaluated` (`admin-visibility-unproven`) |
| 2.4.2 | `fortios.mgmt.admin-no-trusthost` | judgement class (Manual in the benchmark): reports only accounts without trusted hosts; `system api-user` and `system sso-admin` are not read; IPv6 access is reported as not restricted by configuration; a snapshot without a `super_admin` administrator leaves the rule `not-evaluated` (`admin-visibility-unproven`) |
| 2.4.4 | `fortios.mgmt.idle-timeout` | per-profile and per-administrator timeout overrides |
| 2.4.5 | `fortios.mgmt.plaintext-admin-access` | - |
| 3.2 | `fortios.policy.service-all` | - |
| 3.4 | `fortios.policy.logging-disabled` | reports only an explicit disable; the benchmark asks for all sessions on accepting policies |
| 4.1.2 | `fortios.policy.wan-missing-profile` | traffic inspected elsewhere; destinations that cannot be resolved are reported not-evaluated |
| 4.2.2 | `fortios.policy.wan-missing-profile` | same rule as 4.1.2; reports the antivirus profile kind |
| 4.2.4 | `fortios.av.detection-disabled` | reports grayware detection that is not enabled |
| 4.2.5 | `fortios.av.detection-disabled` | reports machine-learning detection that is disabled or only monitors; licence state |
| 4.3.2 | `fortios.dnsfilter.log-all-domain-disabled` | only profiles used by policies towards a WAN interface |
| 4.3.3 | `fortios.policy.wan-missing-profile` | same rule as 4.1.2; reports the DNS filter profile kind |
| 4.5.2 | `fortios.appctrl.default-port-not-enforced` | only lists used by policies towards a WAN interface |
| 4.5.4 | `fortios.policy.wan-missing-profile` | same rule as 4.1.2; reports the application control kind |
| 6.1.2 | `fortios.vpn.ssl-legacy-tls` | Level 2 item; reads protocol versions and the cipher set of the SSL VPN settings |
| 7.1.1 | `fortios.logging.event-disabled` | Level 2 item; reports only an explicit disable of an event category |
| 7.2.1 | `fortios.logging.no-syslog-target` | FortiAnalyzer or FortiManager as the central target |
| 7.3.1 | `fortios.logging.faz-unencrypted` | FortiAnalyzer Cloud and per-VDOM override settings |

`fortios.auth.ldap-without-tls` has no CIS counterpart; it follows the Encrypted protocols section of the Best Practices guide.

`fortios.mgmt.netops-safeguard-leftover` has no CIS counterpart; it reports objects that an interrupted NetOps Admin operation left on the device.

## Not covered

| CIS | Category | Reason |
|---|---|---|
| 2.1.6 | Runtime state or an outside source | Needs the latest-firmware information from an outside release feed. |
| 3.1 | Runtime state or an outside source | Needs runtime hit counters, which a saved configuration does not hold. |
| 3.3 | Runtime state or an outside source | Needs the ISDB and FortiGuard object table. |
| 4.2.6 | Runtime state or an outside source | Licence and region are runtime state. |
| 4.4.1 | Runtime state or an outside source | Needs the FortiGuard web category map. |
| 4.5.1 | Runtime state or an outside source | Needs the FortiGuard application category map. |
| 5.1.1 | Runtime state or an outside source | Depends on FortiAP, FortiSwitch or EMS in the fabric. |
| 6.1.1 | Runtime state or an outside source | Trust in the issuing CA needs the certificate, not only the configuration. |
| 1.1 | A judgement about the organisation | Whether the DNS servers are trustworthy is a judgement about the organisation. |
| 1.2 | A judgement about the organisation | Intra-zone allow is visible; whether it is justified is a judgement. |
| 2.1.1 | A judgement about the organisation | Need and wording of the pre-login banner are decided by the organisation. |
| 2.1.2 | A judgement about the organisation | Need and wording of the post-login banner are decided by the organisation. |
| 2.1.3 | A judgement about the organisation | The correct timezone is a decision of the organisation. |
| 2.1.5 | A judgement about the organisation | Hostname naming is a judgement. |
| 2.3.2 | A judgement about the organisation | Whether the list of SNMPv3 hosts is right is a judgement. |
| 2.3.3 | A judgement about the organisation | Use of SNMPv3 queries is a judgement. |
| 2.4.3 | A judgement about the organisation | A process control over administrator profiles; no single setting shows a defect. |
| 2.4.6 | A judgement about the organisation | Whether the local-in policies are sufficient is a judgement. |
| 2.4.7 | A judgement about the organisation | The value of a non-default admin port is a judgement and a change hits every management client. |
| 2.5.1 | A judgement about the organisation | A standalone unit may be intended. |
| 4.1.1 | A judgement about the organisation | Botnet protection in IPS is a judgement; the link to the WAN is only a heuristic. |
| 4.3.1 | A judgement about the organisation | Botnet protection in the DNS filter is a heuristic. |
| 5.2.1.1 | A judgement about the organisation | Whether to use the Security Fabric is a judgement. |
| 7.3.2 | The fix depends on the receiving side | The fix needs a syslog receiver with TLS and a certificate. |
| 7.3.3 | The fix depends on the receiving side | Duplicate of 7.3.2; the fix depends on the receiving side in the same way. |
| 2.1.11 | Readable from the configuration, not implemented | Readable; the CDN setting has no security gain, so it is left out. |
| 2.3.4 | Readable from the configuration, not implemented | The benchmark gives no threshold and needs the SNMP agent on, which would conflict with 2.3.1 on devices without SNMP. |
| 2.4.8 | Readable from the configuration, not implemented | Readable; the effect depends on a licence, planned for a later slice. |
| 2.5.2 | Readable from the configuration, not implemented | Only in HA mode; planned for a later slice. |
| 2.5.3 | Readable from the configuration, not implemented | Only in HA mode; planned for a later slice. |
| 2.5.4 | Readable from the configuration, not implemented | Only in HA mode; planned for a later slice. |
| 4.2.1 | Readable from the configuration, not implemented | Readable; the CLI Reference defaults of the update schedule are not verified and a real show prints a non-standard time. |
| 4.2.3 | Readable from the configuration, not implemented | Per protocol and licence dependent; kept in reserve. |
| 4.2.7 | Readable from the configuration, not implemented | The CLI attribute names are not verified. |
| 4.5.3 | Readable from the configuration, not implemented | The mapping from the GUI setting to the CLI is not verified. |

## Measured schema rules

The schema-check command is a separate integrity and upgrade audit. Its rules for references, removed paths and attributes, changed values, scope and target availability have no assigned CIS recommendation number. They do not check a benchmark control or simulate firmware migration. Their coverage report distinguishes observed checks from missing metadata.

VDOM and nested table scopes are supported by schema-check. The existing benchmark catalogue still requires individual VDOM exports and refuses a global/VDOM wrapper in `run` and `collect`. The exception is `schema-check --full-snapshot --catalog-vdoms`: it evaluates the catalogue rules, except the VDOM scope gate, separately for the global scope and for each VDOM of a wrapped dump, and a rule whose scope or availability the schema library does not measure is reported `not-evaluated`. The references and limitations in the mapping above continue to apply to that catalogue. From the release with the CIS expansion, `run` on an export of a single VDOM exits with code 3, because the eight global rules report `not-evaluated` with `section-missing: system global`; a global part without the wrapper gives a false finding of `fortios.av.detection-disabled` (grayware) and findings of `fortios.logging.event-disabled` and `fortios.vpn.ssl-legacy-tls` without data. For devices with VDOMs use `schema-check --full-snapshot --catalog-vdoms`; for devices without VDOMs use a complete `show`. The `not-evaluated` result from the global precondition applies in the VDOM view as well.


| Schema rule | Fixtures | Benchmark mapping |
|---|---|---|
| fortios.schema.reference | missing target, empty table, builtin/special value, nested owner and VDOM in tests/test_schema_checks.py | configuration integrity; no CIS control number |
| fortios.schema.upgrade-path | configured removed path | upgrade comparison; no CIS control number |
| fortios.schema.upgrade-attribute | configured removed attribute and inline table | upgrade comparison; no CIS control number |
| fortios.schema.upgrade-value | option, integer bound, text length and type differences | upgrade comparison; no CIS control number |
| fortios.schema.upgrade-scope | VDOM object becoming global | upgrade comparison; no CIS control number |
| fortios.schema.upgrade-availability | measured unavailable target path | upgrade comparison; no CIS control number |

Missing types, option choices and integer bounds are reported as unknown. No finding for a missing reference means only that the configured values with measured reference metadata were checked. Hardware, licence, empty-context and unmeasured builtin gaps remain visible in coverage; they cannot establish complete reference coverage or benchmark compliance. The hardening catalogue above supplies the separate CIS and FortiOS 8.0.0 Best Practices mapping.
