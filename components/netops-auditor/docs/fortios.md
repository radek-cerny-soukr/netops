# FortiOS audit

Use an enrolled, pinned SSH host key for collection. The Auditor reads the configuration and
the effective values needed for its rules in one SSH session. It also accepts an offline export
and supports the existing pinned HTTPS backup channel. The recorded SSH snapshot hash comes
from the original configuration read. The collector handles console pagination in the session.

FortiOS can return the same section headers to administrators with different privileges. A
visible `super_admin` object is evidence for the administrator table in that scope. A restricted
administrator may only see its own entry. The administrator checks report
`admin-visibility-unproven` when an observed table does not establish coverage. Safeguard
checks can report individual visible objects while recording a coverage gap.

| Check | Evidence |
|---|---|
| SSH v1 | `system global admin-ssh-v1`, plus a live configuration interface with `allowaccess ssh` and administrative status up |
| External login | `system admin` remote authentication, `user group` membership and a RADIUS or TACACS+ endpoint, with `external_aaa_required` |
| SNMPv3 | Enabled SNMP and an enabled user with a security level below `auth-priv` |
| NTP authentication | Active custom entries under `system ntp/ntpserver`, with `ntp_auth_required`. FortiGuard sources use a separate branch. |
| Syslog severity | Effective filter severity on each configured active syslog destination, with `syslog_severity` |
| Unused physical port | Physical interface administratively up, with an explicit `ports` declaration of `role: unused` |

Missing permissions, unresolved effective values, and mismatched table readbacks can leave a
rule unevaluated. Secret values stay out of finding evidence. The checks assess configured
settings. The existing global and VDOM scope gates remain in effect.

FortiOS can omit default-valued fields and empty tables from `show` and HTTPS backups.
Auditor uses the FortiOS 7.6 defaults for covered sections. A live section with unproven
visibility, an explicit refusal, or a mismatched readback retains its coverage gap.
For NTP, the downloadable CLI schema lists `ntpsync disable` as its parameter default;
the FortiGate 60F 7.6.8 readback verifies the FortiGuard baseline used here
(`ntpsync enable`, `type fortiguard`, `authentication disable`).

## CLI references

| Rule | Source |
|---|---|
| SSH v1 | [FortiOS system global](https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/339914554/config-system-global) and [system interface](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/317104469/config-system-interface) |
| External admin login | [FortiOS system admin](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/390485493/config-system-admin) and [TACACS+ servers](https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/864014) |
| SNMPv3 | [FortiOS system snmp sysinfo](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/195798379/config-system-snmp-sysinfo) and [system snmp user](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/292257317/config-system-snmp-user) |
| NTP authentication | [FortiOS system ntp](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/105110478/config-system-ntp). The key is a placeholder. |
| Syslog severity | [FortiOS log syslogd filter](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/273422104/config-log-syslogd-filter) and [syslog setting](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/141516630/config-log-syslogd-setting) |
| Unused physical port | [FortiOS system interface](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/317104469/config-system-interface) |
