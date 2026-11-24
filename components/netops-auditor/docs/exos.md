# ExtremeXOS and Switch Engine

Auditor reads `show configuration` over pinned SSH or from a configuration
file. The rules compare effective command order, including port ranges, with
explicit operator intent where applicable. A finding records the configured
state and the affected object. The existing Telnet, SNMP default-community,
time-source, syslog destination, and configuration-management checks keep
their established IDs and semantics.

| Area | Evidence |
| --- | --- |
| Management | HTTP and CLI idle timer switches, explicit or default. Account lockout uses the global and per-account commands in order and leaves an ambiguous administrator exception unevaluated. SSH evaluates the bound policy's ordered source entries when its body is available. |
| AAA | Management RADIUS or TACACS+ activation and a configured primary or secondary server. |
| SNMP | Activation is separate from community or USM configuration. The USM check joins users, security groups and management views. Findings use a scope label instead of community names, user names or key material. |
| Time and logging | Authenticated NTP requires active authentication and a trusted key on each configured server or peer. Syslog severity considers targets, filter and severity, including the `only` modifier. |
| Discovery and switching | Explicit effective LLDP transmit mode, EDP, STP domain membership and BPDU Restrict, untagged VLAN 1, client DHCP snooping, broadcast limits, and port administrative state. |

Controls for accounts, SSH source prefixes, external AAA, NTP authentication,
syslog severity, and port roles use [audit intent](management-policy.md).
DHCP snooping also requires declared VLAN tags and trusted DHCP ports.
The existing management policy still selects the expected native VLAN.

Visibility gaps are reported in Auditor coverage. `show configuration`
prints only settings that differ from the default. A pinned SSH collection
proves a module complete when the dump is clean, ends with the last module
and `show version` gives the software version (see
[channels](channels.md)). For a proven module the rules apply the default of
a setting that has no line:

| Setting | Module | Default |
| --- | --- | --- |
| `enable web http` | `thttpd` | HTTP enabled |
| `enable cli idle-timeout` | `cfgmgr` | enabled, 20 minutes |
| `lockout-on-login-failures` | `aaa` | off for every account |
| RADIUS and TACACS+ management login | `aaa` | disabled, local accounts only |
| `snmp access` | `snmpMaster` | disabled |
| `enable edp ports` | `edp` | enabled on every port |
| `enable lldp ports` | `lldp` | transmit and receive on every port |
| `ssh2 access-profile` | `exsshd` | none, no source filter |
| `enable ports` | `vlan` | port enabled |
| `rate-limit flood broadcast` | `vlan` | no limit |

The defaults are the lines of `show configuration detail` that `show
configuration` leaves out, measured on ExtremeXOS 33.6.1.14 and 33.7.1.6.
The port state and broadcast limit come from `show ports configuration`
and `show ports information detail`. A disabled port is printed as
`disable port <ports>`. A configuration file, an unproven module or an
unreadable version keeps such a rule as a coverage gap. STP domain
membership by the default `s0` auto-bind is not inferred: BPDU Restrict
needs explicit `configure stpd ... add vlan ... ports` lines.

The collector does not read external ACL files, so a bound SSH access
profile stays a gap unless its body is supplied. Configuring a time source establishes a configuration fact, not
synchronization.

The [fixture provenance](../tests/fixtures/exos-taxonomy/PROVENANCE.md)
links the vendor command references and describes the replay inputs.

## Vendor references

- [Switch Engine 33.7.1 HTTP](https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20User%20Guide/content/documents/Switch_Operating_Systems/Switch_Engine/User_Guide/hypertext_transfer_protocol.shtml)
- [EXOS 32.6.3 idle timer](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-9B9876A0-CADE-4CC6-ABA3-4B8C8036652E.shtml)
- [EXOS 22.5 legacy form](https://documentation.extremenetworks.com/exos_commands_22.5/GUID-F730CC8F-E0FD-4029-BF0A-B0AB6074401B.shtml)
- [EXOS 32.1 lockout](https://documentation.extremenetworks.com/exos_commands_32.1/GUID-6E386317-A61E-456A-B1B5-EB4A2A86F83E.shtml)
- [EXOS 31.7.3 policy readback](https://documentation.extremenetworks.com/exos_commands_31.7.3/GUID-D302B86E-3ABC-4A24-B1A5-C7E44568CBA4.shtml)
- [EXOS 33.6.1 SSH2 profiles](https://documentation.extremenetworks.com/ExtremeXOS%20v33.6.1%20Command%20References/Switch_Operating_Systems/ExtremeXOS/Command_References/configure_ssh2_access_profile.shtml)
- [EXOS 31.4 sample policies](https://documentation.extremenetworks.com/exos_31.4/GUID-6DCD102F-909F-410D-9D46-A708385F5965.shtml)
- [EXOS 32.1 RADIUS](https://documentation.extremenetworks.com/exos_commands_32.1/GUID-72E6B6BB-EDD2-4ED5-BF3D-6EA6BD486EAA.shtml)
- [EXOS 32.6.3 TACACS+](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-DC58A72D-FB94-484C-AD43-34AADEEDD088.shtml)
- [EXOS 32.1 access](https://documentation.extremenetworks.com/exos_commands_32.1/GUID-65FEE47E-A342-46F6-8002-9F511FFDE614.shtml)
- [EXOS 32.4 USM](https://documentation.extremenetworks.com/exos_32.4/GUID-8864CD4B-3E16-49CC-B026-80E539C39D23.shtml)
- [Switch Engine 32.1 groups](https://documentation.extremenetworks.com/switchengine_commands_32.1/GUID-44DEC8CC-1163-4A7F-9DBC-415A7CFEE06A.shtml)
- [EXOS 30.2 VACM](https://documentation.extremenetworks.com/exos_commands_30.2/GUID-C097623D-9DC0-4890-8306-1B5434BDEA8D.shtml)
- [Switch Engine 32.7.1 NTP authentication](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-F16072E4-6E16-4E71-8C3E-D6AA4DAD345E.shtml)
- [EXOS 32.2 server/peer](https://documentation.extremenetworks.com/exos_commands_32.2/GUID-4A364EEC-AE84-4DCD-8801-A689C7555DF9.shtml)
- [EXOS 32.6.3 target filter](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-6D9655A9-AE0C-4197-9508-8156E696323E.shtml)
- [EXOS 32.2 LLDP](https://documentation.extremenetworks.com/exos_32.2/GUID-D18E8022-68C3-4485-89AA-27E67A94CB41.shtml)
- [EXOS 32.1 EDP](https://documentation.extremenetworks.com/exos_commands_32.1/GUID-4354A86A-B203-40BE-A290-FC7F9F1893B5.shtml)
- [EXOS 32.6.3 STPD membership](https://documentation.extremenetworks.com/exos_commands_32.6.3/GUID-3251352C-B502-42E1-9AAB-D09329F7FD95.shtml)
- [Switch Engine 32.2 BPDU Restrict](https://documentation.extremenetworks.com/switchengine_commands_32.2/GUID-05F9577C-79E6-4067-84ED-3E39061FB749.shtml)
- [EXOS 32.4 VLAN membership](https://documentation.extremenetworks.com/exos_32.4/GUID-B9870B2A-731B-4D0C-A22C-CCD3E774F1B1.shtml)
- [EXOS 32.3 DHCP snooping](https://documentation.extremenetworks.com/exos_32.3/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Switch Engine 33.7.1 flooded traffic limits](https://documentation.extremenetworks.com/Switch%20Engine%20v33.7.1%20Command%20References/content/documents/Switch_Operating_Systems/Switch_Engine/Command_References/configure_ports_rate_limit_flood.shtml)
- [EXOS 32.4 NTP and SNTP mutual exclusion](https://documentation.extremenetworks.com/exos_32.4/GUID-05AFF0BF-DEAF-4351-A81F-0E3D69F7F5FC.shtml)
