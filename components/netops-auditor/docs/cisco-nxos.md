# Cisco NX-OS audit

Select `cisco-nxos` for a local configuration or `cisco_nxos` in the SSH
inventory. SSH collection checks the pinned host key before authentication,
reads `show running-config` and `show snmp user`, and reads `show nxapi` when
NX-API is configured and the HTTP listener is implicit. The command responses
can contain secrets. Findings contain control states, counts, algorithms and
declared port names.

The audit checks Telnet, NX-API HTTP, VTY idle timeout and login blocking. It
checks SNMP communities and the effective algorithms of SNMPv3 users, including
users mapped automatically from the local account database. NX-OS 9.3 uses DES
when an SNMPv3 configuration specifies `priv` without the AES option. The NTP
and syslog presence checks consider configured destinations and their VRFs.
Reachability and time synchronization require operational monitoring.

Provide `audit_intent` in the policy file to check expected management prefixes,
external AAA, NTP authentication, remote syslog severity, or DHCP snooping
VLANs and trusted ports. External AAA requires an effective default login
binding to an enabled server group with a configured member. The syslog check
compares configured destination and system facility limits. ACL evaluation
supports ordered IPv4 and IPv6 address permits and denies. When an ACE uses
other match conditions, the prefix comparison reports a coverage gap.

Set each port's role in `audit_intent.ports`. An edge role checks BPDU Guard
and can request disabled discovery transmission, a broadcast storm limit or
avoidance of VLAN 1. A trunk role can request an effective native VLAN. The
native VLAN, allowed VLAN list and native tagging are distinct settings.
An unused role checks administrative shutdown on a physical Ethernet port.
NX-OS 9.3(x) prints neither `switchport mode access` nor the default access
VLAN. A port with `switchport access vlan` and no mode line is an access port,
and a VLAN other than 1 passes. A port without that line is in VLAN 1. For such
a port, only a verified complete snapshot proves the Layer 2 default and the
enabled admin state. An exact `[no] system default switchport [shutdown]` line
overrides them.

Running-config output from accounts with unverified visibility can support a
direct finding when the relevant commands are explicit. Missing commands and
implicit defaults require evidence for the affected configuration section.
A rule with mixed visibility can preserve a directly observed finding while
its overall state remains `not-evaluated`. Check the rule coverage in JSON or
MCP before interpreting a clean result. NX-OS 9.3(12) exec output has a
running-config header and no explicit end marker. The collector checks protocol
completion and framing. A permission denial of the primary command stops
collection.

## Sources

- [NX-OS 9.3(x) Security Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/security/configuration/guide/b-cisco-nexus-9000-nx-os-security-configuration-guide-93x.pdf)
- [NX-OS 9.3(x) AAA Configuration Command Reference](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/command/reference/config/b_N9K_Config_Commands_93x/b_N9K_Config_Commands_93x_chapter_01.html)
- [NX-API CLI Programmability Guide, 10.1(x)](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/101x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-release-101x/m-n9k-nx-api-cli-101x.html)
- [NX-OS 9.3(x) SNMP operational commands](https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/snmp-commands/)
- [NX-OS 9.3(x) System Management Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/system-management/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x.pdf)
- [NX-OS 9.3(x) syslog server defaults](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/troubleshooting/guide/b-cisco-nexus-9000-series-nx-os-troubleshooting-guide-93x/b-cisco-nexus-9000-series-nx-os-troubleshooting-guide-93x_chapter_010.html)
- [NX-OS 9.3(x) Layer 2 Switching Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/layer-2-switching/configuration/guide/b-cisco-nexus-9000-nx-os-layer-2-switching-configuration-guide-93x.pdf)
- [NX-OS 9.3(x) Layer 2 Interfaces](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/interfaces/configuration/guide/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x_chapter_0100.html)
