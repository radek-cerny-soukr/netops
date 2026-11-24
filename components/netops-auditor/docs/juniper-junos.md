# Auditor for Junos

NetOps Auditor reads committed Junos OS configuration through pinned SSH or accepts an offline `display set` file. The catalog is `juniper-junos`. Use the `juniper_junos_els` inventory platform for Enhanced Layer 2 Software switches and `juniper_junos` for other Junos devices. Layer 2 checks require proof of the relevant switching syntax and mode.

## Rules

| Area | Coverage |
|---|---|
| Management | Telnet, plain HTTP, timed SSH/Telnet password retry lockout and ordered input filters on addressed management paths. ACL checks are scoped to the requested IPv4 and IPv6 prefixes. They support simple source, TCP destination port and terminal action terms. Unsupported term predicates, filter chains and unresolved paths leave a coverage gap. A service without an interface binding also answers on addressed in-band units such as `irb` or routed ports, so these units need an input filter on `lo0` for their address family; otherwise the rule is not evaluated. |
| AAA | Explicit root SSH password access and the selected RADIUS or TACACS+ backends. An explicit `password` entry enables local fallback after a rejection. Junos also falls back locally if all selected remote backends fail to respond. External password retry protections require separate evidence. |
| SNMP | Active legacy communities, including read-only communities, and local USM users with VACM access at the authentication and privacy level. Community names and key values are omitted from findings. |
| Time and logging | NTP server and peer declarations, key type, trust and binding, explicit NTS on supported configurations, remote syslog targets and requested authorization and daemon coverage. A syslog content filter requires additional evidence. |
| Switching and ports | LLDP on declared edge ports, BPDU protection, access VLAN 1, native VLAN and membership on trunks, ELS DHCP snooping and trust, storm-control profile bindings and physical disable on declared unused ports. A declared port that may be a member of an `interfaces interface-range` (`member` or `member-range`) leaves the port rules not evaluated, because settings inherited from the range are not merged. |

The SSH path uses `show configuration | display set | no-more` and consults `display inheritance` when the primary snapshot contains configuration groups. Deactivated statements are excluded. An `ACCESS-DENIED` marker limits dependent rules and `SECRET-DATA` can prove the existence of a value at a known leaf. A section that appears in a restricted snapshot supplies evidence for direct findings. Absence-based checks require an independently verified section and, where applicable, a documented device default. An offline `display set` file never verifies a section: a missing NTP source or remote syslog target in such a file leaves `time.no-ntp-source` and `logging.no-syslog-target` `not-evaluated` (`visibility-unproven`) instead of `evaluated` without a finding.

Junos NTS on a committed server statement is recognized as configuration evidence. The manufacturer documents it for Junos OS Evolved 24.2R1 and newer on supported ACX, QFX and PTX models. Virtual test coverage for Telnet/HTTP, DHCP snooping, storm control and the routing-platform variants relies on the configuration fixtures.

## Verified release

An SSH collection was verified on vJunos-switch running Junos OS 26.2R1.7, using an account in the built-in `read-only` class. Auditor reported the restricted configuration as incomplete and returned the same coverage through HTTPS MCP. The test covered restricted visibility and readback of a configured trunk. It used a virtual switch.

## Release note

Auditor adds 19 Junos configuration checks for management, AAA, SNMP, NTP, syslog and Ethernet switching. Evaluations use explicit audit intent for organization-specific requirements and report coverage gaps for restricted or unresolved configuration.

## References

- Remote access, HTTP and root SSH [Remote access](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-software-remote-access-overview.html), [SSH options](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/ssh-edit-system.html)
- Local retries and external authentication [Login and retry options](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-settings.html), [Authentication order](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-authentication-order.html)
- Filter ordering and binding [Juniper loopback filter example](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/example/firewall-filter-stateless-example-trusted-source-block-telnet-and-ssh-access.html)
- SNMP [SNMPv3](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/configure-snmpv3.html), [VACM access privileges](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/access-privileges-for-an-snmp-group.html)
- Time and logging [NTP](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/ntp-edit-system.html), [NTS](https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/network-time-security.html), [Remote syslog](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/directing-system-log-messages-to-a-remote-destination.html)
- Switching [Bridging and ELS VLANs](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/topic-map/bridging-and-vlans.html), [LLDP](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/task/layer-2-services-lldp-configuring.html), [BPDU protection](https://www.juniper.net/documentation/us/en/software/junos/stp-l2/topics/topic-map/spanning-tree-bpdu-protection.html), [DHCP snooping](https://www.juniper.net/documentation/us/en/software/junos/security-services/topics/concept/port-security-dhcp-snooping-els.html), [Storm control](https://www.juniper.net/documentation/us/en/software/junos/security-services/topics/task/rate-limiting-storm-control-disabling-cli-els.html)
