# Arista EOS configuration audits

Use the `arista-eos` catalog for a configuration file or a pinned SSH audit.
In inventory, the `arista_eos` platform alias selects the same catalog. The SSH
steps read the running configuration and, when v3 users or groups are present,
request `show snmp user` to resolve ambiguous security attributes.

The catalog checks management listeners, SSH idle timeout and access lists,
local password storage and AAA, SNMP, NTP, remote logging, and declared port
and Layer 2 policy. Configuration evidence describes settings. For example,
an NTP server entry establishes a configured time source. Synchronization
and reachability need operational readback.

Add `audit_intent` to the policy supplied for that device. This example checks a
trunk's untagged VLAN, LLDP and BPDU guard on an edge port, and the
administrative state of a port declared unused.

```json
{
  "audit_intent": {
    "ports": {
      "Ethernet12": {"role": "trunk", "native_vlan": 20},
      "Ethernet13": {"role": "edge", "discovery_allowed": false},
      "Ethernet14": {"role": "unused"}
    }
  }
}
```

To audit source restrictions on management SSH, set `management_prefixes`.
The check reads the attached inbound ACL for each declared address family and
compares ordered source permits with the allowed prefixes. ACL terms whose
effect on SSH cannot be established produce a coverage gap. Declare external
AAA, NTP authentication, syslog severity, storm control, and DHCP snooping
explicitly when those controls are required. A login list that names the
built-in `group tacacs+` or `group radius` uses every `tacacs-server host` or
`radius-server host` entry. A required edge port without a
`storm-control broadcast` limit is reported, because EOS does not print the
unlimited default.

The SSH collector verifies the output envelope independently of command
visibility. EOS does not print most defaults in `show running-config`. When a
complete SSH snapshot proves its families as `verified-profile` (see
[configuration families](channels.md)), the checks apply the documented EOS
default for an omitted command: for example, an administratively enabled
port, LLDP transmit, no SSH idle timeout, no lockout policy, and the
informational trap level. Without that proof, for example in a configuration
file, explicit commands can still establish findings. A decision that depends
on an omitted command or hidden scope is then reported as `not-evaluated`. A
port's physical link status does not establish its administrative setting or
its declared role.

## Vendor references

- [Arista EOS 4.37.0F Session Management Commands](https://www.arista.com/en/um-eos/eos-session-management-commands)
- [ACLs and Route Maps](https://www.arista.com/en/um-eos/eos-acls-and-route-maps)
- [Arista EOS User Manual](https://www.arista.com/assets/data/pdf/user-manual/EOS-User-Manual.pdf)
- [User Security](https://www.arista.com/en/um-eos/eos-user-security)
- [Arista EOS 4.37.0F SNMP](https://www.arista.com/en/um-eos/eos-snmp)
- [Arista EOS 4.37.0F System Clock and Time Protocols](https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols)
- [Arista EOS User Manual, logging trap](https://www.arista.com/en/support/advisories-notices/end-of-support/77-support/quick-start-guide/um-eos?start=130)
- [Arista EOS 4.37.0F LLDP](https://www.arista.com/en/um-eos/eos-link-layer-discovery-protocol)
- [Spanning Tree](https://www.arista.com/en/um-eos/eos-spanning-tree-protocol)
- [Data Transfer](https://www.arista.com/en/um-eos/eos-data-transfer)
- [Arista EOS 4.37.0F IPv4](https://www.arista.com/en/um-eos/eos-ipv4)
- [Arista EOS 4.37.0F Virtual LANs](https://www.arista.com/en/um-eos/eos-virtual-lans-vlans)
- [EOS User Manual](https://www.arista.com/assets/data/pdf/user-manual/EOS-User-Manual.pdf)
