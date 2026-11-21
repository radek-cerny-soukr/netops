"""Scoped EOS extended IPv4/IPv6 ACL definitions and interface attachments."""
from __future__ import annotations

import ipaddress
import re

from netops_admin.errors import Rejected

ACL = "ip-access-list"
BINDING = "interface-access-group"
TABLES = frozenset((ACL, BINDING))
FAMILIES = {"ipv4": "ip", "ipv6": "ipv6"}
NAMES = r"[A-Za-z][A-Za-z0-9_.-]{0,63}"
HEADER = re.compile(r"(ip|ipv6) access-list (standard )?(%s)" % NAMES)
GROUP = re.compile(r"(ip|ipv6) access-group (%s) (in|out)" % NAMES)
FAMILY = {"ip": "ipv4", "ipv6": "ipv6"}
SVI = re.compile(r"Vlan([1-9][0-9]{0,3})")
RESERVED = {"standard", "default-control-plane-acl"}
MAX_RULE_TEXT = 8192
# EOS prints these service keywords instead of their numbers in running-config.
SERVICES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "bootps": 67,
    "bootpc": 68, "tftp": 69, "www": 80, "http": 80, "pop3": 110, "ntp": 123, "imap": 143,
    "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389, "https": 443, "syslog": 514,
    "ldp": 646, "dhcpv6-client": 546, "dhcpv6-server": 547, "msdp": 639, "netconf-ssh": 830,
    "ptp-event": 319, "ptp-general": 320, "lsp-ping": 3503, "mlag": 4432, "gnmi": 6030,
}
ADDRESS = r"(?:any|host [0-9a-fA-F:.]+|[0-9a-fA-F:.]+/[0-9]{1,3})"
RULE = re.compile(r"(\d{1,10}) (permit|deny) (ip|ipv6|tcp|udp|icmp|icmpv6) (%s) (%s)(?: eq ([a-z0-9-]{1,20}))?"
                  % (ADDRESS, ADDRESS))


def refuse(message, code="eos_acl_unsupported"):
    return Rejected([message], reason_codes=[code])


def _address(value, version):
    if value == "any":
        return value
    if value.startswith("host "):
        address = ipaddress.ip_address(value[5:])
        if address.version == version:
            return "host " + str(address)
    else:
        network = ipaddress.ip_network(value, strict=True)
        if network.version == version:
            if network.prefixlen == 0:
                return "any"
            if network.prefixlen == network.max_prefixlen:
                return "host " + str(network.network_address)
            return str(network)
    raise ValueError("family mismatch")


def rules(value, family):
    """Parse the profile value and return numerically ordered, canonical EOS rule lines."""
    parsed = {}
    version = 4 if family == "ipv4" else 6
    for line in value.split(","):
        match = RULE.fullmatch(" ".join(line.split()))
        if not match:
            raise refuse("ACL rules need sequence, permit/deny, protocol, source and destination, and optional TCP/UDP eq port")
        seq, action, protocol, source, dest, port = match.groups()
        seq = int(seq)
        if not 1 <= seq <= 4294967295 or seq in parsed:
            raise refuse("ACL sequence numbers must be distinct and in 1..4294967295")
        if protocol not in (FAMILIES[family], "tcp", "udp", "icmp" if version == 4 else "icmpv6"):
            raise refuse("ACL protocol does not match the IP family")
        if port is not None:
            port = int(port) if port.isdecimal() else SERVICES.get(port)
            if protocol not in ("tcp", "udp") or port is None or not 0 <= port <= 65535:
                raise refuse("ACL eq requires TCP or UDP and a recognised service or numeric port in 0..65535")
        try:
            source, dest = _address(source, version), _address(dest, version)
        except ValueError:
            raise refuse("ACL addresses must use the selected IP family and canonical network prefixes") from None
        suffix = "" if port is None else " eq %d" % int(port)
        parsed[seq] = f"{seq} {action} {protocol} {source} {dest}{suffix}"
    return dict(sorted(parsed.items()))


def canonical_changes(table, key, changes):
    if table == ACL and changes.get("rules") is not None:
        return dict(changes, rules=", ".join(rules(changes["rules"], key.split(":", 1)[0]).values()))
    return changes


def _acl_entries(snapshot, factory):
    result = {}
    for block in snapshot.blocks:
        match = HEADER.fullmatch(block.header)
        if not match:
            continue
        cli_family, standard, name = match.groups()
        family = FAMILY[cli_family]
        key = f"{family}:{name}"
        if key in result:
            raise refuse("EOS reports duplicate ACL definitions", "eos_acl_readback_unreadable")
        entry = factory(key)
        result[key] = entry
        if standard or name.casefold() in RESERVED:
            entry.unsupported.append("standard or reserved ACL")
            continue
        try:
            state = rules(",".join(line.strip() for line in block.children), family) if block.children else {}
        except Rejected:
            entry.unsupported.append("unsupported ACL rules or settings")
            continue
        if state:
            value = ", ".join(state.values())
            if len(value) > MAX_RULE_TEXT:
                entry.unsupported.append("ACL rules exceed the supported request size")
            else:
                entry.attributes["rules"] = value
    return result


def _binding_state(lines, family, direction):
    cli_family = FAMILIES[family]
    names = []
    for line in lines:
        if not line.startswith(cli_family + " access-group "):
            continue
        match = GROUP.fullmatch(line)
        if match is None:
            raise refuse("unsupported interface access-group syntax")
        if match[3] == direction:
            names.append(match[2])
    if len(names) > 1:
        raise refuse("duplicate interface access-groups", "eos_acl_readback_unreadable")
    return {"acl": names[0]} if names else {}


def entries(snapshot, table, factory):
    if table == ACL:
        return _acl_entries(snapshot, factory)
    result = {}
    for interface, block in snapshot.interfaces.items():
        for family in FAMILIES:
            for direction in ("in", "out"):
                key = f"{interface}:{family}:{direction}"
                entry = factory(key)
                result[key] = entry
                try:
                    entry.attributes.update(_binding_state(snapshot.interface_lines(interface), family, direction))
                except Rejected:
                    entry.unsupported.append("unsupported interface access-group configuration")
    return result


def _binding_line(key, state):
    _, family, direction = key.split(":")
    return f"{FAMILIES[family]} access-group {state['acl']} {direction}"


def _definition(key):
    family, name = key.split(":")
    return f"{FAMILIES[family]} access-list {name}"


def render(table, key, before, after):
    if table == BINDING:
        # EOS replaces the ACL for the same family/direction. Removing first would open an unfiltered interval.
        line = _binding_line(key, after) if after else "no " + _binding_line(key, before)
        return ["configure terminal", "interface " + key.split(":")[0], line, "end"]
    header = _definition(key)
    if after is None:
        return ["configure terminal", "no " + header, "end"]
    family = key.split(":")[0]
    old = rules(before["rules"], family) if before and "rules" in before else {}
    new = rules(after["rules"], family) if "rules" in after else {}
    removed = [f"no {seq}" for seq, rule in old.items() if new.get(seq) != rule]
    added = [rule for seq, rule in new.items() if old.get(seq) != rule]
    return ["configure terminal", header, *removed, *added, "exit", "end"]


def without_object(lines, table, key):
    if table == ACL:
        header = _definition(key)
        inside = False
        for line in lines:
            if line and not line.startswith(" "):
                inside = line == header
            if not inside:
                yield line
        return
    interface, family, direction = key.split(":")
    inside = False
    for line in lines:
        if line and not line.startswith(" "):
            inside = line == "interface " + interface
        match = GROUP.fullmatch(line.strip()) if inside else None
        if match is None or (match[1], match[3]) != (FAMILIES[family], direction):
            yield line


def snapshot_after(snapshot, plan):
    table, key = plan["table"], plan["key"]
    after = plan["predicted"]["after"]
    lines = list(without_object(snapshot.lines, table, key))
    if table == ACL and after is not None:
        family = key.split(":")[0]
        state = rules(after["rules"], family).values() if after.get("rules") else ()
        index = lines.index("end")
        lines[index:index] = [_definition(key), *("   " + line for line in state), "!"]
    elif table == BINDING and after:
        index = lines.index("interface " + key.split(":")[0]) + 1
        lines.insert(index, "   " + _binding_line(key, after))
    return "\n".join(lines)


def references(snapshot, key):
    """Return interface/direction references, refusing ACL use by other configuration features."""
    family, name = key.split(":")
    token = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])", re.IGNORECASE)
    matches = set()
    for block in snapshot.blocks:
        if HEADER.fullmatch(block.header):
            continue
        interface = block.header.removeprefix("interface ") if block.header.startswith("interface ") else None
        for line in (block.header, *(child.strip() for child in block.children)):
            if line == block.header and re.fullmatch(r"router ospf [0-9]+(?: vrf [\w.-]+)?", line):
                continue
            group = GROUP.fullmatch(line)
            if interface is not None and group is not None:
                if group[1] == FAMILIES[family] and group[2].casefold() == name.casefold():
                    if group[2] != name:
                        raise refuse("ACL is referenced with ambiguous letter case", "eos_acl_in_use")
                    matches.add((interface, group[3]))
            elif not line.startswith(("description ", "remark ")) and token.search(line):
                raise refuse("ACL is referenced outside a supported interface attachment", "eos_acl_in_use")
    return matches


def protect_interface(snapshot, interface, protected):
    from netops_admin import eos, eos_l3

    if eos.MANAGEMENT.fullmatch(interface):
        raise refuse("ACL changes are refused on management interfaces", "port_management_interface")
    folded = interface.casefold()
    if any(folded in {str(value).casefold() for value in protected.get(table, ())}
           for table in ("interface", "ports", "vlan-membership", BINDING)):
        raise refuse("the ACL interface is protected", "port_protected")
    svi = SVI.fullmatch(interface)
    if svi and svi[1] in {str(v) for v in protected.get("vlan", ())}:
        raise refuse("the ACL SVI is protected", "port_management_vlan")
    if not eos.ETHERNET.fullmatch(interface) and not svi:
        raise refuse("an ACL attachment needs an existing Ethernet interface or SVI", "port_unsupported_interface")
    if interface not in snapshot.interfaces:
        raise refuse("the ACL interface is missing", "eos_acl_readback_unreadable")
    siblings = snapshot.interface_lines(interface)
    if any(eos.LAG.match(line) for line in siblings):
        raise refuse("the ACL interface is a port-channel member", "port_lag_member")
    vrf = eos_l3.interface_vrf(snapshot, interface).casefold()
    if vrf in {str(value).casefold() for value in protected.get("vrf", ())}:
        raise refuse("the ACL interface belongs to a protected VRF", "port_management_interface")


def prechecks(snapshot, table, key, before, after, protected):
    protected = protected or {}
    if table == ACL:
        _, name = key.split(":")
        if name.casefold() in RESERVED | {str(value).casefold() for value in protected.get(ACL, ())}:
            raise refuse("the ACL is protected", "eos_acl_in_use")
        attached = references(snapshot, key)
        if attached and (before is None or after is None or not (after or {}).get("rules")):
            raise refuse("an attached ACL cannot be created, emptied or deleted", "eos_acl_in_use")
        for interface, direction in sorted(attached):
            if f"{interface}:{key.split(':')[0]}:{direction}".casefold() in {
                    str(value).casefold() for value in protected.get(BINDING, ())}:
                raise refuse("an ACL attachment is protected", "port_protected")
            protect_interface(snapshot, interface, protected)
        return
    interface, family, _ = key.split(":")
    protect_interface(snapshot, interface, protected)
    from netops_admin.eos import Entry

    definitions = _acl_entries(snapshot, Entry)
    for state in filter(None, (before, after)):
        name = state["acl"]
        acl_key = f"{family}:{name}"
        if name.casefold() in RESERVED or {name.casefold(), acl_key.casefold()} & {
                str(value).casefold() for value in protected.get(ACL, ())}:
            raise refuse("the referenced ACL is protected", "eos_acl_in_use")
        entry = definitions.get(acl_key)
        if entry is None or entry.unsupported or not entry.attributes.get("rules"):
            raise refuse("the interface needs an existing nonempty extended ACL of the same IP family",
                         "eos_acl_undefined")
