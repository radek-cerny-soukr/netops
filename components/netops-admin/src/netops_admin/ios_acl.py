"""Cisco IOS / IOS XE named ACL rules and their interface attachments (1.0.12 ios access control: IOS-M028, IOS-M029).

Measured on IOSv 15.9(3)M12 (router, GNS3 Cisco IOSv 15.9(3)M12) and IOL XE 17.18.2 (router, GNS3 Cisco IOL XE 17.18.2), verification,
private measurement record Two tables: ``ip-access-list`` (key ``ipv4:<name>`` or ``ipv6:<name>``, attribute ``rules``: the
comma separated, explicitly sequenced rules of one named extended IPv4 / IPv6 ACL) and ``interface-access-group``
(key ``<interface>:ipv4|ipv6:in|out``, attribute ``acl``).

What the measurements decide:

* The running configuration does not carry the sequence numbers of IOS 15.9 (IPv4: none, IPv6: only the ones that
  differ from the automatic 10, 20,... numbering) and shows IOS XE numbers, so the sequence of a rule comes from
  ``show ip access-lists`` / ``show ipv6 access-list`` (the same answer the check account reads). The Admin snapshot
  appends that listing as ``! netops-acl`` comments before ``end`` (like the VLAN database): the listing is the state,
  the configuration block must agree with it rule for rule, otherwise the ACL holds something outside the profile
  (remark, log, port range, object group,...) and is refused. The hit counters of the listing change with traffic
  and are removed.
* IPv4 rules are ``<seq> permit|deny <ip|tcp|udp|icmp> SRC DST [eq PORT]`` and deleted with ``no <seq>``. IPv6 rules
  are written ``sequence <seq> permit|deny <ipv6|tcp|udp|icmp> SRC DST [eq PORT]`` (``<seq> permit...`` is refused
  by the IPv6 ACL mode, "% Invalid input") and deleted with ``no sequence <seq>``.
* ``ip access-list extended NAME`` creates the ACL empty and an empty IPv4 ACL stays in the running configuration and
  is listed with its header only. An IPv6 ACL without rules does not exist: ``ipv6 access-list NAME`` without a rule
  is not part of the running configuration and removing its last rule removes it (measured on both images), so an
  IPv6 ACL is created with at least one rule and the last rule is removed by deleting the ACL.
* ``ip access-group NAME in|out`` and ``ipv6 traffic-filter NAME in|out`` replace the ACL of the direction and are also
  accepted for an ACL that does not exist (traffic is then not filtered), so Admin binds only an existing nonempty
  ACL. ``no ip access-group NAME in|out`` / ``no ipv6 traffic-filter NAME in|out`` remove it.
* An outbound ACL never filters traffic that the router itself originates (measured: a ping from the router through an
  outbound deny ACL still answered), an inbound one filters what arrives.
* A second rule with the same body is refused or ignored by the device, so the plan refuses it.
"""
from __future__ import annotations

import ipaddress
import re

from netops_admin.errors import Rejected

ACL = "ip-access-list"
BINDING = "interface-access-group"
TABLES = frozenset((ACL, BINDING))
FAMILIES = {"ipv4": "ip", "ipv6": "ipv6"}
NAMES = r"[A-Za-z][A-Za-z0-9_.-]{0,63}"
NAME = re.compile(NAMES)
V4_HEADER = re.compile(r"ip access-list (extended|standard) (\S+)")
V6_HEADER = re.compile(r"ipv6 access-list (\S+)")
GROUP = {"ipv4": re.compile(r"ip access-group (\S+) (in|out)"),
         "ipv6": re.compile(r"ipv6 traffic-filter (\S+) (in|out)")}
ACCESS_CLASS = re.compile(r"(?:ipv6 )?access-class (\S+)(?: vrf-also)?(?: (in|out))?")
LISTING_COMMANDS = {"ipv4": "show ip access-lists", "ipv6": "show ipv6 access-list"}
LISTING_MARK = "! netops-acl-listing "
MARK = "! netops-acl "
COUNTERS = re.compile(r" \([0-9]+ match(?:es)?\)")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_RULE_TEXT = 8192
SEQUENCE_LIMIT = {"ipv4": 2147483647, "ipv6": 4294967294}
PROTOCOLS = {"ipv4": ("ip", "tcp", "udp", "icmp"), "ipv6": ("ipv6", "tcp", "udp", "icmp")}
# the port keywords IOS prints for a TCP or UDP port (Cisco IOS command reference, "eq" port names)
SERVICES = {
    "tcp": {"echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20, "ftp": 21, "telnet": 23,
            "smtp": 25, "time": 37, "whois": 43, "tacacs": 49, "domain": 53, "gopher": 70, "finger": 79, "www": 80,
            "hostname": 101, "pop2": 109, "pop3": 110, "sunrpc": 111, "ident": 113, "nntp": 119, "bgp": 179,
            "irc": 194, "pim-auto-rp": 496, "exec": 512, "login": 513, "cmd": 514, "lpd": 515, "talk": 517,
            "uucp": 540, "klogin": 543, "kshell": 544, "drip": 3949},
    "udp": {"echo": 7, "discard": 9, "time": 37, "nameserver": 42, "tacacs": 49, "domain": 53, "bootps": 67,
            "bootpc": 68, "tftp": 69, "sunrpc": 111, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
            "netbios-ss": 139, "snmp": 161, "snmptrap": 162, "xdmcp": 177, "dnsix": 195, "mobile-ip": 434,
            "isakmp": 500, "biff": 512, "who": 513, "syslog": 514, "talk": 517, "rip": 520, "pim-auto-rp": 496,
            "non500-isakmp": 4500},
}


# The IOS XE additions and omissions were measured on IOL XE (iosxe_g82/ports-measured.json).
XE_SERVICES = {
    "tcp": {**{name: port for name, port in SERVICES["tcp"].items() if name != "drip"},
            "msrpc": 135, "onep-plain": 15001, "onep-tls": 15002},
    "udp": {**SERVICES["udp"], "ripv6": 521},
}


class Unsupported(Exception):
    """A rule or setting outside the profile (the object is then refused, never rewritten)."""


def refuse(message, code="ios_acl_unsupported"):
    return Rejected([message], reason_codes=[code])


def _ios():
    from netops_admin import ios
    return ios


# ---- rules ----

def _address(words, index, family, device):
    """(canonical address, next index): any, host A or the network A/len."""
    if index >= len(words):
        raise Unsupported("missing address")
    word = words[index]
    version = 4 if family == "ipv4" else 6
    if word == "any":
        return "any", index + 1
    if word == "host":
        if index + 1 >= len(words):
            raise Unsupported("missing host")
        address = ipaddress.ip_address(words[index + 1])
        if address.version != version:
            raise Unsupported("family")
        return "host " + str(address), index + 2
    if family == "ipv4" and device:
        # device form: address and wildcard mask (inverted contiguous netmask)
        if index + 1 >= len(words):
            raise Unsupported("missing wildcard")
        address = ipaddress.IPv4Address(word)
        wildcard = ipaddress.IPv4Address(words[index + 1])
        mask = ipaddress.IPv4Address(int(wildcard) ^ 0xFFFFFFFF)
        network = ipaddress.IPv4Network("%s/%s" % (address, mask), strict=True)
        return _canonical_network(network), index + 2
    network = ipaddress.ip_network(word, strict=True)
    if network.version != version:
        raise Unsupported("family")
    return _canonical_network(network), index + 1


def _canonical_network(network):
    if network.prefixlen == 0:
        return "any"
    if network.prefixlen == network.max_prefixlen:
        return "host " + str(network.network_address)
    return str(network)


def _port(word, protocol, *, xe):
    if word.isdecimal():
        value = int(word)
    else:
        value = (XE_SERVICES if xe else SERVICES)[protocol].get(word)
    if value is None or not 0 <= value <= 65535:
        raise Unsupported("port")
    return value


def parse_body(text, family, *, device, xe=False):
    """(action, protocol, source, destination, port) of a rule without its sequence number.

    device: the address form of the device (IPv4 ``A.B.C.D wildcard``); otherwise the profile form (``A.B.C.D/len``)."""
    words = text.split()
    if len(words) < 4 or words[0] not in ("permit", "deny") or words[1] not in PROTOCOLS[family]:
        raise Unsupported("rule")
    action, protocol = words[0], words[1]
    try:
        source, index = _address(words, 2, family, device)
        destination, index = _address(words, index, family, device)
    except ValueError:
        raise Unsupported("address") from None
    port = None
    if index < len(words):
        if words[index] != "eq" or index + 2 != len(words) or protocol not in ("tcp", "udp"):
            raise Unsupported("rule options")
        port = _port(words[index + 1], protocol, xe=xe)
        index += 2
    if index != len(words):
        raise Unsupported("rule options")
    return action, protocol, source, destination, port


def body_text(parts):
    action, protocol, source, destination, port = parts
    return "%s %s %s %s%s" % (action, protocol, source, destination, "" if port is None else " eq %d" % port)


def rules(value, family, *, xe=False):
    """The profile value (comma separated ``<seq> <rule>``) as {sequence: canonical rule text}, ordered by sequence."""
    parsed, bodies = {}, set()
    if not isinstance(value, str) or len(value) > MAX_RULE_TEXT or CONTROL.search(value):
        raise refuse("ACL rules must be text of at most %d characters" % MAX_RULE_TEXT)
    for line in value.split(","):
        words = " ".join(line.split())
        match = re.fullmatch(r"([0-9]{1,10}) (.+)", words)
        if match is None:
            raise refuse("ACL rules need a sequence number, permit or deny, a protocol, a source and a destination "
                         "(and for TCP and UDP an optional eq port)")
        seq = int(match.group(1))
        if not 1 <= seq <= SEQUENCE_LIMIT[family] or seq in parsed:
            raise refuse("ACL sequence numbers must be distinct and in 1..%d" % SEQUENCE_LIMIT[family])
        try:
            body = body_text(parse_body(match.group(2), family, device=False, xe=xe))
        except Unsupported:
            raise refuse("ACL rule %d is not a permit or deny of %s with addresses of the selected IP family "
                         "(any, host, a network in prefix form) and an optional eq port" % (
                             seq, "/".join(PROTOCOLS[family]))) from None
        if body in bodies:
            raise refuse("two ACL rules have the same body; the device refuses or ignores the second one")
        bodies.add(body)
        parsed[seq] = "%d %s" % (seq, body)
    return dict(sorted(parsed.items()))


def canonical_changes(table, key, changes, *, xe=False):
    if table == ACL and changes.get("rules") is not None:
        state = rules(changes["rules"], key.split(":", 1)[0], xe=xe)
        return dict(changes, rules=", ".join(state.values()))
    return changes


def custom_numbers(state):
    """True when the rule numbers of a state are not the automatic 10, 20, 30, ... by position."""
    if not state or not state.get("rules"):
        return False
    numbers = [int(rule.split(" ", 1)[0]) for rule in state["rules"].split(", ")]
    return numbers != [10 * (position + 1) for position in range(len(numbers))]


def same_order(actual, wanted):
    """The rules of two states are the same list in the same order (their numbers may differ)."""
    def bodies(state):
        return [rule.split(" ", 1)[1] for rule in (state or {}).get("rules", "").split(", ") if rule]
    return bodies(actual) == bodies(wanted)


def _device_address(value, family):
    if value == "any" or value.startswith("host "):
        return value
    network = ipaddress.ip_network(value)
    return "%s %s" % (network.network_address, network.hostmask) if family == "ipv4" else str(network)


def device_line(seq, text, family):
    """The configuration line of a canonical rule ``<seq> <body>``."""
    action, protocol, source, destination, port = parse_body(text.split(" ", 1)[1], family, device=False)
    body = "%s %s %s %s%s" % (action, protocol, _device_address(source, family),
                              _device_address(destination, family), "" if port is None else " eq %d" % port)
    return ("%d %s" % (seq, body)) if family == "ipv4" else ("sequence %d %s" % (seq, body))


# ---- the listing (show ip access-lists / show ipv6 access-list) appended to the snapshot ----

V4_LIST_HEADER = re.compile(r"(Extended|Standard) IP access list (\S+)(.*)")
V6_LIST_HEADER = re.compile(r"IPv6 access list (\S+)(.*)")
V4_LIST_RULE = re.compile(r"\s+([0-9]+) (.+)")
V6_LIST_RULE = re.compile(r"\s+(.+) sequence ([0-9]+)")


def parse_listing(text, family):
    """{name: rows} of a listing; rows = [(sequence, device rule)] or None for an ACL outside the profile
    (standard, with a header suffix, with a line that is not a rule)."""
    found, current = {}, None
    for raw in text.replace("\r", "").split("\n"):
        if not raw.strip():
            continue
        line = COUNTERS.sub("", raw.rstrip())
        if CONTROL.search(line):
            raise _ios().unreadable("ACL listing")
        if not line.startswith(" "):
            if family == "ipv4":
                match = V4_LIST_HEADER.fullmatch(line)
                name, extended, tail = (match.group(2), match.group(1) == "Extended", match.group(3)) if match \
                    else (None, False, None)
            else:
                match = V6_LIST_HEADER.fullmatch(line)
                name, extended, tail = (match.group(1), True, match.group(2)) if match else (None, False, None)
            if match is None or name in found:
                raise _ios().unreadable("ACL listing")
            found[name] = [] if extended and not tail.strip() else None
            current = name
            continue
        if current is None:
            raise _ios().unreadable("ACL listing")
        if found[current] is None:
            continue
        match = (V4_LIST_RULE if family == "ipv4" else V6_LIST_RULE).fullmatch(line)
        if match is None:
            found[current] = None
        elif family == "ipv4":
            found[current].append((int(match.group(1)), " ".join(match.group(2).split())))
        else:
            found[current].append((int(match.group(2)), " ".join(match.group(1).split())))
    return found


def annotation(v4_text, v6_text):
    """The comment lines that carry both listings in the snapshot."""
    ios = _ios()
    lines = []
    for family, text in (("ipv4", v4_text), ("ipv6", v6_text)):
        if ios.refused(text):
            raise ios.unreadable("ACL listing")
        lines.append(LISTING_MARK + family)
        for name, rows in parse_listing(text, family).items():
            if rows is None:
                lines.append("%s%s %s unsupported" % (MARK, family, name))
                continue
            lines.append("%s%s %s listed" % (MARK, family, name))
            lines += ["%s%s %s %d %s" % (MARK, family, name, seq, body) for seq, body in rows]
    return lines


def with_listing(config, v4_text, v6_text):
    """Append the ACL listings as marked comments before end (the auditor ignores comments)."""
    stripped = config.rstrip()
    if stripped.splitlines()[-1] != "end":
        raise _ios().unreadable("running configuration")
    return stripped[:-3] + "\n".join(annotation(v4_text, v6_text)) + "\nend\n"


def listing(snapshot):
    """{family: (taken, {name: rows or None})} of the annotation lines of a snapshot."""
    result = {family: [False, {}] for family in FAMILIES}
    for line in snapshot.lines:
        if line.startswith(LISTING_MARK):
            family = line[len(LISTING_MARK):]
            if family not in result or result[family][0]:
                raise _ios().unreadable("ACL listing")
            result[family][0] = True
        elif line.startswith(MARK):
            parts = line[len(MARK):].split(" ", 2)
            if len(parts) != 3 or parts[0] not in result or not result[parts[0]][0]:
                raise _ios().unreadable("ACL listing")
            family, name, rest = parts
            rows = result[family][1]
            if rest == "listed":
                if name in rows:
                    raise _ios().unreadable("ACL listing")
                rows[name] = []
            elif rest == "unsupported":
                if name in rows:
                    raise _ios().unreadable("ACL listing")
                rows[name] = None
            else:
                seq, _, body = rest.partition(" ")
                if not seq.isdecimal() or name not in rows or rows[name] is None:
                    raise _ios().unreadable("ACL listing")
                rows[name].append((int(seq), body))
    return {family: (taken, rows) for family, (taken, rows) in result.items()}


def _block_rules(children, family):
    """[(sequence or None, rule)] of the configuration lines of an ACL block (an unknown line: Unsupported)."""
    found = []
    for child in children:
        text = " ".join(child.split())
        if family == "ipv4":
            match = re.fullmatch(r"(?:([0-9]+) )?((?:permit|deny) .+)", text)
            if match is None:
                raise Unsupported("line")
            found.append((None if match.group(1) is None else int(match.group(1)), match.group(2)))
        else:
            match = re.fullmatch(r"(?:sequence ([0-9]+) )?((?:permit|deny) .+?)(?: sequence ([0-9]+))?", text)
            if match is None or (match.group(1) and match.group(3)):
                raise Unsupported("line")
            number = match.group(1) or match.group(3)
            found.append((None if number is None else int(number), match.group(2)))
    return found


def _state(children, rows, family, *, xe=False):
    """{sequence: canonical rule text} of an ACL, from the listing; the configuration block must agree with it."""
    if rows is None:
        raise Unsupported("listing")
    block = _block_rules(children, family)
    if [body for _, body in block] != [body for _, body in rows] or any(
            seq is not None and seq != listed for (seq, _), (listed, _) in zip(block, rows)):
        raise Unsupported("configuration and listing differ")
    return _rows_state(rows, family, xe=xe)


def _rows_state(rows, family, *, xe=False):
    state, bodies, last = {}, set(), 0
    for seq, body in rows:
        parts = parse_body(body, family, device=True, xe=xe)
        if not last < seq <= SEQUENCE_LIMIT[family] or body_text(parts) in bodies:
            raise Unsupported("order")
        last = seq
        bodies.add(body_text(parts))
        state[seq] = "%d %s" % (seq, body_text(parts))
    return state


def _acl_entries(snapshot, factory):
    listed = listing(snapshot)
    xe = snapshot.platform == "iosxe"
    result = {}
    for block in snapshot.blocks:
        match = V4_HEADER.fullmatch(block.header)
        if match is not None:
            family, kind, name = "ipv4", match.group(1), match.group(2)
        else:
            match = V6_HEADER.fullmatch(block.header)
            if match is None:
                continue
            family, kind, name = "ipv6", "extended", match.group(1)
        key = "%s:%s" % (family, name)
        if key in result:
            raise refuse("the device reports duplicate ACL definitions", "ios_acl_readback_unreadable")
        entry = factory(key)
        result[key] = entry
        taken, rows = listed[family]
        if kind == "standard":
            entry.unsupported.append("standard ACL")
        elif not taken and not xe:
            entry.unsupported.append("ACL listing not read")
        elif not NAME.fullmatch(name):
            entry.unsupported.append("ACL name outside the profile")
        else:
            try:
                # an empty IPv6 ACL is not listed at all
                block_rows = _block_rules(block.children, family) if xe else ()
                if xe and not taken and all(number is not None for number, _ in block_rows):
                    state = _rows_state(block_rows, family, xe=True)
                else:
                    state = _state(block.children, rows.get(name, [] if not block.children else None), family, xe=xe)
            except (Unsupported, ValueError):
                entry.unsupported.append("unsupported ACL rules or settings")
                continue
            if state:
                value = ", ".join(state.values())
                if len(value) > MAX_RULE_TEXT:
                    entry.unsupported.append("ACL rules exceed the supported request size")
                else:
                    entry.attributes["rules"] = value
    return result


def binding_key(interface, family, direction):
    return "%s:%s:%s" % (interface, family, direction)


def supported_interface(key, *, xe=False):
    ios = _ios()
    return bool(ios.ETHERNET.fullmatch(key) or ios.SUBINTERFACE.fullmatch(key) or ios.SVI.fullmatch(key)
                or (xe and re.fullmatch(ios.PORT_CHANNEL + r"[1-9][0-9]{0,2}", key)))


def _binding_state(lines, family, direction):
    names = []
    for line in lines:
        text = " ".join(line.split())
        if not text.startswith(("ip access-group ", "ipv6 traffic-filter ")):
            continue
        for other_family, pattern in GROUP.items():
            match = pattern.fullmatch(text)
            if match is None:
                continue
            if other_family == family and match.group(2) == direction:
                names.append(match.group(1))
            break
        else:
            raise refuse("unsupported interface access-group syntax")
    if len(names) > 1:
        raise refuse("duplicate interface access-groups", "ios_acl_readback_unreadable")
    if names and not NAME.fullmatch(names[0]):
        raise refuse("the attached ACL is numbered or outside the profile")
    return {"acl": names[0]} if names else {}


def entries(snapshot, table, factory):
    if table == ACL:
        return _acl_entries(snapshot, factory)
    result = {}
    for interface in snapshot.interfaces:
        if not supported_interface(interface, xe=snapshot.platform == "iosxe"):
            continue
        for family in FAMILIES:
            for direction in ("in", "out"):
                key = binding_key(interface, family, direction)
                entry = factory(key)
                result[key] = entry
                try:
                    entry.attributes.update(_binding_state(snapshot.interface_lines(interface), family, direction))
                except Rejected:
                    entry.unsupported.append("unsupported interface access-group configuration")
    return result


# ---- plan: commands ----

def _header(key):
    family, name = key.split(":", 1)
    return ("ip access-list extended " if family == "ipv4" else "ipv6 access-list ") + name


def _binding_line(key, state):
    _, family, direction = key.rsplit(":", 2)
    return "%s %s %s" % ("ip access-group" if family == "ipv4" else "ipv6 traffic-filter", state["acl"], direction)


def render(table, key, before, after):
    """The lines that turn the state before into the state after (both whole states; None = absent)."""
    if table == BINDING:
        # IOS replaces the ACL of the same family and direction; removing first would open an unfiltered interval
        line = _binding_line(key, after) if after else "no " + _binding_line(key, before)
        return ["configure terminal", "interface " + key.rsplit(":", 2)[0], line, "end"]
    header = _header(key)
    if after is None:
        return ["configure terminal", "no " + header, "end"]
    family = key.split(":")[0]
    old = rules(before["rules"], family) if before and "rules" in before else {}
    new = rules(after["rules"], family) if "rules" in after else {}
    delete = "no %d" if family == "ipv4" else "no sequence %d"
    removed = [delete % seq for seq, rule in old.items() if new.get(seq) != rule]
    added = [device_line(seq, rule, family) for seq, rule in new.items() if old.get(seq) != rule]
    return ["configure terminal", header, *removed, *added, "exit", "end"]


# ---- plan: references and protection ----

def references(snapshot, key):
    """(bindings, others): the (interface, direction) attachments of the ACL and the other users of its name
    (a list of kinds: vty, other)."""
    family, name = key.split(":", 1)
    xe = snapshot.platform == "iosxe"
    token = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])", re.I if xe else 0)
    bindings, others = set(), []
    for block in snapshot.blocks:
        if V4_HEADER.fullmatch(block.header) or V6_HEADER.fullmatch(block.header):
            continue
        interface = block.header[len("interface "):] if block.header.startswith("interface ") else None
        vty = block.header.startswith("line vty")
        for line in (block.header, *(" ".join(child.split()) for child in block.children)):
            if re.match(r"(?:neighbor \S+ )?(?:description|remark) |!", line) or not token.search(line):
                continue
            group = next(((other, match) for other, pattern in GROUP.items()
                          if (match := pattern.fullmatch(line)) is not None), None)
            if interface is not None and group is not None:
                if group[0] == family:
                    attached = group[1].group(1)
                    if xe and attached.casefold() == name.casefold() and attached != name:
                        raise refuse("ACL is referenced with ambiguous letter case", "ios_acl_in_use")
                    if attached == name:
                        bindings.add((interface, group[1].group(2)))
                continue
            if vty and ACCESS_CLASS.fullmatch(line):
                if line.startswith("ipv6 ") == (family == "ipv6"):
                    others.append("vty")
                continue
            others.append("other")
    return bindings, sorted(others)


def protect_interface(snapshot, interface, protected):
    ios = _ios()
    if not supported_interface(interface, xe=snapshot.platform == "iosxe"):
        raise refuse("an ACL attachment needs an Ethernet port, a subinterface or an SVI", "port_unsupported_interface")
    if interface not in snapshot.interfaces:
        raise refuse("the ACL interface is missing", "ios_acl_readback_unreadable")
    folded = interface.casefold()
    if any(folded in {str(value).casefold() for value in protected.get(table, ())}
           for table in ("interface", "ports", BINDING)):
        raise refuse("the ACL interface is protected", "port_protected")
    svi = ios.SVI.fullmatch(interface)
    if svi and svi.group(1) in {str(value) for value in protected.get("vlan", ())}:
        raise refuse("the ACL SVI is protected", "port_management_vlan")
    lines = snapshot.interface_lines(interface)
    if any(ios.LAG.match(line) for line in lines):
        raise refuse("the ACL interface is a port-channel member", "port_lag_member")
    if snapshot.platform == "iosxe":
        if snapshot.management_vrf(interface):
            raise refuse("the ACL interface is in a management VRF", "port_management_interface")
        if any(line == "switchport" or line.startswith("switchport ") for line in lines):
            raise refuse("a Layer 2 port is outside the ACL profile", "port_unsupported_interface")
        parent = ios.SUBINTERFACE.fullmatch(interface)
        if parent and any(parent[1].casefold() in {str(value).casefold() for value in protected.get(table, ())}
                          for table in ("interface", "ports")):
            raise refuse("the parent port of the ACL subinterface is protected", "port_protected")


def acl_rules(snapshot, family, name):
    entry = _acl_entries(snapshot, _Entry).get("%s:%s" % (family, name))
    if entry is None or entry.unsupported or not entry.attributes.get("rules"):
        return None
    return entry.attributes["rules"]


class _Entry:
    def __init__(self, name):
        self.name = name
        self.attributes = {}
        self.unsupported = []


def prechecks(snapshot, table, key, before, after, protected):
    protected = protected or {}
    if table == ACL:
        family, name = key.split(":", 1)
        reserved = {str(value).casefold() for value in protected.get(ACL, ())}
        if name.casefold() in reserved or key.casefold() in reserved:
            raise refuse("the ACL is protected", "ios_acl_in_use")
        bindings, others = references(snapshot, key)
        if snapshot.platform == "iosxe" and others:
            raise refuse("ACL is referenced outside an interface attachment", "ios_acl_in_use")
        if (bindings or others) and (before is None or after is None or not after.get("rules")):
            raise refuse("an ACL that is attached or used elsewhere cannot be created, emptied or deleted",
                         "ios_acl_in_use")
        if family == "ipv6" and after is not None and not after.get("rules"):
            raise refuse("an IPv6 ACL without rules does not exist on IOS (it is not part of the running "
                         "configuration); create it with a rule and delete it instead of emptying it")
        for interface, direction in sorted(bindings):
            if binding_key(interface, family, direction).casefold() in {
                    str(value).casefold() for value in protected.get(BINDING, ())}:
                raise refuse("an ACL attachment is protected", "port_protected")
            protect_interface(snapshot, interface, protected)
        return
    interface, family, _ = key.rsplit(":", 2)
    protect_interface(snapshot, interface, protected)
    lines = snapshot.interface_lines(interface)
    xe = snapshot.platform == "iosxe"
    check_address = after is not None or not xe
    ipv6_address = ("ipv6 address ",) if xe else ("ipv6 address ", "ipv6 enable")
    if check_address and family == "ipv6" and not any(line.startswith(ipv6_address) for line in lines):
        raise refuse("IPv6 is not configured on the ACL interface", "ios_acl_unsupported")
    if check_address and family == "ipv4" and not any(line.startswith("ip address ") for line in lines):
        raise refuse("IPv4 is not configured on the ACL interface", "ios_acl_unsupported")
    reserved = {str(value).casefold() for value in protected.get(ACL, ())}
    for state, wanted in ((before, not xe), (after, True)):
        if not state:
            continue
        name = state["acl"]
        if name.casefold() in reserved or ("%s:%s" % (family, name)).casefold() in reserved:
            raise refuse("the referenced ACL is protected", "ios_acl_in_use")
        if wanted and acl_rules(snapshot, family, name) is None:
            raise refuse("the interface needs an existing nonempty extended ACL of the same IP family",
                         "ios_acl_undefined")


# ---- management path: does the ACL let the SSH sessions through? ----

def _inside(address, ip):
    if address == "any":
        return True
    if address.startswith("host "):
        return ipaddress.ip_address(address[5:]) == ip
    return ip in ipaddress.ip_network(address)


def first_match(rules_text, protocol, source, destination, port):
    """'permit' or 'deny' of the first rule that matches the packet (an implicit deny at the end).

    port None = unknown (the return traffic of SSH): a rule that names a port may match, so a deny of that kind
    decides and a permit of that kind is not relied on."""
    for seq, rule in sorted(rules(rules_text, "ipv4").items()):
        action, rule_protocol, rule_source, rule_destination, rule_port = parse_body(rule.split(" ", 1)[1], "ipv4",
                                                                                     device=False)
        if rule_protocol not in ("ip", protocol):
            continue
        if not (_inside(rule_source, source) and _inside(rule_destination, destination)):
            continue
        if rule_port is None or rule_port == port:
            return action
        if port is None and action == "deny":
            return "deny"
    return "deny"


def permits_ssh(rules_text, peers, locals_, direction):
    """True when SSH between every client and every local management address stays permitted."""
    for peer in peers:
        for local in locals_:
            source, destination = (peer, local) if direction == "in" else (local, peer)
            if first_match(rules_text, "tcp", ipaddress.ip_address(source), ipaddress.ip_address(destination),
                           22 if direction == "in" else None) != "permit":
                return False
    return True


# ---- predicted configuration, digest ----

def without_object(lines, table, key, *, keep_listing=False):
    if table == ACL:
        family, name = key.split(":", 1)
        header = _header(key)
        inside = False
        for line in lines:
            if line.startswith(LISTING_MARK) and not keep_listing:
                continue  # present only while an ACL exists, so creating the first or deleting the last one changes it
            if line.startswith(MARK):
                parts = line[len(MARK):].split(" ", 2)
                if len(parts) == 3 and parts[0] == family and parts[1] == name:
                    continue
            if line and not line.startswith(" "):
                inside = line == header
            if not inside:
                yield line
        return
    interface, family, direction = key.rsplit(":", 2)
    inside = False
    for line in lines:
        if line and not line.startswith(" "):
            inside = line == "interface " + interface
        match = GROUP[family].fullmatch(" ".join(line.split())) if inside else None
        if match is None or match.group(2) != direction:
            yield line


def snapshot_after(snapshot, plan):
    """The snapshot text with the planned state of the object (for the audit prediction)."""
    table, key = plan["table"], plan["key"]
    after = plan["predicted"]["after"]
    lines = list(without_object(snapshot.lines, table, key, keep_listing=plan.get("ios_batch_step", False)))
    index = len(lines) - 1 - lines[::-1].index("end")
    if table == ACL and after is not None:
        family, name = key.split(":", 1)
        state = rules(after["rules"], family) if after.get("rules") else {}
        block = [_header(key), *(" " + device_line(seq, rule, family) for seq, rule in state.items()), "!"]
        notes = ["%s%s %s listed" % (MARK, family, name)]
        rows = (_block_rules(block[1:-1], family) if plan.get("ios_batch_step")
                else [(seq, rule.split(" ", 1)[1]) for seq, rule in state.items()])
        notes += ["%s%s %s %d %s" % (MARK, family, name, seq, body) for seq, body in rows]
        marks = [] if any(line.startswith(LISTING_MARK) for line in lines) else [
            LISTING_MARK + other for other in FAMILIES]
        lines[index:index] = [*block, *marks, *notes]
    elif table == BINDING and after:
        position = lines.index("interface " + key.rsplit(":", 2)[0]) + 1
        lines.insert(position, " " + _binding_line(key, after))
    return "\n".join(lines) + "\n"


def batch_stanzas(snapshot, factory):
    """Canonical rules and their listing bodies, only where both IOS reads agree."""
    stanzas, notes = {}, {}
    entries = _acl_entries(snapshot, factory)
    for key, entry in entries.items():
        if entry.unsupported:
            continue
        family, name = key.split(":", 1)
        value = entry.attributes.get("rules")
        state = rules(value, family) if value else {}
        lines = [" " + device_line(seq, rule, family) for seq, rule in state.items()]
        stanzas[_header(key)] = lines
        notes.update({f"{MARK}{family} {name} {seq}": body for seq, body in _block_rules(lines, family)})
    return stanzas, notes


# ---- the check account (privilege 1): operational readback ----

def _unreadable():
    return refuse("the ACL readback of the check account is incomplete, inconsistent or unrecognised",
                  "ios_acl_readback_unreadable")


def observe_acl(text, key, *, xe=False):
    """The ACL of show ip access-lists NAME / show ipv6 access-list NAME: None (a missing ACL lists nothing), {} (an
    IPv4 ACL without rules lists its header) or the rules."""
    family, name = key.split(":", 1)
    if _ios().refused(text) or "--More--" in text:
        raise _unreadable()
    if not text.strip():
        return None
    try:
        found = parse_listing(text, family)
        if set(found) != {name} or found[name] is None:
            raise Unsupported("listing")
        state = _rows_state(found[name], family, xe=xe)
        if xe and family == "ipv6" and not state:
            raise Unsupported("empty IPv6 ACL")
    except (Unsupported, ValueError, Rejected):
        raise _unreadable() from None
    return {"rules": ", ".join(state.values())} if state else {}


INTERFACE_LINE = {
    "ipv4": re.compile(r"\s+(Inbound|Outgoing)\s+access list is (\S+(?: \S+)*)"),
    "ipv6": re.compile(r"\s+(Inbound|Outgoing) access list (\S+)"),
}


def observe_binding(text, key, *, xe=False):
    """The attachment of show ip interface IF / show ipv6 interface IF for the direction of the key."""
    interface, family, direction = key.rsplit(":", 2)
    lines = [line for line in text.replace("\r", "").split("\n") if line.strip()]
    if xe and family == "ipv6" and not lines:
        return {}
    if _ios().refused(text) or "--More--" in text or not lines or not lines[0].startswith(interface + " is "):
        raise _unreadable()
    wanted = "Inbound" if direction == "in" else "Outgoing"
    found = []
    for line in lines[1:]:
        match = INTERFACE_LINE[family].fullmatch(line.rstrip())
        if match is not None and match.group(1) == wanted:
            found.append(match.group(2))
        elif xe and line.lstrip().startswith(wanted + " access list"):
            raise _unreadable()
    if xe and any(name != "not set" and not NAME.fullmatch(name) for name in found):
        raise _unreadable()
    if family == "ipv4":
        # the answer always names both directions ("not set" without an attachment)
        if xe and not found and any("Internet protocol processing disabled" in line for line in lines):
            return {}
        if len(found) != 1:
            raise _unreadable()
        return {} if found[0] == "not set" else {"acl": found[0]}
    if len(found) > 1:
        raise _unreadable()
    return {"acl": found[0]} if found else {}
