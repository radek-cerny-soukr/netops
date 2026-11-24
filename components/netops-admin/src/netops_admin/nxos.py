"""Cisco NX-OS plan adapter: interface description, admin state and access VLAN from show running-config.

Measured on a Nexus 9000v (N9K-C9300v) with NX-OS 9.3(12) (in the virtual topology, verification/317,
private measurement record): the running configuration starts with the header "!Command: show running-config", the lines
"!Running configuration last done at:" and "!Time:", then "version 9.3(12) Bios:version". Top-level statements are
followed by their own lines indented by two spaces; blocks are separated by empty lines and the answer has no
closing "end". A scheduler job is closed by the top-level line "end-job". NX-OS accepts a VLAN that does not exist
without a warning (the port becomes inactive) and refuses a reserved VLAN (3968-4094) with an error without "%",
so the plan refuses both before anything is sent. mgmt0 would accept description and shutdown, so the plan never
changes it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re

from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected,
                                 SnapshotRejected)
from netops_admin.ios import vlan_numbers, vlan_text

PLATFORM = "nxos"
SAVE_TABLE = "startup-config"
SAVE_KIND = "nxos-save"
COMMAND_LINE = "!Command: show running-config"
# lines of the header that change without a configuration change; a switch without any configuration change since
# its reload prints "!No configuration change since last restart" instead of the "last done at" line (Nexus 9000v
# 9.3(12), measured), so the first change after a reload replaces that line
VOLATILE_HEADER = ("!Command:", "!Running configuration last done at:", "!No configuration change since last restart",
                   "!Time:")
VERSION_LINE = re.compile(r"^version ([0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}[a-z]?\))(?: Bios:.*)?$")
# fixed lines NX-OS prints in every running configuration after the interfaces; a cut-off answer misses them
REQUIRED_LINES = (re.compile(r"^interface mgmt0$"), re.compile(r"^line vty$"), re.compile(r"^boot nxos \S+"))
INDENT = "  "
ETHERNET = re.compile(r"^Ethernet[1-9][0-9]{0,2}/[1-9][0-9]{0,2}(?:/[1-9][0-9]{0,2})?$")
MANAGEMENT = re.compile(r"^mgmt[0-9]+$", re.IGNORECASE)
VLAN_HEADER = re.compile(r"^vlan ([0-9,-]+)$")
VLAN_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")
DEFAULT_VLAN = "1"
# VLAN 3968-4094 are reserved on NX-OS 9.3 ("invalid vlan (reserved value)", measured with 3999)
RESERVED_VLANS = range(3968, 4095)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
ROUTE_TABLE = "static-route"
L3_TABLE = "l3-interface"
RELAY_TABLE = "dhcp-relay"
ACL_TABLE = "ip-access-list"
ACL_BINDING_TABLE = "interface-access-group"
ACL_TABLES = (ACL_TABLE, ACL_BINDING_TABLE)
STATE_TABLES = (ROUTE_TABLE, L3_TABLE, RELAY_TABLE, *ACL_TABLES)
ACL_FAMILIES = {"ipv4": "ip", "ipv6": "ipv6"}
ACL_VERBS = {"ipv4": "access-group", "ipv6": "traffic-filter"}
ACL_NAME = r"[A-Za-z][A-Za-z0-9_.-]{0,63}"
ACL_HEADER = re.compile(rf"(ip|ipv6) access-list ({ACL_NAME})")
ACL_BIND = re.compile(rf"(ip|ipv6)( port)? (access-group|traffic-filter) ({ACL_NAME}) (in|out)")
ACE_ADDRESS = r"(?:any|host [0-9A-Fa-f:.]+|[0-9A-Fa-f:.]+/[0-9]{1,3})"
ACE_PORT = r"(?:eq|neq|gt|lt) [a-z0-9-]{1,20}|range [a-z0-9-]{1,20} [a-z0-9-]{1,20}"
ACE = re.compile(rf"([0-9]{{1,10}}) (permit|deny) (ip|ipv6|tcp|udp|icmp) "
                 rf"({ACE_ADDRESS})(?: ({ACE_PORT}))? ({ACE_ADDRESS})(?: ({ACE_PORT}))?")
ACE_SERVICES = {"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53,
                "bootps": 67, "bootpc": 68, "tftp": 69, "www": 80, "ntp": 123, "snmp": 161,
                "snmptrap": 162, "bgp": 179, "https": 443}
ACL_RULE_LIMIT = 8192
NTP_SERVER, NTP_SOURCE = "ntp-server", "ntp-source"
SYSLOG_SERVER, SYSLOG_SOURCE = "syslog-server", "syslog-source"
DNS_SERVER, DNS_DOMAIN = "dns-server", "dns-domain"
SERVICE_TABLES = (NTP_SERVER, NTP_SOURCE, SYSLOG_SERVER, SYSLOG_SOURCE, DNS_SERVER, DNS_DOMAIN)
VLAN_TABLE = "vlan"
MEMBERSHIP_TABLE = "vlan-membership"
L2_STATE_TABLES = (VLAN_TABLE, MEMBERSHIP_TABLE)
BOUNCE_TABLE = "port-bounce"
CHANNEL_TABLE = "port-channel"
CHANNEL_MEMBER_TABLE = "port-channel-member"
VPC_PORT_TABLE = "vpc-port"
VPC_PEER_LINK_TABLE = "vpc-peer-link"
VPC_DOMAIN_TABLE = "vpc-domain"
LINK_TABLES = (BOUNCE_TABLE, CHANNEL_TABLE, CHANNEL_MEMBER_TABLE, VPC_PORT_TABLE, VPC_PEER_LINK_TABLE,
               VPC_DOMAIN_TABLE)
VPC_TABLES = (VPC_PORT_TABLE, VPC_PEER_LINK_TABLE, VPC_DOMAIN_TABLE)
PORT_CHANNEL = re.compile(r"port-channel([1-9][0-9]{0,3})")
CHANNEL_GROUP = re.compile(r"channel-group ([1-9][0-9]{0,3})(?: mode (active|passive))?")
VPC_ID = re.compile(r"vpc ([1-9][0-9]{0,3})")
VPC_DOMAIN = re.compile(r"vpc domain ([1-9][0-9]{0,3})")
KEEPALIVE = re.compile(r"peer-keepalive destination (\S+) source (\S+)(?: vrf (\S+))?")
KEEPALIVE_FIELDS = ("destination", "source", "vrf")
MEMBERSHIP_LINES = {
    "access-vlan": "switchport access vlan",
    "mode": "switchport mode",
    "allowed-vlans": "switchport trunk allowed vlan",
    "native-vlan": "switchport trunk native vlan",
}
MEMBERSHIP_DEFAULTS = {"access-vlan": "1", "mode": "access", "allowed-vlans": "all", "native-vlan": "1"}
VRF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
SVI = re.compile(r"Vlan([1-9][0-9]{0,3})")
LOOPBACK = re.compile(r"loopback(0|[1-9][0-9]{0,3})")
RELAY = re.compile(r"ip dhcp relay address (\S+)(?: use-vrf (\S+))?")
L3_OWN = re.compile(r"^(?:ip(?:v6)? address |vrf member |(?:no )?switchport$|(?:no )?shutdown$)")
L2_SHUTDOWN_DEFAULT = "system default switchport shutdown"
IP_ATTRIBUTES = ("ipv4-address", "ipv6-address")
OWN_LINES = {
    "interface": (re.compile(r"^description "), re.compile(r"^(?:no )?shutdown$")),
    MEMBERSHIP_TABLE: tuple(re.compile(r"^" + command + r" ") for command in MEMBERSHIP_LINES.values()),
}
TRUNK = re.compile(r"^switchport (?:mode (?!access$)\S+|trunk )")
LAG = re.compile(r"^channel-group ")
ROUTED = re.compile(r"^no switchport$")
SAFEGUARD_PREFIX = "netops-"
SCHEDULER_BLOCK = re.compile(r"^scheduler (?:job|schedule) name (\S+)$")
JOB_END = "end-job"


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []


class Block:
    def __init__(self, header: str, line: int):
        self.header = header
        self.line = line
        self.children = []


def firmware_of(text: str):
    for line in text.replace("\r", "").split("\n"):
        match = VERSION_LINE.match(line.rstrip())
        if match is not None:
            return match.group(1)
    return None


def save_snapshot_digest(text: str) -> str:
    """Bind approval to running-config without the timestamps added by NX-OS."""
    lines = (line for line in text.splitlines() if not line.startswith(VOLATILE_HEADER))
    return hashlib.sha256("\n".join(lines).strip("\n").encode()).hexdigest()


def safeguard_label(change_id: str) -> str:
    """The name of the checkpoint, scheduler job, scheduler schedule and bootflash file of one operation."""
    return SAFEGUARD_PREFIX + change_id[:12]


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        lines = [line.rstrip() for line in text.replace("\r", "").split("\n")]
        filled = [line for line in lines if line.strip()]
        if not filled or filled[0] != COMMAND_LINE:
            raise SnapshotRejected(["snapshot does not start with %r; it is not an NX-OS running configuration"
                                    % COMMAND_LINE], SNAPSHOT_UNREADABLE)
        found = firmware_of(text)
        if found is None:
            raise SnapshotRejected(["snapshot does not name the NX-OS release in its version line"],
                                   SNAPSHOT_UNREADABLE)
        if not all(any(pattern.match(line) for line in filled) for pattern in REQUIRED_LINES):
            raise SnapshotRejected(["snapshot misses interface mgmt0, line vty or boot nxos; the running "
                                    "configuration is cut off"], SNAPSHOT_INCOMPLETE)
        if firmware and firmware != found:
            raise SnapshotRejected(["snapshot was taken on NX-OS %s, not on the configured %s" % (found, firmware)],
                                   SNAPSHOT_FIRMWARE_MISMATCH)
        self.firmware = found
        self.hostname = None
        self.inventory = None
        self.lines = filled
        self.blocks, self.interfaces, self.vlans, self.scheduler = [], {}, {DEFAULT_VLAN}, {}
        current = None
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            if line.startswith("!"):
                current = None
                continue
            if line.startswith(" "):
                if current is None:
                    raise SnapshotRejected(["line %d is indented outside any statement" % number],
                                           SNAPSHOT_UNREADABLE)
                current.children.append(line)
                continue
            if line == JOB_END and current is not None and current.header.startswith("scheduler job name "):
                current.children.append(line)
                current = None
                continue
            current = Block(line, number)
            self.blocks.append(current)
            words = line.split()
            if words[0] == "interface" and len(words) == 2:
                if words[1] in self.interfaces:
                    raise SnapshotRejected(["interface %s is listed twice" % words[1]], SNAPSHOT_UNREADABLE)
                self.interfaces[words[1]] = current
            elif words[0] == "hostname" and len(words) == 2:
                self.hostname = words[1]
            scheduled = SCHEDULER_BLOCK.match(line)
            if scheduled is not None:
                self.scheduler.setdefault(scheduled.group(1), []).append(current)
            vlan = VLAN_HEADER.match(line)
            if vlan is not None:
                self.vlans |= _vlan_list(vlan.group(1))
        if not self.hostname:
            raise SnapshotRejected(["snapshot does not name the device hostname"], SNAPSHOT_UNREADABLE)

    def entries(self, table: str):
        if table in LINK_TABLES:
            return link_entries(self, table)
        if table in SERVICE_TABLES:
            return service_entries(self, table)
        if table == ROUTE_TABLE:
            return static_routes(self)
        if table == L3_TABLE:
            return {name: l3_entry(self, name, block) for name, block in self.interfaces.items()
                    if SVI.fullmatch(name) or LOOPBACK.fullmatch(name) or ETHERNET.fullmatch(name)}
        if table == RELAY_TABLE:
            return relay_entries(self)
        if table in ACL_TABLES:
            return acl_entries(self, table)
        if table == VLAN_TABLE:
            entries = {vid: Entry(vid) for vid in self.vlans}
            for block in self.blocks:
                header = VLAN_HEADER.fullmatch(block.header)
                if not header or not block.children:
                    continue
                for vid in _vlan_list(header[1]):
                    entry = entries[vid]
                    for child in block.children:
                        line = child.strip()
                        if line.startswith("name ") and header[1] == vid and VLAN_NAME.fullmatch(line[5:]):
                            _once(entry, "name", line[5:], block)
                        else:
                            entry.unsupported.append("unmanaged VLAN statement at line %d" % block.line)
            return entries
        if table not in OWN_LINES:
            return None
        return {name: self._entry(table, name, block) for name, block in self.interfaces.items()}

    def _entry(self, table, name, block):
        entry = Entry(name)
        for child in block.children:
            line = child[len(INDENT):] if child.startswith(INDENT) and not child.startswith(INDENT + " ") else None
            if line is None:
                continue
            if table == "interface" and line.startswith("description "):
                _once(entry, "description", line[len("description "):], block)
            elif table == "interface" and line == "shutdown":
                _once(entry, "admin-state", "disabled", block)
            elif table == MEMBERSHIP_TABLE:
                for attribute, command in MEMBERSHIP_LINES.items():
                    if line.startswith(command + " "):
                        value = line[len(command) + 1:]
                        if attribute == "allowed-vlans":
                            value = vlan_text(trunk_vlans(value))
                        _once(entry, attribute, value, block)
                        break
        return entry

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table != L3_TABLE:
            return []
        pattern = re.compile(r"(?<![\w./-])%s(?![\w./-])" % re.escape(key), re.IGNORECASE)
        return [block.line for block in self.blocks if block.header != "interface " + key
                and any(pattern.search(line) for line in (block.header, *block.children)
                        if not line.lstrip().startswith("description "))]


    def in_use(self, key: str) -> bool:
        return key in self.interfaces

    def interface_lines(self, key: str) -> list:
        block = self.interfaces.get(key)
        return [] if block is None else [child.strip() for child in block.children]

    def safeguard_names(self) -> list:
        """Names of the scheduler jobs and schedules that start with the Admin prefix."""
        return sorted(name for name in self.scheduler if name.startswith(SAFEGUARD_PREFIX))

    def rest_digest(self, table: str, key: str, safeguard_id=None) -> str:
        """The configuration without the volatile header, the planned lines of the interface and the scheduler job
        and schedule of the own safeguard (they exist while the operation runs and are removed afterwards)."""
        own = safeguard_label(safeguard_id) if safeguard_id else None
        if table in SERVICE_TABLES:
            return hashlib.sha256("\n".join(_service_rest_lines(self, table, key, own)).encode()).hexdigest()
        if table in STATE_TABLES:
            return state_digest(self, table, key, own)
        if table == VLAN_TABLE:
            return vlan_digest(self, key, own)
        if table in LINK_TABLES:
            kept = link_configuration(self, table, key, safeguard=own)
            return hashlib.sha256("\n".join(kept).encode()).hexdigest()
        kept, inside, skipping = [], False, False
        for line in self.lines:
            if line.startswith(VOLATILE_HEADER):
                continue
            if not line.startswith(" "):
                if skipping and line == JOB_END:
                    continue
                scheduled = SCHEDULER_BLOCK.match(line)
                skipping = scheduled is not None and scheduled.group(1) == own
                if skipping:
                    continue
                inside = line == "interface %s" % key
                kept.append(line)
                continue
            if skipping:
                continue
            if inside and any(pattern.match(line.strip()) for pattern in OWN_LINES.get(table, ())):
                continue
            kept.append(line)
        return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def _once(entry, name, value, block):
    if name in entry.attributes:
        entry.unsupported.append("line %d: repeated %s" % (block.line, name))
    entry.attributes[name] = value


def link_entries(snapshot, table):
    if table == VPC_DOMAIN_TABLE:
        return {match[1]: vpc_domain_entry(match[1], block) for block in snapshot.blocks
                if (match := VPC_DOMAIN.fullmatch(block.header))}
    pattern = ETHERNET if table in (BOUNCE_TABLE, CHANNEL_MEMBER_TABLE) else PORT_CHANNEL
    return {key: link_entry(snapshot, table, key, block) for key, block in snapshot.interfaces.items()
            if pattern.fullmatch(key)}


def link_entry(snapshot, table, key, block):
    entry = Entry(key)
    lines = [line.strip() for line in block.children]
    if table == BOUNCE_TABLE:
        state = l3_entry(snapshot, key, block).attributes
        if "admin-state" in state:
            entry.attributes["admin-state"] = state["admin-state"]
        return entry
    if table == CHANNEL_TABLE:
        expected = {"switchport"} if "no system default switchport" in snapshot.lines else set()
        if "switchport mode trunk" in lines:
            entry.attributes["mode"] = "trunk"
            expected.add("switchport mode trunk")
        if set(lines) != expected or len(lines) != len(expected):
            entry.unsupported.append("port-channel has settings outside the empty Layer 2 profile")
        return entry
    for line in lines:
        if table == CHANNEL_MEMBER_TABLE and line.startswith("channel-group"):
            group = CHANNEL_GROUP.fullmatch(line)
            if group and group[2]:
                _once(entry, "group", group[1], block)
                _once(entry, "mode", group[2], block)
            else:
                entry.unsupported.append("membership is outside the LACP profile")
        elif table == VPC_PORT_TABLE and (match := VPC_ID.fullmatch(line)):
            _once(entry, "vpc-id", match[1], block)
        elif table == VPC_PEER_LINK_TABLE and line == "vpc peer-link":
            _once(entry, "peer-link", "enabled", block)
    return entry


def vpc_domain_entry(key, block):
    entry = Entry(key)
    for child in block.children:
        match = KEEPALIVE.fullmatch(" ".join(child.split()))
        try:
            if not match:
                raise ValueError
            addresses = tuple(str(ipaddress.IPv4Address(value)) for value in match.groups()[:2])
            vrf = match[3] or "management"
            if not VRF.fullmatch(vrf):
                raise ValueError
        except ValueError:
            entry.unsupported.append("domain has settings outside the IPv4 keepalive profile")
            continue
        for name, value in zip(KEEPALIVE_FIELDS, (*addresses, vrf)):
            _once(entry, name, value, block)
    return entry


def channel_members(snapshot, channel):
    group = PORT_CHANNEL.fullmatch(channel)[1]
    return {key for key in snapshot.interfaces if ETHERNET.fullmatch(key)
            and any((match := CHANNEL_GROUP.fullmatch(line)) and match[1] == group
                    for line in snapshot.interface_lines(key))}


def vpc_channels(snapshot):
    return {key: line for key in snapshot.interfaces if PORT_CHANNEL.fullmatch(key)
            for line in snapshot.interface_lines(key) if line == "vpc peer-link" or VPC_ID.fullmatch(line)}


def link_mode(snapshot, key):
    lines = snapshot.interface_lines(key)
    mode = l3_entry(snapshot, key, snapshot.interfaces[key]).attributes.get("mode") if ETHERNET.fullmatch(key) else None
    if mode == "routed" or "no switchport" in lines or (
            "no system default switchport" in snapshot.lines and "switchport" not in lines):
        raise Rejected(["interface %s is a routed port" % key], reason_codes=["port_routed"])
    modes = [line.split()[-1] for line in lines if line.startswith("switchport mode ")]
    if len(modes) > 1 or modes and modes[0] not in ("access", "trunk"):
        raise Rejected(["interface %s has an unsupported switchport mode" % key], reason_codes=["port_uplink"])
    return modes[0] if modes else "access"


def channel_key(group):
    return "port-channel" + group


def link_prechecks(snapshot, table, key, before, after, protected):
    protected = protected or {}
    if table == VPC_DOMAIN_TABLE:
        domains = link_entries(snapshot, table)
        if (int(key) > 1000 or set(domains) - {key} or vpc_channels(snapshot)
                or before is not None and set(before) != set(KEEPALIVE_FIELDS)):
            raise Rejected(["the vPC domain is outside the unused keepalive scope"], reason_codes=["nxos_vpc_dependency"])
        if after is not None:
            source, dest, vrf = (after[name] for name in ("source", "destination", "vrf"))
            addresses = {str(address.ip) for _, network_vrf, address in interface_addresses(snapshot)
                         if (network_vrf or "default") == vrf}
            remote = ipaddress.IPv4Address(dest)
            if (source not in addresses or dest in addresses or remote.is_multicast or remote.is_unspecified
                    or remote.is_loopback or dest == "255.255.255.255"):
                raise Rejected(["keepalive needs a local source and a remote unicast destination in the named VRF"],
                               reason_codes=["nxos_vpc_dependency"])
        return
    if table == BOUNCE_TABLE:
        if link_mode(snapshot, key) != "access":
            raise Rejected(["bounce refuses trunk ports"], reason_codes=["port_uplink"])
        if any(line.startswith("channel-group") for line in snapshot.interface_lines(key)):
            raise Rejected(["bounce refuses a port-channel member"], reason_codes=["port_lag_member"])
        if before or after != {"admin-state": "disabled"}:
            raise Rejected(["bounce needs an enabled port and admin-state=disabled"], reason_codes=["port_disabled"])
        return
    if table == CHANNEL_MEMBER_TABLE:
        if (after and set(after) != {"group", "mode"}
                or before and after and before["group"] != after["group"]):
            raise Rejected(["set or unset group and mode together; detach before changing groups"],
                           reason_codes=["nxos_channel_dependency"])
        channel = channel_key((before or after)["group"])
    else:
        channel = key
    if int(PORT_CHANNEL.fullmatch(channel)[1]) > 4096:
        raise Rejected(["port-channel number must be in 1..4096"], reason_codes=["nxos_channel_dependency"])
    members = channel_members(snapshot, channel)
    interfaces = {channel, *members}
    if table == CHANNEL_MEMBER_TABLE:
        interfaces.add(key)
    guarded = {name.casefold() for kind in ("interface", "l3-interface", MEMBERSHIP_TABLE, *LINK_TABLES)
               if kind != VPC_DOMAIN_TABLE for name in protected.get(kind, ())}
    if any({name.casefold(), short_name(name).casefold()} & guarded for name in interfaces):
        raise Rejected(["an interface of the affected port-channel is protected"], reason_codes=["port_protected"])
    if channel not in snapshot.interfaces:
        if table == CHANNEL_TABLE:
            return
        raise Rejected(["LACP requires a pre-existing port-channel"], reason_codes=["nxos_channel_dependency"])
    roles = vpc_channels(snapshot)
    if table == CHANNEL_TABLE:
        reference = re.compile(r"(?<![\w-])(?:port-channel ?|Po)%s(?![\w/-])" % PORT_CHANNEL.fullmatch(channel)[1],
                               re.IGNORECASE)
        if members or channel in roles or any(
                reference.search(line) for block in snapshot.blocks if block.header != "interface " + channel
                for line in (block.header, *block.children) if not line.lstrip().startswith("description ")):
            raise Rejected(["the port-channel has members or a vPC role"], reason_codes=["nxos_channel_dependency"])
        return
    mode = link_mode(snapshot, channel)
    if table == CHANNEL_MEMBER_TABLE:
        if channel in roles or link_mode(snapshot, key) != mode:
            raise Rejected(["membership requires a compatible channel without a vPC role"],
                           reason_codes=["nxos_channel_dependency"])
        fields = ("access-vlan", "native-vlan", "allowed-vlans")
        states = [MEMBERSHIP_DEFAULTS | snapshot._entry(MEMBERSHIP_TABLE, name, snapshot.interfaces[name]).attributes
                  for name in (key, channel)]
        if any(states[0][field] != states[1][field] for field in fields):
            raise Rejected(["the interface and port-channel VLAN settings differ"],
                           reason_codes=["nxos_channel_dependency"])
        return
    if table == VPC_PORT_TABLE:
        wanted = after.get("vpc-id")
        if (roles.get(channel) == "vpc peer-link"
                or wanted and any(name != channel and role == "vpc " + wanted for name, role in roles.items())):
            raise Rejected(["this port-channel is the peer-link or the vPC ID is already assigned"],
                           reason_codes=["nxos_vpc_dependency"])
    elif (mode != "trunk" or "spanning-tree port type network" not in snapshot.interface_lines(channel)
          or any(name != channel or role != "vpc peer-link" for name, role in roles.items())):
        raise Rejected(["the peer-link needs an idle trunk port-channel that already has spanning-tree port type "
                        "network (NX-OS sets that port type with vpc peer-link and removes it with no vpc peer-link) "
                        "and a domain without other vPC roles"], reason_codes=["nxos_vpc_dependency"])


def _link_target(table, key):
    return ("vpc domain " if table == VPC_DOMAIN_TABLE else "interface ") + key


def _link_lines(snapshot, table, state):
    if table == CHANNEL_TABLE:
        lines = ["switchport"] if "no system default switchport" in snapshot.lines else []
        return lines + (["switchport mode trunk"] if state.get("mode") == "trunk" else [])
    if table == VPC_DOMAIN_TABLE:
        return ["peer-keepalive destination {destination} source {source} vrf {vrf}".format_map(state)]
    if table == BOUNCE_TABLE:
        return ["shutdown" if state else "no shutdown"]
    if not state:
        return []
    if table == CHANNEL_MEMBER_TABLE:
        return ["channel-group {group} mode {mode}".format_map(state)]
    if table == VPC_PORT_TABLE:
        return ["vpc " + state["vpc-id"]]
    return ["vpc peer-link"]


def render_link(snapshot, table, key, before, after):
    target = _link_target(table, key)
    if after is None:
        return ["configure terminal", "no " + target, "end"]
    lines = _link_lines(snapshot, table, after)
    if not lines and before:
        # NX-OS 9.3(12) drops any spanning-tree port type line together with "vpc peer-link" (measured); the peer-link
        # profile only uses channels that already have the network port type, so the removal writes it back and the
        # rest of the channel stays as it was before the assignment
        lines = {CHANNEL_MEMBER_TABLE: ["no channel-group"], VPC_PORT_TABLE: ["no vpc " + before.get("vpc-id", "")],
                 VPC_PEER_LINK_TABLE: ["no vpc peer-link", "spanning-tree port type network"]}[table]
    elif table == VPC_PORT_TABLE and before and after:
        lines.insert(0, "no vpc " + before["vpc-id"])
    return ["configure terminal", target, *lines, "end"]


def _link_owned(table, line):
    if table == BOUNCE_TABLE:
        return line in ("shutdown", "no shutdown")
    if table == CHANNEL_MEMBER_TABLE:
        return line.startswith("channel-group ")
    if table == VPC_PORT_TABLE:
        return VPC_ID.fullmatch(line) is not None
    return line == "vpc peer-link"


def link_configuration(snapshot, table, key, after=None, *, predict=False, safeguard=None):
    target = _link_target(table, key)
    owns_block = table in (CHANNEL_TABLE, VPC_DOMAIN_TABLE)
    result, found = [], False
    for block in snapshot.blocks:
        scheduled = SCHEDULER_BLOCK.fullmatch(block.header)
        if scheduled and scheduled[1] == safeguard:
            continue
        if block.header != target:
            result.extend((block.header, *block.children))
            continue
        found = True
        if owns_block:
            if predict and after is not None:
                result.extend((target, *(INDENT + line for line in _link_lines(snapshot, table, after))))
            continue
        result.extend((target, *(line for line in block.children if not _link_owned(table, line.strip()))))
        if predict:
            lines = _link_lines(snapshot, table, after)
            result.extend(INDENT + line for line in lines)
    if not found and owns_block and predict and after is not None:
        index = len(result)
        if table == CHANNEL_TABLE:
            # nxos config Nexus 9300v, NX-OS 9.3(12)/switch-pair captures list port-channels by number before Ethernet.
            number = int(PORT_CHANNEL.fullmatch(key)[1])
            for offset, line in enumerate(result):
                if not line.startswith("interface "):
                    continue
                interface = line.removeprefix("interface ")
                other = PORT_CHANNEL.fullmatch(interface)
                if ETHERNET.fullmatch(interface) or (other and int(other[1]) > number):
                    index = offset
                    break
        result[index:index] = [target, *(INDENT + line for line in _link_lines(snapshot, table, after))]
    return result


def link_check_view(table, state):
    field = {CHANNEL_MEMBER_TABLE: "mode", VPC_DOMAIN_TABLE: "source"}.get(table)
    return {key: value for key, value in state.items() if key != field}


def _vlan_list(text: str) -> set:
    found = set()
    for part in text.split(","):
        if "-" in part:
            low, high = part.split("-", 1)
            if low.isdigit() and high.isdigit() and int(low) <= int(high):
                found |= {str(number) for number in range(int(low), int(high) + 1)}
        elif part.isdigit():
            found.add(str(int(part)))
    return found


def trunk_vlans(value: str) -> set:
    if value.startswith("except "):
        return vlan_numbers("all") - vlan_numbers(value[7:])
    return vlan_numbers(value)


def vlan_name(key: str) -> str:
    return "VLAN%04d" % int(key)


def vlan_config_references(snapshot, key: str) -> bool:
    """A VLAN can be referenced even when it has no active ports or has yet to be created."""
    single = re.compile(r"^(?:switchport (?:access|trunk native|voice) vlan |"
                        r"encapsulation dot1q |mac address-table static \S+ vlan )" + key + r"(?:\s|$)")
    lists = re.compile(r"^(?:switchport trunk allowed vlan|vlan configuration|spanning-tree vlan|"
                       r"private-vlan association|source vlan) (\S+)(?:\s|$)")
    for block in snapshot.blocks:
        if block.header.casefold() == "interface vlan" + key:
            return True
        for line in (block.header, *(child.strip() for child in block.children)):
            if single.match(line):
                return True
            allowed = line.removeprefix("switchport trunk allowed vlan ")
            if allowed != line and allowed not in ("all", "1-4094"):
                if int(key) in trunk_vlans(allowed):
                    return True
                continue
            match = lists.match(line)
            if match and not line.startswith("switchport trunk allowed vlan "):
                if key in _vlan_list(match[1]):
                    return True
            if line.startswith("switchport vlan mapping ") and key in line.split()[3:]:
                return True
    return False


def vlan_digest(snapshot, key, safeguard):
    """NX-OS rewrites its aggregate bare VLAN header when a VLAN is added or removed."""
    kept = [vlan_text({int(vid) for vid in snapshot.vlans if vid != key})]
    for block in snapshot.blocks:
        scheduled = SCHEDULER_BLOCK.fullmatch(block.header)
        if scheduled and scheduled[1] == safeguard:
            continue
        vlan = VLAN_HEADER.fullmatch(block.header)
        if vlan and (not block.children or vlan[1] == key):
            continue
        kept.extend((block.header, *block.children))
    return hashlib.sha256("\n".join(kept).encode()).hexdigest()


def vlan_snapshot_after(text, plan):
    snapshot = load(text, plan["firmware"])
    key, after = plan["key"], plan["predicted"]["after"]
    members = snapshot.vlans - {key} if after is None else snapshot.vlans | {key}
    # NX-OS prints the database as one bare list, then a separate stanza for each named VLAN.
    result = [line for line in snapshot.lines if line.startswith(VOLATILE_HEADER)]
    named = [block for block in snapshot.blocks
             if (match := VLAN_HEADER.fullmatch(block.header)) and block.children and match[1] != key]
    if after and "name" in after:
        stanza = Block("vlan " + key, 0)
        stanza.children = [INDENT + "name " + after["name"]]
        named.append(stanza)
    vlans = ["vlan " + vlan_text({int(vid) for vid in members})]
    for block in sorted(named, key=lambda item: int(item.header.split()[1])):
        vlans.extend((block.header, *block.children))
    for block in snapshot.blocks:
        if VLAN_HEADER.fullmatch(block.header):
            if vlans:
                result.extend(vlans)
                vlans = []
            continue
        result.extend((block.header, *block.children))
    return "\n".join(result + vlans) + "\n"


def load(text: str, firmware: str | None) -> Snapshot:
    try:
        return Snapshot(text, firmware)
    except SnapshotRejected:
        raise
    except Exception as exc:
        raise SnapshotRejected(["snapshot does not parse: %s" % type(exc).__name__], SNAPSHOT_UNREADABLE) from None


def absent(snapshot, table: str, key: str) -> list:
    if table in STATE_TABLES + SERVICE_TABLES:
        return ["%s %s is not in the running configuration" % (table, key)]
    return ["interface %s is not in the running configuration of the switch; the change is refused" % key]


def _text(value: str) -> str:
    if CONTROL.search(value) or value != value.strip():
        raise Rejected(["the value %r cannot be written safely" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    raise Rejected(["NX-OS %s objects are only updated" % profile.table])


def render_delete(profile, key: str) -> list:
    raise Rejected(["NX-OS %s objects are only updated" % profile.table])


def _line(name: str, value) -> str:
    if name == "description":
        return "no description" if value is None else "description %s" % _text(value)
    if name == "admin-state":
        if value not in (None, "enabled", "disabled"):
            raise Rejected(["admin-state must be enabled or disabled"])
        return "shutdown" if value == "disabled" else "no shutdown"
    if name == "access-vlan":
        if value is None or value == DEFAULT_VLAN:
            return "no switchport access vlan"
        if not str(value).isdigit():
            raise Rejected(["access-vlan must be a VLAN number"])
        return "switchport access vlan %s" % value
    if name == "mode":
        return "switchport mode " + (value or "access")
    if name in ("allowed-vlans", "native-vlan"):
        command = MEMBERSHIP_LINES[name]
        return "no " + command if value is None else command + " " + value
    raise Rejected(["attribute %s is not known on NX-OS" % name])


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    """The interactive lines of the change: configure terminal, the interface, its lines and end.

    The lines run after Admin installed the safeguard (checkpoint and a one-time scheduler job that rolls the whole
    running configuration back to it); configure session cannot be used, because NX-OS 9.3(12) offers neither
    description, shutdown nor switchport under an interface of a session."""
    lines = [_line(name, value) for name, value in sorted(assign.items())]
    lines += [_line(name, None) for name in sorted(remove)]
    if not lines:
        return []
    return ["configure terminal", "interface %s" % key] + lines + ["end"]


def interface_kind(key: str) -> str:
    if MANAGEMENT.fullmatch(key):
        return "management"
    if ETHERNET.fullmatch(key):
        return "ethernet"
    return "other"


def interface_target(table, key):
    if table in ("interface", L3_TABLE, MEMBERSHIP_TABLE, RELAY_TABLE, ACL_BINDING_TABLE,
                 BOUNCE_TABLE, CHANNEL_TABLE, CHANNEL_MEMBER_TABLE, VPC_PORT_TABLE, VPC_PEER_LINK_TABLE):
        return key.split(":", 1)[0]
    return None


def interface_protected(protected, interface):
    names = {item.casefold() for item in (protected or {}).get("interface", ())}
    return bool({interface.casefold(), short_name(interface).casefold()} & names)


def impact_table(table):
    return (table in ACL_TABLES + tuple(SERVICE_SERVER_PREFIX)
            or interface_target(table, "") is not None)


def disruptive(table: str, before, after) -> bool:
    """A change that can cut or restore traffic on the port, including a Layer 2 membership change.

    Enabling a disabled uplink or port-channel member can bring back a loop, so admin up gets the same port checks
    as admin down; the description alone does not."""
    before, after = before or {}, after or {}
    if table in ("interface", BOUNCE_TABLE):
        return after.get("admin-state", "enabled") != before.get("admin-state", "enabled")
    return table == MEMBERSHIP_TABLE and before != after


def membership_vlans(before, after) -> set:
    """VLAN IDs explicitly changed or made active by a new switchport mode."""
    wanted = {after[name] for name in ("access-vlan", "native-vlan")
              if name in after and before.get(name) != after[name]}
    if after.get("mode", "access") == "access":
        wanted.add(after.get("access-vlan", DEFAULT_VLAN))
    else:
        wanted.add(after.get("native-vlan", DEFAULT_VLAN))
        if "allowed-vlans" in after:
            old = trunk_vlans(before.get("allowed-vlans", MEMBERSHIP_DEFAULTS["allowed-vlans"])) \
                if before.get("mode") == "trunk" else set()
            wanted.update(map(str, vlan_numbers(after["allowed-vlans"]) - old))
    return wanted


def reserved_vlan(value) -> bool:
    return str(value).isdigit() and int(value) in RESERVED_VLANS


def prechecks(snapshot, profile, op: str, key: str, after) -> list:
    if profile.table in LINK_TABLES:
        return []  # The scoped planner validates both sides of these changes.
    if profile.table in ACL_TABLES:
        return []  # ACL-specific checks require both sides and the protected inventory (engine.build_plan).
    if profile.table in SERVICE_TABLES:
        return []
    if profile.table in STATE_TABLES:
        return state_prechecks(snapshot, profile.table, op, key, after)
    if profile.table == VLAN_TABLE:
        if int(key) >= 4093 or key == "3999":
            raise Rejected(["VLAN %s is reserved on NX-OS" % key], reason_codes=["vlan_reserved"])
        if after and after.get("name") == vlan_name(key):
            raise Rejected(["use an unset name for the default name of VLAN %s" % key],
                           reason_codes=["vlan_name_reserved"])
        if vlan_config_references(snapshot, key):
            raise Rejected(["VLAN %s is referenced in the configuration" % key], reason_codes=["vlan_in_use"])
        return []
    kind = interface_kind(key)
    if kind == "management":
        raise Rejected(["interface %s is the management interface; Admin never changes it" % key],
                       reason_codes=["port_management_interface"])
    if kind != "ethernet":
        raise Rejected(["interface %s is not an Ethernet port; only EthernetX/Y ports are changed" % key],
                       reason_codes=["port_unsupported_interface"])
    lines = snapshot.interface_lines(key)
    before = snapshot._entry(profile.table, key, snapshot.interfaces[key]).attributes if key in snapshot.interfaces \
        else {}
    if profile.table == MEMBERSHIP_TABLE:
        before = {name: value for name, value in before.items() if value != MEMBERSHIP_DEFAULTS.get(name)}
    if profile.table == MEMBERSHIP_TABLE or disruptive(profile.table, before, after):
        if any(LAG.match(line) for line in lines):
            raise Rejected(["port %s is a member of a port-channel; the change is refused" % key],
                           reason_codes=["port_lag_member"])
        if profile.table == MEMBERSHIP_TABLE:
            mode = before.get("mode", "access")
            access_only = all(before.get(name) == after.get(name) for name in ("mode", "native-vlan", "allowed-vlans"))
            uplink = mode not in ("access", "trunk") or (mode == "trunk" and access_only)
        else:
            uplink = any(TRUNK.match(line) for line in lines)
        if uplink:
            raise Rejected(["port %s is a trunk; a trunk is treated as an uplink and is not changed" % key],
                           reason_codes=["port_uplink"])
        if any(ROUTED.match(line) for line in lines) or (
                "no system default switchport" in snapshot.lines and "switchport" not in lines):
            raise Rejected(["port %s is a routed port, not an access port" % key], reason_codes=["port_routed"])
    if profile.table == MEMBERSHIP_TABLE:
        for wanted in sorted(membership_vlans(before, after), key=int):
            if wanted in snapshot.vlans:
                continue
            if reserved_vlan(wanted) and not any(line.startswith("system vlan ") and line.endswith(" reserve")
                                                 for line in snapshot.lines):
                raise Rejected(["VLAN %s is reserved on NX-OS (3968-4094 by default)" % wanted],
                               reason_codes=["vlan_reserved"])
            raise Rejected(["VLAN %s does not exist in the running configuration" % wanted],
                           reason_codes=["vlan_missing"])
    return []


def snapshot_after(text: str, plan) -> str:
    """The running configuration with the planned state of the interface lines (for the audit prediction)."""
    key, table, state = plan["key"], plan["table"], plan["predicted"]["after"] or {}
    if table in LINK_TABLES:
        snapshot = load(text, plan["firmware"])
        lines = [line for line in snapshot.lines if line.startswith(VOLATILE_HEADER)]
        lines.extend(link_configuration(snapshot, table, key, plan["predicted"]["after"], predict=True))
        return "\n".join(lines) + "\n"
    if table in SERVICE_TABLES:
        return service_snapshot_after(text, plan)
    if table in STATE_TABLES:
        return state_snapshot_after(text, plan)
    if table == VLAN_TABLE:
        return vlan_snapshot_after(text, plan)
    own = OWN_LINES.get(table, ())
    result, inside = [], False
    for line in text.replace("\r", "").split("\n"):
        if line and not line.startswith(" "):
            if inside:
                result.extend(INDENT + _line(name, value) for name, value in sorted(state.items()))
            inside = line.rstrip() == "interface %s" % key
            result.append(line)
            continue
        if inside and line.strip() and any(pattern.match(line.strip()) for pattern in own):
            continue
        result.append(line)
    return "\n".join(result)


# ---- layer 3 configuration measured on Nexus 9000v 9.3(12) ----

def canonical_address(name: str, value) -> str:
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        if name == "next-hop":
            address = ipaddress.ip_address(value)
            if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
                raise ValueError
            return str(address)
        family = 4 if name == "ipv4-address" else 6
        address = ipaddress.ip_interface(value)
        if ("/" not in value or address.version != family or address.ip.is_unspecified
                or address.ip.is_multicast or address.ip.is_link_local or not address.network.prefixlen):
            raise ValueError
        network = address.network
        if family == 4 and network.prefixlen <= 30 and address.ip in (network.network_address,
                                                                        network.broadcast_address):
            # measured: "All 0s host part is invalid" / "All 1s host part is invalid" (nxos routing admin r3)
            raise Rejected(["%s %s is not a host address of its subnet (all 0s or all 1s host part)"
                            % (name, value)])
        return str(address)
    except ValueError:
        raise Rejected(["%s must be a usable unicast %s" %
                        (name, "address" if name == "next-hop" else "address/prefix-length")]) from None


def route_name(vrf, network) -> str:
    return ("vrf:" + vrf + ":" if vrf else "") + str(network)


def route_key(key: str) -> tuple:
    vrf, network = None, key
    if key.startswith("vrf:"):
        _, vrf, network = key.split(":", 2)
        if not VRF.fullmatch(vrf) or vrf.casefold() == "default":
            raise Rejected(["use an unqualified key for the default VRF"])
    try:
        network = ipaddress.ip_network(network)
    except ValueError:
        raise Rejected(["the route destination must be a network prefix without host bits"]) from None
    if route_name(vrf, network) != key:
        raise Rejected(["write the route key in canonical form: %s" % route_name(vrf, network)])
    return vrf, network


def route_line(line: str, vrf=None):
    words = line.split()
    if len(words) < 3 or words[:2] not in (["ip", "route"], ["ipv6", "route"]):
        return None
    try:
        if words[0] == "ip" and "/" not in words[2] and len(words) >= 5:
            network = ipaddress.IPv4Network(words[2] + "/" + words[3], strict=False)
            return route_name(vrf, network), words[4:]
        network = ipaddress.ip_network(words[2], strict=False)
    except ValueError:
        return None
    return route_name(vrf, network), words[3:]


def static_routes(snapshot) -> dict:
    entries = {}
    for block in snapshot.blocks:
        if block.header.startswith("vrf context "):
            vrf = block.header.split()[-1]
            statements = block.children
        else:
            vrf, statements = None, (block.header,)
        for line in statements:
            parsed = route_line(line, vrf)
            if parsed is None:
                continue
            key, options = parsed
            entry = entries.setdefault(key, Entry(key))
            try:
                hop = canonical_address("next-hop", options[0])
                valid = len(options) == 1 or (len(options) == 2 and options[1].isdigit()
                                             and 1 <= int(options[1]) <= 255)
                if not valid:
                    raise ValueError
            except (IndexError, ValueError, Rejected):
                entry.unsupported.append("line %d: route is outside the single-next-hop profile" % block.line)
                continue
            _once(entry, "next-hop", hop, block)
            entry.attributes["distance"] = str(int(options[1])) if len(options) == 2 else "1"
    return entries


def l3_entry(snapshot, key: str, block) -> Entry:
    entry = Entry(key)
    children = snapshot.interface_lines(key)
    if ETHERNET.fullmatch(key) and ("no switchport" in children or (
            "switchport" not in children and "no system default switchport" in snapshot.lines)):
        entry.attributes["mode"] = "routed"
    for line in children:
        words = line.split()
        if words[:2] == ["vrf", "member"] and len(words) == 3:
            _once(entry, "vrf", words[2], block)
        if words[:2] not in (["ip", "address"], ["ipv6", "address"]):
            continue
        name = "ipv4-address" if words[0] == "ip" else "ipv6-address"
        try:
            if len(words) != 3:
                raise ValueError
            _once(entry, name, canonical_address(name, words[2]), block)
        except (ValueError, Rejected):
            entry.unsupported.append("line %d: %s is outside the single-address profile" % (block.line, name))
    if ("shutdown" in children or ("no shutdown" not in children
                                   and interface_shutdown_default(snapshot, key, entry.attributes))):
        entry.attributes["admin-state"] = "disabled"
    return entry


def interface_shutdown_default(snapshot, key, state):
    return bool(SVI.fullmatch(key) or state.get("mode") == "routed"
                or (ETHERNET.fullmatch(key) and L2_SHUTDOWN_DEFAULT in snapshot.lines))


def relay_entries(snapshot) -> dict:
    entries = {}
    for name, block in snapshot.interfaces.items():
        if SVI.fullmatch(name) is None:
            continue
        for line in block.children:
            match = RELAY.fullmatch(line.strip())
            if not match:
                continue
            host, vrf = match.groups()
            key = name + ":" + host
            if key in entries:
                entries[key].unsupported.append("line %d: repeated relay server" % block.line)
                continue
            entry = entries[key] = Entry(key)
            if vrf is not None:
                entry.attributes["vrf"] = vrf
    return entries


def interface_addresses(snapshot, skip=None) -> list:
    """(interface, VRF, address) of every IPv4 and IPv6 address of the running configuration, mgmt0 included;
    the VRF is None for the default VRF."""
    found = []
    for name in snapshot.interfaces:
        if name == skip:
            continue
        vrf = _interface_vrf(snapshot, name)
        for line in snapshot.interface_lines(name):
            words = line.split()
            if len(words) >= 3 and words[:2] in (["ip", "address"], ["ipv6", "address"]):
                try:
                    found.append((name, None if vrf == "default" else vrf, ipaddress.ip_interface(words[2])))
                except ValueError:
                    continue
    return found


def interface_networks(snapshot, skip=None) -> list:
    """(interface, VRF, network) of every interface address (as ios.interface_networks)."""
    return [(name, vrf, address.network) for name, vrf, address in interface_addresses(snapshot, skip)]


def _check_vrf(snapshot, vrf):
    if not vrf or vrf == "default":
        return
    if vrf.casefold() == "management":
        raise Rejected(["the management VRF is protected"], reason_codes=["port_management_interface"])
    if "vrf context " + vrf not in snapshot.lines:
        raise Rejected(["VRF %s does not exist" % vrf])


def state_prechecks(snapshot, table, op, key, after) -> list:
    if table == ROUTE_TABLE:
        vrf, network = route_key(key)
        _check_vrf(snapshot, vrf)
        if not network.prefixlen:
            raise Rejected(["the default route is protected"], reason_codes=["port_management_interface"])
        if network.prefixlen == 1:
            # Either half can redirect management traffic even before the other half exists.
            raise Rejected(["the split default route is protected"], reason_codes=["port_management_interface"])
        if after is not None and ipaddress.ip_address(after["next-hop"]).version != network.version:
            raise Rejected(["the next hop and route must use the same IP version"])
        if after is not None:
            hop = ipaddress.ip_address(after["next-hop"])
            for name, other_vrf, address in interface_addresses(snapshot):
                if other_vrf == (vrf or None) and address.ip == hop:
                    # measured: "ipv4 Nexthop: cannot be local address in same VRF" (nxos routing admin r3)
                    raise Rejected(["the next hop %s is the own address of interface %s in the same VRF"
                                    % (hop, name)])
        if (vrf or "default") == (_interface_vrf(snapshot, "mgmt0") or "default"):
            for line in snapshot.interface_lines("mgmt0"):
                words = line.split()
                if len(words) == 3 and words[:2] in (["ip", "address"], ["ipv6", "address"]):
                    management = ipaddress.ip_interface(words[2]).network
                    if management.version == network.version and management.overlaps(network):
                        raise Rejected(["the route overlaps the management interface subnet"],
                                       reason_codes=["port_management_interface"])
        if after is not None:
            for name, other_vrf, connected in interface_networks(snapshot):
                if (SVI.fullmatch(name) or LOOPBACK.fullmatch(name)) and other_vrf == vrf \
                        and connected.version == network.version and network.subnet_of(connected):
                    raise Rejected(["the route %s overlaps %s of interface %s in the same VRF"
                                    % (network, connected, name)])
        return []

    vid = SVI.fullmatch(key.split(":", 1)[0])
    if vid:
        if int(vid[1]) >= 3968:
            raise Rejected(["the VLAN is out of range or reserved"], reason_codes=["vlan_reserved"])
        if vid[1] not in snapshot.vlans:
            raise Rejected(["the VLAN does not exist"], reason_codes=["vlan_missing"])
    if table == RELAY_TABLE:
        interface, server = key.split(":")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", server):
            raise Rejected(["the relay server must be an IPv4 address"])
        canonical_address("next-hop", server)
        if interface not in snapshot.interfaces:
            raise Rejected(["the SVI does not exist"])
        _check_vrf(snapshot, _interface_vrf(snapshot, interface))
        if str((after or {}).get("vrf") or "").casefold() == "default":
            # measured: NX-OS stores "use-vrf default" as a relay without VRF (nxos routing admin r3)
            raise Rejected(["omit vrf for the default VRF; NX-OS stores use-vrf default as a relay without VRF"])
        current = snapshot.entries(table).get(key)
        if current is not None:
            _check_vrf(snapshot, current.attributes.get("vrf"))
        _check_vrf(snapshot, (after or {}).get("vrf"))
        return []

    port = ETHERNET.fullmatch(key)
    if port and op != "update":
        raise Rejected(["an Ethernet port can only be updated"])
    loopback = LOOPBACK.fullmatch(key)
    if loopback and int(loopback[1]) > 1023:
        raise Rejected(["loopback number must be between 0 and 1023"])
    previous = snapshot.entries(table).get(key)
    before = previous.attributes if previous else {}
    _check_vrf(snapshot, before.get("vrf"))
    _check_vrf(snapshot, (after or {}).get("vrf"))
    if after is None:
        if key == "Vlan1" or any(not L3_OWN.match(line) for line in snapshot.interface_lines(key)):
            raise Rejected(["the interface cannot be deleted because it is reserved or has configuration "
                            "outside the L3 interface profile"])
        return []
    if not port and "mode" in after:
        raise Rejected(["the mode attribute applies only to physical Ethernet ports"])
    if port and "mode" not in after and any(name in after for name in (*IP_ATTRIBUTES, "vrf")):
        raise Rejected(["select routed mode before setting IP addresses or using a VRF on a switchport"])
    if port and before != after and any(LAG.match(line) for line in snapshot.interface_lines(key)):
        raise Rejected(["the port is a link aggregation member"], reason_codes=["port_lag_member"])
    if port and before.get("mode") != after.get("mode"):
        lines = snapshot.interface_lines(key)
        if any(TRUNK.match(line) for line in lines):
            raise Rejected(["the port is a trunk"], reason_codes=["port_uplink"])
        if any(not L3_OWN.match(line) for line in lines):
            raise Rejected(["the port has configuration that a mode change could discard"])
        if "no system default switchport" in snapshot.lines or L2_SHUTDOWN_DEFAULT in snapshot.lines:
            raise Rejected(["the switch has different Ethernet defaults from the measured mode conversion"])
    # measured: NX-OS refuses an overlapping subnet in the same VRF and accepts it in another VRF (nxos routing admin r3)
    vrf = after.get("vrf")
    for name in IP_ATTRIBUTES:
        if name not in after or after[name] == before.get(name):
            continue
        mine = ipaddress.ip_interface(after[name])
        for other, other_vrf, network in interface_networks(snapshot, skip=key):
            if other_vrf == (None if vrf in (None, "default") else vrf) and network.version == mine.version \
                    and network.overlaps(mine.network):
                raise Rejected(["the address %s of %s overlaps %s of interface %s in the same VRF"
                                % (after[name], key, network, other)])
    return []


def _interface_vrf(snapshot, key):
    return next((line.split()[-1] for line in snapshot.interface_lines(key) if line.startswith("vrf member ")), None)


def _route_cli(key, state, no=False) -> str:
    _, network = route_key(key)
    family = "ip" if network.version == 4 else "ipv6"
    line = "%s route %s %s" % (family, network, state["next-hop"])
    if no:
        return "no " + line
    return line + (" " + state["distance"] if state.get("distance", "1") != "1" else "")


def _relay_cli(key, state, no=False) -> str:
    _, server = key.split(":")
    vrf = state.get("vrf")
    return ("no " if no else "") + "ip dhcp relay address " + server + (" use-vrf " + vrf if vrf else "")


def render_state(table, key, before, after, snapshot=None) -> list:
    if table in ACL_TABLES:
        return render_acl(snapshot, table, key, before, after)
    if table == VLAN_TABLE:
        if after is None:
            return ["configure terminal", "no vlan " + key, "end"]
        lines = ["configure terminal", "vlan " + key]
        if after.get("name") != (before or {}).get("name"):
            lines.append("name " + after["name"] if "name" in after else "no name")
        return lines + ["end"]
    if table == MEMBERSHIP_TABLE:
        changed = [name for name in MEMBERSHIP_LINES if before.get(name) != after.get(name)]
        if "mode" in changed:
            changed.remove("mode")
            # Configure the new trunk's policy before enabling trunking.
            changed.insert(len(changed) if after.get("mode") == "trunk" else 0, "mode")
        lines = [_line(name, after.get(name)) for name in changed]
        return ["configure terminal", "interface " + key, *lines, "end"]
    if table == ROUTE_TABLE:
        vrf, _ = route_key(key)
        body = ["vrf context " + vrf] if vrf else []
        if after is not None:
            body.append(_route_cli(key, after))
        if before is not None and (after is None or before["next-hop"] != after["next-hop"]):
            body.append(_route_cli(key, before, no=True))
    elif table == RELAY_TABLE:
        body = ["interface " + key.split(":")[0]]
        if before is not None:
            body.append(_relay_cli(key, before, no=True))
        if after is not None:
            body.append(_relay_cli(key, after))
    elif after is None:
        body = ["no interface " + key]
    else:
        body = ["interface " + key]
        was = before or {}
        mode_changed = ETHERNET.fullmatch(key) and was.get("mode") != after.get("mode")
        if before is None and "vrf" in after:
            body.append("vrf member " + after["vrf"])
        if mode_changed and "mode" in after:
            body.append("no switchport")
        for name, command in zip(IP_ATTRIBUTES, ("ip address ", "ipv6 address ")):
            if was.get(name) == after.get(name):
                continue
            if name in was:
                body.append("no " + command + was[name])
            if name in after:
                body.append(command + after[name])
        if mode_changed:
            routed = after.get("mode") == "routed"
            if not routed:
                body.append("switchport")
            disabled = after.get("admin-state") == "disabled"
            if routed != disabled:
                body.append("shutdown" if disabled else "no shutdown")
        elif before is None or was.get("admin-state") != after.get("admin-state"):
            if before is not None or after.get("admin-state") == "disabled" or SVI.fullmatch(key):
                body.append("shutdown" if after.get("admin-state") == "disabled" else "no shutdown")
    return ["configure terminal", *body, "end"]


def _own_statement(table, key, header, line):
    if table == ACL_TABLE:
        return header == acl_header(key)
    if table == ACL_BINDING_TABLE:
        interface, family, direction = key.split(":")
        binding = ACL_BIND.fullmatch(line)
        return bool(header == "interface " + interface and binding
                    and (binding[1], binding[3], binding[5]) == (ACL_FAMILIES[family], ACL_VERBS[family], direction))
    if table == ROUTE_TABLE:
        if line != header and not header.startswith("vrf context "):
            return False
        vrf = header.split()[-1] if header.startswith("vrf context ") else None
        parsed = route_line(line, vrf)
        return parsed is not None and parsed[0] == key
    if table == L3_TABLE:
        if header != "interface " + key:
            return False
        if line == header:
            return not ETHERNET.fullmatch(key)
        return bool(L3_OWN.match(line))
    interface, server = key.split(":")
    relay = RELAY.fullmatch(line)
    return header == "interface " + interface and relay is not None and relay[1] == server


def state_digest(snapshot, table, key, safeguard):
    kept = []
    for block in snapshot.blocks:
        match = SCHEDULER_BLOCK.fullmatch(block.header)
        if match and match[1] == safeguard:
            continue
        header = block.header
        kept.extend(line for line in (header, *block.children) if not _own_statement(table, key, header, line.strip()))
    return hashlib.sha256("\n".join(kept).encode()).hexdigest()


def state_snapshot_after(text, plan):
    table, key, after = plan["table"], plan["key"], plan["predicted"]["after"]
    snapshot = load(text, plan["firmware"])
    target = None
    if table == ACL_TABLE:
        target = acl_header(key)
        added = [] if after is None else list(acl_rules(after.get("rules", ""), key.split(":")[0]).values())
    elif table == ACL_BINDING_TABLE:
        target = "interface " + key.split(":")[0]
        added = [acl_binding_line(snapshot, key, after)] if after else []
    elif table == ROUTE_TABLE:
        vrf, _ = route_key(key)
        target = "vrf context " + vrf if vrf else None
        added = [_route_cli(key, after)] if after is not None else []
    elif table == RELAY_TABLE:
        target = "interface " + key.split(":")[0]
        added = [_relay_cli(key, after)] if after is not None else []
    else:
        target = "interface " + key
        added = []
        if after is not None:
            if ETHERNET.fullmatch(key):
                routed = after.get("mode") == "routed"
                if routed != ("no system default switchport" in snapshot.lines):
                    added.append("no switchport" if routed else "switchport")
            if "vrf" in after:
                added.append("vrf member " + after["vrf"])
            disabled = after.get("admin-state") == "disabled"
            if disabled != interface_shutdown_default(snapshot, key, after):
                added.append("shutdown" if disabled else "no shutdown")
            added.extend(command + after[name] for name, command in zip(IP_ATTRIBUTES, ("ip address ", "ipv6 address "))
                         if name in after)
    result = [line for line in snapshot.lines if line.startswith(VOLATILE_HEADER)]
    for block in snapshot.blocks:
        header = block.header
        children = [line for line in block.children if not _own_statement(table, key, header, line.strip())]
        if header == target:
            children += [INDENT + line for line in added]
        if not _own_statement(table, key, header, header) or (header == target and after is not None):
            result += [header, *children]
    if table == ACL_TABLE and after is not None and not any(block.header == target for block in snapshot.blocks):
        result += [target, *(INDENT + line for line in added)]
    elif target is None:
        result += added
    elif table == L3_TABLE and after is not None and key not in snapshot.interfaces:
        result += [target, *(INDENT + line for line in added)]
    return "\n".join(result) + "\n"


def acl_header(key):
    family, name = key.split(":")
    return f"{ACL_FAMILIES[family]} access-list {name}"


def _ace_address(text, version):
    if text == "any":
        return text
    if text.startswith("host "):
        address = ipaddress.ip_address(text[5:])
        text = f"{address}/{address.max_prefixlen}"
    network = ipaddress.ip_network(text, strict=True)
    if network.version != version:
        raise ValueError
    return str(network) if network.prefixlen else "any"


def _ace_port(text):
    if text is None:
        return ""
    operator, *values = text.split()
    ports = [int(value) if value.isdecimal() else ACE_SERVICES.get(value, -1) for value in values]
    if not all(0 <= port <= 65535 for port in ports) or ports != sorted(ports):
        raise ValueError
    return " " + operator + " " + " ".join(map(str, ports))


def acl_rules(text, family):
    """Canonicalize explicitly sequenced ACEs and reject syntax that cannot be restored."""
    version = 4 if family == "ipv4" else 6
    rules = {}
    for line in text.split(",") if text else ():
        try:
            match = ACE.fullmatch(" ".join(line.split()))
            if match is None:
                raise ValueError
            sequence, action, protocol, source, sport, destination, dport = match.groups()
            sequence = int(sequence)
            if not 1 <= sequence <= 4294967295 or sequence in rules:
                raise ValueError
            if protocol not in (ACL_FAMILIES[family], "icmp", "udp", "tcp"):
                raise ValueError
            if (sport or dport) and protocol not in ("tcp", "udp"):
                raise ValueError
            rules[sequence] = (f"{sequence} {action} {protocol} {_ace_address(source, version)}{_ace_port(sport)} "
                               f"{_ace_address(destination, version)}{_ace_port(dport)}")
        except ValueError:
            raise Rejected(["use distinct ACE sequence numbers, permit or deny, a family-specific IP protocol, "
                            "two addresses and optional TCP/UDP port comparisons"],
                           reason_codes=["nxos_acl_unsupported"]) from None
    return dict(sorted(rules.items()))


def canonical_acl_changes(table, key, changes):
    if table != ACL_TABLE or changes.get("rules") is None:
        return changes
    value = ", ".join(acl_rules(changes["rules"], key.split(":")[0]).values())
    if not value or len(value) > ACL_RULE_LIMIT:
        raise Rejected(["ACL rules exceed the profile size or are empty"], reason_codes=["nxos_acl_unsupported"])
    return dict(changes, rules=value)


def acl_binding_state(lines, family, direction, *, routed=None):
    cli = ACL_FAMILIES[family]
    verb = ACL_VERBS[family]
    names = []
    for line in lines:
        if not line.startswith((f"{cli} {verb} ", f"{cli} port {verb} ")):
            continue
        group = ACL_BIND.fullmatch(line)
        if group is None:
            raise acl_unreadable("attachment syntax")
        if group[5] == direction:
            if routed is not None and bool(group[2]) == routed:
                raise acl_unreadable("attachment mode")
            names.append(group[4])
    if len(names) > 1:
        raise acl_unreadable("duplicate attachments")
    return {"acl": names[0]} if names else {}


def acl_entries(snapshot, table):
    entries = {}
    if table == ACL_TABLE:
        for block in snapshot.blocks:
            match = ACL_HEADER.fullmatch(block.header)
            if match is None:
                continue
            family = "ipv4" if match[1] == "ip" else "ipv6"
            key = f"{family}:{match[2]}"
            if key in entries:
                raise acl_unreadable("duplicate definitions")
            entries[key] = entry = Entry(key)
            try:
                value = ", ".join(acl_rules(",".join(line.strip() for line in block.children), family).values())
                if len(value) > ACL_RULE_LIMIT:
                    raise ValueError
            except (Rejected, ValueError):
                entry.unsupported.append("ACL has settings or entries outside the profile")
                continue
            if value:
                entry.attributes["rules"] = value
        return entries
    for interface in snapshot.interfaces:
        if not (ETHERNET.fullmatch(interface) or SVI.fullmatch(interface)):
            continue
        lines = snapshot.interface_lines(interface)
        routed = acl_port_is_routed(snapshot, interface)
        for family in ACL_FAMILIES:
            for direction in ("in", "out"):
                key = f"{interface}:{family}:{direction}"
                entries[key] = entry = Entry(key)
                try:
                    entry.attributes = acl_binding_state(lines, family, direction, routed=routed)
                except Rejected:
                    entry.unsupported.append("ACL attachment is ambiguous")
    return entries


def acl_port_is_routed(snapshot, interface):
    return not ETHERNET.fullmatch(interface) or l3_entry(
        snapshot, interface, snapshot.interfaces[interface]).attributes.get("mode") == "routed"


def acl_unreadable(what):
    return Rejected([f"the NX-OS ACL {what} is not recognised"], reason_codes=["nxos_acl_readback_unreadable"])


def acl_binding_line(snapshot, key, state):
    interface, family, direction = key.split(":")
    port = "" if acl_port_is_routed(snapshot, interface) else " port"
    return f"{ACL_FAMILIES[family]}{port} {ACL_VERBS[family]} {state['acl']} {direction}"


def render_acl(snapshot, table, key, before, after):
    if table == ACL_BINDING_TABLE:
        interface = key.split(":")[0]
        # Send the new ACL directly. A preceding removal would leave the interface unfiltered.
        line = acl_binding_line(snapshot, key, after or before)
        return ["configure terminal", "interface " + interface, line if after else "no " + line, "end"]
    header = acl_header(key)
    if after is None:
        return ["configure terminal", "no " + header, "end"]
    family = key.split(":")[0]
    old, new = [acl_rules((side or {}).get("rules", ""), family) for side in (before, after)]
    removed = [f"no {seq}" for seq, rule in old.items() if new.get(seq) != rule]
    added = [rule for seq, rule in new.items() if old.get(seq) != rule]
    return ["configure terminal", header, *removed, *added, "exit", "end"]


def acl_references(snapshot, key):
    family, name = key.split(":")
    token = re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", re.IGNORECASE)
    attachments = set()
    for block in snapshot.blocks:
        if ACL_HEADER.fullmatch(block.header):
            continue
        interface = block.header.removeprefix("interface ") if block.header.startswith("interface ") else None
        for line in (block.header, *(child.strip() for child in block.children)):
            binding = ACL_BIND.fullmatch(line)
            if interface and binding:
                if binding[1] == ACL_FAMILIES[family] and binding[4].casefold() == name.casefold():
                    if binding[3] != ACL_VERBS[family] or binding[4] != name:
                        raise Rejected(["ACL reference has ambiguous syntax or letter case"],
                                       reason_codes=["nxos_acl_in_use"])
                    attachments.add(f"{interface}:{family}:{binding[5]}")
            elif not line.startswith(("description ", "remark ")) and token.search(line):
                raise Rejected(["ACL name is used outside a supported attachment"], reason_codes=["nxos_acl_in_use"])
    return attachments


def _protect_acl_name(key, protected):
    name = key.split(":")[1].casefold()
    if name.startswith(("copp-", "netops-enroll-")) or {name, key.casefold()} & protected[ACL_TABLE]:
        raise Rejected(["the ACL is protected"], reason_codes=["nxos_acl_in_use"])


def acl_prechecks(snapshot, table, key, before, after, protected):
    protected = {name: {str(value).casefold() for value in (protected or {}).get(name, ())}
                 for name in (*ACL_TABLES, "interface", "ports", MEMBERSHIP_TABLE, L3_TABLE, VLAN_TABLE, "vrf")}
    if table == ACL_TABLE:
        _protect_acl_name(key, protected)
        bindings = acl_references(snapshot, key)
        if bindings and (before is None or not after or not after.get("rules")):
            raise Rejected(["an attached ACL cannot be created, emptied or deleted"], reason_codes=["nxos_acl_in_use"])
    else:
        bindings = {key}
        family = key.split(":")[1]
        definitions = acl_entries(snapshot, ACL_TABLE)
        for state in (before, after):
            if not state:
                continue
            target = family + ":" + state["acl"]
            _protect_acl_name(target, protected)
            definition = definitions.get(target)
            if definition is None or definition.unsupported or not definition.attributes.get("rules"):
                raise Rejected(["the attachment needs an existing nonempty ACL of the same IP family"],
                               reason_codes=["nxos_acl_undefined"])
    for binding in sorted(bindings):
        interface, _, direction = binding.split(":")
        if interface_protected(protected, interface) or {binding.casefold(), interface.casefold()} & protected[ACL_BINDING_TABLE] or any(
                interface.casefold() in protected[name] for name in ("interface", "ports", MEMBERSHIP_TABLE, L3_TABLE)):
            raise Rejected(["the ACL interface is protected"], reason_codes=["port_protected"])
        svi = SVI.fullmatch(interface)
        if MANAGEMENT.fullmatch(interface) or (svi and svi[1] in protected[VLAN_TABLE]) or (
                (_interface_vrf(snapshot, interface) or "default").casefold() in protected["vrf"] | {"management"}):
            raise Rejected(["the ACL interface is protected for management"], reason_codes=["port_management_interface"])
        if interface not in snapshot.interfaces or not (svi or ETHERNET.fullmatch(interface)):
            raise Rejected(["the ACL needs an existing Ethernet interface or SVI"],
                           reason_codes=["port_unsupported_interface"])
        lines = snapshot.interface_lines(interface)
        if any(LAG.match(line) for line in lines):
            raise Rejected(["the ACL interface is an aggregation member"], reason_codes=["port_lag_member"])
        if any(TRUNK.match(line) for line in lines):
            raise Rejected(["the ACL interface is a trunk"], reason_codes=["port_uplink"])
        if direction == "out" and not acl_port_is_routed(snapshot, interface):
            raise Rejected(["a switchport ACL can filter only inbound traffic"], reason_codes=["nxos_acl_unsupported"])


# System service profiles target one server or one setting, rather than replacing a service section.
SERVICE_VRF = r"[A-Za-z][A-Za-z0-9_-]{0,31}"
SERVICE_INTERFACE = re.compile(r"(?:Ethernet[\d/]+|Vlan\d+|loopback\d+|port-channel\d+|mgmt\d+)")
SERVICE_DOMAIN = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
SERVICE_SERVER_PREFIX = {NTP_SERVER: "ntp server", SYSLOG_SERVER: "logging server", DNS_SERVER: "ip name-server"}
SERVICE_SOURCE_PREFIX = {NTP_SOURCE: "ntp source-interface", SYSLOG_SOURCE: "logging source-interface"}


def service_unrestorable():
    return Rejected(["the NX-OS service has configuration outside the profile or cannot be restored in order"],
                    reason_codes=["nxos_service_unsupported"])


def service_address(value):
    try:
        return str(ipaddress.ip_address(value)) if "%" not in value else None
    except ValueError:
        return None


def service_key(table, key):
    context, slash, address = key.partition("/")
    if table == DNS_SERVER and slash and context != "default":
        return context, address
    return None, key


def _service_options(words):
    if not words:
        return {}
    if len(words) == 2 and words[0] == "use-vrf" and re.fullmatch(SERVICE_VRF, words[1]):
        return {} if words[1] == "default" else {"vrf": words[1]}
    return None


def service_rows(table, header, line):
    """Return the keys and supported state of one configuration statement."""
    context = None
    if header != line:
        if table not in (DNS_SERVER, DNS_DOMAIN) or not header.startswith("vrf context "):
            return None
        context = header.split()[-1]
    key_prefix = context + "/" if context and context != "default" else ""
    context_key = context or "default"

    if table in SERVICE_SOURCE_PREFIX:
        prefix = SERVICE_SOURCE_PREFIX[table]
        if table == NTP_SOURCE and line.startswith("ntp source "):
            return {"global": None}
        if line.startswith(prefix + " "):
            source = line[len(prefix) + 1:]
            return {"global": {"source-interface": source} if SERVICE_INTERFACE.fullmatch(source) else None}
        return None

    if table == DNS_DOMAIN:
        if not line.startswith("ip domain-name "):
            return None
        value, *options = line[len("ip domain-name "):].split()
        parsed = _service_options(options)
        return {context_key: {"domain": value, **parsed} if parsed is not None and SERVICE_DOMAIN.fullmatch(value)
                else None}

    prefix = SERVICE_SERVER_PREFIX[table] + " "
    if not line.startswith(prefix):
        return None
    if table == DNS_SERVER:
        values, separator, route = line[len(prefix):].partition(" use-vrf ")
        addresses = [service_address(value) for value in values.split()]
        if not addresses or None in addresses:
            raise service_unrestorable()
        parsed = _service_options(["use-vrf", route] if separator else [])
        return {key_prefix + address: parsed for address in addresses}

    address, *options = line[len(prefix):].split()
    address = service_address(address)
    if address is None:
        # Hostname-based state is outside these address profiles, and is preserved verbatim.
        return None
    severity = {}
    if table == SYSLOG_SERVER and options and re.fullmatch(r"[0-7]", options[0]):
        severity = {"severity": options.pop(0)}
    parsed = _service_options(options)
    return {address: {**severity, **parsed} if parsed is not None else None}


def service_entries(snapshot, table):
    result = {}
    for block in snapshot.blocks:
        for line in (block.header, *(child.strip() for child in block.children)):
            for key, values in (service_rows(table, block.header, line) or {}).items():
                duplicate = key in result
                entry = result.setdefault(key, Entry(key))
                if values is None or duplicate:
                    entry.unsupported.append("unmanaged or repeated %s statement at line %d" % (table, block.line))
                else:
                    entry.attributes = values
    return result


def service_prechecks(snapshot, table, key, before, after, protected, impact=None, *, undo=False):
    if table in SERVICE_SERVER_PREFIX:
        scope, address = service_key(table, key)
        if service_address(address) != address:
            raise Rejected(["the service key must use a canonical IP address"])
    else:
        scope = key if table == DNS_DOMAIN and key != "default" else None
    if table == DNS_DOMAIN and after and "domain" not in after:
        raise Rejected(["a DNS domain name is required for use-vrf"], reason_codes=["nxos_service_unsupported"])
    if scope and scope.casefold() in {item.casefold() for item in protected.get("vrf", ())}:
        raise Rejected(["the DNS configuration VRF is protected"], reason_codes=["port_protected"])
    for vrf in {scope, *((state or {}).get("vrf") for state in (before, after))} - {None, "default", "management"}:
        if "vrf context " + vrf not in snapshot.lines:
            raise Rejected(["VRF %s does not exist" % vrf], reason_codes=["nxos_service_unsupported"])
    if table in SERVICE_SOURCE_PREFIX:
        guarded = {name.casefold() for field in ("interface", "l3-interface", "vlan-membership")
                   for name in protected.get(field, ())}
        for source in {(state or {}).get("source-interface") for state in (before, after)} - {None}:
            if MANAGEMENT.fullmatch(source) or source.casefold() in guarded:
                raise Rejected(["the source interface is protected"], reason_codes=["port_protected"])
            if source not in snapshot.interfaces:
                raise Rejected(["the source interface is not configured"], reason_codes=["nxos_service_unsupported"])
            if table == SYSLOG_SOURCE and not any(name == source for name, _, _ in interface_addresses(snapshot)):
                raise Rejected(["the syslog source interface needs a configured IP address"],
                               reason_codes=["nxos_service_unsupported"])
    checks = []
    peers = None
    if table in SERVICE_SERVER_PREFIX and before is not None and before != after:
        old_vrf = before.get("vrf") or "default"
        peers = [item for item, entry in service_entries(snapshot, table).items()
                 if not entry.unsupported and service_key(table, item)[0] == scope
                 and (entry.attributes.get("vrf") or "default") == old_vrf]
        if (after is None or (after.get("vrf") or "default") != old_vrf) and peers == [key]:
            if impact != key and not undo:
                raise Rejected(["removing the last %s target requires endpoint_impact naming %s" % (table, key)],
                               reason_codes=["endpoint_impact_required"])
            # Undo explicitly requests the inverse of a journaled change, including removal of a newly created target.
            checks.append("This change removes the last %s target in its context" % table)
    if table == DNS_SERVER and peers is not None:
        # Removing a member and adding it back appends it to that resolver list. Its order is significant.
        if not peers or peers[-1] != key:
            raise service_unrestorable()
    return checks


def _service_statement(table, key, state, *, remove=False, configured=False):
    vrf = " use-vrf " + state["vrf"] if state.get("vrf") else ""
    if table in SERVICE_SERVER_PREFIX:
        address = service_key(table, key)[1]
        if remove and table == SYSLOG_SERVER:
            return "no logging server " + address
        severity = ""
        if table == SYSLOG_SERVER:
            severity = " " + state.get("severity", "5") if vrf or not configured or "severity" in state else ""
            if not configured and not vrf:
                vrf = " use-vrf default"
        elif table == NTP_SERVER and configured and not vrf:
            vrf = " use-vrf default"
        return ("no " if remove else "") + SERVICE_SERVER_PREFIX[table] + " " + address + severity + vrf
    if table == DNS_DOMAIN:
        return ("no " if remove else "") + "ip domain-name " + state["domain"] + vrf
    source = state["source-interface"]
    if remove and table == SYSLOG_SOURCE:
        return "no logging source-interface"
    return ("no " if remove else "") + SERVICE_SOURCE_PREFIX[table] + " " + source


def render_service(table, key, before, after):
    scope = service_key(table, key)[0] if table == DNS_SERVER else key if table == DNS_DOMAIN else None
    body = ["vrf context " + scope] if scope and scope != "default" else []
    servers = table in SERVICE_SERVER_PREFIX
    deleting = after is None if servers else not after
    replaces_route = (table in (NTP_SERVER, DNS_SERVER, DNS_DOMAIN) and after is not None
                      and before is not None and before.get("vrf") != after.get("vrf"))
    if before is not None and (before or servers) and (deleting or replaces_route):
        body.append(_service_statement(table, key, before, remove=True))
    if after is not None and (after or table in SERVICE_SERVER_PREFIX):
        body.append(_service_statement(table, key, after))
    return ["configure terminal", *body, "end"]


def _service_rest_lines(snapshot, table, key, safeguard=None):
    for block in snapshot.blocks:
        scheduled = SCHEDULER_BLOCK.fullmatch(block.header)
        if scheduled and scheduled[1] == safeguard:
            continue
        for raw in (block.header, *block.children):
            rows = service_rows(table, block.header, raw.strip())
            if rows is None or (table != DNS_SERVER and key not in rows):
                yield raw
            elif table == DNS_SERVER:
                # NX-OS permits several resolvers per statement. Normalize the list without masking other members.
                for member, state in rows.items():
                    if member != key:
                        if state is None:
                            yield raw
                            break
                        yield ("  " if raw.startswith(" ") else "") + _service_statement(table, member, state)


def service_snapshot_after(text, plan):
    table, key = plan["table"], plan["key"]
    snapshot = load(text, plan["firmware"])
    scope = service_key(table, key)[0] if table == DNS_SERVER else key if table == DNS_DOMAIN else None
    after = plan["predicted"]["after"]
    result = [line for line in snapshot.lines if line.startswith(VOLATILE_HEADER)]
    for line in _service_rest_lines(snapshot, table, key):
        result.append(line)
        if scope and scope != "default" and line == "vrf context " + scope and (after or after == {} and table == DNS_SERVER):
            result.append("  " + _service_statement(table, key, after, configured=True))
    if (scope is None or scope == "default") and (after or after == {} and table in SERVICE_SERVER_PREFIX):
        result.append(_service_statement(table, key, after, configured=True))
    return "\n".join(result) + "\n"


# ---- answers of the device (measured fixtures, private measurement record) ----

ERROR_LINES = (
    re.compile(r"^% "),                       # Invalid command, Incomplete command, Permission denied, Invalid number
    re.compile(r"at '\^' marker\.$"),         # reserved VLAN, Invalid range (no "%")
    re.compile(r"^Error: "),                  # scheduler: delete job/schedule failed: schedule in progress
    re.compile(r"^ERROR: "),                  # rollback log
    re.compile(r"^Rollback failed"),          # rollback running-config checkpoint ... atomic
    re.compile(r"^Verification failed"),      # atomic rollback that was undone
    re.compile(r"^Config(?:ure)? [Rr]eplace (?:operation )?failed"),
    re.compile(r"No such file or directory"),
)


def cli_error(text: str):
    """A refused line: the measured error forms of NX-OS 9.3(12), with and without "%".

    A carriage return ends a line too: the interactive session writes "\r" before every prompt, also right after
    the last output line when that line has no newline (read in verification)."""
    for line in re.split(r"[\r\n]", text)[1:]:
        stripped = line.strip()
        if any(pattern.search(stripped) for pattern in ERROR_LINES):
            return stripped[:100]
    return None


NXOS_VERSION = re.compile(r"^\s*NXOS: version (\S+)\s*$", re.MULTILINE)
CLOCK = re.compile(r"^([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)? (\S+) [A-Z][a-z]{2} ([A-Z][a-z]{2}) "
                   r"([0-9]{1,2}) ([0-9]{4})\s*$", re.MULTILINE)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
FEATURE = re.compile(r"^(\S+)[ \t]+[0-9]+[ \t]+(enabled|disabled)(?:[ \t][^\r\n]*)?$", re.MULTILINE)
VLAN_MISSING = re.compile(r"^VLAN ([0-9]+) not found in current VLAN database\s*$", re.MULTILINE)
ACCESS_VLAN = re.compile(r"^\s*Access Mode VLAN:\s*([0-9]+)\b", re.MULTILINE)
NATIVE_VLAN = re.compile(r"^[ \t]*Trunking Native Mode VLAN:[ \t]*([0-9]+)\b", re.MULTILINE)
ALLOWED_VLANS = re.compile(r"^[ \t]*Trunking VLANs Allowed:[ \t]*(\S+)[ \t]*$", re.MULTILINE)
OPERATIONAL_MODE = re.compile(r"^\s*Operational Mode:\s*(\S+)\s*$", re.MULTILINE)
SWITCHPORT = re.compile(r"^\s*Switchport:\s*(\S+)\s*$", re.MULTILINE)
SWITCHPORT_NAME = re.compile(r"^Name:\s*(\S+)\s*$", re.MULTILINE)
MAC_HEADER = re.compile(r"^\s*VLAN\s+MAC Address\s+Type", re.MULTILINE)
MAC_SEPARATOR = re.compile(r"^-+(?:\+-+)+$")
MAC_ENTRY = re.compile(r"^[*G+COR~() ]*(?:\d+|-)\s+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
                       r"\s+(dynamic|static)\s+\S+\s+[TF]\s+[TF]\s+\S+(?:\s+\S+)*$", re.IGNORECASE)
LLDP_HEADER = re.compile(r"^Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID\s*$", re.MULTILINE)
LLDP_TOTAL = re.compile(r"^Total entries displayed:\s*([0-9]+)\s*$", re.MULTILINE)
SHORT_PORT = re.compile(r"^(?:Eth[0-9]+/[0-9]+(?:/[0-9]+)?|mgmt[0-9]+|Po[0-9]+)$")


def short_name(key: str) -> str:
    """The abbreviations NX-OS prints in tables for physical and logical interfaces."""
    if key.startswith("Ethernet"):
        return "Eth" + key[len("Ethernet"):]
    if match := PORT_CHANNEL.fullmatch(key):
        return "Po" + match[1]
    return key


def unreadable(what: str):
    return Rejected(["the %s is not recognised" % what], reason_codes=["port_usage_unreadable"])


def nxos_version(text: str) -> str:
    found = NXOS_VERSION.findall(text)
    if len(found) != 1:
        raise Rejected(["the device does not report its NX-OS version"])
    return found[0]


def clock(text: str):
    """Hour, minute, second, zone, month, day and year of show clock (a leading NTP warning line is ignored)."""
    found = CLOCK.findall(text.replace("\r", ""))
    if len(found) != 1 or found[0][4] not in MONTHS:
        raise Rejected(["the device clock answer is not recognised"])
    hour, minute, second, zone, month, day, year = found[0]
    return int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute), int(second), zone


def feature_state(text: str, name: str):
    states = [state for feature, state in FEATURE.findall(text.replace("\r", "")) if feature == name]
    return states[0] if states and all(state == states[0] for state in states) else None


def vlan_exists(text: str, vlan: str) -> bool:
    missing = VLAN_MISSING.search(text)
    if missing is not None:
        if missing.group(1) != vlan:
            raise Rejected(["the VLAN answer names another VLAN"])
        return False
    for line in text.split("\n"):
        words = line.split()
        if words[:1] == [vlan] and len(words) >= 3:
            return True
    raise Rejected(["the answer about VLAN %s is not recognised" % vlan])


def vlan_status(text: str, key: str):
    lines = [line.rstrip() for line in text.replace("\r", "").splitlines() if line.strip()]
    if len(lines) == 1 and VLAN_MISSING.fullmatch(lines[0]) and VLAN_MISSING.fullmatch(lines[0])[1] == key:
        return None
    header = "VLAN Name                             Status    Ports"
    type_head = "VLAN Type         Vlan-mode"
    if (len(lines) < 8 or lines[0] != header or type_head not in lines
            or lines[1] != "---- -------------------------------- --------- -------------------------------"):
        raise unreadable("VLAN %s table" % key)
    type_index = lines.index(type_head)
    if (type_index < 3 or len(lines) < type_index + 6 or lines[type_index + 2].split() != [key, "enet", "CE"]
            or "Remote SPAN VLAN" not in lines[type_index + 3:] or "Disabled" not in lines[type_index + 3:]):
        raise unreadable("VLAN %s details" % key)
    name, status = lines[2][5:38].strip(), lines[2][38:48].strip()
    if lines[2][:5].strip() != key or not name or status not in ("active", "suspended"):
        raise unreadable("VLAN %s row" % key)
    if any(continuation[:48].strip() for continuation in lines[3:type_index]):
        raise unreadable("VLAN %s port list" % key)
    members = {port for line in lines[2:type_index] for port in line[48:].replace(",", " ").split()}
    if not all(SHORT_PORT.fullmatch(port) for port in members):
        raise unreadable("VLAN %s port list" % key)
    return {"name": name, "status": status, "ports": members}


def switchport(text: str, key: str) -> dict:
    """Switchport state, operational mode and access VLAN of show interface N switchport."""
    name = SWITCHPORT_NAME.search(text)
    enabled = SWITCHPORT.search(text)
    mode = OPERATIONAL_MODE.search(text)
    vlan = ACCESS_VLAN.search(text)
    if name is None or enabled is None or mode is None or vlan is None:
        raise Rejected(["the switchport answer about %s is not recognised" % key])
    if name.group(1) != key:
        raise Rejected(["the switchport answer names another interface"])
    return {"switchport": enabled.group(1), "mode": mode.group(1), "access-vlan": vlan.group(1)}


def membership_status(text: str, key: str) -> dict:
    native, allowed = NATIVE_VLAN.findall(text), ALLOWED_VLANS.findall(text)
    shown = switchport(text, key)
    if (len(native) != 1 or len(allowed) != 1
            or shown["switchport"] != "Enabled" or shown["mode"] not in ("access", "trunk")):
        raise unreadable("switchport state of %s" % key)
    try:
        permitted = vlan_text(trunk_vlans(allowed[0]))
    except Rejected as exc:
        raise unreadable("allowed VLANs of %s" % key) from exc
    return {"access-vlan": shown["access-vlan"], "mode": shown["mode"],
            "native-vlan": native[0], "allowed-vlans": permitted}


def table_rows(text: str, first_column: str) -> tuple:
    """Header column positions and the rows of the first fixed-width table whose header starts with first_column."""
    lines = text.replace("\r", "").split("\n")
    for index, line in enumerate(lines):
        if line.startswith(first_column + " "):
            columns = [(match.group(0), match.start()) for match in re.finditer(r"\S+", line)]
            rows = []
            for row in lines[index + 1:]:
                if not row.strip():
                    if rows:
                        break
                    continue
                if set(row.strip()) <= {"-", " "}:
                    continue
                rows.append(row)
            return columns, rows
    return None, None


def status_row(text: str, key: str):
    """Name, Status and Vlan columns of show interface N status, or None for another layout."""
    columns, rows = table_rows(text, "Port")
    if columns is None or [name for name, _ in columns][:4] != ["Port", "Name", "Status", "Vlan"]:
        return None
    starts = [start for _, start in columns]
    for row in rows:
        if row.split()[:1] == [short_name(key)]:
            return {"name": row[starts[1]:starts[2]].strip(), "status": row[starts[2]:starts[3]].strip(),
                    "vlan": row[starts[3]:starts[4]].strip() if len(starts) > 4 else row[starts[3]:].strip()}
    return None


def description_row(text: str, key: str):
    """The description of the port in show interface description (the Port/Type/Speed/Description table), "" for
    "--", or None when the port is not listed."""
    lines = text.replace("\r", "").split("\n")
    header = None
    for index, line in enumerate(lines):
        if line.split()[:4] == ["Port", "Type", "Speed", "Description"]:
            header = index
            break
    if header is None:
        return None
    start = lines[header].index("Description")
    for row in lines[header + 1:]:
        if row.split()[:1] == [short_name(key)]:
            if len(row.split()) < 4:
                return None
            value = row[start:].strip() if len(row) > start and row[start - 1] == " " else " ".join(row.split()[3:])
            return "" if value == "--" else value
    return None


def trunk_ports(text: str) -> set:
    """Ports listed in show interface trunk (the first column of its tables)."""
    if not re.search(r"^Port\s+Native\s+Status\s+Port\s*$", text, re.MULTILINE):
        raise unreadable("trunk list")
    found = set()
    for line in text.replace("\r", "").split("\n"):
        words = line.split()
        if words and SHORT_PORT.match(words[0]):
            found.add(words[0])
    return found


def lldp_ports(text: str) -> set:
    """Local ports with an LLDP neighbor (measured layout Device ID, Local Intf, Hold-time, Capability, Port ID;
    a long device ID is printed on its own line and the rest of the row on the next)."""
    header = LLDP_HEADER.search(text)
    total = LLDP_TOTAL.search(text)
    if header is None or total is None:
        raise unreadable("LLDP neighbor list")
    found, count = set(), 0
    for line in text[header.end():total.start()].split("\n"):
        words = line.split()
        if not words:
            continue
        local = [word for word in words[:2] if SHORT_PORT.match(word)]
        if not local:
            if len(words) == 1:
                continue  # a long device ID; the next line holds the local port
            raise unreadable("LLDP neighbor list")
        found.add(local[0])
        count += 1
    if count != int(total.group(1)):
        raise unreadable("LLDP neighbor list")
    return found


def learned_macs(text: str) -> int:
    """Rows of show mac address-table interface N (0 when only the legend and the header are printed)."""
    return len(mac_types(text))


def mac_types(text: str) -> list:
    header = MAC_HEADER.search(text)
    if header is None:
        raise unreadable("MAC address table")
    rows = [line.strip() for line in text[header.start():].splitlines() if line.strip()]
    if len(rows) < 2 or not MAC_SEPARATOR.fullmatch(rows[1]):
        raise unreadable("MAC address table")
    matches = [MAC_ENTRY.fullmatch(line) for line in rows[2:]]
    if any(match is None for match in matches):
        raise unreadable("MAC address table rows")
    return [match[1].lower() for match in matches]


def cdp_ports(text: str) -> set:
    header = re.search(r"^Device-ID\s+Local Intrfce\s+Hldtme\s+Capability\s+Platform\s+Port ID\s*$",
                       text, re.MULTILINE)
    total = LLDP_TOTAL.search(text)
    if not header or not total:
        raise unreadable("CDP neighbor list")
    found, count = set(), 0
    for line in text[header.end():total.start()].splitlines():
        words = line.split()
        if not words or len(words) == 1:
            continue
        local = next((word for word in words[:2] if SHORT_PORT.fullmatch(word)), None)
        if not local:
            raise unreadable("CDP neighbor list")
        found.add(local)
        count += 1
    if count != int(total[1]):
        raise unreadable("CDP neighbor list")
    return found


def users(text: str) -> tuple:
    """Own and other sessions of show users: the own row ends with '*'."""
    lines = text.replace("\r", "").split("\n")
    if not lines or not any(line.split()[:2] == ["NAME", "LINE"] for line in lines):
        raise Rejected(["the session list is not readable"])
    rows = [line for line in lines if line.strip() and line.split()[:2] != ["NAME", "LINE"]]
    own = sum(1 for row in rows if row.rstrip().endswith("*"))
    return own, len(rows) - own


def ssh_session_peer(text: str):
    """Read the source of the current interactive SSH session from its starred row."""
    own = [line for line in text.splitlines() if line.rstrip().endswith("*")]
    if len(own) == 1:
        peer = re.search(r"\(([^()\s]+)\)\s+session=ssh\s+\*\s*$", own[0])
        if peer is not None:
            try:
                address = ipaddress.ip_address(peer[1])
                # Socket queries use a numeric address without a CLI-supplied IPv6 scope.
                return ipaddress.ip_address(address.packed)
            except ValueError:
                pass
    raise unreadable("current SSH session source")


def svi_operational(text: str, interface: str) -> bool:
    pattern = re.compile(
        r"%s is (up|down|administratively down)(?: \([^)]*\))?, line protocol is (up|down)\b.*"
        % re.escape(interface))
    states = [match.groups() for line in text.splitlines() if (match := pattern.fullmatch(line.rstrip()))]
    if len(states) != 1:
        raise unreadable("SVI operational state")
    return states[0] == ("up", "up")


def loopback_operational(text: str, interface: str) -> bool:
    pattern = re.compile(r"%s is (up|down)(?: \([^)]*\))?" % re.escape(interface))
    states = [match[1] for line in text.splitlines() if (match := pattern.fullmatch(line.rstrip()))]
    if len(states) != 1:
        raise unreadable("loopback operational state")
    return states[0] == "up"


SSH_SOCKET = re.compile(r"(?:\[[^\]]+\]:[ \t]+)?tcp(?:6|\(4/6\))?\s+ESTABLISHED\s+\d+\s+\S+\(22\)\s*")
SSH_SOCKET_CONTEXT = re.compile(r"\s+(\S+)\s+\d+\s+([^()\s]+)\(\d+\)\s*")


def unmap_ipv4(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def ssh_session_vrf(text: str, peer) -> str:
    """Find the established SSH socket context for the peer on this interactive session."""
    lines = text.splitlines()
    vrfs = set()
    for index, line in enumerate(lines):
        if not SSH_SOCKET.fullmatch(line):
            continue
        context = SSH_SOCKET_CONTEXT.fullmatch(lines[index + 1]) if index + 1 < len(lines) else None
        if context is None:
            raise unreadable("current SSH session VRF")
        vrf, foreign = context.groups()
        try:
            address = unmap_ipv4(ipaddress.ip_address(foreign))
        except ValueError:
            raise unreadable("current SSH session VRF") from None
        if address == unmap_ipv4(peer):
            if not VRF.fullmatch(vrf) or vrf == "Wildcard":
                raise unreadable("current SSH session VRF")
            vrfs.add(vrf)
    if len(vrfs) != 1:
        raise unreadable("current SSH session VRF")
    return vrfs.pop()


def user_accounts(text: str) -> list:
    """The user names of show user-account (lines user:NAME)."""
    return sorted(match.group(1) for match in re.finditer(r"^user:(\S+)\s*$", text, re.MULTILINE))
