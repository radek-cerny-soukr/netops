from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from netops_auditor import l1_exos

from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected
from netops_admin import exos_acl, exos_g44, exos_g46, exos_services, membership
from netops_core import tested

OWN_ATTRIBUTES = ("tag", "description")
BOUNCE_TABLE = "port-bounce"
PORT_STATE_SCHEMA = "exos-port-description-string"
PORT_TABLES = ("ports", BOUNCE_TABLE, "inline-power")
PORT_TEXT = ("display-string", "description-string")
DEFAULT_RECOVERY = ("configure", "sys-recovery-level", "switch", "reset")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SECRET_SUBJECTS = ("snmp", "snmpv3")
SECRET_WORDS = ("community", "encrypted", "password", "shared-secret")
FREE_TEXT = ("description", "description-string", "display-string", "syscontact", "syslocation", "sysname")
KEYWORDS = SECRET_SUBJECTS + SECRET_WORDS + FREE_TEXT

# Source: ExtremeXOS 33.6.1 User Guide, Object Names, Table 7 (+ rmon, task 469-r3), narrowed by a live check on
# EXOS-VM 33.6.1.14 and X440-G2 33.7.1.6 (2026-11-17, task 469-r4, task-evidence/g43/r4/reserved-live.json):
# words that both switches accept in `create vlan <word>` are removed (incl. ipv4); a word rejected by at least
# one of them stays. Both reject ipv6 ("Name cannot be a reserved keyword").
RESERVED_VLAN_NAMES = frozenset("""
    aaa access-list account accounts acl auto-peering auto-provision avb bandwidth banner bfd bgp
    bootprelay bootrom brm cdp cfgmgr cfm checkpoint-data clear clear-flow cli clipaging
    configuration configure cos-index counters cp cpu-monitoring create dcbx delete devmgr dhcp
    dhcp-client dhcp-server dhcpv6 diagnostics diffserv disable dns dns-client dos-protect dot1ag
    dot1p dot1q ds dwdm eaps edp elrp elrp-client elsm ems enable epm erps esrp ethernet evpn exit
    exsh-var fabric failsafe-account fdb firmware flow-redirect force_synchronize forwarding get
    gptp hal hclag icmp identity-management idletimeout idmgr igmp image inline-power ip ip-fix
    ip-mtu ip-security iparp ipconfig ipforwarding ipmc ipmcforwarding ipmroute iproute ipstats ipv6
    irdp isis jumbo-frame jumbo-frame-size kernel l2pt l2stats lacp ldap learning led license
    licenses licmgr lldp load log logout mac mac-lockdown-timeout mac-locking macsec management
    mcast mcm mcmgr memory memorycard meter mirror mlag mld modify mrp msdp msgsrv msrp mstp mv mvr
    mvrp neighbor-discovery netlogin nettools network-clock nodealias ntp orchestration ospf ospfv3
    otm packet performance pim poe policy ports power printk private-vlan process protocol
    provisioning put pwmib q qosprofile qosscheduler quit radius radius-accounting refresh rip ripng
    rmon router-discovery rtmgr run save screen script security session set sflow sharing show slot
    slot-poll-interval slpp snmp snmpmaster snmpv3 sntp-client source ssh2 sshd2 ssl stacking
    stacking-support stm stp stpd switch sys-health-check sys-recovery-level syslog system tacacs
    tech-support telnet telnetd tftpd throw thttpd time trusted-servers tunnel twamp udp-echo-server
    udp-profile unconfigure update upload upm usleep validate var version vid virtual-network
    virtual-router vlan vm vm-tracking vman vpex vr vrrp vsm watchdog web wred wredprofile xml-mode
    xml-notification xml-test xmlc xmld xx_force_synchronize xx_synchronize xx_synchronize2
""".split())


def validate_vlan_name(name: str) -> None:
    if name.casefold() in RESERVED_VLAN_NAMES:
        raise Rejected(["VLAN name %r is a reserved ExtremeXOS keyword" % name],
                       reason_codes=["vlan_name_reserved"])


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []
        # The IP lines outside the profile also appear in unsupported and prevent L3 changes and deletion.
        self.l3_unsupported = []


class Snapshot:
    def __init__(self, text: str, firmware: str | None):
        if not firmware:
            raise Rejected(["an ExtremeXOS configuration does not name its firmware; the caller must state it"])
        self.firmware = firmware
        self.acl_file_observation = text.split("\n", 1)[0]
        self.inventory = None
        try:
            self.configuration = l1_exos.parse(text)
        except l1_exos.ParseError as exc:
            raise SnapshotRejected(["snapshot does not parse: %s" % exc], SNAPSHOT_UNREADABLE) from None
        if "vlan" not in self.configuration.modules:
            raise SnapshotRejected(["snapshot holds no vlan module; it is not a complete configuration"],
                                   SNAPSHOT_INCOMPLETE)
        self.commands = _without_safeguards(self.configuration.commands)
        self.vlans = {}
        for command in self.commands:
            if command.starts_with("create", "vlan") and len(command.tokens) >= 3:
                entry = self.vlans.setdefault(command.tokens[2], Entry(command.tokens[2]))
                if len(command.tokens) != 3:
                    entry.unsupported.append("line %d: create options" % command.line)
        self.ports, self.port_lists, self.inline_power = {}, [], {}
        for command in self.commands:
            if _is_port_disabled(command) or _is_poe_disabled(command):
                port = command.tokens[-1]
                table = self.ports if _is_port_disabled(command) else self.inline_power
                if not membership.PORT_NUMBER.fullmatch(port):
                    # a list disables several ports in one line: only the ports it names are refused
                    try:
                        listed = membership.ports(port)
                    except Exception:
                        self.port_lists.append("line %d" % command.line)
                        continue
                    for member in listed:
                        table.setdefault(member, Entry(member)).unsupported.append(
                            "line %d: %s on a port list" % (command.line, " ".join(command.tokens[:-1])))
                    continue
                entry = table.setdefault(port, Entry(port))
                if "admin-state" in entry.attributes:
                    entry.unsupported.append("line %d: repeated admin-state" % command.line)
                entry.attributes["admin-state"] = "disabled"
        for command in self.commands:
            if _is_port_text(command):
                port = command.tokens[2]
                if not membership.PORT_NUMBER.fullmatch(port):
                    self.port_lists.append("line %d" % command.line)
                    continue
                entry = self.ports.setdefault(port, Entry(port))
                name = command.tokens[3]
                if name in entry.attributes:
                    entry.unsupported.append("line %d: repeated %s" % (command.line, name))
                entry.attributes[name] = " ".join(command.tokens[4:])
        for command in self.commands:
            owner = self._owner(command)
            if owner is not None:
                entry, name, value = owner
                if name in entry.attributes:
                    entry.unsupported.append("line %d: repeated %s" % (command.line, name))
                entry.attributes[name] = value
        parse_l3(self)

    def _entry(self, name: str):
        folded = name.casefold()
        for key, entry in self.vlans.items():
            if key.casefold() == folded:
                return entry
        return None

    def _owner(self, command):
        tokens = command.tokens
        if len(tokens) == 5 and tokens[:2] == ("configure", "vlan") and tokens[3] in OWN_ATTRIBUTES:
            entry = self._entry(tokens[2])
            if entry is not None:
                return entry, tokens[3], tokens[4]
        return None

    def _is_own(self, command, key: str, l3=True) -> bool:
        folded = key.casefold()
        tokens = command.tokens
        if command.starts_with("create", "vlan") and len(tokens) >= 3 and tokens[2].casefold() == folded:
            return True
        owner = self._owner(command)
        if owner is not None and owner[0].name.casefold() == folded:
            return True
        # 1.0.12 G45: the IP lines of the VLAN (address, link-local, forwarding) belong to it (not for the G43
        # rename digest: there they are references followed under the new name, as before G45)
        owned = l3_owner(command) if l3 else None
        return owned is not None and owned[0].casefold() == folded

    def owns_vlan_l3(self, key: str) -> bool:
        """Keep all IP lines of a VLAN with unsupported L3 in the retained configuration."""
        entry = self.vlans.get(key)
        return entry is None or not entry.l3_unsupported

    def _mentions(self, command, key: str) -> bool:
        folded = key.casefold()
        tokens = command.tokens if folded in KEYWORDS else _named_tokens(command)
        return any(token.casefold() == folded for token in tokens)

    def entries(self, table: str):
        if table == exos_acl.POLICY:
            return exos_acl.file_entries(self.acl_file_observation, Entry)
        if table == exos_acl.BINDING:
            return exos_acl.binding_entries(self, Entry)
        if table in DHCP_TABLES:
            return dhcp_entries(self, table)
        if table in exos_services.TABLES:
            return exos_services.entries(self, table, Entry)
        if table in exos_g46.TABLES:
            return exos_g46.entries(self, table, Entry)
        if table in exos_g44.TABLES:
            return exos_g44.entries(self, table, Entry)
        if table == "vlan-membership":
            result = {}
            for port, attrs in membership.states(self).items():
                entry = Entry(port)
                entry.attributes = attrs
                result[port] = entry
            return result
        if table in PORT_TABLES:
            if self.port_lists:
                raise Rejected(["port settings (display string, disabled port or inline power) are set on port lists"
                                " (%s); they cannot be evaluated per port" % ", ".join(self.port_lists)])
            if table == BOUNCE_TABLE:
                result = {}
                for key, port in self.ports.items():
                    entry = result[key] = Entry(key)
                    entry.unsupported = port.unsupported
                    if "admin-state" in port.attributes:
                        entry.attributes["admin-state"] = port.attributes["admin-state"]
                return result
            return dict(self.inline_power if table == "inline-power" else self.ports)
        if table == ROUTE_TABLE:
            return routes(self)
        if table == VRRP_TABLE:
            return vrrps(self)
        if table != "vlan":
            return None
        return dict(self.vlans)

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        if table in ("ports", "vlan-membership", "inline-power") or table in STATE_TABLES:
            return []
        return sorted(
            "line %d (module %s)" % (command.line, command.module or "-")
            for command in self.commands
            if self._mentions(command, key) and not self._is_own(command, key)
        )

    def in_use(self, key: str) -> bool:
        return any(self._mentions(command, key) for command in self.commands)

    def tags(self) -> set:
        return {entry.attributes["tag"] for entry in self.vlans.values() if "tag" in entry.attributes}

    def rest_digest(self, table: str, key: str, safeguard_id=None, port_description=True, *,
                    scope=(), expected=None, require_default=True) -> str:
        commands = tuple(command for command in _without_safeguards(self.configuration.commands, safeguard_id=safeguard_id)
                         if not _default_recovery(command))
        if table in exos_services.TABLES:
            return exos_services.rest_digest(table, key, commands)
        if table in exos_acl.TABLES:
            kept = (command.text for command in commands
                    if table == exos_acl.POLICY or not exos_acl.owns_binding(command, key))
            return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()
        if table in exos_g44.TABLES:
            return exos_g44.rest_digest(self, table, key, commands, scope, expected, require_default)
        if table == "vlan-membership":
            return membership.rest_digest(self, key, commands)
        if table == "inline-power":
            lines = [command.text for command in commands if not port_owned(command, table, key)]
            return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        if table in ("ports", BOUNCE_TABLE):
            kept = tuple(command for command in commands if not port_owned(command, table, key)
                         or (not port_description and command.tokens[3:4] == ("description-string",)))
            if self.inventory is not None:
                return membership.rest_digest(self, None, kept)
            lines = [command.text for command in kept]
        elif table in DHCP_TABLES:
            lines = [command.text for command in commands if not dhcp_owned(command, table, key)]
        elif table in STATE_TABLES:
            owned = route_owned if table == ROUTE_TABLE else vrrp_owned
            lines = [command.text for command in commands if not owned(command, key)]
        elif table in exos_g46.TABLES:
            exos_g46.require_module(self, table, key)
            lines = [command.text for command in commands if not exos_g46.owns(command, table, key)]
        else:
            owns_l3 = self.owns_vlan_l3(key)
            lines = [command.text for command in commands if not self._is_own(command, key, l3=owns_l3)]
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _named_tokens(command) -> tuple:
    folded = tuple(token.casefold() for token in command.tokens)
    if folded[1:2] and folded[1] in SECRET_SUBJECTS:
        return ()
    kept = []
    for index, token in enumerate(command.tokens):
        if folded[index] in FREE_TEXT:
            break
        if index == 0 or folded[index - 1] not in SECRET_WORDS:
            kept.append(token)
    return tuple(kept)


def _without_safeguards(commands, safeguard_id=True) -> tuple:
    names = set(safeguard_names(safeguard_id).values()) if isinstance(safeguard_id, str) else set()
    def own(name):
        return bool(SAFEGUARD_NAME.fullmatch(name)) if safeguard_id is True else name in names
    kept, inside = [], False
    for command in commands:
        tokens = command.tokens
        if inside:
            inside = command.text.strip() != "."
            continue
        if command.module == "upm" and tokens[:3] == ("create", "upm", "profile") and len(tokens) == 4 \
                and own(tokens[3]):
            inside = True
            continue
        if command.module == "upm" and len(tokens) >= 4 and tokens[1:3] == ("upm", "timer") \
                and own(tokens[3]):
            continue
        kept.append(command)
    return tuple(kept)


def _default_recovery(command) -> bool:
    return tuple(token.casefold() for token in command.tokens) == DEFAULT_RECOVERY


def _is_port_text(command) -> bool:
    tokens = command.tokens
    return len(tokens) >= 5 and tokens[:2] == ("configure", "ports") and tokens[3] in PORT_TEXT


def _is_port_disabled(command) -> bool:
    # show configuration prints a disabled port as "disable port N" (singular) in module vlan, whatever the
    # spelling of the command was (measured on 33.7.1.6-patch1-11, X435-8P-4S and X440-G2-12p-10G4)
    return len(command.tokens) == 3 and command.tokens[:2] == ("disable", "port") and command.module == "vlan"


def _is_poe_disabled(command) -> bool:
    # "disable inline-power ports N" keeps its plural spelling and sits in module poe (same measurement)
    return (len(command.tokens) == 4 and command.tokens[:3] == ("disable", "inline-power", "ports")
            and command.module == "poe")


def port_owned(command, table: str, key: str) -> bool:
    """The configuration line belongs to the per-port object of the table (display string or admin state)."""
    if table == "inline-power":
        return _is_poe_disabled(command) and command.tokens[3] == key
    return command.tokens[2:3] == (key,) and (
        _is_port_disabled(command) or (table == "ports" and _is_port_text(command))
    )


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def port_order(port: str) -> tuple:
    return tuple(int(part) for part in port.split(":"))


def absent(snapshot, table: str, key: str) -> list:
    if table == "vlan-membership":
        if key in membership.lag_ports(snapshot):
            return [membership.LAG_REFUSAL]
        if snapshot.inventory is not None:
            if key not in snapshot.inventory:
                return ["port %s is not reported by the switch" % key]
            return [membership.NATIVE_REFUSAL]
    return ["object %r does not exist" % key]


def _text(value: str, spaces=True) -> str:
    if '"' in value or "\\" in value or CONTROL.search(value) or (not spaces and any(c.isspace() for c in value)):
        raise Rejected(["the value %r cannot be written safely: quotes, backslashes and control characters"
                        " are not supported" % value])
    return value


def render_create(profile, key: str, attributes: dict) -> list:
    if profile.table == exos_acl.POLICY:
        return exos_acl.render_file(key, attributes)
    if profile.table == exos_acl.BINDING:
        return exos_acl.render_binding(key, attributes)
    if profile.table in STATE_TABLES or profile.table in exos_g44.TABLES:
        return []           # 1.0.12 G45: rendered from the whole states by render_state
    lines = ["create vlan %s tag %s" % (key, attributes["tag"])]
    if "description" in attributes:
        lines.append('configure vlan %s description "%s"' % (key, _text(attributes["description"])))
    return lines


ADMIN_STATES = ("enabled", "disabled")


def _admin_state(prefix: str, key: str, value: str) -> str:
    if value not in ADMIN_STATES:
        raise Rejected(["admin-state must be enabled or disabled"])
    return "%s %s %s" % ("disable" if value == "disabled" else "enable", prefix, key)


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    if profile.table == exos_acl.POLICY:
        return exos_acl.render_file(key, assign)
    if profile.table in ("vlan-membership", *STATE_TABLES, *exos_g44.TABLES, *DHCP_TABLES):
        return []
    if profile.table == "inline-power":
        lines = [_admin_state("inline-power ports", key, value) for name, value in assign.items()]
        return lines + [_admin_state("inline-power ports", key, "enabled") for _name in remove]
    if profile.table in ("ports", BOUNCE_TABLE):
        lines = []
        for name, value in assign.items():
            if name == "admin-state":
                lines.append(_admin_state("ports", key, value))
            elif name == "description-string":
                lines.append('configure ports %s description-string "%s"' % (key, _text(value)))
            else:
                lines.append("configure ports %s display-string %s" % (key, _text(value, spaces=False)))
        for name in remove:
            lines.append(_admin_state("ports", key, "enabled") if name == "admin-state"
                         else "unconfigure ports %s %s" % (key, name))
        return lines
    lines = []
    if "description" in assign:
        lines.append('configure vlan %s description "%s"' % (key, _text(assign["description"])))
    if "description" in remove:
        lines.append("unconfigure vlan %s description" % key)
    return lines


def render_delete(profile, key: str) -> list:
    if profile.table == exos_acl.POLICY:
        return exos_acl.render_file(key, None)
    if profile.table == exos_acl.BINDING:
        return exos_acl.render_binding(key, None)
    if profile.table in STATE_TABLES or profile.table in exos_g44.TABLES:
        return []
    return ["delete vlan %s" % key]


def prechecks(snapshot, profile, op: str, key: str, after, endpoint_impact=False) -> list:
    if profile.table in exos_acl.TABLES:
        return []
    if profile.table in PORT_TABLES and snapshot.inventory is not None and key not in snapshot.inventory:
        return ["port %s is not reported by the switch" % key]
    if profile.table in PORT_TABLES:
        port_state_prechecks(snapshot, profile, key, after, endpoint_impact)
    if profile.table == "vlan-membership":
        return membership.prechecks(snapshot, key, membership.states(snapshot).get(key, {}), after)
    if op == "create" and after is not None and after.get("tag") in snapshot.tags():
        return ["tag %s is already used by another VLAN" % after["tag"]]
    return []


# Data port operations cover the physical switch and the EXOS-VM. PoE measurements require a physical switch.
# Firmware outside these measurements gets the G00 firmware_support warning.
PORT_ACTION_FIRMWARE = ("33.7.1.6", "33.6.1.14")


def port_action_support(firmware, table: str) -> dict:
    poe = table == "inline-power"
    return tested.support("ExtremeXOS", firmware, ("33.7.1.6",) if poe else PORT_ACTION_FIRMWARE,
                          function="per-port inline power" if poe else "the port admin state")


def touches_admin_state(snapshot, table: str, key: str, after) -> bool:
    entries = snapshot.inline_power if table == "inline-power" else snapshot.ports
    before = entries.get(key).attributes if key in entries else {}
    return (after or {}).get("admin-state", "enabled") != before.get("admin-state", "enabled")


def port_state_prechecks(snapshot, profile, key: str, after, endpoint_impact=False) -> None:
    if not touches_admin_state(snapshot, profile.table, key, after):
        return
    if profile.table == "inline-power":
        return
    # the port checks apply to the admin state in both directions: enabling a disabled uplink or LAG member can
    # bring back a loop just as disabling it cuts traffic
    if not vlan_module_closed(snapshot):
        raise Rejected(["the configuration ends inside its vlan module; VLAN and link aggregation membership of port %s "
                        "cannot be read completely" % key], reason_codes=["port_usage_unreadable"])
    if key in membership.lag_ports(snapshot) and not endpoint_impact:
        raise Rejected(["port %s belongs to a link aggregation; changing its admin state is refused" % key],
                       reason_codes=["port_lag_member"])
    _vlans, members, _descriptions = membership.model(snapshot)
    tagged = sorted(members.get(key, {}).get("tagged", ()))
    if tagged and not endpoint_impact:
        raise Rejected(["port %s carries tagged VLANs (%d); a trunk is treated as an uplink and its admin state is not changed"
                        % (key, len(tagged))], reason_codes=["port_uplink"])


def vlan_module_closed(snapshot) -> bool:
    """VLAN membership and link aggregation are read from the vlan module of show configuration; it is complete
    only when the switch printed another module after it (a dump cut off inside the vlan module is not)."""
    modules = list(snapshot.configuration.modules)
    return "vlan" in modules and modules.index("vlan") < len(modules) - 1


def management_vlan_member(snapshot, key: str, names) -> bool:
    folded = {name.casefold() for name in names or ()}
    if not folded:
        return False
    _vlans, members, _descriptions = membership.model(snapshot)
    modes = members.get(key, {})
    return any(name.casefold() in folded for mode in modes.values() for name in mode)


QUERY_LLDP = "show lldp neighbors"
QUERY_FDB = "show fdb"
LLDP_HEADER = re.compile(r"^Port\s+Chassis ID\s+Port ID\s+TTL\s+Age\s+System Name\s*$", re.MULTILINE)
# 501-r3: EXOS-VM 33.6.1.14 lists the neighbors of the management port as `mgmt` (measured on d-exos)
LLDP_ROW = re.compile(r"^([1-9][0-9]*(?::[1-9][0-9]*)?|mgmt)\s+\S", re.MULTILINE)
FDB_HEADER = re.compile(r"^MAC\s+VLAN Name\( Tag\)\s+Age\s+Flags\s+Port / Virtual Port List\s*$", re.MULTILINE)
FDB_ROW = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}[^\S\n]+\S+\(\d{4}\)[^\S\n]+\d+[^\S\n]+"
                     r"(?:[A-Za-z][^\S\n]+)*?([0-9][0-9:,-]*(?:,[^\S\n]*[0-9][0-9:,-]*)*)[^\S\n]*$", re.MULTILINE)
FDB_TOTAL = re.compile(r"^Total:\s+(\d+)\s", re.MULTILINE)


LLDP_SEPARATOR = re.compile(r"^={3,}$")
LLDP_NOTE = "NOTE: The Chassis ID and/or Port ID might be truncated to fit the screen."


def _lldp_unreadable(reason: str):
    return Rejected(["the LLDP neighbor list %s" % reason], reason_codes=["port_usage_unreadable"])


def lldp_ports(text: str) -> set:
    """Ports with an LLDP neighbor in show lldp neighbors; an unrecognised or incomplete answer is refused.

    The list counts as complete only in the measured layout (33.7.1.6, X435 and X440): the header, a separator,
    the rows, the closing separator and the closing NOTE line. A list cut off anywhere before the NOTE, even
    after valid rows, is refused instead of being read as "no neighbor"."""
    header = LLDP_HEADER.search(text)
    if header is None:
        raise _lldp_unreadable("is not recognised")
    lines = [line.rstrip() for line in text[header.end():].splitlines()]
    lines = [line for line in lines if line.strip()]
    if not lines or not LLDP_SEPARATOR.match(lines[0]):
        raise _lldp_unreadable("has no separator under the header")
    closing = next((index for index in range(1, len(lines)) if LLDP_SEPARATOR.match(lines[index])), None)
    if closing is None:
        raise _lldp_unreadable("is cut off (no closing separator)")
    trailer = lines[closing + 1:]
    if trailer != [LLDP_NOTE]:
        raise _lldp_unreadable("is cut off or ends in an unknown way (no closing NOTE line)")
    found = set()
    for line in lines[1:closing]:
        match = LLDP_ROW.match(line)
        if match is None:
            raise _lldp_unreadable("holds a row that is not recognised")
        found.add(match.group(1))
    return found


FDB_SEPARATOR = re.compile(r"^-{3,}\s*$", re.MULTILINE)


def fdb_ports(text: str) -> set:
    """Ports with learned MAC addresses in show fdb; the list is complete only with its separator under the header
    and the closing Total line after the last row, and the row count must equal that Total."""
    header = FDB_HEADER.search(text)
    if header is None:
        raise Rejected(["the forwarding database is not recognised"], reason_codes=["port_usage_unreadable"])
    separator = FDB_SEPARATOR.search(text, header.end())
    if separator is not None and text[header.end():separator.start()].strip():
        separator = None
    total = FDB_TOTAL.search(text)
    rows = list(FDB_ROW.finditer(text))
    if separator is None or total is None or int(total.group(1)) != len(rows) \
            or any(row.start() < separator.end() or row.end() > total.start() for row in rows):
        raise Rejected(["the forwarding database is incomplete"], reason_codes=["port_usage_unreadable"])
    found = set()
    for row in rows:
        try:
            found |= membership.ports(row.group(1).replace(" ", ""))
        except Exception:
            raise Rejected(["the forwarding database names a port list that is not recognised"],
                           reason_codes=["port_usage_unreadable"]) from None
    return found


PORT_STATES = {"E": "enabled", "D": "disabled", "F": "disabled by link-flap detection", "L": "disabled by licensing"}
LINK_STATES = {"A": "active", "R": "ready", "NP": "not present", "L": "loopback"}


def port_configuration(text: str, key: str):
    """Port State and Link State of show ports N configuration no-refresh, or None when not recognised."""
    if "Port Configuration" not in text:
        return None
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == key and words[2] in PORT_STATES:
            return {"port_state": PORT_STATES[words[2]], "link_state": LINK_STATES.get(words[3], words[3])}
    return None


SAFEGUARD_PREFIX = "netops"
SAFEGUARD_NAME = re.compile(r"^netops[0-9a-f]{6}[pt]$")
ERROR_PREFIXES = ("%%", "Error:", "ERROR:")
QUERY_SWITCH = "show switch"
QUERY_VERSION = "show version"
QUERY_PROFILES = "show upm profile"
QUERY_TIMERS = "show upm timers"
QUERY_PORTS = "show ports no-refresh"
PORT_ROW = re.compile(r"^([1-9][0-9]*(?::[1-9][0-9]*)?)\s", re.MULTILINE)
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SWITCH_CLOCK_FORMAT = "%a %b %d %H:%M:%S %Y"
SWITCH_TIME = re.compile(r"^Current Time:\s+(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s*$", re.MULTILINE)
SYSNAME = re.compile(r"^SysName:\s+(\S+)\s*$", re.MULTILINE)
IMAGE_VERSION = re.compile(r"^Image\s*:\s*ExtremeXOS version (\S+)", re.MULTILINE)
TIMER_ROW = re.compile(r"^(\S+)\s+(\S+)\s+([edop]+)(?:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?\s*$", re.MULTILINE)
UPM_SEPARATOR = re.compile(r"\s*(?:={3,}|-{3,})\s*")
PROFILE_BEGIN = "Profile Contents Begin"
PROFILE_END = "Profile Contents Ends"


def cli_error(text: str):
    for line in text.splitlines()[1:]:
        stripped = line.strip()
        if stripped.startswith(ERROR_PREFIXES):
            return stripped[:80]
    return None


CLEAR_TABLES = ("port-counters", "fdb", "iparp", "neighbor-discovery")
CLEAR_FIRMWARE = ("33.6.1.14",)
CLEAR_MAC = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
CLEAR_PORT = r"[1-9][0-9]{0,2}(?::[1-9][0-9]{0,2})?"
CLEAR_VLAN = r"[A-Za-z][A-Za-z0-9_-]{0,31}"
CLEAR_COUNTER_NAMES = ("tx_packets", "tx_bytes", "rx_packets", "rx_bytes", "rx_broadcast", "rx_multicast",
                       "tx_broadcast", "tx_multicast")


@dataclass(frozen=True)
class ClearTarget:
    key: str
    scope: str
    value: str
    read: str
    write: str
    vr: str | None = None


def clear_target(table: str, key: str, changes: dict) -> ClearTarget:
    """Render only the documented EXOS selectors, each with an explicit target."""
    if table == "port-counters" and not changes and re.fullmatch(CLEAR_PORT, key):
        return ClearTarget(key, "port", key, f"show ports {key} statistics no-refresh wide",
                           f"clear counters ports {key}")
    if table == "fdb" and not changes:
        if re.fullmatch(CLEAR_MAC, key):
            value = key.lower()
            return ClearTarget(value, "mac", value, f"show fdb {value}", f"clear fdb {value}")
        scope, _, value = key.partition(":")
        if scope == "port" and re.fullmatch(CLEAR_PORT, value):
            return ClearTarget(key, scope, value, f"show fdb ports {value}", f"clear fdb ports {value}")
        if scope == "vlan" and value.casefold() != "all" and re.fullmatch(CLEAR_VLAN, value):
            validate_vlan_name(value)
            return ClearTarget(key, scope, value, f"show fdb vlan {value}", f"clear fdb vlan {value}")
    if table in ("iparp", "neighbor-discovery") and set(changes) <= {"vr"}:
        version = 4 if table == "iparp" else 6
        vr = changes.get("vr", "VR-Default")
        if not isinstance(vr, str) or vr.casefold() == "all" or not VR_NAME.fullmatch(vr) or "%" in key:
            raise Rejected(["clear requires one plain IP address and an optional VR name"])
        try:
            ip = ipaddress.ip_address(key)
        except ValueError:
            raise Rejected(["clear requires one plain IPv%d address" % version]) from None
        if ip.version == version and not ip.is_unspecified and not ip.is_multicast:
            subject = "iparp" if version == 4 else "neighbor-discovery cache ipv6"
            selector = f"{subject} {ip} vr {vr}"
            return ClearTarget(str(ip), "ip", str(ip), f"show {selector}", f"clear {selector}", vr)
    raise Rejected(["clear requires one port, MAC, FDB port:<port> or vlan:<name>, or address of the table's family"])


def _clear_unreadable():
    return Rejected(["the scoped ExtremeXOS readback is incomplete or unrecognised"],
                    reason_codes=["clear_readback_unreadable"])


def clear_observation(table: str, target: ClearTarget, text: str) -> dict:
    if any(line.strip().startswith(ERROR_PREFIXES) for line in text.splitlines()):
        raise _clear_unreadable()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if table == "port-counters":
        return _clear_port_counters(lines, target.value)
    entries = _clear_fdb(lines, target) if table == "fdb" else _clear_neighbors(lines, target, table == "iparp")
    return {"scope": target.scope, "target": target.value, "vr": target.vr,
            "entries": sorted(entries, key=lambda entry: tuple(entry.values()))}


def _clear_port_counters(lines, port: str) -> dict:
    if (len(lines) < 6 or lines[0].split() != "Port Link Tx Pkt Tx Byte Rx Pkt Rx Byte Rx Pkt Rx Pkt Tx Pkt Tx Pkt".split()
            or lines[1].split() != "State Count Count Count Count Bcast Mcast Bcast Mcast".split()
            or any(not re.fullmatch(r"=+(?: +=+){9}", lines[index]) for index in (2, 4))
            or not lines[-1].startswith("Link State:")):
        raise _clear_unreadable()
    columns = lines[3].split()
    if (len(columns) != 10 or columns[0] != port or columns[1] not in ("A", "R", "L", "D", "d", "B")
            or any(not re.fullmatch(r"[0-9]+", field) for field in columns[2:])):
        raise _clear_unreadable()
    return {"port": port, "link": columns[1],
            "counters": dict(zip(CLEAR_COUNTER_NAMES, map(int, columns[2:])))}


def _clear_fdb(lines, target: ClearTarget) -> list:
    if (len(lines) < 5 or not FDB_HEADER.fullmatch(lines[0]) or not re.fullmatch(r"-{3,}", lines[1])
            or not FDB_TOTAL.match(lines[-2]) or not re.fullmatch(r"FDB Aging time: \d+", lines[-1])):
        raise _clear_unreadable()
    legend = next((i for i, line in enumerate(lines) if line.startswith("Flags :")), len(lines))
    if not 2 <= legend < len(lines) - 2:
        raise _clear_unreadable()
    entries = []
    for line in lines[2:legend]:
        row = re.fullmatch(rf"({CLEAR_MAC})\s+(\S+)\(\d{{4}}\)\s+\d+\s+((?:[A-Za-z]+\s+)+)(\S+(?:,\s*\S+)*)", line)
        if row is None:
            raise _clear_unreadable()
        mac, vlan, flags, port = row.groups()
        match = {"mac": mac, "vlan": vlan, "port": port}[target.scope]
        if match.casefold() != target.value.casefold():
            raise _clear_unreadable()
        entries.append({"mac": mac.lower(), "vlan": vlan, "port": port, "dynamic": "d" in flags})
    return entries


def _clear_neighbors(lines, target: ClearTarget, ipv4: bool) -> list:
    header = "VR Destination Mac Age Static VLAN VID Port".split()
    if ipv4:
        header_size, footer, last = 1, "Dynamic Entries", "Max Proxy Entries"
    else:
        header_size, footer, last = 2, "Total Entries", "Max Pending Entries"
    columns = " ".join(lines[:header_size]).split()
    summary = next((i for i, line in enumerate(lines) if line.startswith(footer)), len(lines))
    if (columns != header or not header_size <= summary < len(lines) - 1
            or not re.fullmatch(rf"{last}\s*:\s*\d+", lines[-1])):
        raise _clear_unreadable()
    rows = lines[header_size:summary]
    if not ipv4:
        if len(rows) % 2:
            raise _clear_unreadable()
        rows = [ip + " " + details for ip, details in zip(rows[::2], rows[1::2])]
    entries = []
    for line in rows:
        row = re.fullmatch(rf"(\S+)\s+(\S+)\s+({CLEAR_MAC}|-+|\(?[Ii]ncomplete\)?)\s+\d+\s+(YES|NO)"
                           r"\s+(\S+)\s+\d+(?:\s+(\S+))?", line)
        if row is None:
            raise _clear_unreadable()
        vr, address, mac, static, vlan, port = row.groups()
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise _clear_unreadable() from None
        if vr.casefold() != target.vr.casefold() or address != target.value:
            raise _clear_unreadable()
        entries.append({"mac": mac.lower(), "vlan": vlan, "port": port or "",
                        "dynamic": static == "NO" and bool(re.fullmatch(CLEAR_MAC, mac))})
    return entries


def safeguard_names(change_id: str) -> dict:
    base = SAFEGUARD_PREFIX + change_id[:6]
    return {"profile": base + "p", "timer": base + "t"}


EXPANDED = "$("
EXPANDED_REFUSAL = "text with $( cannot be restored as a literal value by the timed safeguard"


def safeguard_script(inverse):
    if any(EXPANDED in line for line in inverse):
        raise Rejected([EXPANDED_REFUSAL])
    return ["configure cli mode persistent", "configure cli mode scripting ignore-error"] + [line.strip() for line in inverse]


def render_safeguard(change_id: str, inverse: list, seconds: int) -> list:
    names = safeguard_names(change_id)
    steps = [("ask", "create upm profile %s" % names["profile"], b"Start typing")]
    steps.extend(("raw", line) for line in safeguard_script(inverse))
    steps.extend((
        ".",
        "create upm timer %s" % names["timer"],
        "configure upm timer %s profile %s" % (names["timer"], names["profile"]),
        "configure upm timer %s after %d" % (names["timer"], seconds),
    ))
    return steps


def render_safeguard_removal(change_id: str) -> list:
    names = safeguard_names(change_id)
    return ["delete upm timer %s" % names["timer"], "delete upm profile %s" % names["profile"]]


def profile_contents(text: str):
    if PROFILE_BEGIN not in text or PROFILE_END not in text:
        return None
    body = text.split(PROFILE_BEGIN, 1)[1].split(PROFILE_END, 1)[0]
    return [line.strip() for line in body.splitlines() if line.strip() and not set(line.strip()) <= {"*"}]


def timer_row(text: str, timer: str):
    for match in TIMER_ROW.finditer(text):
        if match.group(1) == timer:
            return {"profile": match.group(2), "flags": match.group(3), "next": match.group(4)}
    return None


def upm_listing_complete(text: str, kind: str) -> bool:
    count = re.search(r"^[^\S\n]*Number of UPM %s:\s*(\d{1,9})\s*$" % kind, text, re.MULTILINE)
    if count is None:
        return False
    lines = text.splitlines()
    separators = [index for index, line in enumerate(lines) if UPM_SEPARATOR.fullmatch(line)]
    rows = [line for line in lines[separators[1] + 1:separators[2]] if line.strip()] if len(separators) >= 3 else []
    declared = int(count.group(1))
    return not rows if declared == 0 else len(rows) >= declared


def listed_names(text: str) -> list:
    names = []
    for line in text.splitlines():
        words = line.split()
        if words and words[0].startswith(SAFEGUARD_PREFIX):
            names.append(words[0])
    return names


def switch_field(pattern, text: str, label: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise Rejected(["the switch does not report its %s" % label])
    return " ".join(match.group(1).split())


ACCOUNT_COMMANDS = (("create", "account"), ("configure", "account"), ("create", "sshd2"), ("configure", "sshd2"))


def account_fingerprint(snapshot) -> str:
    lines = sorted(command.text.strip() for command in snapshot.commands if command.tokens[:2] in ACCOUNT_COMMANDS)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def accounts(snapshot) -> list:
    names = set()
    for command in snapshot.commands:
        tokens = command.tokens
        if tokens[:2] == ("create", "account") and len(tokens) >= 4:
            names.add(tokens[3])
        elif tokens[:2] == ("configure", "account") and len(tokens) >= 3:
            names.add(tokens[2])
    return sorted(names)


VLAN_HEADER = re.compile(r"^VLAN Interface with name (\S+) created", re.MULTILINE)
VLAN_TAG = re.compile(r"802\.1Q Tag (\d+)")
VLAN_DESCRIPTION = re.compile(r"^[^\S\n]*Description:\s*(.*)$", re.MULTILINE)
VLAN_ABSENT = "Invalid numeric list"
NO_DESCRIPTION = "None"


def shown_vlan(text: str, key: str, strict_l3=False, include_l3=True):
    header = VLAN_HEADER.search(text)
    if header is None:
        if VLAN_ABSENT in text:
            return None
        raise Rejected(["the check account answer about VLAN %s is not recognised" % key])
    if header.group(1) != key:
        raise Rejected(["the check account answer names another VLAN"])
    attributes = {}
    tag = VLAN_TAG.search(text)
    if tag is not None:
        attributes["tag"] = tag.group(1)
    description = VLAN_DESCRIPTION.search(text)
    if description is not None and description.group(1).rstrip() != NO_DESCRIPTION:
        attributes["description"] = description.group(1).rstrip()
    if include_l3:
        attributes.update(shown_l3(text, strict=strict_l3))     # 1.0.12 G45
    return attributes


QUERY_SESSIONS = "show session"
SESSION_ROW = re.compile(r"^[^\S\n]*(\*?)\d+\s+\w{3} \w{3} +\d", re.MULTILINE)


def foreign_sessions(text: str) -> int:
    rows = SESSION_ROW.findall(text)
    if not rows:
        raise Rejected(["the session list is not readable"])
    return sum(1 for marker in rows if marker != "*")


PORT_HEADER = re.compile(r"^Port:[^\S\n]+(" + membership.PORT_NUMBER.pattern + r")(?:\(([^\n]*)\))?:?[^\S\n]*$", re.MULTILINE)
PORT_ABSENT = "Invalid port number"
ADMIN_STATE_LINE = re.compile(r"^[^\S\n]*Admin state:\s+(Enabled|Disabled)\b", re.MULTILINE)
PORT_DESCRIPTION = re.compile(r"^[^\S\n]*Description String:[^\S\n]*(.+)$", re.MULTILINE | re.IGNORECASE)
PORT_DETAIL_END = re.compile(r"^[^\S\n]*Static MAC-based VLANs:", re.MULTILINE)


def shown_port(text: str, key: str, admin_state=False, description=False):
    header = PORT_HEADER.search(text)
    if header is None:
        if PORT_ABSENT in text:
            return None
        raise Rejected(["the check account answer about port %s is not recognised" % key])
    if header.group(1) != key:
        raise Rejected(["the check account answer names another port"])
    attributes = {"display-string": header.group(2)} if header.group(2) else {}
    if description:
        names = PORT_DESCRIPTION.findall(text)
        if len(names) > 1 or not PORT_DETAIL_END.search(text):
            raise Rejected(["the port description readback is incomplete or ambiguous"],
                           reason_codes=["port_usage_unreadable"])
        if names:
            value = names[0].rstrip()
            if len(value) < 3 or not (value.startswith('"') and value.endswith('"')):
                raise Rejected(["the port description readback does not show a complete quoted value"],
                               reason_codes=["port_usage_unreadable"])
            attributes["description-string"] = value[1:-1]
    state = ADMIN_STATE_LINE.findall(text)
    if admin_state and len(state) != 1:
        raise Rejected(["the check account answer about port %s shows no admin state" % key])
    if state and state[0] == "Disabled":
        attributes["admin-state"] = "disabled"
    return attributes


POE_NOT_CAPABLE = re.compile(r"\bPort (\S+) is not inline-power capable\b")
POE_INFO_HEADER = re.compile(r"^Port\s+State\s+Class\s+Volts\s+Curr\s+Power\s+Fault\s*$", re.MULTILINE)
POE_DETAIL = {
    "configured": re.compile(r"^Configured Admin State:\s*(enabled|disabled)\s*$", re.MULTILINE),
    "state": re.compile(r"^Inline Power State\s*:\s*(\S+)\s*$", re.MULTILINE),
    "class": re.compile(r"^PD Class\s*:[^\S\n]*(\S*)\s*$", re.MULTILINE),
    "power": re.compile(r"^Measured Power\s*:\s*([0-9.]+ W)\s*$", re.MULTILINE),
    "fault": re.compile(r"^Fault Status\s*:\s*(.*?)\s*$", re.MULTILINE),
}
POE_DETAIL_HEADER = re.compile(r"^Port (\S+)\s*$", re.MULTILINE)


class NotInlinePower(Rejected):
    pass


def poe_info(text: str, key: str) -> dict:
    """The row of port N in show inline-power info ports N (measured format), or a coded refusal."""
    refused = POE_NOT_CAPABLE.search(text)
    if refused is not None:
        if refused.group(1) != key:
            raise Rejected(["the inline-power answer names another port"], reason_codes=["poe_state_unreadable"])
        raise NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    if POE_INFO_HEADER.search(text) is None:
        raise Rejected(["the switch gives no inline-power table for port %s; the platform may have no PoE" % key],
                       reason_codes=["poe_unsupported"])
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 7 and words[0] == key:
            return {"state": words[1], "class": words[2], "power_watts": words[5], "fault": " ".join(words[6:])}
    raise Rejected(["the inline-power table holds no row for port %s" % key], reason_codes=["poe_state_unreadable"])


# measured (ref 171, X435 port 9 and X440 port 13): show inline-power info ports N on a port without PoE ends
# with exit status 250 and prints only this line
POE_NOT_CAPABLE_RC = 250


def poe_not_capable_answer(rc, text: str, key: str) -> bool:
    """True only for the measured refusal of a port without PoE: exit status 250 and the single line."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return rc == POE_NOT_CAPABLE_RC and lines == ["Port %s is not inline-power capable" % key]


def poe_detail(text: str, key: str) -> dict:
    """show inline-power info detail ports N: the configured admin state and the inline power state."""
    refused = POE_NOT_CAPABLE.search(text)
    if refused is not None and refused.group(1) == key:
        raise NotInlinePower(["port %s is not inline-power capable" % key], reason_codes=["poe_not_capable"])
    header = POE_DETAIL_HEADER.search(text)
    if header is None or header.group(1) != key:
        raise Rejected(["the inline-power detail of port %s is not recognised" % key],
                       reason_codes=["poe_state_unreadable"])
    found = {}
    for name, pattern in POE_DETAIL.items():
        values = pattern.findall(text)
        if len(values) != 1:
            if name in ("configured", "state"):
                raise Rejected(["the inline-power detail of port %s shows no %s" % (key, name)],
                               reason_codes=["poe_state_unreadable"])
            continue
        found[name] = values[0]
    return found


def switch_ports(text: str) -> list:
    found = set(PORT_ROW.findall(text)) if "Port Summary" in text else set()
    if not found:
        raise Rejected(["the port list of the switch is not recognised"])
    return sorted(found, key=port_order)

def vlan_absent_from_list(text, key):
    if not all(word in text for word in ("Name", "VID", "Protocol", "Ports", "Flags")):
        return False
    total = re.search(r"^Total number of VLAN\(s\) : (\d+)\s*$", text, re.MULTILINE)
    if total is None:
        return False
    rows = re.findall(r"^([A-Za-z][A-Za-z0-9_-]{0,31})\s+([0-9]{1,4})\s+.+$", text, re.MULTILINE)
    names = [name for name, _tag in rows]
    if len(names) != int(total[1]) or len(set(names)) != len(names):
        return False
    folded = key.casefold()
    return not any(name.casefold() == folded or (len(name) >= 15 and folded.startswith(name.casefold()))
                   for name in names)


# 1.0.12 G43 (X14, XP14): a VLAN is renamed with "configure vlan <old> name <new>" and a VLAN plan may carry the
# tagged and untagged ports of the VLAN, so a VLAN is created with its ports (or several ports are added and
# removed) in one plan with one preview, one safeguard and one compensating inverse. Measured on X440-G2-12p-10G4
# 33.7.1.6-patch1-11 (G43): the rename keeps the tag, the description and the port membership, and show
# configuration prints every reference with the new name; "configure vlan <X> add ports <P> untagged" moves the
# port from Default (auto-move); "delete vlan <X>" leaves its untagged ports without a native VLAN, so the
# inverse of a create and every removal of an untagged port returns the port to Default first.
RENAME = "name"
PORT_ATTRIBUTES = ("tagged-ports", "untagged-ports")
AUTO_MOVE_OFF = ("configure", "vlan", "untagged-ports", "auto-move", "off")
PLACEHOLDER = "\x00vlan"


def vlan_change(profile, op: str, changes: dict):
    """The G43 kind of a VLAN request: "rename", "ports" or None (an ordinary VLAN request)."""
    if profile.platform != "exos" or profile.table != "vlan":
        return None
    if RENAME in changes:
        if op != "update":
            raise Rejected(["a VLAN is named by its key; %s takes no name attribute" % op])
        if set(changes) != {RENAME}:
            raise Rejected(["a VLAN rename is a separate request: it changes only the name"])
        return "rename"
    if names_vlan_ports(changes):
        return "ports"
    return None


def names_vlan_ports(changes) -> bool:
    return any(name in changes for name in PORT_ATTRIBUTES)


def plan_kind(before, after):
    """The G43 kind of a stored plan, read from its predicted states."""
    sides = [state for state in (before, after) if state]
    if any(RENAME in state for state in sides):
        return "rename"
    if any(name in state for state in sides for name in PORT_ATTRIBUTES):
        return "ports"
    return None


def _port_list(value) -> list:
    ports = (value or "").split()
    if not all(membership.PORT_NUMBER.fullmatch(port) for port in ports):
        raise Rejected(["a VLAN port must be a single port number or slot:port"])
    return sorted(ports, key=port_order)


def _port_text(ports) -> str:
    return ",".join(sorted(ports, key=port_order))


def vlan_ports(snapshot, name: str) -> dict:
    """tagged-ports and untagged-ports of a VLAN from the membership lines of the snapshot (only when not empty)."""
    _vlans, members, _descriptions = membership.model(snapshot)
    folded = name.casefold()
    found = {"tagged-ports": set(), "untagged-ports": set()}
    for port, modes in members.items():
        for mode, attribute in (("tagged", "tagged-ports"), ("untagged", "untagged-ports")):
            if any(vlan.casefold() == folded for vlan in modes.get(mode, ())):
                found[attribute].add(port)
    return {attribute: " ".join(sorted(ports)) for attribute, ports in found.items() if ports}


def natives(snapshot) -> dict:
    """The untagged VLANs of every port named by a membership line of the snapshot."""
    _vlans, members, _descriptions = membership.model(snapshot)
    return {port: set(modes.get("untagged", ())) for port, modes in members.items()}


def _upm_command(command) -> bool:
    return command.module == "upm" or bool(command.upm_profile)


def _is_membership(command) -> bool:
    tokens = command.tokens
    return (not _upm_command(command) and len(tokens) >= 5 and tokens[:2] == ("configure", "vlan")
            and tokens[3:5] == ("add", "ports"))


def _own_membership(command, name: str) -> bool:
    return _is_membership(command) and command.tokens[2].casefold() == name.casefold()


def references_without_members(snapshot, key: str) -> list:
    """References of a VLAN that are not its own port membership lines (used when the request names the ports)."""
    return sorted(
        "line %d (module %s)" % (command.line, command.module or "-")
        for command in snapshot.commands
        if snapshot._mentions(command, key) and not snapshot._is_own(command, key) and not _own_membership(command, key)
    )


def rename_prechecks(snapshot, profile, key: str, new: str, protected) -> list:
    validate_vlan_name(new)
    reasons = []
    if not profile.key_pattern.fullmatch(new):
        reasons.append("the new name %r does not match %s" % (new, profile.key_pattern.pattern))
    if new.casefold() == key.casefold():
        reasons.append("the new name differs from the old one only in letter case; rename it in two steps")
    guarded = {name.casefold() for name in profile.protected_keys}
    guarded |= {name.casefold() for name in (protected or {}).get("vlan", ())}
    if new.casefold() in guarded or new.casefold().startswith("netops-enroll-"):
        reasons.append("the new name %r is protected or reserved" % new)
    if snapshot._entry(new) is not None or snapshot.in_use(new):
        reasons.append("name %r is already used in the configuration" % new)
    scripts = sorted("line %d" % command.line for command in snapshot.commands
                     if _upm_command(command) and snapshot._mentions(command, key))
    if scripts:
        # a UPM script names the VLAN in its text; the switch renames the VLAN object, not the script text
        reasons.append("VLAN %s is named in a UPM script (%s); a rename would leave the script on the old name"
                       % (key, ", ".join(scripts)))
    return reasons


def changed_vlan_ports(before, after) -> set:
    changed = set()
    for attribute in PORT_ATTRIBUTES:
        changed |= set(_port_list((before or {}).get(attribute))) ^ set(_port_list((after or {}).get(attribute)))
    return changed


def port_prechecks(snapshot, key: str, before, after, protected) -> list:
    """The ports of a G43 port plan: real port numbers, no link aggregation, no protected port, and untagged ports
    that come from (and return to) Default, because "add ports untagged" moves a port out of Default and the
    inverse brings it back there."""
    before, after = before or {}, after or {}
    tagged_after = set(_port_list(after.get("tagged-ports")))
    untagged_after = set(_port_list(after.get("untagged-ports")))
    untagged_before = set(_port_list(before.get("untagged-ports")))
    touched = changed_vlan_ports(before, after)
    reasons = []
    if tagged_after & untagged_after:
        reasons.append("port %s cannot be tagged and untagged in the same VLAN"
                       % _port_text(tagged_after & untagged_after))
    if key.casefold() == membership.DEFAULT_VLAN.casefold():
        reasons.append("the ports of Default are changed per port (vlan-membership)")
    try:
        lag = membership.lag_ports(snapshot)
    except Rejected as exc:
        return reasons + list(exc.reasons)
    if touched & lag:
        reasons.append("%s %s: %s" % ("port" if len(touched & lag) == 1 else "ports", _port_text(touched & lag),
                                      membership.LAG_REFUSAL))
    guarded = set((protected or {}).get("ports", ())) & touched
    if guarded:
        reasons.append("port %s is protected" % _port_text(guarded))
    moved = untagged_after ^ untagged_before
    if moved:
        if any(command.tokens == AUTO_MOVE_OFF for command in snapshot.commands):
            reasons.append("native VLAN movement is disabled on this switch")
        vlans, members, _descriptions = membership.model(snapshot)
        if not any(name.casefold() == membership.DEFAULT_VLAN.casefold() for name in vlans):
            reasons.append("the switch has no Default VLAN to return untagged ports to")
        coming = sorted(port for port in untagged_after - untagged_before
                        if members.get(port, {}).get("untagged") != {membership.DEFAULT_VLAN})
        if coming:
            reasons.append("untagged port %s is not an untagged member of Default; only ports of Default are moved"
                           % _port_text(coming))
    return reasons


def render_vlan(key: str, before, after) -> list:
    """Commands from one whole G43 VLAN state to another (create, delete, rename, port changes)."""
    if before is None:
        lines = ["create vlan %s tag %s" % (key, after["tag"])]
        if "description" in after:
            lines.append('configure vlan %s description "%s"' % (key, _text(after["description"])))
        return lines + l3_lines(key, None, after) + _port_lines(key, {}, after)
    if after is None:
        # an untagged port of a deleted VLAN keeps no native VLAN (G43 measurement): Default first, then the delete
        untagged = _port_list(before.get("untagged-ports"))
        lines = ["configure vlan %s add ports %s untagged" % (membership.DEFAULT_VLAN, _port_text(untagged))] if untagged else []
        return lines + ["delete vlan %s" % key]
    old, new = before.get(RENAME, key), after.get(RENAME, key)
    if old != new:
        return ["configure vlan %s name %s" % (old, new)]
    lines = []
    if after.get("description") != before.get("description"):
        lines.append('configure vlan %s description "%s"' % (key, _text(after["description"]))
                     if "description" in after else "unconfigure vlan %s description" % key)
    return lines + l3_lines(key, before, after) + _port_lines(key, before, after)


def _port_lines(key: str, before, after) -> list:
    old_tagged, new_tagged = set(_port_list(before.get("tagged-ports"))), set(_port_list(after.get("tagged-ports")))
    old_untagged, new_untagged = (set(_port_list(before.get("untagged-ports"))),
                                  set(_port_list(after.get("untagged-ports"))))
    lines = []
    if old_tagged - new_tagged:
        lines.append("configure vlan %s delete ports %s" % (key, _port_text(old_tagged - new_tagged)))
    if old_untagged - new_untagged:
        lines.append("configure vlan %s add ports %s untagged"
                     % (membership.DEFAULT_VLAN, _port_text(old_untagged - new_untagged)))
    if new_tagged - old_tagged:
        lines.append("configure vlan %s add ports %s tagged" % (key, _port_text(new_tagged - old_tagged)))
    if new_untagged - old_untagged:
        lines.append("configure vlan %s add ports %s untagged" % (key, _port_text(new_untagged - old_untagged)))
    return lines


def touched_untagged(before, after) -> list:
    return sorted(set(_port_list((before or {}).get("untagged-ports")))
                  | set(_port_list((after or {}).get("untagged-ports"))), key=port_order)


def g43_rest_digest(snapshot, kind: str, name: str, touched=(), safeguard_id=None) -> str:
    """The configuration outside a G43 VLAN plan.

    rename: every line except the own lines of the VLAN, with the current name of the VLAN (the old one before,
    the new one after) replaced by a placeholder, so a reference the switch did not rename shows as a difference.
    ports: every line except the own lines and all membership lines, plus the membership of all ports without
    this VLAN and without the native VLAN of the untagged ports of the plan (those are compared separately)."""
    commands = tuple(command for command in _without_safeguards(snapshot.configuration.commands,
                                                                 safeguard_id=safeguard_id)
                     if _upm_command(command) or not _default_recovery(command))
    folded = name.casefold()
    if kind == "rename":
        lines = []
        for command in commands:
            if snapshot._is_own(command, name, l3=False):
                continue
            if snapshot._mentions(command, name):
                lines.append(" ".join(PLACEHOLDER if token.casefold() == folded else token for token in command.tokens))
            else:
                lines.append(command.text)
        body = {"configuration": lines}
    else:
        _vlans, members, _descriptions = membership.model(snapshot)
        other = {}
        for port, modes in members.items():
            kept = {}
            for mode, names in modes.items():
                names = {vlan for vlan in names if vlan.casefold() != folded}
                if mode == "untagged" and port in touched:
                    names = set()
                kept[mode] = sorted(names)
            if any(kept.values()):
                other[port] = kept
        owns_l3 = snapshot.owns_vlan_l3(name)
        lines = [command.text for command in commands
                 if not snapshot._is_own(command, name, l3=owns_l3) and not _is_membership(command)
                 and not membership.default_rendering(snapshot, command)]
        body = {"configuration": lines, "other_memberships": other}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def native_differences(snapshot, key: str, touched, wanted) -> list:
    """Each untagged port of a G43 port plan is an untagged member of this VLAN when the expected state lists it,
    otherwise of Default."""
    current = natives(snapshot)
    listed = set(_port_list((wanted or {}).get("untagged-ports")))
    differences = []
    for port in touched:
        expected = key if port in listed else membership.DEFAULT_VLAN
        found = sorted(current.get(port, set()))
        if [vlan.casefold() for vlan in found] != [expected.casefold()]:
            differences.append("port %s: expected untagged in %s, found %s" % (port, expected, ", ".join(found) or "none"))
    return differences


def predicted_text(snapshot, plan, text: str) -> str:
    """show configuration after a G43 VLAN plan (for the audit of the predicted configuration)."""
    before, after, key = plan["predicted"]["before"], plan["predicted"]["after"], plan["key"]
    if plan_kind(before, after) == "rename":
        # only the lines that name the VLAN change; module headers and every other line stay as they are
        old, new = before[RENAME], after[RENAME]
        lines = l1_exos.split_lines(text)
        for command in snapshot.configuration.commands:
            if snapshot._mentions(command, old) or snapshot._is_own(command, old):
                lines[command.line - 1] = " ".join(
                    new if token.casefold() == old.casefold() else token for token in command.tokens) + "\n"
        return "".join(lines)
    _vlans, members, _descriptions = membership.model(snapshot)
    folded = key.casefold()
    for port, modes in members.items():
        for mode in modes:
            modes[mode] = {vlan for vlan in modes[mode] if vlan.casefold() != folded}
    for port in touched_untagged(before, after):
        members.setdefault(port, {"tagged": set(), "untagged": set()})["untagged"] = {membership.DEFAULT_VLAN}
    for attribute, mode in (("tagged-ports", "tagged"), ("untagged-ports", "untagged")):
        for port in _port_list((after or {}).get(attribute)):
            modes = members.setdefault(port, {"tagged": set(), "untagged": set()})
            if mode == "untagged":
                modes["untagged"] = set()
            modes[mode].add(key)
    owns_l3 = snapshot.owns_vlan_l3(key)
    kept = [command for command in snapshot.commands
            if not snapshot._is_own(command, key, l3=owns_l3) and not _is_membership(command)]
    added = []
    if after is not None:
        added += ['create vlan "%s"' % key]
        if "description" in after:
            added.append('configure vlan %s description "%s"' % (key, after["description"]))
        added.append("configure vlan %s tag %s" % (key, after["tag"]))
        added += l3_config_lines(key, after)
    for port, modes in sorted(members.items(), key=lambda item: port_order(item[0])):
        for mode, names in sorted(modes.items()):
            added += ["configure vlan %s add ports %s %s" % (vlan, port, mode) for vlan in sorted(names)]
    return "\n".join(membership.modular(snapshot, kept, added)) + "\n"


VLAN_PORTS = re.compile(r"^[^\S\n]*Ports:\s+(\d+)\.", re.MULTILINE)
VLAN_PORT_MODE = re.compile(r"^[^\S\n]*(Untag|Tag):\s*(.*)$")
VLAN_PORT_ITEM = re.compile(r"[*!]?([1-9][0-9]{0,2})(?:\([^()\s]*\))?[a-zA-Z]*")


def shown_vlan_ports(text: str) -> dict:
    """tagged-ports and untagged-ports of the port block of show vlan <name> (measured on 33.7.1.6:
    "Ports:   N." then "Untag:" and "Tag:" rows with continuation lines, flags before and after each port and the
    display string in parentheses); the number of listed ports must equal N."""
    total = VLAN_PORTS.findall(text)
    if len(total) != 1:
        raise Rejected(["the check account answer shows no port count of the VLAN"])
    found = {"Untag": [], "Tag": []}
    mode = None
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if VLAN_PORTS.match(line))
    for line in lines[start + 1:]:
        row = VLAN_PORT_MODE.match(line)
        if row is not None:
            mode, rest = row.group(1), row.group(2)
        elif mode is not None and line.startswith((" ", "\t")) and line.strip() and not line.strip().startswith("Flags"):
            rest = line
        else:
            break
        for item in (part.strip() for part in rest.split(",")):
            if not item:
                continue
            match = VLAN_PORT_ITEM.fullmatch(item)
            if match is None:
                raise Rejected(["the check account answer lists a VLAN port that is not recognised"])
            found[mode].append(match.group(1))
    listed = found["Untag"] + found["Tag"]
    if len(listed) != int(total[0]) or len(set(listed)) != len(listed):
        raise Rejected(["the check account answer lists %d VLAN ports, not %s" % (len(listed), total[0])])
    result = {}
    if found["Tag"]:
        result["tagged-ports"] = " ".join(sorted(found["Tag"]))
    if found["Untag"]:
        result["untagged-ports"] = " ".join(sorted(found["Untag"]))
    return result


# ---- 1.0.12 G45: static routes (X12), VLAN IP addresses and forwarding (X13), VRRP (X39) ----
# Measured on EXOS-VM 33.6.1.14 (GNS3 d-exos, licence Core, task netops-20261117-479, task-evidence/g45):
# * "configure iproute add|delete <net>/<len>|default <gateway> [vr <vr>]"; show configuration prints IPv4 as
#   "configure iproute add A M GW", IPv6 as "... P/L GW", the default route as "... default GW" and omits
#   "vr VR-Default" (another VR as "vr <name>"). A second gateway of the same destination is added as a second route,
#   so a new gateway is added before the old route is deleted.
#   The IPv6 default route ('configure iproute add default <IPv6 gw>') is printed the same way and shown by
#   show iproute ipv6 as the row 'Default route' (task 479-r2, M2). A static route stays configured when the VLAN of its
#   gateway is deleted (its gateway becomes unresolved).
# * "configure vlan V ipaddress A/len" (printed "configure vlan V ipaddress A M"); a primary IPv4 address cannot be
#   changed in place ("unconfigure vlan V ipaddress" first), and "unconfigure vlan V ipaddress" also disables IPv4
#   forwarding. "enable ipforwarding [ipv6] vlan V". The first IPv6 address adds "configure vlan V ipaddress eui64
#   fe80::/64" (link-local), which stays after the IPv6 address is removed and goes only with "delete vlan" or its
#   MAC-derived address; another IPv6 address is added, not replaced.
# * "create vrrp vlan V vrid N", "configure vrrp vlan V vrid N priority P" (100 is not printed), "... add VIP" (the
#   switch refuses a VIP outside the subnets of V), "enable vrrp vlan V vrid N"; "delete vrrp vlan V vrid N" removes
#   the whole instance. The global "enable vrrp" would enable every instance; Admin uses the per-instance form.
ROUTE_TABLE = "iproute"
VRRP_TABLE = "vrrp"
STATE_TABLES = (ROUTE_TABLE, VRRP_TABLE)
L3_ATTRIBUTES = ("ipaddress", "ipforwarding", "ipv6-address", "ipforwarding-ipv6")
L3_FIRMWARE = ("33.6.1.14",)
DEFAULT_VR = "VR-Default"
SYSTEM_VRS = ("VR-Mgmt", "VR-Control")
MANAGEMENT_VLAN = "Mgmt"
VR_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
LINK_LOCAL = ("eui64", "fe80::/64")
ENABLED = "enabled"


def l3_support(firmware) -> dict:
    return tested.support("ExtremeXOS", firmware, L3_FIRMWARE, function="IP routing and VRRP")


def touches_l3(table: str, before, after) -> bool:
    if table in STATE_TABLES:
        return True
    return table == "vlan" and any(name in (state or {}) for state in (before, after) for name in L3_ATTRIBUTES)


def _ipv4_interface(address: str, mask: str):
    return ipaddress.IPv4Interface("%s/%s" % (address, mask))


def l3_owner(command):
    """(VLAN, kind) of an IP line of a VLAN ("ipv4", "ipv6", "link-local", "forwarding", "forwarding-ipv6",
    "other" for another ipaddress form), or None."""
    tokens = command.tokens
    if _upm_command(command):
        return None
    if len(tokens) >= 5 and tokens[:2] == ("configure", "vlan") and tokens[3] == "ipaddress":
        rest = tokens[4:]
        if tuple(rest) == LINK_LOCAL:
            return tokens[2], "link-local"
        if len(rest) == 2 and re.fullmatch(r"[0-9.]+", rest[0]) and re.fullmatch(r"[0-9.]+", rest[1]):
            return tokens[2], "ipv4"
        if len(rest) == 1 and ":" in rest[0] and "/" in rest[0]:
            return tokens[2], "ipv6"
        return tokens[2], "other"
    if len(tokens) == 4 and tokens[:3] == ("enable", "ipforwarding", "vlan"):
        return tokens[3], "forwarding"
    if len(tokens) == 5 and tokens[:4] == ("enable", "ipforwarding", "ipv6", "vlan"):
        return tokens[4], "forwarding-ipv6"
    return None


def vlan_interfaces(snapshot) -> dict:
    """VLAN name -> {"vr", "ipv4": [IPv4Interface], "ipv6": [IPv6Interface]} of every VLAN with an address,
    the built-in Mgmt VLAN (VR-Mgmt) included."""
    found = {}
    for command in snapshot.commands:
        owner = l3_owner(command)
        if owner is None or owner[1] not in ("ipv4", "ipv6"):
            continue
        name, kind = owner
        item = found.setdefault(name, {"vr": "VR-Mgmt" if name == MANAGEMENT_VLAN else DEFAULT_VR, "ipv4": [], "ipv6": []})
        try:
            if kind == "ipv4":
                item["ipv4"].append(_ipv4_interface(command.tokens[4], command.tokens[5]))
            else:
                item["ipv6"].append(ipaddress.IPv6Interface(command.tokens[4]))
        except ValueError:
            continue
    return found


def routing_scope(snapshot, table, key, protected):
    """Check local VLAN dependencies and return the VLANs affected by a routing change."""
    proto = exos_g46.protocol(table, key)
    if table in (exos_g46.AREA, exos_g46.BGP):
        return set()
    if not vlan_module_closed(snapshot):
        exos_g46.read_error("the VLAN configuration module is incomplete")
    if table == exos_g46.PEER:
        peer = ipaddress.IPv4Address(key)
        vlans = {vlan for vlan, addresses in vlan_interfaces(snapshot).items()
                 if any(peer in ip.network and peer != ip.ip and not (
                     ip.network.prefixlen < 31 and peer in (ip.network.network_address, ip.network.broadcast_address))
                        for ip in addresses["ipv4"])}
        if len(vlans) != 1 or peer.is_multicast or peer.is_unspecified or peer.is_loopback:
            exos_g46.refuse("BGP needs one directly connected unicast IPv4 peer on an eligible VLAN")
    elif table == exos_g46.INTERFACE:
        vlans = {key.split(":", 1)[1]}
    else:
        prefix = proto + ":"
        vlans = {name[len(prefix):] for name in snapshot.entries(exos_g46.INTERFACE) if name.startswith(prefix)}
    guarded = {name.casefold() for name in ("Default", MANAGEMENT_VLAN, *(protected or {}).get("vlan", ()))}
    guarded_ports = set((protected or {}).get("ports", ()))
    for name in sorted(vlans):
        vlan = snapshot.vlans.get(name)
        if name.casefold() in guarded:
            exos_g46.refuse("the routing change affects a protected VLAN")
        if vlan is None or any(command.tokens[:2] in (("create", "vlan"), ("configure", "vr"))
                               and name in command.tokens[2:] and
                               (("create", "vlan") != command.tokens[:2] or len(command.tokens) != 3)
                               for command in snapshot.commands if command.module == "vlan"):
            exos_g46.refuse("the routing VLAN must be configured in VR-Default")
        ports = set(" ".join(vlan_ports(snapshot, name).values()).split())
        if ports & guarded_ports or any(management_vlan_member(snapshot, port, guarded) for port in ports):
            exos_g46.refuse("the routing VLAN shares a port with protected or management configuration")
        if table == exos_g46.INTERFACE:
            field = "ipforwarding-ipv6" if proto == "ospfv3" else "ipforwarding"
            address = "ipv6-address" if proto == "ospfv3" else "ipaddress"
            link_local = proto == "ospfv3" and any(l3_owner(cmd) == (name, "link-local") for cmd in snapshot.commands)
            if vlan.attributes.get(field) != ENABLED or not (vlan.attributes.get(address) or link_local):
                exos_g46.refuse("the OSPF VLAN needs an address and enabled IP forwarding for this protocol")
    return vlans


def parse_l3(snapshot) -> None:
    """The IP attributes of the VLAN entries of the snapshot (only VLANs created in the configuration)."""
    link_local = set()
    for command in snapshot.commands:
        owner = l3_owner(command)
        if owner is None:
            continue
        name, kind = owner
        entry = snapshot._entry(name)
        if entry is None:
            continue

        def unsupported(text, entry=entry):
            entry.unsupported.append(text)
            entry.l3_unsupported.append(text)

        tokens = command.tokens
        attribute, value = None, None
        if kind == "ipv4":
            try:
                interface = _ipv4_interface(tokens[4], tokens[5])
            except ValueError:
                unsupported("line %d: IPv4 address %s %s" % (command.line, tokens[4], tokens[5]))
                continue
            attribute, value = "ipaddress", "%s %s" % (interface.ip, interface.network.netmask)
        elif kind == "ipv6":
            try:
                interface = ipaddress.IPv6Interface(tokens[4])
                plain_address(str(interface))
            except (ValueError, Rejected):
                unsupported("line %d: IPv6 address %s" % (command.line, tokens[4][:64]))
                continue
            if interface.ip.is_link_local:
                unsupported("line %d: a fixed IPv6 link-local address" % command.line)
                continue
            attribute, value = "ipv6-address", str(interface)
        elif kind == "forwarding":
            attribute, value = "ipforwarding", ENABLED
        elif kind == "forwarding-ipv6":
            attribute, value = "ipforwarding-ipv6", ENABLED
        elif kind == "link-local":
            link_local.add(entry.name)
            continue
        else:
            unsupported("line %d: %s" % (command.line, " ".join(tokens[3:])))
            continue
        if attribute in entry.attributes:
            unsupported("line %d: a second %s" % (command.line, attribute))
            continue
        entry.attributes[attribute] = value
    for entry in snapshot.vlans.values():
        # the switch adds the eui64 link-local address with the first IPv6 address and keeps it after its removal
        if (entry.name in link_local) != ("ipv6-address" in entry.attributes):
            text = ("IPv6 link-local address %s an IPv6 address"
                    % ("without" if entry.name in link_local else "missing beside"))
            entry.unsupported.append(text)
            entry.l3_unsupported.append(text)


def without_l3(state, unsupported, entry):
    """Project the VLAN state when its IP lines are tracked by the rest digest."""
    kept = [item for item in unsupported if item not in entry.l3_unsupported]
    return {name: value for name, value in state.items() if name not in L3_ATTRIBUTES}, kept


# -- static routes ------------------------------------------------------------------------------------------------

def route_key(key: str) -> tuple:
    """(VR, network) of an iproute key: [vr:<VR>:]<network>/<length> in the canonical form (VR-Default without vr:)."""
    vr, text = DEFAULT_VR, key
    if key.startswith("vr:"):
        parts = key.split(":", 2)
        if len(parts) != 3 or not VR_NAME.fullmatch(parts[1]):
            raise Rejected(["route key %r must be [vr:<name>:]<network>/<length>" % key])
        vr, text = parts[1], parts[2]
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise Rejected(["route key %r must be [vr:<name>:]<network>/<length> without host bits" % key]) from None
    if route_name(vr, network) != key:
        raise Rejected(["route key must be written as %s" % route_name(vr, network)])
    return vr, network


def route_name(vr: str, network) -> str:
    return ("" if vr == DEFAULT_VR else "vr:%s:" % vr) + str(network)


# 1.0.12 G45 r2 (479-rv finding 1): an address attribute is a plain address before it is parsed. Python accepts an
# IPv6 zone identifier after "%" (with any text, white space included) and keeps it in str(), and str.strip() would
# hide white space around the value; neither may reach a CLI line. The limits are the profile max_length values.
ADDRESS_TEXT = {
    "gateway": (re.compile(r"[0-9A-Fa-f:.]{2,39}"), 39),
    "virtual-ip": (re.compile(r"[0-9.]{7,15}"), 15),
    "ipv6-address": (re.compile(r"[0-9A-Fa-f:.]{2,45}/[0-9]{1,3}"), 49),
}
PLAIN_ADDRESS = re.compile(r"[0-9a-f:.]{2,45}(?:/[0-9]{1,3})?")


def canonical_address(name: str, value) -> str:
    """gateway (unicast address), virtual-ip (IPv4 unicast) and ipv6-address (global "addr/len", lower case)."""
    if not isinstance(value, str):
        raise Rejected(["attribute %s must be a string" % name])
    if name not in ADDRESS_TEXT:
        raise Rejected(["attribute %s is not an address attribute" % name])
    pattern, limit = ADDRESS_TEXT[name]
    if len(value) > limit or not pattern.fullmatch(value):
        raise Rejected(["attribute %s must be a plain address (%s; no zone identifier, no white space, at most %d "
                        "characters)" % (name, "a.b.c.d or IPv6 hex digits and colons" if name != "ipv6-address"
                                         else "IPv6 address/prefix length", limit)])
    text = value
    try:
        if name in ("gateway", "virtual-ip"):
            address = ipaddress.ip_address(text)
            if (address.is_link_local or address.is_multicast or address.is_unspecified or address.is_loopback
                    or (name == "virtual-ip" and address.version != 4)):
                raise ValueError(text)
            return plain_address(str(address))
        interface = ipaddress.IPv6Interface(text)
        if (interface.ip.is_link_local or interface.ip.is_multicast or interface.ip.is_unspecified
                or not 1 <= interface.network.prefixlen <= 127):
            raise ValueError(text)
        return plain_address(str(interface))
    except (ValueError, Rejected):
        raise Rejected(["attribute %s: %r is not a usable %s" % (name, text[:64], {
            "gateway": "unicast gateway address", "virtual-ip": "IPv4 unicast address",
            "ipv6-address": "global IPv6 address with its prefix length"}[name])]) from None


def plain_address(text: str) -> str:
    """An address (or address/length) as it may stand in a CLI line: lower-case hex digits, dots, colons and one
    prefix length, nothing else (no zone identifier, no white space)."""
    if not isinstance(text, str) or not PLAIN_ADDRESS.fullmatch(text):
        raise Rejected(["address %r is not a plain address; it is not put into a CLI line" % str(text)[:64]])
    return text


def _route_line(command):
    """(key, gateway, options) of a static route line of show configuration, or None."""
    tokens = command.tokens
    if _upm_command(command) or tokens[:3] != ("configure", "iproute", "add") or len(tokens) < 5:
        return None
    rest = list(tokens[3:])
    blackhole = rest[0] == "blackhole"
    if blackhole:
        rest = rest[1:]
    try:
        if rest[0] == "default":
            gateway = rest[1] if len(rest) > 1 else ""
            network = ipaddress.ip_network("::/0" if ":" in gateway else "0.0.0.0/0")
            rest = rest[1:]
        elif "/" in rest[0]:
            network = ipaddress.ip_network(rest[0], strict=False)
            rest = rest[1:]
        else:
            network = ipaddress.ip_network("%s/%s" % (rest[0], rest[1]), strict=False)
            rest = rest[2:]
    except (ValueError, IndexError):
        return None
    vr = DEFAULT_VR
    options = []
    gateway = rest[0] if rest else ""
    index = 1
    while index < len(rest):
        if rest[index] == "vr" and index + 1 < len(rest):
            vr = rest[index + 1]
            index += 2
            continue
        options.append(rest[index])
        index += 1
    if blackhole:
        options.insert(0, "blackhole")
    return route_name(vr, network), gateway, options


def routes(snapshot) -> dict:
    """iproute entries of the configuration: one gateway; a second gateway of the same destination (shared routes),
    a blackhole route or another option (metric, bfd, protection, unicast/multicast) is outside the profile."""
    found = {}
    for command in snapshot.commands:
        parsed = _route_line(command)
        if parsed is None:
            continue
        key, gateway, options = parsed
        entry = found.setdefault(key, Entry(key))
        try:
            gateway = plain_address(str(ipaddress.ip_address(gateway)))
        except (ValueError, Rejected):
            entry.unsupported.append("line %d: gateway %s" % (command.line, gateway or "-"))
            continue
        if options:
            entry.unsupported.append("line %d: route option %s" % (command.line, " ".join(options)))
        if "gateway" in entry.attributes:
            entry.unsupported.append("line %d: a second gateway %s" % (command.line, gateway))
            continue
        entry.attributes["gateway"] = gateway
    return found


def route_owned(command, key: str) -> bool:
    parsed = _route_line(command)
    return parsed is not None and parsed[0] == key


def _route_command(verb: str, key: str, gateway: str) -> str:
    vr, network = route_key(key)
    destination = "default" if network.prefixlen == 0 else str(network)
    return "configure iproute %s %s %s%s" % (verb, destination, plain_address(gateway),
                                            "" if vr == DEFAULT_VR else " vr " + vr)


def render_route(key: str, before, after) -> list:
    old, new = (before or {}).get("gateway"), (after or {}).get("gateway")
    lines = []
    if new is not None and new != old:
        lines.append(_route_command("add", key, new))
    if old is not None and old != new:
        lines.append(_route_command("delete", key, old))
    return lines


def virtual_routers(snapshot) -> set:
    names = {DEFAULT_VR} | set(SYSTEM_VRS)
    for command in snapshot.commands:
        tokens = command.tokens
        if tokens[:2] == ("create", "virtual-router") and len(tokens) >= 3:
            names.add(tokens[2].strip('"'))
    return names


# -- VRRP -----------------------------------------------------------------------------------------------------------

VRRP_KEY = re.compile(r"([A-Za-z][A-Za-z0-9_-]{0,31}):([1-9][0-9]{0,2})")


def vrrp_key(key: str) -> tuple:
    match = VRRP_KEY.fullmatch(key)
    if match is None or not 1 <= int(match.group(2)) <= 255:
        raise Rejected(["VRRP key %r must be <vlan>:<vrid> with a VRID of 1-255" % key])
    return match.group(1), match.group(2)


def _vrrp_line(command):
    """(key, rest) of a line of one VRRP instance ("create|configure|enable|disable|delete vrrp vlan V vrid N ..."),
    or None."""
    tokens = command.tokens
    if _upm_command(command) or len(tokens) < 6 or tokens[1:3] != ("vrrp", "vlan") or tokens[4] != "vrid":
        return None
    return "%s:%s" % (tokens[3], tokens[5]), (tokens[0],) + tuple(tokens[6:])


def vrrps(snapshot) -> dict:
    """vrrp entries: virtual-ip (one IPv4 address), priority and admin-state; any other line of the instance
    (tracking, timers, preempt, accept mode, version, a second address) is outside the profile."""
    found = {}
    for command in snapshot.commands:
        parsed = _vrrp_line(command)
        if parsed is None:
            continue
        key, rest = parsed
        if rest == ("create",):
            entry = found.setdefault(key, Entry(key))
            entry.attributes.setdefault("admin-state", "disabled")
            continue
        entry = found.setdefault(key, Entry(key))
        if rest == ("enable",):
            entry.attributes["admin-state"] = ENABLED
        elif rest[:2] == ("configure", "priority") and len(rest) == 3 and rest[2].isdigit():
            entry.attributes["priority"] = str(int(rest[2]))
        elif rest[:2] == ("configure", "add") and len(rest) == 3:
            try:
                address = ipaddress.IPv4Address(rest[2])
            except ValueError:
                entry.unsupported.append("line %d: virtual address %s" % (command.line, rest[2]))
                continue
            if "virtual-ip" in entry.attributes:
                entry.unsupported.append("line %d: a second virtual address" % command.line)
                continue
            entry.attributes["virtual-ip"] = str(address)
        else:
            entry.unsupported.append("line %d: %s" % (command.line, " ".join(command.tokens)))
    for entry in found.values():
        if "admin-state" not in entry.attributes:
            entry.unsupported.append("instance without its create line")
    return found


def vrrp_owned(command, key: str) -> bool:
    parsed = _vrrp_line(command)
    return parsed is not None and parsed[0] == key


def render_vrrp(key: str, before, after) -> list:
    vlan, vrid = vrrp_key(key)
    base = "vrrp vlan %s vrid %s" % (vlan, vrid)
    if before is None:
        lines = ["create " + base]
        if "priority" in after:
            lines.append("configure %s priority %s" % (base, after["priority"]))
        if "virtual-ip" in after:
            # 479-rv finding 4: an instance without VIP (measured, vrrp-created) is recreated without one
            lines.append("configure %s add %s" % (base, plain_address(after["virtual-ip"])))
        if after.get("admin-state", ENABLED) == ENABLED:
            lines.append("enable " + base)
        return lines
    if after is None:
        return ["delete " + base]
    lines = []
    if before.get("priority", "100") != after.get("priority", "100"):
        lines.append("configure %s priority %s" % (base, after.get("priority", "100")))
    old, new = before.get("virtual-ip"), after.get("virtual-ip")
    if old != new:
        if new is not None:
            lines.append("configure %s add %s" % (base, plain_address(new)))
        if old is not None:
            lines.append("configure %s delete %s" % (base, plain_address(old)))
    if before.get("admin-state", ENABLED) != after.get("admin-state", ENABLED):
        lines.append("%s %s" % ("enable" if after.get("admin-state", ENABLED) == ENABLED else "disable", base))
    return lines


def vrrp_vlans(snapshot) -> set:
    return {key.split(":", 1)[0].casefold() for key in vrrps(snapshot)}


# -- VLAN IP lines --------------------------------------------------------------------------------------------------

def _cidr(value: str) -> str:
    address, mask = value.split()
    interface = _ipv4_interface(address, mask)
    return "%s/%d" % (interface.ip, interface.network.prefixlen)


def l3_lines(key: str, before, after) -> list:
    """Commands from the IP attributes of VLAN key before to after (measured order and side effects)."""
    before, after = before or {}, after or {}
    lines = []
    old, new = before.get("ipaddress"), after.get("ipaddress")
    forwarding = after.get("ipforwarding") == ENABLED
    if old != new:
        if old is not None:
            lines.append("unconfigure vlan %s ipaddress" % key)       # also disables IPv4 forwarding (measured)
        if new is not None:
            lines.append("configure vlan %s ipaddress %s" % (key, plain_address(_cidr(new))))
            if forwarding:
                lines.append("enable ipforwarding vlan %s" % key)
    elif (before.get("ipforwarding") == ENABLED) != forwarding:
        lines.append("%s ipforwarding vlan %s" % ("enable" if forwarding else "disable", key))
    old, new = before.get("ipv6-address"), after.get("ipv6-address")
    if old != new:
        if new is not None:
            lines.append("configure vlan %s ipaddress %s" % (key, plain_address(new)))
        if old is not None:
            lines.append("unconfigure vlan %s ipaddress %s" % (key, plain_address(old)))
    forwarding = after.get("ipforwarding-ipv6") == ENABLED
    if (before.get("ipforwarding-ipv6") == ENABLED) != forwarding:
        lines.append("%s ipforwarding ipv6 vlan %s" % ("enable" if forwarding else "disable", key))
    return lines


def l3_config_lines(key: str, state) -> list:
    """The IP lines of VLAN key in the form show configuration prints them (for the predicted configuration)."""
    state = state or {}
    lines = []
    if "ipaddress" in state:
        lines.append("configure vlan %s ipaddress %s" % (key, state["ipaddress"]))
    if state.get("ipforwarding") == ENABLED:
        lines.append("enable ipforwarding vlan %s" % key)
    if "ipv6-address" in state:
        lines += ["configure vlan %s ipaddress %s" % (key, " ".join(LINK_LOCAL)),
                  "configure vlan %s ipaddress %s" % (key, state["ipv6-address"])]
    if state.get("ipforwarding-ipv6") == ENABLED:
        lines.append("enable ipforwarding ipv6 vlan %s" % key)
    return lines


def render_state(table: str, key: str, before, after) -> list:
    if table == ROUTE_TABLE:
        return render_route(key, before, after)
    if table == VRRP_TABLE:
        return render_vrrp(key, before, after)
    return render_vlan(key, before, after)


# -- prechecks on the snapshot --------------------------------------------------------------------------------------

def _networks(state, family=None) -> list:
    found = []
    if (state or {}).get("ipaddress") and family in (None, 4):
        found.append(ipaddress.IPv4Interface(_cidr(state["ipaddress"])))
    if (state or {}).get("ipv6-address") and family in (None, 6):
        found.append(ipaddress.IPv6Interface(state["ipv6-address"]))
    return found


def _gateways_in(snapshot, networks) -> list:
    hit = []
    for key, entry in sorted(routes(snapshot).items()):
        gateway = entry.attributes.get("gateway")
        if gateway and any(ipaddress.ip_address(gateway) in network.network for network in networks
                           if network.version == ipaddress.ip_address(gateway).version):
            hit.append(key)
    return hit


def g45_prechecks(snapshot, profile, op: str, key: str, before, after, protected) -> list:
    """Snapshot checks of a G45 plan (static route, VLAN IP attributes, VRRP); refusals are returned as reasons."""
    table = profile.table
    reasons = []
    if table == ROUTE_TABLE:
        vr, network = route_key(key)
        if vr in SYSTEM_VRS:
            return ["routes of %s are the management or control path; Admin never changes them" % vr]
        if vr not in virtual_routers(snapshot):
            return ["virtual router %s does not exist" % vr]
        gateway = (after or {}).get("gateway")
        if gateway is not None:
            address = ipaddress.ip_address(gateway)
            if address.version != network.version:
                reasons.append("gateway %s is not an IPv%d address" % (gateway, network.version))
            elif network.prefixlen and address in network:
                reasons.append("gateway %s lies inside the destination %s" % (gateway, network))
        return reasons
    if table == VRRP_TABLE:
        vlan, _vrid = vrrp_key(key)
        guarded = {name.casefold() for name in ("Default", MANAGEMENT_VLAN)}
        guarded |= {name.casefold() for name in (protected or {}).get("vlan", ())}
        if vlan.casefold() in guarded:
            return ["VLAN %s is protected; Admin does not add VRRP to it" % vlan]
        entry = snapshot._entry(vlan)
        if entry is None or entry.name != vlan:
            return ["VLAN %s does not exist (the VLAN name is case-sensitive in the key)" % vlan]
        if after is None:
            return []
        address = entry.attributes.get("ipaddress")
        if address is None:
            return ["VLAN %s has no IPv4 address; VRRP needs one" % vlan]
        if "virtual-ip" not in after:
            # 479-rv finding 4 (M2 measured): an instance without VIP takes a priority and stays disabled; the switch
            # refuses to enable it ("VR must have at least 1 virtual IP address!")
            if after.get("admin-state", ENABLED) == ENABLED:
                reasons.append("VRRP %s has no virtual address; the switch enables an instance only with at least one "
                               "virtual address (set admin-state disabled or add the address first)" % key)
            return reasons
        if before is not None and "virtual-ip" not in before:
            return ["VRRP %s has no virtual address; adding the first virtual address to an existing instance is "
                    "outside the profile (its return is not measured); delete and create the instance instead" % key]
        interface = ipaddress.IPv4Interface(_cidr(address))
        virtual = ipaddress.IPv4Address(after["virtual-ip"])
        if virtual not in interface.network or virtual in (interface.network.network_address,
                                                           interface.network.broadcast_address):
            reasons.append("virtual address %s is not a host address of the subnet %s of VLAN %s"
                           % (virtual, interface.network, vlan))
        elif virtual == interface.ip:
            reasons.append("virtual address %s is the address of VLAN %s (address owner); this is outside the profile"
                           % (virtual, vlan))
        return reasons
    if table != "vlan" or not touches_l3(table, before, after):
        return []
    before, after = before or {}, after
    if after is not None:
        if after.get("ipforwarding") == ENABLED and "ipaddress" not in after:
            reasons.append("IPv4 forwarding needs an IPv4 address of the VLAN")
        if after.get("ipforwarding-ipv6") == ENABLED and "ipv6-address" not in after:
            reasons.append("IPv6 forwarding needs an IPv6 address of the VLAN")
        if op == "update" and ("ipv6-address" in before) != ("ipv6-address" in after):
            reasons.append("an IPv6 address is added to or removed from an existing VLAN only with the VLAN: the switch "
                           "keeps its automatic link-local address, which the inverse cannot return")
        mine, known = key.casefold(), set(_networks(before))
        for name, item in sorted(vlan_interfaces(snapshot).items()):
            if name.casefold() == mine:
                continue
            for wanted in (item_ for item_ in _networks(after) if item_ not in known):
                for other in item["ipv4"] + item["ipv6"]:
                    if other.version == wanted.version and other.network.overlaps(wanted.network):
                        reasons.append("%s overlaps %s of VLAN %s" % (wanted, other, name))
    old = _networks(before, 4)
    if old and (after is None or before.get("ipaddress") != after.get("ipaddress")):
        if after is not None and key.casefold() in vrrp_vlans(snapshot):
            reasons.append("VLAN %s carries VRRP; its IPv4 address is not changed under it" % key)
        kept = _networks(after, 4) if after is not None else []
        lost = [key_ for key_ in _gateways_in(snapshot, old) if key_ not in _gateways_in_kept(snapshot, kept)]
        if lost:
            reasons.append("static route %s uses a gateway in the subnet of VLAN %s" % (", ".join(lost), key))
    old6 = _networks(before, 6)
    if old6 and (after is None or before.get("ipv6-address") != after.get("ipv6-address")):
        kept = _networks(after, 6) if after is not None else []
        lost = [key_ for key_ in _gateways_in(snapshot, old6) if key_ not in _gateways_in_kept(snapshot, kept)]
        if lost:
            reasons.append("static route %s uses a gateway in the subnet of VLAN %s" % (", ".join(lost), key))
    return reasons


def _gateways_in_kept(snapshot, networks) -> list:
    return _gateways_in(snapshot, networks) if networks else []


# -- management path (session client addresses) ---------------------------------------------------------------------

def session_addresses(text: str) -> list:
    """Client addresses of show session (the last column of the session rows); the own session (marked *) must name
    an address, another session without one (a console) is skipped."""
    found, own = [], False
    for line in text.splitlines():
        row = SESSION_ROW.match(line)
        if row is None:
            continue
        try:
            found.append(ipaddress.ip_address(line.split()[-1].split("%")[0]))
            own = own or row.group(1) == "*"
        except (ValueError, IndexError):
            if row.group(1) == "*":
                raise Rejected(["the own session in the session list names no client address"]) from None
    if not own:
        raise Rejected(["the session list shows no client address of the own session"])
    return found


def routing_vrs(snapshot) -> list:
    """The VRs whose route table can carry a session: every VR of the configuration except VR-Control (measured on
    33.6.1.14: the switch refuses "show iproute vr VR-Control"; it holds no route of a user interface)."""
    return sorted(vr for vr in virtual_routers(snapshot) if vr != "VR-Control")


def management_refusals(snapshot, table: str, key: str, before, after, clients, route_rows) -> list:
    """A G45 plan does not take or change the path of a session client.

    route_rows(vr, version) gives the rows of show iproute [ipv6] vr <vr> (every origin, dynamic routes included;
    a complete list). A route (create, update or delete) or a VLAN subnet (old or new) that holds a client needs the
    VR of the session: it is the only VR with an active unicast route to the client. When no VR or more than one VR
    holds it, the plan is refused (fail-closed). In the VR of the session the plan is refused when its
    network is at least as specific as the best route to the client there (it would take or it carries the path)."""
    if table == ROUTE_TABLE:
        vr, network = route_key(key)
        touched = [(vr, network, before is None)]
    else:
        vr = "VR-Mgmt" if key.casefold() == MANAGEMENT_VLAN.casefold() else DEFAULT_VR
        old = [item.network for item in _networks(before)]
        touched = [(vr, network, False) for network in old]
        touched += [(vr, item.network, True) for item in _networks(after) if item.network not in old]
    reasons = []
    for client in clients:
        held = None
        for side_vr, network, new in touched:
            if network.version != client.version or client not in network:
                continue
            if held is None:
                held = {}
                for name in routing_vrs(snapshot):
                    lengths = [row.network.prefixlen for row in route_rows(name, client.version)
                               if row.active_unicast and client in row.network]
                    if lengths:
                        held[name] = max(lengths)
            if len(held) != 1:
                reasons.append("%s %s holds the session client %s and the VR of that session cannot be determined "
                               "(routes to the client in %s)" % (key, network, client, ", ".join(sorted(held)) or "no VR"))
                continue
            (session_vr, best), = held.items()
            if side_vr != session_vr or network.prefixlen < best:
                continue
            if new:
                reasons.append("%s %s would take the path of the session client %s" % (key, network, client))
            else:
                reasons.append("%s carries the session of client %s; Admin does not change it" % (key, client))
    return reasons


# -- check account answers -------------------------------------------------------------------------------------------

SHOWN_FIELD = re.compile(r"^[^\S\n]*(IPv4 Forwarding|IPv6 Forwarding|Primary IP|IPv6):[^\S\n]*(.*?)\s*$", re.MULTILINE)
SHOWN_IPV6_MORE = re.compile(r"^\t+[^\S\n]*([0-9a-fA-F:]+/\d+)")
SHOWN_IPV6_LINE = re.compile(r"^[^\S\n]*IPv6:")


def shown_l3(text: str, strict=False) -> dict:
    """IP attributes of show vlan <name> (measured on 33.6.1.14): Primary IP, IPv4/IPv6 Forwarding and the IPv6
    address rows (the link-local row of the automatic address is not an attribute).

    Forwarding is read explicitly (479-rv finding 5): "Enabled" is the attribute, "Disabled" its default (no
    attribute); strict (a plan with IP attributes) refuses an answer without the row or with another value, so a
    missing row never confirms a disabled forwarding."""
    fields = {}
    for match in SHOWN_FIELD.finditer(text):
        fields.setdefault(match.group(1), match.group(2))
    state = {}
    for label, attribute in (("IPv4 Forwarding", "ipforwarding"), ("IPv6 Forwarding", "ipforwarding-ipv6")):
        value = fields.get(label)
        if value == "Enabled":
            state[attribute] = ENABLED
        elif value == "Disabled":
            continue
        elif strict:
            raise Rejected(["the check account answer shows %s of the VLAN %s" % (
                label, "without its forwarding state" if value is None else "with the unknown forwarding state %r"
                % value[:32])])
    primary = fields.get("Primary IP")
    if primary:
        interface = ipaddress.IPv4Interface(primary.split()[0])
        state["ipaddress"] = "%s %s" % (interface.ip, interface.network.netmask)
    addresses = []
    if "IPv6:" in text:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if "IPv6:" in line and SHOWN_IPV6_LINE.match(line):
                first = line.split(":", 1)[1].split()
                addresses += first[:1] if first and first[0] != "None" else []
                for other in lines[index + 1:]:
                    more = SHOWN_IPV6_MORE.match(other)
                    if more is None:
                        break
                    addresses.append(more.group(1))
                break
    globals_ = [str(ipaddress.IPv6Interface(item)) for item in addresses
                if not ipaddress.IPv6Interface(item).ip.is_link_local]
    if globals_:
        state["ipv6-address"] = " ".join(globals_)
    return state


ROUTE_ROW = re.compile(r"^([#*@ ])([a-z0-9]{1,3})\s+(Default Route|\S+/\d+)\s+(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s*$")
# measured (M2, 33.6.1.14): the IPv6 default route is the row "Default route", its gateway on the next line
ROUTE6_ROW = re.compile(r"^([#*@ ])([a-z0-9]{1,3})\s+(Default route|\S+/\d+)\s+\d+\s+(\S+)\s+\S+\s*$")
ROUTE6_GATEWAY = re.compile(r"^\s+(\S+)\s+(\S+)\s*$")
ROUTE_TOTAL = re.compile(r"^Total number of routes = (\d+)\s*$", re.MULTILINE)


def _shown_network(destination: str, version: int):
    if destination in ("Default Route", "Default route"):
        return ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
    # a link-local destination names its interface ("fe80::%g45m/64")
    return ipaddress.ip_network(re.sub(r"%[^/]*", "", destination), strict=False)


@dataclass(frozen=True)
class RouteRow:
    origin: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    gateway: str
    preference: str
    flags: str
    vlan: str = ""

    @property
    def active_unicast(self) -> bool:
        # The legend marks preferred unicast with '*' or '#', and routes provided to the FIB with 'f'.
        return "u" in self.flags and (self.preference in ("*", "#") or "f" in self.flags)


def route_rows(text: str, version: int) -> list[RouteRow]:
    """Every row of show iproute [ipv6] vr <VR>; the list counts as complete only when
    the number of rows equals its "Total number of routes"."""
    total = ROUTE_TOTAL.findall(text)
    if len(total) != 1:
        raise Rejected(["the check account answer about the route table is not recognised"])
    rows = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = (ROUTE_ROW if version == 4 else ROUTE6_ROW).match(line)
        if match is None:
            continue
        if version == 4:
            gateway, vlan = match.group(4, 6)
        else:
            following = ROUTE6_GATEWAY.match(lines[index + 1]) if index + 1 < len(lines) else None
            if following is None:
                raise Rejected(["the check account answer lists an IPv6 route without its gateway"])
            gateway, vlan = following.groups()
        try:
            network = _shown_network(match.group(3), version)
        except ValueError:
            raise Rejected(["the check account answer lists the unknown destination %r" % match.group(3)[:64]]) from None
        rows.append(RouteRow(match.group(2), network, gateway, match.group(1), match.group(5 if version == 4 else 4), vlan))
    if len(rows) != int(total[0]):
        raise Rejected(["the check account answer lists %d routes, not %s" % (len(rows), total[0])])
    return rows


def shown_route(text: str, key: str):
    """The static route of the key in show iproute [ipv6] vr <VR> of the check account: {"gateway": ...} or None."""
    _vr, network = route_key(key)
    gateways = [str(ipaddress.ip_address(row.gateway)) for row in route_rows(text, network.version)
                if row.origin == "s" and row.network == network]
    if not gateways:
        return None
    return {"gateway": " ".join(sorted(gateways))}


VRRP_BLOCK = re.compile(r"^VLAN:\s+(\S+)\s+VRID:\s+(\d+)\s+VRRP:\s+(Enabled|Disabled)\s+State:", re.MULTILINE)
VRRP_PRIORITY = re.compile(r"^Priority:\s+(\d+)\(")
VRRP_TOTAL = re.compile(r"^Total number of VRs : (\d+)\s*$", re.MULTILINE)
VRRP_ROW = re.compile(r"^\s+(\S+)\((?:En|Ds)\)\s+(\d{4})\s+\d+\s", re.MULTILINE)


def shown_vrrp(text: str, key: str):
    """The VRRP instance of the key in show vrrp vlan <vlan>: virtual-ip, priority, admin-state; None when the
    answer holds no block of this VRID."""
    vlan, vrid = vrrp_key(key)
    blocks = list(VRRP_BLOCK.finditer(text))
    for index, block in enumerate(blocks):
        if block.group(1) != vlan or int(block.group(2)) != int(vrid):
            continue
        end = blocks[index + 1].start() if index + 1 < len(blocks) else len(text)
        body = text[block.end():end].splitlines()
        state = {"admin-state": ENABLED if block.group(3) == "Enabled" else "disabled"}
        addresses, inside = [], False
        for line in body:
            priority = VRRP_PRIORITY.match(line.strip())
            if priority is not None:
                state["priority"] = str(int(priority.group(1)))
            if line.strip() == "Virtual IP Addresses:":
                inside = True
                continue
            if inside:
                try:
                    addresses.append(str(ipaddress.ip_address(line.strip())))
                except ValueError:
                    inside = False
        if "priority" not in state:
            raise Rejected(["the check account answer about VRRP %s shows no priority" % key])
        if addresses:
            state["virtual-ip"] = " ".join(addresses)
        return state
    return None


def vrrp_absent_from_list(text: str, key: str) -> bool:
    """show vrrp lists every instance (rows equal to its total) and none of them is this VLAN and VRID."""
    vlan, vrid = vrrp_key(key)
    total = VRRP_TOTAL.findall(text)
    if len(total) != 1:
        return False
    rows = VRRP_ROW.findall(text)
    if len(rows) != int(total[0]):
        return False
    return not any(int(number) == int(vrid) and (name == vlan or (len(name) >= 8 and vlan.startswith(name)))
                   for name, number in rows)


def state_prediction(snapshot, table: str, key: str, state) -> str:
    """show configuration after a G45 route or VRRP plan, in the form the switch prints (module rtmgr or vrrp)."""
    owned = route_owned if table == ROUTE_TABLE else vrrp_owned
    kept = [command for command in snapshot.commands if not owned(command, key)]
    added = []
    if state is not None and table == ROUTE_TABLE:
        vr, network = route_key(key)
        if network.prefixlen == 0:
            destination = "default"
        elif network.version == 4:
            destination = "%s %s" % (network.network_address, network.netmask)
        else:
            destination = str(network)
        added.append("configure iproute add %s %s%s" % (destination, state["gateway"],
                                                         "" if vr == DEFAULT_VR else " vr " + vr))
    elif state is not None:
        vlan, vrid = vrrp_key(key)
        base = "vrrp vlan %s vrid %s" % (vlan, vrid)
        added.append("create " + base)
        if "priority" in state:
            added.append("configure %s priority %s" % (base, state["priority"]))
        if "virtual-ip" in state:
            added.append("configure %s add %s" % (base, state["virtual-ip"]))
        if state.get("admin-state", ENABLED) == ENABLED:
            added.append("enable " + base)
    module = "rtmgr" if table == ROUTE_TABLE else "vrrp"
    return "\n".join(membership.modular(snapshot, kept, added, module=module)) + "\n"


def l3_changed(table: str, before, after) -> bool:
    if table in STATE_TABLES:
        return True
    return table == "vlan" and any((before or {}).get(name) != (after or {}).get(name) for name in L3_ATTRIBUTES)


DHCP_RELAY = "bootprelay"
DHCP_SERVER = "dhcp-server"
DHCP_TABLES = (DHCP_RELAY, DHCP_SERVER)
DHCP_MODULE = "netTools"
DHCP_RANGE = ("range-start", "range-end")
DHCP_OPTIONS = {"default-gateway": "default-gateway", "primary-dns": "dns-server primary",
                "secondary-dns": "dns-server secondary"}


def dhcp_refusal(reason, code="exos_dhcp_scope"):
    return Rejected([reason], reason_codes=[code])


def dhcp_statement(command):
    """Return table, VLAN and configured values. Unknown forms still own their VLAN's DHCP state."""
    t = command.tokens
    if command.module != DHCP_MODULE or command.upm_profile:
        return None
    if t[:3] == ("configure", "bootprelay", "vlan") and len(t) >= 4:
        values = {"server-ip": t[5]} if len(t) == 6 and t[4] == "add" else None
        return DHCP_RELAY, t[3], values
    if t[1:4] == ("bootprelay", "ipv4", "vlan") and len(t) == 5:
        return DHCP_RELAY, t[4], {"enabled": True} if t[0] == "enable" else None
    if t[:2] == ("configure", "vlan") and len(t) >= 4 and t[3].startswith("dhcp-"):
        values = None
        if t[3] == "dhcp-address-range" and len(t) == 7 and t[5] == "-":
            values = dict(zip(DHCP_RANGE, (t[4], t[6])))
        elif t[3] == "dhcp-lease-timer" and len(t) == 5:
            values = {"lease-seconds": t[4]}
        elif t[3] == "dhcp-options" and len(t) >= 6:
            option = ("dns-server primary" if t[4:-1] == ("dns-server",) else " ".join(t[4:-1]))
            values = next(({name: t[-1]} for name, cli in DHCP_OPTIONS.items() if cli == option), None)
        return DHCP_SERVER, t[2], values
    if t[1:3] == ("dhcp", "ports") and len(t) == 6 and t[4] == "vlan":
        values = {"ports": " ".join(sorted(membership.ports(t[3])))} if t[0] == "enable" else None
        return DHCP_SERVER, t[5], values
    return None


def dhcp_entries(snapshot, table):
    if DHCP_MODULE not in snapshot.configuration.modules:
        raise dhcp_refusal("the configuration has no netTools module", "exos_dhcp_readback_unreadable")
    result = {name: Entry(name) for name in (*snapshot.vlans, "Default", "Mgmt")}
    for command in snapshot.commands:
        try:
            statement = dhcp_statement(command)
        except ValueError:
            raise dhcp_refusal("DHCP port list cannot be decoded", "exos_dhcp_readback_unreadable") from None
        if statement is None or statement[0] != table:
            continue
        _, vlan, values = statement
        item = next((entry for name, entry in result.items() if name.casefold() == vlan.casefold()), None)
        if item is None:
            raise dhcp_refusal("DHCP configuration references an unknown VLAN", "exos_dhcp_readback_unreadable")
        try:
            for name, value in (values or {}).items():
                if name in (*DHCP_RANGE, *DHCP_OPTIONS, "server-ip"):
                    ipaddress.IPv4Address(value)
                if name == "lease-seconds" and not (value.isdecimal() and 3 <= int(value) <= 4294967295):
                    raise ValueError("invalid lease")
        except ValueError:
            values = None
        if values is None or item.attributes.keys() & values.keys():
            item.unsupported.append("line %d: unsupported or repeated DHCP setting" % command.line)
        else:
            item.attributes.update(values)
    if table == DHCP_RELAY:
        for item in result.values():
            enabled = item.attributes.pop("enabled", False)
            if enabled != ("server-ip" in item.attributes):
                item.unsupported.append("the VLAN does not have exactly one independently readable relay target")
    return result


def dhcp_owned(command, table, vlan):
    statement = dhcp_statement(command)
    return statement is not None and statement[0] == table and statement[1].casefold() == vlan.casefold()


def dhcp_vlan_ports(snapshot, vlan):
    _, members, _ = membership.model(snapshot)
    return {port for port, modes in members.items()
            if any(name.casefold() == vlan.casefold() for names in modes.values() for name in names)}


def validate_dhcp(snapshot, table, vlan, before, after, protected, *, impact, undo):
    other = DHCP_SERVER if table == DHCP_RELAY else DHCP_RELAY
    peer = next(entry for name, entry in dhcp_entries(snapshot, other).items() if name.casefold() == vlan.casefold())
    if peer.attributes or peer.unsupported:
        raise dhcp_refusal("the VLAN already has a conflicting DHCP server or relay", "exos_dhcp_conflict")
    # The scoped IPv4 readback must agree with the configuration. Other relay forms on
    # this VLAN (including IPv6) or a trusted external DHCP server are outside this profile.
    for command in snapshot.commands:
        t = tuple(token.casefold() for token in command.tokens)
        if vlan.casefold() in t and (
            (t[1:2] == ("bootprelay",) and not dhcp_owned(command, DHCP_RELAY, vlan))
            or t[:3] in (("enable", "bootp", "vlan"), ("enable", "dhcp", "vlan"))
            or "trusted-servers" in t and "dhcp-server" in t
        ):
            raise dhcp_refusal("the VLAN names a DHCP or relay setting outside this profile", "exos_dhcp_conflict")
    if vlan.casefold() in {name.casefold() for name in protected.get("vlan", ())}:
        raise dhcp_refusal("the VLAN is protected")
    if table == DHCP_RELAY and any(
        command.tokens[:3] == ("configure", "bootprelay", "add")
        or command.tokens[:4] == ("configure", "bootprelay", "ipv4", "add")
        for command in snapshot.commands if command.module == DHCP_MODULE
    ):
        raise dhcp_refusal("a VR-wide IPv4 relay target could apply to this VLAN", "exos_dhcp_conflict")
    if (before and not undo or vlan.casefold() in ("default", "mgmt")) and not impact:
        raise dhcp_refusal("endpoint_impact must explicitly name the VLAN", "endpoint_impact_required")
    scope = dhcp_vlan_ports(snapshot, vlan)
    if scope.intersection(protected.get("ports", ())):
        raise dhcp_refusal("a member port of the VLAN is protected", "port_protected")
    if not after and table == DHCP_RELAY:
        return
    interfaces = [ip for name, state in vlan_interfaces(snapshot).items() if name.casefold() == vlan.casefold()
                  for ip in state["ipv4"]]
    if len(interfaces) != 1:
        raise dhcp_refusal("the VLAN needs an unambiguous IPv4 subnet")
    if table == DHCP_RELAY:
        entry = snapshot._entry(vlan)
        if entry is None or entry.attributes.get("ipforwarding") != "enabled":
            raise dhcp_refusal("IPv4 forwarding must be enabled on the relay VLAN")
        target = ipaddress.IPv4Address(after["server-ip"])
        if target.is_unspecified or target.is_multicast or target.is_loopback or target == interfaces[0].ip:
            raise dhcp_refusal("the relay target must be a usable IPv4 server address")
        return
    for state in (before, after):
        if not state:
            continue
        if not set(DHCP_RANGE) <= state.keys():
            raise dhcp_refusal("a DHCP server configuration needs both range endpoints")
        first, last = (ipaddress.IPv4Address(state[key]) for key in DHCP_RANGE)
        interface = interfaces[0]
        subnet = interface.network
        if not (subnet.network_address < first <= last < subnet.broadcast_address) or first <= interface.ip <= last:
            raise dhcp_refusal("the DHCP range must be inside the VLAN subnet and exclude its own address")
        gateway = state.get("default-gateway")
        if gateway is not None:
            address = ipaddress.IPv4Address(gateway)
            if not subnet.network_address < address < subnet.broadcast_address or first <= address <= last:
                raise dhcp_refusal("the default gateway must be within the subnet and outside the DHCP range")
        ports = set(state.get("ports", "").split())
        if ports - scope or ports & membership.lag_ports(snapshot):
            raise dhcp_refusal("DHCP ports must be standalone ports in the selected VLAN")
    if before and after and ("lease-seconds" in before) != ("lease-seconds" in after):
        raise dhcp_refusal("resetting a DHCP lease to its default would also clear the existing pool",
                           "exos_dhcp_inverse_unsupported")


def render_dhcp(table, vlan, before, after):
    if table == DHCP_RELAY:
        old, new = before.get("server-ip"), after.get("server-ip")
        if old == new:
            return []
        lines = [f"configure bootprelay vlan {vlan} add {new}"] if new else []
        if new and not old:
            lines.append(f"enable bootprelay ipv4 vlan {vlan}")
        if old:
            if not new:
                lines.append(f"disable bootprelay ipv4 vlan {vlan}")
            lines.append(f"configure bootprelay vlan {vlan} delete {old}")
        return lines
    old_ports, new_ports = (set(state.get("ports", "").split()) for state in (before, after))
    removed = ",".join(sorted(old_ports - new_ports, key=port_order))
    added = ",".join(sorted(new_ports - old_ports, key=port_order))
    lines = [f"disable dhcp ports {removed} vlan {vlan}"] if removed else []
    if not after and "lease-seconds" in before:
        return lines + [f"unconfigure vlan {vlan} dhcp"]
    prefix = f"configure vlan {vlan} "
    unset = "un" + prefix
    if any(before.get(attr) != after.get(attr) for attr in DHCP_RANGE):
        lines += ([prefix + f"dhcp-address-range {after['range-start']} - {after['range-end']}"] if after else
                  [unset + "dhcp-address-range"])
    if "lease-seconds" in after and before.get("lease-seconds") != after["lease-seconds"]:
        lines.append(prefix + "dhcp-lease-timer " + after["lease-seconds"])
    for attr, option in DHCP_OPTIONS.items():
        if before.get(attr) == after.get(attr):
            continue
        if attr in after:
            lines.append(prefix + f"dhcp-options {option} {after[attr]}")
        else:
            lines.append(unset + "dhcp-options " + option)
    if added:
        lines.append(f"enable dhcp ports {added} vlan {vlan}")
    return lines


def dhcp_prediction(snapshot, table, vlan, state):
    kept = [command for command in snapshot.commands if not dhcp_owned(command, table, vlan)]
    added = render_dhcp(table, vlan, {}, state)
    if table == DHCP_RELAY:
        added.reverse()  # EXOS prints enable before the target.
    else:
        added = [line.replace(" dhcp-options dns-server primary ", " dhcp-options dns-server ") for line in added]
    return "\n".join(membership.modular(snapshot, kept, added, module=DHCP_MODULE)) + "\n"
