"""Ruckus Unleashed planning adapter of the common Admin engine (engine.ADAPTERS["ruckus"]), 1.0.12 wireless wlans and wireless dhcp.

The snapshot is not a configuration export (Unleashed has no CLI command that prints the whole configuration to a
write account in a parseable form): Admin composes it from the identity of ``show sysinfo`` and the WLAN listing of
``show wlan all`` with every secret line removed and the WLAN group memberships from ``show config`` (see
``exec_ruckus.snapshot``). The table ``wlan`` is keyed by the WLAN name; Admin writes only the SSID, the
description, the client VLAN and the service state of a WLAN, and
creates a WLAN only with WPA2 and a passphrase generated at the moment of the write (never part of a plan).
The rest digest covers every other WLAN as the device lists it, so a change outside the planned WLAN is seen.

1.0.12 wireless dhcp adds to the table ``wlan`` the WPA2/WPA3 mode with the passphrase of a vault reference or an enterprise
(802.1X) authentication server (R06), the L2/L3 ACL, the client isolation per AP (R22), the client limit and the
per-client and per-WLAN rate limits (R24), and the table ``dhcp-relay`` for the DHCP relay server entries (R23).
A passphrase is never part of a plan: the plan holds the name of the vault entry and the privileged transport
resolves it when it types the line (exec_ruckus.resolve).
"""
from __future__ import annotations

import hashlib
import json
import re

from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected
from netops_admin.request import canonical_value

TABLE = "wlan"
HEADER = "#netops-ruckus-snapshot firmware="
GROUPS_HEADER = "\n#netops-ruckus-wlan-groups "
DEFAULT_GROUP = "System Default"
GROUP_BLOCK = re.compile(r"(?m)^    ([1-9][0-9]*):\n      Name=[ \t]*(\S[^\n]*)\n"
                         r"      Description=[^\n]*\n      WLAN Service:$")
GROUP_MEMBER = re.compile(r"(?m)^        WLAN([1-9][0-9]*):\n          NAME=[ \t]*(\S[^\n]*)\n"
                          r"          VLAN=[ \t]*([0-9]*)$")
FIRMWARE = re.compile(r"[0-9]+(?:\.[0-9]+){2,4} build [0-9]+")
LISTING_HEAD = "WLAN Service:"
BLOCK = re.compile(r"^ {4}([0-9]+):[ \t]*$")
LINE = re.compile(r"^ {6}([A-Za-z0-9][^=]*?)[ \t]*=[ \t]?(.*)$")
TERMINAL_CONTROLS = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|(?:\x1b\]|\x9d)[^\x07\x1b\x80-\x9f\r\n]*(?:\x07|\x1b\\|\x9c)"
    r"|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x80-\x9f\r\n]*(?:\x1b\\|\x9c)"
    r"|\x1b[ -/]*[0-~]"
    r"|[\x00-\x08\x0b-\x1f\x7f-\x9f]"
)
SECRET_LINE = re.compile(r"(?i)^(\s*[^=:\n]*\b(?:passphrase|password|passwd|secret|psk|key|token)\b[^=:\n]*[=:])[ \t]*(\S.*)$")
DYNAMIC_PSK_DISABLED = re.compile(r"^\s*Dynamic PSK\s*=\s*Disabled\s*$")
REDACTED = "<redacted>"
# the mark of the passphrase in the commands of a plan; the write replaces it with a passphrase it generates and
# forgets, so no plan, journal or audit record holds a passphrase
PASSPHRASE_TOKEN = "<generated-passphrase>"
# device names of the attributes of the profile (ruckus-wlan.json) in the WLAN listing
FIELDS = {"ssid": "SSID", "description": "Description", "vlan": "VLAN-ID", "service": "Service"}
SECURITY_FIELDS = {"authentication": "Authentication", "encryption": "Encryption"}
CREATE_SECURITY = {"authentication": "open", "encryption": "wpa2"}
PSK_COMMANDS = {
    "wpa2": "open wpa2 passphrase %s algorithm aes" % PASSPHRASE_TOKEN,
    "wpa3": "open wpa3 passphrase %s algorithm aes" % PASSPHRASE_TOKEN,
}
# 1.0.12 wireless dhcp: attributes of a WLAN beyond the wireless wlans ones, with the device lines they are read from
AUTH_VALUES = {"open": "open", "802.1x-eap": "dot1x"}
SECURITY_MODES = ("wpa2", "wpa3")
SECURITY_GROUP = ("authentication", "encryption", "auth-server", "passphrase-ref")
# a write-only attribute is never readable on the device and so never part of a stored state
WRITE_ONLY = ("passphrase-ref",)
PASSPHRASE_REF_PREFIX = "<vault-passphrase:"
PASSPHRASE_REF = re.compile(r"^WLAN_PSK_[A-Z0-9_]{1,48}$")
LIMIT_FIELDS = {"max-clients": "Max. Clients", "isolation-ap": "Isolation per AP",
                "rate-perssid-uplink": "PerSSID Rate Limiting Uplink",
                "rate-perssid-downlink": "PerSSID Rate Limiting Downlink",
                "rate-uplink": "Rate Limiting Uplink", "rate-downlink": "Rate Limiting Downlink"}
ACL_FIELDS = {"l2acl": "L2/MAC", "l3acl": "L3/L4/IP Address"}
NO_ACL = "No ACLS"
G112_ATTRIBUTES = frozenset((*LIMIT_FIELDS, *ACL_FIELDS, *SECURITY_GROUP))
RATE = re.compile(r"^([0-9]+)\.00Mbps$")
WHOLE = re.compile(r"^[0-9]{1,4}$")
# 1.0.12 wireless dhcp R23: DHCP relay server entries (`show dhcp all`, `dhcp <name>`, `first`, `second`)
RELAY_TABLE = "dhcp-relay"
DHCP_HEADER = "\n#netops-ruckus-dhcp\n"
DHCP_HEAD = "DHCP servers for DHCP relay agent:"
RELAY_BLOCK = re.compile(r"^ {4}([0-9]+):$")
RELAY_LINE = re.compile(r"^ {6}(Name|Description|IP Address)=[ \t]?(.*?)[ \t]*$")
CHANGED_PASSPHRASE = ("The change was returned with a newly generated WLAN passphrase. Set the real passphrase in the"
                      " Unleashed web interface and update the clients' passphrase.")
NEW_PASSPHRASE = ("The WLAN was recreated with a new passphrase. Set it in the Unleashed web interface before enabling"
                  " the WLAN and update the clients' passphrase.")
CREATED_PASSPHRASE = ("Admin generated a new WLAN passphrase. Set it in the Unleashed web interface and configure it"
                      " on the clients before enabling the WLAN.")
UNVERIFIED_PASSPHRASE = "The stored WLAN passphrase could not be verified. The new passphrase may still be installed."
SERVICE = {"enabled": "enabled", "disabled": "disabled"}
ORDER = ("ssid", "description", "vlan", "service")
DEFAULT_VLAN = "1"
# Defaults recorded for a new Standard Usage WLAN on R610 200.15.6.212 build 27.
# Keep nested rows and unparsed lines in the comparison so unknown settings fail closed.
DEFAULT_OTHER_ROWS = """\
Tx. Rate of Management Frame(2.4GHz) = 2.0Mbps
Tx. Rate of Management Frame(5GHz)   = 6.0Mbps
Beacon Interval = 100ms
FT Roaming = Disabled
802.11k Neighbor report = Enabled
Web Authentication = Disabled
Authentication Server = Disabled
Accounting Server = Disabled
Called-Station-Id type = wlan-bssid
Tunnel Mode = Disabled
DHCP relay = Disabled
Background Scanning = Enabled
Max. Clients = 100
Isolation per AP = Disabled
Isolation across AP = Disabled
Zero-IT Activation = Disabled
Priority = High
Load Balancing = Disabled
Band Balancing = Disabled
Wifi6 = Disabled
Rate Limiting Uplink = Disabled
PerSSID Rate Limiting Uplink = 0
Rate Limiting Downlink = Disabled
PerSSID Rate Limiting Downlink = 0
Auto-Proxy configuration:
  Status = Disabled
Inactivity Timeout:
    Status = Enabled
    Timeout = 5 Minutes
Dynamic VLAN = Disabled
Closed System = Disabled
Https Redirection = Disabled
OFDM-Only State = Disabled
Multicast Filter State = Disabled
Directed Multicast= Enabled
802.11d State = Disabled
Force DHCP State = Disabled
Force DHCP Timeout = 10
DHCP Option82:
    Status = Disabled
    Option82 sub-Option1 = Disabled
    Option82 sub-Option2 = Disabled
    Option82 sub-Option150 = Disabled
    Option82 sub-Option151 = Disabled
Ignore unauthorized client statistic = Disabled
STA Info Extraction State = Enabled
BSS Minrate = Disabled
DTIM period = 1
Directed MC/BC Threshold = 5
Call Admission Control State = Disabled
PMK Cache Timeout= 720 minutes
PMK Cache for Reconnect= Enabled
NAS-ID Type= wlan-bssid
Roaming Acct-Interim-Update= Disabled
PAP Message Authenticator = Enabled
Send EAP-Failure = Disabled
L2/MAC = No ACLS
L3/L4/IP Address = No ACLS
L3/L4/IPv6 Address = No ACLS
Precedence = Default
Proxy ARP = Disabled
Device Policy = No ACLS
Vlan Pool = No Pools
Role based Access Control Policy = Disabled
SmartRoam = Disabled  Roam-factor = 1
Allow List = No ACLS
URL Filtering = Disabled
Application Recognition & Control = Disabled
Client Flow Data Logging = Disabled
Wlan Bind = all
Client Connection Data = Disabled
Transient Client Management = Disabled
""".splitlines()
RECREATED_FIELDS = {*FIELDS.values(), *SECURITY_FIELDS.values(), "NAME", "Type", "Algorithm", "Passphrase",
                    "Dynamic PSK", "80211w-pmf", "SAE anti-clogging-threshold"}


class Entry:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.unsupported = []
        self.lines = []


def strip_terminal_controls(text: str) -> str:
    """Remove terminal escapes and control characters, preserving newlines and tabs."""
    return TERMINAL_CONTROLS.sub("", text)


def redact(text: str) -> str:
    """The listing without the value of any line that names a passphrase, key, secret or similar."""
    return "\n".join(line if DYNAMIC_PSK_DISABLED.fullmatch(line)
                     else SECRET_LINE.sub(lambda found: "%s %s" % (found.group(1), REDACTED), line)
                     for line in strip_terminal_controls(text).split("\n"))


def sysinfo_firmware(text: str) -> str:
    found = re.findall(r"(?m)^[ \t]*Version[ \t]*=[ \t]*(.*?)[ \t]*$", text.replace("\r", ""))
    if len(found) != 1 or FIRMWARE.fullmatch(found[0]) is None:
        raise Rejected(["the device does not report one Unleashed firmware version"])
    return found[0]


def sysinfo_model(text: str):
    found = re.findall(r"(?m)^[ \t]*Model[ \t]*=[ \t]*(.*?)[ \t]*$", text.replace("\r", ""))
    return found[0].lower() if len(found) == 1 and found[0] else None


def read_group_memberships(config: str) -> dict | None:
    """Read the entire WLAN Group section of show config, retaining only names and VLAN overrides."""
    header = "\nWLAN Group:\n"
    if config.count(header) != 1:
        return None
    section, terminator, tail = config.partition(header)[2].partition("\nVenue:")
    if not terminator or (tail and not tail.startswith("\n")):
        return None
    section = "\n".join(line.rstrip() for line in section.splitlines() if line.strip())
    prefix, *groups = GROUP_BLOCK.split(section)
    if prefix != "  ID:\n" or not groups:
        return None

    memberships = {}
    group_ids = set()
    group_names = set()
    for number, name, rows in zip(groups[::3], groups[1::3], groups[2::3]):
        if number in group_ids or name.casefold() in group_names:
            return None
        if name == DEFAULT_GROUP and number != "1":
            return None
        group_ids.add(number)
        group_names.add(name.casefold())
        members = {}
        member_ids = set()
        position = 0
        for member in GROUP_MEMBER.finditer(rows):
            index, wlan, vlan = member.groups()
            key = wlan.casefold()
            if rows[position:member.start()].strip() or index in member_ids or key in members:
                return None
            member_ids.add(index)
            members[key] = vlan
            position = member.end()
        if rows[position:].strip():
            return None
        memberships[name] = members
    return memberships


def _load_group_memberships(text: str) -> dict | None:
    try:
        groups = json.loads(text)
    except ValueError:
        return None
    if not isinstance(groups, dict) or DEFAULT_GROUP not in groups:
        return None
    if any(not isinstance(members, dict) or any(not isinstance(vlan, str) for vlan in members.values())
           for members in groups.values()):
        return None
    return groups


def parse_relays(text: str) -> dict | None:
    """`show dhcp all` of the privileged mode: the relay entries by name, or None when the listing is not complete
    (an unknown line, a missing name, a third server address)."""
    rows = [line.rstrip() for line in text.replace("\r", "").split("\n") if line.strip()]
    if not rows or rows[0].strip() != DHCP_HEAD:
        return None
    rows = rows[1:]
    if rows and rows[0].strip() == "ID:":
        rows = rows[1:]
    relays, current = {}, None
    for row in rows:
        if RELAY_BLOCK.match(row):
            current = {"name": None, "description": "", "addresses": []}
            relays[len(relays)] = current
            continue
        found = RELAY_LINE.match(row)
        if current is None or found is None:
            return None
        field, value = found.groups()
        if field == "IP Address":
            current["addresses"].append(value)
        elif field == "Name" and current["name"] is None:
            current["name"] = value
        elif field == "Description" and not current["description"]:
            current["description"] = value
        else:
            return None
    named = {}
    for current in relays.values():
        addresses = current["addresses"]
        if not current["name"] or not 1 <= len(addresses) <= 2 or not addresses[0] or current["name"] in named:
            return None
        named[current["name"]] = {"first": addresses[0], "second": addresses[1] if len(addresses) == 2 else "",
                                  "description": current["description"]}
    return named


class Snapshot:
    def __init__(self, text: str, firmware: str | None, composed: bool = True):
        self.group_memberships = None
        self.relays = None
        if composed:
            text, marker, groups = text.partition(GROUPS_HEADER)
            if marker:
                self.group_memberships = _load_group_memberships(groups)
            text, marker, dhcp = text.partition(DHCP_HEADER)
            if marker:
                self.relays = parse_relays(dhcp)
        lines = text.replace("\r", "").split("\n")
        if composed:
            if not lines or not lines[0].startswith(HEADER) or not FIRMWARE.fullmatch(lines[0][len(HEADER):]):
                raise SnapshotRejected(["snapshot is not a Ruckus Unleashed Admin snapshot (no firmware line)"],
                                       SNAPSHOT_UNREADABLE)
            self.firmware = lines[0][len(HEADER):]
            lines = lines[1:]
            if firmware and firmware != self.firmware:
                raise Rejected(["the Unleashed runs %s, not the configured %s" % (self.firmware, firmware)])
        else:
            self.firmware = None
        self.inventory = None
        self.blocks = {}
        self._parse(lines)

    def _parse(self, lines) -> None:
        body = [line for line in lines if line.strip()]
        if len(body) < 2 or body[0].strip() != LISTING_HEAD or body[1].strip() != "ID:":
            raise SnapshotRejected(["snapshot holds no WLAN listing; it is not a complete Unleashed snapshot"],
                                   SNAPSHOT_INCOMPLETE)
        current = None
        for raw in body[2:]:
            line = raw.rstrip()
            opened = BLOCK.match(line)
            if opened:
                current = {"id": opened.group(1), "lines": [], "values": {}}
                self.blocks.setdefault("\0order", []).append(current)
                continue
            if current is None:
                raise SnapshotRejected(["snapshot does not parse: a line outside a WLAN block"], SNAPSHOT_UNREADABLE)
            current["lines"].append(line)
            found = LINE.match(raw)
            if found:
                field, value = found.groups()
                if field in current["values"]:
                    raise SnapshotRejected(["snapshot lists %s twice in a WLAN" % field], SNAPSHOT_UNREADABLE)
                current["values"][field] = value if field == "Description" else value.strip()
        order = self.blocks.pop("\0order", [])
        self.wlans = {}
        for block in order:
            values = block["values"]
            missing = [name for name in ("NAME", "SSID", "Service", "VLAN-ID", *SECURITY_FIELDS.values())
                       if name not in values or not values[name]]
            if missing or not values.get("NAME"):
                raise SnapshotRejected(["snapshot is incomplete: WLAN %s has no %s" % (block["id"], ", ".join(missing or ["NAME"]))],
                                       SNAPSHOT_INCOMPLETE)
            name = values["NAME"]
            if name in self.wlans:
                raise SnapshotRejected(["snapshot lists WLAN %s twice" % name], SNAPSHOT_UNREADABLE)
            self.wlans[name] = block

    def entries(self, table: str):
        if table == RELAY_TABLE:
            return self._relay_entries()
        if table != TABLE:
            return None
        entries = {}
        for name, block in self.wlans.items():
            entry = Entry(name)
            values = block["values"]
            entry.attributes = {"ssid": values["SSID"], "vlan": values["VLAN-ID"],
                                "service": values["Service"].lower()}
            entry.attributes.update({name: values[field].lower() for name, field in SECURITY_FIELDS.items()})
            entry.attributes["authentication"] = AUTH_VALUES.get(values["Authentication"].lower(),
                                                                 entry.attributes["authentication"])
            if values.get("Description", ""):
                entry.attributes["description"] = values["Description"]
            if entry.attributes["service"] not in SERVICE:
                entry.unsupported.append("service %s" % values["Service"])
            self._g112_state(entry, values)
            entry.lines = block["lines"]
            entries[name] = entry
        return entries

    @staticmethod
    def _g112_state(entry, values) -> None:
        """1.0.12 wireless dhcp: the ACLs, limits and enterprise server the listing shows. A value the profile cannot write back
        (a fractional rate, an unknown rate line) is outside the profile, so the WLAN is not changed blindly."""
        attributes = entry.attributes
        for name, field in LIMIT_FIELDS.items():
            value = values.get(field)
            if value is None:
                continue
            if name == "isolation-ap":
                if value.lower() == "enabled":
                    attributes[name] = "enabled"
                elif value.lower() != "disabled":
                    entry.unsupported.append("%s %s" % (field, value))
            elif name in ("rate-uplink", "rate-downlink"):
                found = RATE.fullmatch(value)
                if value == "Disabled":
                    continue
                if found:
                    attributes[name] = str(int(found.group(1)))
                else:
                    entry.unsupported.append("%s %s" % (field, value))
            elif WHOLE.fullmatch(value):
                if value != G112_REMOVE[name]:  # a default is not part of the state (like VLAN 1)
                    attributes[name] = value
            else:
                entry.unsupported.append("%s %s" % (field, value))
        for name, field in ACL_FIELDS.items():
            value = values.get(field)
            if value is not None and value != NO_ACL:
                attributes[name] = value
        server = values.get("Authentication Server")
        if attributes["authentication"] == "dot1x" and server not in (None, "Disabled"):
            attributes["auth-server"] = server

    def _relay_entries(self):
        if self.relays is None:
            return None
        entries = {}
        for name, relay in self.relays.items():
            entry = Entry(name)
            entry.attributes = {"first": relay["first"]}
            for field in ("second", "description"):
                if relay[field]:
                    entry.attributes[field] = relay[field]
            entries[name] = entry
        return entries

    def relay_wlans(self) -> list:
        """WLANs the listing shows with an enabled DHCP relay (the line exists only on WLANs created after wireless wlans)."""
        return sorted(name for name, block in self.wlans.items()
                      if block["values"].get("DHCP relay", "Disabled") != "Disabled")

    def entry_state(self, entry, lists=()):
        return dict(entry.attributes), list(entry.unsupported)

    def references(self, table: str, key: str) -> list:
        return []

    def in_use(self, key: str) -> bool:
        return any(name.casefold() == key.casefold() for name in self.wlans)

    def ssids(self) -> dict:
        return {name: block["values"]["SSID"] for name, block in self.wlans.items()}

    def rest_digest(self, table: str, key: str, safeguard_id=None, *, legacy=False) -> str:
        rows = []
        if table == RELAY_TABLE:
            # a relay entry is planned against the whole WLAN listing and every other relay entry
            for name in sorted(self.relays or {}):
                if name != key:
                    rows.append("RELAY %s %s" % (name, json.dumps(self.relays[name], sort_keys=True)))
            key = None
        for name in sorted(self.wlans):
            if name == key:
                continue
            rows.append("WLAN %s" % name)
            for line in self.wlans[name]["lines"]:
                if legacy and DYNAMIC_PSK_DISABLED.fullmatch(line):
                    line = SECRET_LINE.sub(lambda found: "%s %s" % (found.group(1), REDACTED), line)
                rows.append(line)
        return hashlib.sha256(("%s\n" % self.firmware + "\n".join(rows)).encode("utf-8")).hexdigest()


def load(text: str, firmware: str | None) -> Snapshot:
    return Snapshot(text, firmware)


def parse_listing(text: str) -> Snapshot:
    """The WLAN listing alone (what the check account reads), parsed like a snapshot."""
    return Snapshot(text, None, composed=False)


def absent(snapshot, table: str, key: str) -> list:
    return ["WLAN %s is not configured" % key]


def _context(key: str) -> list:
    return ["config", "wlan %s" % key]


def _description(profile, value: str) -> str:
    # Validate values from the snapshot too, because the inverse writes them back as CLI input.
    value = canonical_value(profile.attributes["description"], value, profile.platform)
    return 'description "%s"' % value


def render_create(profile, key: str, attributes: dict) -> list:
    if profile.table == RELAY_TABLE:
        return render_relay_state(key, attributes, replace=False)
    lines = _context(key) + ["type standard-usage", "ssid %s" % attributes["ssid"],
                             PSK_COMMANDS[attributes.get("encryption", CREATE_SECURITY["encryption"])]]
    if "description" in attributes:
        lines.append(_description(profile, attributes["description"]))
    if "vlan" in attributes:
        lines.append("vlan %s" % attributes["vlan"])
    lines.append("service" if attributes.get("service") == "enabled" else "no service")
    return lines + ["end", "exit"]


def _security_line(assign: dict, remove: list) -> list:
    """The one line that sets the authentication and encryption of a WLAN, or None when the request leaves them as
    they are (with the PMF line of WPA2: measured, the device keeps 802.11w PMF "Required" after a WPA3 mode until it is
    set back). A passphrase line carries the vault reference (resolved when the line is typed) or, for the inverse of a
    change, the mark of a passphrase generated at the write."""
    auth, mode, ref = assign.get("authentication"), assign.get("encryption"), assign.get("passphrase-ref")
    line = None
    if ref is not None:
        if mode not in SECURITY_MODES:
            raise Rejected(["a passphrase reference needs encryption wpa2 or wpa3 in the same request"])
        line = "open %s passphrase %s%s> algorithm aes" % (mode, PASSPHRASE_REF_PREFIX, ref)
    elif auth == "dot1x":
        server = assign.get("auth-server")
        if mode not in SECURITY_MODES or not server:
            raise Rejected(["enterprise authentication needs encryption wpa2 or wpa3 and auth-server in the same request"])
        line = "dot1x %s algorithm AES auth-server name %s" % (mode, server)
    elif auth == "open" and mode in SECURITY_MODES and "passphrase-ref" in remove:
        line = PSK_COMMANDS[mode]
    if line is None:
        return []
    return [line, "80211w-pmf 0"] if mode == "wpa2" else [line]


def _rate_lines(assign: dict, remove: list) -> list:
    uplink, downlink = assign.get("rate-uplink"), assign.get("rate-downlink")
    if uplink is not None and downlink is not None:
        return ["rate-limit uplink %s downlink %s" % (uplink, downlink)]
    if "rate-uplink" in remove and "rate-downlink" in remove:
        return ["no rate-limit"]
    if uplink is not None or downlink is not None or "rate-uplink" in remove or "rate-downlink" in remove:
        raise Rejected(["the per-client rate limits rate-uplink and rate-downlink are set or removed together"])
    return []


def render_relay_state(key: str, state: dict, *, replace: bool = True) -> list:
    """The firmware refuses in-place saves (cli_dhcp_update.out). Delete only when replacing an existing profile."""
    lines = ["config"]
    if replace:
        lines.append("no dhcp %s" % key)
    lines.extend(["dhcp %s" % key, "first %s" % state["first"]])
    if "second" in state:
        lines.append("second %s" % state["second"])
    if "description" in state:
        lines.append("description %s" % state["description"])
    return lines + ["end", "exit"]


def render_update(profile, key: str, assign: dict, remove: list) -> list:
    if profile.table == RELAY_TABLE:
        return []  # the engine renders a relay entry from its whole state (render_relay_state)
    lines = []
    lines.extend(_security_line(assign, remove))
    for name in ORDER:
        if name not in assign:
            continue
        value = assign[name]
        if name == "service":
            lines.append("service" if value == "enabled" else "no service")
        elif name == "description":
            lines.append(_description(profile, value))
        else:
            lines.append("%s %s" % (name, value))
    for name in remove:
        # an attribute that is back to its default: the VLAN returns to 1, the service to enabled
        if name == "vlan":
            lines.append("vlan %s" % DEFAULT_VLAN)
        elif name == "service":
            lines.append("service")
        elif name == "description":
            lines.append('description ""')
        elif name in G112_REMOVE or name in SECURITY_GROUP or name in ("rate-uplink", "rate-downlink"):
            continue  # rendered below (defaults, ACLs, security) or by the security line
        else:
            raise Rejected(["attribute %s cannot be removed" % name])
    lines.extend(_g112_lines(assign, remove))
    return _context(key) + lines + ["end", "exit"]


# the default a removed (or restored-to-default) wireless dhcp attribute returns to, and the line that sets it
G112_REMOVE = {"max-clients": "100", "isolation-ap": "disabled", "rate-perssid-uplink": "0",
               "rate-perssid-downlink": "0", "l2acl": None, "l3acl": None}


def _g112_lines(assign: dict, remove: list) -> list:
    lines = []
    wanted = {**{name: G112_REMOVE[name] for name in remove if name in G112_REMOVE and G112_REMOVE[name]},
              **{name: value for name, value in assign.items() if name in G112_REMOVE}}
    if "max-clients" in wanted:
        lines.append("max-clients %s" % wanted["max-clients"])
    if "isolation-ap" in wanted:
        lines.append("client-isolation isolation-on-ap %s" % ("enable" if wanted["isolation-ap"] == "enabled" else "disable"))
    for name, word in (("l2acl", "l2acl"), ("l3acl", "l3acl")):
        if name in assign:
            lines.append("acl %s %s" % (word, assign[name]))
        elif name in remove:
            lines.append("no %s" % word)
    for name, word in (("rate-perssid-uplink", "perssid_uplink"), ("rate-perssid-downlink", "perssid_downlink")):
        if name in wanted:
            lines.append("rate-limit %s %s" % (word, wanted[name]))
    lines.extend(_rate_lines(assign, remove))
    return lines


def render_delete(profile, key: str) -> list:
    if profile.table == RELAY_TABLE:
        return ["config", "no dhcp %s" % key, "exit"]
    return ["config", "no wlan %s" % key, "exit"]


def delete_refusal(reason: str) -> Rejected:
    return Rejected([reason], reason_codes=["wlan_delete_not_restorable"])


def require_group_membership(memberships: dict | None, key: str, *, present: bool) -> None:
    if memberships is None:
        raise delete_refusal("the WLAN group memberships could not be read completely")
    name = key.casefold()
    actual = {group: members[name] for group, members in memberships.items() if name in members}
    # R610 adds a new WLAN to System Default without an override. The inverse configures no other group settings.
    if present and actual != {DEFAULT_GROUP: ""}:
        raise delete_refusal("Admin can recreate only membership in System Default without a VLAN override")
    if not present and actual:
        raise delete_refusal("a WLAN group still refers to the deleted WLAN")


def restoration_security(state: dict) -> dict:
    if state.get("authentication") != "open" or state.get("encryption") not in PSK_COMMANDS:
        raise delete_refusal("the recorded WLAN security does not establish that Admin can recreate it")
    return {name: state[name] for name in SECURITY_FIELDS}


def _row(line: str) -> str:
    return re.sub(r"[ \t]*=[ \t]*", " = ", line).rstrip()


def require_restorable(snapshot: Snapshot, profile, entry: Entry) -> None:
    if entry.attributes["service"] != "disabled":
        raise delete_refusal("only a WLAN with service disabled is deleted; disable it first")
    security = restoration_security(entry.attributes)
    values = snapshot.wlans[entry.name]["values"]
    if (values.get("Type") != "Standard Usage" or values.get("Passphrase") != REDACTED
            or "Description" not in values
            or values.get("Authentication Server") != "Disabled" or values.get("Web Authentication") != "Disabled"):
        raise delete_refusal("delete requires a Standard Usage WLAN with a personal passphrase and no authentication server or guest access")
    mode = security["encryption"]
    if not _has_default_settings(entry, values, mode):
        raise delete_refusal("the WLAN has settings beyond the defaults Admin can recreate")
    require_group_membership(snapshot.group_memberships, entry.name, present=True)
    for name in ("ssid", "description", "vlan"):
        if name not in entry.attributes:
            continue
        value = entry.attributes[name]
        try:
            if canonical_value(profile.attributes[name], value, profile.platform) == value:
                continue
        except Rejected:
            pass
        raise delete_refusal("Admin cannot recreate the WLAN's %s as recorded" % name)


def _has_default_settings(entry: Entry, values: dict, mode: str) -> bool:
    security_defaults = {
        "Algorithm": "aes",
        "Dynamic PSK": "Disabled",
        "80211w-pmf": "Required" if mode == "wpa3" else "Disabled",
        "SAE anti-clogging-threshold": "5" if mode == "wpa3" else None,
    }
    if any(values.get(name) != value for name, value in security_defaults.items()):
        return False
    other_rows = []
    for line in entry.lines:
        found = LINE.fullmatch(line)
        if not found or found.group(1) not in RECREATED_FIELDS:
            other_rows.append(_row(line[6:]))
    return other_rows == list(map(_row, DEFAULT_OTHER_ROWS))


def _security_prechecks(snapshot, key: str, before, after, changes: dict) -> list:
    """1.0.12 wireless dhcp R06: the WPA2/WPA3 mode, the passphrase reference and the enterprise server of one WLAN."""
    named = [name for name in SECURITY_GROUP if name in changes]
    if not named:
        return []
    reasons = []
    if (before or {}).get("authentication") not in ("open", "dot1x") or (before or {}).get("encryption") not in SECURITY_MODES:
        return ["the WLAN security is not WPA2/WPA3 personal or enterprise; Admin changes only those"]
    pmf = snapshot.wlans[key]["values"].get("80211w-pmf") if key in snapshot.wlans else None
    if pmf != ("Required" if before["encryption"] == "wpa3" else "Disabled"):
        return ["the WLAN has its own 802.11w PMF setting (%s); Admin changes the security of a WLAN with the default of its"
                " mode only" % pmf]
    if "authentication" not in changes or "encryption" not in changes:
        reasons.append("a security change names authentication and encryption together")
    if changes.get("passphrase-ref") is not None and not PASSPHRASE_REF.fullmatch(changes["passphrase-ref"]):
        reasons.append("passphrase-ref must name a vault entry WLAN_PSK_<NAME>")
    auth, mode = changes.get("authentication"), changes.get("encryption")
    if auth == "dot1x":
        if not changes.get("auth-server"):
            reasons.append("enterprise authentication needs auth-server")
        if changes.get("passphrase-ref") is not None:
            reasons.append("an enterprise WLAN has no passphrase")
    elif auth == "open":
        if changes.get("auth-server") is not None:
            reasons.append("auth-server belongs to enterprise authentication")
        moved = before.get("authentication") != "open" or before.get("encryption") != mode
        if moved and "passphrase-ref" not in changes:
            reasons.append("a change to personal %s needs passphrase-ref" % (mode or "WPA"))
    return reasons


def prechecks(snapshot, profile, op: str, key: str, after, before=None, changes=None) -> list:
    reasons = []
    changes = changes or {}
    if profile.table == RELAY_TABLE:
        if op in ("update", "delete") and snapshot.relay_wlans():
            reasons.append("WLAN %s use a DHCP relay; the relay entry is not changed while one is enabled"
                           % ", ".join(snapshot.relay_wlans()))
        if after is not None and after.get("first") and after.get("first") == after.get("second"):
            reasons.append("the first and second DHCP relay server must differ")
        return reasons
    if op in ("create", "update") and after is not None:
        ssid = after.get("ssid")
        others = [name for name, value in snapshot.ssids().items() if name != key and value == ssid]
        if others:
            reasons.append("SSID %s is already configured on WLAN %s" % (ssid, ", ".join(sorted(others))))
    if op == "create" and (after or {}).get("service") != "disabled":
        reasons.append("a new WLAN is created with service disabled; enable it with a separate update")
    if op == "create" and G112_ATTRIBUTES & set(changes):
        reasons.append("a new WLAN is created with the supported creation attributes; change the other settings with an update")
    if op == "update" and after is not None:
        reasons.extend(_security_prechecks(snapshot, key, before, after, changes))
    return reasons


def inverse_names(before: dict, changes: dict) -> set:
    """The attributes the inverse of an update restores beyond the named ones: the enterprise server a change of the
    security leaves (the request need not name it for the inverse to type the whole enterprise line)."""
    if before.get("authentication") == "dot1x" and any(name in changes for name in SECURITY_GROUP):
        return {"authentication", "encryption", "auth-server"}
    return set()


def settle(after: dict) -> dict:
    """The predicted state of a WLAN as the listing can show it: a passphrase reference is write-only and the
    server of an enterprise WLAN is not listed once the WLAN is personal again (the device keeps the old name)."""
    state = {name: value for name, value in after.items() if name not in WRITE_ONLY}
    if state.get("authentication") != "dot1x":
        state.pop("auth-server", None)
    return state


def active_impact(before: dict, after: dict, changes: dict) -> bool:
    """Require explicit impact when changing settings that can affect clients of a broadcasting WLAN."""
    if before.get("service", "enabled") != "enabled":
        return False
    fields = G112_ATTRIBUTES | {"vlan", "ssid", "service"}
    return changes.get("passphrase-ref") is not None or any(before.get(name) != after.get(name) for name in fields)


def undo_changes(plan: dict, before: dict, after: dict, changes: dict) -> dict:
    """The changes of the undo of an update: the state differences plus, when the plan wrote a passphrase or changed the
    security, the whole security group (the passphrase cannot be restored: it is generated, see NEW_PASSPHRASE)."""
    if plan["table"] != TABLE or plan["op"] != "update":
        return changes
    wrote = any(PASSPHRASE_REF_PREFIX in command for command in plan["commands"])
    if wrote or any(name in changes for name in SECURITY_GROUP):
        for name in ("authentication", "encryption", "auth-server"):
            changes[name] = before.get(name)
        if before.get("authentication") == "open":
            changes["passphrase-ref"] = None  # the inverse types a generated passphrase
    if any(name in changes for name in ("rate-uplink", "rate-downlink")):
        for name in ("rate-uplink", "rate-downlink"):
            changes[name] = before.get(name)
    return changes


def writes_passphrase(plan: dict) -> bool:
    """True when the plan writes (or its inverse writes) a passphrase Admin does not know: the user sets the real one."""
    return plan["table"] == TABLE and any(
        PASSPHRASE_REF_PREFIX in command or PASSPHRASE_TOKEN in command
        for command in [*plan["commands"], *plan["inverse"]])


def passphrase_only(plan: dict) -> bool:
    return (plan["table"] == TABLE and plan["op"] == "update"
            and plan["predicted"]["before"] == plan["predicted"]["after"]
            and any(PASSPHRASE_REF_PREFIX in command or PASSPHRASE_TOKEN in command for command in plan["commands"]))
