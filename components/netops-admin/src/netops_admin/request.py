from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected
from netops_admin.jsontext import loads
from netops_admin.profiles import OPS
from netops_auditor import l1_fortios

REQUEST_OPS = (*OPS, "clear", "save")
MAX_REQUEST_BYTES = 16384
MAX_KEY_LENGTH = 128
MAX_CHANGES = 16
MAX_BATCH_STEPS = 32
BATCH = "batch"
FORTIOS_POLICY_MAX_CHANGES = 32
MAX_REASON = 500
MAX_USER_REQUEST = 4000
REQUEST_FIELDS = frozenset(("device", "table", "op", "key", "changes", "reason", "user_request", "request_id", "endpoint_impact"))
REQUIRED_FIELDS = REQUEST_FIELDS - {"device", "endpoint_impact"}
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ATTRIBUTE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
TEXT_VALUE = re.compile(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]*$')
QUOTED_TEXT_VALUE = re.compile(r'^[\x20-\x7e]*$')
QUOTED_TEXT_PLATFORMS = ("fortios",)
# 1.0.12 G122 (EP19): EOS stores a port description literally with any printable character, diacritics included
# (measured on cEOS 4.36.1F); '?' opens the CLI help and is refused like control characters and outer spaces
UNICODE_TEXT = {("eos", "description")}
MAC_ADDRESS = r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}"
MAC_RANGE = re.compile(rf"({MAC_ADDRESS})(?:-({MAC_ADDRESS}))?", re.IGNORECASE)
OBJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}")
FORTIOS_GROUP_MEMBER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_. -]{0,77}[A-Za-z0-9_.-])?")
FORTIOS_POLICY_LIST_FIELDS = frozenset((
    "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service", "poolname", "groups", "users",
    "internet-service-name", "internet-service-group", "internet-service-custom", "internet-service-custom-group",
))
FORTIOS_PORT_VLAN_LISTS = frozenset(("allowed-vlans", "untagged-vlans"))
FORTIOS_VLAN_NAME = re.compile(r"[A-Za-z0-9_.-](?:[A-Za-z0-9_. -]{0,13}[A-Za-z0-9_.-])?")


@dataclass(frozen=True)
class Request:
    device: str | None
    table: str
    op: str
    key: str
    changes: dict
    reason: str
    user_request: str
    request_id: str
    endpoint_impact: str | None = None

    def fingerprint(self) -> str:
        body = json.dumps(
            {"device": self.device, "table": self.table, "op": self.op, "key": self.key,
             "changes": self.changes, "reason": self.reason, "user_request": self.user_request,
             **({"endpoint_impact": self.endpoint_impact} if self.endpoint_impact is not None else {})},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class ProfileBatch(Request):
    changes: tuple[Request, ...]

    def fingerprint(self) -> str:
        body = [step.fingerprint() for step in self.changes]
        return hashlib.sha256(json.dumps(body, separators=(",", ":")).encode("ascii")).hexdigest()


def _text(value, label, limit):
    if not isinstance(value, str) or not value.strip():
        raise Rejected(["%s must be a non-empty string" % label])
    if len(value) > limit:
        raise Rejected(["%s is longer than %d characters" % (label, limit)])
    return value


def parse_request(raw: bytes) -> Request:
    if len(raw) > MAX_REQUEST_BYTES:
        document = None
        if len(raw) <= 131072:
            try:
                document = loads(raw, "request")
            except Rejected:
                pass
        if isinstance(document, dict) and "operations" in document:
            from netops_admin.schema_request import parse
            return parse(raw)
        raise Rejected(["request is larger than %d bytes" % MAX_REQUEST_BYTES])
    data = loads(raw, "request")
    if isinstance(data, dict) and "operations" in data:
        from netops_admin.schema_request import parse
        return parse(raw)
    if not isinstance(data, dict):
        raise Rejected(["request must be a JSON object"])
    unknown = set(data) - REQUEST_FIELDS
    missing = REQUIRED_FIELDS - set(data)
    if unknown or missing:
        raise Rejected(["request fields differ: missing %s, unknown %s" % (sorted(missing), sorted(unknown))])
    device = data.get("device")
    if device is not None and (not isinstance(device, str) or not DEVICE.fullmatch(device)):
        raise Rejected(["device must be an inventory alias"])
    table = _text(data["table"], "table", 64)
    if data["op"] not in REQUEST_OPS:
        raise Rejected(["op must be one of %s" % ", ".join(REQUEST_OPS)])
    key = _text(data["key"], "key", MAX_KEY_LENGTH)
    changes = data["changes"]
    if table == BATCH:
        if (data["op"] != "update" or key != BATCH or "endpoint_impact" in data
                or not isinstance(changes, list) or not 2 <= len(changes) <= MAX_BATCH_STEPS):
            raise Rejected(["batch requires op update, key batch and 2 to 32 profile changes"])
        common = {name: value for name, value in data.items() if name not in ("table", "op", "key", "changes")}
        child_fields = {"table", "op", "key", "changes"}
        steps = []
        for item in changes:
            if (not isinstance(item, dict) or not child_fields <= item.keys()
                    or item.keys() - child_fields - {"endpoint_impact"}
                    or item["table"] == BATCH or item["op"] not in OPS):
                raise Rejected(["each batch step needs table, op, key and changes, with optional endpoint_impact"])
            steps.append(parse_request(json.dumps(common | item).encode("utf-8")))
        return ProfileBatch(device, table, data["op"], key, tuple(steps), steps[0].reason,
                            steps[0].user_request, steps[0].request_id)
    if not isinstance(changes, dict):
        raise Rejected(["changes must be an object"])
    max_changes = FORTIOS_POLICY_MAX_CHANGES if table == "firewall policy" else MAX_CHANGES
    if len(changes) > max_changes:
        raise Rejected(["changes name more than %d attributes" % max_changes])
    for name, value in changes.items():
        if not ATTRIBUTE_NAME.fullmatch(name):
            raise Rejected(["attribute name %r is not a CLI attribute name" % name[:64]])
        if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int, list))):
            raise Rejected(["attribute %s: value must be a string, an integer or null" % name])
    request_id = data["request_id"]
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise Rejected(["request_id must match %s" % REQUEST_ID.pattern])
    impact = data.get("endpoint_impact")
    if impact is not None and (not isinstance(impact, str) or impact != key):
        raise Rejected(["endpoint_impact must explicitly name the affected object (the request key)"])
    return Request(
        device=device, table=table, op=data["op"], key=key, changes=dict(changes),
        reason=_text(data["reason"], "reason", MAX_REASON),
        user_request=_text(data["user_request"], "user_request", MAX_USER_REQUEST),
        request_id=request_id, endpoint_impact=impact,
    )


def group_members_text(values) -> str:
    # Keep existing plan strings for unquoted names and preserve token boundaries for names with spaces.
    items = []
    for value in sorted(values):
        if not value or value == "''" or any(c in value for c in ' "\\'):
            value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        items.append(value)
    return " ".join(items)


def list_items(attribute, value: str, platform: str) -> list:
    if platform == "fortios" and attribute.name in FORTIOS_POLICY_LIST_FIELDS | FORTIOS_PORT_VLAN_LISTS | {"member"}:
        return l1_fortios.tokenize(value)
    return value.split()


def canonical_value(attribute, value, platform: str) -> str:
    name = attribute.name
    if platform in ("ios", "iosxe") and name == "voice-vlan" and type(value) is int:
        if not 1 <= value <= 4094:
            raise Rejected(["voice-vlan must lie in 1..4094"])
        value = str(value)
    if platform in ("ios", "iosxe") and name in ("next-hop", "ipv4-address", "ipv6-address"):
        # 1.0.12 G80 (IOS XE) and G62 (IOS): addresses of a static route and an L3 interface in their canonical form
        from netops_admin.ios import canonical_address
        return canonical_address(name, value)
    if platform == "nxos" and name in ("next-hop", "ipv4-address", "ipv6-address"):
        from netops_admin.nxos import canonical_address
        return canonical_address(name, value)
    if platform == "exos" and name in ("gateway", "virtual-ip", "ipv6-address"):
        # 1.0.12 G45: a route gateway, a VRRP virtual address and a VLAN IPv6 address in their canonical form
        from netops_admin.exos import canonical_address as exos_address
        return exos_address(name, value)
    if platform == "junos" and name in ("name-servers", "ntp-source-address"):
        # 1.0.12 G145: addresses in the form Junos shows them; name-servers is an ordered list
        from netops_admin.junos import canonical_address, canonical_addresses
        return canonical_addresses(value) if name == "name-servers" else canonical_address(value)
    if platform in ("ios", "iosxe", "eos", "nxos") and name == "allowed-vlans":
        from netops_admin.ios import vlan_numbers, vlan_text
        return vlan_text(vlan_numbers(value))
    if attribute.type == "name-list":
        if platform == "junos" and name == "members":
            from netops_admin.junos import PHYSICAL
            if (not isinstance(value, list) or len(value) > 128
                    or not all(isinstance(item, str) and PHYSICAL.fullmatch(item) for item in value)
                    or len(value) != len(set(value))):
                raise Rejected(["Junos members must be a list of distinct physical Ethernet ports"])
            return " ".join(sorted(value))
        if platform == "exos" and name in ("tagged-ports", "untagged-ports", "members", "ports"):
            from netops_admin.membership import PORT_NUMBER
            if (not isinstance(value, list) or len(value) > 128
                    or not all(isinstance(item, str) and PORT_NUMBER.fullmatch(item) for item in value)
                    or len(value) != len(set(value))):
                raise Rejected(["attribute %s must be a list of distinct port numbers or slot:port values" % name])
            return " ".join(sorted(value))
        if platform == "fortios" and name in FORTIOS_PORT_VLAN_LISTS:
            if not isinstance(value, list) or len(value) > 128 or not all(
                isinstance(item, str) and FORTIOS_VLAN_NAME.fullmatch(item) for item in value
            ) or len(value) != len({item.casefold() for item in value}):
                raise Rejected(["attribute %s must be a list of distinct FortiLink VLAN interface names" % name])
            return group_members_text(value)
        quoted_fortios_list = platform == "fortios" and name in FORTIOS_POLICY_LIST_FIELDS | {"member"}
        pattern = FORTIOS_GROUP_MEMBER if quoted_fortios_list else OBJECT_NAME
        if not isinstance(value, list) or len(value) > 128 or not all(
            isinstance(item, str) and pattern.fullmatch(item) for item in value
        ) or len(value) != len(set(value)):
            raise Rejected(["attribute %s must be a list of distinct object names" % name])
        if quoted_fortios_list:
            return group_members_text(value)
        return " ".join(sorted(value))
    if attribute.type == "mac-address-list":
        if not isinstance(value, list) or not 1 <= len(value) <= 128:
            raise Rejected(["attribute %s needs a nonempty list of MAC addresses or ranges" % name])
        addresses = []
        for item in value:
            match = MAC_RANGE.fullmatch(item) if isinstance(item, str) else None
            if match is None or (match[2] and match[1].lower() > match[2].lower()):
                raise Rejected(["attribute %s needs MAC addresses or ascending MAC ranges" % name])
            addresses.append(item.lower())
        if len(addresses) != len(set(addresses)):
            raise Rejected(["attribute %s needs distinct MAC addresses or ranges" % name])
        return " ".join(addresses)
    if attribute.type == "ipv4-address":
        try:
            if not isinstance(value, str):
                raise ValueError("type")
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise Rejected(["attribute %s must be an IPv4 address" % name]) from None
    if attribute.type == "mac-address":
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
            raise Rejected(["attribute %s must be a MAC address" % name])
        if int(value[:2], 16) & 1 or int(value.replace(":", ""), 16) == 0:
            raise Rejected(["attribute %s must be a nonzero unicast MAC address" % name])
        return value.lower()
    if attribute.type == "integer":
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool):
            raise Rejected(["attribute %s must be an integer" % name])
        if not attribute.minimum <= value <= attribute.maximum:
            raise Rejected(["attribute %s must lie in %d..%d" % (name, attribute.minimum, attribute.maximum)])
        return str(value)
    if not isinstance(value, str):
        raise Rejected(["attribute %s must be a string" % name])
    if attribute.type == "ipv4-interface":
        # 1.0.12 G19: "a.b.c.d/len" or "a.b.c.d m.m.m.m"; a usable host address of a /8../30 subnet
        parts = value.strip().split()
        try:
            if len(parts) == 1 and "/" in parts[0]:
                interface = ipaddress.IPv4Interface(parts[0])
            elif len(parts) == 2:
                interface = ipaddress.IPv4Interface("%s/%s" % tuple(parts))
            else:
                raise ValueError(value)
        except ValueError:
            raise Rejected(["attribute %s must be an IPv4 interface address with its mask" % name]) from None
        network = interface.network
        if not 8 <= network.prefixlen <= 30 or interface.ip in (network.network_address, network.broadcast_address):
            raise Rejected(["attribute %s must be a usable host address of a /8 to /30 subnet" % name])
        return "%s %s" % (interface.ip, network.netmask)
    if attribute.type == "ipv4-network":
        text = value.strip()
        try:
            if "/" in text:
                network = ipaddress.IPv4Network(text, strict=True)
            else:
                parts = text.split()
                if len(parts) != 2:
                    raise ValueError(text)
                network = ipaddress.IPv4Network("%s/%s" % tuple(parts), strict=True)
        except ValueError:
            raise Rejected(["attribute %s must be an IPv4 network without host bits" % name]) from None
        return "%s %s" % (network.network_address, network.netmask)
    if not value:
        raise Rejected(["attribute %s: use null to remove the value, not an empty string" % name])
    if len(value) > attribute.max_length:
        raise Rejected(["attribute %s is longer than %d characters" % (name, attribute.max_length)])
    if attribute.type == "text" and (platform, name) in UNICODE_TEXT:
        if not value.isprintable() or "?" in value or value != value.strip():
            raise Rejected(["attribute %s may hold printable characters only, without '?' and without leading or "
                            "trailing spaces" % name])
    elif attribute.type == "text" and platform == "junos" and name == "description":
        # 1.0.12 G137 JP17: Junos stores a quoted description as UTF-8 text, diacritics included (measured)
        from netops_admin.junos import text_value
        text_value(value)
    elif attribute.type == "text" and platform in QUOTED_TEXT_PLATFORMS:
        if not QUOTED_TEXT_VALUE.fullmatch(value):
            raise Rejected(["attribute %s may hold printable ASCII only" % name])
    elif not TEXT_VALUE.fullmatch(value):
        raise Rejected(["attribute %s may hold printable ASCII only, without quotes or backslashes" % name])
    if attribute.pattern is not None and not attribute.pattern.fullmatch(value):
        raise Rejected(["attribute %s must match %s" % (name, attribute.pattern.pattern)])
    if value.casefold() in attribute.forbidden_values:
        raise Rejected(["attribute %s: the value %r is a CLI keyword" % (name, value)])
    return value
