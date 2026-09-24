from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected
from netops_admin.profiles import OPS

MAX_REQUEST_BYTES = 16384
MAX_KEY_LENGTH = 128
MAX_CHANGES = 16
MAX_REASON = 500
MAX_USER_REQUEST = 4000
REQUEST_FIELDS = frozenset(("device", "table", "op", "key", "changes", "reason", "user_request", "request_id"))
REQUIRED_FIELDS = REQUEST_FIELDS - {"device"}
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ATTRIBUTE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
TEXT_VALUE = re.compile(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]*$')


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

    def fingerprint(self) -> str:
        body = json.dumps(
            {"device": self.device, "table": self.table, "op": self.op, "key": self.key,
             "changes": self.changes, "reason": self.reason, "user_request": self.user_request},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("ascii")).hexdigest()


def _text(value, label, limit):
    if not isinstance(value, str) or not value.strip():
        raise Rejected(["%s must be a non-empty string" % label])
    if len(value) > limit:
        raise Rejected(["%s is longer than %d characters" % (label, limit)])
    return value


def parse_request(raw: bytes) -> Request:
    if len(raw) > MAX_REQUEST_BYTES:
        raise Rejected(["request is larger than %d bytes" % MAX_REQUEST_BYTES])
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Rejected(["request is not UTF-8 JSON"]) from None
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
    if data["op"] not in OPS:
        raise Rejected(["op must be one of %s" % ", ".join(OPS)])
    key = _text(data["key"], "key", MAX_KEY_LENGTH)
    changes = data["changes"]
    if not isinstance(changes, dict):
        raise Rejected(["changes must be an object"])
    if len(changes) > MAX_CHANGES:
        raise Rejected(["changes name more than %d attributes" % MAX_CHANGES])
    for name, value in changes.items():
        if not ATTRIBUTE_NAME.match(name):
            raise Rejected(["attribute name %r is not a CLI attribute name" % name[:64]])
        if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int, list))):
            raise Rejected(["attribute %s: value must be a string, an integer or null" % name])
    request_id = data["request_id"]
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise Rejected(["request_id must match %s" % REQUEST_ID.pattern])
    return Request(
        device=device, table=table, op=data["op"], key=key, changes=dict(changes),
        reason=_text(data["reason"], "reason", MAX_REASON),
        user_request=_text(data["user_request"], "user_request", MAX_USER_REQUEST),
        request_id=request_id,
    )


def canonical_value(attribute, value) -> str:
    name = attribute.name
    if attribute.type == "name-list":
        if not isinstance(value, list) or len(value) > 128 or not all(
            isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}", item)
            for item in value
        ) or len(value) != len(set(value)):
            raise Rejected(["attribute %s must be a list of distinct object names" % name])
        return " ".join(sorted(value))
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
    if not TEXT_VALUE.fullmatch(value):
        raise Rejected(["attribute %s may hold printable ASCII only, without quotes or backslashes" % name])
    if attribute.pattern is not None and not attribute.pattern.fullmatch(value):
        raise Rejected(["attribute %s must match %s" % (name, attribute.pattern.pattern)])
    if value.casefold() in attribute.forbidden_values:
        raise Rejected(["attribute %s: the value %r is a CLI keyword" % (name, value)])
    return value
