"""ExtremeXOS policy files and static ingress ACL bindings (X21)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re

from netops_admin import membership
from netops_admin.errors import Rejected
from netops_core.sftp import EXOS_POLICY_MAX_BYTES, EXOS_POLICY_NAME

POLICY = "acl-policy"
BINDING = "acl-attachment"
TABLES = (POLICY, BINDING)
CONTENT = "policy-content"
UNREADABLE = "exos_acl_unreadable"
UNSAFE = "exos_acl_unsafe_scope"
INVALID = "exos_acl_policy_invalid"

VLAN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
IDENTIFIER = r"[A-Za-z][A-Za-z0-9_-]{0,31}"
ENTRY = re.compile(rf"entry\s+({IDENTIFIER})\s*\{{\s*if\s*\{{([^{{}}]*)\}}\s*then\s*\{{([^{{}}]+)\}}\s*\}}")
COUNT = re.compile(rf"count\s+{IDENTIFIER}")
MARKER = "# netops-exos-acl-file "
ACL_HEADER = "Vlan Name Port Policy Name Dir Rules Dyn Rules"
POLICY_HEADER = "PolicyName ClientUsage Client BindCount"


def unreadable(message):
    raise Rejected([message], reason_codes=[UNREADABLE])


def unsafe(message):
    raise Rejected([message], reason_codes=[UNSAFE])


def invalid():
    raise Rejected(["ExtremeXOS policy must contain named ACL entries with supported matches and actions"],
                   reason_codes=[INVALID])


def _statements(body):
    if not body.strip():
        return []
    parts = body.strip().split(";")
    if parts.pop().strip() or any(not item.strip() for item in parts):
        invalid()
    return [" ".join(item.split()) for item in parts]


def _matches(body):
    names = set()
    for statement in _statements(body):
        field, _, value = statement.partition(" ")
        if field in names:
            invalid()
        names.add(field)
        if field in ("source-address", "destination-address"):
            try:
                if "/" not in value:
                    invalid()
                ipaddress.ip_network(value)
            except ValueError:
                invalid()
        elif field == "protocol":
            if value not in ("tcp", "udp", "icmp"):
                invalid()
        elif field in ("source-port", "destination-port"):
            if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
                invalid()
        else:
            invalid()


def content(value):
    """Validate the supported policy grammar while preserving the exact approved file bytes."""
    if (not isinstance(value, str) or not 0 < len(value) <= EXOS_POLICY_MAX_BYTES
            or re.search(r"[^\x20-\x7e\t\n\r]", value)):
        invalid()
    remaining = value.strip()
    entries = set()
    while remaining:
        match = ENTRY.match(remaining)
        if not match or match[1].casefold() in entries:
            invalid()
        entries.add(match[1].casefold())
        _matches(match[2])
        actions = _statements(match[3])
        if (not 1 <= len(actions) <= 2 or actions[0] not in ("permit", "deny")
                or (len(actions) == 2 and not COUNT.fullmatch(actions[1]))):
            invalid()
        remaining = remaining[match.end():].lstrip()
    if not entries:
        invalid()
    return value


def snapshot_line(name, data):
    encoded = "-" if data is None else base64.b64encode(data).decode("ascii")
    return f"{MARKER}{name} {encoded}\n"


def file_entries(text, entry_type):
    first = text.split("\n", 1)[0]
    if not first.startswith(MARKER):
        unreadable("ExtremeXOS policy planning requires a verified SFTP file observation")
    name, _, encoded = first[len(MARKER):].partition(" ")
    if not EXOS_POLICY_NAME.fullmatch(name) or not encoded:
        unreadable("ExtremeXOS policy file observation is incomplete")
    if encoded == "-":
        return {}
    try:
        value = content(base64.b64decode(encoded, validate=True).decode("ascii"))
    except (binascii.Error, UnicodeError):
        invalid()
    entry = entry_type(name)
    entry.attributes = {CONTENT: value}
    return {name: entry}


def selector(key):
    kind, _, name = key.partition(":")
    if kind == "port" and membership.PORT_NUMBER.fullmatch(name):
        return "ports", name
    if kind == "vlan" and VLAN.fullmatch(name):
        return "vlan", name
    unsafe("ExtremeXOS ACL target must identify one physical port or one named VLAN")


def binding_line(command):
    tokens = command.tokens
    if command.module != "acl" or tokens[:2] != ("configure", "access-list"):
        return None
    if len(tokens) == 6 and tokens[3] in ("ports", "vlan") and tokens[5] == "ingress":
        return tokens[2], tokens[3], tokens[4]
    if tokens[3:] == ("any", "ingress"):
        return tokens[2], "any", "*"
    return None


def owns_binding(command, key):
    binding = binding_line(command)
    kind, name = selector(key)
    return binding is not None and binding[1] == kind and binding[2].casefold() == name.casefold()


def binding_entries(snapshot, entry_type):
    modules = tuple(snapshot.configuration.modules)
    if "acl" not in modules or modules[-1] == "acl":
        unreadable("ExtremeXOS ACL configuration module is incomplete")
    entries = {}
    for command in snapshot.commands:
        binding = binding_line(command)
        if binding is None:
            continue
        policy, kind, name = binding
        if kind == "any" or not (VLAN if kind == "vlan" else membership.PORT_NUMBER).fullmatch(name):
            continue
        if not EXOS_POLICY_NAME.fullmatch(policy):
            unreadable("ExtremeXOS ACL configuration contains an unsupported policy name")
        key = f"{'port' if kind == 'ports' else 'vlan'}:{name}"
        entry = entry_type(key)
        entry.attributes = {"policy": policy}
        if key.casefold() in {existing.casefold() for existing in entries}:
            unreadable("ExtremeXOS ACL configuration repeats an ingress attachment")
        entries[key] = entry
    return entries


def render_file(key, state):
    if state is None:
        return [f"SFTP remove {key}.pol"]
    digest = hashlib.sha256(state[CONTENT].encode("ascii")).hexdigest()
    return [f"SFTP validate and install {key}.pol (SHA-256 {digest})"]


def render_binding(key, state):
    kind, name = selector(key)
    if state is not None and not EXOS_POLICY_NAME.fullmatch(state["policy"]):
        invalid()
    prefix = "unconfigure access-list" if state is None else f"configure access-list {state['policy']}"
    return [f"{prefix} {kind} {name} ingress"]


def _lines(text):
    return [" ".join(line.split()) for line in text.splitlines() if line.strip()]


def active_bindings(text):
    lines = _lines(text)
    if lines == ["No entry found!"]:
        return {}
    if len(lines) < 3 or lines[0] != ACL_HEADER or not re.fullmatch(r"=+", lines[1]):
        unreadable("ExtremeXOS operational ACL table is incomplete")
    entries = {}
    for line in lines[2:]:
        columns = line.split()
        if len(columns) != 6:
            unreadable("ExtremeXOS operational ACL table contains an unknown row")
        vlan, port, policy, direction, rules, dynamic = columns
        if (direction not in ("ingress", "egress") or not re.fullmatch(r"[0-9]+", rules)
                or not re.fullmatch(r"[0-9]+", dynamic) or not EXOS_POLICY_NAME.fullmatch(policy)):
            unreadable("ExtremeXOS operational ACL table contains an unknown row")
        if direction == "egress":
            continue
        if vlan == port == "*":
            key = "any:*"
        elif vlan == "*" and membership.PORT_NUMBER.fullmatch(port):
            key = f"port:{port}"
        elif port == "*" and VLAN.fullmatch(vlan):
            key = f"vlan:{vlan.casefold()}"
        else:
            unreadable("ExtremeXOS operational ACL attachment scope is unrecognised")
        if key in entries:
            unreadable("ExtremeXOS operational ACL table repeats an ingress attachment")
        entries[key] = (policy, int(rules), int(dynamic))
    return entries


def require_unused(text, name):
    lines = _lines(text)
    if (len(lines) < 3 or lines[:2] != ["Policies at Policy Server:", POLICY_HEADER]
            or not re.fullmatch(r"-+", lines[2])):
        unreadable("ExtremeXOS policy client table is incomplete")
    current = None
    for line in lines[3:]:
        columns = line.split()
        if len(columns) == 4 and EXOS_POLICY_NAME.fullmatch(columns[0]) and columns[1].isdigit():
            current = columns[0].casefold()
        elif len(columns) != 3 or current is None or not columns[0].isdigit():
            unreadable("ExtremeXOS policy client table contains an unknown row")
        if not columns[-1].isdigit():
            unreadable("ExtremeXOS policy client count is unreadable")
        if current == name.casefold():
            unsafe("ExtremeXOS policy has a registered client; detach it before changing the file")
