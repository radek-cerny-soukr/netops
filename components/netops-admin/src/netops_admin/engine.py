from __future__ import annotations

import hashlib
import json

from netops_admin import __version__, exos, fortios, membership
from netops_admin.errors import SNAPSHOT_INCOMPLETE, SNAPSHOT_UNREADABLE, Rejected, SnapshotRejected
from netops_admin.profiles import find_profile
from netops_admin.request import canonical_value

PLAN_FORMAT = "netops-admin-plan/1"
ADAPTERS = {"fortios": fortios, "exos": exos}
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
REFERENCE_TEXT_ATTRIBUTES = {"vlan-membership": ("untagged",)}


def adapter_for(platform: str):
    adapter = ADAPTERS.get(platform)
    if adapter is None:
        raise Rejected(["unknown platform %r" % platform])
    return adapter


def decode_snapshot(raw: bytes) -> str:
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotRejected(["snapshot is larger than %d bytes" % MAX_SNAPSHOT_BYTES], SNAPSHOT_UNREADABLE)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SnapshotRejected(["snapshot is not UTF-8"], SNAPSHOT_UNREADABLE) from None


def normalize(profile, attributes: dict):
    state, unsupported = {}, []
    for name, value in attributes.items():
        if name in profile.volatile:
            continue
        if name in profile.fixed:
            if value != profile.fixed[name]:
                unsupported.append("%s %s" % (name, value))
            continue
        attribute = profile.attributes.get(name)
        if attribute is None:
            unsupported.append(name)
            continue
        if attribute.default is not None and value == attribute.default:
            continue
        if attribute.type == "name-list":
            value = " ".join(sorted(value.split()))
        if attribute.type == "mac-address":
            value = value.lower()
        state[name] = value
    return state, unsupported


def observed_state(plan, attributes):
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return attributes
    if attributes is None:
        return None
    profile = find_profile(plan["platform"], plan["table"], plan["firmware"])
    state, unknown = normalize(profile, attributes)
    if unknown:
        raise Rejected(["the check account sees configuration outside the profile: %s" % ", ".join(sorted(unknown))])
    return state


def _find_entry(entries: dict, key: str):
    if key in entries:
        return entries[key]
    if any(name.casefold() == key.casefold() for name in entries):
        raise Rejected(["key %r differs only in letter case from an existing object" % key])
    return None


def _entry_state(snapshot, profile, entry):
    lists = [name for name, attribute in profile.attributes.items() if attribute.type == "name-list"]
    attributes, unsupported = snapshot.entry_state(entry, lists)
    state, unknown = normalize(profile, attributes)
    return state, unsupported + unknown


def canonical_changes(profile, request):
    canonical, reasons = {}, []
    for name, value in sorted(request.changes.items()):
        attribute = profile.attributes.get(name)
        if attribute is None:
            reasons.append("attribute %s is not in the profile" % name)
            continue
        if value is None:
            if not attribute.unset:
                reasons.append("attribute %s cannot be removed" % name)
            else:
                canonical[name] = None
            continue
        try:
            canonical[name] = canonical_value(attribute, value, profile.platform)
        except Rejected as exc:
            reasons.extend(exc.reasons)
            continue
        if canonical[name] in profile.reserved_values.get(name, ()):
            reasons.append("attribute %s: value %s is reserved on this platform" % (name, canonical[name]))
    if reasons:
        raise Rejected(reasons)
    return canonical


def _without_defaults(profile, values: dict) -> dict:
    return {
        name: value for name, value in values.items()
        if value is not None and value != profile.attributes[name].default
    }


def _referenced(profile, state) -> set:
    names = set()
    for name, value in (state or {}).items():
        attribute = profile.attributes.get(name)
        if attribute is not None and (attribute.type == "name-list"
                                      or name in REFERENCE_TEXT_ATTRIBUTES.get(profile.table, ())):
            names.update(str(value).split())
    return names


def _linked(snapshot, profile, key) -> set:
    if profile.platform != "exos" or profile.table not in ("ports", "vlan"):
        return set()
    _vlans, members, _descriptions = membership.model(snapshot)
    if profile.table == "ports":
        modes = members.get(key, {})
        return set(modes.get("tagged", ())) | set(modes.get("untagged", ()))
    folded = key.casefold()
    return {port for port, modes in members.items()
            if any(name.casefold() == folded for names in modes.values() for name in names)}


def _protected_references(snapshot, profile, protected, key, before, after) -> list:
    guarded = {name.casefold() for names in (protected or {}).values() for name in names}
    if not guarded:
        return []
    try:
        names = _referenced(profile, before) | _referenced(profile, after) | _linked(snapshot, profile, key)
    except Rejected as exc:
        raise Rejected(["the references of the object to protected names cannot be evaluated: %s"
                        % "; ".join(exc.reasons)]) from None
    return sorted(name for name in names if name.casefold() in guarded)


def _digest(value) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def build_plan(platform: str, snapshot_raw: bytes, request, firmware: str | None = None,
               protected: dict | None = None, enrollment_probe=False, ports=None) -> dict:
    from netops_admin.schema_request import Transaction
    if isinstance(request, Transaction):
        raise Rejected(["schema transaction planning requires schema-plan with a pinned library and calibration"])
    adapter = adapter_for(platform)
    snapshot = adapter.load(decode_snapshot(snapshot_raw), firmware)
    if ports is not None:
        if platform != "exos":
            raise Rejected(["a port list applies only to ExtremeXOS"])
        snapshot.inventory = frozenset(ports)
    profile = find_profile(platform, request.table, snapshot.firmware)
    key, op = request.key, request.op
    if key.startswith("netops-enroll-") and not enrollment_probe:
        raise Rejected(["the enrollment object namespace is reserved"])
    checks = ["firmware %s is measured for this profile" % snapshot.firmware]
    if op not in profile.ops:
        raise Rejected(["operation %s is not enabled in the profile" % op])
    if not profile.key_pattern.fullmatch(key):
        raise Rejected(["key %r does not match %s" % (key, profile.key_pattern.pattern)])
    guarded = {name.casefold() for name in profile.protected_keys}
    guarded |= {name.casefold() for name in (protected or {}).get(profile.table, ())}
    if key.casefold() in guarded:
        raise Rejected(["object %r is protected" % key])
    checks.append("key is valid and not protected")
    entries = snapshot.entries(profile.table)
    if entries is None:
        raise Rejected(["snapshot holds no %s section; it cannot be evaluated" % profile.table])
    entry = _find_entry(entries, key)
    changes = canonical_changes(profile, request)
    reasons = []

    if op == "create":
        if entry is not None or snapshot.in_use(key):
            raise Rejected(["name %r is already used in the configuration" % key])
        checks.append("name is unused among the object names and references of the snapshot")
        missing = [name for name, attribute in sorted(profile.attributes.items())
                   if attribute.required_on_create and changes.get(name) is None]
        if missing:
            raise Rejected(["create needs %s" % ", ".join(missing)])
        before = None
        after = _without_defaults(profile, changes)
        assign = {name: value for name, value in changes.items() if value is not None}
        commands = adapter.render_create(profile, key, assign)
        inverse = adapter.render_delete(profile, key)
    else:
        if entry is None and not profile.implicit_keys:
            raise Rejected(adapter.absent(snapshot, profile.table, key))
        before, unsupported = ({}, []) if entry is None else _entry_state(snapshot, profile, entry)
        if unsupported:
            raise Rejected(["object %r holds configuration outside the profile: %s"
                            % (key, ", ".join(sorted(unsupported)))])
        checks.append("object exists and holds only profile attributes")
        references = snapshot.references(profile.table, key)
        if op == "update":
            for name in changes:
                attribute = profile.attributes[name]
                if not attribute.update:
                    reasons.append("attribute %s cannot be updated" % name)
                elif references and not attribute.referenced_update:
                    reasons.append("attribute %s cannot change on a referenced object (%d references)"
                                   % (name, len(references)))
            if not changes:
                reasons.append("update names no attribute")
            if reasons:
                raise Rejected(reasons)
            after = dict(before)
            for name, value in changes.items():
                if value is None or value == profile.attributes[name].default:
                    after.pop(name, None)
                else:
                    after[name] = value
            if after == before:
                raise Rejected(["update changes nothing"])
            checks.append("references allow the changed attributes")
            assign = {name: value for name, value in changes.items() if value is not None}
            remove = sorted(name for name, value in changes.items() if value is None)
            commands = adapter.render_update(profile, key, assign, remove)
            restore = {name: before[name] for name in changes if name in before}
            clear = sorted(name for name in changes if name not in before)
            inverse = adapter.render_update(profile, key, restore, clear)
        else:
            if changes:
                raise Rejected(["delete takes no attribute changes"])
            if references:
                raise Rejected(["object %r is referenced in the configuration" % key])
            missing = [name for name, attribute in sorted(profile.attributes.items())
                       if attribute.required_on_create and name not in before]
            if missing:
                raise Rejected(["object %r cannot be recreated by the inverse: it has no %s"
                                % (key, ", ".join(missing))])
            checks.append("object is not referenced and can be recreated")
            after = None
            commands = adapter.render_delete(profile, key)
            inverse = adapter.render_create(profile, key, before)

    touched = _protected_references(snapshot, profile, protected, key, before, after)
    if touched:
        raise Rejected(["the object holds a reference to protected object %s before or after the change"
                        % ", ".join(repr(name) for name in touched)])
    if profile.table == "vlan-membership":
        if key in (protected or {}).get("ports", []):
            raise Rejected(["the port is protected"])
        commands = membership.render(key, before, after)
        inverse = membership.render(key, after, before)
    if platform == "fortios" and any("%%" in line for line in commands + inverse):
        raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
    reasons.extend(adapter.prechecks(snapshot, profile, op, key, after))
    if reasons:
        raise Rejected(reasons)
    document = {
        "format": PLAN_FORMAT,
        "safeguard_id": None,
        "admin_version": __version__,
        "platform": platform,
        "firmware": snapshot.firmware,
        "table": profile.table,
        "op": op,
        "key": key,
        "device": request.device,
        "request_id": request.request_id,
        "request_sha256": request.fingerprint(),
        "reason_characters": len(request.reason),
        "user_request_characters": len(request.user_request),
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "rest_sha256": snapshot.rest_digest(profile.table, key),
        "prechecks": checks,
        "commands": commands,
        "inverse": inverse,
        "predicted": {"before": before, "after": after},
        "ignored_attributes": sorted(profile.volatile),
        "inverse_identity_changes": list(profile.inverse_identity_changes.get(op, ())),
        "rollback_evidence": profile.rollback_evidence,
        "plan_sha256": _digest({"commands": commands, "inverse": inverse, "before": before, "after": after}),
    }
    if ports is not None:
        document["ports"] = sorted(snapshot.inventory, key=exos.port_order)
    return document


PLAN_FIELDS = frozenset((
    "format", "admin_version", "platform", "firmware", "table", "op", "key", "device", "request_id",
    "request_sha256", "reason_characters", "user_request_characters", "snapshot_sha256", "rest_sha256",
    "prechecks", "commands", "inverse", "predicted", "ignored_attributes", "inverse_identity_changes",
    "rollback_evidence", "plan_sha256", "safeguard_id",
))
PLAN_OPS = ("create", "update", "delete")
PLAN_TEXTS = ("format", "admin_version", "table", "key", "request_sha256", "snapshot_sha256", "rest_sha256",
              "plan_sha256", "rollback_evidence")
PLAN_OPTIONAL_TEXTS = ("firmware", "device", "request_id", "safeguard_id")
PLAN_COUNTS = ("reason_characters", "user_request_characters")
PLAN_TEXT_LISTS = ("prechecks", "commands", "inverse", "ignored_attributes", "inverse_identity_changes")


def _texts(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _typed(plan) -> bool:
    return (plan["platform"] in tuple(ADAPTERS) and plan["op"] in PLAN_OPS
            and all(isinstance(plan[name], str) for name in PLAN_TEXTS)
            and all(plan[name] is None or isinstance(plan[name], str) for name in PLAN_OPTIONAL_TEXTS)
            and all(isinstance(plan[name], int) and not isinstance(plan[name], bool) and plan[name] >= 0
                    for name in PLAN_COUNTS)
            and all(_texts(plan[name]) for name in PLAN_TEXT_LISTS)
            and all(side is None or isinstance(side, dict) for side in plan["predicted"].values()))


def _read_plan(plan) -> dict:
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return schema_runtime.read_plan(plan)
    if not isinstance(plan, dict) or set(plan) - {"ports"} != PLAN_FIELDS or plan.get("format") != PLAN_FORMAT:
        raise Rejected(["plan is not a %s document" % PLAN_FORMAT])
    predicted = plan["predicted"]
    if not isinstance(predicted, dict) or set(predicted) != {"before", "after"}:
        raise Rejected(["plan has no prediction"])
    if not _typed(plan):
        raise Rejected(["plan holds a value of the wrong type"])
    if "ports" in plan and (plan["platform"] != "exos" or not isinstance(plan["ports"], list)
                            or not all(isinstance(port, str) for port in plan["ports"])):
        raise Rejected(["plan holds an invalid port list"])
    expected = _digest({"commands": plan["commands"], "inverse": plan["inverse"],
                        "before": predicted["before"], "after": predicted["after"]})
    if expected != plan["plan_sha256"]:
        raise Rejected(["plan content does not match its plan_sha256"])
    return plan


def verify(plan, snapshot_raw: bytes, expect: str = "after") -> dict:
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return schema_runtime.verify(plan, snapshot_raw, expect)
    plan = _read_plan(plan)
    if expect not in ("before", "after"):
        raise Rejected(["expect must be before or after"])
    adapter = adapter_for(plan["platform"])
    snapshot = adapter.load(decode_snapshot(snapshot_raw), plan["firmware"])
    if "ports" in plan:
        snapshot.inventory = frozenset(plan["ports"])
    profile = find_profile(plan["platform"], plan["table"], snapshot.firmware)
    entries = snapshot.entries(profile.table)
    if entries is None:
        raise SnapshotRejected(["snapshot holds no %s section" % profile.table], SNAPSHOT_INCOMPLETE)
    differences = []
    entry = _find_entry(entries, plan["key"])
    actual = {} if profile.implicit_keys else None
    if entry is not None:
        actual, unsupported = _entry_state(snapshot, profile, entry)
        differences.extend("object holds configuration outside the profile: %s" % item for item in unsupported)
    wanted = plan["predicted"][expect]
    if (actual is None) != (wanted is None):
        differences.append("object %s, expected %s"
                           % ("absent" if actual is None else "present", "absent" if wanted is None else "present"))
    elif actual is not None:
        for name in sorted(set(actual) | set(wanted)):
            if actual.get(name) != wanted.get(name):
                differences.append("%s: expected %r, found %r" % (name, wanted.get(name), actual.get(name)))
    object_matches = not differences
    rest_digest = snapshot.rest_digest(profile.table, plan["key"], plan.get("safeguard_id"))
    rest_matches = rest_digest == plan["rest_sha256"]
    if not rest_matches:
        differences.append("configuration outside the planned object changed")
    return {
        "result": "match" if not differences else "mismatch",
        "object_matches": object_matches,
        "rest_matches": rest_matches,
        "expect": expect,
        "key": plan["key"],
        "plan_sha256": plan["plan_sha256"],
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "differences": differences,
    }
