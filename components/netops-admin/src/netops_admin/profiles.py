from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources

from netops_admin.errors import Rejected

PLATFORMS = ("fortios", "exos")
OPS = ("create", "update", "delete")
ATTRIBUTE_TYPES = ("ipv4-network", "ipv4-address", "mac-address", "name-list", "text", "integer")
PROFILE_FIELDS = frozenset((
    "platform", "table", "versions", "ops", "key_pattern", "protected_keys", "attributes",
    "fixed", "volatile", "reserved_values", "inverse_identity_changes", "rollback_evidence",
))
ATTRIBUTE_FIELDS = frozenset((
    "type", "default", "required_on_create", "update", "unset", "referenced_update",
    "max_length", "minimum", "maximum", "forbidden_values", "pattern",
))
OPTIONAL_PROFILE_FIELDS = frozenset(("implicit_keys",))


class ProfileError(Exception):
    pass


@dataclass(frozen=True)
class Attribute:
    name: str
    type: str
    default: str | None
    required_on_create: bool
    update: bool
    unset: bool
    referenced_update: bool
    max_length: int | None
    minimum: int | None
    maximum: int | None
    forbidden_values: tuple
    pattern: re.Pattern | None = None


@dataclass(frozen=True)
class Profile:
    platform: str
    table: str
    versions: tuple
    ops: tuple
    key_pattern: re.Pattern
    protected_keys: tuple
    attributes: dict
    fixed: dict
    volatile: tuple
    reserved_values: dict
    inverse_identity_changes: dict
    rollback_evidence: str
    implicit_keys: bool = False


def _require(condition, message):
    if not condition:
        raise ProfileError(message)


def _strings(value, label):
    _require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
             "%s must be a list of non-empty strings" % label)
    _require(len(set(value)) == len(value), "%s holds duplicates" % label)
    return tuple(value)


def _attribute(name, data):
    _require(isinstance(data, dict), "attribute %s must be an object" % name)
    unknown = set(data) - ATTRIBUTE_FIELDS
    _require(not unknown, "attribute %s has unknown fields: %s" % (name, sorted(unknown)))
    kind = data.get("type")
    _require(kind in ATTRIBUTE_TYPES, "attribute %s has an unknown type" % name)
    for flag in ("required_on_create", "update", "unset", "referenced_update"):
        _require(isinstance(data.get(flag), bool), "attribute %s needs boolean %s" % (name, flag))
    default = data.get("default")
    _require(default is None or isinstance(default, str), "attribute %s default must be a string" % name)
    max_length = data.get("max_length")
    minimum, maximum = data.get("minimum"), data.get("maximum")
    if kind == "text":
        _require(isinstance(max_length, int) and not isinstance(max_length, bool) and max_length > 0,
                 "text attribute %s needs max_length" % name)
    else:
        _require(max_length is None, "attribute %s: max_length is only for text" % name)
    if kind == "integer":
        _require(all(isinstance(item, int) and not isinstance(item, bool) for item in (minimum, maximum))
                 and minimum <= maximum, "integer attribute %s needs minimum <= maximum" % name)
    else:
        _require(minimum is None and maximum is None, "attribute %s: bounds are only for integers" % name)
    forbidden = _strings(data.get("forbidden_values", []), "attribute %s forbidden_values" % name)
    pattern = data.get("pattern")
    if pattern is not None:
        _require(kind == "text" and isinstance(pattern, str) and pattern.startswith("^") and pattern.endswith("$"),
                 "attribute %s: pattern must be an anchored expression of a text attribute" % name)
        try:
            pattern = re.compile(pattern)
        except re.error as exc:
            raise ProfileError("attribute %s: pattern does not compile: %s" % (name, exc)) from exc
    _require(not (data["required_on_create"] and data["unset"]),
             "attribute %s cannot be both required and unsettable" % name)
    return Attribute(
        name=name, type=kind, default=default,
        required_on_create=data["required_on_create"], update=data["update"], unset=data["unset"],
        referenced_update=data["referenced_update"], max_length=max_length,
        minimum=minimum, maximum=maximum,
        forbidden_values=tuple(item.casefold() for item in forbidden), pattern=pattern,
    )


def parse_profile(data) -> Profile:
    _require(isinstance(data, dict), "profile must be an object")
    _require(PROFILE_FIELDS <= set(data) <= PROFILE_FIELDS | OPTIONAL_PROFILE_FIELDS,
             "profile fields differ: missing %s, unknown %s"
             % (sorted(PROFILE_FIELDS - set(data)), sorted(set(data) - PROFILE_FIELDS - OPTIONAL_PROFILE_FIELDS)))
    implicit = data.get("implicit_keys", False)
    _require(isinstance(implicit, bool), "implicit_keys must be true or false")
    _require(not implicit or tuple(data["ops"]) == ("update",),
             "a table whose objects always exist allows update only")
    _require(data["platform"] in PLATFORMS, "unknown platform")
    _require(isinstance(data["table"], str) and data["table"], "table must be a non-empty string")
    versions = _strings(data["versions"], "versions")
    _require(versions, "a profile needs at least one measured version")
    ops = _strings(data["ops"], "ops")
    _require(set(ops) <= set(OPS) and ops, "ops must be a subset of %s" % (OPS,))
    _require(isinstance(data["key_pattern"], str), "key_pattern must be a string")
    try:
        key_pattern = re.compile(data["key_pattern"])
    except re.error as exc:
        raise ProfileError("key_pattern does not compile: %s" % exc) from exc
    _require(key_pattern.pattern.startswith("^") and key_pattern.pattern.endswith("$"),
             "key_pattern must be anchored")
    attributes_data = data["attributes"]
    _require(isinstance(attributes_data, dict) and attributes_data, "attributes must be a non-empty object")
    attributes = {name: _attribute(name, value) for name, value in attributes_data.items()}
    fixed = data["fixed"]
    _require(isinstance(fixed, dict) and all(isinstance(v, str) for v in fixed.values()),
             "fixed must map attribute names to strings")
    volatile = _strings(data["volatile"], "volatile")
    overlap = (set(attributes) & set(fixed)) | (set(attributes) & set(volatile)) | (set(fixed) & set(volatile))
    _require(not overlap, "an attribute is listed twice: %s" % sorted(overlap))
    reserved = data["reserved_values"]
    _require(isinstance(reserved, dict), "reserved_values must be an object")
    for name, values in reserved.items():
        _require(name in attributes, "reserved_values names an unknown attribute: %s" % name)
        _strings(values, "reserved_values %s" % name)
    identity = data["inverse_identity_changes"]
    _require(isinstance(identity, dict) and set(identity) <= set(OPS), "inverse_identity_changes is invalid")
    for op, names in identity.items():
        _require(set(_strings(names, "inverse_identity_changes %s" % op)) <= set(volatile),
                 "an identity change must be a volatile attribute")
    _require(isinstance(data["rollback_evidence"], str) and data["rollback_evidence"],
             "rollback_evidence must describe the measured rollback")
    return Profile(
        platform=data["platform"], table=data["table"], versions=versions, ops=ops,
        key_pattern=key_pattern, protected_keys=_strings(data["protected_keys"], "protected_keys"),
        attributes=attributes, fixed=dict(fixed), volatile=volatile,
        reserved_values={name: tuple(values) for name, values in reserved.items()},
        inverse_identity_changes={op: tuple(names) for op, names in identity.items()},
        rollback_evidence=data["rollback_evidence"], implicit_keys=implicit,
    )


def load_profiles() -> dict:
    profiles = {}
    directory = resources.files("netops_admin") / "profiles"
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        if not entry.name.endswith(".json"):
            continue
        try:
            profile = parse_profile(json.loads(entry.read_text(encoding="utf-8")))
        except (ValueError, ProfileError) as exc:
            raise ProfileError("%s: %s" % (entry.name, exc)) from exc
        identity = (profile.platform, profile.table)
        if identity in profiles:
            raise ProfileError("two profiles for %s %s" % identity)
        profiles[identity] = profile
    return profiles


def find_profile(platform: str, table: str, firmware: str) -> Profile:
    profile = load_profiles().get((platform, table))
    if profile is None:
        raise Rejected(["no profile for %s table %r" % (platform, table)])
    family_supported = (
        platform == "fortios" and any(v.startswith("7.6.") for v in profile.versions)
        and re.fullmatch(r"7\.6\.[0-9]+ build[0-9]+", firmware) is not None
    ) or (platform == "exos" and re.fullmatch(r"33\.7\.[0-9]+\.[0-9]+", firmware) is not None)
    if firmware not in profile.versions and not family_supported:
        raise Rejected(["profile %s %r is not measured on firmware %r (measured: %s)"
                        % (platform, table, firmware, ", ".join(profile.versions))])
    return profile
