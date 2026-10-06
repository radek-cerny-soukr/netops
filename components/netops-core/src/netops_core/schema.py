from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import ipaddress
import json
import re
import uuid

from .inputs import InputError, read_regular

MAX_BYTES = 16 * 1024 * 1024
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,95}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
BUILD = re.compile(r"^\d{4,6}$")
SCOPES = ("global", "vdom", "global+vdom", None)
STRING_TYPES = {"string", "var-string", "user", "text"}
NETWORK_TYPES = {"ipv4-classnet", "ipv4-classnet-any", "ipv4-classnet-host"}
VALIDATED_TYPES = STRING_TYPES | NETWORK_TYPES | {"integer", "option", "uuid", "mac-address",
    "ipv6-network", "ipv6-prefix", "ipv6-address", "ipv4-netmask", "ipv4-netmask-any",
    "ipv4-address", "ipv4-address-any", "ipv4-address-multicast"}


class SchemaError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SchemaError("schema contains duplicate fields")
        result[key] = value
    return result


def _text(value, limit=4096):
    if not isinstance(value, str) or not value.isprintable() or len(value.encode("utf-8")) > limit:
        raise SchemaError("a value must be printable text within its size limit")
    return value


def quoted(value):
    if value == "":
        return '""'
    text = _text(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise SchemaError("schema contains an invalid CLI name")
    return value


def _path(value):
    if not isinstance(value, str) or len(value) > 512 or not value:
        raise SchemaError("schema contains an invalid configuration path")
    for word in value.split(" "):
        _name(word)
    return value


def _scalar_tokens(attribute, value):
    kind = attribute.get("type")
    if isinstance(value, bool) or value is None:
        raise SchemaError("a value has the wrong type")
    if kind == "integer":
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and re.fullmatch(r"-?\d{1,20}", value):
            number = int(value)
        else:
            raise SchemaError("an integer is required")
        lower, upper = attribute.get("min"), attribute.get("max")
        if str(number) != str(attribute.get("default")):
            if lower is not None and number < lower or upper is not None and number > upper:
                raise SchemaError("an integer is outside the measured range")
        return (str(number),)
    text = value if value == "" else _text(value)
    if not isinstance(text, str):
        raise SchemaError("a string is required")
    if "max_length" in attribute and len(text.encode("utf-8")) > attribute["max_length"]:
        raise SchemaError("a string exceeds the measured length")
    if kind == "option":
        if text not in attribute.get("options", []):
            raise SchemaError("an option is absent from the measured schema")
        return (quoted(text),)
    if kind in STRING_TYPES:
        return (quoted(text),)
    try:
        if kind in NETWORK_TYPES:
            interface = ipaddress.IPv4Interface(text)
            address = interface.ip if kind == "ipv4-classnet-host" else interface.network.network_address
            return (str(address), str(interface.netmask))
        if kind in {"ipv6-network", "ipv6-prefix"}:
            return (str(ipaddress.IPv6Network(text, strict=False)),)
        if kind and kind.startswith("ipv4-address"):
            address = ipaddress.IPv4Address(text)
            if kind == "ipv4-address-multicast" and not address.is_multicast:
                raise SchemaError("a multicast address is required")
            return (str(address),)
        if kind == "ipv6-address":
            address = ipaddress.IPv6Address(text)
            if address.scope_id is not None:
                raise SchemaError("scoped IPv6 addresses require a measured validator")
            return (str(address),)
        if kind in {"ipv4-netmask", "ipv4-netmask-any"}:
            mask = ipaddress.IPv4Network("0.0.0.0/" + text).netmask
            return (str(mask),)
        if kind == "uuid":
            return (str(uuid.UUID(text)),)
        if kind == "mac-address" and re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", text):
            return (text.lower(),)
    except (ValueError, TypeError):
        raise SchemaError("a network value has the wrong syntax") from None
    raise SchemaError("this attribute type has no measured write validator")


@dataclass(frozen=True)
class ConfigInstance:
    path: str
    scope: str | None
    owners: tuple
    node: object

    @property
    def key(self):
        return self.owners[-1][1] if self.owners and self.owners[-1][0] == self.path else ""


def config_instances(library, tree, include_unknown=False):
    known = set(library.paths)
    def walk(current, prefix, owners, scope):
        for name, container in sorted(current.sub.items()):
            if not prefix and name in ("global", "vdom"):
                continue
            path = (prefix + " " + name).strip()
            inline_key = None
            if path not in known and len(container.config_tokens) >= 2 and not container.entries:
                candidate = (prefix + " " + " ".join(container.config_tokens[:-1])).strip()
                if candidate in known:
                    candidate_node = library.node(candidate)
                    key_attr = candidate_node["attrs"].get(candidate_node.get("key"))
                    if candidate_node["kind"] == "table" and key_attr:
                        try:
                            _text(container.config_tokens[-1], 128)
                            _scalar_tokens(key_attr, container.config_tokens[-1])
                        except SchemaError:
                            pass
                        else:
                            path, inline_key = candidate, container.config_tokens[-1]
            metadata = library.node(path) if path in known else None
            entries = [(inline_key, container)] if inline_key is not None else container.entries.items() if container.entries else [(None, container)]
            node_scope = library.scope(path) if metadata else None
            for key, node in entries:
                ownership = owners + ((path, key),) if key is not None else owners
                actual_scope = None if metadata and node_scope == "global" else scope
                if (metadata or include_unknown) and (key is not None or not metadata or metadata["kind"] == "section"):
                    yield ConfigInstance(path, actual_scope, ownership, node)
                yield from walk(node, path, ownership, actual_scope)
    yield from walk(tree, "", (), "root")
    global_node = tree.section("global")
    if global_node is not None:
        yield from walk(global_node, "", (), None)
    vdom_node = tree.section("vdom")
    if vdom_node is not None:
        for name, node in sorted(vdom_node.entries.items()):
            yield from walk(node, "", (), name)


class Library:
    def __init__(self, document, digest=None):
        if not isinstance(document, dict) or type(document.get("format")) is not int or document["format"] != 1:
            raise SchemaError("schema format 1 is required")
        if document.get("platform") != "fortios":
            raise SchemaError("this schema runtime requires FortiOS")
        for field, pattern in (("hardware", MODEL), ("os_version", VERSION), ("build", BUILD)):
            value = document.get(field)
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise SchemaError("schema identity is invalid")
        config = document.get("config")
        if not isinstance(config, dict) or not config or len(config) > 5000:
            raise SchemaError("schema configuration nodes are absent or exceed the limit")
        count = 0
        for path, node in config.items():
            _path(path)
            if not isinstance(node, dict) or node.get("kind") not in {"table", "section"}:
                raise SchemaError("schema node kind is invalid")
            if node.get("scope") not in SCOPES or type(node.get("available")) not in (bool, type(None)):
                raise SchemaError("schema availability or scope is invalid")
            attrs = node.get("attrs")
            if not isinstance(attrs, dict):
                raise SchemaError("schema attributes are invalid")
            count += len(attrs)
            for name, attr in attrs.items():
                _name(name)
                if not isinstance(attr, dict) or not isinstance(attr.get("type"), (str, type(None))):
                    raise SchemaError("schema attribute metadata is invalid")
                for bound in ("min", "max", "max_length"):
                    if bound in attr and type(attr[bound]) is not int:
                        raise SchemaError("schema bounds must be integers")
                if "max_length" in attr and attr["max_length"] < 0:
                    raise SchemaError("schema string lengths must be nonnegative")
                if "min" in attr and "max" in attr and attr["min"] > attr["max"]:
                    raise SchemaError("schema bounds are inverted")
                if "options" in attr and (not isinstance(attr["options"], list) or
                        any(not isinstance(v, str) for v in attr["options"])):
                    raise SchemaError("schema options are invalid")
                ref = attr.get("ref")
                if ref is not None:
                    if not isinstance(ref, dict) or not isinstance(ref.get("tables"), list):
                        raise SchemaError("schema references are invalid")
                    for target in ref["tables"]:
                        _path(target)
                    if "builtin_values_not_captured" in ref and type(ref["builtin_values_not_captured"]) is not bool:
                        raise SchemaError("schema builtin reference coverage flag is invalid")
                    unresolved = ref.get("unresolved", False)
                    if not isinstance(unresolved, bool) and (not isinstance(unresolved, list) or
                            len(unresolved) > 256 or any(not isinstance(value, str) or not value or
                                not value.isprintable() or len(value.encode("utf-8")) > 128 for value in unresolved)):
                        raise SchemaError("schema unresolved reference metadata is invalid")
                    contexts = ref.get("measured_contexts")
                    if "measured_contexts" in ref and (not isinstance(contexts, list) or not contexts or len(contexts) > 256 or
                            any(not isinstance(value, str) or not value.isprintable() or
                                value != "global" and (not value.startswith("vdom:") or not 1 <= len(value[5:].encode("utf-8")) <= 128)
                                for value in contexts) or len(contexts) != len(set(contexts))):
                        raise SchemaError("schema measured reference contexts are invalid")
                    for field in ("special", "builtin"):
                        if field in ref and (not isinstance(ref[field], list) or
                                any(not isinstance(v, str) for v in ref[field])):
                            raise SchemaError("schema reference values are invalid")
        if count > 100000:
            raise SchemaError("schema attribute limit is exceeded")
        self._document = copy.deepcopy(document)
        self.sha256 = digest or hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                                         allow_nan=False).encode()).hexdigest()

    @property
    def identity(self):
        return tuple(self._document[k] for k in ("hardware", "os_version", "build"))

    @property
    def paths(self):
        return tuple(sorted(self._document["config"]))

    def require_identity(self, hardware, version, build):
        if (hardware, version, build) != self.identity:
            raise SchemaError("the measured hardware and firmware identity does not match")

    def node(self, path):
        _path(path)
        if path not in self._document["config"]:
            raise SchemaError("the configuration path is absent from the measured schema")
        return copy.deepcopy(self._document["config"][path])

    def chain(self, path):
        self.node(path)
        words = path.split()
        return tuple(" ".join(words[:i]) for i in range(1, len(words) + 1)
                     if " ".join(words[:i]) in self._document["config"])

    def availability(self, path):
        measured = [self._document["config"][p]["available"] for p in self.chain(path)
                    if "available" in self._document["config"][p]]
        if any(value is False for value in measured):
            return False
        return True if measured and all(value is True for value in measured) else None

    def scope(self, path):
        domains = {"global", "vdom"}
        measured = False
        for parent in self.chain(path):
            node = self._document["config"][parent]
            if "scope" not in node:
                continue
            measured = True
            value = node["scope"]
            if value is None:
                return None
            domains &= {"global", "vdom"} if value == "global+vdom" else {value}
        if not measured or not domains:
            return None
        return "global+vdom" if len(domains) == 2 else next(iter(domains))

    def read_command(self, path):
        root = self.chain(path)[0]
        return "show full-configuration " + root

    def validate(self, path, changes):
        node = self.node(path)
        if self.availability(path) is not True or self.scope(path) is None:
            raise SchemaError("write availability and scope must be measured")
        if not isinstance(changes, dict) or not changes or len(changes) > 64:
            raise SchemaError("changes must contain 1 to 64 attributes")
        result = {}
        for name, value in changes.items():
            _name(name)
            if name not in node["attrs"]:
                raise SchemaError("an attribute is absent from the measured schema")
            attribute = node["attrs"][name]
            if value is None:
                if attribute.get("type") not in VALIDATED_TYPES:
                    raise SchemaError("this attribute type has no measured write validator")
                result[name] = None
                continue
            values = value if isinstance(value, list) else [value]
            if not values or len(values) > 64 or isinstance(value, list) and not attribute.get("multi"):
                raise SchemaError("a value list is not allowed by the measured schema")
            tokens = tuple(token for item in values for token in _scalar_tokens(attribute, item))
            result[name] = tokens
        return result


def load(path, expected_sha256=None):
    try:
        raw = read_regular(path, MAX_BYTES)
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(SchemaError("nonfinite schema value")))
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise SchemaError("schema content does not match the configured digest")
        return Library(document, digest)
    except SchemaError:
        raise
    except (OSError, InputError, UnicodeError, ValueError, TypeError, RecursionError):
        raise SchemaError("schema cannot be read as a bounded UTF-8 JSON document") from None
