from __future__ import annotations

import re

from . import jsontext
from .engine import EVALUATED, NOT_EVALUATED, check
from .inputs import InputError, read_regular

SUPPORTED = ("FortiADC-KVM", "7.6.7", "0676")
CONTEXT_KEY = "fortiadc_snapshot_context"
MAX_CONTEXT_BYTES = 65536

AREAS = frozenset(
    ("system", "networking", "load-balance", "log", "link-load-balance",
     "global-load-balance", "security", "share-resource", "user")
)
GLOBAL_LIMITATIONS = frozenset(("access-profile-unverified", "vdom-unverified"))
VDOM_LIMITATION = "vdom-override-unverified"
KNOWN_LIMITATIONS = AREAS | GLOBAL_LIMITATIONS | {VDOM_LIMITATION}

REASON_NO_CONTEXT = "snapshot-context-missing"
REASON_IDENTITY = "identity-mismatch"
REASON_DEFAULT = "default-undocumented"
REASON_MARKER = "redacted-or-unverified-value"
REASON_SECTION = "section-absent"

_MARKS = ("<REDACTED", "<UNVERIFIED")
_OPEN_HOSTS = ("0.0.0.0/0", "::/0")
_PLAINTEXT_SERVICES = ("http", "telnet")
_LEGACY_TLS = ("sslv3", "tlsv1.0", "tlsv1.1")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOKEN = object()
_META_KEYS = frozenset(("version", "sha256", "identity", "configuration_complete", "visibility_limitations"))
_IDENTITY_KEYS = frozenset(("platform", "version", "build"))
_HELPER_REQUIRED = frozenset(("firmware", "configuration_complete", "visibility_limitations"))
_FIRMWARE_KEYS = frozenset(("model", "version", "build"))

_ADMIN = "system admin"
_INTERFACE = "system interface"
_POOL = "load-balance pool"
_SSL_PROFILE = "load-balance client-ssl-profile"
_MEMBERS = "pool_member"


class ContextError(ValueError):
    pass


class SnapshotContext:
    __slots__ = ("sha256", "identity", "complete", "limitations")

    def __init__(self, token, sha256, identity, complete, limitations):
        if token is not _TOKEN:
            raise TypeError("a snapshot context is built by build_context only")
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "complete", complete)
        object.__setattr__(self, "limitations", limitations)

    def __setattr__(self, name, value):
        raise AttributeError("a snapshot context is read-only")


def _text(value, what):
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or not value.isprintable():
        raise ContextError("%s must be a short printable string" % what)
    return value


def build_context(meta, text_sha256):
    if not isinstance(text_sha256, str) or not _SHA256.fullmatch(text_sha256):
        raise ContextError("the digest of the loaded snapshot is not a sha256")
    if not isinstance(meta, dict) or set(meta) != _META_KEYS:
        raise ContextError("snapshot metadata must carry exactly: " + ", ".join(sorted(_META_KEYS)))
    if type(meta["version"]) is not int or meta["version"] != 1:
        raise ContextError("snapshot metadata version must be 1")
    if meta["sha256"] != text_sha256:
        raise ContextError("snapshot metadata belongs to another snapshot")
    identity = meta["identity"]
    if not isinstance(identity, dict) or set(identity) != _IDENTITY_KEYS:
        raise ContextError("identity must carry exactly: " + ", ".join(sorted(_IDENTITY_KEYS)))
    measured = tuple(_text(identity[name], "identity " + name) for name in ("platform", "version", "build"))
    complete, limits = meta["configuration_complete"], meta["visibility_limitations"]
    if type(complete) is not bool:
        raise ContextError("configuration_complete must be a boolean")
    if not isinstance(limits, list) or len(limits) > len(KNOWN_LIMITATIONS):
        raise ContextError("visibility_limitations must be a list")
    if any(not isinstance(item, str) or item not in KNOWN_LIMITATIONS for item in limits) or len(set(limits)) != len(limits):
        raise ContextError("visibility_limitations holds an unknown or repeated name")
    if complete == bool(limits):
        raise ContextError("configuration_complete contradicts visibility_limitations")
    return SnapshotContext(_TOKEN, text_sha256, measured, complete, frozenset(limits))


def from_helper_metadata(helper, text_sha256):
    if not isinstance(helper, dict) or not _HELPER_REQUIRED <= set(helper):
        raise ContextError("helper metadata must carry: " + ", ".join(sorted(_HELPER_REQUIRED)))
    firmware = helper["firmware"]
    if not isinstance(firmware, dict) or set(firmware) != _FIRMWARE_KEYS:
        raise ContextError("helper firmware must carry exactly: " + ", ".join(sorted(_FIRMWARE_KEYS)))
    for key in ("content_sha256", "snapshot_sha256"):
        if key in helper and helper[key] != text_sha256:
            raise ContextError("snapshot metadata belongs to another snapshot")
    return {
        "version": 1,
        "sha256": text_sha256,
        "identity": {"platform": firmware["model"], "version": firmware["version"], "build": firmware["build"]},
        "configuration_complete": helper["configuration_complete"],
        "visibility_limitations": helper["visibility_limitations"],
    }


def load_context(path, text_sha256):
    try:
        data = read_regular(path, MAX_CONTEXT_BYTES)
        meta = jsontext.loads(data.decode("utf-8"))
    except (InputError, jsontext.JsonError, UnicodeError) as error:
        raise ContextError("snapshot metadata cannot be read: %s" % error) from None
    if isinstance(meta, dict) and "firmware" in meta:
        meta = from_helper_metadata(meta, text_sha256)
    return build_context(meta, text_sha256)


def attach(policy, context):
    result = {key: value for key, value in (policy or {}).items() if key != CONTEXT_KEY}
    if context is not None:
        if not isinstance(context, SnapshotContext):
            raise TypeError("context must come from build_context")
        result[CONTEXT_KEY] = context
    return result


def _context(policy):
    value = policy.get(CONTEXT_KEY) if isinstance(policy, dict) else None
    return value if isinstance(value, SnapshotContext) else None


def _marked(values):
    return any(item.startswith(_MARKS) for item in values)


def _entries(tree, name):
    section = tree.section(name)
    return None if section is None else section.entries


def _version_reason(context):
    if context is None:
        return REASON_NO_CONTEXT
    return None if context.identity == SUPPORTED else REASON_IDENTITY


@check("fortiadc_unsupported_version", contextual=True)
def fortiadc_unsupported_version(tree, policy=None):
    context = _context(policy)
    reason = _version_reason(context)
    if reason is None:
        return
    platform, version, build = context.identity if context is not None else ("", "", "")
    yield {
        "object_key": "identity",
        "section": "identity",
        "line": 0,
        "evidence": {"reason": reason, "platform": platform, "version": version, "build": build},
    }


@check("fortiadc_vdom_unsupported", contextual=True)
def fortiadc_vdom_unsupported(tree, policy=None):
    context = _context(policy)
    reason, count, line = None, 0, 0
    for name in ("vdom", "global"):
        section = tree.section(name)
        if section is not None:
            reason, count, line = "vdom-section", len(section.entries), section.line
            break
    else:
        vdoms = _entries(tree, "system vdom")
        if vdoms is not None and len(vdoms) > 1:
            reason, count, line = "multiple-vdoms", len(vdoms), tree.section("system vdom").line
        elif context is not None and VDOM_LIMITATION in context.limitations:
            reason = VDOM_LIMITATION
    if reason is not None:
        yield {"object_key": "vdom", "section": "vdom", "line": line, "evidence": {"reason": reason, "vdoms": count}}


def _blocked(context, areas):
    if context.complete:
        return None
    for name in sorted(context.limitations):
        if name in GLOBAL_LIMITATIONS or name == VDOM_LIMITATION or name in areas:
            return "visibility:" + name
    return None


def _probe(areas, hits, undetermined):
    def status(tree, policy=None):
        context = _context(policy)
        reason = _version_reason(context)
        if reason is not None:
            return NOT_EVALUATED, reason
        if any(True for _ in hits(tree)):
            return EVALUATED, ""
        reason = _blocked(context, areas) or undetermined(tree)
        return (NOT_EVALUATED, reason) if reason else (EVALUATED, "")
    return status


def _attribute_gap(tree, section, attribute):
    entries = _entries(tree, section)
    if entries is None:
        return REASON_SECTION if section in (_ADMIN, _INTERFACE) else None
    for node in entries.values():
        values = node.values(attribute)
        if _marked(values) or _marked((node.path[-1],)):
            return REASON_MARKER
        if not values:
            return REASON_DEFAULT
    return None


def _open(values):
    return any(item in _OPEN_HOSTS for item in values) or tuple(values[:2]) == ("0.0.0.0", "0.0.0.0")


def _trusted_hosts_hits(tree):
    for name, node in (_entries(tree, _ADMIN) or {}).items():
        values = node.values("trusted-hosts")
        if not _marked(values) and _open(values):
            yield {
                "object_key": "/".join(node.path),
                "section": _ADMIN,
                "line": node.line_of("trusted-hosts"),
                "evidence": {"admin": name, "trusted_hosts": " ".join(values)},
            }


def _plaintext_hits(tree):
    for name, node in (_entries(tree, _INTERFACE) or {}).items():
        values = node.values("allowaccess")
        if _marked(values):
            continue
        for service in _PLAINTEXT_SERVICES:
            if service in values:
                yield {
                    "object_key": "%s/%s" % ("/".join(node.path), service),
                    "section": _INTERFACE,
                    "line": node.line_of("allowaccess"),
                    "evidence": {"interface": name, "service": service},
                }


def _legacy_tls_hits(tree):
    for name, node in (_entries(tree, _SSL_PROFILE) or {}).items():
        values = node.values("ssl-allowed-versions")
        found = sorted(item for item in values if item in _LEGACY_TLS)
        if found and not _marked(values):
            yield {
                "object_key": "/".join(node.path),
                "section": _SSL_PROFILE,
                "line": node.line_of("ssl-allowed-versions"),
                "evidence": {"profile": name, "versions": " ".join(found)},
            }


def _no_health_check_hits(tree):
    for name, node in (_entries(tree, _POOL) or {}).items():
        if node.values("health-check-ctrl") == ("disable",):
            yield {
                "object_key": "/".join(node.path),
                "section": _POOL,
                "line": node.line_of("health-check-ctrl"),
                "evidence": {"pool": name},
            }


def _single_member_hits(tree):
    for name, node in (_entries(tree, _POOL) or {}).items():
        members = node.section(_MEMBERS)
        if members is not None and len(members.entries) == 1:
            yield {
                "object_key": "/".join(node.path),
                "section": _POOL,
                "line": members.line,
                "evidence": {"pool": name},
            }


def _single_member_gap(tree):
    for node in (_entries(tree, _POOL) or {}).values():
        if _marked((node.path[-1],)):
            return REASON_MARKER
    return None


def _contextual(name, hits, areas, undetermined):
    def evaluate(tree, policy=None):
        yield from hits(tree)
    evaluate.__name__ = name
    check(name, contextual=True, status=_probe(areas, hits, undetermined))(evaluate)
    globals()[name] = evaluate


_contextual("fortiadc_trusted_hosts_open", _trusted_hosts_hits, frozenset(("system",)),
            lambda tree: _attribute_gap(tree, _ADMIN, "trusted-hosts"))
_contextual("fortiadc_plaintext_admin_access", _plaintext_hits, frozenset(("system", "networking")),
            lambda tree: _attribute_gap(tree, _INTERFACE, "allowaccess"))
_contextual("fortiadc_legacy_tls_versions", _legacy_tls_hits, frozenset(("load-balance",)),
            lambda tree: _attribute_gap(tree, _SSL_PROFILE, "ssl-allowed-versions"))
_contextual("fortiadc_pool_no_health_check", _no_health_check_hits, frozenset(("load-balance",)),
            lambda tree: _attribute_gap(tree, _POOL, "health-check-ctrl"))
_contextual("fortiadc_pool_single_member", _single_member_hits, frozenset(("load-balance",)),
            _single_member_gap)


REASON_FACTORY = "factory-provenance-unproven"
_MAX_BINDINGS = 8


def _certificate_bindings(tree):
    for name, node in (_entries(tree, _SSL_PROFILE) or {}).items():
        group = node.value("local-cert-group")
        if group:
            yield "%s=%s" % (name, group)


def _factory_hits(tree):
    return iter(())


def _factory_status(tree, policy=None):
    context = _context(policy)
    reason = _version_reason(context)
    if reason is not None:
        return NOT_EVALUATED, reason
    bindings = list(_certificate_bindings(tree))
    shown = ",".join(bindings[:_MAX_BINDINGS])[:200]
    return NOT_EVALUATED, REASON_FACTORY + (":" + shown if shown else "")


_contextual_status = check("fortiadc_factory_certificate", contextual=True, status=_factory_status)
fortiadc_factory_certificate = _contextual_status(lambda tree, policy=None: _factory_hits(tree))
