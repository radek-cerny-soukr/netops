from __future__ import annotations

import json
import logging
import re
from importlib import import_module
from dataclasses import dataclass
from pathlib import Path

from .findings import CLASSES, EVIDENCE_TYPES, SEVERITIES, Finding, FingerprintError, checked_component

from .platforms import AuditContext, PLATFORMS, TAXONOMY, VISIBLE

CATALOG_DIR = Path(__file__).parent / "catalog"
LOGGER = logging.getLogger(__name__)

_CHECKS = {}
_CONTEXTUAL = set()
_STATUS = {}
_AUDITOR = {}

EVALUATED = "evaluated"
NOT_EVALUATED = "not-evaluated"
UNSUPPORTED = "unsupported"
RULE_STATES = (EVALUATED, NOT_EVALUATED, UNSUPPORTED)
SECTION_MISSING = "section-missing"


class CatalogError(Exception):
    pass


class CheckError(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    check: str
    rule_class: str
    severity: str
    evidence_fields: tuple
    title: str
    remediation: str
    refs: tuple
    known_false_positives: str
    scope_gate: bool = False
    sections: tuple = ()
    default_sections: tuple = ()


def section_missing(name: str) -> str:
    return "%s: %s" % (SECTION_MISSING, name)


def check(name, contextual=False, status=None, *, audit_context=False, applies=None, partial=False,
          offline_scope=None):
    """Register a check. Auditor callbacks receive (tree, AuditContext)."""
    if (applies is not None or partial or offline_scope is not None) and not audit_context:
        raise CheckError("Auditor context is required for applicability or partial evaluation")
    if partial and status is None:
        raise CheckError("partial evaluation requires a status callback")
    def register(function):
        if name in _CHECKS:
            raise CheckError("duplicate check %s" % name)
        _CHECKS[name] = function
        if audit_context:
            _AUDITOR[name] = (applies, partial, offline_scope)
        if contextual:
            _CONTEXTUAL.add(name)
        if status is not None:
            _STATUS[name] = status
        return function

    return register


def registered_checks() -> tuple:
    return tuple(sorted(_CHECKS))


LEGACY_CATALOGS = frozenset({"exos", "fortiadc", "fortios"})
UNTERMINATED_UPM = "unterminated-upm-profile"
RULE_ID = re.compile(r"([a-z0-9-]+)\.([a-z0-9-]+)\.([a-z0-9-]+)")
VERSION = re.compile(r"([a-z0-9-]+):[1-9][0-9]*:[a-f0-9]{64}(?::[a-f0-9]{64})?")


def catalog_path(platform):
    if not isinstance(platform, str) or platform not in PLATFORMS:
        raise CatalogError("unknown Auditor catalog")
    return CATALOG_DIR / ("%s.json" % platform)


def run_platform(rules_version):
    match = VERSION.fullmatch(rules_version) if isinstance(rules_version, str) else None
    return match[1] if match and match[1] in PLATFORMS else None


def available_platforms(*, require_all=False):
    available = []
    for platform in PLATFORMS:
        try:
            if not require_all and platform not in LEGACY_CATALOGS and not catalog_path(platform).exists():
                continue
            load_catalog(platform)
        except (CatalogError, OSError) as error:
            if require_all:
                raise
            LOGGER.warning("Auditor catalog %s is unavailable: %s", platform, error)
            continue
        available.append(platform)
    return tuple(available)


def load_catalog(platform: str) -> tuple:
    path = catalog_path(platform)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CatalogError("rules are unavailable for %s: catalog is missing" % platform) from None
    except (ValueError, RecursionError):
        raise CatalogError("catalog is not readable JSON") from None
    name = f"{__package__}.{PLATFORMS[platform].checks_module}"
    try:
        import_module(name)
    except ModuleNotFoundError as error:
        if error.name != name:
            raise
        raise CatalogError("catalog check module is missing for %s" % platform) from None
    rows = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not rows:
        raise CatalogError("catalog has no rule definitions")
    rules, seen = [], set()
    for item in rows:
        required = ("id", "version", "check", "class", "severity", "evidence_fields", "title", "remediation")
        if (not isinstance(item, dict) or any(key not in item for key in required)
                or any(not isinstance(item[key], str) or not item[key].strip()
                       for key in required if key not in ("version", "evidence_fields"))
                or type(item["version"]) is not int or item["version"] <= 0
                or not isinstance(item["evidence_fields"], list) or not item["evidence_fields"]
                or not all(isinstance(key, str) and key for key in item["evidence_fields"])
                or not isinstance(item.get("refs", []), list)
                or not all(isinstance(ref, str) for ref in item.get("refs", []))
                or not isinstance(item.get("known_false_positives", ""), str)
                or type(item.get("scope_gate", False)) is not bool):
            raise CatalogError("incomplete or invalid rule definition")
        try:
            checked_component("id", item["id"])
        except FingerprintError as error:
            raise CatalogError("%r: %s" % (item["id"], error)) from None
        match = RULE_ID.fullmatch(item["id"])
        if not match or match[1] != platform or platform not in LEGACY_CATALOGS and match[2] not in TAXONOMY:
            raise CatalogError("invalid rule ID for catalog %s" % platform)
        sections = item.get("sections")
        if not isinstance(sections, list) or not all(isinstance(name, str) and name for name in sections):
            raise CatalogError("%s: sections are not declared" % item["id"])
        defaults = item.get("default_sections", [])
        if not isinstance(defaults, list) or not all(isinstance(name, str) and name for name in defaults):
            raise CatalogError("%s: default sections are not a list of names" % item["id"])
        if set(sections) & set(defaults):
            raise CatalogError("%s: a section is both required and default" % item["id"])
        rule = Rule(
            id=item["id"],
            version=item["version"],
            check=item["check"],
            rule_class=item["class"],
            severity=item["severity"],
            evidence_fields=tuple(item["evidence_fields"]),
            title=item["title"],
            remediation=item["remediation"],
            refs=tuple(item.get("refs", ())),
            known_false_positives=item.get("known_false_positives", ""),
            scope_gate=bool(item.get("scope_gate", False)),
            sections=tuple(sections),
            default_sections=tuple(defaults),
        )
        if rule.id in seen:
            raise CatalogError("duplicate rule id %s" % rule.id)
        if rule.severity not in SEVERITIES:
            raise CatalogError("%s: unknown severity %s" % (rule.id, rule.severity))
        if rule.rule_class not in CLASSES:
            raise CatalogError("%s: unknown class %s" % (rule.id, rule.rule_class))
        if rule.rule_class == "usudek" and rule.severity == "high":
            raise CatalogError("%s: class usudek must not be high severity" % rule.id)
        if rule.check not in _CHECKS:
            raise CatalogError("%s: check %s is not implemented" % (rule.id, rule.check))
        seen.add(rule.id)
        rules.append(rule)
    return tuple(rules)


def _evidence(rule: Rule, raw: dict) -> tuple:
    unknown = set(raw) - set(rule.evidence_fields)
    if unknown:
        raise CheckError("%s: evidence fields not declared: %s" % (rule.id, ", ".join(sorted(unknown))))
    for key, value in raw.items():
        if not isinstance(value, EVIDENCE_TYPES):
            raise CheckError("%s: evidence %s is not a scalar" % (rule.id, key))
    return tuple(sorted(raw.items()))


def _collect(tree, tenant: str, device: str, rules, policy=None, context=None) -> list:
    findings = []
    for rule in rules:
        if rule.check in _AUDITOR:
            arguments = (tree, context or AuditContext(management_policy=policy))
        else:
            arguments = (tree, policy) if rule.check in _CONTEXTUAL else (tree,)
        for hit in _CHECKS[rule.check](*arguments):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_version=rule.version,
                    tenant=tenant,
                    device=device,
                    object_key=hit["object_key"],
                    severity=rule.severity,
                    rule_class=rule.rule_class,
                    section=hit["section"],
                    line=hit["line"],
                    evidence=_evidence(rule, hit.get("evidence", {})),
                )
            )
    return findings


def _ordered(findings) -> tuple:
    return tuple(sorted(findings, key=lambda f: (f.rule_id, f.object_key)))


def _present(tree, name) -> bool:
    modules = getattr(tree, "modules", None)
    if modules is not None:
        return name in modules
    return tree.section(name) is not None


def _status(rule, tree, policy, context) -> tuple:
    probe = _STATUS.get(rule.check)
    argument = (context or AuditContext(management_policy=policy)) if rule.check in _AUDITOR else policy
    state, reason = (EVALUATED, "") if probe is None else probe(tree, argument)
    if state not in RULE_STATES:
        raise CheckError("%s: unknown rule state %s" % (rule.id, state))
    if state == EVALUATED:
        for name in rule.sections:
            if context is not None and context.snapshot is not None and rule.check in _AUDITOR:
                visibility = context.visibility(name)
                if visibility.state != VISIBLE:
                    return NOT_EVALUATED, visibility.reason
            elif not _present(tree, name):
                return NOT_EVALUATED, section_missing(name)
    return state, reason


def _applies(rule, context):
    predicate = _AUDITOR.get(rule.check, (None, False, None))[0]
    return predicate is None or context is not None and bool(predicate(context.intent))


def is_required(rule, context):
    return _applies(rule, context)


def evaluate(tree, tenant: str, device: str, rules, policy=None, *, context=None) -> tuple:
    gates = [rule for rule in rules if rule.scope_gate]
    gated = _ordered(_collect(tree, tenant, device, gates, policy, context))
    states = {rule.id: (EVALUATED, "") for rule in gates}
    if gated:
        for rule in rules:
            states.setdefault(rule.id, (UNSUPPORTED, gated[0].rule_id))
        return gated, states
    if getattr(tree, "unterminated_upm", False):
        # NETOPS-009: after an unterminated UPM profile the rest of an EXOS snapshot cannot be
        # attributed, so no rule is evaluated - with or without audit intent, file or collection.
        for rule in rules:
            states.setdefault(rule.id, (NOT_EVALUATED, UNTERMINATED_UPM))
        return (), states
    findings = []
    for rule in rules:
        if rule.scope_gate:
            continue
        if not _applies(rule, context):
            states[rule.id] = (EVALUATED, "")
            continue
        states[rule.id] = _status(rule, tree, policy, context)
        state = states[rule.id][0]
        registration = _AUDITOR.get(rule.check)
        if state == EVALUATED:
            findings.extend(_collect(tree, tenant, device, [rule], policy, context))
        elif state == NOT_EVALUATED and registration is not None:
            _, partial, offline_scope = registration
            if context is not None and context.live:
                if partial and context.snapshot is not None and context.snapshot.complete:
                    findings.extend(_collect(tree, tenant, device, [rule], policy, context))
            elif context is None or not context.intent:
                reason = states[rule.id][1]
                preserve = reason == "admin-visibility-unproven" or (
                    context is None and reason.startswith(SECTION_MISSING)
                )
                in_scope = (offline_scope(tree) if offline_scope is not None else
                            any(_present(tree, section) for section in rule.sections))
                if not preserve and not in_scope:
                    findings.extend(_collect(tree, tenant, device, [rule], policy, context))
                    states[rule.id] = (EVALUATED, "")
    return _ordered(findings), states


def run(tree, tenant: str, device: str, rules, policy=None) -> tuple:
    return evaluate(tree, tenant, device, rules, policy)[0]
