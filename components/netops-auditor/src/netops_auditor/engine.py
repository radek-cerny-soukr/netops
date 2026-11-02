from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .findings import CLASSES, EVIDENCE_TYPES, SEVERITIES, Finding, FingerprintError, checked_component

CATALOG_DIR = Path(__file__).parent / "catalog"

_CHECKS = {}
_CONTEXTUAL = set()
_STATUS = {}

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


def check(name, contextual=False, status=None):
    def register(function):
        if name in _CHECKS:
            raise CheckError("duplicate check %s" % name)
        _CHECKS[name] = function
        if contextual:
            _CONTEXTUAL.add(name)
        if status is not None:
            _STATUS[name] = status
        return function

    return register


def registered_checks() -> tuple:
    return tuple(sorted(_CHECKS))


def load_catalog(platform: str) -> tuple:
    path = CATALOG_DIR / ("%s.json" % platform)
    document = json.loads(path.read_text(encoding="utf-8"))
    rules, seen = [], set()
    for item in document["rules"]:
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
        try:
            checked_component("id", rule.id)
        except FingerprintError as error:
            raise CatalogError("%r: %s" % (rule.id, error)) from None
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


def _collect(tree, tenant: str, device: str, rules, policy=None) -> list:
    findings = []
    for rule in rules:
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


def _status(rule, tree, policy) -> tuple:
    probe = _STATUS.get(rule.check)
    state, reason = (EVALUATED, "") if probe is None else probe(tree, policy)
    if state not in RULE_STATES:
        raise CheckError("%s: unknown rule state %s" % (rule.id, state))
    if state == EVALUATED:
        for name in rule.sections:
            if not _present(tree, name):
                return NOT_EVALUATED, section_missing(name)
    return state, reason


def evaluate(tree, tenant: str, device: str, rules, policy=None) -> tuple:
    gates = [rule for rule in rules if rule.scope_gate]
    gated = _ordered(_collect(tree, tenant, device, gates, policy))
    states = {rule.id: (EVALUATED, "") for rule in gates}
    if gated:
        for rule in rules:
            states.setdefault(rule.id, (UNSUPPORTED, gated[0].rule_id))
        return gated, states
    findings = []
    for rule in rules:
        if rule.scope_gate:
            continue
        states[rule.id] = _status(rule, tree, policy)
        if states[rule.id][0] == EVALUATED:
            findings.extend(_collect(tree, tenant, device, [rule], policy))
    return _ordered(findings), states


def run(tree, tenant: str, device: str, rules, policy=None) -> tuple:
    return evaluate(tree, tenant, device, rules, policy)[0]
