from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .findings import CLASSES, EVIDENCE_TYPES, SEVERITIES, Finding

CATALOG_DIR = Path(__file__).parent / "catalog"

_CHECKS = {}


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


def check(name):
    def register(function):
        if name in _CHECKS:
            raise CheckError("duplicate check %s" % name)
        _CHECKS[name] = function
        return function

    return register


def registered_checks() -> tuple:
    return tuple(sorted(_CHECKS))


def load_catalog(platform: str) -> tuple:
    path = CATALOG_DIR / ("%s.json" % platform)
    document = json.loads(path.read_text(encoding="utf-8"))
    rules, seen = [], set()
    for item in document["rules"]:
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


def _collect(tree, tenant: str, device: str, rules) -> list:
    findings = []
    for rule in rules:
        for hit in _CHECKS[rule.check](tree):
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


def run(tree, tenant: str, device: str, rules) -> tuple:
    gated = _collect(tree, tenant, device, [rule for rule in rules if rule.scope_gate])
    if gated:
        return _ordered(gated)
    return _ordered(_collect(tree, tenant, device, [rule for rule in rules if not rule.scope_gate]))
