from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("high", "medium", "low", "info")
CLASSES = ("fakt", "usudek")
EVIDENCE_TYPES = (str, int, bool)
FINGERPRINT_VERSION = 2
FINGERPRINT_SEPARATOR = "\x1f"


class FingerprintError(ValueError):
    pass


def checked_component(name: str, value: str) -> str:
    if FINGERPRINT_SEPARATOR in value:
        raise FingerprintError("%s holds U+001F, the separator of the finding fingerprint" % name)
    return value


def _digest(*components) -> str:
    values = tuple(checked_component(name, value) for name, value in components)
    return hashlib.sha256(FINGERPRINT_SEPARATOR.join(values).encode("utf-8")).hexdigest()


def fingerprint_of(rule_id, rule_version, tenant, device, object_key) -> str:
    return _digest(
        ("rule_id", rule_id),
        ("rule_version", str(rule_version)),
        ("tenant", tenant),
        ("device", device),
        ("object_key", object_key),
    )


def fingerprint_v1(rule_id, rule_version, device, object_key) -> str:
    return _digest(
        ("rule_id", rule_id), ("rule_version", str(rule_version)), ("device", device), ("object_key", object_key)
    )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_version: int
    tenant: str
    device: str
    object_key: str
    severity: str
    rule_class: str
    section: str
    line: int
    evidence: tuple = field(default_factory=tuple)

    def fingerprint(self) -> str:
        return fingerprint_of(
            self.rule_id, self.rule_version, self.tenant, self.device, self.object_key
        )

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "tenant": self.tenant,
            "device": self.device,
            "object_key": self.object_key,
            "severity": self.severity,
            "class": self.rule_class,
            "section": self.section,
            "line": self.line,
            "evidence": dict(self.evidence),
            "fingerprint": self.fingerprint(),
        }
