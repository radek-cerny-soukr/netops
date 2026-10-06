from __future__ import annotations

from dataclasses import dataclass

from .engine import EVALUATED

STATE_NEW = "new"
STATE_OPEN_KNOWN = "open-known"
STATE_SUPPRESSED = "suppressed"
STATE_GONE = "gone"
STATE_NOT_EVALUATED = "not-evaluated"

STATES = (STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED, STATE_GONE)


@dataclass(frozen=True)
class GoneFinding:
    fingerprint: str
    rule_id: str
    object_key: str
    severity: str


@dataclass(frozen=True)
class Classification:
    states: tuple
    gone: tuple
    orphaned_suppressions: tuple
    expired_suppressions: tuple
    counts: dict
    not_evaluated: tuple = ()


UNEVALUATED_RULES = frozenset((
    "fortios.snapshot.incomplete", "exos.snapshot.incomplete", "fortios.scope.vdom-unsupported",
))


def suppressions_for_device(suppressions, device) -> tuple:
    return tuple(item for item in suppressions if getattr(item, "device", device) == device)


def evaluation_complete(findings, statuses=None) -> bool:
    for item in findings:
        rule_id = item["rule_id"] if hasattr(item, "keys") else getattr(item, "rule_id", None)
        if rule_id in UNEVALUATED_RULES:
            return False
    return not any(item["required"] and item["status"] != EVALUATED for item in (statuses or {}).values())


def unevaluated_rules(statuses) -> frozenset:
    return frozenset(rule for rule, item in (statuses or {}).items() if item["status"] != EVALUATED)


def stored_statuses(store, tenant, run_id) -> dict:
    reader = getattr(store, "rule_status_for_run", None)
    return {} if reader is None else reader(tenant, run_id)


def last_evaluated(store, tenant, runs) -> tuple:
    for run in runs:
        findings = store.findings_for_run(tenant, run["id"])
        if evaluation_complete(findings, stored_statuses(store, tenant, run["id"])):
            return run, findings
    return None, ()


def _today(findings) -> frozenset:
    return frozenset(finding.fingerprint() for finding in findings)


def _gone(previous, today) -> tuple:
    items = {}
    for entry in previous:
        fingerprint = entry["fingerprint"]
        if fingerprint in today or fingerprint in items:
            continue
        items[fingerprint] = GoneFinding(
            fingerprint=fingerprint,
            rule_id=entry["rule_id"],
            object_key=entry["object_key"],
            severity=entry["severity"],
        )
    return tuple(sorted(items.values(), key=lambda item: (item.rule_id, item.object_key, item.fingerprint)))


def _suppression_key(suppression) -> tuple:
    return (
        suppression.fingerprint,
        str(suppression.expires),
        str(suppression.author),
        str(suppression.reason),
    )


def classify(findings, baseline_fingerprints, suppressions, previous, now, statuses=None) -> Classification:
    findings = tuple(findings)
    evaluated = evaluation_complete(findings, statuses)
    skipped = unevaluated_rules(statuses)
    today = _today(findings)
    baseline = frozenset(baseline_fingerprints)
    active = set()
    expired = []
    orphaned = []
    for suppression in suppressions:
        if suppression.is_active(now):
            active.add(suppression.fingerprint)
        else:
            expired.append(suppression)
        if evaluated and suppression.fingerprint not in today and getattr(suppression, "rule_id", None) not in skipped:
            orphaned.append(suppression)
    counts = {STATE_NEW: 0, STATE_OPEN_KNOWN: 0, STATE_SUPPRESSED: 0, STATE_GONE: 0}
    states = []
    for fingerprint in sorted(today):
        if fingerprint in active:
            state = STATE_SUPPRESSED
        elif fingerprint in baseline:
            state = STATE_OPEN_KNOWN
        else:
            state = STATE_NEW
        states.append((fingerprint, state))
        counts[state] += 1
    absent = _gone(previous, today)
    gone = tuple(item for item in absent if item.rule_id not in skipped) if evaluated else ()
    counts[STATE_GONE] = len(gone)
    return Classification(
        states=tuple(states),
        gone=gone,
        orphaned_suppressions=tuple(sorted(orphaned, key=_suppression_key)),
        expired_suppressions=tuple(sorted(expired, key=_suppression_key)),
        counts=counts,
        not_evaluated=tuple(item for item in absent if item.rule_id in skipped) if evaluated else absent,
    )
