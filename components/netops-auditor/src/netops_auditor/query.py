from __future__ import annotations

from datetime import datetime, timezone

from .findings import SEVERITIES
from .state import STATE_GONE, STATES, classify
from .state import STATE_NOT_EVALUATED, evaluation_complete, last_evaluated
from .suppressions import MOMENT_FORMAT

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_NEVER = "never"
STATUS_INCOMPLETE = "incomplete"
STATUSES = (STATUS_FRESH, STATUS_STALE, STATUS_NEVER, STATUS_INCOMPLETE)

DEFAULT_STALE_AFTER_HOURS = 26.0

RUN_PRESENT = "present"
RUN_NEVER = "never"
RUN_BEFORE_SINCE = "before-since"
RUN_STATES = (RUN_PRESENT, RUN_NEVER, RUN_BEFORE_SINCE)

GROUP_BY_OBJECT = "object"
GROUP_BY = (GROUP_BY_OBJECT,)

STATUS_KEYS = ("tenant", "stale_after_hours", "devices", "never_audited", "totals")

DEVICE_STATUS_KEYS = (
    "device",
    "state",
    "last_audit",
    "age_hours",
    "run_id",
    "findings_total",
    "severity_counts",
    "state_counts",
)

TOTALS_KEYS = ("devices", STATUS_FRESH, STATUS_STALE, STATUS_NEVER)

RULE_KEYS = ("id", "version", "class", "severity", "title", "refs")

RULE_DETAIL_KEYS = RULE_KEYS + ("remediation", "known_false_positives", "evidence_fields")

FINDING_KEYS = (
    "rule_id",
    "rule_version",
    "severity",
    "class",
    "object_key",
    "section",
    "line",
    "fingerprint",
    "evidence",
    "state",
)

GONE_KEYS = ("rule_id", "severity", "object_key", "fingerprint", "state")

GROUP_KEYS = ("object_key", "count", "severity", "rule_ids", "states", "fingerprints")

LISTING_KEYS = (
    "tenant",
    "device",
    "run_state",
    "run_id",
    "started_at",
    "total",
    "counts",
    "findings",
    "gone",
    "groups",
)

BASELINE_KEYS = ("accepted_at", "accepted_by", "note", "run_id")

SUPPRESSION_KEYS = ("author", "reason", "expires", "active")

DETAIL_KEYS = FINDING_KEYS + ("tenant", "device", "run_id", "started_at", "baseline", "suppression")

RUN_KEYS = ("run_id", "started_at", "rules_version", "snapshot_sha256", "findings_total")

COMPARE_ITEM_KEYS = ("rule_id", "severity", "object_key", "fingerprint")

COMPARE_COUNT_KEYS = ("added", "removed", "kept")

COMPARE_KEYS = ("tenant", "device", "first", "second", "added", "removed", "kept", "counts")

_SELECT_TENANT_DEVICES = (
    "SELECT device FROM runs WHERE tenant = ?"
    " UNION SELECT device FROM channel_events WHERE tenant = ?"
    " ORDER BY device"
)


class QueryError(Exception):
    pass


class _Stored:
    __slots__ = ("_fingerprint", "rule_id")

    def __init__(self, fingerprint, rule_id=None):
        self._fingerprint = fingerprint
        self.rule_id = rule_id

    def fingerprint(self) -> str:
        return self._fingerprint


def _checked_text(name: str, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QueryError("%s must be a non-empty string, got %r" % (name, value))
    return value


def _checked_now(now, name: str = "now") -> datetime:
    if not isinstance(now, datetime):
        raise QueryError("%s must be a timezone aware datetime, got %r" % (name, now))
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise QueryError("%s must be timezone aware, got %r" % (name, now))
    return now


def _checked_hours(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise QueryError("stale_after_hours must be a positive number, got %r" % (value,))
    return float(value)


def _checked_choice(name: str, value, allowed):
    if value is None:
        return None
    if not isinstance(value, str) or value not in allowed:
        raise QueryError("%s must be one of %s, got %r" % (name, ", ".join(allowed), value))
    return value


def _checked_severity(value) -> str:
    if not isinstance(value, str) or value not in SEVERITIES:
        raise QueryError("store holds an unknown severity: %r" % (value,))
    return value


def _moment(value) -> datetime:
    try:
        parsed = datetime.strptime(value, MOMENT_FORMAT)
    except (TypeError, ValueError):
        raise QueryError("store holds an unreadable timestamp: %r" % (value,)) from None
    return parsed.replace(tzinfo=timezone.utc)


def _checked_since(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return _checked_now(value, "since")
    if not isinstance(value, str):
        raise QueryError("since must be ISO 8601 UTC %s, got %r" % (MOMENT_FORMAT, value))
    try:
        parsed = datetime.strptime(value, MOMENT_FORMAT)
    except ValueError:
        raise QueryError("since must be ISO 8601 UTC %s, got %r" % (MOMENT_FORMAT, value)) from None
    if parsed.strftime(MOMENT_FORMAT) != value:
        raise QueryError("since must be ISO 8601 UTC %s, got %r" % (MOMENT_FORMAT, value))
    return parsed.replace(tzinfo=timezone.utc)


def _expires_text(value) -> str:
    if not isinstance(value, datetime):
        raise QueryError("suppression expires must be a datetime, got %r" % (value,))
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.strftime(MOMENT_FORMAT)
    return value.astimezone(timezone.utc).strftime(MOMENT_FORMAT)


def _tenant_devices(store, tenant) -> tuple:
    rows = store._connection.execute(_SELECT_TENANT_DEVICES, (tenant, tenant)).fetchall()
    return tuple(row[0] for row in rows)


def _runs(store, tenant, device) -> tuple:
    return tuple(store.runs_for_device(tenant, device))


def _for_device(suppressions, device) -> tuple:
    return tuple(item for item in suppressions if getattr(item, "device", device) == device)


def _classified(store, tenant, device, runs, stored, suppressions, now):
    previous = last_evaluated(store, tenant, runs[1:])[1]
    return classify(
        tuple(_Stored(item["fingerprint"], item["rule_id"]) for item in stored),
        store.baseline_fingerprints(tenant, device),
        _for_device(suppressions, device),
        previous,
        now,
    )


def _severity_counts(findings) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    for item in findings:
        counts[_checked_severity(item["severity"])] += 1
    return counts


def _state_counts(result) -> dict:
    return {name: result.counts[name] for name in STATES}


def _present_entry(item, state: str) -> dict:
    return {
        "rule_id": item["rule_id"],
        "rule_version": item["rule_version"],
        "severity": _checked_severity(item["severity"]),
        "class": item["class"],
        "object_key": item["object_key"],
        "section": item["section"],
        "line": item["line"],
        "fingerprint": item["fingerprint"],
        "evidence": dict(sorted(item["evidence"].items())),
        "state": state,
    }


def _gone_entry(item) -> dict:
    return {
        "rule_id": item.rule_id,
        "severity": _checked_severity(item.severity),
        "object_key": item.object_key,
        "fingerprint": item.fingerprint,
        "state": STATE_GONE,
    }


def _compare_entry(item) -> dict:
    return {
        "rule_id": item["rule_id"],
        "severity": _checked_severity(item["severity"]),
        "object_key": item["object_key"],
        "fingerprint": item["fingerprint"],
    }


def _worst_severity(entries) -> str:
    present = frozenset(entry["severity"] for entry in entries)
    for name in SEVERITIES:
        if name in present:
            return name
    raise QueryError("group holds no severity")


def _groups(entries) -> tuple:
    buckets = {}
    for entry in entries:
        buckets.setdefault(entry["object_key"], []).append(entry)
    groups = []
    for object_key in sorted(buckets):
        items = buckets[object_key]
        states = frozenset(item["state"] for item in items)
        groups.append(
            {
                "object_key": object_key,
                "count": len(items),
                "severity": _worst_severity(items),
                "rule_ids": tuple(sorted(frozenset(item["rule_id"] for item in items))),
                "states": tuple(name for name in STATES + (STATE_NOT_EVALUATED,) if name in states),
                "fingerprints": tuple(sorted(frozenset(item["fingerprint"] for item in items))),
            }
        )
    return tuple(sorted(groups, key=lambda group: (-group["count"], group["object_key"])))


def _device_status(store, tenant, device, now, stale_after_hours) -> dict:
    runs = _runs(store, tenant, device)
    if not runs:
        return {
            "device": device,
            "state": STATUS_NEVER,
            "last_audit": None,
            "age_hours": None,
            "run_id": None,
            "findings_total": 0,
            "severity_counts": dict.fromkeys(SEVERITIES, 0),
            "state_counts": dict.fromkeys(STATES, 0),
        }
    last = runs[0]
    stored = store.findings_for_run(tenant, last["id"])
    result = _classified(store, tenant, device, runs, stored, (), now)
    age = (now - _moment(last["started_at"])).total_seconds() / 3600.0
    return {
        "device": device,
        "state": (STATUS_STALE if age > stale_after_hours else STATUS_FRESH) if evaluation_complete(stored) else STATUS_INCOMPLETE,
        "last_audit": last["started_at"],
        "age_hours": round(age, 2),
        "run_id": last["id"],
        "findings_total": len(stored),
        "severity_counts": _severity_counts(stored),
        "state_counts": _state_counts(result),
    }


def audit_status(store, tenant, device=None, now=None, stale_after_hours=DEFAULT_STALE_AFTER_HOURS) -> dict:
    _checked_text("tenant", tenant)
    moment = _checked_now(now)
    hours = _checked_hours(stale_after_hours)
    if device is None:
        names = _tenant_devices(store, tenant)
    else:
        names = (_checked_text("device", device),)
    devices = tuple(
        _device_status(store, tenant, name, moment, hours) for name in sorted(frozenset(names))
    )
    totals = {"devices": len(devices), STATUS_FRESH: 0, STATUS_STALE: 0, STATUS_NEVER: 0}
    for item in devices:
        totals[item["state"]] = totals.get(item["state"], 0) + 1
    return {
        "tenant": tenant,
        "stale_after_hours": hours,
        "devices": devices,
        "never_audited": tuple(item["device"] for item in devices if item["state"] == STATUS_NEVER),
        "totals": totals,
    }


def _rule_entry(rule) -> dict:
    return {
        "id": rule.id,
        "version": rule.version,
        "class": rule.rule_class,
        "severity": rule.severity,
        "title": rule.title,
        "refs": tuple(rule.refs),
    }


def list_rules(rules) -> tuple:
    return tuple(sorted((_rule_entry(rule) for rule in rules), key=lambda item: item["id"]))


def rule_detail(rules, rule_id) -> dict:
    _checked_text("rule_id", rule_id)
    for rule in rules:
        if rule.id == rule_id:
            entry = _rule_entry(rule)
            entry["remediation"] = rule.remediation
            entry["known_false_positives"] = rule.known_false_positives
            entry["evidence_fields"] = tuple(rule.evidence_fields)
            return entry
    raise QueryError("the catalog holds no rule %r" % (rule_id,))


def _empty_listing(tenant, device, run_state) -> dict:
    return {
        "tenant": tenant,
        "device": device,
        "run_state": run_state,
        "run_id": None,
        "started_at": None,
        "total": 0,
        "counts": dict.fromkeys(STATES, 0),
        "findings": (),
        "gone": (),
        "groups": (),
    }


def list_findings(
    store,
    tenant,
    device,
    suppressions=(),
    now=None,
    severity=None,
    state=None,
    since=None,
    group_by=None,
) -> dict:
    _checked_text("tenant", tenant)
    _checked_text("device", device)
    moment = _checked_now(now)
    wanted_severity = _checked_choice("severity", severity, SEVERITIES)
    wanted_state = _checked_choice("state", state, STATES + (STATE_NOT_EVALUATED,))
    boundary = _checked_since(since)
    grouping = _checked_choice("group_by", group_by, GROUP_BY)
    runs = _runs(store, tenant, device)
    if not runs:
        return _empty_listing(tenant, device, RUN_NEVER)
    last = runs[0]
    if boundary is not None and _moment(last["started_at"]) < boundary:
        return _empty_listing(tenant, device, RUN_BEFORE_SINCE)
    stored = store.findings_for_run(tenant, last["id"])
    result = _classified(store, tenant, device, runs, stored, suppressions, moment)
    states = dict(result.states)
    findings = tuple(_present_entry(item, states[item["fingerprint"]]) for item in stored)
    if not evaluation_complete(stored):
        historical = last_evaluated(store, tenant, runs[1:])[1]
        findings += tuple(_present_entry(item, STATE_NOT_EVALUATED) for item in historical)
    gone = tuple(_gone_entry(item) for item in result.gone)
    if wanted_severity is not None:
        findings = tuple(item for item in findings if item["severity"] == wanted_severity)
        gone = tuple(item for item in gone if item["severity"] == wanted_severity)
    if wanted_state is not None:
        findings = tuple(item for item in findings if item["state"] == wanted_state)
        gone = tuple(item for item in gone if item["state"] == wanted_state)
    entries = findings + gone
    counts = dict.fromkeys(STATES, 0)
    for item in entries:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return {
        "tenant": tenant,
        "device": device,
        "run_state": RUN_PRESENT,
        "run_id": last["id"],
        "started_at": last["started_at"],
        "total": len(entries),
        "counts": counts,
        "findings": findings,
        "gone": gone,
        "groups": _groups(entries) if grouping is not None else (),
    }


def _baseline_entry(store, tenant, device, fingerprint):
    for item in store.baseline_entries(tenant, device):
        if item["fingerprint"] == fingerprint:
            return {
                "accepted_at": item["accepted_at"],
                "accepted_by": item["accepted_by"],
                "note": item["note"],
                "run_id": item["run_id"],
            }
    return None


def _suppression_entry(suppressions, fingerprint, now):
    for item in suppressions:
        if item.fingerprint == fingerprint:
            return {
                "author": item.author,
                "reason": item.reason,
                "expires": _expires_text(item.expires),
                "active": bool(item.is_active(now)),
            }
    return None


def finding_detail(store, tenant, device, fingerprint, suppressions=(), now=None):
    _checked_text("tenant", tenant)
    _checked_text("device", device)
    _checked_text("fingerprint", fingerprint)
    moment = _checked_now(now)
    runs = _runs(store, tenant, device)
    if not runs:
        return None
    last = runs[0]
    stored = store.findings_for_run(tenant, last["id"])
    historical_run, historical = (None, ()) if evaluation_complete(stored) else last_evaluated(store, tenant, runs[1:])
    historical_match = False
    match = None
    for item in stored:
        if item["fingerprint"] == fingerprint:
            match = item
            break
    if match is None:
        match = next((item for item in historical if item["fingerprint"] == fingerprint), None)
        historical_match = match is not None
    if match is None:
        return None
    result = _classified(store, tenant, device, runs, stored, suppressions, moment)
    entry = _present_entry(match, STATE_NOT_EVALUATED if historical_match else dict(result.states)[fingerprint])
    if historical_match:
        last = historical_run
    entry["tenant"] = tenant
    entry["device"] = device
    entry["run_id"] = last["id"]
    entry["started_at"] = last["started_at"]
    entry["baseline"] = _baseline_entry(store, tenant, device, fingerprint)
    entry["suppression"] = _suppression_entry(_for_device(suppressions, device), fingerprint, moment)
    return entry


def _checked_run(runs, tenant, device, run_id) -> dict:
    run = runs.get(run_id)
    if run is None:
        raise QueryError(
            "run %r does not belong to tenant %r and device %r" % (run_id, tenant, device)
        )
    return run


def _run_envelope(run, findings) -> dict:
    return {
        "run_id": run["id"],
        "started_at": run["started_at"],
        "rules_version": run["rules_version"],
        "snapshot_sha256": run["snapshot_sha256"],
        "findings_total": len(findings),
    }


def _by_fingerprint(findings) -> dict:
    items = {}
    for item in findings:
        items.setdefault(item["fingerprint"], item)
    return items


def _compare_items(items, fingerprints) -> tuple:
    entries = [_compare_entry(items[fingerprint]) for fingerprint in fingerprints]
    return tuple(
        sorted(entries, key=lambda item: (item["rule_id"], item["object_key"], item["fingerprint"]))
    )


def compare(store, tenant, device, first_run_id, second_run_id) -> dict:
    _checked_text("tenant", tenant)
    _checked_text("device", device)
    runs = {run["id"]: run for run in _runs(store, tenant, device)}
    first = _checked_run(runs, tenant, device, first_run_id)
    second = _checked_run(runs, tenant, device, second_run_id)
    first_findings = store.findings_for_run(tenant, first["id"])
    second_findings = store.findings_for_run(tenant, second["id"])
    if not evaluation_complete(first_findings) or not evaluation_complete(second_findings):
        raise QueryError("cannot compare an unevaluated audit; select two evaluated runs")
    before = _by_fingerprint(first_findings)
    after = _by_fingerprint(second_findings)
    added = _compare_items(after, frozenset(after) - frozenset(before))
    removed = _compare_items(before, frozenset(before) - frozenset(after))
    kept = _compare_items(after, frozenset(after) & frozenset(before))
    return {
        "tenant": tenant,
        "device": device,
        "first": _run_envelope(first, first_findings),
        "second": _run_envelope(second, second_findings),
        "added": added,
        "removed": removed,
        "kept": kept,
        "counts": {"added": len(added), "removed": len(removed), "kept": len(kept)},
    }
