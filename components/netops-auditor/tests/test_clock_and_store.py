import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from netops_auditor import cli, query, state
from netops_auditor.store import Store


def record(store, moment, version="v1", statuses=None, admit=None):
    return store.record_run("tenant", "device", "a" * 64, "fixture", version, (),
                            started_at=moment, rule_status=statuses, admit=admit)


def test_latest_committed_audit_survives_a_backward_clock_step(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        first = record(store, "2026-10-13T12:00:00Z", "older")
        latest = record(store, "2026-10-13T11:00:00Z", "newer")
        assert store.last_run("tenant", "device")["id"] == latest
        observed = []
        record(store, "2026-10-13T11:01:00Z", admit=observed.append)
        assert observed == ["newer"]


def test_future_timestamp_is_never_fresh():
    args = SimpleNamespace(tenant="tenant", device="device", stale_after_hours=24)
    now = datetime(2026, 10, 13, 11, tzinfo=timezone.utc)
    answer = cli._status_report(args, {"started_at": "2026-10-13T12:00:00Z"}, now)
    assert answer["state"] != cli.STATUS_FRESH
    assert answer["age_hours"] == -1


def test_new_database_is_private_even_under_public_umask(tmp_path):
    old = os.umask(0o022)
    try:
        path = tmp_path / "audit.db"
        with Store(path):
            assert path.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(old)


def test_status_uses_the_later_incomplete_audit_after_clock_rollback(tmp_path, capsys):
    import json
    path = tmp_path / "audit.db"
    with Store(path) as store:
        record(store, "2026-10-13T12:00:00Z", statuses={"R": {"status": "evaluated", "reason": "", "required": True}})
        record(store, "2026-10-13T11:00:00Z", statuses={"R": {"status": "not-evaluated", "reason": "fixture incomplete", "required": True}})
    args = SimpleNamespace(store=str(path), tenant="tenant", device="device", stale_after_hours=24, as_json=True)
    assert cli._command_status(args) == cli.EXIT_STALE
    assert json.loads(capsys.readouterr().out)["state"] == "incomplete"


EVALUATED = {"R": {"status": "evaluated", "reason": "", "required": True}}
NOW = datetime(2026, 10, 13, 11, tzinfo=timezone.utc)


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def mcp_status(store, now):
    return query.audit_status(store, "tenant", device="device", now=now, stale_after_hours=24)["devices"][0]


@pytest.mark.parametrize("hours_ago, expected", ((-0.5, "stale"), (0, "fresh"), (24, "fresh"), (24.5, "stale")))
def test_cli_and_mcp_judge_the_age_of_one_audit_alike(tmp_path, hours_ago, expected):
    started = stamp(NOW - timedelta(hours=hours_ago))
    with Store(tmp_path / "audit.db") as store:
        record(store, started, statuses=EVALUATED)
        mcp = mcp_status(store, NOW)
    args = SimpleNamespace(tenant="tenant", device="device", stale_after_hours=24)
    answer = cli._status_report(args, {"started_at": started}, NOW)
    assert (answer["state"], mcp["state"]) == (expected, expected)
    assert answer["age_hours"] == mcp["age_hours"] == hours_ago


def test_mcp_never_calls_a_future_timestamp_fresh_and_the_next_audit_takes_over(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        record(store, stamp(NOW - timedelta(hours=1)), statuses=EVALUATED)
        assert mcp_status(store, NOW)["state"] == query.STATUS_FRESH
        future = record(store, stamp(NOW + timedelta(days=365)), statuses=EVALUATED)
        for later in (NOW, NOW + timedelta(days=30)):
            entry = mcp_status(store, later)
            assert entry["run_id"] == future
            assert entry["age_hours"] < 0
            assert entry["state"] == query.STATUS_STALE
        totals = query.audit_status(store, "tenant", now=NOW, stale_after_hours=24)["totals"]
        assert (totals[query.STATUS_FRESH], totals[query.STATUS_STALE]) == (0, 1)
        latest = record(store, stamp(NOW), statuses=EVALUATED)
        entry = mcp_status(store, NOW)
        assert (entry["run_id"], entry["state"]) == (latest, query.STATUS_FRESH)
        assert query.list_findings(store, "tenant", "device", now=NOW)["run_id"] == latest


def test_cli_status_of_a_future_timestamp_exits_stale(tmp_path, capsys):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        record(store, stamp(datetime.now(timezone.utc) + timedelta(days=365)), statuses=EVALUATED)
    args = SimpleNamespace(store=str(path), tenant="tenant", device="device", stale_after_hours=24, as_json=True)
    assert cli._command_status(args) == cli.EXIT_STALE
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == cli.STATUS_STALE and report["age_hours"] < 0
    with Store(path) as store:
        assert mcp_status(store, datetime.now(timezone.utc))["state"] == report["state"]


FACTORY = "fortiadc.tls.factory-certificate"
PLAIN = "fortiadc.mgmt.plaintext-admin-access"


def gap(rule, status="not-evaluated", reason=""):
    return {rule: {"status": status, "reason": reason, "required": True}}


@pytest.mark.parametrize("statuses, inherent, actionable", (
    (gap(FACTORY, reason="factory-provenance-unproven"), [FACTORY], []),
    (gap(PLAIN, reason="visibility:networking"), [], [PLAIN]),
    ({**gap(FACTORY, reason="factory-provenance-unproven"), **gap(PLAIN, reason="visibility:networking")}, [FACTORY], [PLAIN]),
    (gap(FACTORY, status="unsupported", reason="unsupported-version"), [], [FACTORY]),
))
def test_mcp_status_carries_the_coverage_of_the_last_run(tmp_path, statuses, inherent, actionable):
    with Store(tmp_path / "audit.db") as store:
        record(store, stamp(NOW - timedelta(hours=1)), statuses=statuses)
        device = mcp_status(store, NOW)
    assert device["state"] == query.STATUS_INCOMPLETE
    assert device["coverage"]["complete"] is False
    assert [item["rule_id"] for item in device["coverage"]["inherent_gaps"]] == inherent
    assert [item["rule_id"] for item in device["coverage"]["actionable_gaps"]] == actionable


def test_mcp_status_of_a_device_without_a_run_has_no_coverage(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        answer = query.audit_status(store, "tenant", device="device", now=NOW, stale_after_hours=24)
    assert answer["devices"][0]["coverage"] is None


def test_state_coverage_classifies_a_run_stored_before_the_classification_existed(tmp_path):
    statuses = {**gap(FACTORY, reason="factory-provenance-unproven: ssl-profile=csp1"), **gap(PLAIN, reason="visibility:networking"), **EVALUATED}
    with Store(tmp_path / "audit.db") as store:
        run = record(store, stamp(NOW - timedelta(hours=1)), statuses=statuses)
        found = state.coverage(store.findings_for_run("tenant", run), state.stored_statuses(store, "tenant", run))
    assert found["complete"] is False
    assert [item["rule_id"] for item in found["inherent_gaps"]] == [FACTORY]
    assert [item["rule_id"] for item in found["actionable_gaps"]] == [PLAIN]


def test_state_coverage_of_a_run_stored_without_rule_status_has_no_gaps(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run = record(store, stamp(NOW - timedelta(hours=1)))
        found = state.coverage(store.findings_for_run("tenant", run), state.stored_statuses(store, "tenant", run))
    assert found == {"complete": True, "inherent_gaps": [], "actionable_gaps": []}
