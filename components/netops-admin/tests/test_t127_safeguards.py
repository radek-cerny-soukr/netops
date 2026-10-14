from types import SimpleNamespace
import pytest
from netops_admin import fortios, exec_exos, exec_fortios, exos, execute
from netops_core.fortios import parse
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request, audit_lines

CHANGE = "ab12cd" + "0" * 26
FIRE = "2026-10-13 12:00:00"
INVERSE = ["config firewall address", 'edit "fixture"', 'set comment "previous"', "next", "end"]


def answers():
    text = "\n".join(fortios.render_safeguard(CHANGE, INVERSE, FIRE)) + "\n"
    return {kind: text for kind in ("action", "trigger", "stitch")}


def test_rendered_safeguard_has_effective_single_shot_enabled_configuration():
    text = answers()["action"]
    tree = parse(text)
    names = fortios.safeguard_names(CHANGE)
    assert tree.section("system automation-action").entries[names["action"]].value("action-type") == "cli-script"
    trigger = tree.section("system automation-trigger").entries[names["trigger"]]
    assert trigger.value("trigger-type") == "scheduled" and trigger.value("trigger-frequency") == "once"
    assert tree.section("system automation-stitch").entries[names["stitch"]].value("status") == "enable"
    assert fortios.safeguard_state(CHANGE, answers(), INVERSE, FIRE) == []


@pytest.mark.parametrize("kind,original,replacement", [("action", "set action-type cli-script", "set action-type email"), ("trigger", "set trigger-frequency once", "set trigger-frequency hourly"), ("trigger", FIRE, "2026-10-14 12:00:00"), ("stitch", "set status enable", "set status disable"), ("stitch", "set trigger", "set unrelated-trigger"), ("stitch", "set action", "set unrelated-action")])
def test_invalid_safeguard_readback_is_refused(kind, original, replacement):
    texts = answers()
    texts[kind] = texts[kind].replace(original, replacement)
    assert fortios.safeguard_state(CHANGE, texts, INVERSE, FIRE)


@pytest.mark.parametrize("flags,profile", [("ep", None), ("eo", "foreign-profile"), ("ep", "foreign-profile")])
def test_exos_rejects_a_periodic_or_foreign_timer(flags, profile):
    names = exos.safeguard_names(CHANGE)
    class Access:
        def apply(self, *args):
            pass
        def query(self, command):
            if command == exos.QUERY_TIMERS:
                return "%s %s %s %s\n" % (names["timer"], profile or names["profile"], flags, FIRE)
            return "Profile Contents Begin\n" + "\n".join(exos.safeguard_script(INVERSE)) + "\nProfile Contents Ends"
    record = {"change_id": CHANGE, "safeguard": {"fire_at": FIRE}}
    assert exec_exos.install_safeguard(Access(), record, {"inverse": INVERSE}, SimpleNamespace(safeguard_seconds=180), None)


@pytest.mark.parametrize("adapter", [exec_exos, exec_fortios])
def test_safeguard_query_failure_never_means_cleaned(adapter):
    class Access:
        def query(self, command):
            raise OSError("fixture query failed")
    assert adapter.safeguard_absent(Access(), {"change_id": CHANGE}) is False


def test_installation_exception_never_applies_the_requested_change(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    def failed(*args):
        raise OSError("fixture install failed")
    monkeypatch.setattr(exec_fortios, "install_safeguard", failed)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] != "confirmed"
    assert "new-host" not in device.addresses


def test_start_audit_identifies_the_exact_change_device_and_plan(tmp_path):
    device = FakeFortiOS()
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    start = next(event for event in audit_lines(tmp_path) if event["event"] == "start")
    assert start["change_id"] == record["change_id"]
    assert start["device"] == "lab"
    assert start["request_sha256"] == record["request_sha256"]
    assert len(start["plan_sha256"]) == 64
    assert start["plan_sha256"] == record["plan"]["plan_sha256"]
    assert isinstance(start["commands"], int) and start["commands"] > 0
    plan = record["plan"]
    for field in ("platform", "firmware", "table", "op", "key", "snapshot_sha256", "reason_characters", "user_request_characters"):
        assert start[field] == plan[field]
    assert start["request_id"] == request().request_id
    assert start["request_sha256"] == request().fingerprint()
    assert start["commands"] == len(plan["commands"])
    assert start["inverse_commands"] == len(plan["inverse"])
    assert start["safeguard"] == exec_fortios.safeguard_label(record["change_id"])
    assert start["changes"] == {"comment": "text of 8 characters", "subnet": "ipv4-network changed"}


@pytest.mark.parametrize("cleaned,persisted,result", [(False, True, "unknown"), (True, False, "reverted")])
def test_unverified_installation_blocks_if_cleanup_or_persistence_is_uncertain(tmp_path, monkeypatch, cleaned, persisted, result):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(exec_fortios, "install_safeguard", lambda *a: ["fixture mismatch"])
    monkeypatch.setattr(exec_fortios, "remove_safeguard", lambda *a: cleaned)
    monkeypatch.setattr(execute, "_persist", lambda *a: persisted)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == result
    assert runtime.store.blocked("lab") is not None
    assert "new-host" not in device.addresses


def test_expiry_with_an_unpersisted_return_blocks_the_device(tmp_path, monkeypatch):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(execute, "_persist", lambda *a: False)
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"}))
    assert record["result"] == "reverted" and record["reason"] == "not persisted"
    assert runtime.store.blocked("lab") is not None


def test_expiry_with_an_unverified_cleanup_blocks_the_device(tmp_path, monkeypatch):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(exec_fortios, "remove_safeguard", lambda *a: False)
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"}))
    assert record["result"] == "unknown"
    assert runtime.store.blocked("lab") is not None


def test_clock_forward_does_not_reset_budget_even_across_runtime_restart(tmp_path, monkeypatch):
    import time
    from test_limits_and_undo import limited
    from netops_admin.errors import BudgetExhausted
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(changes_per_device_per_hour=1))
    execute.apply(runtime, "lab", request())
    future = time.time() + 3700
    monkeypatch.setattr(execute.time, "time", lambda: future)
    restarted = make_runtime(tmp_path, device, limits=limited(changes_per_device_per_hour=1))
    with pytest.raises(BudgetExhausted):
        execute.apply(restarted, "lab", request(key="second-host", request_id="req-second-clock"))


def test_transient_foreign_change_still_blocks_after_a_clean_return(tmp_path):
    from test_execute import foreign_comment
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    previous = device.addresses["srv-web"]["comment"]
    queries, query = [], device.check_query
    def checking(command):
        answer = query(command)
        queries.append(command)
        if len(queries) == 2:
            foreign_comment(device)
        return answer
    advance = device.advance
    def returning(seconds):
        advance(seconds)
        device.addresses["srv-web"]["comment"] = previous
    device.check_query = checking
    runtime.sleep = returning
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "foreign change"
    assert runtime.store.blocked("lab") is not None
    assert "new-host" not in device.addresses
    assert device.addresses["srv-web"]["comment"] == previous


def test_unreadable_final_snapshot_after_removal_finishes_unknown_and_blocks(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    apply = device.apply
    def removing(lines, spec):
        answer = apply(lines, spec)
        if lines[:1] == ["config system automation-stitch"] and lines[1].startswith("delete"):
            device.unreadable = True
        return answer
    device.apply = removing
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "unknown" and record["status"] == "finished"
    assert runtime.store.blocked("lab") is not None


def test_batch_start_audit_counts_operations_and_changed_attributes(tmp_path, monkeypatch):
    import json
    from test_schema_execute import runtime
    from test_schema_runtime import request as batch_request
    from test_schema_plan import op
    value, device = runtime(tmp_path, monkeypatch)
    req = batch_request([op(changes={"comment": "intermediate"}),
                         op(changes={"comment": "final", "subnet": "192.0.2.32/27"})])
    record = execute.apply(value, "lab", req)
    assert record["result"] == "confirmed"
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    start = next(event for event in events if event["event"] == "start")
    assert start["changes"] == {"operation_count": 2, "attribute_count": 3}
