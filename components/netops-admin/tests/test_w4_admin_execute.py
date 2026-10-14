from __future__ import annotations

import contextlib
import datetime
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fake_020 import ExosMembership
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_enrollment import ready
from test_execute import audit_lines, make_runtime, request, steps
from test_execute_exos import make_runtime as make_exos_runtime, request as exos_request
from test_schema_execute import Lab as SchemaLab
from test_schema_plan import op as schema_op
from test_schema_runtime import request as schema_request, setup as schema_setup
from test_t127_admin_regressions import (DeviceTime, changed_back_by_hand, changed_elsewhere_by_hand, killed_after_the_change,
                                         killed_in_the_removal, safeguard_deleted_by_hand, wait_for_expiry)

from netops_admin import enrollment, exec_schema_fortios, execute, schema_runtime
from netops_admin.config import DEFAULT_LIMITS, Config
from netops_admin.errors import BudgetExhausted, Rejected

UNDELIVERED = ("the notification of operation %s was not delivered; run notify-retry, or a person"
               " unblocks the device after checking the notification channel")


class Crash(BaseException):
    pass


def notified_runtime(tmp_path, device, notifier, export_status=None):
    plain = make_runtime(tmp_path, device, export_status=export_status)
    return execute.Runtime(plain.config, plain.access_factory, notifier=notifier, sleep=device.advance)


def result_events(tmp_path):
    return [event for event in audit_lines(tmp_path) if event["event"] == "result"]


def test_the_notifier_given_to_the_runtime_runs_once_the_stored_operation_says_sending(tmp_path):
    device = FakeFortiOS()
    seen = []

    def notifier(record):
        seen.append((record["result"], runtime.store.operation(record["change_id"])["notification"]))
        return "sent"

    runtime = notified_runtime(tmp_path, device, notifier)
    record = execute.apply(runtime, "lab", request())
    assert seen == [("confirmed", "sending")]
    assert record["notification"] == "sent"
    assert runtime.store.operation(record["change_id"])["notification"] == "sent"
    assert [event["notification"] for event in result_events(tmp_path)] == ["pending"]


def test_a_crash_inside_the_notifier_keeps_the_device_refusing_changes_until_the_retry(tmp_path):
    device = FakeFortiOS()

    def crash(_record):
        raise Crash()

    runtime = notified_runtime(tmp_path, device, crash)
    with pytest.raises(Crash):
        execute.apply(runtime, "lab", request())
    (change,) = [record["change_id"] for record in runtime.store.records()]
    assert runtime.store.operation(change)["notification"] == "sending"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="other-host", request_id="req-0002-example"))
    assert caught.value.reasons == [UNDELIVERED % change]
    assert len(device.applied_blocks) == blocks
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    again = execute.apply(runtime, "lab", request(key="other-host", request_id="req-0002-example"))
    assert again["result"] == "confirmed"


@pytest.mark.parametrize("pending,expected", [(0, "pending"), (1, "pending"), (None, "not-configured")])
def test_the_audit_delivery_of_a_result_waits_for_an_export_after_the_result(tmp_path, pending, expected):
    device = FakeFortiOS()
    status = None
    if pending is not None:
        status = tmp_path / "export-status.json"
        status.write_text(json.dumps({"updated_at": time.time(), "pending": pending}))
    runtime = make_runtime(tmp_path, device, export_status=None if status is None else str(status))
    record = execute.apply(runtime, "lab", request())
    assert record["audit_delivery"] == expected
    assert runtime.store.operation(record["change_id"])["audit_delivery"] == expected
    assert [event["audit_delivery"] for event in result_events(tmp_path)] == [expected]


def budget_runtime(records, now, hour, day):
    store = SimpleNamespace(rejections_since=lambda _moment: 0, records=lambda: records, budget_now=lambda: now)
    limits = {"rejections_per_hour": 30, "journal_records": 20000,
              "changes_per_device_per_hour": hour, "changes_per_day": day}
    return SimpleNamespace(store=store, config=SimpleNamespace(limits=limits))


HOUR_EXHAUSTED = "the budget of changes on this device for this hour is exhausted"
DAY_EXHAUSTED = "the budget of changes for this day is exhausted"


@pytest.mark.parametrize("device,hour,day,exhausted,window", [
    ("lab", 1, 100, HOUR_EXHAUSTED, execute.HOUR),
    ("other", 100, 1, DAY_EXHAUSTED, execute.DAY),
])
def test_the_budget_windows_follow_the_budget_clock_and_not_the_wall_clock(device, hour, day, exhausted, window):
    now = 500000.0
    lab = SimpleNamespace(name="lab")
    fresh = {"device": device, "status": "running", "budget_at_epoch": now - window, "created_at_epoch": now - 9 * execute.DAY}
    with pytest.raises(BudgetExhausted) as caught:
        execute._budgets(budget_runtime([fresh], now, hour, day), lab)
    assert caught.value.reasons == [exhausted]
    stale = dict(fresh, budget_at_epoch=now - window - 1, created_at_epoch=now)
    execute._budgets(budget_runtime([stale], now, hour, day), lab)
    legacy = {"device": device, "status": "running", "created_at_epoch": now - window}
    with pytest.raises(BudgetExhausted):
        execute._budgets(budget_runtime([legacy], now, hour, day), lab)
    execute._budgets(budget_runtime([dict(legacy, created_at_epoch=now - window - 1)], now, hour, day), lab)


def test_a_new_operation_takes_its_budget_moment_from_the_budget_clock(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(runtime.store, "budget_now", lambda: 4242.5)
    running = []
    device.on_apply = lambda fake, lines: running.extend(runtime.store.running("lab"))
    started = time.time()
    record = execute.apply(runtime, "lab", request())
    assert record["budget_at_epoch"] == 4242.5
    assert runtime.store.operation(record["change_id"])["budget_at_epoch"] == 4242.5
    assert started <= record["created_at_epoch"] <= time.time()
    assert time.strftime("%Y-%m-%dT", time.gmtime(started)) in record["created_at"]
    first = running[0]
    assert (first["status"], first["result"], first["change_id"]) == ("running", None, record["change_id"])
    assert first["audit_coverage"] == record["audit_coverage"] and "address-policy" in first["audit_coverage"]
    assert first["foreign_sessions"] == 0


@pytest.mark.parametrize("fields", [{}, {"op": "delete", "key": "spare-host", "changes": {}}])
def test_a_plan_is_refused_when_either_side_holds_more_commands_than_the_limit(tmp_path, fields):
    shown = execute.preview(make_runtime(tmp_path / "wide", FakeFortiOS()), "lab", request(**fields))
    sizes = (len(shown["commands"]), shown["inverse_commands"])
    assert sizes[0] != sizes[1]
    narrow = make_runtime(tmp_path / "narrow", FakeFortiOS(), limits=dict(DEFAULT_LIMITS, plan_commands=min(sizes)))
    with pytest.raises(Rejected) as caught:
        execute.apply(narrow, "lab", request(**fields))
    assert caught.value.reasons == ["the plan holds more than %d commands" % min(sizes)]
    exact = make_runtime(tmp_path / "exact", FakeFortiOS(), limits=dict(DEFAULT_LIMITS, plan_commands=max(sizes)))
    assert execute.apply(exact, "lab", request(**fields))["result"] == "confirmed"


@pytest.mark.parametrize("notifier,pending,refused", [
    (lambda record: "sent", None, True),
    (None, 0, True),
    (lambda record: "sent", 1, False),
])
def test_enrollment_needs_both_a_notifier_and_a_healthy_configured_export(tmp_path, notifier, pending, refused):
    runtime, target, name = ready(tmp_path)
    runtime.notifier = notifier
    if pending is None:
        runtime.config = replace(runtime.config, export_status_file=None)
    else:
        with open(runtime.config.export_status_file, "w") as handle:
            json.dump({"updated_at": time.time(), "pending": pending}, handle)
    if refused:
        with pytest.raises(Rejected) as caught:
            enrollment.run(runtime, name, "192.0.2.254/32")
        assert caught.value.reasons == ["enrollment requires notification and a healthy configured audit export"]
        assert target.applied_blocks == []
    else:
        assert enrollment.run(runtime, name, "192.0.2.254/32")["enrollment"] == "valid"


def test_a_mandatory_rule_of_the_planned_table_is_required_before_the_change_without_a_policy(tmp_path):
    device = ExosMembership()
    runtime = make_exos_runtime(tmp_path, device)
    fields = {"table": "vlan-membership", "op": "update", "key": "10", "changes": {"tagged": ["guest", "staging"]}}
    shown = execute.preview(runtime, "sw", exos_request(**fields))
    assert (shown["result"], shown["reasons"]) == ("rejected", ["mandatory audit rules were not evaluated: port-policy"])
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", exos_request(**fields))
    assert caught.value.reasons == ["mandatory audit rules were not evaluated: port-policy"]
    assert device.applied_blocks == []


START = [("foreign_sessions", "0 other sessions"), ("safeguard_install", None), ("safeguard_verified", None),
         ("change_start", None)]
CHECKED = START + [("change_applied", None), ("postcheck_passed", None)]


def trail(record):
    return [(step["step"], step["detail"]) for step in record["steps"]]


def nth_call(monkeypatch, name, call, outcome):
    original, calls = getattr(execute.exec_fortios, name), []

    def scripted(*arguments):
        calls.append(arguments)
        if len(calls) == call:
            if isinstance(outcome, type):
                raise outcome("scripted")
            return outcome(*arguments) if callable(outcome) else outcome
        return original(*arguments)

    monkeypatch.setattr(execute.exec_fortios, name, scripted)


def after_check(monkeypatch, call, outcome):
    verify, calls = execute.engine.verify, []

    def scripted(plan, text, expect="after"):
        answer = verify(plan, text, expect=expect)
        if expect == "after":
            calls.append(text)
            if len(calls) == call:
                if isinstance(outcome, type):
                    raise outcome("scripted")
                return dict(answer, result="mismatch", object_matches=False, differences=list(outcome))
        return answer

    monkeypatch.setattr(execute.engine, "verify", scripted)


def gate_call(monkeypatch, name, call, outcome):
    original, calls = getattr(execute.audit_gate, name), []

    def scripted(*arguments):
        calls.append(arguments)
        if len(calls) == call:
            if isinstance(outcome, type):
                raise outcome("scripted")
            return outcome
        return original(*arguments)

    monkeypatch.setattr(execute.audit_gate, name, scripted)


def at_change(device, action):
    def hook(fake, lines):
        if len(fake.applied_blocks) == 2:
            action(fake)
    device.on_apply = hook


def refuse_line(fake, lines):
    fake.fail_at_line = 3 if len(fake.applied_blocks) == 2 else None


def refuse_block(fake):
    raise RuntimeError("refused")


def unreadable_check(fake):
    fake.check_unreadable = True


def other_check_answer(fake):
    fake.check_override = {"new-host": {"uuid": "00000000-0000-4000-8000-000000000099", "comment": "other",
                                        "subnet": "192.0.2.30 255.255.255.255"}}


def audit_passed():
    return ("audit_passed", "%d rules, 4 findings before, none new" % execute.audit_gate.rule_count("fortios"))


EXECUTE_CASES = {
    "clock": (lambda mp, device: nth_call(mp, "clock", 1, RuntimeError),
              [("foreign_sessions", "0 other sessions"), ("clock_unreadable", "RuntimeError")], "rejected", "device clock"),
    "install raises": (lambda mp, device: nth_call(mp, "install_safeguard", 1, RuntimeError),
                       [("foreign_sessions", "0 other sessions"), ("safeguard_install", None),
                        ("safeguard_not_verified", "safeguard installation failed (RuntimeError)")],
                       "reverted", "safeguard not verified"),
    "install unverified and kept": (lambda mp, device: (nth_call(mp, "install_safeguard", 1, ["not read back"]),
                                                        nth_call(mp, "remove_safeguard", 1, False)),
                                    [("foreign_sessions", "0 other sessions"), ("safeguard_install", None),
                                     ("safeguard_not_verified", "not read back")], "unknown", "safeguard not verified"),
    "install unverified and not persisted": (lambda mp, device: (nth_call(mp, "install_safeguard", 1, ["not read back"]),
                                                                 nth_call(mp, "persist", 1, RuntimeError)),
                                             [("foreign_sessions", "0 other sessions"), ("safeguard_install", None),
                                              ("safeguard_not_verified", "not read back"), ("persist_failed", "RuntimeError")],
                                             "reverted", "not persisted"),
    "refused line": (lambda mp, device: setattr(device, "on_apply", refuse_line),
                     START + [("change_failed", "DeviceRefused after 2 lines"), ("safeguard_removed", None)],
                     "reverted", "change failed"),
    "refused block": (lambda mp, device: at_change(device, refuse_block),
                      START + [("change_failed", "RuntimeError after 0 lines"), ("safeguard_removed", None)],
                      "reverted", "change failed"),
    "postcheck unavailable": (lambda mp, device: after_check(mp, 1, RuntimeError),
                              START + [("change_applied", None), ("postcheck_failed", "RuntimeError"),
                                       ("safeguard_removed", None)], "reverted", "postcheck unavailable"),
    "prediction mismatch": (lambda mp, device: after_check(mp, 1, ["first", "second"]),
                            START + [("change_applied", None), ("postcheck_failed", "2 differences"),
                                     ("safeguard_removed", None)], "reverted", "prediction mismatch"),
    "audit unavailable": (lambda mp, device: gate_call(mp, "evaluate", 2, RuntimeError),
                          CHECKED + [("audit_failed", "RuntimeError"), ("safeguard_removed", None)],
                          "reverted", "audit unavailable"),
    "audit finding": (lambda mp, device: gate_call(mp, "new_blocking", 2, ["fortios.example"]),
                      CHECKED + [("audit_failed", "1 new findings"), ("safeguard_removed", None)],
                      "reverted", "audit finding"),
    "check unavailable": (lambda mp, device: at_change(device, unreadable_check),
                          CHECKED + [audit_passed(), ("check_identity_failed", "RuntimeError"), ("safeguard_removed", None)],
                          "reverted", "check identity unavailable"),
    "check mismatch": (lambda mp, device: at_change(device, other_check_answer),
                       CHECKED + [audit_passed(), ("check_identity_failed", "state differs"), ("safeguard_removed", None)],
                       "reverted", "check identity mismatch"),
    "final unavailable": (lambda mp, device: after_check(mp, 2, RuntimeError),
                          CHECKED + [audit_passed(), ("check_identity_passed", None), ("final_check_failed", "RuntimeError"),
                                     ("safeguard_removed", None)], "reverted", "final check unavailable"),
    "final mismatch": (lambda mp, device: after_check(mp, 2, ["first"]),
                       CHECKED + [audit_passed(), ("check_identity_passed", None), ("final_check_failed", "1 differences"),
                                  ("safeguard_removed", None)], "reverted", "foreign change"),
    "confirmation unverified": (lambda mp, device: nth_call(mp, "remove_safeguard", 1, False),
                                CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None),
                                           ("confirm_unverified", None), ("safeguard_removed", None)],
                                "reverted", "confirmation unverified"),
    "removal unavailable": (lambda mp, device: after_check(mp, 3, RuntimeError),
                            CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None),
                                       ("removal_check_failed", "RuntimeError")], "unknown", "final check unavailable"),
    "removal mismatch": (lambda mp, device: after_check(mp, 3, ["first"]),
                         CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None),
                                    ("removal_check_failed", "1 differences")],
                         "unknown", "foreign change after the safeguard was removed"),
    "saved unverified": (lambda mp, device: (nth_call(mp, "persist", 1, True), after_check(mp, 4, RuntimeError)),
                         CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None),
                                    ("configuration_saved", None), ("saved_check_failed", "RuntimeError")],
                         "confirmed", "saved configuration unverified"),
    "saved mismatch": (lambda mp, device: (nth_call(mp, "persist", 1, True), after_check(mp, 4, ["first", "second"])),
                       CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None),
                                  ("configuration_saved", None), ("saved_check_failed", "2 differences")],
                       "confirmed", "foreign change during save"),
    "confirmed": (lambda mp, device: None,
                  CHECKED + [audit_passed(), ("check_identity_passed", None), ("confirm_start", None)], "confirmed", None),
}


@pytest.mark.parametrize("case", list(EXECUTE_CASES))
def test_each_way_out_of_a_change_records_its_steps_and_its_reason(tmp_path, monkeypatch, case):
    arrange, expected, result, reason = EXECUTE_CASES[case]
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    arrange(monkeypatch, device)
    record = execute.apply(runtime, "lab", request())
    assert trail(record) == expected
    assert (record["result"], record["reason"]) == (result, reason)
    assert runtime.store.operation(record["change_id"])["steps"] == record["steps"]
    assert [(event["step"], event["detail"]) for event in audit_lines(tmp_path) if event["event"] == "step"] == expected


@pytest.mark.parametrize("left,result,tail", [
    (45, ("confirmed", None), [("confirm_start", None)]),
    (44, ("reverted", "no time left to confirm"), [("confirm_skipped", "too close to the safeguard"), ("safeguard_removed", None)]),
    (None, ("reverted", "no time left to confirm"), [("confirm_skipped", "too close to the safeguard"), ("safeguard_removed", None)]),
])
def test_the_confirmation_needs_the_margin_left_on_the_device_clock(tmp_path, monkeypatch, left, result, tail):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    clock, seen = execute.exec_fortios.clock, []

    def scripted(access):
        seen.append(clock(access))
        if len(seen) == 2:
            if left is None:
                raise RuntimeError("clock")
            return seen[0] + datetime.timedelta(seconds=device.safeguard_seconds - left)
        return seen[-1]

    device.safeguard_seconds = runtime.config.devices["lab"].safeguard_seconds
    monkeypatch.setattr(execute.exec_fortios, "clock", scripted)
    record = execute.apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == result
    assert trail(record) == CHECKED + [audit_passed(), ("check_identity_passed", None)] + tail


def test_the_result_event_carries_the_whole_outcome_of_the_operation(tmp_path, monkeypatch):
    after_check(monkeypatch, 3, ["first"])
    runtime = make_runtime(tmp_path, FakeFortiOS())
    record = execute.apply(runtime, "lab", request())
    [event] = result_events(tmp_path)
    assert event == {
        "event": "result", "at": event["at"], "change_id": record["change_id"], "request_id": "req-0001-example",
        "device": "lab", "status": "finished", "result": "unknown",
        "reason": "foreign change after the safeguard was removed", "differences": 1,
        "notification": "not-configured", "audit_delivery": "not-configured",
        "safeguard": record["safeguard"]["fire_at"],
    }
    assert record["notification"] == "not-configured" and record["differences"] == ["first"]


def test_each_step_is_stamped_with_its_time(tmp_path):
    record = execute.apply(make_runtime(tmp_path, FakeFortiOS()), "lab", request())
    assert all(sorted(step) == ["at", "detail", "step"] for step in record["steps"])
    assert all(step["at"].endswith("Z") and step["at"][4] == "-" and step["at"][10] == "T" for step in record["steps"])


def test_unreadable_foreign_sessions_do_not_stop_the_change(tmp_path, monkeypatch):
    nth_call(monkeypatch, "foreign_sessions", 1, RuntimeError)
    runtime = make_runtime(tmp_path, FakeFortiOS())
    record = execute.apply(runtime, "lab", request())
    assert record["foreign_sessions"] is None
    assert trail(record)[:2] == [("foreign_sessions_unreadable", "RuntimeError"), ("safeguard_install", None)]
    assert (record["result"], record["reason"]) == ("confirmed", None)


def test_a_rejected_enrollment_notification_names_its_reason_and_a_sent_one_is_a_step(tmp_path):
    runtime, target, name = ready(tmp_path / "failed")
    runtime.notifier = lambda record: "failed"
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert (record["result"], record["reason"]) == ("rejected", "enrollment notification unavailable")
    assert trail(record) == [("foreign_sessions", "0 other sessions")]
    runtime, target, name = ready(tmp_path / "sent")
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert trail(record)[:2] == [("foreign_sessions", "0 other sessions"), ("enrollment_notification_verified", None)]


def blind_safeguard(fake, lines):
    if len(fake.applied_blocks) == 2:
        fake.stitches.clear()


def unreadable_after_refusal(fake, lines):
    if len(fake.applied_blocks) == 2:
        fake.unreadable = True
        raise RuntimeError("refused")


SETTLED = {
    "revert unverified": (lambda mp, device: setattr(device, "on_apply", unreadable_after_refusal),
                          START + [("change_failed", "RuntimeError after 0 lines"), ("revert_unverified", "RuntimeError")],
                          ("unknown", "change failed")),
    "cleanup unverified": (lambda mp, device: (at_change(device, refuse_block), nth_call(mp, "remove_safeguard", 1, False)),
                           START + [("change_failed", "RuntimeError after 0 lines"), ("safeguard_removal_unverified", None)],
                           ("unknown", "safeguard cleanup unverified")),
    "revert failed": (lambda mp, device: (setattr(device, "on_apply", blind_safeguard), after_check(mp, 1, ["first"])),
                      START + [("change_applied", None), ("postcheck_failed", "1 differences"), ("safeguard_removed", None)],
                      ("revert-failed", "prediction mismatch")),
}


@pytest.mark.parametrize("case", list(SETTLED))
def test_settling_after_the_safeguard_expiry_records_how_it_ended(tmp_path, monkeypatch, case):
    arrange, expected, outcome = SETTLED[case]
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    arrange(monkeypatch, device)
    record = execute.apply(runtime, "lab", request())
    assert trail(record) == expected
    assert (record["result"], record["reason"]) == outcome
    assert (record["differences"] != []) == (outcome[0] == "revert-failed")
    assert runtime.store.blocked("lab")["reason"] == outcome[1]


def interrupted(tmp_path, device, crash, twice=True, safeguard=True):
    device.on_apply = crash
    with pytest.raises(KeyboardInterrupt):
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    device.on_apply = None
    runtime = make_runtime(tmp_path, device)
    [running] = runtime.store.running("lab")
    if not safeguard:
        running.pop("safeguard")
        runtime.store.save(running)
    if twice:
        runtime.store.save(dict(running, change_id="f" * 32, request_id="req-0009-example"))
    return runtime


def recovery_trail(record):
    steps = trail(record)
    return steps[max(index for index, step in enumerate(steps) if step[0] == "recovery_start"):]


def persisted(saved, outcome):
    def persist(access, spec):
        saved.append(access)
        if isinstance(outcome, type):
            raise outcome("scripted")
        return outcome
    return persist


def failing_factory(_device):
    raise RuntimeError("unreachable")


RECOVERY_CASES = {
    "before any mutation": (killed_after_the_change, False, lambda mp, runtime, device, saved: None,
                            [("recovery_start", None)], ("rejected", "interrupted before any mutation")),
    "device unreachable": (killed_after_the_change, True,
                           lambda mp, runtime, device, saved: setattr(runtime, "access_factory", failing_factory),
                           [("recovery_start", None), ("recovery_access_failed", "RuntimeError")],
                           ("unknown", "interrupted; device unreachable")),
    "safeguard unreadable": (killed_after_the_change, True,
                             lambda mp, runtime, device, saved: mp.setattr(execute.exec_fortios, "safeguard_absent",
                                                                           persisted([], RuntimeError)),
                             [("recovery_start", None)], ("unknown", "interrupted; safeguard state unreadable")),
    "state unreadable": (killed_after_the_change, True,
                         lambda mp, runtime, device, saved: (safeguard_deleted_by_hand(device),
                                                             setattr(device, "unreadable", True)),
                         [("recovery_start", None)], ("unknown", "interrupted; state unreadable")),
    "neither side": (killed_after_the_change, True, lambda mp, runtime, device, saved: changed_elsewhere_by_hand(device),
                     [("recovery_start", None)], ("unknown", "interrupted; state matches neither side")),
    "before, saved": (killed_after_the_change, True,
                      lambda mp, runtime, device, saved: (changed_back_by_hand(device),
                                                          mp.setattr(execute.exec_fortios, "persist", persisted(saved, True))),
                      [("recovery_start", None), ("configuration_saved", None)], ("reverted", "interrupted")),
    "before, not persisted": (killed_after_the_change, True,
                              lambda mp, runtime, device, saved: (changed_back_by_hand(device),
                                                                  mp.setattr(execute.exec_fortios, "persist",
                                                                             persisted(saved, RuntimeError))),
                              [("recovery_start", None), ("persist_failed", "RuntimeError")], ("reverted", "not persisted")),
    "confirmed, saved": (killed_in_the_removal(0), True,
                         lambda mp, runtime, device, saved: (safeguard_deleted_by_hand(device),
                                                             mp.setattr(execute.exec_fortios, "persist", persisted(saved, True))),
                         [("recovery_start", None), ("configuration_saved", None)],
                         ("confirmed", "confirmed before the interruption")),
    "confirmed, not persisted": (killed_in_the_removal(0), True,
                                 lambda mp, runtime, device, saved: (safeguard_deleted_by_hand(device),
                                                                     mp.setattr(execute.exec_fortios, "persist",
                                                                                persisted(saved, RuntimeError))),
                                 [("recovery_start", None), ("persist_failed", "RuntimeError")],
                                 ("confirmed", "not persisted")),
}


@pytest.mark.parametrize("case", list(RECOVERY_CASES))
def test_recover_settles_every_interrupted_operation_with_its_steps_and_reason(tmp_path, monkeypatch, case):
    crash, safeguard, arrange, expected, outcome = RECOVERY_CASES[case]
    device = FakeFortiOS()
    runtime = interrupted(tmp_path, device, crash() if crash is killed_after_the_change else crash, safeguard=safeguard)
    saved = []
    arrange(monkeypatch, runtime, device, saved)
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [outcome, outcome]
    assert [recovery_trail(record) for record in settled] == [expected, expected]
    assert sorted(record["change_id"] for record in settled) == sorted(
        record["change_id"] for record in runtime.store.records())
    assert runtime.store.running("lab") == []
    if saved:
        assert saved == [device, device]


def test_recover_names_a_device_that_is_not_configured(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    with pytest.raises(Rejected) as caught:
        execute.recover(runtime, "ghost")
    assert caught.value.reasons == ["device %s is not configured" % execute.shown("ghost")]


def confirmed_before(runtime, device):
    assert execute.apply(runtime, "lab", request(key="first-host", request_id="req-0003-example"))["result"] == "confirmed"


def stale_export(runtime):
    path = runtime.config.export_status_file
    with open(path, "w") as handle:
        json.dump({"updated_at": time.time() - 10 * execute.DAY, "pending": 0}, handle)


def comment_changed(device):
    device.admin_comments["netops-rw"] = "changed"


REFUSALS = {
    "blocked without operation": (lambda mp, runtime, device: runtime.store.block("lab", None, "administrator table"),
                                  ["the device is blocked (administrator table, operation none);"
                                   " a person must investigate and unblock it"]),
    "blocked by operation": (lambda mp, runtime, device: runtime.store.block("lab", "a" * 32, "foreign change"),
                             ["the device is blocked (foreign change, operation %s);"
                              " a person must investigate and unblock it" % ("a" * 32)]),
    "export stale": (lambda mp, runtime, device: stale_export(runtime), ["audit export is blocked: export status is stale"]),
    "accounts changed": (lambda mp, runtime, device: (confirmed_before(runtime, device), comment_changed(device)),
                         ["the administrator accounts changed since the last operation"]),
    "leftovers": (lambda mp, runtime, device: device.stitches.update({
        "netops-sg-deadbeef0000-s": {"trigger": None, "action": None},
        "netops-sg-deadbeef0001-s": {"trigger": None, "action": None}}),
        ["a safeguard of an earlier operation is still installed: netops-sg-deadbeef0000-s, netops-sg-deadbeef0001-s"]),
    "unreadable": (lambda mp, runtime, device: setattr(device, "unreadable", True),
                   ["the device could not be read before any change: snapshot unavailable"]),
    "predicted findings": (lambda mp, runtime, device: gate_call(mp, "new_blocking", 1, ["first-rule", "second-rule"]),
                           ["predicted audit findings: first-rule, second-rule"]),
    "auditor unavailable": (lambda mp, runtime, device: gate_call(mp, "findings", 1, RuntimeError),
                            ["the auditor could not evaluate the snapshot before the change (RuntimeError)"]),
    "check account unavailable": (lambda mp, runtime, device: setattr(device, "check_unreadable", True),
                                  ["the check account could not read the object before the change (RuntimeError)"]),
    "check account disagrees": (lambda mp, runtime, device: other_check_answer(device),
                                ["the check account sees the object in another state than the snapshot"]),
}


@pytest.mark.parametrize("case", list(REFUSALS))
def test_each_refusal_before_a_change_names_its_reason(tmp_path, monkeypatch, case):
    arrange, reasons = REFUSALS[case]
    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    arrange(monkeypatch, runtime, device)
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert caught.value.reasons == reasons
    assert len(device.applied_blocks) == blocks


def test_an_interrupted_operation_refuses_new_changes_until_recover(tmp_path):
    device = FakeFortiOS()
    runtime = interrupted(tmp_path, device, killed_after_the_change(), twice=False)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="other-host", request_id="req-0002-example"))
    assert caught.value.reasons == ["an unfinished operation exists on this device; run recover first"]


def test_an_undo_is_refused_when_the_object_moved_on_since_the_change(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    device.addresses["new-host"]["comment"] = "edited by hand"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record["change_id"], "restore")
    assert caught.value.reasons == ["the object differs from the state the undo was planned against"]
    assert len(device.applied_blocks) == blocks


def test_a_request_for_an_unknown_or_another_device_is_refused_by_name(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "ghost", request())
    assert caught.value.reasons == ["device %s is not configured" % execute.shown("ghost")]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(device="other"))
    assert caught.value.reasons == ["the request names device 'other', but it was sent to device 'lab'"]


def test_preview_shows_the_plan_the_apply_will_run(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    shown = execute.preview(runtime, "lab", request())
    record = execute.apply(runtime, "lab", request())
    plan = record["plan"]
    assert shown == {
        "result": "ready", "reasons": [], "device": "lab", "platform": "fortios", "firmware": plan["firmware"],
        "table": "firewall address", "op": "create", "key": "new-host", "predicted": plan["predicted"],
        "commands": plan["commands"], "inverse_commands": len(plan["inverse"]), "prechecks": plan["prechecks"],
        "rollback_evidence": plan["rollback_evidence"], "plan_sha256": plan["plan_sha256"],
        "audit_findings_before": len(record["audit_before"]), "audit_coverage": record["audit_coverage"],
        "safeguard_seconds": 180,
    }
    assert shown["firmware"] is not None and shown["audit_findings_before"] == 4
    again = execute.preview(runtime, "lab", request())
    assert again == {"result": "known-request", "device": "lab", "change_id": record["change_id"],
                     "reasons": ["request_id already started an operation; apply returns it without running again"]}


def test_unblock_and_notify_retry_name_what_they_refuse(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    with pytest.raises(Rejected) as caught:
        execute.unblock(runtime, "ghost", "checked")
    assert caught.value.reasons == ["device %s is not configured" % execute.shown("ghost")]
    with pytest.raises(Rejected) as caught:
        execute.notify_retry(runtime, "a" * 32)
    assert caught.value.reasons == ["no finished operation matches"]
    record = execute.apply(runtime, "lab", request())
    with pytest.raises(Rejected) as caught:
        execute.notify_retry(runtime, record["change_id"])
    assert caught.value.reasons == ["notification is not configured"]


def test_the_administrator_table_block_is_audited_with_its_action(tmp_path):
    device = FakeFortiOS()
    device.admins.append("persisted-account")
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab", request())
    [event] = [event for event in audit_lines(tmp_path) if event["event"] == "administrative"]
    assert event == {"event": "administrative", "at": event["at"], "device": "lab",
                     "action": "blocked: administrator table", "reason_characters": 0, "change_id": None}


def test_an_undo_of_an_operation_with_an_unreadable_plan_names_its_state_file(tmp_path):
    from netops_admin.errors import StateUnreadable

    runtime = make_runtime(tmp_path, FakeFortiOS())
    record = execute.apply(runtime, "lab", request())
    stored = runtime.store.operation(record["change_id"])
    stored["plan"]["commands"].append("set comment \"other\"")
    runtime.store.save(stored)
    with pytest.raises(StateUnreadable) as caught:
        execute.undo(runtime, record["change_id"], "restore")
    assert caught.value.reasons == ["the state file operations/%s.json cannot be read; a person must check it"
                                    % record["change_id"]]


def test_only_a_confirmed_operation_is_undone_and_the_undo_names_it(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, "a" * 32, "restore")
    assert caught.value.reasons == ["only a confirmed operation can be undone"]
    record = execute.apply(runtime, "lab", request())
    undone = execute.undo(runtime, record["change_id"], "restore")
    assert (undone["result"], undone["request_id"]) == ("confirmed", "undo-%s" % record["change_id"])
    assert undone["plan"]["user_request_characters"] == len("undo of operation %s" % record["change_id"])
    assert "new-host" not in device.addresses


@pytest.mark.parametrize("offset,waited", [(200, 0), (199, 1)])
def test_the_expiry_wait_starts_the_proof_once_nothing_is_left_of_the_grace(offset, waited):
    clock = DeviceTime(0, offset, True)
    wait_for_expiry(clock)
    assert clock.now == waited


def test_the_transaction_weight_may_reach_its_limit_and_a_full_journal_is_named():
    lab = SimpleNamespace(name="lab")
    execute._budgets(budget_runtime([], 1000.0, 32, 32), lab, changes=32)
    with pytest.raises(Rejected) as caught:
        execute._budgets(budget_runtime([], 1000.0, 64, 64), lab, changes=33)
    assert caught.value.reasons == ["the transaction change count must be in 1..32"]
    full = budget_runtime([{"device": "lab", "status": "finished"}], 1000.0, 32, 32)
    full.config.limits["journal_records"] = 1
    with pytest.raises(BudgetExhausted) as caught:
        execute._budgets(full, lab)
    assert caught.value.reasons == ["the journal holds its maximum number of operations; archive it before new changes"]


def schema_bench(tmp_path, monkeypatch):
    lib, device = schema_setup(tmp_path, True)
    device = replace(device, audit_policy={"version": 1, "platform": "fortios"})
    fake = SchemaLab(lib)
    config = Config(str(tmp_path / "state"), str(tmp_path / "audit.jsonl"), None, None, dict(DEFAULT_LIMITS), {"lab": device})
    runtime = execute.Runtime(config, lambda _device: fake, sleep=fake.advance)
    runtime.store.save_enrollment("lab", {"protocol": enrollment.PROTOCOL,
                                          "binding": enrollment.binding(device, "fp", device.firmware, config)})
    calls = {"access": [], "before": [], "after": [], "absent": [], "removed": [], "fortios": []}
    audit_before = {}

    def access(base, named):
        calls["access"].append(named)
        return base

    def before(*arguments):
        calls["before"].append(arguments)
        return audit_before, {"phase": "before"}

    def after(*arguments):
        calls["after"].append(arguments)
        return [], {"phase": "after %d" % len(calls["after"])}

    absent, removed = exec_schema_fortios.safeguard_absent, exec_schema_fortios.remove_safeguard
    monkeypatch.setattr(schema_runtime, "Access", access)
    monkeypatch.setattr(exec_schema_fortios, "accounts_check", lambda *_arguments: "fp")
    monkeypatch.setattr(schema_runtime, "audit_snapshot", before)
    monkeypatch.setattr(schema_runtime, "after_audit", after)
    monkeypatch.setattr(exec_schema_fortios, "safeguard_absent",
                        lambda *arguments: calls["absent"].append(arguments) or absent(*arguments))
    monkeypatch.setattr(exec_schema_fortios, "remove_safeguard",
                        lambda *arguments: calls["removed"].append(arguments) or removed(*arguments))
    for name in ("safeguard_absent", "safeguard_disarmed", "remove_safeguard", "remove_remaining"):
        monkeypatch.setattr(execute.exec_fortios, name, lambda *arguments, name=name: calls["fortios"].append(name))
    return runtime, fake, device, calls, audit_before


def test_a_schema_transaction_hands_the_auditor_its_plan_snapshots_and_policy(tmp_path, monkeypatch):
    runtime, fake, device, calls, audit_before = schema_bench(tmp_path, monkeypatch)
    shown = execute.preview(runtime, "lab", schema_request([schema_op(changes={"comment": "final"})]))
    assert (shown["result"], shown["reasons"], shown["audit_coverage"]) == ("ready", [], {"phase": "after 1"})
    calls["access"].clear(), calls["before"].clear(), calls["after"].clear()
    record = execute.apply(runtime, "lab", schema_request([schema_op(changes={"comment": "final"})]))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert record["audit_coverage"] == {"phase": "after 2"}
    assert calls["access"] == [device]
    [(plan, before_text, policy)] = calls["before"]
    assert plan is record["plan"] and policy == device.audit_policy
    assert "source text" in before_text and "final" not in before_text
    assert [arguments[0] is record["plan"] and arguments[1] is audit_before and arguments[3] == device.audit_policy
            for arguments in calls["after"]] == [True, True]
    assert ['set comment "final"' in arguments[2] for arguments in calls["after"]] == [True, True]


def test_recover_of_a_schema_transaction_reads_through_the_schema_adapter(tmp_path, monkeypatch):
    runtime, fake, device, calls, _audit_before = schema_bench(tmp_path, monkeypatch)

    def interrupt(target, lines):
        if len(target.applied_blocks) == 2:
            raise KeyboardInterrupt()

    fake.on_apply = interrupt
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab", schema_request([schema_op(changes={"comment": "final"})]))
    fake.on_apply = None
    calls["access"].clear(), calls["absent"].clear(), calls["removed"].clear()
    [settled] = execute.recover(runtime, "lab")
    assert (settled["result"], settled["reason"]) == ("reverted", "interrupted")
    assert calls["access"] == [device]
    assert len(calls["absent"]) >= 1 and len(calls["removed"]) == 1 and calls["fortios"] == []
    assert fake.addresses["source"]["comment"] == "source text"


def test_recover_goes_on_to_the_next_operation_after_settling_one_through_the_safeguard(tmp_path):
    device = FakeFortiOS()
    runtime = interrupted(tmp_path, device, killed_after_the_change())
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"], recovery_trail(record)) for record in settled] == [
        ("reverted", "interrupted", [("recovery_start", None), ("safeguard_removed", None)]),
        ("reverted", "interrupted", [("recovery_start", None)]),
    ]
    assert settled[1]["change_id"] == "f" * 32 and runtime.store.running("lab") == []


def test_a_schema_transaction_is_previewed_against_the_budget_of_all_its_operations(tmp_path, monkeypatch):
    runtime, fake, device, calls, _audit_before = schema_bench(tmp_path, monkeypatch)
    runtime.config = replace(runtime.config, limits=dict(DEFAULT_LIMITS, changes_per_device_per_hour=2))
    operations = [schema_op(changes={"comment": word}) for word in ("first", "second", "third")]
    shown = execute.preview(runtime, "lab", schema_request(operations))
    assert shown == {"result": "rejected", "device": "lab", "reasons": [HOUR_EXHAUSTED]}
    assert fake.applied_blocks == []


def stored_plan_edit(runtime, change_id, edit):
    stored = runtime.store.operation(change_id)
    plan = stored["plan"]
    edit(plan)
    plan["plan_sha256"] = execute.engine._digest({"commands": plan["commands"], "inverse": plan["inverse"],
                                                  "before": plan["predicted"]["before"],
                                                  "after": plan["predicted"]["after"]})
    runtime.store.save(stored)


def without_firmware(plan):
    plan["firmware"] = None


def foreign_attribute(plan):
    plan["predicted"]["before"]["bogus"] = "one"
    plan["predicted"]["after"]["bogus"] = "two"


def numeric_comment(plan):
    plan["predicted"]["before"]["comment"] = 5


@pytest.mark.parametrize("edit,reasons", [
    (without_firmware, ["the plan of the operation names no firmware"]),
    (foreign_attribute, ["the plan of the operation holds attribute 'bogus' outside the profile"]),
    (numeric_comment, ["the plan of the operation holds attribute 'comment' outside the profile"]),
])
def test_an_undo_refuses_a_plan_it_cannot_turn_back_into_a_request(tmp_path, edit, reasons):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"}))
    stored_plan_edit(runtime, record["change_id"], edit)
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record["change_id"], "restore")
    assert caught.value.reasons == reasons
    assert len(device.applied_blocks) == blocks


class PromptExos(FakeExos):
    def __init__(self):
        super().__init__()
        self.prompts = []

    def login_prefix(self, spec):
        self.prompts.append(spec)
        return super().login_prefix(spec)


def test_the_switch_prechecks_read_the_prompt_of_the_snapshot_hostname(tmp_path):
    from netops_admin import exec_exos

    device = PromptExos()
    runtime = make_exos_runtime(tmp_path, device)
    shown = execute.preview(runtime, "sw", exos_request())
    hostname = exec_exos.hostname(device, device.snapshot())
    assert device.prompts and set(device.prompts) == {exec_exos.prompt_spec(hostname)}
    assert shown["result"] == "ready", shown


def test_preview_refuses_the_enrollment_namespace_like_apply(tmp_path):
    runtime, target, name = ready(tmp_path)
    shown = execute.preview(runtime, name, request(key="netops-enroll-example"))
    assert shown == {"result": "rejected", "device": name, "reasons": ["the enrollment object namespace is reserved"]}


def transaction(operations, request_id):
    from netops_admin.request import parse_request

    return parse_request(json.dumps({"device": "lab", "operations": operations, "reason": "operator request",
                                     "user_request": "perform the transaction", "request_id": request_id}).encode())


def test_admission_counts_every_operation_of_a_transaction_against_the_budget_once_more(tmp_path, monkeypatch):
    runtime, fake, device, calls, _audit_before = schema_bench(tmp_path, monkeypatch)
    runtime.config = replace(runtime.config, limits=dict(DEFAULT_LIMITS, changes_per_device_per_hour=4))
    first = execute.apply(runtime, "lab", transaction([schema_op(changes={"comment": "first"})], "schema-req-00001"))
    assert first["result"] == "confirmed"
    admission = runtime.store.admission

    @contextlib.contextmanager
    def crowded():
        with admission():
            runtime.store.save(dict(first, change_id="e" * 32, request_id="schema-req-00002"))
            yield

    monkeypatch.setattr(runtime.store, "admission", crowded)
    blocks = len(fake.applied_blocks)
    operations = [schema_op(changes={"comment": word}) for word in ("second", "third", "fourth")]
    with pytest.raises(BudgetExhausted) as caught:
        execute.apply(runtime, "lab", transaction(operations, "schema-req-00003"))
    assert caught.value.reasons == [HOUR_EXHAUSTED]
    assert len(fake.applied_blocks) == blocks


def test_a_schema_create_binds_the_generated_identity_it_saw_after_the_change(tmp_path, monkeypatch):
    runtime, fake, device, calls, _audit_before = schema_bench(tmp_path, monkeypatch)
    operation = schema_op(owners=["new"], mode="create", changes={"subnet": "192.0.2.183/32", "comment": "created"})
    record = execute.apply(runtime, "lab", schema_request([operation]))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert fake.addresses["new"]["uuid"] in json.dumps(record["plan"]["generated_bindings"])
    assert runtime.store.operation(record["change_id"])["plan"]["generated_bindings"] == record["plan"]["generated_bindings"]


def test_recover_reads_the_device_it_settles_and_names_an_unreadable_plan(tmp_path):
    from netops_admin.errors import StateUnreadable

    device = FakeFortiOS()
    runtime = interrupted(tmp_path, device, killed_after_the_change(), twice=False)
    asked = []
    runtime.access_factory = lambda named: asked.append(named) or device
    [running] = runtime.store.running("lab")
    changed_back_by_hand(device)
    assert [(record["result"], record["reason"]) for record in execute.recover(runtime, "lab")] == [("reverted", "interrupted")]
    assert asked == [runtime.config.devices["lab"]]
    broken = dict(running, change_id="d" * 32, request_id="req-0008-example")
    broken["plan"] = dict(running["plan"], commands=running["plan"]["commands"] + ['set comment "other"'])
    runtime.store.save(broken)
    with pytest.raises(StateUnreadable) as caught:
        execute.recover(runtime, "lab")
    assert caught.value.reasons == ["the state file operations/%s.json cannot be read; a person must check it" % ("d" * 32)]


RECORD_FIELDS = sorted([
    "change_id", "request_id", "request_sha256", "device", "status", "result", "hostname", "plan", "steps",
    "created_at", "created_at_epoch", "budget_at_epoch", "kind", "budget_changes", "audit_before", "audit_policy",
    "audit_coverage", "accounts", "foreign_sessions", "safeguard", "finished_at_epoch", "reason", "differences",
    "audit_delivery", "notification",
])


def test_a_confirmed_operation_journals_exactly_its_fields(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    record = execute.apply(runtime, "lab", request())
    assert sorted(record) == RECORD_FIELDS
    assert sorted(runtime.store.operation(record["change_id"])) == RECORD_FIELDS
    assert record["kind"] == "change" and record["budget_changes"] == 1


def test_a_second_refresh_of_an_acknowledged_delivery_returns_the_same_record(tmp_path):
    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    record = execute.apply(runtime, "lab", request())
    status.write_text(json.dumps({"updated_at": time.time() + 1, "pending": 0}))
    shown = execute.refresh_delivery(runtime, record)
    assert shown["audit_delivery"] == "acknowledged"
    events = len(audit_lines(tmp_path))
    assert execute.refresh_delivery(runtime, shown) is shown
    assert len(audit_lines(tmp_path)) == events


def test_a_schema_enrollment_builds_its_probe_in_the_reserved_namespace(tmp_path, monkeypatch):
    runtime, fake, device, calls, _audit_before = schema_bench(tmp_path, monkeypatch)
    status = tmp_path / "export-status.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    runtime.config = replace(runtime.config, export_status_file=str(status))
    runtime.notifier = lambda record: "sent"
    record = enrollment.run(runtime, "lab", "192.0.2.254/32")
    assert (record["result"], record["reason"]) == ("reverted", "enrollment self-test"), (record["result"], record["reason"])
    assert record["kind"] == "enrollment"


def test_recover_starts_the_step_list_of_a_journaled_operation_that_has_none(tmp_path):
    device = FakeFortiOS()
    runtime = interrupted(tmp_path, device, killed_after_the_change(), twice=False, safeguard=False)
    [running] = runtime.store.running("lab")
    running.pop("steps")
    runtime.store.save(running)
    [settled] = execute.recover(runtime, "lab")
    assert (settled["result"], settled["reason"]) == ("rejected", "interrupted before any mutation")
    assert trail(settled) == [("recovery_start", None)]
