"""Port bounce (1.0.12 junos port maintenance J11) and PoE cycle (J10) of one Junos port.

Both run as one journaled operation through the same admission as apply (target, enrollment, budgets, blocking, audit
log, notification) and behind the commit confirmed safeguard of exec_junos.py. The plan is a plan of an action-only
table (port-bounce, inline-power): its commands are the change session "set interfaces <if> disable" (bounce) or
"set poe interface <if> disable" (PoE) ending with "commit confirmed 10 comment netops-change", its inverse the delete
of that statement.

Order: the state before, the margin of the own timer, the change session (the commit confirmed restarts the timer),
postcheck and audit of the off state, the observed off state, a pause of HOLD_SECONDS, the immediate return of
exec_junos.revert_now (the inverse lines committed with a plain "commit comment netops-<id>-revert", which ends the
own timer and keeps the state before; it is never committed with commit confirmed, because an expiry would return the
state before the newest commit confirmed, which is the disabled port, measured in verification), the check of the
configuration against the state before and the observed on state. Until the plain commit the expiry of the timer
returns the port to the state before, so an interrupted operation settles like any other Junos change (execute.py
recover). A link or a powered device that does not return within the wait leaves the configuration as before, with the
operational failure recorded; a PoE cycle without restored power finishes as reverted.

Not measured on a physical port: the time until a link is up again (vJunos: ge-0/0/9 is a virtual port) and all of PoE
(vJunos has no PoE controller): the PoE layout comes from the Juniper EX documentation (fixtures/junos_g138).
"""
from __future__ import annotations

import json

from netops_admin import audit_gate, engine, exec_junos, execute, fortios, junos, prediction
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

BOUNCE = "port-bounce"
POE = "poe-cycle"
TABLES = {BOUNCE: junos.BOUNCE_TABLE, POE: junos.POE_CYCLE_TABLE}
OFF_WAIT_SECONDS = 10
HOLD_SECONDS = 5
LINK_WAIT_SECONDS = 30
POE_ON_WAIT_SECONDS = 60
POLL_SECONDS = 2
LINK_NOT_BACK = "link not up after the bounce"
PD_NOT_BACK = "powered device not powered after the cycle"
TIME_LIMIT = "cycle exceeded the safeguard time budget"


def request(action: str, device: str, port: str, reason: str, user_request: str, request_id: str,
            endpoint_impact: str | None = None):
    body = {"device": device, "table": TABLES[action], "op": "update", "key": str(port),
            "changes": {"admin-state": "disabled"}, "reason": reason, "user_request": user_request,
            "request_id": request_id}
    if endpoint_impact is not None:
        body["endpoint_impact"] = endpoint_impact
    return parse_request(json.dumps(body).encode("utf-8"))


def _admissible(runtime, device_name, action, cycle_request):
    """Platform and measured profile of the target, from the configuration only: no device read or write."""
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform != "junos":
        raise Rejected(["operation %s of this module is for Junos switches" % action],
                       reason_codes=["action_unsupported"])
    if device is not None:
        execute._measured(runtime, device, cycle_request)


def preview(runtime, device_name: str, action: str, cycle_request) -> dict:
    try:
        _admissible(runtime, device_name, action, cycle_request)
        result, refused = execute._preview(runtime, device_name, cycle_request, action=action)
    except Rejected as exc:
        if not isinstance(exc, execute.BudgetExhausted):
            execute._count_rejection(runtime)
        raise
    if refused:
        execute._count_rejection(runtime)
    if result.get("result") in ("ready", "rejected") and "commands" in result:
        result = dict(result, operation=action, hold_seconds=HOLD_SECONDS)
    return result


def apply(runtime, device_name: str, action: str, cycle_request, *, expected_plan_sha256=None) -> dict:
    try:
        _admissible(runtime, device_name, action, cycle_request)
        if expected_plan_sha256 is None:
            raise Rejected(["Junos cycle apply requires the plan_sha256 from preview"], reason_codes=["plan_changed"])
        expected_plan = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device_name, cycle_request, expected_plan=expected_plan, action=action)


def _state(access, action, port) -> dict:
    if action == BOUNCE:
        row = junos.interface_row(access.check_query("show interfaces %s terse" % port), port)
        if row is None:
            raise Rejected(["the switch does not report interface %s" % port], reason_codes=["port_usage_unreadable"])
        return {"admin": row["admin"], "link": row["link"]}
    state = junos.poe_state(exec_junos._read(access, "show poe interface %s" % port), port)
    if state is None:
        raise Rejected(["port %s has no PoE controller" % port], reason_codes=["poe_not_capable"])
    return state


def _off(action, state) -> bool:
    if action == BOUNCE:
        return state["admin"] == "down"
    return state["configured"] == "disabled" and state["state"] == "disabled"


def _on(action, state) -> bool:
    if action == BOUNCE:
        return state["admin"] == "up"
    return state["configured"] == "enabled"


def _back(action, before, state) -> bool:
    if action == BOUNCE:
        return before["link"] != "up" or state["link"] == "up"
    return before["state"] == "powered" and state["state"] == "powered"


def _shown(state) -> str:
    return "%s/%s" % ((state["admin"], state["link"]) if "admin" in state else (state["configured"], state["state"]))


def _observe(runtime, deadline, access, action, port, wanted, seconds):
    until = runtime.monotonic() + seconds
    while True:
        last = deadline.read(access, _state, action, port)
        remaining = until - runtime.monotonic()
        if remaining >= 0 and wanted(last):
            return last, True
        if remaining <= 0:
            return last, False
        pause = min(POLL_SECONDS, remaining, deadline.left())
        if pause <= 0:
            raise Rejected([TIME_LIMIT])
        runtime.sleep(pause)


def run(runtime, adapter, access, record, plan, device, due, requested=None) -> dict:
    step, finish, settle = execute._step, execute._finish, execute._settle_after_expiry
    spec, port, action = execute._spec(record), plan["key"], record["kind"]
    prefix = "port" if action == BOUNCE else "poe"
    timer_end = due
    deadline = execute._Deadline(runtime, timer_end - runtime.monotonic(), TIME_LIMIT)
    try:
        before = deadline.read(access, _state, action, port)
    except Exception as exc:
        step(runtime, record, "%s_state_unreadable" % prefix, type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", timer_end)
    record["cycle"] = {"before": before}
    step(runtime, record, "%s_before" % prefix, _shown(before))
    planned = plan["cycle_state"]["link" if action == BOUNCE else "poe"]
    seen = ("up" if before["link"] == "up" else "down") if action == BOUNCE else before["state"]
    if not _on(action, before) or (action == POE and before["state"] != "powered") or seen != planned:
        return settle(runtime, access, record, plan, "cycle port state changed after preflight", timer_end)
    refused = adapter.before_write(access, record, timer_end - runtime.monotonic(), device)
    if refused is not None:
        step(runtime, record, "change_not_written", refused)
        return settle(runtime, access, record, plan, "no time left to write", timer_end)
    access.line_guard = adapter.line_guard_for(plan["commands"], lambda: timer_end - runtime.monotonic())
    step(runtime, record, "change_start")
    sent = runtime.monotonic()
    try:
        try:
            access.apply(plan["commands"], spec)
        finally:
            access.line_guard = None
        step(runtime, record, "change_applied")
    except Exception as exc:
        step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__,
                                                                      getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan, "change failed", timer_end)
    answered = runtime.monotonic()
    try:
        problems = adapter.safeguard_rearmed(access, record)
    except Exception as exc:
        problems = ["the timer after the change is unreadable (%s)" % type(exc).__name__]
    runtime.store.save(record)
    if problems:
        step(runtime, record, "safeguard_rearm_unverified", problems[0])
        return settle(runtime, access, record, plan, "safeguard not verified after the change", timer_end)
    step(runtime, record, "safeguard_rearmed", record["safeguard"].get("device_expiry"))
    timer_end = execute._restarted_end(adapter, device, record, sent if requested is None else requested, sent, answered)
    deadline = execute._Deadline(runtime, timer_end - runtime.monotonic(), TIME_LIMIT)
    cause = "administrator table"
    try:
        off_text = deadline.read(access, lambda target: target.snapshot())
        if adapter.accounts_check(access, device, off_text) != record["accounts"]:
            raise Rejected(["the administrator accounts changed during the operation"])
        cause = "postcheck rejected"
        verdict = engine.verify(plan, off_text.encode("utf-8"), expect="after")
    except Rejected as exc:
        cause = getattr(exc, "category", cause)
        step(runtime, record, "postcheck_failed", cause)
        return settle(runtime, access, record, plan, cause, timer_end)
    except Exception as exc:
        step(runtime, record, "postcheck_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "postcheck unavailable", timer_end)
    if verdict["result"] != "match":
        step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", timer_end)
    step(runtime, record, "postcheck_passed")
    try:
        policy = record.get("audit_policy")
        audited = prediction.audited(off_text, plan)
        record["audit_coverage"] = audit_gate.evaluate(device.platform, audited, policy, plan["table"],
                                                       record["audit_before"])
        audit_gate.check_policy(plan, policy, audited, record["audit_before"])
        found = audit_gate.new_blocking(device.platform, record["audit_before"], audited, device.name, policy,
                                        fortios.SAFEGUARD_PREFIX + record["change_id"][:12] + "-")
    except audit_gate.Incomplete as exc:
        step(runtime, record, "audit_incomplete", exc.summary)
        return settle(runtime, access, record, plan, "audit incomplete", timer_end)
    except Exception as exc:
        step(runtime, record, "audit_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "audit unavailable", timer_end)
    if found:
        record["audit_findings"] = found
        step(runtime, record, "audit_failed", "%d new findings" % len(found))
        return settle(runtime, access, record, plan, "audit finding", timer_end)
    step(runtime, record, "audit_passed", "%d rules, %d findings before, none new%s"
         % (audit_gate.rule_count(device.platform), audit_gate.finding_count(record["audit_before"]),
            audit_gate.unevaluated_note(record["audit_before"])))
    try:
        off, met = _observe(runtime, deadline, access, action, port, lambda state: _off(action, state), OFF_WAIT_SECONDS)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", timer_end)
    record["cycle"]["off"] = off
    if not met:
        step(runtime, record, "check_identity_failed", "not off: %s" % _shown(off))
        return settle(runtime, access, record, plan, "check identity mismatch", timer_end)
    step(runtime, record, "%s_off_observed" % prefix, _shown(off))
    if timer_end - runtime.monotonic() < exec_junos.REVERT_NOW_SECONDS + HOLD_SECONDS:
        return settle(runtime, access, record, plan, TIME_LIMIT, timer_end)
    runtime.sleep(HOLD_SECONDS)
    step(runtime, record, "off_held", "%d s" % HOLD_SECONDS)
    step(runtime, record, "%s_enable_start" % prefix)
    try:
        returned = adapter.revert_now(access, record, spec)
    except Exception as exc:
        step(runtime, record, "%s_enable_failed" % prefix, type(exc).__name__)
        return settle(runtime, access, record, plan, "change failed", timer_end)
    if not returned:
        step(runtime, record, "%s_enable_failed" % prefix, "the return was not proven")
        return settle(runtime, access, record, plan, "change failed", timer_end)
    step(runtime, record, "%s_enable_applied" % prefix)
    try:
        back = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "%s_enable_check_failed" % prefix, type(exc).__name__)
        return finish(runtime, record, "unknown", "final check unavailable")
    if back["result"] != "match":
        step(runtime, record, "%s_enable_check_failed" % prefix, "%d differences" % len(back["differences"]))
        record["postcheck_differences"] = back["differences"]
        return finish(runtime, record, "unknown", "foreign change after the return", back["differences"])
    step(runtime, record, "%s_enable_verified" % prefix)
    step(runtime, record, "confirm_start")
    failure = None
    try:
        wait = LINK_WAIT_SECONDS if action == BOUNCE else POE_ON_WAIT_SECONDS
        late = execute._Deadline(runtime, wait + 60, TIME_LIMIT)
        on, good = _observe(runtime, late, access, action, port,
                            lambda state: _on(action, state) and _back(action, before, state), wait)
        record["cycle"]["after"] = on
        if not _on(action, on):
            failure = "check identity mismatch"
        elif not good:
            failure = LINK_NOT_BACK if action == BOUNCE else PD_NOT_BACK
        step(runtime, record, "%s_on_observed" % prefix, _shown(on) if not failure else "%s, %s" % (_shown(on), failure))
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        failure = "check identity unavailable"
    if failure:
        record["cycle"]["return_failure"] = failure
    result = "reverted" if action == POE and failure else "confirmed"
    return finish(runtime, record, result, failure)
