"""Port bounce (1.0.12 eos port maintenance E08) and PoE cycle (E07) of one Arista EOS port.

Both run as one journaled operation through the same admission as apply (target, enrollment, budgets, blocking, audit
log, notification) and behind the timed safeguard session of EOS (configure session with commit timer), as the EXOS PoE
cycle in exos_poe.py does. The plan is a plan of an action-only table (eos-port-bounce, eos-inline-power): its command is
"shutdown" or "poe disabled" and its inverse "no shutdown" or "no poe disabled", so recover and the safeguard settle an
interrupted operation like any other EOS change (an expired timer returns the port to its state before).

Order: margin check against the safeguard, the off command, postcheck and audit of the off state, the observed off
state, a pause of HOLD_SECONDS, the inverse, its check against the configuration before, the observed on state, then
the confirmation of the safeguard and write memory. Bounce: the check account reads the Status column of
show interfaces N status (measured on cEOS 4.36.1F: disabled right after shutdown, connected right after
no shutdown). PoE: the write account reads show poe interface N (Privileged EXEC; layout of the Arista EOS manual, not
measured: the lab has no EOS switch with PoE). A link or a powered device that does not return within the wait leaves
the configuration as before, with the operational failure recorded separately. A PoE cycle without restored
power finishes as reverted.
"""
from __future__ import annotations

import json

from netops_admin import audit_gate, engine, eos, exec_eos, execute, fortios, prediction
from netops_admin.errors import Rejected
from netops_admin.exos_poe import MARGIN_CODE, MARGIN_REASON, _refused, _wait_reads
from netops_admin.request import parse_request

BOUNCE = "port-bounce"
POE = "poe-cycle"
TABLES = {BOUNCE: eos.BOUNCE_TABLE, POE: eos.POE_TABLE}
# measured on cEOS (private measurement record): disabled at the first read after shutdown
OFF_WAIT_SECONDS = 10
# the pause while the port or its power stays off
HOLD_SECONDS = 5
# not measured on a physical port: the time until the link is up again after no shutdown
LINK_WAIT_SECONDS = 30
# not measured on EOS: the time until a powered device draws power again (the EXOS cycle waits as long)
POE_ON_WAIT_SECONDS = 60
POLL_SECONDS = 2
# as in exos_poe: a read at most 2 s, show running-config at most 4 s, an interactive write as two reads
READ_SECONDS = 2
SNAPSHOT_SECONDS = 4
WRITE_SECONDS = 2 * READ_SECONDS
CONNECTED = "connected"
DISABLED = "disabled"
POWERED = "powered"
LINK_NOT_BACK = "link not connected after the bounce"
PD_NOT_BACK = "powered device not powered after the cycle"
TIME_LIMIT = "cycle exceeded the safeguard time budget"


def on_wait(action) -> int:
    return LINK_WAIT_SECONDS if action == BOUNCE else POE_ON_WAIT_SECONDS


def cycle_seconds(action) -> int:
    """Off and on command and the safeguard removal, show running-config after each, the off wait, the pause and the on
    wait with all their reads: bounce 109 s, PoE cycle 169 s."""
    return (3 * WRITE_SECONDS + 2 * SNAPSHOT_SECONDS
            + OFF_WAIT_SECONDS + _wait_reads(OFF_WAIT_SECONDS) * READ_SECONDS + HOLD_SECONDS
            + on_wait(action) + _wait_reads(on_wait(action)) * READ_SECONDS)


def request(action: str, device: str, port: str, reason: str, user_request: str, request_id: str,
            endpoint_impact: str | None = None):
    body = {"device": device, "table": TABLES[action], "op": "update", "key": str(port),
            "changes": {"admin-state": "disabled"}, "reason": reason, "user_request": user_request,
            "request_id": request_id}
    if endpoint_impact is not None:
        body["endpoint_impact"] = endpoint_impact
    return parse_request(json.dumps(body).encode("utf-8"))


def required_safeguard_seconds(device, action) -> int:
    return cycle_seconds(action) + device.confirm_margin_seconds + 1


def _admissible(runtime, device_name, action, cycle_request):
    """Platform and safeguard margin of the target, from the configuration only: no device read or write."""
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform != "eos":
        raise Rejected(["operation %s of this module is for Arista EOS switches" % action],
                       reason_codes=["action_unsupported"])
    if device is not None:
        execute._measured(runtime, device, cycle_request)
    if device is not None and cycle_seconds(action) + device.confirm_margin_seconds >= device.safeguard_seconds:
        raise Rejected(["the %s can take up to %d s and needs confirm_margin_seconds %d s on top, but the safeguard "
                        "gives only %d s; set safeguard_seconds of device %s to at least %d"
                        % (action, cycle_seconds(action), device.confirm_margin_seconds, device.safeguard_seconds,
                           device.name, required_safeguard_seconds(device, action))],
                       reason_codes=["safeguard_margin_insufficient"],
                       reason_details=[{"code": MARGIN_CODE, "cycle_seconds": cycle_seconds(action),
                                        "confirm_margin_seconds": device.confirm_margin_seconds,
                                        "available_seconds": device.safeguard_seconds,
                                        "required_safeguard_seconds": required_safeguard_seconds(device, action)}])


def preview(runtime, device_name: str, action: str, cycle_request) -> dict:
    """Every check of the operation against the device, without any change."""
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
        back = "no shutdown" if action == BOUNCE else "no poe disabled"
        result = dict(result, operation=action, hold_seconds=HOLD_SECONDS,
                      cycle_commands=list(result["commands"]) + ["configure terminal", "interface %s" % result["key"],
                                                                  back, "end"])
    return result


def apply(runtime, device_name: str, action: str, cycle_request, *, expected_plan_sha256=None) -> dict:
    try:
        _admissible(runtime, device_name, action, cycle_request)
        if expected_plan_sha256 is None:
            raise Rejected(["EOS cycle apply requires the plan_sha256 from preview"], reason_codes=["plan_changed"])
        expected_plan = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device_name, cycle_request, expected_plan=expected_plan, action=action)


def _state(access, action, port) -> dict:
    if action == BOUNCE:
        return {"status": exec_eos.link_state(access, port)}
    return exec_eos.poe_answer(access, port)


def _off(action, state) -> bool:
    if action == BOUNCE:
        return state["status"] == DISABLED
    return state["configured"] == "disabled" and state["state"] != POWERED


def _on(action, state) -> bool:
    if action == BOUNCE:
        return state["status"] != DISABLED
    return state["configured"] == "enabled"


def _back(action, before, state) -> bool:
    if action == BOUNCE:
        return before["status"] != CONNECTED or state["status"] == CONNECTED
    return before["state"] == POWERED and state["state"] == POWERED


def _observe(runtime, deadline, access, action, port, wanted, seconds):
    """Count time spent reading and sleeping against both the poll window and the safeguard."""
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


def _guarded_write(access, commands, spec, left):
    if left() <= 0:
        raise Rejected([TIME_LIMIT])
    previous = getattr(access, "line_guard", None)
    access.line_guard = lambda: left() > 0 and (previous is None or previous())
    try:
        access.apply(commands, spec)
    finally:
        access.line_guard = previous
    if left() <= 0:
        raise Rejected([TIME_LIMIT])


def _cycle_failure(record):
    cycle = record.get("cycle", {})
    if cycle.get("return_failure"):
        return cycle["return_failure"]
    # In-progress records from the older code contain the raw observation and
    # a last step detail, but have no explicit return_failure field.
    before, after = cycle.get("before"), cycle.get("after")
    if before is None or after is None:
        return None
    if not _back(record["kind"], before, after):
        return LINK_NOT_BACK if record["kind"] == BOUNCE else PD_NOT_BACK
    return None


def _result(record):
    return "reverted" if record["kind"] == POE and _cycle_failure(record) else "confirmed"


def _persistence_failure(return_failure):
    return "%s; not persisted" % return_failure if return_failure else "not persisted"


def recover_disarmed(runtime, adapter, access, record, is_before):
    failure = _cycle_failure(record)
    steps = {step["step"] for step in record.get("steps", [])}
    if not is_before:
        return execute._finish(runtime, record, "unknown", failure or "interrupted; state matches neither side")
    result, reason = "reverted", "interrupted"
    if "confirm_start" in steps:
        verified = "safeguard_confirmed" in steps or adapter.safeguard_confirmed(access, record)
        if verified:
            result, reason = _result(record), "confirmed before the interruption"
        elif not adapter.safeguard_fired(access, record):
            return execute._finish(runtime, record, "unknown", failure or "confirmation unverified")
    saved = execute._persist(runtime, adapter, access, record)
    return execute._finish(runtime, record, result, (failure or reason) if saved else _persistence_failure(failure))


def _shown(state) -> str:
    return state["status"] if "status" in state else "%s/%s" % (state["configured"], state["state"])


def run(runtime, adapter, access, record, plan, device, due) -> dict:
    step, finish, settle = execute._step, execute._finish, execute._settle_after_expiry
    spec, port, action = execute._spec(record), plan["key"], record["kind"]
    prefix = "port" if action == BOUNCE else "poe"
    clock_started = runtime.monotonic()
    try:
        remaining = (execute._fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception as exc:
        step(runtime, record, "clock_unreadable", type(exc).__name__)
        return settle(runtime, access, record, plan, "device clock", due)
    timer_end = min(due, clock_started + remaining)
    deadline = execute._Deadline(runtime, timer_end - runtime.monotonic(), TIME_LIMIT)
    deadline.tighten(timer_end - device.confirm_margin_seconds, TIME_LIMIT)
    try:
        before = deadline.read(access, _state, action, port)
    except Exception as exc:
        step(runtime, record, "%s_state_unreadable" % prefix, type(exc).__name__)
        reason = TIME_LIMIT if deadline.left() <= 0 else "check identity unavailable"
        return settle(runtime, access, record, plan, reason, timer_end)
    record["cycle"] = {"before": before}
    step(runtime, record, "%s_before" % prefix, _shown(before))
    if not _on(action, before) or (action == POE and before["state"] != POWERED):
        return settle(runtime, access, record, plan, "cycle port state changed after preflight", timer_end)
    observed = before["status"] if action == BOUNCE else before["state"]
    if observed != plan["cycle_state"]["link" if action == BOUNCE else "poe"]:
        return settle(runtime, access, record, plan, "cycle port state changed after preflight", timer_end)
    remaining = timer_end - runtime.monotonic()
    margin = "%d s left, %d s cycle, %d s margin" % (remaining, cycle_seconds(action), device.confirm_margin_seconds)
    if cycle_seconds(action) + device.confirm_margin_seconds >= remaining:
        step(runtime, record, "cycle_refused", margin)
        if deadline.left() <= 0:
            return settle(runtime, access, record, plan, TIME_LIMIT, timer_end)
        return _refused(runtime, adapter, access, record, spec, MARGIN_REASON, MARGIN_CODE)
    step(runtime, record, "margin_checked", margin)
    step(runtime, record, "change_start")
    try:
        _guarded_write(access, plan["commands"], spec, deadline.left)
        step(runtime, record, "change_applied")
    except Exception as exc:
        step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__,
                                                                      getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "change failed", timer_end)
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
        return settle(runtime, access, record, plan, TIME_LIMIT if deadline.left() <= 0 else cause, timer_end)
    except Exception as exc:
        step(runtime, record, "postcheck_failed", type(exc).__name__)
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "postcheck unavailable", timer_end)
    if verdict["result"] != "match":
        step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", due)
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
        return settle(runtime, access, record, plan, "audit incomplete", due)
    except Exception as exc:
        step(runtime, record, "audit_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "audit unavailable", due)
    if found:
        record["audit_findings"] = found
        step(runtime, record, "audit_failed", "%d new findings" % len(found))
        return settle(runtime, access, record, plan, "audit finding", due)
    step(runtime, record, "audit_passed", "%d rules, %d findings before, none new%s"
         % (audit_gate.rule_count(device.platform), audit_gate.finding_count(record["audit_before"]),
            audit_gate.unevaluated_note(record["audit_before"])))
    try:
        off, met = _observe(runtime, deadline, access, action, port, lambda state: _off(action, state), OFF_WAIT_SECONDS)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "check identity unavailable", timer_end)
    record["cycle"]["off"] = off
    if not met:
        step(runtime, record, "check_identity_failed", "not off: %s" % _shown(off))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    step(runtime, record, "%s_off_observed" % prefix, _shown(off))
    if deadline.left() <= HOLD_SECONDS:
        return settle(runtime, access, record, plan, TIME_LIMIT, timer_end)
    runtime.sleep(HOLD_SECONDS)
    step(runtime, record, "off_held", "%d s" % HOLD_SECONDS)
    step(runtime, record, "%s_enable_start" % prefix)
    try:
        _guarded_write(access, plan["inverse"], spec, deadline.left)
        step(runtime, record, "%s_enable_applied" % prefix)
    except Exception as exc:
        step(runtime, record, "%s_enable_failed" % prefix, "%s after %d lines"
             % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "change failed", timer_end)
    try:
        returned = engine.verify(plan, deadline.read(access, lambda target: target.snapshot()).encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "%s_enable_check_failed" % prefix, type(exc).__name__)
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "postcheck unavailable", timer_end)
    if returned["result"] != "match":
        step(runtime, record, "%s_enable_check_failed" % prefix, "%d differences" % len(returned["differences"]))
        record["postcheck_differences"] = returned["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", due)
    step(runtime, record, "%s_enable_verified" % prefix)
    try:
        on, back = _observe(runtime, deadline, access, action, port,
                            lambda state: _on(action, state) and _back(action, before, state), on_wait(action))
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "check identity unavailable", timer_end)
    record["cycle"]["after"] = on
    if not _on(action, on):
        step(runtime, record, "check_identity_failed", "not on: %s" % _shown(on))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    failure = None
    if not back:
        failure = LINK_NOT_BACK if action == BOUNCE else PD_NOT_BACK
    if failure:
        record["cycle"]["return_failure"] = failure
    step(runtime, record, "%s_on_observed" % prefix, _shown(on) if back else "%s, %s" % (_shown(on), failure))
    if deadline.left() <= 0:
        return settle(runtime, access, record, plan, failure or TIME_LIMIT, timer_end)

    step(runtime, record, "confirm_start")
    confirmation = execute._Deadline(runtime, timer_end - runtime.monotonic(), TIME_LIMIT)
    try:
        if not deadline.read(access, adapter.cycle_timer_pending, record):
            return settle(runtime, access, record, plan, failure or "confirmation unverified", timer_end)
        label = adapter.safeguard_label(record["change_id"])
        _guarded_write(access, ["configure session %s commit" % label], spec, confirmation.left)
        if confirmation.read(access, adapter.cycle_timer_pending, record):
            raise Rejected(["cycle timer is still pending"])
    except Exception as exc:
        step(runtime, record, "confirm_unverified", type(exc).__name__)
        if adapter.safeguard_confirmed(access, record):
            return finish(runtime, record, "unknown", failure or "confirmation unverified")
        return settle(runtime, access, record, plan,
                      failure or (TIME_LIMIT if deadline.left() <= 0 else "confirmation unverified"), timer_end)
    step(runtime, record, "safeguard_confirmed")
    if not adapter.clean_confirmed_cycle(access, record, spec):
        return finish(runtime, record, "unknown", failure or "safeguard cleanup unverified")
    try:
        removed = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "removal_check_failed", type(exc).__name__)
        return finish(runtime, record, "unknown", failure or "final check unavailable")
    if removed["result"] != "match":
        step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        return finish(runtime, record, "unknown", failure or "foreign change after the safeguard was removed",
                      removed["differences"])
    result = _result(record)
    if not execute._persist(runtime, adapter, access, record):
        return finish(runtime, record, result, _persistence_failure(failure))
    if record["steps"][-1]["step"] == "configuration_saved":
        try:
            saved = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
        except Exception as exc:
            step(runtime, record, "saved_check_failed", type(exc).__name__)
            return finish(runtime, record, result, "saved configuration unverified")
        if saved["result"] != "match":
            step(runtime, record, "saved_check_failed", "%d differences" % len(saved["differences"]))
            return finish(runtime, record, result, "foreign change during save", saved["differences"])
    return finish(runtime, record, result, failure)
