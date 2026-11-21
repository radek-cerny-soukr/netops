"""Port bounce (1.0.12 G61, IOS-C021) and PoE cycle (IOS-M024) of one Cisco IOS or IOS XE port.

Both run as ONE journaled operation through the same admission as apply (target, enrollment, budgets, blocking, audit
log, notification) and behind the revert timer of Admin (exec_ios: configure terminal revert timer, confirmed with
configure confirm), as the EOS cycle in eos_cycle.py and the EXOS cycle in exos_poe.py do. The plan is a plan of an
action-only table (port-bounce, poe-cycle): its command is "shutdown" or "power inline never" and its inverse
"no shutdown" or the earlier "power inline" line of the port, so an interrupted operation is settled like any other IOS
change: an expired timer returns the whole running configuration to the archive taken before (the port is enabled and
powered again).

Order: margin check against the timer, the off command, postcheck of the off state in the running configuration, the
observed off state (check account), a pause of HOLD_SECONDS, the inverse, its check against the configuration before,
the observed on state, then configure confirm. The operation ends on the configuration before it, which the startup
configuration already holds (the preflight refuses a device with unsaved changes), so nothing is saved.

Bounce: the check account reads the Status column of show interfaces N status (measured on IOSvL2 15.2: notconnect
or connected before, disabled after shutdown, notconnect again after no shutdown on a port without a peer). PoE: the
check account reads the Admin and Oper columns of show power inline N (layout of the Cisco Catalyst manual, not
measured: the lab has no PoE switch). A link or a powered device that does not return within the wait leaves the
configuration as before, with the operational failure recorded separately; the result of the bounce reports the link
before and after. A PoE cycle without restored power finishes as reverted.
"""
from __future__ import annotations

import json

from netops_admin import audit_gate, engine, exec_ios, execute, fortios, ios, prediction
from netops_admin.errors import Rejected
from netops_admin.exos_poe import MARGIN_CODE, MARGIN_REASON, _wait_reads
from netops_admin.request import parse_request

BOUNCE = "port-bounce"
POE = "poe-cycle"
TABLES = {BOUNCE: ios.BOUNCE_TABLE, POE: ios.POE_CYCLE_TABLE}
# not measured on a physical port: the wait for the status disabled after shutdown (the lab node shows it at the first
# read) and the time until a link is up again after no shutdown
OFF_WAIT_SECONDS = 10
LINK_WAIT_SECONDS = 20
# not measured on IOS: the time until a powered device draws power again (the EXOS cycle waits 60 s, the EOS cycle 60 s)
POE_ON_WAIT_SECONDS = 30
# the pause while the port or its power stays off (the Cisco guide recommends 2-4 s between shut and no shut)
HOLD_SECONDS = 5
POLL_SECONDS = 2
# measured on IOSvL2 (ref/mereni-c4c5): the revert timer installation 9 s + 3 reads, a write session 8 s, an exec read
# 1.1 s, show running-config 6.1 s
INSTALL_SECONDS = 13
READ_SECONDS = 2
SNAPSHOT_SECONDS = 7
WRITE_SECONDS = 10
CONNECTED = "connected"
DISABLED = "disabled"
POWERED = "on"
LINK_NOT_BACK = "link not connected after the bounce"
PD_NOT_BACK = "powered device not powered after the cycle"
TIME_LIMIT = "cycle exceeded the safeguard time budget"


def on_wait(action) -> int:
    return LINK_WAIT_SECONDS if action == BOUNCE else POE_ON_WAIT_SECONDS


def cycle_seconds(action) -> int:
    """The installation of the revert timer, the off command, the on command and configure confirm (a session each),
    show running-config after each of them and after the confirmation, the off wait, the pause and the on wait with all
    their reads: bounce 133 s, PoE cycle 153 s."""
    return (INSTALL_SECONDS + 3 * WRITE_SECONDS + 3 * SNAPSHOT_SECONDS
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
    """The smallest safeguard_seconds (whole minutes) whose timer, counted 2 % short for the clock drift, covers the
    cycle and the confirmation margin."""
    need = cycle_seconds(action) + device.confirm_margin_seconds
    minutes = int(need // (60 * (1 - exec_ios.DRIFT_FRACTION))) + 1
    return max(exec_ios.MIN_MINUTES, minutes) * 60


def _admissible(runtime, device_name, action):
    """Platform and timer margin of the target, from the configuration only: no device read or write."""
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform not in ios.PLATFORMS:
        raise Rejected(["operation %s of this module is for Cisco IOS and IOS XE switches" % action],
                       reason_codes=["action_unsupported"])
    if device is not None and cycle_seconds(action) + device.confirm_margin_seconds >= exec_ios.timer_seconds(device):
        raise Rejected(["the %s can take up to %d s and needs confirm_margin_seconds %d s on top, but the revert timer "
                        "of safeguard_seconds %d covers %d s; set safeguard_seconds of device %s to at least %d"
                        % (action, cycle_seconds(action), device.confirm_margin_seconds, device.safeguard_seconds,
                           exec_ios.timer_seconds(device), device.name, required_safeguard_seconds(device, action))],
                       reason_codes=["safeguard_margin_insufficient"],
                       reason_details=[{"code": MARGIN_CODE, "cycle_seconds": cycle_seconds(action),
                                        "confirm_margin_seconds": device.confirm_margin_seconds,
                                        "available_seconds": int(exec_ios.timer_seconds(device)),
                                        "required_safeguard_seconds": required_safeguard_seconds(device, action)}])


def preview(runtime, device_name: str, action: str, cycle_request) -> dict:
    """Every check of the operation against the device, without any change."""
    try:
        _admissible(runtime, device_name, action)
        result, refused = execute._preview(runtime, device_name, cycle_request, action=action)
    except Rejected as exc:
        if not isinstance(exc, execute.BudgetExhausted):
            execute._count_rejection(runtime)
        raise
    if refused:
        execute._count_rejection(runtime)
    if result.get("result") in ("ready", "rejected") and "commands" in result:
        back = (["no shutdown"] if action == BOUNCE else ios.render_poe(result["key"], result["predicted"]["before"])[2:3])
        result = dict(result, operation=action, hold_seconds=HOLD_SECONDS,
                      cycle_commands=list(result["commands"]) + ["configure terminal", "interface %s" % result["key"],
                                                                  *back, "end"])
    return result


def apply(runtime, device_name: str, action: str, cycle_request, *, expected_plan_sha256=None) -> dict:
    try:
        _admissible(runtime, device_name, action)
        if expected_plan_sha256 is None:
            raise Rejected(["IOS cycle apply requires the plan_sha256 from preview"], reason_codes=["plan_changed"])
        expected_plan = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device_name, cycle_request, expected_plan=expected_plan, action=action)


def _state(access, action, port) -> dict:
    if action == BOUNCE:
        return {"status": exec_ios.link_state(access, port)}
    return exec_ios.poe_answer(access, port, check=True)


def _off(action, state, *, xe=False) -> bool:
    if action == BOUNCE:
        return state["status"] == DISABLED
    return state["admin"] == "off" and (state["oper"] == "off" if xe else state["oper"] != POWERED)


def _on(action, before, state, *, xe=False) -> bool:
    if action == BOUNCE:
        return state["status"] in (CONNECTED, "notconnect") if xe else state["status"] != DISABLED
    return state["admin"] == before["admin"]


def _back(action, before, state) -> bool:
    if action == BOUNCE:
        return before["status"] != CONNECTED or state["status"] == CONNECTED
    return state["oper"] == POWERED


def _shown(state) -> str:
    return state["status"] if "status" in state else "%s/%s" % (state["admin"], state["oper"])


def _observe(runtime, deadline, access, action, port, wanted, seconds):
    """Count time spent reading and sleeping against both the poll window and the revert timer."""
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


def _guarded_write(adapter, access, commands, spec, left):
    if not adapter.line_allowed(left()):
        raise Rejected([TIME_LIMIT])
    previous = getattr(access, "line_guard", None)
    access.line_guard = lambda: adapter.line_allowed(left()) and (previous is None or previous())
    try:
        access.apply(commands, spec)
    finally:
        access.line_guard = previous
    if left() <= 0:
        raise Rejected([TIME_LIMIT])


def _refused(runtime, adapter, access, record, spec, plan, reason, code) -> dict:
    """Confirm the unused revert timer before refusing a cycle that never touched the port."""
    cleaned = adapter.remove_safeguard(access, record, spec)
    execute._step(runtime, record, "safeguard_removed" if cleaned else "safeguard_removal_unverified")
    if not cleaned:
        return execute._finish(runtime, record, "unknown", "safeguard cleanup unverified")
    try:
        returned = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception:
        return execute._finish(runtime, record, "unknown", "final check unavailable")
    if returned["result"] != "match":
        return execute._finish(runtime, record, "unknown", "foreign change after the safeguard was removed",
                               returned["differences"])
    return execute._finish(runtime, record, "rejected", reason, reason_code=code)


def _result(record, failure):
    return "reverted" if failure and (record["kind"] == POE or record["plan"]["platform"] == "iosxe") else "confirmed"


def recover_return(runtime, access, record, is_before, steps):
    if not is_before:
        return execute._finish(runtime, record, "unknown", "interrupted; original configuration not verified")
    cycle = record.get("cycle") or {}
    failure = cycle.get("return_failure")
    if failure or "confirm_start" not in steps or not all(side in cycle for side in ("before", "off", "after")):
        return execute._finish(runtime, record, "reverted", failure or "interrupted")
    action = record["kind"]
    try:
        before, off = cycle["before"], cycle["off"]
        after = _state(access, action, record["plan"]["key"])
        returned = _off(action, off, xe=True) and _on(action, before, after, xe=True) and _back(action, before, after)
    except (KeyError, Rejected):
        return execute._finish(runtime, record, "unknown", "interrupted; operational return unverified")
    if not returned:
        failure = LINK_NOT_BACK if action == BOUNCE else PD_NOT_BACK
        return execute._finish(runtime, record, "reverted", failure)
    return execute._finish(runtime, record, "confirmed", "operational return verified after the interruption")


def run(runtime, adapter, access, record, plan, device, due) -> dict:
    step, finish, settle = execute._step, execute._finish, execute._settle_after_expiry
    spec, port, action = execute._spec(record), plan["key"], record["kind"]
    prefix = "port" if action == BOUNCE else "poe"
    # the revert timer ends at "due" on the monotonic clock of Admin (counted from before it was requested)
    timer_end = due
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
    observed = before["status"] if action == BOUNCE else before["oper"]
    if (action == BOUNCE and before["status"] == DISABLED) or (action == POE and before["admin"] == "off") \
            or observed != plan["cycle_state"]["link" if action == BOUNCE else "poe"]:
        return settle(runtime, access, record, plan, "cycle port state changed after preflight", timer_end)
    remaining = timer_end - runtime.monotonic()
    margin = "%d s left, %d s cycle, %d s margin" % (remaining, cycle_seconds(action), device.confirm_margin_seconds)
    # the installation of the timer is behind us: only the part of the cycle that follows it must fit
    if cycle_seconds(action) - INSTALL_SECONDS + device.confirm_margin_seconds >= remaining:
        step(runtime, record, "cycle_refused", margin)
        if deadline.left() <= 0:
            return settle(runtime, access, record, plan, TIME_LIMIT, timer_end)
        return _refused(runtime, adapter, access, record, spec, plan, MARGIN_REASON, MARGIN_CODE)
    step(runtime, record, "margin_checked", margin)
    refused = adapter.before_write(access, record, timer_end - runtime.monotonic(), device)
    if refused is not None:
        step(runtime, record, "change_not_written", refused)
        return settle(runtime, access, record, plan, "no time left to write", timer_end)
    step(runtime, record, "change_start")
    try:
        _guarded_write(adapter, access, plan["commands"], spec, deadline.left)
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
        off, met = _observe(runtime, deadline, access, action, port, lambda state: _off(action, state, xe=device.platform == "iosxe"), OFF_WAIT_SECONDS)
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
        _guarded_write(adapter, access, plan["inverse"], spec, deadline.left)
        step(runtime, record, "%s_enable_applied" % prefix)
    except Exception as exc:
        step(runtime, record, "%s_enable_failed" % prefix, "%s after %d lines"
             % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "change failed", timer_end)
    try:
        returned = engine.verify(plan, deadline.read(access, lambda target: target.snapshot()).encode("utf-8"),
                                 expect="before")
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
                            lambda state: _on(action, before, state, xe=device.platform == "iosxe") and _back(action, before, state), on_wait(action))
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan,
                      TIME_LIMIT if deadline.left() <= 0 else "check identity unavailable", timer_end)
    record["cycle"]["after"] = on
    if not _on(action, before, on, xe=device.platform == "iosxe"):
        step(runtime, record, "check_identity_failed", "not on: %s" % _shown(on))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    failure = None
    if not back:
        failure = LINK_NOT_BACK if action == BOUNCE else PD_NOT_BACK
        record["cycle"]["return_failure"] = failure
    step(runtime, record, "%s_on_observed" % prefix, _shown(on) if back else "%s, %s" % (_shown(on), failure))
    if deadline.left() <= 0:
        return settle(runtime, access, record, plan, failure or TIME_LIMIT, timer_end)
    step(runtime, record, "confirm_start")
    if not adapter.remove_safeguard(access, record, spec):
        step(runtime, record, "confirm_unverified")
        return settle(runtime, access, record, plan, failure or "confirmation unverified", timer_end)
    step(runtime, record, "safeguard_confirmed")
    try:
        removed = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "removal_check_failed", type(exc).__name__)
        return finish(runtime, record, "unknown", failure or "final check unavailable")
    if removed["result"] != "match":
        step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        return finish(runtime, record, "unknown", failure or "foreign change after the safeguard was removed",
                      removed["differences"])
    return finish(runtime, record, _result(record, failure), failure)
