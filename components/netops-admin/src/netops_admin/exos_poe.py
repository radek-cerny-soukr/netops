"""PoE and data port cycles on one ExtremeXOS port.

The cycle runs as one journaled operation through the same admission as apply (target, enrollment, budgets,
blocking, audit log, notification) and behind the same timed UPM safeguard; its plan is a plan of the
action-only table inline-power, so recover and the safeguard settle it like any other EXOS change.

Variant: disable/enable, not reset inline-power. Measured on X435-8P-4S and X440-G2-12p-10G4
(33.7.1.6-patch1-11): reset is silent (empty output, rc 0) on a port without PoE, leaves no trace in the
configuration and its off time varied from 3 s to 40 s, so neither the refusal nor the cycle itself is
observable. disable/enable refuses a port without PoE with an error, shows each step in show configuration
(module poe) and in show inline-power info detail, and its inverse is the safeguard line.
"""
from __future__ import annotations

import json

from netops_admin import audit_gate, engine, execute, exec_exos, fortios, prediction
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

ACTION = "poe-cycle"
TABLE = "inline-power"
BOUNCE = "port-bounce"
BOUNCE_HOLD_SECONDS = 5
BOUNCE_WAIT_SECONDS = 10
# measured: searching for about 1 s after disable, then disabled
OFF_WAIT_SECONDS = 15
# measured: searching again 3-4 s after enable; a powered device (delivering) is not measured, so the wait
# covers the longest measured off time of reset (about 40 s) with a margin
ON_WAIT_SECONDS = 60
POLL_SECONDS = 2
DELIVERING = "delivering"
PD_NOT_BACK = "powered device not delivering after the cycle"
# Time budget of one cycle from the margin check before the disable until the safeguard is removed. Measured in
# verification (ops.log, ssh exec from the Admin host, 1 s resolution): a show command took at most 2 s, show
# configuration at most 4 s. An interactive write (login and one line) was not timed on its own; it is budgeted
# as two reads. The waits are the pauses of _observe; every read of a wait comes on top of its pauses.
READ_SECONDS = 2
SNAPSHOT_SECONDS = 4
WRITE_SECONDS = 2 * READ_SECONDS


def _wait_reads(seconds) -> int:
    """Reads of one _observe wait that runs out: one at the start and one after every pause."""
    return 1 + -(-seconds // POLL_SECONDS)


# disable, enable and the safeguard removal; show configuration after the disable and after the enable;
# the off wait and the on wait with all their reads (15 + 9 x 2 and 60 + 31 x 2): 175 s
CYCLE_SECONDS = (3 * WRITE_SECONDS + 2 * SNAPSHOT_SECONDS
                 + OFF_WAIT_SECONDS + _wait_reads(OFF_WAIT_SECONDS) * READ_SECONDS
                 + ON_WAIT_SECONDS + _wait_reads(ON_WAIT_SECONDS) * READ_SECONDS)
BOUNCE_SECONDS = (3 * WRITE_SECONDS + 2 * SNAPSHOT_SECONDS + BOUNCE_HOLD_SECONDS
                  + 2 * (BOUNCE_WAIT_SECONDS + _wait_reads(BOUNCE_WAIT_SECONDS) * READ_SECONDS))
MARGIN_CODE = "safeguard_margin_insufficient"
MARGIN_REASON = "safeguard margin insufficient"
CYCLE_CONFIRMED = "cycle confirmed before the interruption; safeguard removed by recover"
CYCLE_NOT_PROVEN = "interrupted; PoE cycle not proven"


def request(device: str, port: str, reason: str, user_request: str, request_id: str,
            *, action=ACTION, endpoint_impact=None):
    body = {"device": device, "table": BOUNCE if action == BOUNCE else TABLE, "op": "update", "key": str(port),
            "changes": {"admin-state": "disabled"}, "reason": reason, "user_request": user_request,
            "request_id": request_id}
    if endpoint_impact is not None:
        body["endpoint_impact"] = endpoint_impact
    return parse_request(json.dumps(body).encode("utf-8"))


def _admissible(runtime, device_name, action):
    """Platform and safeguard margin of the target, from the configuration only: no device read or write."""
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform != "exos":
        raise Rejected(["this cycle operation is for ExtremeXOS switches"], reason_codes=["action_unsupported"])
    if device is not None:
        _margin(device, action)


def _budget(action):
    return BOUNCE_SECONDS if action == BOUNCE else CYCLE_SECONDS


def required_safeguard_seconds(device, action=ACTION) -> int:
    """The smallest safeguard_seconds that leaves the confirm margin after a whole cycle."""
    return _budget(action) + device.confirm_margin_seconds + 1


def _margin_refusal(device, action):
    available = device.safeguard_seconds
    seconds = _budget(action)
    return Rejected(["%s can take up to %d s and needs confirm_margin_seconds %d s on top, but the safeguard gives only %d s; set "
                     "safeguard_seconds of device %s to at least %d"
                     % (action, seconds, device.confirm_margin_seconds, available,
                        device.name, required_safeguard_seconds(device, action))],
                    reason_codes=["safeguard_margin_insufficient"],
                    reason_details=[{"code": MARGIN_CODE, "cycle_seconds": seconds,
                                     "confirm_margin_seconds": device.confirm_margin_seconds,
                                     "available_seconds": available,
                                     "required_safeguard_seconds": required_safeguard_seconds(device, action)}])


def _margin(device, action) -> None:
    """Before any write: the whole cycle plus the confirm margin must fit inside the safeguard."""
    if required_safeguard_seconds(device, action) > device.safeguard_seconds:
        raise _margin_refusal(device, action)


def preview(runtime, device_name: str, cycle_request, *, action=ACTION) -> dict:
    """Every check of the cycle against the device, without any change."""
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
        enable = "enable ports" if action == BOUNCE else "enable inline-power ports"
        result = dict(result, operation=action, cycle_commands=[*result["commands"], f"{enable} {result['key']}"])
        if action == BOUNCE:
            result["hold_seconds"] = BOUNCE_HOLD_SECONDS
    return result


def apply(runtime, device_name: str, cycle_request, *, action=ACTION, expected_plan_sha256=None,
          require_preview=False) -> dict:
    try:
        _admissible(runtime, device_name, action)
        if (require_preview or action == BOUNCE) and expected_plan_sha256 is None:
            raise Rejected(["ExtremeXOS cycle apply requires the approved preview's plan_sha256"],
                           reason_codes=["plan_changed"])
        expected_plan = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device_name, cycle_request, action=action, expected_plan=expected_plan)


def _read_state(access, port, action):
    if action == BOUNCE:
        state = exec_exos.data_admin_state(access, port)
        return {"configured": state, "state": state}
    return exec_exos.poe_state(access, port, check=True)


def _observe(runtime, access, port, wanted, seconds, action):
    """Poll the check account until wanted(state) holds; return (state, met). A read error ends the wait."""
    waited, last = 0.0, None
    while True:
        last = _read_state(access, port, action)
        if wanted(last):
            return last, True
        if waited >= seconds:
            return last, False
        pause = min(POLL_SECONDS, seconds - waited)
        runtime.sleep(pause)
        waited += pause


def _shown(state) -> dict:
    return {name: state[name] for name in ("configured", "state", "class", "power", "fault") if name in (state or {})}


def _refused(runtime, adapter, access, record, spec, reason, code, *, plan=None) -> dict:
    """Remove the safeguard before refusing a cycle that never touched the port."""
    cleaned = adapter.remove_safeguard(access, record, spec)
    execute._step(runtime, record, "safeguard_removed" if cleaned else "safeguard_removal_unverified")
    if not cleaned:
        return execute._finish(runtime, record, "unknown", "safeguard cleanup unverified")
    if plan is not None:
        try:
            returned = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
        except Exception:
            return execute._finish(runtime, record, "unknown", "final check unavailable")
        if returned["result"] != "match":
            return execute._finish(runtime, record, "unknown", "foreign change after the safeguard was removed",
                                   returned["differences"])
    if not execute._persist(runtime, adapter, access, record):
        return execute._finish(runtime, record, "rejected", "not persisted", reason_code=code)
    return execute._finish(runtime, record, "rejected", reason, reason_code=code)


def run(runtime, adapter, access, record, plan, device, due) -> dict:
    step, finish, settle = execute._step, execute._finish, execute._settle_after_expiry
    spec, port = execute._spec(record), plan["key"]
    action = record["kind"]
    bounce = action == BOUNCE
    prefix = "port" if bounce else "poe"
    budget = _budget(action)
    try:
        before = _read_state(access, port, action)
    except Exception as exc:
        step(runtime, record, prefix + "_state_unreadable", type(exc).__name__)
        return _refused(runtime, adapter, access, record, spec, "check identity unavailable",
                        "port_usage_unreadable" if bounce else "poe_state_unreadable", plan=plan)
    if before["configured"] != "enabled":
        return _refused(runtime, adapter, access, record, spec, "state changed before cycle",
                        "port_disabled" if bounce else "poe_disabled", plan=plan)
    record[prefix] = {"before": _shown(before)}
    step(runtime, record, prefix + "_before", before["state"])
    try:
        remaining = (execute._fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception as exc:
        step(runtime, record, "clock_unreadable", type(exc).__name__)
        return _refused(runtime, adapter, access, record, spec, "device clock", "device_clock_unreadable", plan=plan)
    margin = "%d s left, %d s cycle, %d s margin" % (remaining, budget, device.confirm_margin_seconds)
    if budget + device.confirm_margin_seconds >= remaining:
        step(runtime, record, "cycle_refused", margin)
        return _refused(runtime, adapter, access, record, spec, MARGIN_REASON, MARGIN_CODE, plan=plan)
    step(runtime, record, "margin_checked", margin)
    step(runtime, record, "change_start")
    try:
        access.apply(plan["commands"], spec)
        step(runtime, record, "change_applied")
    except Exception as exc:
        step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan, "change failed", due)
    cause = "administrator table"
    try:
        off_text = access.snapshot()
        if adapter.accounts_check(access, device, off_text) != record["accounts"]:
            raise Rejected(["the administrator accounts changed during the operation"])
        cause = "postcheck rejected"
        verdict = engine.verify(plan, off_text.encode("utf-8"), expect="after")
    except Rejected as exc:
        cause = getattr(exc, "category", cause)
        step(runtime, record, "postcheck_failed", cause)
        return settle(runtime, access, record, plan, cause, due)
    except Exception as exc:
        step(runtime, record, "postcheck_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "postcheck unavailable", due)
    if verdict["result"] != "match":
        step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", due)
    step(runtime, record, "postcheck_passed")
    try:
        policy = record.get("audit_policy")
        audited = prediction.audited(off_text, plan)
        record["audit_coverage"] = audit_gate.evaluate(device.platform, audited, policy, plan["table"], record["audit_before"])
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
        off, met = _observe(runtime, access, port,
                            lambda state: state["configured"] == "disabled" and state["state"] == "disabled",
                            BOUNCE_WAIT_SECONDS if bounce else OFF_WAIT_SECONDS, action)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", due)
    record[prefix]["off"] = _shown(off)
    if not met:
        step(runtime, record, "check_identity_failed", "power not off: %s/%s" % (off["configured"], off["state"]))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    step(runtime, record, prefix + "_off_observed")
    if bounce:
        runtime.sleep(BOUNCE_HOLD_SECONDS)
    step(runtime, record, prefix + "_enable_start")
    try:
        access.apply(plan["inverse"], spec)
        step(runtime, record, prefix + "_enable_applied")
    except Exception as exc:
        step(runtime, record, prefix + "_enable_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan, "change failed", due)
    try:
        on_text = access.snapshot()
        returned = engine.verify(plan, on_text.encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, prefix + "_enable_check_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "postcheck unavailable", due)
    if returned["result"] != "match":
        step(runtime, record, prefix + "_enable_check_failed", "%d differences" % len(returned["differences"]))
        record["postcheck_differences"] = returned["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", due)
    step(runtime, record, prefix + "_enable_verified")
    delivering = before["state"] == DELIVERING

    def powered(state):
        return (state["configured"] == "enabled" and state["state"] != "disabled"
                and (not delivering or state["state"] == DELIVERING))

    try:
        on, met = _observe(runtime, access, port, powered, BOUNCE_WAIT_SECONDS if bounce else ON_WAIT_SECONDS, action)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", due)
    record[prefix]["after"] = _shown(on)
    if on["configured"] != "enabled" or on["state"] == "disabled":
        step(runtime, record, "check_identity_failed", "power not on: %s/%s" % (on["configured"], on["state"]))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    pd_back = met
    step(runtime, record, prefix + "_on_observed", on["state"] if pd_back else "%s, powered device not back" % on["state"])
    step(runtime, record, "confirm_start")
    if not adapter.remove_safeguard(access, record, spec):
        step(runtime, record, "confirm_unverified")
        return settle(runtime, access, record, plan, "confirmation unverified", due)
    try:
        text = access.snapshot().encode("utf-8")
        removed = engine.verify(plan, text, expect="before")
    except Exception as exc:
        step(runtime, record, "removal_check_failed", type(exc).__name__)
        return finish(runtime, record, "unknown", "final check unavailable")
    if removed["result"] != "match":
        step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        return finish(runtime, record, "unknown", "foreign change after the safeguard was removed", removed["differences"])
    if not execute._persist(runtime, adapter, access, record):
        return finish(runtime, record, "confirmed", "not persisted")
    if record["steps"][-1]["step"] == "configuration_saved":
        try:
            saved = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
        except Exception as exc:
            step(runtime, record, "saved_check_failed", type(exc).__name__)
            return finish(runtime, record, "confirmed", "saved configuration unverified")
        if saved["result"] != "match":
            step(runtime, record, "saved_check_failed", "%d differences" % len(saved["differences"]))
            return finish(runtime, record, "confirmed", "foreign change during save", saved["differences"])
    return finish(runtime, record, "confirmed", None if pd_back else PD_NOT_BACK)


def _journal_proves_cycle(record) -> bool:
    """The journal shows power off, the verified enable and power on again, in that order, before confirm_start."""
    names = [step.get("step") for step in record.get("steps", [])]
    prefix = "port" if record.get("kind") == BOUNCE else "poe"
    order = tuple(prefix + tail for tail in ("_off_observed", "_enable_verified", "_on_observed")) + ("confirm_start",)
    if not all(name in names for name in order):
        return False
    places = [names.index(name) for name in order]
    poe = record.get(prefix) or {}
    off, after = poe.get("off") or {}, poe.get("after") or {}
    return (places == sorted(places) and (off.get("configured"), off.get("state")) == ("disabled", "disabled")
            and after.get("configured") == "enabled" and after.get("state") not in (None, "disabled"))


def recover_installed(runtime, adapter, access, record, plan, device) -> dict:
    """Recover a cycle interrupted after confirm_start while its safeguard is still installed.

    The cycle counts as done only on proof: the journal holds off -> on (see _journal_proves_cycle) and a fresh
    read shows the configuration equal to before and the check account sees inline power configured enabled and
    not disabled. Then the safeguard is removed and the result is confirmed. Without that proof the safeguard
    restores power as for any interrupted change and the result says the cycle was not proven.
    """
    step, finish, spec = execute._step, execute._finish, execute._spec(record)
    due = runtime.monotonic() + device.safeguard_seconds
    bounce = record["kind"] == BOUNCE
    prefix = "port" if bounce else "poe"

    def unproven(detail):
        step(runtime, record, "cycle_unproven", detail)
        return execute._settle_after_expiry(runtime, access, record, plan,
                                            "interrupted; port bounce not proven" if bounce else CYCLE_NOT_PROVEN, due)

    if not _journal_proves_cycle(record):
        return unproven("the journal does not show power off and on again")
    try:
        state = _read_state(access, plan["key"], record["kind"])
        text = access.snapshot().encode("utf-8")
        configuration = engine.verify(plan, text, expect="before")
    except Exception as exc:
        return unproven("fresh read failed: %s" % type(exc).__name__)
    record[prefix]["recovered"] = _shown(state)
    if state["configured"] != "enabled" or state["state"] == "disabled":
        return unproven("power not on: %s/%s" % (state["configured"], state["state"]))
    if configuration["result"] != "match":
        return unproven("configuration differs from before (%d differences)" % len(configuration["differences"]))
    step(runtime, record, "cycle_proven", state["state"])
    if not adapter.remove_safeguard(access, record, spec):
        step(runtime, record, "safeguard_removal_unverified")
        return finish(runtime, record, "unknown", "safeguard cleanup unverified")
    step(runtime, record, "safeguard_removed")
    try:
        removed = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "removal_check_failed", type(exc).__name__)
        return finish(runtime, record, "unknown", "final check unavailable")
    if removed["result"] != "match":
        step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        return finish(runtime, record, "unknown", "foreign change after the safeguard was removed", removed["differences"])
    if not execute._persist(runtime, adapter, access, record):
        return finish(runtime, record, "confirmed", "not persisted")
    pd_back = (record[prefix].get("before") or {}).get("state") != DELIVERING or state["state"] == DELIVERING
    return finish(runtime, record, "confirmed", CYCLE_CONFIRMED if pd_back else PD_NOT_BACK)
