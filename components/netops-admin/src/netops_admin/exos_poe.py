"""PoE cycle of one ExtremeXOS port: disable inline-power ports N, then enable inline-power ports N.

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
# measured: searching for about 1 s after disable, then disabled
OFF_WAIT_SECONDS = 15
# measured: searching again 3-4 s after enable; a powered device (delivering) is not measured, so the wait
# covers the longest measured off time of reset (about 40 s) with a margin
ON_WAIT_SECONDS = 60
POLL_SECONDS = 2
DELIVERING = "delivering"
PD_NOT_BACK = "powered device not delivering after the cycle"


def request(device: str, port: str, reason: str, user_request: str, request_id: str):
    body = {"device": device, "table": TABLE, "op": "update", "key": str(port),
            "changes": {"admin-state": "disabled"}, "reason": reason, "user_request": user_request,
            "request_id": request_id}
    return parse_request(json.dumps(body).encode("utf-8"))


def _platform(runtime, device_name):
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform != "exos":
        raise Rejected(["the PoE cycle exists only for ExtremeXOS switches"], reason_codes=["action_unsupported"])


def preview(runtime, device_name: str, cycle_request) -> dict:
    """Every check of the cycle against the device, without any change."""
    try:
        _platform(runtime, device_name)
        result, refused = execute._preview(runtime, device_name, cycle_request, action=ACTION)
    except Rejected as exc:
        if not isinstance(exc, execute.BudgetExhausted):
            execute._count_rejection(runtime)
        raise
    if refused:
        execute._count_rejection(runtime)
    if result.get("result") in ("ready", "rejected") and "commands" in result:
        result = dict(result, operation=ACTION,
                      cycle_commands=list(result["commands"]) + ["enable inline-power ports %s" % result["key"]])
    return result


def apply(runtime, device_name: str, cycle_request) -> dict:
    try:
        _platform(runtime, device_name)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device_name, cycle_request, action=ACTION)


def _observe(runtime, access, port, wanted, seconds):
    """Poll the check account until wanted(state) holds; return (state, met). A read error ends the wait."""
    waited, last = 0.0, None
    while True:
        last = exec_exos.poe_state(access, port, check=True)
        if wanted(last):
            return last, True
        if waited >= seconds:
            return last, False
        pause = min(POLL_SECONDS, seconds - waited)
        runtime.sleep(pause)
        waited += pause


def _shown(state) -> dict:
    return {name: state[name] for name in ("configured", "state", "class", "power", "fault") if name in (state or {})}


def run(runtime, adapter, access, record, plan, device, due) -> dict:
    step, finish, settle = execute._step, execute._finish, execute._settle_after_expiry
    spec, port = execute._spec(record), plan["key"]
    try:
        before = exec_exos.poe_state(access, port, check=True)
    except Exception as exc:
        step(runtime, record, "poe_state_unreadable", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", due)
    record["poe"] = {"before": _shown(before)}
    step(runtime, record, "poe_before", before["state"])
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
                            OFF_WAIT_SECONDS)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", due)
    record["poe"]["off"] = _shown(off)
    if not met:
        step(runtime, record, "check_identity_failed", "power not off: %s/%s" % (off["configured"], off["state"]))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    step(runtime, record, "poe_off_observed")
    step(runtime, record, "poe_enable_start")
    try:
        access.apply(plan["inverse"], spec)
        step(runtime, record, "poe_enable_applied")
    except Exception as exc:
        step(runtime, record, "poe_enable_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return settle(runtime, access, record, plan, "change failed", due)
    try:
        on_text = access.snapshot()
        returned = engine.verify(plan, on_text.encode("utf-8"), expect="before")
    except Exception as exc:
        step(runtime, record, "poe_enable_check_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "postcheck unavailable", due)
    if returned["result"] != "match":
        step(runtime, record, "poe_enable_check_failed", "%d differences" % len(returned["differences"]))
        record["postcheck_differences"] = returned["differences"]
        return settle(runtime, access, record, plan, "prediction mismatch", due)
    step(runtime, record, "poe_enable_verified")
    delivering = before["state"] == DELIVERING

    def powered(state):
        return (state["configured"] == "enabled" and state["state"] != "disabled"
                and (not delivering or state["state"] == DELIVERING))

    try:
        on, met = _observe(runtime, access, port, powered, ON_WAIT_SECONDS)
    except Exception as exc:
        step(runtime, record, "check_identity_failed", type(exc).__name__)
        return settle(runtime, access, record, plan, "check identity unavailable", due)
    record["poe"]["after"] = _shown(on)
    if on["configured"] != "enabled" or on["state"] == "disabled":
        step(runtime, record, "check_identity_failed", "power not on: %s/%s" % (on["configured"], on["state"]))
        return settle(runtime, access, record, plan, "check identity mismatch", due)
    pd_back = met
    step(runtime, record, "poe_on_observed", on["state"] if pd_back else "%s, powered device not back" % on["state"])
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
