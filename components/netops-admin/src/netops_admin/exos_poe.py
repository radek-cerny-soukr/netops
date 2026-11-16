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
# Time budget of one cycle from the margin check before the disable until the safeguard is removed. Measured in
# task 171 (ops.log, ssh exec from the Admin host, 1 s resolution): a show command took at most 2 s, show
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
MARGIN_CODE = "safeguard_margin_insufficient"
MARGIN_REASON = "safeguard margin insufficient"
CYCLE_CONFIRMED = "cycle confirmed before the interruption; safeguard removed by recover"
CYCLE_NOT_PROVEN = "interrupted; PoE cycle not proven"


def request(device: str, port: str, reason: str, user_request: str, request_id: str):
    body = {"device": device, "table": TABLE, "op": "update", "key": str(port),
            "changes": {"admin-state": "disabled"}, "reason": reason, "user_request": user_request,
            "request_id": request_id}
    return parse_request(json.dumps(body).encode("utf-8"))


def _admissible(runtime, device_name):
    """Platform and safeguard margin of the target, from the configuration only: no device read or write."""
    device = runtime.config.devices.get(device_name)
    if device is not None and device.platform != "exos":
        raise Rejected(["the PoE cycle exists only for ExtremeXOS switches"], reason_codes=["action_unsupported"])
    if device is not None:
        _margin(device)


def required_safeguard_seconds(device) -> int:
    """The smallest safeguard_seconds that leaves the confirm margin after a whole cycle."""
    return CYCLE_SECONDS + device.confirm_margin_seconds + 1


def _margin_refusal(device):
    available = device.safeguard_seconds
    return Rejected(["the PoE cycle can take up to %d s (disable, %d s off wait, enable, %d s on wait and the "
                     "read-backs) and needs confirm_margin_seconds %d s on top, but the safeguard gives only %d s; set "
                     "safeguard_seconds of device %s to at least %d"
                     % (CYCLE_SECONDS, OFF_WAIT_SECONDS, ON_WAIT_SECONDS, device.confirm_margin_seconds, available,
                        device.name, required_safeguard_seconds(device))],
                    reason_codes=["safeguard_margin_insufficient"],
                    reason_details=[{"code": MARGIN_CODE, "cycle_seconds": CYCLE_SECONDS,
                                     "confirm_margin_seconds": device.confirm_margin_seconds,
                                     "available_seconds": available,
                                     "required_safeguard_seconds": required_safeguard_seconds(device)}])


def _margin(device) -> None:
    """Before any write: the whole cycle plus the confirm margin must fit inside the safeguard."""
    if CYCLE_SECONDS + device.confirm_margin_seconds >= device.safeguard_seconds:
        raise _margin_refusal(device)


def preview(runtime, device_name: str, cycle_request) -> dict:
    """Every check of the cycle against the device, without any change."""
    try:
        _admissible(runtime, device_name)
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
        _admissible(runtime, device_name)
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


def _refused(runtime, adapter, access, record, spec, reason, code) -> dict:
    """Refuse the cycle before the disable: remove the installed safeguard; power was never touched."""
    cleaned = adapter.remove_safeguard(access, record, spec)
    execute._step(runtime, record, "safeguard_removed" if cleaned else "safeguard_removal_unverified")
    if not cleaned:
        return execute._finish(runtime, record, "unknown", "safeguard cleanup unverified")
    if not execute._persist(runtime, adapter, access, record):
        return execute._finish(runtime, record, "rejected", "not persisted", reason_code=code)
    return execute._finish(runtime, record, "rejected", reason, reason_code=code)


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
    try:
        remaining = (execute._fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception as exc:
        step(runtime, record, "clock_unreadable", type(exc).__name__)
        return _refused(runtime, adapter, access, record, spec, "device clock", "device_clock_unreadable")
    margin = "%d s left, %d s cycle, %d s margin" % (remaining, CYCLE_SECONDS, device.confirm_margin_seconds)
    if CYCLE_SECONDS + device.confirm_margin_seconds >= remaining:
        step(runtime, record, "cycle_refused", margin)
        return _refused(runtime, adapter, access, record, spec, MARGIN_REASON, MARGIN_CODE)
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


def _journal_proves_cycle(record) -> bool:
    """The journal shows power off, the verified enable and power on again, in that order, before confirm_start."""
    names = [step.get("step") for step in record.get("steps", [])]
    order = ("poe_off_observed", "poe_enable_verified", "poe_on_observed", "confirm_start")
    if not all(name in names for name in order):
        return False
    places = [names.index(name) for name in order]
    poe = record.get("poe") or {}
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

    def unproven(detail):
        step(runtime, record, "cycle_unproven", detail)
        return execute._settle_after_expiry(runtime, access, record, plan, CYCLE_NOT_PROVEN, due)

    if not _journal_proves_cycle(record):
        return unproven("the journal does not show power off and on again")
    try:
        state = exec_exos.poe_state(access, plan["key"], check=True)
        text = access.snapshot().encode("utf-8")
        configuration = engine.verify(plan, text, expect="before")
    except Exception as exc:
        return unproven("fresh read failed: %s" % type(exc).__name__)
    record["poe"]["recovered"] = _shown(state)
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
    pd_back = (record["poe"].get("before") or {}).get("state") != DELIVERING or state["state"] == DELIVERING
    return finish(runtime, record, "confirmed", CYCLE_CONFIRMED if pd_back else PD_NOT_BACK)
