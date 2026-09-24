from __future__ import annotations

import datetime
import json
import secrets
import time

from netops_admin import audit, audit_gate, engine, exec_exos, exec_fortios, prediction, enrollment
from netops_admin.errors import BudgetExhausted, Rejected
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request
from netops_admin.state import Store

EXPIRY_GRACE_SECONDS = 20
EXPIRY_POLL_SECONDS = 10
EXPIRY_WAIT_LIMIT_SECONDS = 600
BLOCKING_RESULTS = ("unknown", "revert-failed")
UNDELIVERED = ("pending", "failed")
BLOCKING_REASONS = ("administrator table", "foreign change", "not persisted")
ADAPTERS = {"fortios": exec_fortios, "exos": exec_exos}
FIRE_AT_FORMAT = "%Y-%m-%d %H:%M:%S"
HOUR = 3600
ANY_STATE = object()
DAY = 86400


class Runtime:
    def __init__(self, config, access_factory, notifier=None, sleep=time.sleep):
        self.config = config
        self.access_factory = access_factory
        self.notifier = notifier
        self.sleep = sleep
        self.store = Store(config.state_dir)
        self.audit = audit.AuditLog(config.audit_file)


def _adapter(platform: str):
    return ADAPTERS[platform]


def _spec(record):
    return _adapter(record["plan"]["platform"]).prompt_spec(record["hostname"])


def _fire_at(record) -> datetime.datetime:
    return datetime.datetime.strptime(record["safeguard"]["fire_at"], FIRE_AT_FORMAT)


def _step(runtime, record, name, detail=None):
    record.setdefault("steps", []).append({"step": name, "at": audit.now_utc(), "detail": detail})
    runtime.store.save(record)
    runtime.audit.event("step", change_id=record["change_id"], device=record["device"], step=name, detail=detail)


def _finish(runtime, record, result, reason=None, differences=None):
    record["status"] = "finished"
    record["finished_at_epoch"] = time.time()
    record["result"] = result
    record["reason"] = reason
    record["differences"] = differences or []
    state, _why = audit.export_state(runtime.config.export_status_file, runtime.config.limits)
    record["audit_delivery"] = "pending" if state in ("acknowledged", "pending") else state
    record["notification"] = "pending" if runtime.notifier is not None else "not-configured"
    if result in BLOCKING_RESULTS or reason in BLOCKING_REASONS:
        runtime.store.block(record["device"], record["change_id"], reason or result)
    runtime.store.save(record)
    runtime.audit.event(
        "result", change_id=record["change_id"], request_id=record["request_id"], device=record["device"],
        status="finished", result=result, reason=reason, differences=len(record["differences"]),
        notification=record["notification"], audit_delivery=record["audit_delivery"],
        safeguard=record.get("safeguard", {}).get("fire_at"),
    )
    if runtime.notifier is not None:
        _deliver_notification(runtime, record)
    return record


def _deliver_notification(runtime, record) -> None:
    try:
        result = runtime.notifier(record)
    except Exception:
        result = "failed"
    record["notification"] = result if result in ("sent", "failed") else "failed"
    runtime.store.save(record)
    runtime.audit.event("delivery", change_id=record["change_id"], device=record["device"],
                        notification=record["notification"], audit_delivery=record.get("audit_delivery"))


def notify_retry(runtime, change_id: str) -> dict:
    record = runtime.store.operation(change_id)
    if record is None or record.get("status") != "finished":
        raise Rejected(["no finished operation matches"])
    if runtime.notifier is None:
        raise Rejected(["notification is not configured"])
    if record.get("notification") != "sent":
        _deliver_notification(runtime, record)
    return record


def refresh_delivery(runtime, record) -> dict:
    if record.get("status") != "finished" or record.get("audit_delivery") != "pending":
        return record
    state, _why = audit.export_state(runtime.config.export_status_file, runtime.config.limits)
    status_time = audit.export_updated_at(runtime.config.export_status_file)
    finished_at = record.get("finished_at_epoch")
    if state == "acknowledged" and status_time is not None and finished_at is not None and status_time > finished_at:
        record["audit_delivery"] = "acknowledged"
        runtime.store.save(record)
        runtime.audit.event("delivery", change_id=record["change_id"], device=record["device"],
                            notification=record.get("notification"), audit_delivery="acknowledged")
    return record


def _wait_for_expiry(runtime, adapter, access, fire_at: datetime.datetime) -> None:
    waited = 0
    while waited <= EXPIRY_WAIT_LIMIT_SECONDS:
        now = adapter.clock(access)
        remaining = (fire_at - now).total_seconds() + EXPIRY_GRACE_SECONDS
        if remaining <= 0:
            return
        pause = min(max(remaining, 1), EXPIRY_POLL_SECONDS)
        runtime.sleep(pause)
        waited += pause
    raise Rejected(["the safeguard did not expire within the wait limit"])


def _persist(runtime, adapter, access, record) -> bool:
    try:
        saved = adapter.persist(access, _spec(record))
    except Exception as exc:
        _step(runtime, record, "persist_failed", type(exc).__name__)
        return False
    if saved:
        _step(runtime, record, "configuration_saved")
    return True


def _settle_after_expiry(runtime, access, record, plan, reason):
    adapter = _adapter(plan["platform"])
    try:
        _wait_for_expiry(runtime, adapter, access, _fire_at(record))
        after_expiry = access.snapshot()
        verdict = engine.verify(plan, after_expiry.encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        return _finish(runtime, record, "unknown", reason)
    cleaned = adapter.remove_safeguard(access, record, _spec(record))
    _step(runtime, record, "safeguard_removed" if cleaned else "safeguard_removal_unverified")
    if verdict["result"] == "match":
        if not cleaned:
            return _finish(runtime, record, "unknown", "safeguard cleanup unverified")
        if not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        kept = reason if reason in BLOCKING_REASONS else "foreign change"
        return _finish(runtime, record, "reverted", kept, verdict["differences"])
    return _finish(runtime, record, "revert-failed", reason, verdict["differences"])


def _undelivered(runtime, device_name: str) -> list:
    return sorted(record["change_id"] for record in runtime.store.records()
                  if record.get("device") == device_name and record.get("status") == "finished"
                  and record.get("notification") in UNDELIVERED)


def _block_accounts(runtime, device) -> None:
    runtime.store.block(device.name, None, "administrator table")
    runtime.audit.event("administrative", device=device.name, action="blocked: administrator table",
                        reason_characters=0, change_id=None)


def _budgets(runtime, device) -> None:
    limits, now = runtime.config.limits, time.time()
    if runtime.store.rejections_since(now - HOUR) >= limits["rejections_per_hour"]:
        raise BudgetExhausted(["the budget of rejected requests for this hour is exhausted"])
    records = runtime.store.records()
    if len(records) >= limits["journal_records"]:
        raise BudgetExhausted(["the journal holds its maximum number of operations; archive it before new changes"])
    started = [record.get("created_at_epoch") or 0 for record in records if "safeguard" in record]
    mine = [record.get("created_at_epoch") or 0 for record in records
            if "safeguard" in record and record.get("device") == device.name]
    if sum(1 for moment in mine if moment >= now - HOUR) >= limits["changes_per_device_per_hour"]:
        raise BudgetExhausted(["the budget of changes on this device for this hour is exhausted"])
    if sum(1 for moment in started if moment >= now - DAY) >= limits["changes_per_day"]:
        raise BudgetExhausted(["the budget of changes for this day is exhausted"])


def apply(runtime, device_name: str, request, expected_before=ANY_STATE) -> dict:
    try:
        return _apply(runtime, device_name, request, expected_before)
    except BudgetExhausted:
        raise
    except Rejected:
        try:
            runtime.store.note_rejection(time.time())
        except OSError:
            pass
        raise


def preview(runtime, device_name: str, request) -> dict:
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %r is not configured" % device_name])
    adapter = _adapter(device.platform)
    with runtime.store.lock(device.name):
        known = runtime.store.request(request.request_id)
        if known is not None:
            return {"result": "known-request", "device": device.name, "change_id": known["change_id"],
                    "reasons": ["request_id already started an operation; apply returns it without running again"]}
        missing = []
        try:
            prepared = _prepared(runtime, device, adapter, request, ANY_STATE, False, missing)
        except Rejected as exc:
            return {"result": "rejected", "device": device.name, "reasons": list(exc.reasons)}
    plan, audit_before, coverage = prepared[4], prepared[5], prepared[7]
    return {
        "result": "rejected" if missing else "ready",
        "reasons": missing,
        "device": device.name,
        "platform": plan["platform"],
        "firmware": plan["firmware"],
        "table": plan["table"],
        "op": plan["op"],
        "key": plan["key"],
        "predicted": plan["predicted"],
        "commands": list(plan["commands"]),
        "inverse_commands": len(plan["inverse"]),
        "prechecks": list(plan["prechecks"]),
        "rollback_evidence": plan["rollback_evidence"],
        "plan_sha256": plan["plan_sha256"],
        "audit_findings_before": len(audit_before),
        "audit_coverage": coverage,
        "safeguard_seconds": device.safeguard_seconds,
    }


def _prepared(runtime, device, adapter, request, expected_before, enrolling, missing=None):
    config = runtime.config
    _budgets(runtime, device)
    blocked = runtime.store.blocked(device.name)
    if blocked is not None:
        raise Rejected(["the device is blocked (%s, operation %s); a person must investigate and unblock it"
                        % (blocked.get("reason"), blocked.get("change_id") or "none")])
    undelivered = _undelivered(runtime, device.name)
    if undelivered:
        raise Rejected(["the notification of operation %s was not delivered; run notify-retry, or a person"
                        " unblocks the device after checking the notification channel" % undelivered[0]])
    if runtime.store.running(device.name):
        raise Rejected(["an unfinished operation exists on this device; run recover first"])
    runtime.store.check_writable()
    runtime.audit.check_writable()
    export, why = audit.export_state(config.export_status_file, config.limits)
    if export == "blocked":
        raise Rejected(["audit export is blocked: %s" % why])
    try:
        access = runtime.access_factory(device)
        before_text = access.snapshot()
        try:
            accounts = adapter.accounts_check(access, device, before_text)
            known = runtime.store.baseline(device.name)
            if known is not None and known != accounts:
                raise Rejected(["the administrator accounts changed since the last operation"])
        except Rejected:
            if missing is None:
                _block_accounts(runtime, device)
            raise
        leftovers = adapter.leftovers(access)
        if leftovers:
            raise Rejected(["a safeguard of an earlier operation is still installed: %s" % ", ".join(leftovers)])
        hostname = adapter.hostname(access, before_text)
        reasons = adapter.prechecks(access, device, before_text, adapter.prompt_spec(hostname))
        if reasons:
            raise Rejected(reasons)
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected(["the device could not be read before any change: %s" % exc]) from None
    plan = engine.build_plan(device.platform, before_text.encode("utf-8"), request,
                             firmware=device.firmware, protected=device.protected, enrollment_probe=enrolling)
    if missing is not None:
        try:
            enrollment.require(runtime, device, accounts, plan["firmware"])
        except Rejected as exc:
            missing.extend(exc.reasons)
    elif not enrolling:
        enrollment.require(runtime, device, accounts, plan["firmware"])
    elif runtime.notifier is None or export not in ("acknowledged", "pending"):
        raise Rejected(["enrollment requires notification and a healthy configured audit export"])
    if len(plan["commands"]) > config.limits["plan_commands"] or len(plan["inverse"]) > config.limits["plan_commands"]:
        raise Rejected(["the plan holds more than %d commands" % config.limits["plan_commands"]])
    if expected_before is not ANY_STATE and plan["predicted"]["before"] != expected_before:
        raise Rejected(["the object differs from the state the undo was planned against"])
    try:
        policy = device.audit_policy
        audit_before = audit_gate.findings(device.platform, before_text, device.name, policy)
        plan["device"] = device.name
        predicted_text = prediction.snapshot_after(before_text, plan)
        coverage = audit_gate.evaluate(device.platform, predicted_text, policy, plan["table"])
        audit_gate.check_policy(plan, policy, predicted_text)
        predicted_findings = audit_gate.new_blocking(device.platform, audit_before, predicted_text, device.name, policy)
        if predicted_findings:
            raise Rejected(["predicted audit findings: " + ", ".join(predicted_findings)])
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected(["the auditor could not evaluate the snapshot before the change (%s)"
                        % type(exc).__name__]) from None
    try:
        seen = engine.observed_state(plan, adapter.observe(access, plan))
    except Exception as exc:
        raise Rejected(["the check account could not read the object before the change (%s)"
                        % type(exc).__name__]) from None
    if seen != plan["predicted"]["before"]:
        raise Rejected(["the check account sees the object in another state than the snapshot"])
    return access, before_text, accounts, hostname, plan, audit_before, policy, coverage


def _apply(runtime, device_name: str, request, expected_before, enrolling=False) -> dict:
    config = runtime.config
    device = config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %r is not configured" % device_name])
    adapter = _adapter(device.platform)
    fingerprint = request.fingerprint()
    with runtime.store.lock(device.name):
        known = runtime.store.request(request.request_id)
        if known is not None:
            if known["request_sha256"] != fingerprint or known["device"] != device.name:
                raise Rejected(["request_id was already used for a different request"])
            return runtime.store.operation(known["change_id"])
        if enrolling:
            runtime.store.clear_enrollment(device.name)
        access, before_text, accounts, hostname, plan, audit_before, policy, coverage = _prepared(
            runtime, device, adapter, request, expected_before, enrolling)
        profile = find_profile(plan["platform"], plan["table"], plan["firmware"])
        change_id = secrets.token_hex(16)
        plan["safeguard_id"] = change_id
        record = {
            "change_id": change_id, "request_id": request.request_id, "request_sha256": fingerprint,
            "device": device.name, "status": "running", "result": None, "hostname": hostname,
            "plan": plan, "steps": [], "created_at": audit.now_utc(), "created_at_epoch": time.time(),
            "kind": "enrollment" if enrolling else "change",
            "audit_before": audit_before, "audit_policy": policy, "audit_coverage": coverage, "accounts": accounts,
        }
        runtime.store.save(record)
        runtime.store.save_baseline(device.name, accounts)
        runtime.store.remember_request(request.request_id, change_id, fingerprint, device.name)
        runtime.audit.event(
            "start", change_id=change_id, request_id=request.request_id, device=device.name,
            platform=plan["platform"], firmware=plan["firmware"], table=plan["table"], op=plan["op"],
            key=plan["key"], request_sha256=fingerprint, plan_sha256=plan["plan_sha256"],
            snapshot_sha256=plan["snapshot_sha256"], reason_characters=plan["reason_characters"],
            user_request_characters=plan["user_request_characters"],
            changes=audit.summarized_changes(profile, engine.canonical_changes(profile, request)),
            commands=len(plan["commands"]), inverse_commands=len(plan["inverse"]),
            safeguard=adapter.safeguard_label(change_id),
        )
        try:
            record["foreign_sessions"] = adapter.foreign_sessions(access, device)
        except Exception as exc:
            record["foreign_sessions"] = None
            _step(runtime, record, "foreign_sessions_unreadable", type(exc).__name__)
        else:
            _step(runtime, record, "foreign_sessions", "%d other sessions" % record["foreign_sessions"])
        if enrolling:
            try:
                delivered = runtime.notifier(dict(record, result="enrollment-preflight"))
            except Exception:
                delivered = "failed"
            if delivered != "sent":
                return _finish(runtime, record, "rejected", "enrollment notification unavailable")
            _step(runtime, record, "enrollment_notification_verified")
        result = _execute(runtime, adapter, access, record, plan, device)
        return enrollment.complete(runtime, device, access, result) if enrolling else result


def _execute(runtime, adapter, access, record, plan, device) -> dict:
    change_id, spec = record["change_id"], _spec(record)
    try:
        fire_at = adapter.clock(access) + datetime.timedelta(seconds=device.safeguard_seconds)
    except Exception as exc:
        _step(runtime, record, "clock_unreadable", type(exc).__name__)
        return _finish(runtime, record, "rejected", "device clock")
    record["safeguard"] = {"fire_at": fire_at.strftime(FIRE_AT_FORMAT), "name": adapter.safeguard_label(change_id)}
    _step(runtime, record, "safeguard_install")
    try:
        problems = adapter.install_safeguard(access, record, plan, device, spec)
    except Exception as exc:
        problems = ["safeguard installation failed (%s)" % type(exc).__name__]
    if problems:
        _step(runtime, record, "safeguard_not_verified", problems[0])
        cleaned = adapter.remove_safeguard(access, record, spec)
        if cleaned and not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted" if cleaned else "unknown", "safeguard not verified")
    runtime.store.save(record)
    _step(runtime, record, "safeguard_verified")
    _step(runtime, record, "change_start")
    try:
        access.apply(plan["commands"], spec)
        _step(runtime, record, "change_applied")
    except Exception as exc:
        _step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return _settle_after_expiry(runtime, access, record, plan, "change failed")
    try:
        after_text = access.snapshot()
        if adapter.accounts_check(access, device, after_text) != record["accounts"]:
            raise Rejected(["the administrator accounts changed during the operation"])
        verdict = engine.verify(plan, after_text.encode("utf-8"), expect="after")
    except Rejected:
        _step(runtime, record, "postcheck_failed", "administrator table")
        return _settle_after_expiry(runtime, access, record, plan, "administrator table")
    except Exception as exc:
        _step(runtime, record, "postcheck_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "postcheck unavailable")
    if verdict["result"] != "match":
        _step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return _settle_after_expiry(runtime, access, record, plan, "prediction mismatch")
    _step(runtime, record, "postcheck_passed")
    try:
        policy = record.get("audit_policy")
        record["audit_coverage"] = audit_gate.evaluate(device.platform, after_text, policy, plan["table"])
        audit_gate.check_policy(plan, policy, after_text)
        found = audit_gate.new_blocking(device.platform, record["audit_before"], after_text, device.name, policy)
    except Exception as exc:
        _step(runtime, record, "audit_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "audit unavailable")
    if found:
        record["audit_findings"] = found
        _step(runtime, record, "audit_failed", "%d new findings" % len(found))
        return _settle_after_expiry(runtime, access, record, plan, "audit finding")
    _step(runtime, record, "audit_passed", "%d rules, %d findings before, none new"
          % (audit_gate.rule_count(device.platform), len(record["audit_before"])))
    try:
        seen = engine.observed_state(plan, adapter.observe(access, plan))
    except Exception as exc:
        _step(runtime, record, "check_identity_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "check identity unavailable")
    if seen != plan["predicted"]["after"]:
        _step(runtime, record, "check_identity_failed", "state differs")
        return _settle_after_expiry(runtime, access, record, plan, "check identity mismatch")
    _step(runtime, record, "check_identity_passed")
    if record.get("kind") == "enrollment":
        return _settle_after_expiry(runtime, access, record, plan, "enrollment self-test")
    try:
        remaining = (_fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception:
        remaining = -1
    if remaining < device.confirm_margin_seconds:
        _step(runtime, record, "confirm_skipped", "too close to the safeguard")
        return _settle_after_expiry(runtime, access, record, plan, "no time left to confirm")
    _step(runtime, record, "confirm_start")
    if not adapter.remove_safeguard(access, record, spec):
        _step(runtime, record, "confirm_unverified")
        return _settle_after_expiry(runtime, access, record, plan, "confirmation unverified")
    try:
        final = engine.verify(plan, access.snapshot().encode("utf-8"), expect="after")
    except Exception as exc:
        _step(runtime, record, "final_check_failed", type(exc).__name__)
        return _finish(runtime, record, "unknown", "final check unavailable")
    if final["result"] == "match":
        if not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "confirmed", "not persisted")
        return _finish(runtime, record, "confirmed")
    try:
        reverted = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")["result"] == "match"
    except Exception:
        reverted = False
    return _finish(runtime, record, "reverted" if reverted else "unknown", "safeguard fired during confirmation")


def undo_request(record, reason: str):
    if record is None or record.get("status") != "finished" or record.get("result") != "confirmed":
        raise Rejected(["only a confirmed operation can be undone"])
    plan = record["plan"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if plan["op"] == "create":
        op, changes = "delete", {}
    elif plan["op"] == "delete":
        op, changes = "create", dict(before)
    else:
        op = "update"
        changes = {name: before.get(name) for name in sorted(set(before) | set(after))
                   if before.get(name) != after.get(name)}
    profile = find_profile(plan["platform"], plan["table"], plan["firmware"])
    for name in changes:
        if profile.attributes[name].type == "name-list":
            changes[name] = (changes[name] or "").split()
    body = {
        "device": record["device"], "table": plan["table"], "op": op, "key": plan["key"], "changes": changes,
        "reason": reason, "user_request": "undo of operation %s" % record["change_id"],
        "request_id": "undo-%s" % record["change_id"],
    }
    return parse_request(json.dumps(body).encode("utf-8")), after


def undo(runtime, change_id: str, reason: str) -> dict:
    original = runtime.store.operation(change_id)
    request, expected = undo_request(original, reason)
    return apply(runtime, original["device"], request, expected_before=expected)


def recover(runtime, device_name: str) -> list:
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %r is not configured" % device_name])
    settled = []
    with runtime.store.lock(device.name):
        for record in runtime.store.running(device.name):
            access = runtime.access_factory(device)
            plan = record["plan"]
            adapter = _adapter(plan["platform"])
            _step(runtime, record, "recovery_start")
            if "safeguard" not in record:
                settled.append(_finish(runtime, record, "rejected", "interrupted before any mutation"))
                continue
            try:
                present = not adapter.safeguard_absent(access, record)
            except Exception:
                settled.append(_finish(runtime, record, "unknown", "interrupted; safeguard state unreadable"))
                continue
            if present:
                settled.append(_settle_after_expiry(runtime, access, record, plan, "interrupted"))
                continue
            try:
                text = access.snapshot().encode("utf-8")
                is_after = engine.verify(plan, text, expect="after")["result"] == "match"
                is_before = engine.verify(plan, text, expect="before")["result"] == "match"
            except Exception:
                settled.append(_finish(runtime, record, "unknown", "interrupted; state unreadable"))
                continue
            steps = {step["step"] for step in record.get("steps", [])}
            if is_after and "confirm_start" in steps:
                saved = _persist(runtime, adapter, access, record)
                settled.append(_finish(runtime, record, "confirmed",
                                       "confirmed before the interruption" if saved else "not persisted"))
            elif is_before:
                saved = _persist(runtime, adapter, access, record)
                settled.append(_finish(runtime, record, "reverted", "interrupted" if saved else "not persisted"))
            else:
                settled.append(_finish(runtime, record, "unknown", "interrupted; state matches neither side"))
    return settled


def unblock(runtime, device_name: str, reason: str) -> bool:
    if device_name not in runtime.config.devices:
        raise Rejected(["device %r is not configured" % device_name])
    blocked = runtime.store.blocked(device_name)
    removed = runtime.store.unblock(device_name)
    runtime.store.clear_baseline(device_name)
    if removed:
        runtime.audit.event("administrative", device=device_name, action="unblock",
                            reason_characters=len(reason), change_id=(blocked or {}).get("change_id"))
    waived = 0
    for change_id in _undelivered(runtime, device_name):
        record = runtime.store.operation(change_id)
        record["notification"] = "waived"
        runtime.store.save(record)
        runtime.audit.event("administrative", device=device_name, action="notification waived",
                            reason_characters=len(reason), change_id=change_id)
        waived += 1
    return removed or waived > 0
