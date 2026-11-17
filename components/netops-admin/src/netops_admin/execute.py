from __future__ import annotations

import datetime
from contextlib import contextmanager
import json
import re
import secrets
import time

from netops_core.target_lock import target_lock, TargetBusy, TargetLockError

from netops_admin import audit, audit_gate, engine, exec_eos, exec_exos, exec_fortiadc, exec_fortios, exec_ios, exec_junos, exec_nxos, fortios, prediction, enrollment, schema_runtime, exec_schema_fortios
from netops_admin.schema_request import Transaction
from netops_admin.blocking import BLOCKING_REASONS, BLOCKING_RESULTS, blocks
from netops_admin.config import SAFEGUARD_MAX_SECONDS
from netops_admin.errors import BudgetExhausted, Rejected, SnapshotRejected, StateUnreadable, shown
from netops_admin.profiles import find_profile, load_profiles
from netops_admin.request import parse_request
from netops_admin.state import Store

EXPIRY_GRACE_SECONDS = 20
EXPIRY_POLL_SECONDS = 10
EXPIRY_WAIT_SLACK_SECONDS = 60
EXPIRY_WAIT_LIMIT_SECONDS = SAFEGUARD_MAX_SECONDS + EXPIRY_GRACE_SECONDS + EXPIRY_WAIT_SLACK_SECONDS
READ_FLOOR_SECONDS = 1.0
UNDELIVERED = ("pending", "failed", "sending")
ADAPTERS = {"fortios": exec_fortios, "exos": exec_exos, "eos": exec_eos, "ios": exec_ios, "iosxe": exec_ios, "fortiadc": exec_fortiadc, "nxos": exec_nxos,
            "junos": exec_junos}
FIRE_AT_FORMAT = "%Y-%m-%d %H:%M:%S"
HOUR = 3600
ANY_STATE = object()
DAY = 86400
REUSED_REQUEST = "request_id was already used for a different request"
UNDO_DONE = ("undo of this change has already been performed; "
             "after a reverted change remove the object with regular administration")
PLAN_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLAN_CHANGED = ("the fresh plan differs from the previewed plan (another device or firmware, or the object"
                " changed since the preview); run a new preview and approve its plan_sha256")
NO_UNDO = "a PoE cycle returns the configuration to its state before the operation; it has no undo"


class Runtime:
    def __init__(self, config, access_factory, notifier=None, sleep=time.sleep, monotonic=time.monotonic, *, require_export=True,
                 simulate_unmeasured_profiles=False):
        if type(require_export) is not bool:
            raise ValueError("require_export must be a boolean")
        if type(simulate_unmeasured_profiles) is not bool:
            raise ValueError("simulate_unmeasured_profiles must be a boolean")
        self.require_export = require_export
        # Only tests against simulated devices set this; the CLI and the MCP server never pass it.
        self.simulate_unmeasured_profiles = simulate_unmeasured_profiles
        self.config = config
        self.access_factory = access_factory
        self.notifier = notifier
        self.sleep = sleep
        self.monotonic = monotonic
        self.store = Store(config.state_dir)
        self.audit = audit.AuditLog(config.audit_file)


@contextmanager
def _target_lock(device):
    try:
        with target_lock(device.host_key_fingerprint):
            yield
    except (TargetBusy, TargetLockError) as error:
        raise Rejected([str(error)]) from None


def _adapter(platform: str, schema=False):
    if platform not in ADAPTERS:
        raise Rejected(["platform %s has no plan and apply adapter" % shown(platform)])
    return exec_schema_fortios if schema and platform == "fortios" else ADAPTERS[platform]


def _spec(record):
    return _adapter(record["plan"]["platform"], schema_runtime.is_plan(record["plan"])).prompt_spec(record["hostname"])


def _fire_at(record) -> datetime.datetime:
    return datetime.datetime.strptime(record["safeguard"]["fire_at"], FIRE_AT_FORMAT)


def _step(runtime, record, name, detail=None):
    record.setdefault("steps", []).append({"step": name, "at": audit.now_utc(), "detail": detail})
    runtime.store.save(record)
    runtime.audit.event("step", change_id=record["change_id"], device=record["device"], step=name, detail=detail)


def export_state(config) -> tuple:
    return audit.export_state(config.export_status_file, config.limits, audit_file=config.audit_file,
                              require_audit_file=config.export_status_require_audit_file)


def _finish(runtime, record, result, reason=None, differences=None, reason_code=None):
    record["status"] = "finished"
    record["finished_at_epoch"] = time.time()
    record["result"] = result
    record["reason"] = reason
    if result == "rejected":
        # a refusal recorded here carries the same machine fields as a refusal raised before the operation
        record["reason_codes"] = [reason_code or "unspecified_refusal"]
        record["reason_details"] = []
    record["differences"] = differences or []
    state, _why = export_state(runtime.config)
    record["audit_delivery"] = "pending" if state in ("acknowledged", "pending") else state
    record["notification"] = "pending" if runtime.notifier is not None else "not-configured"
    if blocks(result, reason):
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


def _note_notification(runtime, record, value) -> None:
    def change(current):
        current["notification"] = value
        return True

    runtime.store.update(record["change_id"], change)
    record["notification"] = value


def _deliver_notification(runtime, record) -> None:
    previous = record.get("notification")
    if previous in UNDELIVERED:
        _note_notification(runtime, record, "sending")
    try:
        result = runtime.notifier(record)
    except Exception:
        result = "failed"
    outcome = result if result in ("sent", "failed") else "failed"
    _note_notification(runtime, record, "waived" if outcome == "failed" and previous == "waived" else outcome)
    runtime.audit.event("delivery", change_id=record["change_id"], device=record["device"],
                        notification=outcome, audit_delivery=record.get("audit_delivery"))


def notify_retry(runtime, change_id: str) -> dict:
    runtime.audit.check_writable()
    record = runtime.store.operation(change_id)
    if record is None or record.get("status") != "finished":
        raise Rejected(["no finished operation matches"])
    if runtime.notifier is None:
        raise Rejected(["notification is not configured"])
    with runtime.store.lock(record["device"]):
        record = runtime.store.operation(change_id)
        if record.get("notification") != "sent":
            _deliver_notification(runtime, record)
    return record


def refresh_delivery(runtime, record) -> dict:
    if record.get("status") != "finished" or record.get("audit_delivery") != "pending":
        return record
    state, _why = export_state(runtime.config)
    status_time = audit.export_updated_at(runtime.config.export_status_file)
    finished_at = record.get("finished_at_epoch")
    if not (state == "acknowledged" and status_time is not None and finished_at is not None and status_time > finished_at):
        return record
    acknowledged = []

    def acknowledge(current):
        if (current.get("status") != "finished" or current.get("audit_delivery") != "pending"
                or current.get("finished_at_epoch") != finished_at):
            return False
        current["audit_delivery"] = "acknowledged"
        acknowledged.append(True)
        return True

    try:
        saved = runtime.store.update(record["change_id"], acknowledge)
    except StateUnreadable:
        raise
    except Rejected:
        return record
    if acknowledged:
        runtime.audit.event("delivery", change_id=saved["change_id"], device=saved["device"],
                            notification=saved.get("notification"), audit_delivery="acknowledged")
    return saved


class _Deadline:
    def __init__(self, runtime, seconds, expired):
        self.runtime, self.expired = runtime, expired
        self.end, self.unslept = runtime.monotonic() + seconds, seconds

    def left(self) -> float:
        return min(self.end - self.runtime.monotonic(), self.unslept)

    def tighten(self, end, expired) -> None:
        self.end, self.expired = min(self.end, end), expired

    def read(self, access, query, *arguments):
        if self.left() < 0:
            raise Rejected([self.expired])
        limited = hasattr(access, "read_seconds")
        if limited:
            previous, access.read_seconds = access.read_seconds, max(self.left(), READ_FLOOR_SECONDS)
        try:
            answer = query(access, *arguments)
        finally:
            if limited:
                access.read_seconds = previous
        if self.left() < 0:
            raise Rejected([self.expired])
        return answer

    def pause(self, wanted) -> None:
        left = self.left()
        if left <= 0:
            raise Rejected([self.expired])
        pause = min(max(min(wanted, left), 1), EXPIRY_POLL_SECONDS)
        self.runtime.sleep(pause)
        self.unslept -= pause


def _firing_slack(adapter) -> int:
    # a platform whose return takes longer than the default slack names its own (Junos: minute granularity of the
    # timer and the automatic rollback commit, exec_junos.FIRING_SLACK_SECONDS)
    return getattr(adapter, "FIRING_SLACK_SECONDS", EXPIRY_WAIT_SLACK_SECONDS)


# Adapter hook contract (module attributes; absent means the default below).
# Readers are functions in this module unless qualified; callables run only on their named path.
# Flags must be bool, seconds int/float (not bool), and functions callable.
#
# Attribute                         Type       Default / meaning and reader
# TIMER_WATCH                       bool       False: _watched selects a monotonic timer instead of the device clock.
# FIRING_SLACK_SECONDS              seconds    EXPIRY_WAIT_SLACK_SECONDS (60): extra return time, _firing_slack.
# COMPENSATING                      bool       False: _compensating selects an inverse write without a device timer.
# AUDIT_RULES                       bool       True: _audited_rules enables the auditor rules; readiness._doctor
#                                             checks audit policy (False reports AUDIT_NOT_RUN[2] as unverified).
# REVERT_NOW_KEEPS_SAFEGUARD          bool       False: _keeps_safeguard requires cleanup after an immediate return.
# REVERT_AFTER_EXPIRY                bool       False: _settle_after_expiry may return a mismatching object again.
# INSTALL_JOURNAL                   bool       False: _execute supplies install_safeguard with a journal save callback.
# REFUSED_REASON_CODE               str        "rollback_timer_pending": _execute reports a refused installation.
# REVERT_NOW_SECONDS                seconds    None (no budget check): _settle_after_expiry reserves return time.
# revert_now(access, record, spec)   callable   None (wait for expiry): _revert_now returns the change; bool result.
# adopt_change_head(access, record)  callable   None (skip): _adopt_change_head records the timer head; bool result;
#                                             _settle_after_expiry calls it only with REVERT_NOW_SECONDS available.
# revoke_token(access, record, spec) callable   None (skip): _settle_after_expiry revokes an unproven safeguard's
#                                             token; bool result (None means no revocation to report).
# discard_installation(access, record, spec)
#                                  callable   None (normal cleanup): _execute/recover select _discard_installation
#                                             to remove a partial installation; returns (cleaned: bool, detail).
# safeguard_rearmed(access, record)  callable   None (no restart): _execute verifies/records a restarted timer;
#                                             returns a list of problems (empty means verified).
# safeguard_preflight(access, device, snapshot_text, firmware)
#                                  callable   None (skip webhook check): readiness._doctor checks webhook readiness
#                                             when firmware is known; returns str, raises Rejected on refusal.
# line_guard_for(steps, left)        callable   None (use line_allowed): _execute builds a per-line callable returning
#                                             bool; left() gives seconds left on Admin's monotonic clock.
#
# TIMER_WATCH=True additionally requires these attributes (no default):
# FIRE_AT_TEXT                      str        _execute records this description as safeguard.fire_at.
# timer_seconds(device) -> seconds: _timer_end/_restarted_end compute the timer duration.
# before_write(access, record, left, device) -> str | None: _execute refuses with a reason or permits the write.
# line_allowed(left) -> bool: _execute's per-line fallback when line_guard_for is absent.
# `line_guard` belongs to access, not the adapter: _execute installs the guard for access.apply and clears it in finally.
# COMPENSATING=True also requires RETURN_MECHANISM (str) and AUDIT_NOT_RUN (rule, state, detail), consumed by
# _execute_compensating and _preview/_prepared. Common mandatory adapter methods are outside this optional contract.

def _watched(adapter) -> bool:
    """The adapter watches its on-device timer on the monotonic clock of Admin and by reading the timer, never by
    the device clock (TIMER_WATCH: IOS, IOS XE, NX-OS and Junos). The other adapters with an on-device safeguard
    (FortiOS, ExtremeXOS, EOS) plan fire_at on the device clock; FortiADC has no on-device timer and returns by
    compensation (_compensating)."""
    return getattr(adapter, "TIMER_WATCH", False) is True


def _timer_end(adapter, device, record, requested) -> float:
    """The end of the own timer on the monotonic clock of Admin (watched adapters), counted from the moment before
    it was requested, so never later than the device ends it. An adapter that observed a shorter lead of its timer
    on the device itself (NX-OS: the schedule time against the creation of the checkpoint, both on the device
    clock) records it in safeguard.lead_seconds; the shorter count applies."""
    seconds = adapter.timer_seconds(device)
    lead = (record.get("safeguard") or {}).get("lead_seconds")
    if isinstance(lead, (int, float)) and not isinstance(lead, bool):
        seconds = min(seconds, lead)
    return requested + seconds


def _restarted_end(adapter, device, record, requested, sent, answered) -> float:
    """The end of the own timer after the change commit restarted it (Junos commit confirmed), on the monotonic clock
    of Admin. The restart happened after the change session was started (sent) and before its answer (answered), so
    the timer ends no earlier than sent plus the timer. An adapter that read both commit rows on the device records
    in safeguard.restart_offset_seconds how much later than the start of the safeguard the restart came (both on the
    device clock, shortened for its drift); counted from the moment before the safeguard was requested and never
    past the answer of the session, it gives the later of the two lower bounds."""
    seconds = adapter.timer_seconds(device)
    start = sent
    offset = (record.get("safeguard") or {}).get("restart_offset_seconds")
    if isinstance(offset, (int, float)) and not isinstance(offset, bool) and offset > 0:
        start = max(sent, min(requested + offset, answered))
    return start + seconds


def _wait_for_expiry(runtime, adapter, access, record, due) -> None:
    if _watched(adapter):
        # the state of the timer decides: it is read again and again until it is no longer the own pending one,
        # limited on the monotonic clock of Admin (the longest timer plus grace and slack)
        # (an adapter whose timed return takes longer names its own slack, Junos: FIRING_SLACK_SECONDS)
        deadline = _Deadline(runtime, EXPIRY_WAIT_LIMIT_SECONDS - EXPIRY_WAIT_SLACK_SECONDS + _firing_slack(adapter),
                             "the safeguard was not seen ended within the wait limit")
        return _wait_for_proof(runtime, adapter, access, record, deadline)
    fire_at = _fire_at(record)
    slack = _firing_slack(adapter)
    deadline = _Deadline(runtime, EXPIRY_WAIT_LIMIT_SECONDS - EXPIRY_WAIT_SLACK_SECONDS + slack,
                         "the safeguard did not expire within the wait limit")
    while True:
        remaining = (fire_at - deadline.read(access, adapter.clock)).total_seconds() + EXPIRY_GRACE_SECONDS
        if remaining <= 0:
            deadline.tighten(max(runtime.monotonic(), due + EXPIRY_GRACE_SECONDS) + slack,
                             "the safeguard was not seen fired within the wait limit")
            return _wait_for_proof(runtime, adapter, access, record, deadline)
        deadline.pause(remaining)


def _wait_for_proof(runtime, adapter, access, record, deadline) -> None:
    pending = False
    while not deadline.read(access, adapter.safeguard_fired, record):
        deadline.pause(deadline.left())
        pending = True
    if pending:
        runtime.sleep(EXPIRY_GRACE_SECONDS)


def _persist(runtime, adapter, access, record) -> bool:
    try:
        saved = adapter.persist(access, _spec(record))
    except Exception as exc:
        _step(runtime, record, "persist_failed", type(exc).__name__)
        return False
    if saved:
        _step(runtime, record, "configuration_saved")
    return True


def _compensating(adapter) -> bool:
    return getattr(adapter, "COMPENSATING", False) is True


def _audited_rules(adapter) -> bool:
    return getattr(adapter, "AUDIT_RULES", True) is not False


def _compensate(runtime, adapter, access, record, plan, reason):
    """Return an unverified change of a platform without an on-device timer: the inverse is written in this run.

    The inverse is written only when the planned object is not in its state before; the result is then judged by a
    fresh snapshot against the side before, as after an on-device return."""
    _step(runtime, record, "compensation_start", reason)
    try:
        verdict = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "compensation_state_unreadable", type(exc).__name__)
        verdict = None
    if verdict is None or not verdict["object_matches"]:
        try:
            access.apply(plan["inverse"], _spec(record))
            _step(runtime, record, "compensation_applied")
        except Exception as exc:
            _step(runtime, record, "compensation_failed",
                  "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        try:
            verdict = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
        except Exception as exc:
            _step(runtime, record, "revert_unverified", type(exc).__name__)
            return _finish(runtime, record, "unknown", reason)
    else:
        _step(runtime, record, "compensation_not_needed", "the object is in its state before")
    if verdict["result"] == "match":
        _step(runtime, record, "compensation_verified")
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        kept = reason if reason in BLOCKING_REASONS else "foreign change"
        return _finish(runtime, record, "reverted", kept, verdict["differences"])
    return _finish(runtime, record, "revert-failed", reason, verdict["differences"])


# a failure that is returned by the expiry of the timer although the adapter can return at once: the enrollment
# self-test is left unconfirmed on purpose, and recover decides by the state of the timer
EXPIRY_ONLY_REASONS = ("enrollment self-test", "interrupted")


def _keeps_safeguard(adapter) -> bool:
    """The on-device safeguard is still installed after the immediate return of the adapter (NX-OS: configure replace
    leaves the scheduler job, the schedule and the checkpoint, which are removed only after the return is proven);
    IOS ends its own timer with configure revert now."""
    return getattr(adapter, "REVERT_NOW_KEEPS_SAFEGUARD", False) is True


def _revert_now(runtime, adapter, access, record, plan, reason):
    """Return a failed change at once with the own on-device safeguard (IOS: configure revert now, NX-OS: configure
    replace of the own saved file); None when the adapter could not prove it (the safeguard is not the own one or
    is still pending, or the object is not seen in its state before while the safeguard is still armed), then the
    caller waits for the expiry."""
    _step(runtime, record, "revert_now_start", reason)
    keeps = _keeps_safeguard(adapter)
    try:
        reverted = adapter.revert_now(access, record, _spec(record))
    except Exception as exc:
        _step(runtime, record, "revert_now_unverified", "%s; waiting for the expiry of the safeguard"
              % type(exc).__name__)
        return None
    if not reverted:
        _step(runtime, record, "revert_now_unverified", "waiting for the expiry of the safeguard")
        return None
    _step(runtime, record, "revert_now_done")
    try:
        verdict = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        if keeps:
            # the safeguard is still armed and returns the change at its time
            return None
        return _finish(runtime, record, "unknown", reason)
    if keeps:
        if not verdict["object_matches"]:
            _step(runtime, record, "revert_unverified", "the object is not in its state before")
            return None
        cleaned = adapter.remove_safeguard(access, record, _spec(record))
        _step(runtime, record, "safeguard_removed" if cleaned else "safeguard_removal_unverified")
        if not cleaned:
            return _finish(runtime, record, "unknown", "safeguard cleanup unverified")
    if verdict["result"] == "match":
        if not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        kept = reason if reason in BLOCKING_REASONS else "foreign change"
        return _finish(runtime, record, "reverted", kept, verdict["differences"])
    return _finish(runtime, record, "revert-failed", reason, verdict["differences"])


def _adopt_change_head(runtime, adapter, access, record, until) -> None:
    """An adapter whose change commit becomes the head of its timer (Junos) records it again before the immediate
    return when the read right after the change failed; the read may use only the time before `until` on the
    monotonic clock of Admin (the end of the timer less the budget of the return), so the budget stays whole."""
    deadline = _Deadline(runtime, until - runtime.monotonic(), "too little of the safeguard left to read its head")
    try:
        adopted = deadline.read(access, adapter.adopt_change_head, record)
    except Exception as exc:
        _step(runtime, record, "change_head_unverified", type(exc).__name__)
        return
    if adopted:
        _step(runtime, record, "change_head_adopted", record["safeguard"].get("device_expiry"))


def _settle_after_expiry(runtime, access, record, plan, reason, due):
    adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan))
    if _compensating(adapter):
        return _compensate(runtime, adapter, access, record, plan, reason)
    if getattr(adapter, "revert_now", None) is not None and reason not in EXPIRY_ONLY_REASONS:
        # an adapter whose immediate return takes long (NX-OS configure replace) sets its budget: with less of the
        # own timer left (due is its end on the monotonic clock of Admin) the timer is awaited first, so the return
        # never runs together with the timed return of the device
        budget = getattr(adapter, "REVERT_NOW_SECONDS", None)
        if (getattr(adapter, "adopt_change_head", None) is not None and budget is not None
                and due - runtime.monotonic() >= budget):
            _adopt_change_head(runtime, adapter, access, record, due - budget)
        if budget is not None and due - runtime.monotonic() < budget:
            _step(runtime, record, "revert_now_skipped", "too little of the safeguard left; waiting for its expiry")
        else:
            settled = _revert_now(runtime, adapter, access, record, plan, reason)
            if settled is not None:
                return settled
    try:
        _wait_for_expiry(runtime, adapter, access, record, due)
        after_expiry = access.snapshot()
        verdict = engine.verify(plan, after_expiry.encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        return _finish(runtime, record, "unknown", reason)
    if not verdict["object_matches"] and getattr(adapter, "REVERT_AFTER_EXPIRY", False) is True:
        # the timed return ran but the object is not in its state before (a line written late, or a change of
        # someone else after the return): the adapter returns to its own saved state before giving up
        _step(runtime, record, "expiry_not_returned", "%d differences" % len(verdict["differences"]))
        settled = _revert_now(runtime, adapter, access, record, plan, reason)
        if settled is not None:
            return settled
    if (verdict["result"] != "match" and not verdict["object_matches"] and not adapter.FIRING_OBSERVED
            and not adapter.safeguard_disarmed(access, record)):
        _step(runtime, record, "safeguard_kept", "firing not proven")
        revoke = getattr(adapter, "revoke_token", None)
        revoked = None if revoke is None else revoke(access, record, _spec(record))
        if revoked is not None:
            _step(runtime, record, "safeguard_token_revoked" if revoked else "safeguard_token_revoke_unverified")
        return _finish(runtime, record, "unknown", reason, verdict["differences"])
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


def _discard_installation(runtime, adapter, access, record, plan, reason):
    """Remove the safeguard of a change that was never sent (unverified or interrupted installation): only the
    objects whose creation the own session proved; the result is judged by a fresh snapshot against the side before.
    What cannot be removed that way stays (unknown, the device is blocked); the adapter notes the manual procedure in
    the journal record."""
    try:
        cleaned, detail = adapter.discard_installation(access, record, _spec(record))
    except Exception as exc:
        cleaned, detail = False, type(exc).__name__
    if not cleaned:
        _step(runtime, record, "safeguard_removal_unverified", detail)
        return _finish(runtime, record, "unknown", reason if reason == "safeguard not verified"
                       else "interrupted safeguard installation; manual cleanup needed")
    _step(runtime, record, "safeguard_removed", detail)
    try:
        verdict = engine.verify(plan, access.snapshot().encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        return _finish(runtime, record, "unknown", reason)
    if verdict["result"] == "match":
        if not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        return _finish(runtime, record, "reverted", "foreign change", verdict["differences"])
    return _finish(runtime, record, "unknown", reason, verdict["differences"])


def _undelivered(runtime, device_name: str, *, records=None) -> list:
    if records is None:
        records = runtime.store.records()
    return sorted(record["change_id"] for record in records
                  if record.get("device") == device_name and record.get("status") == "finished"
                  and record.get("notification") in UNDELIVERED)


def _block_accounts(runtime, device) -> None:
    runtime.store.block(device.name, None, "administrator table")
    runtime.audit.event("administrative", device=device.name, action="blocked: administrator table",
                        reason_characters=0, change_id=None)


def _budgets(runtime, device, changes=1, *, records=None) -> None:
    if type(changes) is not int or not 1 <= changes <= 32:
        raise Rejected(["the transaction change count must be in 1..32"])
    limits, now = runtime.config.limits, runtime.store.budget_now()
    if runtime.store.rejections_since(now - HOUR) >= limits["rejections_per_hour"]:
        raise BudgetExhausted(["the budget of rejected requests for this hour is exhausted"], reason_details=[{"code": "budget_exhausted", "budget": "rejected_hour"}])
    if records is None:
        records = runtime.store.records()
    if len(records) >= limits["journal_records"]:
        raise BudgetExhausted(["the journal holds its maximum number of operations; archive it before new changes"], reason_details=[{"code": "budget_exhausted", "budget": "journal_records"}])
    counted = [record for record in records if "safeguard" in record or record.get("status") == "running"]
    started = [(record.get("budget_at_epoch", record.get("created_at_epoch")) or 0, record.get("budget_changes", 1)) for record in counted]
    mine = [(record.get("budget_at_epoch", record.get("created_at_epoch")) or 0, record.get("budget_changes", 1)) for record in counted
            if record.get("device") == device.name]
    if sum(weight for moment, weight in mine if moment >= now - HOUR) + changes > limits["changes_per_device_per_hour"]:
        raise BudgetExhausted(["the budget of changes on this device for this hour is exhausted"], reason_details=[{"code": "budget_exhausted", "budget": "device_hour"}])
    if sum(weight for moment, weight in started if moment >= now - DAY) + changes > limits["changes_per_day"]:
        raise BudgetExhausted(["the budget of changes for this day is exhausted"], reason_details=[{"code": "budget_exhausted", "budget": "global_day"}])


def _count_rejection(runtime) -> None:
    try:
        runtime.store.note_rejection(runtime.store.budget_now())
    except (OSError, Rejected):
        pass


def _expected_plan(request, expected_plan_sha256):
    if expected_plan_sha256 is None:
        return None
    if isinstance(request, Transaction):
        raise Rejected(["expected_plan_sha256 is supported only for profile requests: the plan_sha256 of a schema"
                        " transaction depends on the snapshot and the request_id, so a preview never matches it"])
    if not isinstance(expected_plan_sha256, str) or not PLAN_SHA256.fullmatch(expected_plan_sha256):
        raise Rejected(["expected_plan_sha256 must be 64 lowercase hexadecimal characters"])
    return expected_plan_sha256


def apply(runtime, device_name: str, request, expected_before=ANY_STATE, expected_plan_sha256=None) -> dict:
    # expected_plan_sha256 binds the apply to an approved preview; like expected_before it stays outside
    # Request.fingerprint, so a repeated request_id returns its operation whatever hash is sent
    try:
        expected_plan = _expected_plan(request, expected_plan_sha256)
    except Rejected:
        # a malformed or unsupported hash is a rejected apply like any other: zero device writes and
        # zero operation records, but the hourly budget of rejected requests counts it
        _count_rejection(runtime)
        raise
    return _apply_counted(runtime, device_name, request, expected_before, expected_plan=expected_plan)


def _apply_counted(runtime, device_name: str, request, expected_before=ANY_STATE, undo=False, expected_plan=None,
                   action=None) -> dict:
    try:
        return _apply(runtime, device_name, request, expected_before, undo=undo, expected_plan=expected_plan,
                      action=action)
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise


def _opt_in(device, request, undo=False) -> None:
    from netops_admin.config import OPT_IN_TABLES
    if isinstance(request, Transaction):
        for operation in request.operations:
            path = " ".join(operation["path"].replace("/", " ").split())
            for table in OPT_IN_TABLES:
                if path == table or path.startswith(table + " "):
                    raise Rejected(["schema transaction path %r is not supported: %s changes need the %s profile"
                                    % (operation["path"], table, table)])
        return
    if undo:
        return
    if request.table in OPT_IN_TABLES and request.table not in device.opt_in:
        raise Rejected(["table %r is not enabled for device %s (opt_in)" % (request.table, device.name)])


def _action(device, request, action) -> None:
    """A table with an own operation (profile action) is changed only by that operation, never by apply."""
    if isinstance(request, Transaction):
        if action is not None:
            raise Rejected(["operation %s takes no schema transaction" % action])
        return
    profile = load_profiles().get((device.platform, request.table))
    owner = None if profile is None else profile.action
    if owner == action:
        return
    if owner is not None:
        raise Rejected(["table %r is changed only by the %s operation" % (request.table, owner)],
                       reason_codes=["action_only_table"])
    raise Rejected(["operation %s does not apply to table %r on platform %s"
                    % (action, request.table, device.platform)], reason_codes=["action_unsupported"])


def _measured(runtime, device, request) -> None:
    if isinstance(request, Transaction) or runtime.simulate_unmeasured_profiles:
        return
    profile = load_profiles().get((device.platform, request.table))
    if profile is not None and not profile.measured:
        raise Rejected(["profile %s %r is not measured on a device; it is refused until the measurement is done"
                        " (opt_in does not enable it)" % (device.platform, request.table)],
                       reason_codes=["profile_not_measured"])


def _target(runtime, device_name: str, request):
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %s is not configured" % shown(device_name)])
    if request.device is not None and request.device != device.name:
        raise Rejected(["the request names device %r, but it was sent to device %r" % (request.device, device.name)])
    return device


def _known(runtime, device, request):
    known = runtime.store.request(request.request_id)
    if known is None:
        return _journaled(runtime, device, request)
    if known["request_sha256"] != request.fingerprint() or known["device"] != device.name:
        raise Rejected([REUSED_REQUEST], reason_codes=["request_id_reused"])
    record = runtime.store.operation(known["change_id"])
    if record is None:
        raise runtime.store.unreadable(runtime.store.operations / ("%s.json" % known["change_id"]))
    return record


def _journaled(runtime, device, request):
    found = [record for record in runtime.store.records() if record.get("request_id") == request.request_id]
    if any(record.get("request_sha256") != request.fingerprint() or record.get("device") != device.name
           for record in found):
        raise Rejected([REUSED_REQUEST], reason_codes=["request_id_reused"])
    return found[0] if found else None


def preview(runtime, device_name: str, request) -> dict:
    try:
        result, refused = _preview(runtime, device_name, request)
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise
    if refused:
        _count_rejection(runtime)
    return result


def _preview(runtime, device_name: str, request, expected_before=ANY_STATE, undo=False, action=None):
    device = _target(runtime, device_name, request)
    _action(device, request, action)
    _opt_in(device, request, undo)
    _measured(runtime, device, request)
    adapter = _adapter(device.platform, isinstance(request, Transaction))
    with runtime.store.lock(device.name), _target_lock(device):
        missing = []
        try:
            known = _known(runtime, device, request)
            if known is not None:
                return {"result": "known-request", "device": device.name, "change_id": known["change_id"],
                        "reasons": ["request_id already started an operation; apply returns it without running again"]}, False
            prepared = _prepared(runtime, device, adapter, request, expected_before, False, missing, undo=undo)
        except Rejected as exc:
            return ({"result": "rejected", "device": device.name, "reasons": list(exc.reasons), "reason_codes": list(exc.reason_codes), "reason_details": list(exc.reason_details)},
                    not isinstance(exc, BudgetExhausted))
    plan, audit_before, coverage = prepared[4], prepared[5], prepared[7]
    return {
        "result": "rejected" if missing else "ready",
        "reasons": [reason for exc in missing for reason in exc.reasons],
        "reason_codes": [code for exc in missing for code in exc.reason_codes],
        "reason_details": [detail for exc in missing for detail in exc.reason_details],
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
        "audit_findings_before": audit_gate.finding_count(audit_before),
        "audit_unevaluated": audit_gate.unevaluated(audit_before),
        "audit_coverage": coverage,
        "safeguard_seconds": device.safeguard_seconds,
        **({"return_mechanism": adapter.RETURN_MECHANISM} if _compensating(adapter) else {}),
    }, bool(missing)


def _prepared(runtime, device, adapter, request, expected_before, enrolling, missing=None, undo=False,
              expected_plan=None):
    config = runtime.config
    transaction = isinstance(request, Transaction)
    _budgets(runtime, device, len(request.operations) if transaction else 1)
    blocked = runtime.store.blocked(device.name)
    if blocked is not None:
        raise Rejected(["the device is blocked (%s, operation %s); a person must investigate and unblock it"
                        % (blocked.get("reason"), blocked.get("change_id") or "none")], reason_codes=["device_blocked"])
    undelivered = _undelivered(runtime, device.name)
    if undelivered:
        raise Rejected(["the notification of operation %s was not delivered; run notify-retry, or a person"
                        " unblocks the device after checking the notification channel" % undelivered[0]], reason_codes=["notification_pending"])
    if runtime.store.running(device.name):
        raise Rejected(["an unfinished operation exists on this device; run recover first"], reason_codes=["operation_unfinished"])
    runtime.store.check_writable()
    runtime.audit.check_writable()
    export, why = export_state(config)
    if export == "blocked":
        raise Rejected(["audit export is blocked: %s" % why])
    known = runtime.store.baseline(device.name)
    try:
        access = runtime.access_factory(device)
        if transaction:
            access = schema_runtime.Access(access, device)
        before_text = access.snapshot()
        try:
            accounts = adapter.accounts_check(access, device, before_text)
            if known is not None and known != accounts:
                raise Rejected(["the administrator accounts changed since the last operation"])
        except Rejected as exc:
            if missing is None and not isinstance(exc, SnapshotRejected):
                _block_accounts(runtime, device)
            raise
        leftovers = adapter.leftovers(access)
        if leftovers:
            raise Rejected(["a safeguard of an earlier operation is still installed: %s" % ", ".join(leftovers)])
        hostname = adapter.hostname(access, before_text)
        reasons = adapter.prechecks(access, device, before_text, adapter.prompt_spec(hostname))
        if reasons:
            raise Rejected(reasons)
        ports = adapter.ports(access, request.table)
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected(["the device could not be read before any change: %s" % exc]) from None
    if transaction:
        plan = schema_runtime.build(device, request, before_text, enrolling=enrolling)
    else:
        plan = engine.build_plan(device.platform, before_text.encode("utf-8"), request,
                                 firmware=device.firmware, protected=device.protected, enrollment_probe=enrolling,
                                 ports=ports, undo=undo, device=device.name)
    try:
        reasons = adapter.plan_prechecks(access, device, plan, before_text)
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected(["the device could not be read before any change: %s" % exc]) from None
    if reasons:
        raise Rejected(reasons)
    if missing is not None:
        try:
            enrollment.require(runtime, device, accounts, plan["firmware"])
        except Rejected as exc:
            missing.append(exc)
    elif not enrolling:
        enrollment.require(runtime, device, accounts, plan["firmware"])
    elif runtime.notifier is None or (export not in ("acknowledged", "pending")
                                      and (runtime.require_export or export != "not-configured")):
        requirement = "a healthy configured audit export" if runtime.require_export else "an available operation audit"
        raise Rejected(["enrollment requires notification and " + requirement])
    if len(plan["commands"]) > config.limits["plan_commands"] or len(plan["inverse"]) > config.limits["plan_commands"]:
        raise Rejected(["the plan holds more than %d commands" % config.limits["plan_commands"]])
    if expected_before is not ANY_STATE and plan["predicted"]["before"] != expected_before:
        raise Rejected(["the object differs from the state the undo was planned against"])
    if expected_plan is not None and plan["plan_sha256"] != expected_plan:
        raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"],
                       reason_details=[{"code": "plan_changed", "expected": expected_plan,
                                        "actual": plan["plan_sha256"]}])
    try:
        policy = device.audit_policy
        plan["device"] = device.name
        predicted_text = (prediction.audited(prediction.snapshot_after(before_text, plan), plan)
                          if transaction or _audited_rules(adapter) else None)
        if not transaction and not _audited_rules(adapter):
            rule, state, why = adapter.AUDIT_NOT_RUN
            audit_before, coverage = {audit_gate.UNEVALUATED + rule: (rule, state, why)}, {rule: state}
            predicted_findings = []
        elif transaction:
            audit_before, _before_coverage = schema_runtime.audit_snapshot(plan, before_text, policy, None,
                                                                           audit_gate.BASELINE)
            predicted_findings, coverage = schema_runtime.after_audit(plan, audit_before, predicted_text, policy)
        else:
            audit_before = audit_gate.baseline(device.platform, prediction.audited(before_text, plan), device.name, policy)
            coverage = audit_gate.evaluate(device.platform, predicted_text, policy, plan["table"], audit_before)
            audit_gate.check_policy(plan, policy, predicted_text, audit_before)
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
    except Rejected as exc:
        raise Rejected(["the check account answer about the object before the change was refused: %s"
                        % "; ".join(exc.reasons)], reason_codes=exc.reason_codes, reason_details=exc.reason_details) from None
    except Exception as exc:
        raise Rejected(["the check account could not read the object before the change (%s)"
                        % type(exc).__name__]) from None
    if seen != plan["predicted"]["before"]:
        raise Rejected(["the check account sees the object in another state than the snapshot"])
    return access, before_text, accounts, hostname, plan, audit_before, policy, coverage


def _apply(runtime, device_name: str, request, expected_before, enrolling=False, undo=False, expected_plan=None,
           action=None) -> dict:
    device = _target(runtime, device_name, request)
    _action(device, request, action)
    _opt_in(device, request, undo)
    _measured(runtime, device, request)
    adapter = _adapter(device.platform, isinstance(request, Transaction))
    fingerprint = request.fingerprint()
    with runtime.store.lock(device.name), _target_lock(device):
        known = _known(runtime, device, request)
        if known is not None:
            return known
        access, before_text, accounts, hostname, plan, audit_before, policy, coverage = _prepared(
            runtime, device, adapter, request, expected_before, enrolling, undo=undo, expected_plan=expected_plan)
        profile = None if isinstance(request, Transaction) else find_profile(plan["platform"], plan["table"], plan["firmware"])
        change_id = secrets.token_hex(16)
        plan["safeguard_id"] = change_id
        record = {
            "change_id": change_id, "request_id": request.request_id, "request_sha256": fingerprint,
            "device": device.name, "status": "running", "result": None, "hostname": hostname,
            "plan": plan, "steps": [], "created_at": audit.now_utc(), "created_at_epoch": time.time(), "budget_at_epoch": runtime.store.budget_now(),
            "kind": "enrollment" if enrolling else (action or "change"),
            "budget_changes": len(request.operations) if isinstance(request, Transaction) else 1,
            "audit_before": audit_before, "audit_policy": policy, "audit_coverage": coverage, "accounts": accounts,
        }
        with runtime.store.admission():
            known = _known(runtime, device, request)
            if known is not None:
                return known
            _budgets(runtime, device, record["budget_changes"])
            runtime.store.save(record)
            runtime.store.save_baseline(device.name, accounts)
            runtime.store.remember_request(request.request_id, change_id, fingerprint, device.name)
        runtime.audit.event(
            "start", change_id=change_id, request_id=request.request_id, device=device.name,
            platform=plan["platform"], firmware=plan["firmware"], table=plan["table"], op=plan["op"],
            key=plan["key"], request_sha256=fingerprint, plan_sha256=plan["plan_sha256"],
            snapshot_sha256=plan["snapshot_sha256"], reason_characters=plan["reason_characters"],
            user_request_characters=plan["user_request_characters"],
            changes=({"operation_count": len(request.operations), "attribute_count": sum(len(x["changes"]) for x in request.operations)}
                     if isinstance(request, Transaction) else audit.summarized_changes(profile, engine.canonical_changes(profile, request))),
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
                return _finish(runtime, record, "rejected", "enrollment notification unavailable",
                               reason_code="notification_unavailable")
            _step(runtime, record, "enrollment_notification_verified")
            runtime.store.clear_enrollment(device.name)
        result = _execute(runtime, adapter, access, record, plan, device)
        return enrollment.complete(runtime, device, access, result) if enrolling else result


def _execute(runtime, adapter, access, record, plan, device) -> dict:
    change_id, spec = record["change_id"], _spec(record)
    if _compensating(adapter):
        return _execute_compensating(runtime, adapter, access, record, plan, device)
    watched = _watched(adapter)
    if watched:
        record["safeguard"] = {"fire_at": adapter.FIRE_AT_TEXT, "name": adapter.safeguard_label(change_id)}
    else:
        try:
            fire_at = adapter.clock(access) + datetime.timedelta(seconds=device.safeguard_seconds)
        except Exception as exc:
            _step(runtime, record, "clock_unreadable", type(exc).__name__)
            return _finish(runtime, record, "rejected", "device clock", reason_code="device_clock_unreadable")
        record["safeguard"] = {"fire_at": fire_at.strftime(FIRE_AT_FORMAT), "name": adapter.safeguard_label(change_id)}
    _step(runtime, record, "safeguard_install")
    requested = runtime.monotonic()
    try:
        if getattr(adapter, "INSTALL_JOURNAL", False) is True:
            # the adapter notes in record["safeguard"] which objects its own session proved it created, line by line;
            # each note is saved at once, so recover knows them after an interruption of the installation
            problems = adapter.install_safeguard(access, record, plan, device, spec,
                                                 journal=lambda: runtime.store.save(record))
        else:
            problems = adapter.install_safeguard(access, record, plan, device, spec)
    except Exception as exc:
        from netops_admin.access import AccessError

        cause = "AccessError: %s" % exc if isinstance(exc, AccessError) else type(exc).__name__
        problems = ["safeguard installation failed (%s)" % cause]
    due = runtime.monotonic() + device.safeguard_seconds
    # the end of the own timer on the monotonic clock of Admin (watched adapters only), counted from before the
    # request, so never later than the device ends it
    timer_end = _timer_end(adapter, device, record, requested) if watched else None
    if watched:
        due = timer_end
    if problems and watched:
        # a timer whose installation the own session did not prove is never confirmed, returned or saved over
        _step(runtime, record, "safeguard_not_verified", problems[0])
        if record["safeguard"].get("install") == "refused":
            return _finish(runtime, record, "rejected", "safeguard refused by the device",
                           reason_code=getattr(adapter, "REFUSED_REASON_CODE", "rollback_timer_pending"))
        if getattr(adapter, "discard_installation", None) is not None:
            # an adapter whose unfinished installation can block the device (NX-OS: a job armed before its checkpoint
            # holds it) removes at once what its own session proved it created, and nothing else
            return _discard_installation(runtime, adapter, access, record, plan, "safeguard not verified")
        return _finish(runtime, record, "unknown", "safeguard not verified")
    if problems:
        _step(runtime, record, "safeguard_not_verified", problems[0])
        cleaned = adapter.remove_safeguard(access, record, spec)
        if cleaned and not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted" if cleaned else "unknown", "safeguard not verified")
    runtime.store.save(record)
    _step(runtime, record, "safeguard_verified")
    if record.get("kind") == "poe-cycle":
        from netops_admin import exos_poe
        return exos_poe.run(runtime, adapter, access, record, plan, device, due)
    if watched:
        refused = adapter.before_write(access, record, timer_end - runtime.monotonic(), device)
        if refused is not None:
            _step(runtime, record, "change_not_written", refused)
            return _settle_after_expiry(runtime, access, record, plan, "no time left to write", due)
        guard = getattr(adapter, "line_guard_for", None)
        if guard is not None:
            # an adapter whose change session ends with a commit that restarts the timer (Junos) judges each line
            # itself: the lines up to that commit need the time of the commit, the lines after it nothing more
            access.line_guard = guard(plan["commands"], lambda: timer_end - runtime.monotonic())
        else:
            access.line_guard = lambda: adapter.line_allowed(timer_end - runtime.monotonic())
    _step(runtime, record, "change_start")
    sent = runtime.monotonic()
    try:
        try:
            access.apply(plan["commands"], spec)
        finally:
            if watched:
                access.line_guard = None
        _step(runtime, record, "change_applied")
    except Exception as exc:
        _step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return _settle_after_expiry(runtime, access, record, plan, "change failed", due)
    answered = runtime.monotonic()
    rearmed = getattr(adapter, "safeguard_rearmed", None)
    if rearmed is not None:
        # the change commit restarted the device timer (Junos commit confirmed): its expiry moves with it
        try:
            problems = rearmed(access, record)
        except Exception as exc:
            problems = ["the timer after the change is unreadable (%s)" % type(exc).__name__]
        runtime.store.save(record)
        if problems:
            _step(runtime, record, "safeguard_rearm_unverified", problems[0])
            return _settle_after_expiry(runtime, access, record, plan, "safeguard not verified after the change", due)
        _step(runtime, record, "safeguard_rearmed", record["safeguard"].get("device_expiry") or record["safeguard"]["fire_at"])
        if watched:
            # the restarted timer protects the readback and the confirmation (counted on the monotonic clock)
            timer_end = due = _restarted_end(adapter, device, record, requested, sent, answered)
    cause = "administrator table"
    try:
        after_text = access.snapshot()
        if adapter.accounts_check(access, device, after_text) != record["accounts"]:
            raise Rejected(["the administrator accounts changed during the operation"])
        cause = "postcheck rejected"
        verdict = engine.verify(plan, after_text.encode("utf-8"), expect="after")
    except Rejected as exc:
        cause = getattr(exc, "category", cause)
        _step(runtime, record, "postcheck_failed", cause)
        return _settle_after_expiry(runtime, access, record, plan, cause, due)
    except Exception as exc:
        _step(runtime, record, "postcheck_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "postcheck unavailable", due)
    if verdict["result"] != "match":
        _step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return _settle_after_expiry(runtime, access, record, plan, "prediction mismatch", due)
    if schema_runtime.is_plan(plan):
        schema_runtime.bind_generated(plan, verdict["generated_bindings"])
    _step(runtime, record, "postcheck_passed")
    try:
        policy = record.get("audit_policy")
        audited = prediction.audited(after_text, plan)
        if schema_runtime.is_plan(plan):
            found, record["audit_coverage"] = schema_runtime.after_audit(plan, record["audit_before"], audited, policy)
        else:
            record["audit_coverage"] = audit_gate.evaluate(device.platform, audited, policy, plan["table"],
                                                           record["audit_before"])
            audit_gate.check_policy(plan, policy, audited, record["audit_before"])
            found = audit_gate.new_blocking(device.platform, record["audit_before"], audited, device.name, policy,
                                            fortios.SAFEGUARD_PREFIX + record["change_id"][:12] + "-")
    except audit_gate.Incomplete as exc:
        _step(runtime, record, "audit_incomplete", exc.summary)
        return _settle_after_expiry(runtime, access, record, plan, "audit incomplete", due)
    except Exception as exc:
        _step(runtime, record, "audit_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "audit unavailable", due)
    if found:
        record["audit_findings"] = found
        _step(runtime, record, "audit_failed", "%d new findings" % len(found))
        return _settle_after_expiry(runtime, access, record, plan, "audit finding", due)
    _step(runtime, record, "audit_passed", "%d rules, %d findings before, none new%s"
          % (audit_gate.rule_count(device.platform), audit_gate.finding_count(record["audit_before"]),
             audit_gate.unevaluated_note(record["audit_before"])))
    try:
        seen = engine.observed_state(plan, adapter.observe(access, plan))
    except Exception as exc:
        _step(runtime, record, "check_identity_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "check identity unavailable", due)
    if seen != plan["predicted"]["after"]:
        _step(runtime, record, "check_identity_failed", "state differs")
        return _settle_after_expiry(runtime, access, record, plan, "check identity mismatch", due)
    _step(runtime, record, "check_identity_passed")
    if record.get("kind") == "enrollment":
        return _settle_after_expiry(runtime, access, record, plan, "enrollment self-test", due)
    try:
        if watched:
            remaining = timer_end - runtime.monotonic()
        else:
            remaining = (_fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception:
        remaining = -1
    if remaining < device.confirm_margin_seconds:
        _step(runtime, record, "confirm_skipped", "too close to the safeguard")
        return _settle_after_expiry(runtime, access, record, plan, "no time left to confirm", due)
    try:
        last = access.snapshot().encode("utf-8")
        final = engine.verify(plan, last, expect="after")
    except Exception as exc:
        _step(runtime, record, "final_check_failed", type(exc).__name__)
        return _settle_after_expiry(runtime, access, record, plan, "final check unavailable", due)
    if final["result"] != "match":
        _step(runtime, record, "final_check_failed", "%d differences" % len(final["differences"]))
        record["final_check_differences"] = final["differences"]
        fired = "safeguard fired during confirmation" if _returned(plan, last) else "foreign change"
        return _settle_after_expiry(runtime, access, record, plan, fired, due)
    _step(runtime, record, "confirm_start")
    if not adapter.remove_safeguard(access, record, spec):
        _step(runtime, record, "confirm_unverified")
        return _settle_after_expiry(runtime, access, record, plan, "confirmation unverified", due)
    try:
        text = access.snapshot().encode("utf-8")
        removed = engine.verify(plan, text, expect="after")
    except Exception as exc:
        _step(runtime, record, "removal_check_failed", type(exc).__name__)
        return _finish(runtime, record, "unknown", "final check unavailable")
    if removed["result"] != "match":
        _step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        if _returned(plan, text):
            return _finish(runtime, record, "reverted", "safeguard fired during confirmation")
        return _finish(runtime, record, "unknown", "foreign change after the safeguard was removed",
                       removed["differences"])
    if not _persist(runtime, adapter, access, record):
        return _finish(runtime, record, "confirmed", "not persisted")
    if record["steps"][-1]["step"] == "configuration_saved":
        try:
            saved = engine.verify(plan, access.snapshot().encode("utf-8"), expect="after")
        except Exception as exc:
            _step(runtime, record, "saved_check_failed", type(exc).__name__)
            return _finish(runtime, record, "confirmed", "saved configuration unverified")
        if saved["result"] != "match":
            _step(runtime, record, "saved_check_failed", "%d differences" % len(saved["differences"]))
            return _finish(runtime, record, "confirmed", "foreign change during save", saved["differences"])
    return _finish(runtime, record, "confirmed")


def _execute_compensating(runtime, adapter, access, record, plan, device) -> dict:
    """The change on a platform without an on-device timer (FortiADC): written, read back by the write and the check
    account and confirmed; any failure after the write is returned by the inverse in this run (_compensate)."""
    record["safeguard"] = {"fire_at": "none", "name": adapter.safeguard_label(record["change_id"]),
                           "mechanism": adapter.RETURN_MECHANISM}
    runtime.store.save(record)
    _step(runtime, record, "compensation_armed", "no on-device timer; an unverified change is returned in this run")
    _step(runtime, record, "change_start")
    try:
        access.apply(plan["commands"], _spec(record))
        _step(runtime, record, "change_applied")
    except Exception as exc:
        _step(runtime, record, "change_failed", "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        return _compensate(runtime, adapter, access, record, plan, "change failed")
    cause = "administrator table"
    try:
        after_text = access.snapshot()
        if adapter.accounts_check(access, device, after_text) != record["accounts"]:
            raise Rejected(["the administrator accounts changed during the operation"])
        cause = "postcheck rejected"
        verdict = engine.verify(plan, after_text.encode("utf-8"), expect="after")
    except Rejected as exc:
        cause = getattr(exc, "category", cause)
        _step(runtime, record, "postcheck_failed", cause)
        return _compensate(runtime, adapter, access, record, plan, cause)
    except Exception as exc:
        _step(runtime, record, "postcheck_failed", type(exc).__name__)
        return _compensate(runtime, adapter, access, record, plan, "postcheck unavailable")
    if verdict["result"] != "match":
        _step(runtime, record, "postcheck_failed", "%d differences" % len(verdict["differences"]))
        record["postcheck_differences"] = verdict["differences"]
        return _compensate(runtime, adapter, access, record, plan, "prediction mismatch")
    _step(runtime, record, "postcheck_passed")
    _step(runtime, record, "audit_not_run", adapter.AUDIT_NOT_RUN[2])
    try:
        seen = engine.observed_state(plan, adapter.observe(access, plan))
    except Exception as exc:
        _step(runtime, record, "check_identity_failed", type(exc).__name__)
        return _compensate(runtime, adapter, access, record, plan, "check identity unavailable")
    if seen != plan["predicted"]["after"]:
        _step(runtime, record, "check_identity_failed", "state differs")
        return _compensate(runtime, adapter, access, record, plan, "check identity mismatch")
    _step(runtime, record, "check_identity_passed")
    if record.get("kind") == "enrollment":
        return _compensate(runtime, adapter, access, record, plan, "enrollment self-test")
    _step(runtime, record, "confirm_start")
    if not _persist(runtime, adapter, access, record):
        return _finish(runtime, record, "confirmed", "not persisted")
    return _finish(runtime, record, "confirmed")


def _returned(plan, text) -> bool:
    try:
        return engine.verify(plan, text, expect="before")["result"] == "match"
    except Exception:
        return False


def _stored_plan(runtime, record) -> dict:
    try:
        return engine._read_plan(record.get("plan"))
    except Rejected:
        raise runtime.store.unreadable(runtime.store.operations / ("%s.json" % record["change_id"])) from None


def undo_request(record, reason: str):
    if record is not None and record.get("kind") == "poe-cycle":
        raise Rejected([NO_UNDO], reason_codes=["undo_not_applicable"])
    if record is None or record.get("status") != "finished" or record.get("result") != "confirmed":
        raise Rejected(["only a confirmed operation can be undone"])
    plan = engine._read_plan(record.get("plan"))
    if schema_runtime.is_plan(plan):
        return schema_runtime.undo_request(record, reason)
    if plan["firmware"] is None:
        raise Rejected(["the plan of the operation names no firmware"])
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
    if op == "update":
        for name, values in (profile.value_requires or {}).items():
            value = changes.get(name)
            if value is None and name in changes:
                value = profile.attributes[name].default
            for other in values.get(value, ()):
                changes.setdefault(other, before.get(other))
    for name in changes:
        attribute = profile.attributes.get(name)
        if attribute is None or not (changes[name] is None or isinstance(changes[name], str)):
            raise Rejected(["the plan of the operation holds attribute %s outside the profile" % shown(name)])
        if changes[name] is None and not attribute.unset and attribute.undo_to_default:
            changes[name] = attribute.default
        if attribute.type == "name-list":
            changes[name] = (changes[name] or "").split()
    body = {
        "device": record["device"], "table": plan["table"], "op": op, "key": plan["key"], "changes": changes,
        "reason": reason, "user_request": "undo of operation %s" % record["change_id"],
        "request_id": "undo-%s" % record["change_id"],
    }
    return parse_request(json.dumps(body).encode("utf-8")), after


def undo(runtime, change_id: str, reason: str) -> dict:
    original = runtime.store.operation(change_id)
    if original is not None and original.get("status") == "finished" and original.get("result") == "confirmed":
        _stored_plan(runtime, original)
    request, expected = undo_request(original, reason)
    try:
        return _apply_counted(runtime, original["device"], request, expected_before=expected, undo=True)
    except Rejected as exc:
        if exc.reasons == [REUSED_REQUEST]:
            raise Rejected([UNDO_DONE], reason_codes=["undo_already_done"]) from None
        raise


def preview_undo(runtime, change_id: str, reason: str) -> dict:
    """Every check of undo without a change: nothing is written to the device, the journal or a notification."""
    original = runtime.store.operation(change_id)
    try:
        if original is not None and original.get("status") == "finished" and original.get("result") == "confirmed":
            _stored_plan(runtime, original)
        request, expected = undo_request(original, reason)
        result, refused = _preview(runtime, original["device"], request, expected_before=expected, undo=True)
    except BudgetExhausted:
        raise
    except Rejected as exc:
        _count_rejection(runtime)
        if exc.reasons == [REUSED_REQUEST]:
            raise Rejected([UNDO_DONE], reason_codes=["undo_already_done"]) from None
        raise
    if result["result"] == "known-request":
        _count_rejection(runtime)
        raise Rejected([UNDO_DONE], reason_codes=["undo_already_done"],
                       reason_details=[{"code": "undo_already_done", "change_id": result["change_id"]}])
    if result["result"] == "rejected" and result.get("reasons") == [REUSED_REQUEST]:
        _count_rejection(runtime)
        raise Rejected([UNDO_DONE], reason_codes=["undo_already_done"])
    if refused:
        _count_rejection(runtime)
    return dict(result, undo_of=change_id, request_id=request.request_id)


def recover(runtime, device_name: str) -> list:
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %s is not configured" % shown(device_name)])
    settled = []
    with runtime.store.lock(device.name), _target_lock(device):
        for record in runtime.store.running(device.name):
            if "safeguard" not in record:
                _step(runtime, record, "recovery_start")
                settled.append(_finish(runtime, record, "rejected", "interrupted before any mutation",
                                       reason_code="interrupted_before_mutation"))
                continue
            plan = _stored_plan(runtime, record)
            adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan))
            _step(runtime, record, "recovery_start")
            try:
                access = runtime.access_factory(device)
                if schema_runtime.is_plan(plan):
                    access = schema_runtime.Access(access, device)
            except Exception as exc:
                _step(runtime, record, "recovery_access_failed", type(exc).__name__)
                settled.append(_finish(runtime, record, "unknown", "interrupted; device unreachable"))
                continue
            if (getattr(adapter, "discard_installation", None) is not None
                    and "change_start" not in {step.get("step") for step in record.get("steps", [])}):
                # the change was never sent: the safeguard (also an unfinished installation, which can block the
                # device when its job runs) is removed at once, as far as the own session proved it created it
                _step(runtime, record, "installation_interrupted", record["safeguard"].get("phase"))
                settled.append(_discard_installation(runtime, adapter, access, record, plan, "interrupted"))
                continue
            try:
                present = not adapter.safeguard_absent(access, record)
                disarmed = present and adapter.safeguard_disarmed(access, record)
            except Exception:
                settled.append(_finish(runtime, record, "unknown", "interrupted; safeguard state unreadable"))
                continue
            if disarmed:
                if not adapter.remove_remaining(access, record, _spec(record)):
                    _step(runtime, record, "safeguard_removal_unverified")
                    settled.append(_finish(runtime, record, "unknown", "safeguard cleanup unverified"))
                    continue
                _step(runtime, record, "safeguard_removed")
                present = False
            if present and record.get("kind") == "poe-cycle" and any(
                    step.get("step") == "confirm_start" for step in record.get("steps", [])):
                # the cycle may be done although its safeguard is installed: confirmed only on fresh proof
                from netops_admin import exos_poe
                settled.append(exos_poe.recover_installed(runtime, adapter, access, record, plan, device))
                continue
            if present:
                settled.append(_settle_after_expiry(runtime, access, record, plan, "interrupted",
                                                    runtime.monotonic() + device.safeguard_seconds))
                continue
            try:
                text = access.snapshot().encode("utf-8")
                is_after = engine.verify(plan, text, expect="after")["result"] == "match"
                is_before = engine.verify(plan, text, expect="before")["result"] == "match"
            except Exception:
                settled.append(_finish(runtime, record, "unknown", "interrupted; state unreadable"))
                continue
            steps = {step["step"] for step in record.get("steps", [])}
            if record.get("kind") == "poe-cycle" and is_before and "confirm_start" in steps:
                # the cycle ends on the before side: power was observed back on before confirm_start
                saved = _persist(runtime, adapter, access, record)
                settled.append(_finish(runtime, record, "confirmed",
                                       "confirmed before the interruption" if saved else "not persisted"))
            elif is_after and "confirm_start" in steps:
                saved = _persist(runtime, adapter, access, record)
                settled.append(_finish(runtime, record, "confirmed",
                                       "confirmed before the interruption" if saved else "not persisted"))
            elif is_before:
                saved = _persist(runtime, adapter, access, record)
                settled.append(_finish(runtime, record, "reverted", "interrupted" if saved else "not persisted"))
            elif is_after and _compensating(adapter):
                # no on-device timer returns it: the interrupted, unconfirmed change is returned now
                settled.append(_compensate(runtime, adapter, access, record, plan, "interrupted"))
            elif is_after:
                settled.append(_finish(runtime, record, "unknown",
                                       "interrupted; device state matches the after side but confirm_start is missing"))
            else:
                settled.append(_finish(runtime, record, "unknown", "interrupted; state matches neither side"))
        leftover = _unverified_safeguard(runtime, device.name)
        if leftover is not None:
            settled.append(_remove_unverified_safeguard(runtime, device, leftover))
    return settled


def _unverified_safeguard(runtime, device_name: str):
    blocked = runtime.store.blocked(device_name)
    record = None if blocked is None else runtime.store.operation(blocked["change_id"])
    if record is None or (record.get("status"), record.get("result"), record.get("reason")) != (
            "finished", "unknown", "safeguard not verified"):
        return None
    names = [step.get("step") for step in record.get("steps", [])]
    if "safeguard_not_verified" not in names or "change_start" in names or names[-1:] == ["safeguard_removed"]:
        return None
    return record


def _remove_unverified_safeguard(runtime, device, record) -> dict:
    plan = _stored_plan(runtime, record)
    adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan))
    _step(runtime, record, "recovery_start")
    try:
        access = runtime.access_factory(device)
        if schema_runtime.is_plan(plan):
            access = schema_runtime.Access(access, device)
        removed = adapter.remove_remaining(access, record, _spec(record))
    except Exception as exc:
        _step(runtime, record, "recovery_access_failed", type(exc).__name__)
        return record
    _step(runtime, record, "safeguard_removed" if removed else "safeguard_removal_unverified")
    return record


def unblock(runtime, device_name: str, reason: str) -> bool:
    if device_name not in runtime.config.devices:
        raise Rejected(["device %s is not configured" % shown(device_name)])
    runtime.audit.check_writable()
    with runtime.store.lock(device_name):
        blocked = runtime.store.blocked(device_name)
        removed = blocked is not None and runtime.store.unblock(device_name, blocked)
        if removed:
            runtime.store.clear_baseline(device_name)
            runtime.audit.event("administrative", device=device_name, action="unblock",
                                reason_characters=len(reason), change_id=blocked.get("change_id"))
        waived = 0
        for change_id in _undelivered(runtime, device_name):
            if _waived(runtime, change_id):
                runtime.audit.event("administrative", device=device_name, action="notification waived",
                                    reason_characters=len(reason), change_id=change_id)
                waived += 1
    return removed or waived > 0


def _waived(runtime, change_id: str) -> bool:
    changed = []

    def waive(current):
        if current.get("notification") not in UNDELIVERED:
            return False
        current["notification"] = "waived"
        changed.append(True)
        return True

    runtime.store.update(change_id, waive)
    return bool(changed)
