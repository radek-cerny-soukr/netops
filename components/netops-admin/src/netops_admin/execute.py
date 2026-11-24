from __future__ import annotations

import datetime
from contextlib import ExitStack, contextmanager
import hashlib
import json
import re
import secrets
import time

from netops_core import tested
from netops_core.target_lock import target_lock, TargetBusy, TargetLockError

from netops_admin import (
    audit, audit_gate, engine, enrollment, eos_l2, eos_save, eos_services,
    exec_eos, exec_exos, exec_exos_acl, exec_fortiadc, exec_fortios, exec_ios, exos_save, exos_services,
    exec_junos, exec_nxos, exec_ruckus, exec_schema_fortios, fortiadc, fortiadc_certificate_import,
    fortios, ios, ios_save, junos_clear, prediction, schema_runtime,
)
from netops_admin import eos_clear, fortios_lease, fortios_tables, nxos_clear
from netops_admin.schema_request import Transaction
from netops_admin.blocking import (BLOCKING_REASONS, BLOCKING_RESULTS, MCP_UNBLOCK_RESULTS, MCP_UNBLOCK_SIDE, blocks,
                                   unblock_digest)
from netops_admin.access import AccessError, operation
from netops_admin.config import SAFEGUARD_MAX_SECONDS
from netops_admin.errors import (SNAPSHOT_FIRMWARE_MISMATCH, BudgetExhausted, Rejected, SnapshotRejected,
                                 StateUnreadable, shown)
from netops_admin.profiles import find_profile, load_profiles
from netops_admin.request import BATCH, ProfileBatch, inverse_profile_changes, parse_request, profile_undo_request
from netops_admin.state import Store

EXPIRY_GRACE_SECONDS = 20
EXPIRY_POLL_SECONDS = 10
EXPIRY_WAIT_SLACK_SECONDS = 60
EXPIRY_WAIT_LIMIT_SECONDS = SAFEGUARD_MAX_SECONDS + EXPIRY_GRACE_SECONDS + EXPIRY_WAIT_SLACK_SECONDS
READ_FLOOR_SECONDS = 1.0
UNDELIVERED = ("pending", "failed", "sending")
ADAPTERS = {"fortios": exec_fortios, "exos": exec_exos, "eos": exec_eos, "ios": exec_ios, "iosxe": exec_ios, "fortiadc": exec_fortiadc, "nxos": exec_nxos,
            "junos": exec_junos, "ruckus": exec_ruckus}
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
NO_UNDO_BOUNCE = "a port bounce returns the configuration to its state before the operation; it has no undo"
# operations that end on the configuration before them (1.0.12 eos port maintenance: the EOS port bounce too)
CYCLE_KINDS = ("poe-cycle", "port-bounce")
CLEAR_KIND = "exos-clear"
CLEAR_KINDS = {"exos": CLEAR_KIND, "fortiadc": "fortiadc-clear", "junos": junos_clear.KIND, "nxos": nxos_clear.KIND,
               "eos": eos_clear.KIND, "fortios": fortios_lease.KIND, **dict.fromkeys(ios.PLATFORMS, "ios-clear")}
CLEAR_RETURN = "irreversible"
SAVE_KINDS = {"eos": eos_save.KIND, "exos": exos_save.KIND, "nxos": engine.nxos.SAVE_KIND,
              **dict.fromkeys(ios.PLATFORMS, ios_save.KIND)}
IRREVERSIBLE_KINDS = (*CLEAR_KINDS.values(), fortios.IPSEC_RECOVERY_KIND, *SAVE_KINDS.values())
UNBLOCK_CHANGED = ("the block, its operation or the state read on the device differs from the approved"
                   " admin_unblock_preview; run a new preview and approve its unblock_sha256")
MAX_UNBLOCK_REASON = 500
# 1.0.12 execution access r2 (review finding 1): the hash of an MCP undo or unblock is accepted only for the last preview of that
# kind this server issued for the device, once, within this time and while the journal of the device is unchanged
PREVIEW_TICKET_SECONDS = 600
PREVIEW_NOT_ISSUED = ("the hash is not the one of the last admin_%s_preview this server issued for the device, or"
                      " that preview was already presented, is older than %d seconds, or an operation or block of the"
                      " device changed since; run a new preview, show it to the person and use its hash")


def _generation(runtime, device_name: str) -> str:
    """The journal state of a device an issued preview is bound to: its operations with their status and result,
    and its block. Any operation, result or block (also one that ends where it began) makes another value."""
    operations = sorted([record["change_id"], record.get("status"), record.get("result")]
                        for record in runtime.store.records() if record.get("device") == device_name)
    document = {"operations": operations, "block": runtime.store.blocked(device_name)}
    data = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def _issue_preview(runtime, device_name: str, kind: str, subject: str, sha256: str) -> None:
    runtime.store.issue_preview(device_name, kind, {"subject": subject, "sha256": sha256,
                                                    "generation": _generation(runtime, device_name),
                                                    "issued_at": runtime.store.budget_now()})


def _redeem_preview(runtime, device_name: str, kind: str, subject: str, sha256: str, code: str) -> None:
    """Take the issued preview of the device; refuse unless it is the one of this subject and hash, fresh and issued
    for the current journal state. The record is used up by every attempt, so a hash is presented once."""
    ticket = runtime.store.take_preview(device_name, kind)
    if (ticket is None or ticket["subject"] != subject or ticket["sha256"] != sha256
            or not 0 <= runtime.store.budget_now() - ticket["issued_at"] <= PREVIEW_TICKET_SECONDS
            or ticket["generation"] != _generation(runtime, device_name)):
        raise Rejected([PREVIEW_NOT_ISSUED % (kind, PREVIEW_TICKET_SECONDS)], reason_codes=[code],
                       reason_details=[{"code": code, "expected": sha256}])


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


def _adapter(platform: str, schema=False, table=None):
    if platform == "exos" and table == engine.exos_acl.POLICY:
        return exec_exos_acl
    if platform in ("ios", "iosxe") and table == "vlan":
        from netops_admin import exec_ios_vlan
        return exec_ios_vlan
    if platform not in ADAPTERS:
        raise Rejected(["platform %s has no plan and apply adapter" % shown(platform)])
    return exec_schema_fortios if schema and platform == "fortios" else ADAPTERS[platform]


def _snapshot(access, adapter, table):
    text = access.snapshot()
    if adapter is exec_ruckus and table == engine.ruckus.RELAY_TABLE:
        return adapter.with_dhcp(access, text)
    if adapter is exec_fortiadc and table in (fortiadc.CERT_TABLE, fortiadc.CERT_GROUP, fortiadc.CERT_MEMBER):
        return adapter.with_certificates(access, text, table)
    return text


def _spec(record):
    adapter = _adapter(record["plan"]["platform"], schema_runtime.is_plan(record["plan"]), record["plan"]["table"])
    others = getattr(adapter, "plan_hostnames", None)
    if others is not None:
        # 1.0.12 junos port ownership: a Junos host-name change shows the new name in the prompt right after its commit
        return adapter.prompt_spec(record["hostname"], others(record["plan"], record["hostname"]))
    return adapter.prompt_spec(record["hostname"])


def _fire_at(record) -> datetime.datetime:
    return datetime.datetime.strptime(record["safeguard"]["fire_at"], FIRE_AT_FORMAT)


def _step(runtime, record, name, detail=None):
    record.setdefault("steps", []).append({"step": name, "at": audit.now_utc(), "detail": detail})
    runtime.store.save(record)
    runtime.audit.event("step", change_id=record["change_id"], device=record["device"], step=name, detail=detail)


def _started_batch_steps(record):
    return {event["detail"] for event in record["steps"] if event["step"] == "batch_step_start"}


def _start_batch_step(runtime, record, index):
    record["batch_results"][index - 1]["result"] = "started"
    _step(runtime, record, "batch_step_start", str(index))


def export_state(config) -> tuple:
    return audit.export_state(config.export_status_file, config.limits, audit_file=config.audit_file,
                              require_audit_file=config.export_status_require_audit_file)


def _finish(runtime, record, result, reason=None, differences=None, reason_code=None, *, verified_clear_config=False):
    record["status"] = "finished"
    record["finished_at_epoch"] = time.time()
    record["result"] = result
    record["reason"] = reason
    if result == "reverted" and record.get("batch_results"):
        # A failed step may have been refused before its write started.
        started_steps = _started_batch_steps(record)
        for step in record["batch_results"]:
            if str(step["index"]) in started_steps and step["result"] in ("started", "verified", "failed"):
                step.setdefault("rollback", "safeguard-verified")
                if step["result"] != "failed":
                    step["result"] = "reverted"
    if result == "rejected":
        # a refusal recorded here carries the same machine fields as a refusal raised before the operation
        record["reason_codes"] = [reason_code or "unspecified_refusal"]
        record["reason_details"] = []
    record["differences"] = differences or []
    state, _why = export_state(runtime.config)
    record["audit_delivery"] = "pending" if state in ("acknowledged", "pending") else state
    record["notification"] = "pending" if runtime.notifier is not None else "not-configured"
    if blocks(result, reason) and not verified_clear_config:
        runtime.store.block(record["device"], record["change_id"], reason or result)
        record["device_blocked"] = True
    elif result == "unknown":
        record["device_blocked"] = False
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
        # A retry can outlive the original block or use a journal written before the flag existed.
        blocked = runtime.store.blocked(record["device"]) is not None
        result = runtime.notifier(dict(record, device_blocked=blocked))
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
# request_prechecks(device, request) callable   None (skip): _prepared refuses a request by its target alone, before any
#                                             device contact (Ruckus: WLAN not selected); raises Rejected.
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
    plan = record["plan"]
    if adapter is exec_ios and record.get("kind") in CYCLE_KINDS and plan["platform"] == "iosxe":
        # A cycle restores its saved baseline.
        return True
    xe_service = plan["platform"] == "iosxe" and any(
        step["table"] in ios.ios_services.TABLES for step in plan.get("batch_steps", (plan,)))
    if xe_service or (adapter is exec_exos and plan["table"] in exos_services.TABLES):
        _step(runtime, record, "running_configuration_only")
        return True
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


def _adc_write_session_lost(adapter, access):
    return adapter is exec_fortiadc and getattr(access, "write_session_lost", lambda: False)()


def _defer_adc_compensation(runtime, record, reason):
    _step(runtime, record, "compensation_recovery_pending", "FortiADC state must be verified in a new write session")
    return _finish(runtime, record, "unknown", reason)


def _ruckus_relay_update(adapter, plan):
    return adapter is exec_ruckus and plan["table"] == engine.ruckus.RELAY_TABLE and plan["op"] == "update"


def _ruckus_relay_missing(plan, text):
    relays = engine.ruckus.load(text, plan["firmware"]).relays
    return relays is not None and all(name.casefold() != plan["key"].casefold() for name in relays)


def _defer_ruckus_relay_compensation(runtime, record):
    reason = "The DHCP relay profile may be missing. Run recover when its state can be read and restored."
    _step(runtime, record, "relay_recovery_pending", reason)
    return _finish(runtime, record, "unknown", reason)


def _adc_ha_compensation_failure(runtime, access, record, plan):
    try:
        exec_fortiadc.verify_ha_sync(access, runtime.sleep)
    except Rejected as exc:
        _step(runtime, record, "compensation_recovery_pending", exc.reason_codes[0])
        return _finish(runtime, record, "unknown", exc.reasons[0])
    try:
        observed = engine.observed_state(plan, exec_fortiadc.observe(access, plan))
        if observed == engine.check_view(plan, plan["predicted"]["before"]):
            return None
    except Exception:
        pass
    reason = "check account could not verify FortiADC compensation"
    _step(runtime, record, "compensation_recovery_pending", reason)
    return _finish(runtime, record, "unknown", reason)


def _compensate(runtime, adapter, access, record, plan, reason, *, recovering=False):
    """Return an unverified change of a platform without an on-device timer: the inverse is written in this run.

    The inverse is written only when the planned object is not in its state before; the result is then judged by a
    fresh snapshot against the side before, as after an on-device return."""
    _step(runtime, record, "compensation_start", reason)
    if adapter is exec_exos_acl:
        try:
            access.recover_stage()
        except Rejected:
            _step(runtime, record, "compensation_stage_unverified")
            return _finish(runtime, record, "unknown", "policy staging cleanup unverified")
    inverse_written = False
    if _adc_write_session_lost(adapter, access):
        return _defer_adc_compensation(runtime, record, reason)
    wlan_plan = adapter is exec_ruckus and plan["table"] == engine.ruckus.TABLE
    if wlan_plan and engine.ruckus.passphrase_only(plan):
        return _finish(runtime, record, "unknown", "%s. %s" % (reason, engine.ruckus.UNVERIFIED_PASSPHRASE))
    relay_update = _ruckus_relay_update(adapter, plan)
    restore_wlan = wlan_plan and plan["op"] == "delete"
    try:
        snapshot_text = _snapshot(access, adapter, plan["table"])
        verdict = engine.verify(plan, snapshot_text.encode("utf-8"), expect="before")
    except Exception as exc:
        _step(runtime, record, "compensation_state_unreadable", type(exc).__name__)
        if relay_update:
            return _defer_ruckus_relay_compensation(runtime, record)
        if recovering or _adc_write_session_lost(adapter, access):
            return _defer_adc_compensation(runtime, record, reason)
        verdict = None
    if verdict is None or not verdict["object_matches"]:
        inverse = plan["inverse"]
        if relay_update and _ruckus_relay_missing(plan, snapshot_text):
            inverse = engine.ruckus.render_relay_state(plan["key"], plan["predicted"]["before"], replace=False)
        if wlan_plan and plan["op"] == "create":
            # The inverse of a create deletes the WLAN. Preserve memberships added since the create.
            memberships = (adapter.group_memberships(access) if verdict is None
                           else engine.ruckus.load(snapshot_text, plan["firmware"]).group_memberships)
            try:
                engine.ruckus.require_group_membership(memberships, plan["key"], present=True)
            except Rejected as exc:
                if verdict is None:
                    return _finish(runtime, record, "unknown", exc.reasons[0])
                return _finish(runtime, record, "revert-failed", exc.reasons[0], verdict["differences"])
        if restore_wlan:
            if verdict is None:
                return _finish(runtime, record, "unknown", "cannot determine whether the WLAN is absent for recreation")
            if engine.ruckus.load(snapshot_text, plan["firmware"]).in_use(plan["key"]):
                return _finish(runtime, record, "revert-failed", "the WLAN still exists and differs from its previous state",
                               verdict["differences"])
            try:
                engine.ruckus.restoration_security(plan["predicted"]["before"])
            except Rejected as exc:
                return _finish(runtime, record, "revert-failed", exc.reasons[0], verdict["differences"])
        if adapter is exec_fortiadc:
            try:
                fortiadc.require_ha_write(access, plan.get("fortiadc_ha_role"))
            except Rejected as exc:
                _step(runtime, record, "compensation_recovery_pending", exc.reason_codes[0])
                return _finish(runtime, record, "unknown", exc.reasons[0], reason_code=exc.reason_codes[0])
        try:
            access.apply(inverse, _spec(record))
            inverse_written = True
            _step(runtime, record, "compensation_applied")
        except Exception as exc:
            _step(runtime, record, "compensation_failed",
                  "%s after %d lines" % (type(exc).__name__, getattr(exc, "accepted_lines", 0)))
        if _adc_write_session_lost(adapter, access):
            return _defer_adc_compensation(runtime, record, reason)
        try:
            snapshot_text = _snapshot(access, adapter, plan["table"])
            verdict = engine.verify(plan, snapshot_text.encode("utf-8"), expect="before")
        except Exception as exc:
            _step(runtime, record, "revert_unverified", type(exc).__name__)
            if restore_wlan:
                return _finish(runtime, record, "unknown", "WLAN recreation is unverified. If present, it has a new"
                               " passphrase to set in the Unleashed web interface.")
            if relay_update:
                return _defer_ruckus_relay_compensation(runtime, record)
            if recovering or _adc_write_session_lost(adapter, access):
                return _defer_adc_compensation(runtime, record, reason)
            return _finish(runtime, record, "unknown", reason)
        if restore_wlan and verdict["object_matches"]:
            warning = engine.ruckus.NEW_PASSPHRASE
            _step(runtime, record, "compensation_partial", warning)
            return _finish(runtime, record, "revert-failed", warning, verdict["differences"])
    else:
        _step(runtime, record, "compensation_not_needed", "the object is in its state before")
    if adapter is exec_fortiadc and plan.get("fortiadc_ha_role") == "primary":
        failure = _adc_ha_compensation_failure(runtime, access, record, plan)
        if failure is not None:
            return failure
    if verdict["result"] == "match":
        _step(runtime, record, "compensation_verified")
        if inverse_written and wlan_plan and plan["op"] == "update" and engine.ruckus.writes_passphrase(plan):
            _step(runtime, record, "compensation_partial", engine.ruckus.CHANGED_PASSPHRASE)
            reason = "%s. %s" % (reason, engine.ruckus.CHANGED_PASSPHRASE)
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        kept = reason if reason in BLOCKING_REASONS else "foreign change"
        return _finish(runtime, record, "reverted", kept, verdict["differences"])
    if relay_update and _ruckus_relay_missing(plan, snapshot_text):
        return _defer_ruckus_relay_compensation(runtime, record)
    return _finish(runtime, record, "revert-failed", reason, verdict["differences"])


# a failure that is returned by the expiry of the timer although the adapter can return at once: the enrollment
# self-test is left unconfirmed on purpose, and recover decides by the state of the timer
EXPIRY_ONLY_REASONS = ("enrollment self-test", "interrupted")


def _keeps_safeguard(adapter) -> bool:
    """The on-device safeguard is still installed after the immediate return of the adapter (NX-OS: configure replace
    leaves the scheduler job, the schedule and the checkpoint, which are removed only after the return is proven);
    IOS ends its own timer with configure revert now."""
    return getattr(adapter, "REVERT_NOW_KEEPS_SAFEGUARD", False) is True


def _exec_banner_lost(access, record, plan, text, verdict) -> bool:
    return (plan["platform"] == "ios" and record.get("exec_banner_before") is True
            and verdict["object_matches"] and not verdict["rest_matches"]
            and not exec_ios.has_exec_banner(text, plan["firmware"])
            and record["safeguard"].get("verified") is True
            and exec_ios.safeguard_state(access, record) == "fired")


def _block_exec_banner_loss(runtime, record, verdict):
    record["reason_codes"] = [exec_ios.EXEC_BANNER_LOST]
    return _finish(runtime, record, "unknown", exec_ios.EXEC_BANNER_LOST_REASON, verdict["differences"])


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
        returned = access.snapshot()
        verdict = engine.verify(plan, returned.encode("utf-8"), expect="before")
        banner_lost = _exec_banner_lost(access, record, plan, returned, verdict)
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        if keeps:
            # the safeguard is still armed and returns the change at its time
            return None
        return _finish(runtime, record, "unknown", reason)
    if banner_lost:
        return _block_exec_banner_loss(runtime, record, verdict)
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
        if plan["table"] == ios.MEMBER_TABLE:
            return _finish(runtime, record, "unknown", "EtherChannel return unverified", verdict["differences"])
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


def _settle_after_expiry(runtime, access, record, plan, reason, due, *, persist_failure="not persisted"):
    adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan), plan["table"])
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
        if verdict["object_matches"]:
            warnings = _checked_policy_return(access, plan, verdict)
            if warnings:
                record["warnings"] = warnings
        banner_lost = _exec_banner_lost(access, record, plan, after_expiry, verdict)
    except Exception as exc:
        _step(runtime, record, "revert_unverified", type(exc).__name__)
        return _finish(runtime, record, "unknown", reason)
    if banner_lost:
        return _block_exec_banner_loss(runtime, record, verdict)
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
            return _finish(runtime, record, "reverted", persist_failure)
        return _finish(runtime, record, "reverted", reason)
    if verdict["object_matches"]:
        if plan["table"] == ios.MEMBER_TABLE:
            return _finish(runtime, record, "unknown", "EtherChannel return unverified", verdict["differences"])
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
    counted = [record for record in records if "safeguard" in record or record.get("status") == "running"
               or (record.get("kind") in (*IRREVERSIBLE_KINDS, fortiadc_certificate_import.KIND)
                   and any(step["step"] == "change_start" for step in record["steps"]))]
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


def _write_preflight(runtime, device, changes=1):
    _budgets(runtime, device, changes)
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
    export, why = export_state(runtime.config)
    if export == "blocked":
        raise Rejected(["audit export is blocked: %s" % why])
    return export


def _check_accounts(runtime, adapter, access, device, text, *, preview=False):
    known = runtime.store.baseline(device.name)
    try:
        accounts = adapter.accounts_check(access, device, text)
        if known is not None and known != accounts:
            raise Rejected(["the administrator accounts changed since the last operation"])
    except Rejected as exc:
        if not preview and not isinstance(exc, SnapshotRejected):
            _block_accounts(runtime, device)
        raise
    return accounts


def _expected_plan(request, expected_plan_sha256):
    if expected_plan_sha256 is None:
        return None
    if not isinstance(expected_plan_sha256, str) or not PLAN_SHA256.fullmatch(expected_plan_sha256):
        raise Rejected(["expected_plan_sha256 must be 64 lowercase hexadecimal characters"])
    return expected_plan_sha256


def apply(runtime, device_name: str, request, expected_before=ANY_STATE, expected_plan_sha256=None) -> dict:
    # expected_plan_sha256 binds the apply to an approved preview; like expected_before it stays outside
    # Request.fingerprint, so a repeated request_id returns its operation whatever hash is sent
    try:
        expected_plan = _expected_plan(request, expected_plan_sha256)
        if not isinstance(request, Transaction) and getattr(request, "op", None) == "save" and expected_plan is None:
            device = runtime.config.devices.get(device_name)
            if device is not None and device.platform == "exos":
                raise Rejected(["save requires the approved preview's plan_sha256"],
                               reason_codes=["exos_save_preview_required"])
        if not isinstance(request, Transaction) and getattr(request, "op", None) == "clear" and expected_plan is None:
            raise Rejected(["clear requires the approved preview's plan_sha256"], reason_codes=["clear_preview_required"])
        if getattr(request, "table", None) == fortiadc.CERT_MEMBER and expected_plan is None:
            raise Rejected(["certificate replacement requires the approved preview's plan_sha256"],
                           reason_codes=["fortiadc_certificate_preview_required"])
        if getattr(request, "table", None) == fortios.POLICY_TABLE and expected_plan is None:
            raise Rejected(["a firewall policy change requires the approved preview's plan_sha256"],
                           reason_codes=["fortios_policy_preview_required"])
        if getattr(request, "table", None) in fortios.NAT_TABLES and expected_plan is None:
            raise Rejected(["a NAT object change requires the approved preview's plan_sha256"],
                           reason_codes=["fortios_nat_preview_required"])
    except Rejected:
        # a malformed or unsupported hash is a rejected apply like any other: zero device writes and
        # zero operation records, but the hourly budget of rejected requests counts it
        _count_rejection(runtime)
        raise
    ticket = (("save", request.fingerprint()) if getattr(request, "op", None) == "save" else None)
    return _apply_counted(runtime, device_name, request, expected_before, expected_plan=expected_plan, ticket=ticket)


def _apply_counted(runtime, device_name: str, request, expected_before=ANY_STATE, undo=False, expected_plan=None,
                   action=None, undo_plan=None, ticket=None) -> dict:
    try:
        return _apply(runtime, device_name, request, expected_before, undo=undo, expected_plan=expected_plan,
                      action=action, undo_plan=undo_plan, ticket=ticket)
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise


def _opt_in(device, request, undo=False) -> None:
    from netops_admin.config import OPT_IN_TABLES
    if isinstance(request, ProfileBatch):
        for change in request.changes:
            _opt_in(device, change, undo)
        return
    if isinstance(request, Transaction):
        for operation in request.operations:
            path = " ".join(operation["path"].replace("/", " ").split())
            for table in OPT_IN_TABLES:
                if path == table or path.startswith(table + " "):
                    raise Rejected(["schema transaction path %r is not supported: %s changes need the %s profile"
                                    % (operation["path"], table, table)])
        return
    if (device.platform == "fortiadc" and request.table == fortiadc.CERT_MEMBER
            and not getattr(device, "fortiadc_https_sha256", None)):
        raise Rejected(["configure the FortiADC HTTPS pin to enable certificate replacement"],
                       reason_codes=["fortiadc_certificate_input_invalid"])
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
    if isinstance(request, ProfileBatch):
        if device.platform not in engine.BATCH_PLATFORMS or action is not None:
            raise Rejected([engine.BATCH_UNSUPPORTED], reason_codes=["action_unsupported"])
        for change in request.changes:
            _action(device, change, None)
        return
    if getattr(request, "op", None) == "save" and device.platform == "exos":
        exos_save.validate(device.platform, request)
        return
    if device.platform == "exos" and request.table == exos_save.TABLE:
        raise Rejected(["startup-config accepts only save"], reason_codes=["action_unsupported"])
    if request.table == ios.WIRELESS_CLIENT:
        if device.platform != "iosxe" or request.op != "clear":
            raise Rejected(["wireless-client accepts clear on Catalyst 9800 IOS XE"],
                           reason_codes=["action_unsupported"])
        target = ios.clear_target(request.table, request.key, request.changes)
        if request.endpoint_impact is None or ios.clear_mac_address(request.endpoint_impact) != target.key:
            raise Rejected(["endpoint_impact must explicitly name the client MAC"],
                           reason_codes=["endpoint_impact_required"])
        return
    if getattr(request, "op", None) == "clear":
        if device.platform == "fortios" and request.table == fortios_lease.TABLE:
            # 1.0.12 dhcp dns FG-37: a lease release moves a client off its address: the request names the address
            if request.endpoint_impact is None:
                raise Rejected(["releasing a DHCP lease affects its client; endpoint_impact naming the request key is"
                                " required"], reason_codes=["endpoint_impact_required"])
            return
        if device.platform == "fortios" and request.table == fortios.SESSION_TABLE:
            if request.endpoint_impact is None or request.endpoint_impact != request.key:
                raise Rejected(["session clear requires endpoint_impact naming the request key"],
                               reason_codes=["endpoint_impact_required"])
            return
        if request.table in engine.CLEAR_TABLES.get(device.platform, ()) and (
                request.endpoint_impact is None or device.platform in (*ios.PLATFORMS, "fortios")):
            return
        raise Rejected(["clear is available for ExtremeXOS and Cisco IOS/IOS XE port-counters, fdb, iparp and neighbor-discovery,"
                        " NX-OS port-counters, mac-address-table, ip-arp and ipv6-neighbor,"
                        " Junos port-counters, fdb, arp, neighbor-discovery and bgp-neighbor-refresh,"
                        " EOS port-counters, mac-address-table, ip-arp, ipv6-neighbor and bgp-refresh,"
                        " FortiADC waf-block-ip, slb-session and slb-persistence, and FortiOS sessions, ipsec-tunnel and dhcp-lease (one IPv4 address)"],
                       reason_codes=["action_unsupported"])
    if getattr(request, "op", None) == "save":
        if device.platform in SAVE_KINDS and request.table == request.key == eos_save.TABLE \
                and not request.changes and request.endpoint_impact is None:
            return
        raise Rejected(["save takes the startup-config key and table with empty changes"],
                       reason_codes=["action_unsupported"])
    profile = load_profiles().get((device.platform, request.table))
    owner = None if profile is None else profile.action
    if device.platform == "exos" and (request.table, action) in (
            ("inline-power", "poe-cycle"), (engine.exos.BOUNCE_TABLE, "port-bounce")):
        if request.op != "update" or request.changes != {"admin-state": "disabled"}:
            raise Rejected(["ExtremeXOS cycles require update with admin-state=disabled"],
                           reason_codes=["action_unsupported"])
        return
    if owner == action and device.platform in ios.PLATFORMS and action is not None:
        # 1.0.12 ios port maintenance: the IOS cycles take the one change admin-state=disabled
        if request.op != "update" or request.changes != {"admin-state": "disabled"}:
            raise Rejected(["IOS cycles require update with admin-state=disabled"], reason_codes=["action_unsupported"])
        return
    if device.platform == "fortios" and action == owner and action in exec_fortios.ACTION_CHANGES:
        if request.op != "update" or request.changes != exec_fortios.ACTION_CHANGES[action]:
            required, = exec_fortios.ACTION_CHANGES[action].items()
            raise Rejected(["a FortiSwitch %s requires update with %s=%s" % (action, *required)],
                           reason_codes=["action_unsupported"])
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
    if isinstance(request, ProfileBatch):
        for change in request.changes:
            _measured(runtime, device, change)
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


def _known(runtime, device, request, action=None):
    known = runtime.store.request(request.request_id)
    if known is None:
        record = _journaled(runtime, device, request)
    else:
        if known["request_sha256"] != request.fingerprint() or known["device"] != device.name:
            raise Rejected([REUSED_REQUEST], reason_codes=["request_id_reused"])
        record = runtime.store.operation(known["change_id"])
        if record is None:
            raise runtime.store.unreadable(runtime.store.operations / ("%s.json" % known["change_id"]))
    if (record is not None and device.platform == "exos" and getattr(request, "table", None) == "inline-power"
            and (record.get("kind") == "poe-cycle") != (action == "poe-cycle")):
        raise Rejected([REUSED_REQUEST], reason_codes=["request_id_reused"])
    return record


def _journaled(runtime, device, request):
    found = [record for record in runtime.store.records() if record.get("request_id") == request.request_id]
    if any(record.get("request_sha256") != request.fingerprint() or record.get("device") != device.name
           for record in found):
        raise Rejected([REUSED_REQUEST], reason_codes=["request_id_reused"])
    return found[0] if found else None


def preview(runtime, device_name: str, request) -> dict:
    ticket = (("save", request.fingerprint()) if getattr(request, "op", None) == "save" else None)
    try:
        result, refused = _preview(runtime, device_name, request, ticket=ticket)
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise
    if refused:
        _count_rejection(runtime)
    return result


def _preview(runtime, device_name: str, request, expected_before=ANY_STATE, undo=False, action=None,
             undo_plan=None, ticket=None):
    # ticket (kind, subject): the preview is issued for the bound MCP action (1.0.12 execution access r2); every such preview first
    # withdraws the earlier one of the device, and only a ready preview is issued
    device = _target(runtime, device_name, request)
    _action(device, request, action)
    _opt_in(device, request, undo)
    _measured(runtime, device, request)
    adapter = _adapter(device.platform, isinstance(request, Transaction), request.table)
    with runtime.store.lock(device.name), _target_lock(device), ExitStack() as stack:
        if ticket is not None:
            runtime.store.withdraw_preview(device.name, ticket[0])
        missing = []
        try:
            known = _known(runtime, device, request, action)
            if known is not None:
                return {"result": "known-request", "device": device.name, "change_id": known["change_id"],
                        "reasons": ["request_id already started an operation; apply returns it without running again"]}, False
            prepared = _prepared(runtime, device, adapter, request, expected_before, False, stack, missing,
                                 undo=undo, undo_plan=undo_plan, action=action)
        except Rejected as exc:
            return ({"result": "rejected", "device": device.name, "reasons": list(exc.reasons), "reason_codes": list(exc.reason_codes), "reason_details": list(exc.reason_details)},
                    not isinstance(exc, BudgetExhausted))
        if ticket is not None and not missing:
            _issue_preview(runtime, device.name, ticket[0], ticket[1], prepared[4]["plan_sha256"])
    plan, audit_before, coverage = prepared[4], prepared[5], prepared[7]
    irreversible = plan["op"] in ("clear", "save")
    return {
        "result": "rejected" if missing else "ready",
        "reasons": [reason for exc in missing for reason in exc.reasons],
        "reason_codes": [code for exc in missing for code in exc.reason_codes],
        "reason_details": [detail for exc in missing for detail in exc.reason_details],
        "device": device.name,
        "platform": plan["platform"],
        "firmware": plan["firmware"],
        "firmware_support": plan.get("firmware_support"),
        "table": plan["table"],
        "op": plan["op"],
        "key": plan["key"],
        "predicted": plan["predicted"],
        "commands": list(plan["commands"]),
        "inverse_commands": len(plan["inverse"]),
        "prechecks": list(plan["prechecks"]),
        "rollback_evidence": plan["rollback_evidence"],
        **({"cycle_state": plan["cycle_state"]} if "cycle_state" in plan else {}),
        **({"port_impact": plan["port_impact"]} if "port_impact" in plan else {}),
        **({"endpoint_impact": plan["endpoint_impact"]} if plan["table"] == ios.WIRELESS_CLIENT else {}),
        **({"operations": [
            {field: step[field] for field in ("table", "op", "key", "predicted", "commands", "inverse",
                                            "prechecks", "firmware_support", "endpoint_impact", "port_impact")
             if field in step} for step in plan["batch_steps"]
        ]} if "batch_steps" in plan else {}),
        **({"policy_order": plan["policy_order"], "inverse_identity_changes": plan["inverse_identity_changes"]}
           if "policy_order" in plan else {}),
        "plan_sha256": plan["plan_sha256"],
        "audit_findings_before": audit_gate.finding_count(audit_before),
        "audit_unevaluated": audit_gate.unevaluated(audit_before),
        "audit_coverage": coverage,
        "safeguard_seconds": None if irreversible else device.safeguard_seconds,
        **({"return_mechanism": CLEAR_RETURN} if irreversible else
           {"return_mechanism": adapter.RETURN_MECHANISM} if _compensating(adapter) else {}),
        # 1.0.12 adc pool members r2: the FortiADC virtual servers whose service the change stops (maintain or disable)
        **({"service_outage": list(plan["service_outage"])} if "service_outage" in plan else {}),
    }, bool(missing)


def _clear_target(platform, request):
    if platform in ios.PLATFORMS:
        return ios.clear_target(request.table, request.key, request.changes)
    if platform == "nxos":
        return nxos_clear.target(request.table, request.key, request.changes)
    if platform == "eos":
        return eos_clear.target(request.table, request.key, request.changes)
    if platform == "fortios":
        if request.table == fortios.SESSION_TABLE:
            return fortios.clear_target(request.key, request.changes)
        if request.table == fortios_lease.TABLE:
            return fortios_lease.target(request.table, request.key, request.changes)
        return fortios.ipsec_target(request)
    module = {"fortiadc": fortiadc, "junos": junos_clear, "exos": engine.exos}[platform]
    return module.clear_target(request.table, request.key, request.changes)


def _prepared(runtime, device, adapter, request, expected_before, enrolling, stack, missing=None, undo=False,
              expected_plan=None, undo_plan=None, ticket=None, action=None):
    config = runtime.config
    transaction = isinstance(request, Transaction)
    batch = isinstance(request, ProfileBatch)
    clear_target = clear_firmware = None
    ha_role = None
    saving = not transaction and request.op == "save"
    g66 = adapter is exec_ios and not transaction and (saving or request.table in ios.ios_services.TABLES)
    xe_service = device.platform == "iosxe" and (
        (g66 and not saving) or (batch and any(step.table in ios.ios_services.TABLES for step in request.changes)))
    guard = getattr(adapter, "request_prechecks", None)
    if guard is not None and not transaction:
        # 1.0.12 wireless wlans: a request the platform refuses by its target alone (Ruckus: a WLAN Admin may not write) is
        # refused before the device is contacted
        guard(device, request)
    if not transaction and request.op == "clear":
        clear_target = _clear_target(device.platform, request)
    fos_clear = clear_target is not None and adapter is exec_fortios and request.table == fortios.SESSION_TABLE
    ios_clear = clear_target is not None and adapter is exec_ios
    count = len(request.operations) if transaction else len(request.changes) if batch else 1
    export = _write_preflight(runtime, device, count)
    try:
        access = stack.enter_context(operation(runtime.access_factory(device)))
        if transaction:
            access = schema_runtime.Access(access, device)
        if adapter is exec_exos_acl:
            access = exec_exos_acl.wrap_access(access, request.key)
        if fos_clear:
            model, clear_firmware, hostname = adapter.clear_identity(access)
            if adapter.clear_identity(access, check=True) != (model, clear_firmware, hostname):
                raise Rejected(["the FortiOS check account sees another device or scope"],
                               reason_codes=["clear_scope_unverified"])
            checksum = adapter.clear_checksum(access)
            if adapter.clear_checksum(access, check=True) != checksum:
                raise Rejected(["the FortiOS accounts see different configuration checksums"],
                               reason_codes=["clear_scope_unverified"])
            profiles = adapter.clear_query(access, "show system accprofile")
            accounts = _check_accounts(runtime, adapter, access, device, profiles, preview=missing is not None)
            before_text = _snapshot(access, adapter, request.table) if device.audit_policy else ""
        else:
            before_text = _snapshot(access, adapter, request.table)
            if adapter is exec_fortiadc:
                ha_role = fortiadc.require_ha_write(access)
                if ha_role == "primary" and expected_plan is None and missing is None and not enrolling and not undo:
                    raise Rejected(["FortiADC HA apply requires the approved preview's plan_sha256"],
                                   reason_codes=["fortiadc_ha_preview_required"])
            accounts = _check_accounts(runtime, adapter, access, device, before_text, preview=missing is not None)
            # a clear installs no safeguard, so the safeguard of someone else's operation does not concern it
            lease_clear = clear_target is not None and adapter is exec_fortios and request.table == fortios_lease.TABLE
            leftovers = ([] if g66 or lease_clear or (clear_target is not None and adapter in (exec_ios, exec_nxos, exec_junos, exec_eos))
                         else adapter.leftovers(access))
            if leftovers:
                raise Rejected(["a safeguard of an earlier operation is still installed: %s" % ", ".join(leftovers)])
            hostname = adapter.hostname(access, before_text)
            spec = adapter.prompt_spec(hostname)
        if not (ios_clear or fos_clear):
            if clear_target is not None and adapter in (exec_nxos, exec_eos):
                # a clear writes no configuration: the preconditions of a timed return do not apply
                clear_firmware, reasons = adapter.clear_device_prechecks(access, device, before_text), []
            elif clear_target is not None and adapter is exec_junos:
                reasons = adapter.prechecks(access, device, before_text, spec, clearing=True)
            elif adapter is exec_exos and (saving or request.table in exos_services.TABLES):
                reasons = adapter.prechecks(access, device, before_text, spec, allow_unsaved=True)
            elif xe_service:
                reasons = adapter.prechecks(access, device, before_text, spec, allow_unsaved=True)
            elif saving:
                reasons = adapter.prechecks(access, device, before_text, spec, saving=True)
            else:
                reasons = adapter.prechecks(access, device, before_text, spec)
            if reasons:
                raise Rejected(reasons)
            ports = (adapter.ports(access, request.table, request.changes) if adapter is exec_exos
                     else adapter.ports(access, request.table))
    except SnapshotRejected as exc:
        if g66 and exc.category != SNAPSHOT_FIRMWARE_MISMATCH:
            code = ios_save.UNREADABLE if saving else "ios_service_read_unreadable"
            raise Rejected(["the IOS running configuration is incomplete or unreadable"], reason_codes=[code]) from None
        raise
    except Rejected:
        raise
    except Exception as exc:
        if batch and isinstance(exc, AccessError):
            raise adapter.batch_read_error(exc) from None
        if adapter is exec_nxos and isinstance(exc, AccessError) and (
                saving or request.table in engine.nxos.SERVICE_TABLES):
            raise exec_nxos.service_read_error(exc, saving=saving) from None
        if adapter is exec_ios and not transaction and request.table in ios.DHCP_TABLES and isinstance(
                exc, (AccessError, TimeoutError)):
            raise exec_ios.dhcp_read_failure(exc) from None
        if g66 and isinstance(exc, AccessError):
            timed_out = re.search(r"timeout|timed out|within", str(exc), re.I)
            code = (ios_save.TIMEOUT if timed_out else ios_save.UNREADABLE) if saving else (
                "ios_service_read_timeout" if timed_out else "ios_service_read_unreadable")
            raise Rejected(["the IOS device read failed before any change"], reason_codes=[code]) from None
        if ios_clear and isinstance(exc, AccessError):
            raise exec_ios.clear_access_error(exc, clear_target) from None
        if ios_clear or (clear_target is not None and adapter is exec_fortiadc):
            platform = "IOS" if ios_clear else "FortiADC"
            raise Rejected(["the %s configuration could not be read before the clear" % platform],
                           reason_codes=["clear_readback_unreadable"]) from None
        if fos_clear:
            raise Rejected(["the FortiOS configuration could not be read before the clear"],
                           reason_codes=["clear_readback_unreadable"]) from None
        raise Rejected(["the device could not be read before any change: %s" % exc]) from None
    if clear_target is not None and adapter is exec_fortios and request.table == fortios.IPSEC_TUNNEL:
        observed = exec_fortios.prepare_ipsec(access, device, before_text, clear_target)
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed)
    elif saving and adapter is exec_exos:
        plan, denied = exos_save.prepare(access, device, request, before_text, spec)
        if denied is not None:
            if missing is None:
                raise denied
            missing.append(denied)
    elif fos_clear:
        observed = adapter.clear_checked_observation(access, clear_target, clear_firmware,
                                                     protected=device.protected)
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed, firmware=clear_firmware,
                                       model=model, checksum=checksum)
    elif clear_target is not None and adapter is exec_fortiadc:
        firmware, observed = adapter.clear_prechecks(access, device, adapter.prompt_spec(hostname),
                                                     clear_target, before_text)
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed, firmware=firmware)
    elif ios_clear:
        observed = exec_ios.clear_prechecks(access, device, clear_target, before_text)
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed)
    elif clear_target is not None and adapter is exec_fortios:
        try:
            observed = exec_fortios.observe_clear(access, clear_target)
        except Rejected:
            raise
        except Exception as exc:
            raise Rejected(["the device could not be read before any change: %s" % exc]) from None
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed)
    elif clear_target is not None:
        observed = adapter.observe_clear(access, request.table, clear_target)
        try:
            checked = adapter.clear_prechecks(access, device, request.table, clear_target, observed, before_text)
        except Rejected:
            raise
        except Exception as exc:
            raise Rejected(["the device could not be read before any change: %s" % exc]) from None
        plan = engine.build_clear_plan(device, before_text, request, clear_target, observed, firmware=clear_firmware)
        plan["prechecks"].extend(checked)
    elif saving and adapter is exec_ios:
        plan = engine.build_save_plan(device, before_text, request, ios_save.read(access, device.firmware, before_text))
    elif saving:
        diff = (exec_nxos.read_save_diff(access) if adapter is exec_nxos else eos_save.read_diff(access))
        plan = engine.build_save_plan(device, before_text, request, diff)
        if adapter is exec_eos:
            try:
                eos_save.compare_check(access, diff)
            except Rejected as exc:
                if missing is None:
                    raise
                missing.append(exc)
    elif transaction:
        plan = schema_runtime.build(device, request, before_text, enrolling=enrolling)
    elif batch:
        batch_options = {"baseline_text": before_text} if adapter is exec_junos else {}
        # a firewall policy a batch recreates keeps its UUID only when the device lets a user set it
        policy_restore = adapter is exec_fortios and any(
            change.table == fortios.POLICY_TABLE and (change.op == "delete" or undo_plan is not None)
            for change in request.changes)
        manual_uuid = policy_restore and exec_fortios.manual_policy_uuid(access)
        plan, batch_prediction = engine.build_batch(
            device.platform, before_text.encode("utf-8"), request, device.firmware, device.protected,
            device=device.name, undo_plan=undo_plan, manual_policy_uuid=manual_uuid,
            check=lambda step, text, earlier: adapter.batch_prechecks(
                access, device, step, text, earlier, undo=undo, **batch_options))
        if xe_service:
            plan["prechecks"].append("The IOS XE service batch changes running configuration only")
    else:
        policy_restore = adapter is exec_fortios and request.table == fortios.POLICY_TABLE and (
            request.op == "delete" or (undo_plan is not None and undo_plan["op"] == "delete"))
        manual_uuid = policy_restore and exec_fortios.manual_policy_uuid(access)
        plan = engine.build_plan(device.platform, before_text.encode("utf-8"), request,
                                 firmware=device.firmware, protected=device.protected, enrollment_probe=enrolling,
                                 ports=ports, undo=undo, device=device.name, undo_plan=undo_plan,
                                 manual_policy_uuid=manual_uuid)
    try:
        reasons = [] if saving or clear_target or batch else adapter.plan_prechecks(
            access, device, plan, before_text,
            **({"undo": True} if undo and adapter in (exec_ios, exec_eos, exec_fortiadc, exec_exos, exec_nxos) else {}))
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
    # a FortiOS batch is written step by step, so the limit applies to each step (the safeguard script limit to all)
    sized = ([step for step in plan["batch_steps"]] if batch and plan["platform"] == "fortios" else [plan])
    if any(len(step[field]) > config.limits["plan_commands"] for step in sized for field in ("commands", "inverse")):
        raise Rejected(["the plan holds more than %d commands" % config.limits["plan_commands"]])
    if undo_plan and engine.tracks_registered_fortios_uuid(undo_plan):
        uuid = fortios.object_uuid(expected_before.get("uuid"))
        if uuid is None:
            raise Rejected(["the original operation has no verified object identity"])
        snapshot = fortios.load(before_text, plan["firmware"])
        entry = (snapshot.entries(plan["table"]) or {}).get(plan["key"])
        if entry is None or fortios.object_uuid(entry.value("uuid")) != uuid:
            raise Rejected(["the object identity differs from the original creation"],
                           reason_codes=["undo_identity_mismatch"])
        expected_before = undo_plan["predicted"]["after"]
    if expected_before is not ANY_STATE:
        observed = plan["predicted"]["before"]
        if undo_plan and plan["platform"] == "fortios" and plan["table"] == fortios.SWITCH_PORT:
            observed = engine.check_view(undo_plan, observed)
        if undo_plan and plan["platform"] == "eos" and plan["table"] == "interface" and "state_schema" not in undo_plan:
            observed = engine.eos.legacy_interface_state(observed)
            expected_before = engine.eos.legacy_interface_state(expected_before)
        if undo_plan and plan["platform"] == "exos" and plan["table"] == "ports" and "state_schema" not in undo_plan:
            observed = {name: value for name, value in observed.items() if name != "description-string"}
        if undo_plan and plan["platform"] == "junos" and plan["table"] == "interface" and "state_schema" not in undo_plan:
            # Before junos port maintenance, link parameters were outside the object state and stayed untouched by an undo.
            link = set(engine.junos.LINK_PARAMETERS)
            if all(link.isdisjoint(state or {}) for state in undo_plan["predicted"].values()):
                observed = {name: value for name, value in observed.items() if name not in link}
        if (undo_plan and plan["platform"] == "ruckus" and plan["table"] == engine.ruckus.TABLE
                and expected_before is not None and observed is not None
                and engine.ruckus.SECURITY_FIELDS.keys().isdisjoint(expected_before)):
            observed = {name: value for name, value in observed.items() if name not in engine.ruckus.SECURITY_FIELDS}
        if (undo_plan and plan["platform"] == "fortios" and plan["table"] == fortios.POLICY_TABLE
                and undo_plan["op"] == "create" and expected_before is not None and "uuid" not in expected_before):
            observed = {name: value for name, value in observed.items() if name != "uuid"}
        if observed != expected_before:
            raise Rejected(["the object differs from the state the undo was planned against"])
    if undo_plan and "exos_acl_file_sha256" in plan:
        if plan["exos_acl_file_sha256"] != undo_plan.get("exos_acl_file_sha256"):
            engine.exos_acl.unsafe("ExtremeXOS policy file changed since the original attachment operation")
    if device.platform == "exos" and action in CYCLE_KINDS:
        plan["cycle_action"] = action
    if ha_role == "primary":
        plan["fortiadc_ha_role"] = ha_role
        plan["prechecks"].append("FortiADC primary with a synchronized secondary")
    if {"cycle_state", "port_impact", "cycle_action", "acl_attachment_links", "link_before",
        "exos_acl_file_sha256", "fortiadc_ha_role"}.intersection(plan):
        plan["plan_sha256"] = engine.plan_digest(plan)
    if expected_plan is not None and ticket is not None:
        # 1.0.12 execution access r2: MCP undo - the hash must be the one of the issued undo preview (used up here), and the
        # refusal never names the current plan_sha256, which the action would accept
        _redeem_preview(runtime, device.name, ticket[0], ticket[1], expected_plan, "plan_changed")
        if plan["plan_sha256"] != expected_plan:
            raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"],
                           reason_details=[{"code": "plan_changed", "expected": expected_plan}])
    elif expected_plan is not None and plan["plan_sha256"] != expected_plan:
        raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"],
                       reason_details=[{"code": "plan_changed", "expected": expected_plan,
                                        "actual": plan["plan_sha256"]}])
    try:
        policy = device.audit_policy
        plan["device"] = device.name
        if clear_target is not None or saving:
            predicted_text = before_text
        elif batch:
            predicted_text = batch_prediction
        else:
            predicted_text = (prediction.audited(prediction.snapshot_after(before_text, plan), plan)
                              if transaction or _audited_rules(adapter) else None)
        if fos_clear and not policy:
            rule, why = "fortios.session-clear", "runtime-only, configuration verified by device checksum"
            audit_before = {audit_gate.UNEVALUATED + rule: (rule, audit_gate.NOT_EVALUATED, why)}
            coverage, predicted_findings = {rule: audit_gate.NOT_EVALUATED}, []
        elif not transaction and not _audited_rules(adapter):
            rule, state, why = adapter.AUDIT_NOT_RUN
            audit_before, coverage = {audit_gate.UNEVALUATED + rule: (rule, state, why)}, {rule: state}
            predicted_findings = []
        elif transaction:
            audit_before, _before_coverage = schema_runtime.audit_snapshot(plan, before_text, policy, None,
                                                                           audit_gate.BASELINE)
            predicted_findings, coverage = schema_runtime.after_audit(plan, audit_before, predicted_text, policy)
        else:
            audit_before = audit_gate.baseline(device.platform, prediction.audited(before_text, plan), device.name, policy)
            if (undo_plan and adapter is exec_exos and plan["table"] == exos_services.SYSLOG
                    and undo_plan["op"] == "create" and plan["op"] == "delete"
                    and plan["rest_sha256"] == undo_plan["rest_sha256"]):
                # An exact return to the approved pre-create state may restore the finding that the creation removed.
                restored = audit_gate.baseline(device.platform, predicted_text, device.name, policy)
                audit_before.update({key: item for key, item in restored.items()
                                     if item[0] == "exos.logging.no-syslog-target"})
            coverage = audit_gate.evaluate(device.platform, predicted_text, policy, audit_gate.plan_tables(plan),
                                           audit_before)
            audit_gate.check_policy(plan, policy, predicted_text, audit_before)
            predicted_findings = audit_gate.new_blocking(device.platform, audit_before, predicted_text, device.name, policy)
        if predicted_findings:
            raise Rejected(["predicted audit findings: " + ", ".join(predicted_findings)])
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected(["the auditor could not evaluate the snapshot before the change (%s)"
                        % type(exc).__name__]) from None
    if clear_target is not None or saving or batch:
        return access, before_text, accounts, hostname, plan, audit_before, policy, coverage
    try:
        observed = (adapter.observe(access, plan, before=True)
                    if "acl_attachment_links" in plan or "policy_order" in plan else adapter.observe(access, plan))
        seen = engine.observed_state(plan, observed)
    except Rejected as exc:
        raise Rejected(["the check account answer about the object before the change was refused: %s"
                        % "; ".join(exc.reasons)], reason_codes=exc.reason_codes, reason_details=exc.reason_details) from None
    except Exception as exc:
        raise Rejected(["the check account could not read the object before the change (%s)"
                        % type(exc).__name__]) from None
    if seen != engine.check_view(plan, plan["predicted"]["before"]):
        raise Rejected(["the check account sees the object in another state than the snapshot"])
    return access, before_text, accounts, hostname, plan, audit_before, policy, coverage


# a save keeps the reason code it had before every apply required the approved preview
SAVE_PREVIEW_REQUIRED = {"eos": "eos_save_preview_required", "nxos": "nxos_save_preview_required",
                         "ios": "ios_save_preview_required", "iosxe": "ios_save_preview_required",
                         "exos": "exos_save_preview_required"}


def _plan_required(device, request, expected_plan, *, undo=False, enrolling=False) -> None:
    """Every apply (profile request, batch, port action or schema Transaction) needs the approved preview's plan_sha256.

    A schema Transaction is planned from the same request (request_id included), snapshot and schema binding in
    preview and apply, so its preview's plan_sha256 is the one apply computes while nothing changed.
    Only undo (it replays a recorded operation) and the operator enrollment self-test are exempt.
    The check runs before the request journal and before any device connection."""
    if expected_plan is not None or undo or enrolling:
        return
    if request.op == "save":
        reason = SAVE_PREVIEW_REQUIRED.get(device.platform, "plan_changed")
    elif device.platform == "fortios" and request.table == fortios.PHASE2_TABLE:
        reason = "fortios_ipsec_preview_required"
    elif (device.platform == "fortios" and not isinstance(request, (Transaction, ProfileBatch))
          and fortios_tables.hooks(request.table) is not None):
        # 1.0.13 A1-R: every table of the FortiOS registry keeps the preview code of its registration
        reason = fortios_tables.hooks(request.table).preview_code
    else:
        reason = "plan_changed"
    what = ("a profile batch" if isinstance(request, ProfileBatch) else "a schema transaction"
            if isinstance(request, Transaction) else "the %s %s change" % (device.platform, request.table))
    raise Rejected(["%s requires the approved preview's plan_sha256" % what], reason_codes=[reason])


def _apply(runtime, device_name: str, request, expected_before, enrolling=False, undo=False, expected_plan=None,
           action=None, undo_plan=None, ticket=None) -> dict:
    device = _target(runtime, device_name, request)
    _action(device, request, action)
    _opt_in(device, request, undo)
    _measured(runtime, device, request)
    adapter = _adapter(device.platform, isinstance(request, Transaction), request.table)
    fingerprint = request.fingerprint()
    with runtime.store.lock(device.name), _target_lock(device), ExitStack() as stack:
        batch = isinstance(request, ProfileBatch)
        _plan_required(device, request, expected_plan, undo=undo, enrolling=enrolling)
        known = _known(runtime, device, request, action)
        if known is not None:
            return known
        access, before_text, accounts, hostname, plan, audit_before, policy, coverage = _prepared(
            runtime, device, adapter, request, expected_before, enrolling, stack, undo=undo, expected_plan=expected_plan,
            undo_plan=undo_plan, ticket=ticket, action=action)
        clear = plan["op"] == "clear"
        saving = plan["op"] == "save"
        irreversible = clear or saving
        profile = (None if isinstance(request, Transaction) or irreversible or batch
                   else find_profile(plan["platform"], plan["table"], plan["firmware"]))
        change_id = secrets.token_hex(16)
        if not irreversible:
            plan["safeguard_id"] = change_id
        if adapter is exec_exos_acl:
            access.bind_plan(plan)
        clear_kind = (fortios.IPSEC_RECOVERY_KIND if plan["table"] == fortios.IPSEC_TUNNEL
                      else CLEAR_KINDS.get(device.platform))
        record = {
            "change_id": change_id, "request_id": request.request_id, "request_sha256": fingerprint,
            "device": device.name, "status": "running", "result": None, "hostname": hostname,
            "plan": plan, "steps": [], "created_at": audit.now_utc(), "created_at_epoch": time.time(), "budget_at_epoch": runtime.store.budget_now(),
            "kind": (clear_kind if clear else SAVE_KINDS[device.platform] if saving
                     else ("enrollment" if enrolling else (action or "change"))),
            "budget_changes": len(request.operations) if isinstance(request, Transaction) else len(request.changes) if batch else 1,
            "audit_before": audit_before, "audit_policy": policy, "audit_coverage": coverage, "accounts": accounts,
        }
        if device.platform == "ios" and not irreversible:
            record["exec_banner_before"] = exec_ios.has_exec_banner(before_text, plan["firmware"])
        if batch:
            record["batch_results"] = [
                dict(index=index, table=step["table"], op=step["op"], key=step["key"], result="not-run")
                for index, step in enumerate(plan["batch_steps"], 1)]
        attribute_changes = request.changes if not isinstance(request, Transaction) else {}
        if "policy_order" in plan:
            attribute_changes, _position = fortios.policy_position(plan["op"], attribute_changes)
        if plan["platform"] == "fortios" and plan["table"] == fortios.PHASE2_TABLE:
            attribute_changes = {name: value for name, value in attribute_changes.items() if name != "copy-from"}
        if isinstance(request, Transaction):
            audit_changes = {"operation_count": len(request.operations),
                             "attribute_count": sum(len(x["changes"]) for x in request.operations)}
        elif batch:
            audit_changes = {"operation_count": len(request.changes),
                             "attribute_count": sum(len(x.changes) for x in request.changes)}
        elif irreversible:
            audit_changes = {}
        else:
            restore_defaults = engine.default_restorations(profile, attribute_changes, op=plan["op"], undo=undo)
            canonical = engine.canonical_changes(profile, attribute_changes, restore_defaults)
            audit_changes = audit.summarized_changes(profile, canonical)
        with runtime.store.admission():
            known = _known(runtime, device, request, action)
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
            changes=audit_changes,
            commands=len(plan["commands"]), inverse_commands=len(plan["inverse"]),
            safeguard=None if irreversible else adapter.safeguard_label(change_id),
            **({"firmware_tested": tested.is_tested(plan["firmware_support"])} if "firmware_support" in plan else {}),
        )
        try:
            record["foreign_sessions"] = adapter.foreign_sessions(access, device)
        except Exception as exc:
            record["foreign_sessions"] = None
            _step(runtime, record, "foreign_sessions_unreadable", type(exc).__name__)
        else:
            _step(runtime, record, "foreign_sessions", "%d other sessions" % record["foreign_sessions"])
        if clear:
            return _execute_clear(runtime, access, record, request)
        if saving:
            if adapter is exec_ios:
                return _execute_ios_save(runtime, access, record)
            save_operation = _execute_exos_save if adapter is exec_exos else _execute_save
            return save_operation(runtime, access, record)
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
        result = _execute(runtime, adapter, access, record, plan, device, undo=undo)
        return enrollment.complete(runtime, device, access, result) if enrolling else result


def _execute_ios_save(runtime, access, record):
    plan = record["plan"]
    try:
        if exec_ios.pending(access) is not None:
            raise Rejected(["an IOS revert timer is pending"], reason_codes=["rollback_timer_pending"])
        if ios_save.read(access, plan["firmware"]) != plan["predicted"]["before"]:
            raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"])
    except Rejected as exc:
        return _finish(runtime, record, "rejected", exc.reasons[0], reason_code=exc.reason_codes[0])
    except Exception:
        return _finish(runtime, record, "rejected", "IOS save preflight is unreadable",
                       reason_code="ios_save_diff_unreadable")
    _step(runtime, record, "change_start")
    try:
        if not exec_ios.persist(access, _spec(record)):
            return _finish(runtime, record, "unknown", "save command acceptance unverified")
        _step(runtime, record, "change_applied")
        if ios_save.read(access, plan["firmware"]) != plan["predicted"]["after"]:
            return _finish(runtime, record, "unknown", "saved configuration does not match the approved running configuration")
    except Exception:
        return _finish(runtime, record, "unknown", "save outcome unverified")
    _step(runtime, record, "postcheck_passed")
    return _finish(runtime, record, "confirmed")


def _execute_save(runtime, access, record):
    plan = record["plan"]
    approved = plan["predicted"]["before"]
    nx_save = plan["platform"] == "nxos"
    snapshot_digest = (engine.nxos.save_snapshot_digest if nx_save
                       else lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest())
    try:
        if nx_save:
            exec_nxos.save_prechecks(access)
            current = snapshot_digest(access.snapshot())
            diff = exec_nxos.read_save_diff(access)
        else:
            eos_save.compare_check(access, approved)
            diff = eos_save.read_diff(access)
            current = snapshot_digest(access.snapshot())
            sessions = exec_eos.sessions(access)
            if (sessions.get("commitTimerSessionName")
                    or any(item.get("state") == "pending" for item in sessions["sessions"].values())):
                raise Rejected(["a configuration session is active"], reason_codes=["foreign_config_session"])
        if diff != approved or current != plan["snapshot_sha256"]:
            raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"])
    except Rejected as exc:
        return _finish(runtime, record, "rejected", exc.reasons[0], reason_code=exc.reason_codes[0])
    except Exception:
        code = "nxos_save_diff_unreadable" if nx_save else "eos_save_diff_unreadable"
        return _finish(runtime, record, "rejected", "save preflight is unreadable", reason_code=code)
    _step(runtime, record, "change_start")
    try:
        if access.apply(plan["commands"], _spec(record)) != 1:
            return _finish(runtime, record, "unknown", "save command acceptance unverified")
        _step(runtime, record, "change_applied")
        if nx_save:
            if exec_nxos.read_save_diff(access) != plan["predicted"]["after"]:
                return _finish(runtime, record, "unknown", "running and startup still differ after save")
        else:
            eos_save.compare_check(access, plan["predicted"]["after"])
        if snapshot_digest(access.snapshot()) != plan["snapshot_sha256"]:
            return _finish(runtime, record, "unknown", "foreign change during save")
    except Exception:
        return _finish(runtime, record, "unknown", "save outcome unverified")
    _step(runtime, record, "postcheck_passed")
    return _finish(runtime, record, "confirmed")


def _execute_exos_save(runtime, access, record):
    plan, spec = record["plan"], _spec(record)
    if record["foreign_sessions"] != 0:
        return _finish(runtime, record, "rejected", "Other ExtremeXOS sessions are present or unreadable",
                       reason_code="exos_save_sessions")
    try:
        exos_save.prewrite(access, spec, plan)
    except Rejected as exc:
        return _finish(runtime, record, "rejected", exc.reasons[0], reason_code=exc.reason_codes[0])
    except Exception:
        return _finish(runtime, record, "rejected", "ExtremeXOS could not recheck the approved save",
                       reason_code="exos_save_diff_unreadable")
    _step(runtime, record, "change_start")
    try:
        if not exec_exos.persist(access, spec):
            raise RuntimeError("save was not accepted")
        _step(runtime, record, "change_applied")
        record["readback"] = exos_save.readback(access, spec, plan)
    except Rejected as exc:
        _step(runtime, record, "postcheck_failed", exc.reason_codes[0])
        return _finish(runtime, record, "unknown", exc.reasons[0])
    except Exception:
        _step(runtime, record, "postcheck_failed", "save acceptance or readback unavailable")
        return _finish(runtime, record, "unknown", "ExtremeXOS save acceptance or readback is unverified")
    _step(runtime, record, "postcheck_passed")
    return _finish(runtime, record, "confirmed")


def _execute_fortios_clear(runtime, access, record, target) -> dict:
    plan = record["plan"]
    approved = plan["predicted"]["before"]
    protected = runtime.config.devices[record["device"]].protected
    attempted = False

    def clear_and_read(query):
        nonlocal attempted
        before = exec_fortios.clear_observe(query, target, protected=protected)
        if before != approved:
            raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"])
        _step(runtime, record, "change_start")
        attempted = True
        if access.apply([fortios.SESSION_CLEAR], _spec(record)) != 1:
            raise AccessError("the session clear command was not acknowledged")
        _step(runtime, record, "change_applied")
        return exec_fortios.clear_observe(query, target)

    try:
        if exec_fortios.clear_checksum(access) != plan["snapshot_sha256"]:
            raise Rejected([PLAN_CHANGED], reason_codes=["plan_changed"])
        after = exec_fortios.with_clear_filter(access, target, plan["firmware"], clear_and_read)
        checked = exec_fortios.clear_checked_observation(access, target, plan["firmware"])
        record["readback"] = checked
        if exec_fortios.clear_checksum(access, check=True) != plan["snapshot_sha256"]:
            _step(runtime, record, "postcheck_failed", "configuration differs")
            return _finish(runtime, record, "unknown", "foreign change")
    except Rejected as exc:
        _step(runtime, record, "postcheck_failed" if attempted else "change_refused", ", ".join(exc.reason_codes))
        return _finish(runtime, record, "unknown" if attempted else "rejected", " / ".join(exc.reasons),
                       reason_code=exc.reason_codes[0])
    except AccessError:
        _step(runtime, record, "change_failed", "clear command acceptance unverified")
        return _finish(runtime, record, "unknown", "clear command acceptance unverified")
    cleared = {entry["serial"] for entry in approved["entries"]}
    if any(entry["serial"] in cleared for view in (after, checked) for entry in view["entries"]):
        _step(runtime, record, "postcheck_failed", "one or more original sessions remain")
        return _finish(runtime, record, "unknown", "clear readback mismatch")
    _step(runtime, record, "postcheck_passed")
    return _finish(runtime, record, "confirmed")


def _execute_clear(runtime, access, record, request) -> dict:
    plan = record["plan"]
    adc = plan["platform"] == "fortiadc"
    jun = plan["platform"] == "junos"
    ios_clear = plan["platform"] in engine.ios.PLATFORMS
    target = _clear_target(plan["platform"], request)
    if plan["platform"] == "fortios" and plan["table"] == fortios.SESSION_TABLE:
        return _execute_fortios_clear(runtime, access, record, target)
    spec = _spec(record)
    _step(runtime, record, "change_start")
    if plan["platform"] == "fortios" and plan["table"] == fortios.IPSEC_TUNNEL:
        try:
            readback = exec_fortios.recover_ipsec(access, spec, target, plan, runtime.sleep)
            record["readback"] = readback
            after = fortios.load(access.snapshot(), plan["firmware"])
        except Exception as exc:
            _step(runtime, record, "postcheck_failed", type(exc).__name__)
            return _finish(runtime, record, "unknown", "IPsec recovery readback unavailable")
        if after.rest_digest(fortios.PHASE2_TABLE, "") != plan["snapshot_sha256"]:
            return _finish(runtime, record, "unknown", "configuration changed during IPsec recovery")
        if readback["after"] != plan["predicted"]["after"] or (
                plan["predicted"]["before"]["up"] and not (readback["down_observed"] or readback["sas_replaced"])):
            return _finish(runtime, record, "unknown", "IPsec recovery transition was not observed")
        _step(runtime, record, "postcheck_passed")
        return _finish(runtime, record, "confirmed")
    timed = ((plan["platform"] == "nxos" and plan["table"] in ("port-counters", "mac-address-table"))
             or (plan["platform"] == "eos" and plan["table"] == eos_clear.COUNTERS))
    sent = None

    def mark_sent():
        nonlocal sent
        if guard is not None and not guard():
            return False
        sent = runtime.monotonic()
        return True

    if timed:
        guard = access.line_guard
        access.line_guard = mark_sent
    try:
        if adc:
            fortiadc.require_ha_write(access, plan.get("fortiadc_ha_role", "standalone"))
            exec_fortiadc.write_clear(access, spec, target, plan)
            accepted = 1
        elif ios_clear:
            accepted, before_clear = exec_ios.write_clear(access, spec, target, plan)
        else:
            accepted = access.apply(plan["commands"], spec)
    except Rejected as exc:
        if adc or ios_clear:
            _step(runtime, record, "change_refused", exc.reason_codes[0])
            return _finish(runtime, record, "rejected", exc.reasons[0], reason_code=exc.reason_codes[0])
        _step(runtime, record, "change_failed", type(exc).__name__)
        return _finish(runtime, record, "unknown", "clear command acceptance unverified")
    except Exception as exc:
        _step(runtime, record, "change_failed", type(exc).__name__)
        return _finish(runtime, record, "unknown", "clear command acceptance unverified")
    finally:
        if timed:
            access.line_guard = guard
    if accepted != 1:
        _step(runtime, record, "change_failed", "no accepted command")
        return _finish(runtime, record, "unknown", "clear command acceptance unverified")
    _step(runtime, record, "change_applied")
    try:
        if adc:
            observed = exec_fortiadc.readback_clear(access, spec, target, plan["predicted"]["after"], runtime.sleep)
            record["readback"] = observed
            matches = observed == plan["predicted"]["after"]
            current_hash = fortiadc.clear_snapshot_digest(access.snapshot())
        elif plan["platform"] == "fortios":
            observed = exec_fortios.observe_clear(access, target)
            matches, record["readback"] = fortios_lease.readback(plan, observed)
            current_hash = fortios_lease.config_digest(fortios.load(access.snapshot(), plan["firmware"]))
        elif plan["platform"] == "nxos":
            observed = exec_nxos.observe_clear(access, plan["table"], target)
            since_send = None if sent is None else runtime.monotonic() - sent
            matches, record["readback"] = nxos_clear.readback(
                plan, observed, time.time() - record["created_at_epoch"], since_send=since_send)
            current_hash = nxos_clear.config_digest(access.snapshot())
        elif ios_clear:
            observed = exec_ios.observe_clear(access, target)
            before = before_clear if plan["platform"] == "iosxe" else plan["predicted"]["before"]
            matches, record["readback"] = exec_ios.clear_readback(
                target, before, observed, platform=plan["platform"])
            current_hash = engine.ios.clear_snapshot_digest(access.snapshot())
        elif plan["platform"] == "eos":
            for attempt in range(eos_clear.BGP_READBACK_ATTEMPTS if plan["table"] == eos_clear.BGP else 1):
                if attempt:
                    runtime.sleep(eos_clear.BGP_READBACK_WAIT_SECONDS)
                observed = exec_eos.observe_clear(access, plan["table"], target)
                since_send = None if sent is None else runtime.monotonic() - sent
                matches, record["readback"] = eos_clear.readback(
                    plan, observed, time.time() - record["created_at_epoch"], since_send=since_send)
                if matches:
                    break
            current_hash = eos_clear.config_digest(access.snapshot())
        else:
            if jun:
                matches, record["readback"] = exec_junos.read_back_clear(access, plan, target, runtime.sleep)
            else:
                observed = exec_exos.observe_clear(access, plan["table"], target)
                matches, record["readback"] = exec_exos.clear_readback(plan, observed)
            current_hash = hashlib.sha256(access.snapshot().encode("utf-8")).hexdigest()
    except Exception as exc:
        _step(runtime, record, "postcheck_failed", type(exc).__name__)
        return _finish(runtime, record, "unknown", "clear readback unavailable")
    if current_hash != plan["snapshot_sha256"]:
        _step(runtime, record, "postcheck_failed", "configuration differs")
        return _finish(runtime, record, "unknown", "foreign change")
    if not matches:
        _step(runtime, record, "postcheck_failed", "operational state differs")
        # A complete but inconclusive IOS XE clear readback leaves no configuration to restore.
        return _finish(runtime, record, "unknown", "clear readback mismatch",
                       verified_clear_config=plan["platform"] == "iosxe")
    relearned = 0 if adc else sum(1 for entry in record["readback"].get("entries", ()) if entry.get("relearned"))
    if relearned:
        # Review finding 1: live traffic learned the target again after the clear; this is not a mismatch
        _step(runtime, record, "relearned", "%d entries learned again after the clear" % relearned)
    _step(runtime, record, "postcheck_passed")
    return _finish(runtime, record, "confirmed")


def _postcheck_observed(runtime, adapter, access, plan, device, due, *, created_uuid=None):
    if adapter is exec_fortios and plan["table"] == fortios.SWITCH_PORT:
        before, after = (plan["predicted"][side].get("status", "up") for side in ("before", "after"))
        if before != after:
            exec_fortios.wait_switch_state(runtime, access, plan["key"], lambda state: state["admin"] == after,
                                           min(due - device.confirm_margin_seconds, runtime.monotonic() + 10))
    if adapter is not exec_eos or plan["table"] != eos_services.NTP:
        observed = adapter.observe(access, plan, **({"operational": True} if adapter is exec_junos else {}))
        if (engine.tracks_registered_fortios_uuid(plan)
                and fortios.object_uuid((observed or {}).get("uuid")) != created_uuid):
            raise Rejected(["the two accounts read different identities for the created object"])
        return engine.observed_state(plan, observed)
    deadline = min(runtime.monotonic() + 30, due - device.confirm_margin_seconds)
    expected = engine.check_view(plan, plan["predicted"]["after"])
    while True:
        remaining = deadline - runtime.monotonic()
        saved_limit = getattr(access, "read_seconds", None)
        access.read_seconds = max(1, min(remaining, 5))
        try:
            observed = adapter.observe(access, plan)
        finally:
            access.read_seconds = saved_limit
        if observed == expected or deadline - runtime.monotonic() <= 2:
            return observed
        runtime.sleep(2)


def _batch_write(runtime, adapter, access, record, plan, device, spec, due, undo):
    steps = [dict(step, safeguard_id=record["change_id"]) for step in plan["batch_steps"]]
    results = record["batch_results"]
    for step, result in zip(steps, results):
        index = result["index"]

        def sent(number=1):
            if number == 1:
                _start_batch_step(runtime, record, index)

        try:
            current = access.snapshot()
            if engine.verify(step, current.encode("utf-8"), "before")["result"] != "match":
                raise Rejected(["batch step starting state differs from the approved plan"])
            checked = dict(step, prechecks=list(step["prechecks"]))
            adapter.batch_prechecks(access, device, checked, current, (), undo=undo)
            if engine.plan_digest(checked) != step["plan_sha256"]:
                raise Rejected(["batch step impact differs from the approved plan"])
            refused = adapter.before_write(access, record, due - runtime.monotonic(), device)
            if refused is not None:
                raise Rejected([refused])
            access.line_sent = sent
            try:
                access.apply(step["commands"], spec)
            finally:
                access.line_sent = None
            verdict = engine.verify(step, access.snapshot().encode("utf-8"))
            if verdict["result"] != "match":
                raise Rejected(["batch step configuration readback differs"])
            seen = _postcheck_observed(runtime, adapter, access, step, device, due)
            expected = engine.check_view(step, step["predicted"]["after"])
            if verdict.get("warnings"):
                # a firewall policy the device recreated under a UUID of its own
                expected = {**expected, "uuid": verdict["warnings"][0]["new_uuid"]}
                record.setdefault("warnings", []).extend(verdict["warnings"])
            if seen != expected:
                raise Rejected(["batch step check account readback differs"])
        except Exception as exc:
            attempted = result["result"] == "started"
            result.update(result="failed", failure=type(exc).__name__)
            if isinstance(exc, Rejected):
                result["reason_codes"] = list(exc.reason_codes)
            _step(runtime, record, "batch_step_failed", str(index))
            return _batch_return(runtime, adapter, access, record, plan, device, spec, due,
                                 steps[:index if attempted else index - 1])
        result["result"] = "verified"
        _step(runtime, record, "batch_step_verified", str(index))
    return None


def _batch_return(runtime, adapter, access, record, plan, device, spec, due, steps):
    reason = "profile batch step failed"
    try:
        for index in range(len(steps), 0, -1):
            step = steps[index - 1]
            before = engine.verify(step, access.snapshot().encode("utf-8"), "before")
            if before["result"] != "match":
                # A command can fail after an earlier line modified the same object. Its
                # approved inverse may run while the rest of the configuration still matches.
                if not before["rest_matches"] or adapter.before_write(access, record, due - runtime.monotonic(), device):
                    raise Rejected(["batch inverse cannot be verified against its starting state"])
                access.apply(step["inverse"], spec)
                if engine.verify(step, access.snapshot().encode("utf-8"), "before")["result"] != "match":
                    raise Rejected(["batch inverse readback differs"])
            # a FortiOS policy is read in the order it had before the step
            observed = (adapter.observe(access, step, before=True)
                        if adapter is exec_fortios and "policy_order" in step else adapter.observe(access, step))
            seen = engine.observed_state(step, observed)
            if seen != engine.check_view(step, step["predicted"]["before"]):
                raise Rejected(["batch inverse check account readback differs"])
            result = record["batch_results"][index - 1]
            result["rollback"] = "verified"
            if result["result"] != "failed":
                result["result"] = "reverted"
            _step(runtime, record, "batch_step_reverted", str(index))
        if not _returned(plan, access.snapshot().encode("utf-8")):
            raise Rejected(["batch return did not restore the starting configuration"])
    except Exception as exc:
        _step(runtime, record, "batch_return_unverified", type(exc).__name__)
        access.line_guard = None
        return _settle_after_expiry(runtime, access, record, plan, reason, due)
    access.line_guard = None
    if not adapter.remove_safeguard(access, record, spec):
        return _settle_after_expiry(runtime, access, record, plan, "confirmation unverified", due)
    _step(runtime, record, "safeguard_removed")
    if not _returned(plan, access.snapshot().encode("utf-8")):
        return _finish(runtime, record, "unknown", "batch return changed during safeguard removal")
    if not _persist(runtime, adapter, access, record):
        return _finish(runtime, record, "reverted", "not persisted")
    return _finish(runtime, record, "reverted", reason)


def _checked_policy_return(access, plan, verdict):
    warnings = verdict.get("warnings", [])
    if warnings:
        expected = {**plan["predicted"]["before"], "uuid": warnings[0]["new_uuid"]}
        seen = engine.observed_state(plan, exec_fortios.observe(access, plan, before=True))
        if seen != expected:
            raise Rejected(["the check account could not verify the restored firewall policy and UUID"])
    return warnings


def _execute(runtime, adapter, access, record, plan, device, undo=False) -> dict:
    change_id, spec = record["change_id"], _spec(record)
    if _compensating(adapter):
        return _execute_compensating(runtime, adapter, access, record, plan, device, undo=undo)
    staged = adapter is exec_eos and exec_eos.changes_in_session(plan)
    atomic_batch = adapter is exec_junos and "batch_steps" in plan
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
    if atomic_batch:
        _step(runtime, record, "change_start")

    pending_step = None

    def next_batch_step(index):
        # The atomic adapter identifies the next edit after checking the preceding reply.
        nonlocal pending_step
        pending_step = index

    def batch_line_sent(_number):
        nonlocal pending_step
        if pending_step is not None:
            _start_batch_step(runtime, record, pending_step)
            pending_step = None

    requested = runtime.monotonic()
    try:
        if atomic_batch:
            access.line_sent = batch_line_sent
            try:
                problems, commit_start, failed_index = adapter.apply_batch(
                    access, record, plan, spec, next_batch_step, runtime.monotonic)
            finally:
                access.line_sent = None
            if commit_start is not None:
                requested = commit_start
            if (problems and failed_index is None and record["safeguard"].get("install") != "refused"
                    and not _started_batch_steps(record)):
                failed_index = 1
            if failed_index is not None:
                record["batch_results"][failed_index - 1]["result"] = "failed"
                _step(runtime, record, "batch_step_failed", str(failed_index))
        elif getattr(adapter, "INSTALL_JOURNAL", False) is True:
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
                           reason_code=record["safeguard"].get("refused_code")
                           or getattr(adapter, "REFUSED_REASON_CODE", "rollback_timer_pending"))
        if atomic_batch and record["safeguard"].get("install") == "candidate-discarded":
            started_steps = _started_batch_steps(record)
            for result in record["batch_results"]:
                if str(result["index"]) in started_steps:
                    result["rollback"] = "candidate-discarded"
            return _finish(runtime, record, "reverted", problems[0])
        if getattr(adapter, "discard_installation", None) is not None:
            # an adapter whose unfinished installation can block the device (NX-OS: a job armed before its checkpoint
            # holds it) removes at once what its own session proved it created, and nothing else
            return _discard_installation(runtime, adapter, access, record, plan, "safeguard not verified")
        return _finish(runtime, record, "unknown", "safeguard not verified")
    if problems:
        _step(runtime, record, "safeguard_not_verified", problems[0])
        if staged:
            try:
                cleaned = adapter.discard_routing_session(access, record, spec)
                returned = cleaned and _returned(plan, access.snapshot().encode("utf-8"))
            except Exception:
                returned = False
            return _finish(runtime, record, "reverted" if returned else "unknown", "configuration session unverified")
        cleaned = adapter.remove_safeguard(access, record, spec)
        if cleaned and not _persist(runtime, adapter, access, record):
            return _finish(runtime, record, "reverted", "not persisted")
        return _finish(runtime, record, "reverted" if cleaned else "unknown", "safeguard not verified")
    runtime.store.save(record)
    _step(runtime, record, "safeguard_verified")
    if record.get("kind") in CYCLE_KINDS and device.platform == "fortios":
        return exec_fortios.run_switch_cycle(runtime, adapter, access, record, plan, device, due)
    if record.get("kind") == "port-bounce" and device.platform == "nxos":
        return exec_nxos.run_bounce(runtime, adapter, access, record, plan, device, due)
    if record.get("kind") in CYCLE_KINDS and device.platform == "eos":
        # 1.0.12 eos port maintenance (E07/E08): PoE cycle and port bounce of an EOS port
        from netops_admin import eos_cycle
        return eos_cycle.run(runtime, adapter, access, record, plan, device, due)
    if record.get("kind") in CYCLE_KINDS and device.platform == "junos":
        # 1.0.12 junos port maintenance (J10/J11): PoE cycle and port bounce of a Junos port
        from netops_admin import junos_cycle
        return junos_cycle.run(runtime, adapter, access, record, plan, device, due, requested)
    if record.get("kind") in CYCLE_KINDS and device.platform == "exos":
        from netops_admin import exos_poe
        return exos_poe.run(runtime, adapter, access, record, plan, device, due)
    if record.get("kind") in CYCLE_KINDS and device.platform in ios.PLATFORMS:
        # 1.0.12 ios port maintenance (IOS-C021, IOS-M024): port bounce and PoE cycle of an IOS or IOS XE port
        from netops_admin import ios_cycle
        return ios_cycle.run(runtime, adapter, access, record, plan, device, due)
    if adapter is exec_fortios and plan["table"] == fortios.SWITCH_PORT:
        try:
            current = exec_fortios.switch_port_preflight(access, plan)
        except Rejected:
            current = None
        if current != plan["cycle_state"]:
            return _settle_after_expiry(runtime, access, record, plan, "managed switch port state changed", due)
    if watched and not atomic_batch:
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
    if not atomic_batch:
        _step(runtime, record, "change_start")
    sent = runtime.monotonic()
    try:
        try:
            if atomic_batch:
                pass  # The candidate was activated by installing its commit-confirmed timer.
            elif "batch_steps" in plan:
                settled = _batch_write(runtime, adapter, access, record, plan, device, spec, due, undo)
                if settled is not None:
                    return settled
            elif not staged:
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
    if rearmed is not None and not atomic_batch:
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
            record["audit_coverage"] = audit_gate.evaluate(device.platform, audited, policy, audit_gate.plan_tables(plan),
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
    check_plans = [plan["batch_steps"][-1]] if "batch_steps" in plan else [plan]
    created_uuid = verdict.get("fortios_object_uuid")
    try:
        if atomic_batch:
            snapshot = engine.junos.load(after_text, plan["firmware"])
            check_plans = [adapter.batch_step_for_read(step, snapshot, "after") for step in plan["batch_steps"]]
        for index, check_plan in enumerate(check_plans, 1):
            seen = _postcheck_observed(runtime, adapter, access, check_plan, device, due, created_uuid=created_uuid)
            expected = engine.check_view(check_plan, check_plan["predicted"]["after"])
            new_identity = verdict.get("warnings", [])
            if new_identity:
                expected = {**expected, "uuid": new_identity[0]["new_uuid"]}
            if seen != expected:
                _step(runtime, record, "check_identity_failed", "state differs")
                return _settle_after_expiry(runtime, access, record, plan, "check identity mismatch", due)
            if atomic_batch:
                record["batch_results"][index - 1]["result"] = "verified"
                _step(runtime, record, "batch_step_verified", str(index))
    except Exception as exc:
        detail = type(exc).__name__
        if (isinstance(exc, Rejected) and exc.reason_codes and device.platform == "fortios"
                and fortios_tables.hooks(plan.get("table")) is not None):
            # 1.0.13 A1-R r2: the readback of a registered table names its refusal code (fortios_service_readback_unreadable)
            detail += " (%s)" % ", ".join(exc.reason_codes)
        _step(runtime, record, "check_identity_failed", detail)
        return _settle_after_expiry(runtime, access, record, plan, "check identity unavailable", due)
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
    if (final["result"] != "match" or final.get("warnings", []) != new_identity
            or final.get("fortios_object_uuid") != created_uuid):
        _step(runtime, record, "final_check_failed", "%d differences" % len(final["differences"]))
        record["final_check_differences"] = final["differences"]
        fired = ("safeguard fired during confirmation" if _returned(plan, last, access=access, record=record)
                 else "foreign change")
        return _settle_after_expiry(runtime, access, record, plan, fired, due)
    if created_uuid is not None:
        record["fortios_object_uuid"] = created_uuid
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
    if (removed["result"] != "match" or removed.get("warnings", []) != new_identity
            or removed.get("fortios_object_uuid") != created_uuid):
        _step(runtime, record, "removal_check_failed", "%d differences" % len(removed["differences"]))
        if _returned(plan, text, access=access, record=record):
            return _finish(runtime, record, "reverted", "safeguard fired during confirmation")
        return _finish(runtime, record, "unknown", "foreign change after the safeguard was removed",
                       removed["differences"])
    if new_identity:
        record["warnings"] = new_identity
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


def _execute_compensating(runtime, adapter, access, record, plan, device, undo=False) -> dict:
    """The change on a platform without an on-device timer (FortiADC): written, read back by the write and the check
    account and confirmed; any failure after the write is returned by the inverse in this run (_compensate)."""
    if adapter is exec_fortiadc:
        try:
            fortiadc.require_ha_write(access, plan.get("fortiadc_ha_role", "standalone"))
        except Rejected as exc:
            return _finish(runtime, record, "rejected", exc.reasons[0], reason_code=exc.reason_codes[0])
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
        after_text = _snapshot(access, adapter, plan["table"])
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
    if adapter is exec_fortiadc and plan.get("fortiadc_ha_role") == "primary":
        try:
            exec_fortiadc.verify_ha_sync(access, runtime.sleep)
        except Rejected as exc:
            _step(runtime, record, "postcheck_failed", exc.reason_codes[0])
            _step(runtime, record, "compensation_recovery_pending", exc.reason_codes[0])
            return _finish(runtime, record, "unknown", exc.reasons[0], reason_code=exc.reason_codes[0])
    try:
        attributes = adapter.observe(access, plan, after=True) if adapter is exec_ruckus else adapter.observe(access, plan)
        seen = engine.observed_state(plan, attributes)
    except Exception as exc:
        _step(runtime, record, "check_identity_failed", type(exc).__name__)
        return _compensate(runtime, adapter, access, record, plan, "check identity unavailable")
    if seen != engine.check_view(plan, plan["predicted"]["after"]):
        _step(runtime, record, "check_identity_failed", "state differs")
        return _compensate(runtime, adapter, access, record, plan, "check identity mismatch")
    _step(runtime, record, "check_identity_passed")
    if record.get("kind") == "enrollment":
        return _compensate(runtime, adapter, access, record, plan, "enrollment self-test")
    _step(runtime, record, "confirm_start")
    if not _persist(runtime, adapter, access, record):
        return _finish(runtime, record, "confirmed", "not persisted")
    if (adapter is exec_ruckus and plan["table"] == engine.ruckus.TABLE
            and any(engine.ruckus.PASSPHRASE_TOKEN in command for command in plan["commands"])):
        if undo:
            warning = engine.ruckus.NEW_PASSPHRASE if plan["op"] == "create" else engine.ruckus.CHANGED_PASSPHRASE
            _step(runtime, record, "undo_partial", warning)
        else:
            warning = engine.ruckus.CREATED_PASSPHRASE
        return _finish(runtime, record, "confirmed", warning)
    return _finish(runtime, record, "confirmed")


def _returned(plan, text, *, access=None, record=None) -> bool:
    try:
        verdict = engine.verify(plan, text, expect="before")
        if verdict["result"] != "match":
            return False
        if verdict.get("warnings"):
            if access is None:
                return False
            record["warnings"] = _checked_policy_return(access, plan, verdict)
        return True
    except Exception:
        return False


def _stored_plan(runtime, record) -> dict:
    try:
        return engine._read_plan(record.get("plan"))
    except Rejected:
        raise runtime.store.unreadable(runtime.store.operations / ("%s.json" % record["change_id"])) from None


def undo_request(record, reason: str):
    if record is not None and record.get("kind") in CYCLE_KINDS:
        raise Rejected([NO_UNDO if record["kind"] == "poe-cycle" else NO_UNDO_BOUNCE], reason_codes=["undo_not_applicable"])
    if record is not None and record.get("kind") in (eos_save.KIND, engine.nxos.SAVE_KIND, ios_save.KIND):
        raise Rejected([eos_save.NO_UNDO], reason_codes=["undo_not_applicable"])
    if record is not None and record.get("kind") in IRREVERSIBLE_KINDS:
        operation = "save" if record["kind"] == exos_save.KIND else "clear"
        raise Rejected(["%s is irreversible" % operation], reason_codes=["undo_not_applicable"])
    if record is not None and record.get("kind") == fortiadc_certificate_import.KIND:
        raise Rejected(["certificate import has no Admin undo"], reason_codes=["undo_not_applicable"])
    if record is None or record.get("status") != "finished" or record.get("result") != "confirmed":
        raise Rejected(["only a confirmed operation can be undone"])
    plan = engine._read_plan(record.get("plan"))
    if schema_runtime.is_plan(plan):
        return schema_runtime.undo_request(record, reason)
    if "batch_steps" in plan:
        changes = [_profile_undo(record, step, reason)[0] for step in reversed(plan["batch_steps"])]
        body = {"device": record["device"], "table": BATCH, "op": "update", "key": BATCH,
                "reason": reason, "user_request": "undo of operation %s" % record["change_id"],
                "request_id": "undo-%s" % record["change_id"], "changes": [
                    {"table": step.table, "op": step.op, "key": step.key, "changes": step.changes,
                     **({"endpoint_impact": step.endpoint_impact} if step.endpoint_impact else {})} for step in changes]}
        return parse_request(json.dumps(body).encode("utf-8")), ANY_STATE
    request, expected = _profile_undo(record, plan, reason)
    if engine.tracks_registered_fortios_uuid(plan):
        expected = {**expected, "uuid": record.get("fortios_object_uuid")}
    return request, expected


def _profile_undo(record, plan, reason):
    if plan["firmware"] is None:
        raise Rejected(["the plan of the operation names no firmware"])
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    key = plan["key"]
    impact = plan.get("endpoint_impact")
    if (plan["platform"] == "junos" and plan["table"] == "vlan-membership"
            and before.get("mode", "access") == "access" and "access-vlan" not in before
            and any(line.startswith("set ") and line.endswith(" %s %s" % (engine.junos.MEMBERS, engine.junos.DEFAULT_VLAN))
                    for line in plan["inverse"])):
        raise Rejected(["the original plan does not record whether default VLAN membership was explicit"])
    g43 = engine.exos.plan_kind(before, after) if plan["platform"] == "exos" else None
    if g43 == "rename":
        # 1.0.12 switch rest: the undo of a rename renames the VLAN back, so it is addressed by the new name
        key = after["name"]
    if plan["op"] == "create" and g43 == "ports":
        # 1.0.12 switch rest: a VLAN created with its ports is deleted by a request that names those ports
        op, changes = "delete", {name: after[name] for name in engine.exos.PORT_ATTRIBUTES if name in after}
    elif plan["op"] == "move":
        position = fortios.position_at(plan["policy_order"]["before"], key)
        op, changes = "move", dict([position])
    else:
        op, changes = inverse_profile_changes(plan["op"], before, after)
    if plan["platform"] == "ruckus":
        if op == "create" and plan["table"] == engine.ruckus.TABLE:
            engine.ruckus.restoration_security(before)
            for name in engine.ruckus.SECURITY_FIELDS:
                changes.pop(name)
        if op == "update":
            if engine.ruckus.passphrase_only(plan):
                raise Rejected(["the previous WLAN passphrase cannot be restored after a passphrase-only change"],
                               reason_codes=["undo_not_applicable"])
            changes = engine.ruckus.undo_changes(plan, before, after, changes)
            if plan["table"] == engine.ruckus.TABLE and engine.ruckus.active_impact(after, before, changes):
                impact = key
    profile = find_profile(plan["platform"], plan["table"], plan["firmware"])
    if plan["platform"] == "junos" and profile.table == engine.junos_g140.LAG and op == "update":
        # The empty aggregate is a configuration form, reconstructed from the resulting state.
        changes.pop("empty-aggregate", None)
    if op == "create" and profile.table == fortios.ADDRESS_TABLE:
        if changes.get("type") == fortios.INTERFACE_SUBNET:
            changes.pop("subnet", None)
        elif changes.get("type", "ipmask") == "ipmask":
            changes.setdefault("subnet", profile.attributes["subnet"].default)
    if op == "create" and profile.table == fortios.POLICY_TABLE:
        fortios.require_policy_uuid(changes.get("uuid"))
        changes = fortios.policy_restore_attributes(profile, changes)
    request = profile_undo_request(profile, op, key, changes, before=before, device=record["device"], impact=impact,
                                   change_id=record["change_id"], reason=reason)
    return request, after


def undo(runtime, change_id: str, reason: str, expected_plan_sha256=None) -> dict:
    # expected_plan_sha256 (1.0.12 execution access, MCP admin_undo) binds the undo to the plan_sha256 of the approved
    # admin_undo_preview: a fresh undo plan that differs is refused with plan_changed before any write.
    # execution access r2: the hash is accepted only as the one of the last undo preview issued for this change, once, fresh and
    # for the unchanged journal of the device; the operator command admin undo passes no hash and needs none
    original = runtime.store.operation(change_id)
    stored = (_stored_plan(runtime, original)
              if original is not None and original.get("kind") != fortiadc_certificate_import.KIND
              and original.get("status") == "finished" and original.get("result") == "confirmed"
              else None)
    request, expected = undo_request(original, reason)
    try:
        expected_plan = _expected_plan(request, expected_plan_sha256)
    except Rejected:
        _count_rejection(runtime)
        raise
    try:
        return _apply_counted(runtime, original["device"], request, expected_before=expected, undo=True,
                              expected_plan=expected_plan, undo_plan=stored,
                              ticket=None if expected_plan is None else ("undo", change_id))
    except Rejected as exc:
        if exc.reasons == [REUSED_REQUEST]:
            raise Rejected([UNDO_DONE], reason_codes=["undo_already_done"]) from None
        raise


def preview_undo(runtime, change_id: str, reason: str, issue=False) -> dict:
    """Every check of undo without a change: nothing is written to the device, the journal or a notification.

    issue (MCP admin_undo_preview with mcp_undo enabled): a ready preview is recorded as the one whose plan_sha256
    admin_undo accepts (1.0.12 execution access r2)."""
    original = runtime.store.operation(change_id)
    try:
        stored = (_stored_plan(runtime, original)
                  if original is not None and original.get("kind") != fortiadc_certificate_import.KIND
                  and original.get("status") == "finished" and original.get("result") == "confirmed"
                  else None)
        request, expected = undo_request(original, reason)
        result, refused = _preview(runtime, original["device"], request, expected_before=expected, undo=True,
                                   undo_plan=stored, ticket=("undo", change_id) if issue else None)
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
    locally_restored_adc = set()
    with runtime.store.lock(device.name), _target_lock(device):
        for record in runtime.store.running(device.name):
            if record.get("kind") == fortiadc_certificate_import.KIND:
                settled.append(fortiadc_certificate_import.recover(runtime, device, record))
                continue
            if record.get("kind") in IRREVERSIBLE_KINDS:
                steps = {step["step"] for step in record["steps"]}
                if "change_start" in steps:
                    _step(runtime, record, "recovery_start")
                    settled.append(_finish(runtime, record, "confirmed") if "postcheck_passed" in steps else
                                   _finish(runtime, record, "unknown", "interrupted; %s outcome unverified" % record["plan"]["op"]))
                    continue
            if "safeguard" not in record:
                _step(runtime, record, "recovery_start")
                settled.append(_finish(runtime, record, "rejected", "interrupted before any mutation",
                                       reason_code="interrupted_before_mutation"))
                continue
            with ExitStack() as stack:
                plan = _stored_plan(runtime, record)
                adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan), plan["table"])
                steps = {step["step"] for step in record.get("steps", [])}
                _step(runtime, record, "recovery_start")
                ruckus_wlan = adapter is exec_ruckus and plan["table"] == engine.ruckus.TABLE
                if adapter is exec_ruckus and "change_start" in steps and engine.ruckus.passphrase_only(plan):
                    settled.append(_finish(runtime, record, "unknown",
                                           "interrupted. " + engine.ruckus.UNVERIFIED_PASSPHRASE))
                    continue
                try:
                    access = stack.enter_context(operation(runtime.access_factory(device)))
                    if schema_runtime.is_plan(plan):
                        access = schema_runtime.Access(access, device)
                    if adapter is exec_exos_acl:
                        access = exec_exos_acl.wrap_access(access, plan["key"])
                        access.bind_plan(plan)
                        if any(step["step"] == "change_start" for step in record["steps"]):
                            access.recover_stage()
                except Exception as exc:
                    _step(runtime, record, "recovery_access_failed", type(exc).__name__)
                    if _ruckus_relay_update(adapter, plan) and "change_start" in steps and "confirm_start" not in steps:
                        settled.append(_defer_ruckus_relay_compensation(runtime, record))
                    else:
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
                if present and record.get("kind") in CYCLE_KINDS and device.platform == "exos" and any(
                        step.get("step") == "confirm_start" for step in record.get("steps", [])):
                    # the cycle may be done although its safeguard is installed: confirmed only on fresh proof
                    from netops_admin import exos_poe
                    settled.append(exos_poe.recover_installed(runtime, adapter, access, record, plan, device))
                    continue
                eos_cycle_operation = device.platform == "eos" and record.get("kind") in CYCLE_KINDS
                if eos_cycle_operation:
                    from netops_admin import eos_cycle
                    cycle_failure = eos_cycle._cycle_failure(record)
                else:
                    cycle_failure = None
                if present:
                    persist_failure = eos_cycle._persistence_failure(cycle_failure) if eos_cycle_operation else "not persisted"
                    settled.append(_settle_after_expiry(runtime, access, record, plan, cycle_failure or "interrupted",
                                                        runtime.monotonic() + device.safeguard_seconds,
                                                        persist_failure=persist_failure))
                    continue
                try:
                    text = _snapshot(access, adapter, plan["table"]).encode("utf-8")
                    after = engine.verify(plan, text, expect="after")
                    is_after = after["result"] == "match"
                    if is_after and "fortios_object_uuid" in record:
                        is_after = after.get("fortios_object_uuid") == record["fortios_object_uuid"]
                    if adapter is exec_fortios:
                        is_before = _returned(plan, text, access=access, record=record)
                    else:
                        is_before = engine.verify(plan, text, expect="before")["result"] == "match"
                    if is_after and after.get("warnings"):
                        expected = {**plan["predicted"]["after"], "uuid": after["warnings"][0]["new_uuid"]}
                        is_after = engine.observed_state(plan, adapter.observe(access, plan)) == expected
                        if is_after:
                            record["warnings"] = after["warnings"]
                except Exception:
                    if _ruckus_relay_update(adapter, plan) and "change_start" in steps and "confirm_start" not in steps:
                        settled.append(_defer_ruckus_relay_compensation(runtime, record))
                    else:
                        settled.append(_finish(runtime, record, "unknown", "interrupted; state unreadable"))
                    continue
                if eos_cycle_operation:
                    settled.append(eos_cycle.recover_disarmed(runtime, adapter, access, record, is_before))
                elif device.platform == "nxos" and record.get("kind") == "port-bounce" and "confirm_start" in steps:
                    settled.append(exec_nxos.recover_bounce(runtime, adapter, access, record, plan, is_before))
                elif device.platform == "iosxe" and record.get("kind") in CYCLE_KINDS:
                    from netops_admin import ios_cycle
                    settled.append(ios_cycle.recover_return(runtime, access, record, is_before, steps))
                elif record.get("kind") in CYCLE_KINDS and is_before and "confirm_start" in steps:
                    # the cycle ends on the before side: power was observed back on before confirm_start
                    saved = _persist(runtime, adapter, access, record)
                    settled.append(_finish(runtime, record, "confirmed",
                                           "confirmed before the interruption" if saved else "not persisted"))
                elif is_after and "confirm_start" in steps:
                    saved = _persist(runtime, adapter, access, record)
                    reason = "confirmed before the interruption" if saved else "not persisted"
                    if saved and ruckus_wlan and any(
                            engine.ruckus.PASSPHRASE_TOKEN in command for command in plan["commands"]):
                        warning = (engine.ruckus.CREATED_PASSPHRASE if plan["op"] == "create"
                                   else engine.ruckus.CHANGED_PASSPHRASE)
                        reason += ". " + warning
                    settled.append(_finish(runtime, record, "confirmed", reason))
                elif is_before and adapter is exec_fortiadc and plan.get("fortiadc_ha_role") == "primary":
                    failure = _adc_ha_compensation_failure(runtime, access, record, plan)
                    if failure is None:
                        _step(runtime, record, "compensation_verified")
                        settled.append(_finish(runtime, record, "reverted", "interrupted"))
                    else:
                        locally_restored_adc.add(record["change_id"])
                        settled.append(failure)
                elif is_before:
                    saved = _persist(runtime, adapter, access, record)
                    reason = "interrupted" if saved else "not persisted"
                    result = "reverted"
                    if ruckus_wlan and "compensation_applied" in steps and any(
                            engine.ruckus.PASSPHRASE_TOKEN in command for command in plan["inverse"]):
                        warning = engine.ruckus.CHANGED_PASSPHRASE
                        if plan["op"] == "delete":
                            result, warning = "revert-failed", engine.ruckus.NEW_PASSPHRASE
                        _step(runtime, record, "compensation_partial", warning)
                        reason += ". " + warning
                    settled.append(_finish(runtime, record, result, reason))
                elif ((is_after and _compensating(adapter)) or
                      (_ruckus_relay_update(adapter, plan) and "change_start" in steps
                       and _ruckus_relay_missing(plan, text.decode("utf-8")))):
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
        if device.platform == "fortiadc":
            blocked = runtime.store.blocked(device.name)
            if blocked:
                record = runtime.store.operation(blocked["change_id"])
                if record and record.get("kind") == fortiadc_certificate_import.KIND and record["device"] == device.name:
                    if all(item["change_id"] != record["change_id"] for item in settled):
                        settled.append(fortiadc_certificate_import.recover(runtime, device, record, blocked))
                elif _adc_compensation_pending(record) and record["change_id"] not in locally_restored_adc:
                    settled.append(_recover_adc_compensation(runtime, device, record))
        if device.platform == "ruckus":
            blocked = runtime.store.blocked(device.name)
            if blocked and all(item["change_id"] != blocked["change_id"] for item in settled):
                record = runtime.store.operation(blocked["change_id"])
                if (record and record.get("result") == "unknown"
                        and any(item["step"] == "relay_recovery_pending" for item in record.get("steps", []))):
                    settled.append(_recover_ruckus_relay_compensation(runtime, device, record))
    return settled


def _recover_ruckus_relay_compensation(runtime, device, record):
    plan = _stored_plan(runtime, record)
    _step(runtime, record, "recovery_start")
    with ExitStack() as stack:
        try:
            access = stack.enter_context(operation(runtime.access_factory(device)))
            text = _snapshot(access, exec_ruckus, plan["table"])
            before = engine.verify(plan, text.encode("utf-8"), expect="before")
            after = engine.verify(plan, text.encode("utf-8"), expect="after")
        except Exception as exc:
            _step(runtime, record, "recovery_access_failed", type(exc).__name__)
            return record
        if before["object_matches"] or after["object_matches"] or _ruckus_relay_missing(plan, text):
            return _compensate(runtime, exec_ruckus, access, record, plan, "interrupted")
    return _finish(runtime, record, "revert-failed", "DHCP relay profile differs from both planned states")


def _adc_compensation_pending(record):
    if record is None or (record.get("status"), record.get("result")) != ("finished", "unknown"):
        return False
    if (record.get("plan") or {}).get("platform") != "fortiadc":
        return False
    steps = {entry["step"] for entry in record.get("steps", [])}
    # Older journals recorded the failed read, inverse and verification individually.
    return ("change_start" in steps and ("compensation_recovery_pending" in steps or
            {"compensation_start", "compensation_failed", "revert_unverified"} <= steps))


def _recover_adc_compensation(runtime, device, record):
    plan = _stored_plan(runtime, record)
    _step(runtime, record, "recovery_start")
    try:
        access = runtime.access_factory(device)
    except Exception as exc:
        _step(runtime, record, "recovery_access_failed", type(exc).__name__)
        return record
    with operation(access):
        return _compensate(runtime, exec_fortiadc, access, record, plan, record["reason"], recovering=True)


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
    adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan), plan["table"])
    _step(runtime, record, "recovery_start")
    try:
        with operation(runtime.access_factory(device)) as access:
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


def _unblock_check(runtime, device):
    """1.0.12 execution access: read the actual device for MCP admin_unblock; returns the block, its operation, the side and digest.

    Only the block of an unknown operation of a profile plan qualifies, and only when the write account reads the
    device exactly on the after side of its plan, the check account reads the same object state, no safeguard is
    left and the administrator accounts equal the baseline. Nothing is written. 1.0.12 execution access r2 (review finding 2):
    a revert-failed operation, a schema transaction and the state before stay the operator commands."""
    blocked = runtime.store.blocked(device.name)
    if blocked is None:
        return None
    record = runtime.store.operation(blocked["change_id"]) if blocked.get("change_id") else None
    if (record is None or record.get("device") != device.name or record.get("status") != "finished"
            or record.get("result") not in MCP_UNBLOCK_RESULTS):
        raise Rejected(["the block of device %s (%s, operation %s, result %s) is not the block of an unknown"
                        " operation; a person investigates, runs admin recover if needed and lifts it with the"
                        " operator command admin unblock"
                        % (device.name, blocked.get("reason"), blocked.get("change_id") or "none",
                           (record or {}).get("result") or "none")],
                       reason_codes=["unblock_operator_only"])
    if runtime.store.running(device.name):
        raise Rejected(["an unfinished operation exists on this device; a person runs admin recover first"],
                       reason_codes=["operation_unfinished"])
    if record.get("kind") == fortiadc_certificate_import.KIND:
        raise Rejected(["run admin recover to verify the certificate import"], reason_codes=["unblock_operator_only"])
    plan = _stored_plan(runtime, record)
    if schema_runtime.is_plan(plan):
        raise Rejected(["the block of device %s belongs to schema transaction %s; MCP admin_unblock does not lift it:"
                        " a person checks the device, runs admin recover if needed and lifts the block with the"
                        " operator command admin unblock" % (device.name, record["change_id"])],
                       reason_codes=["unblock_operator_only"])
    if "batch_steps" in plan:
        raise Rejected(["check the state of each profile batch step and run the operator command admin unblock"],
                       reason_codes=["unblock_operator_only"])
    adapter = _adapter(plan["platform"], schema_runtime.is_plan(plan), plan["table"])
    try:
        with operation(runtime.access_factory(device)) as access:
            if schema_runtime.is_plan(plan):
                access = schema_runtime.Access(access, device)
            if adapter is exec_exos_acl:
                access = exec_exos_acl.wrap_access(access, plan["key"])
                access.bind_plan(plan)
            text = _snapshot(access, adapter, plan["table"])
            accounts = adapter.accounts_check(access, device, text)
            leftovers = adapter.leftovers(access)
            side = engine.observed_side(plan, text.encode("utf-8"))
            kwargs = {"side": side} if adapter is exec_junos and plan["table"] in engine.junos_g140.TABLES else {}
            if "policy_order" in plan:
                kwargs["before"] = side == "before"
            seen = engine.observed_state(plan, adapter.observe(access, plan, **kwargs)) if side is not None else None
    except Exception as exc:
        detail = "; ".join(exc.reasons) if isinstance(exc, Rejected) else type(exc).__name__
        raise Rejected(["the actual state of device %s could not be verified: %s" % (device.name, detail)],
                       reason_codes=["unblock_state_unverified"]) from None
    known = runtime.store.baseline(device.name)
    if known is not None and known != accounts:
        raise Rejected(["the administrator accounts changed since the last operation; a person investigates and"
                        " lifts the block with the operator command admin unblock"],
                       reason_codes=["unblock_operator_only"])
    if leftovers:
        raise Rejected(["a safeguard is still installed on the device: %s; a person runs admin recover"
                        % ", ".join(leftovers)], reason_codes=["unblock_state_unverified"])
    if side is None:
        raise Rejected(["the device matches neither the state before nor the state after operation %s; a person"
                        " investigates" % record["change_id"]], reason_codes=["unblock_state_unverified"])
    if side != MCP_UNBLOCK_SIDE:
        raise Rejected(["the device is in the state before operation %s (its change is not on the device); MCP"
                        " admin_unblock lifts only a block whose change is verified on the device: a person"
                        " investigates, runs admin recover if needed and lifts the block with the operator command"
                        " admin unblock" % record["change_id"]], reason_codes=["unblock_operator_only"])
    expected = plan["predicted"][side]
    if device.platform == "eos" and plan["table"] in (eos_l2.STP_PORT, eos_l2.STP_VLAN):
        expected = engine.check_view(plan, expected)
    if seen != expected:
        raise Rejected(["the check account sees the object in another state than the write account (%s side of"
                        " operation %s)" % (side, record["change_id"])], reason_codes=["unblock_state_unverified"])
    state = plan["predicted"][side]
    return blocked, record, side, state, unblock_digest(device.name, blocked, record, side, state)


def _unblock_answer(device, checked) -> dict:
    blocked, record, side, state, digest = checked
    plan = record["plan"]
    return {
        "device": device.name,
        "blocked": {"reason": blocked.get("reason"), "change_id": blocked.get("change_id")},
        "change_id": record["change_id"],
        "operation_result": record.get("result"),
        "operation_reason": record.get("reason"),
        "table": plan.get("table"), "op": plan.get("op"), "key": plan.get("key"),
        "observed": side,
        "object": state,
        "unblock_sha256": digest,
        "effect": ("lifts only the block; the operation stays %s and is not confirmed, the device keeps the %s state,"
                   " the account baseline and undelivered notifications are kept" % (record.get("result"), side)),
    }


def _unblock_device(runtime, device_name: str):
    device = runtime.config.devices.get(device_name)
    if device is None:
        raise Rejected(["device %s is not configured" % shown(device_name)])
    return device


def preview_unblock(runtime, device_name: str, issue=False) -> dict:
    """Every check of admin_unblock without a change: the device is read, nothing is written or journaled.

    issue (MCP admin_unblock_preview with mcp_undo enabled): the earlier preview of the device is withdrawn and a ready
    one is recorded as the one whose unblock_sha256 admin_unblock accepts (1.0.12 execution access r2)."""
    try:
        device = _unblock_device(runtime, device_name)
        with runtime.store.lock(device.name), _target_lock(device):
            if issue:
                runtime.store.withdraw_preview(device.name, "unblock")
            checked = _unblock_check(runtime, device)
            if issue and checked is not None:
                _issue_preview(runtime, device.name, "unblock", checked[1]["change_id"], checked[4])
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise
    if checked is None:
        return {"result": "not-blocked", "device": device.name}
    return dict(_unblock_answer(device, checked), result="ready")


def unblock_observed(runtime, device_name: str, reason: str, expected_unblock_sha256) -> dict:
    """1.0.12 execution access, MCP admin_unblock: lift the block approved by its admin_unblock_preview after reading the device again.

    Unlike the operator command admin unblock it keeps the account baseline and undelivered notifications, and lifts
    only the block of an unknown or revert-failed operation; the operation result is not changed."""
    try:
        device = _unblock_device(runtime, device_name)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_UNBLOCK_REASON:
            raise Rejected(["reason must be a non-empty text of at most %d characters" % MAX_UNBLOCK_REASON])
        if not isinstance(expected_unblock_sha256, str) or not PLAN_SHA256.fullmatch(expected_unblock_sha256):
            raise Rejected(["expected_unblock_sha256 must be 64 lowercase hexadecimal characters"])
        runtime.audit.check_writable()
        with runtime.store.lock(device.name), _target_lock(device):
            checked = _unblock_check(runtime, device)
            if checked is None:
                return {"result": "not-blocked", "device": device.name}
            blocked, record, side, state, digest = checked
            # 1.0.12 execution access r2 (review finding 1): only the hash of the issued preview, once; the refusal never names
            # the current digest, which the action would accept
            _redeem_preview(runtime, device.name, "unblock", record["change_id"], expected_unblock_sha256,
                            "unblock_changed")
            if digest != expected_unblock_sha256:
                raise Rejected([UNBLOCK_CHANGED], reason_codes=["unblock_changed"],
                               reason_details=[{"code": "unblock_changed", "expected": expected_unblock_sha256}])
            runtime.store.unblock(device.name, blocked)
            _step(runtime, record, "unblocked_observed_%s" % side)
            runtime.audit.event("administrative", device=device.name, action="unblock observed %s" % side,
                                reason_characters=len(reason), change_id=record["change_id"])
    except BudgetExhausted:
        raise
    except Rejected:
        _count_rejection(runtime)
        raise
    return dict(_unblock_answer(device, checked), result="unblocked")


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
