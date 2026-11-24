"""Execute one authorization-bound page of overview reads."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import replace
from threading import Event, Lock
import time
from types import MappingProxyType

from .. import engine, fortios_vdom, normalization, progress, wifi_rest
from ..auth import TargetAuth, PolicyScopeError
from . import adapter
from . import model


class Budget:
    def __init__(self, deadline: float, cancelled: Event):
        self.deadline = deadline
        self.end = deadline
        self.cancelled = cancelled

    def remaining(self):
        seconds = self.end - time.monotonic()
        if seconds <= 0 or self.cancelled.is_set():
            raise TimeoutError("overview deadline elapsed")
        return seconds

    def begin_read(self):
        self.end = min(self.deadline, time.monotonic() + model.READ_SECONDS)
        self.remaining()


def _skipped(spec, reason, retry=None):
    return model.ReadResult(spec, "not_run", reason=reason, retry_after_seconds=retry)


def _transport_result(code):
    if code in {"auth", "name_invalid"}:
        return "auth_failed", "reachable"
    if code in {"host_key_mismatch", "host_key_unavailable", "negotiation"}:
        return "host_key_failed", "reachable"
    if code in {"connection_refused", "unreachable", "dns"}:
        return "unreachable", "unreachable"
    if code == "timeout":
        return "timeout", "unknown"
    if code == "output_limit":
        return "truncated", "unknown"
    if code in {"disconnected", "transport_failure", "ssh_unavailable"}:
        return "unreachable", "unknown"
    return "internal_error", "unknown"


def _read_status(reason):
    return "incomplete" if reason in {"unparsed", "truncated", "source_limit"} else "failed"


def _read(auth, spec, budget, scope, *, identity=False):
    started = time.monotonic()
    reason = text = document = rc = None
    coverage = {}
    state, reachability = "ok", "unknown"
    tried = [False]
    token = engine._TRIAGE_READ_ATTEMPT.set(tried)

    def capture(target, platform, command):
        nonlocal text, reachability
        rc, text = engine.read_from_device(target, platform, command)
        reachability = "reachable"
        return rc, text

    try:
        if spec.transport == "https":
            tried[0] = True
            document = engine._overview_rest_document(auth, spec.query, budget)
            reachability = "reachable"
            if not document["results"]:
                state = "empty"
        elif identity:
            auth.require_tcp_port(auth.port)
            engine._ssh_read_state(auth, auth.ssh_platform, spec.query, {}, auth.read_inventory)
            engine._overview_identity(auth, capture)
            identity_state = normalization.output_status(
                text, truncated=len(text.encode("utf-8")) > engine._SSH_CAPTURE_MAX_BYTES,
                profile=auth.ssh_platform,
            )
            if identity_state != "ok":
                reason = "truncated" if identity_state == "truncated" else "identity_unverified"
            elif auth.ssh_platform == "fortinet":
                try:
                    found = fortios_vdom.scope(text)
                    scope["scope"] = fortios_vdom.require(found, auth.read_inventory, text)
                except fortios_vdom.VdomRefused:
                    scope["refused"] = True
            if text is not None:
                text = engine._overview_redact(text, auth)
            coverage = engine._overview_redact(scope.get("scope", {}), auth)
        else:
            answer = engine._overview_ssh(auth, spec, scope)
            coverage = engine._overview_redact({
                key: answer[key] for key in ("data_scope", "vdom_mode", "vdom", "context", "interface_vdoms")
                if key in answer
            }, auth)
            state, text, rc = answer.get("status", "ok"), answer.get("text"), answer.get("rc")
            if text is not None:
                text = engine._overview_redact(text, auth)
            if "rc" in answer or answer.get("ok"):
                reachability = "reachable"
            if not answer.get("ok"):
                reason = answer.get("reason")
                if reason == "transport_error":
                    reason, reachability = _transport_result(answer.get("error_code"))
                elif reason in {"device_cli_error", "empty", "unsupported", "ok"}:
                    reason = "unparsed" if answer.get("error_code") != "ssh_unavailable" else "internal_error"
                elif reason in {"vdom_unverified", fortios_vdom.VDOM_ADMIN_GLOBAL}:
                    reason = "policy_scope"
        budget.remaining()
    except engine._ProductIdentityError:
        reason = "identity_unverified"
    except PolicyScopeError:
        reason = "policy_scope"
    except wifi_rest.RestError as exc:
        reason = {
            "authentication_failed": "auth_failed", "authorization_failed": "permission_denied",
            "rate_limited": "rate_limited", "timeout": "timeout", "tls_pin_mismatch": "host_key_failed",
            "tls_verification_failed": "host_key_failed", "egress_denied": "policy_scope",
            "response_too_large": "truncated", "unparsed_envelope": "unparsed",
        }.get(exc.code, "rest_unavailable")
        if exc.http_status is not None or exc.code in {"unparsed_envelope", "tls_pin_mismatch",
                                                       "tls_verification_failed", "invalid_json"}:
            reachability = "reachable"
    except Exception as exc:
        reason, reachability = _transport_result(engine._transport_cause(exc))
    finally:
        engine._TRIAGE_READ_ATTEMPT.reset(token)
    if reason is not None:
        reason = reason if reason in model.REASONS else "unparsed"
        state = _read_status(reason)
        if identity or reason == "timeout":
            text = document = None
    if not tried[0] and reason:
        return _skipped(spec, reason)
    return model.ReadResult(spec, state, max(0, int(1000 * (time.monotonic() - started))),
                            model.utc_now(), reason, text, document, reachability=reachability, scope=coverage,
                            rc=rc if type(rc) is int else None)


def _selected_steps(row, specs):
    payload = row["steps"]
    if len(payload) != len(specs):
        raise ValueError("internal overview plan does not match the enrolled platform")
    for step, spec in zip(payload, specs, strict=True):
        if not isinstance(step, dict) or set(step) - {"spec", "reason", "retry_after_seconds"}:
            raise ValueError("invalid internal overview step")
        encoded = dict(step["spec"])
        encoded["fields"] = tuple(encoded["fields"])
        encoded["requires"] = tuple(encoded["requires"])
        if encoded != spec.wire() or (step["reason"] is not None and step["reason"] not in model.REASONS):
            raise ValueError("invalid internal overview read")
        yield spec, step["reason"], step.get("retry_after_seconds")


def _run_reads(auth, steps, budget):
    answers = {}
    scope = {}
    with engine._overview_transport(auth, budget) as reader:
        identity = None
        lost = None
        for index, (spec, reason, retry) in enumerate(steps):
            if reason is None:
                try:
                    budget.begin_read()
                except TimeoutError:
                    reason = "timeout"
            if reason is None and any(answers[key].status not in {"ok", "empty"} for key in spec.requires):
                reason = next((answers[key].reason for key in spec.requires if answers[key].reason), "unparsed")
            if reason is None and index > 0:
                if identity.reason == "identity_unverified":
                    reason = "identity_unverified"
                elif spec.transport == "ssh":
                    reason = identity.reason or lost or ("policy_scope" if scope.get("refused") else None)
                elif scope.get("refused") or (scope.get("scope") or {}).get("vdom", "root") != "root":
                    reason = "policy_scope"
            answer = _skipped(spec, reason, retry) if reason else _read(auth, spec, budget, scope, identity=index == 0)
            if index == 0:
                identity = answer
            if auth.ssh_platform in {"fortinet", "fortiadc"} and spec.transport == "ssh":
                if reader.failure is not None or getattr(reader.cli, "_closed", False):
                    lost = answer.reason or "unreachable"
            answers[spec.id] = answer
    return answers


def _findings(row, reads):
    """Derive common findings from evidence the parser actually reported."""
    findings = []

    def add(code, severity, field, sources=None, subject=None):
        references = list(sources or [
            read.spec.id for read in reads.values()
            if read.status in {"ok", "empty", "incomplete"} and field in read.spec.fields
        ])
        if references:
            findings.append({"code": code, "severity": severity, "field": field, "read_ids": references,
                             **({"subject": subject} if subject is not None else {})})

    def evaluate(item, prefix=""):
        interfaces = item.get("interfaces") or {}
        for entry in interfaces.get("admin_up_down") or []:
            add("admin_up_link_down", "warning", prefix + "interfaces.admin_up_down", entry.get("read_ids"), entry.get("name"))
        for entry in interfaces.get("with_errors") or []:
            if any(type(value) is int and value > 0 for value in entry.get("counters", {}).values()):
                add("interface_errors_present", "warning", prefix + "interfaces.with_errors", entry.get("read_ids"), entry.get("name"))
        for field in ("temperatures", "fans", "power"):
            for entry in item.get(field) or []:
                state = entry.get("state")
                if state in {"warning", "failed"}:
                    add("hardware_degraded", "critical" if state == "failed" else "warning",
                        prefix + field, entry.get("read_ids"), entry.get("name"))
        for entry in item.get("redundancy") or []:
            if entry.get("state") == "degraded":
                add("redundancy_degraded", "critical", prefix + "redundancy", entry.get("read_ids"), entry.get("kind"))
        for field, code in (("licenses", "license"), ("fortiguard", "fortiguard")):
            for entry in item.get(field) or []:
                state = entry.get("state")
                if state in {"valid", "expired", "expiring"} and entry.get("expires_on"):
                    state = model.expiry_state(entry["expires_on"])
                    entry["state"] = state
                if state in {"expired", "expiring"}:
                    add(code + "_" + state, "critical" if state == "expired" else "warning",
                        prefix + field, entry.get("read_ids"), entry.get("name"))

    evaluate(row)
    for index, child in enumerate(row["managed"] or []):
        evaluate(child, f"managed[{index}].")
    firmware = row.get("firmware_support")
    if isinstance(firmware, dict) and firmware.get("status") in {"untested", "unknown"}:
        identity = next(iter(reads.values()), None)
        if identity is not None and identity.status == "ok":
            add("firmware_untested", "info", "firmware_support", [identity.spec.id])
    return findings


_REFERENCE_KEYS = frozenset({"field", "read_id"})


def _plain(value, depth=0):
    """Return a JSON-shaped copy of adapter output or raise ValueError.

    Only the JSON types are accepted, so redaction, size bounds and the wire
    encoding of the whole page cannot fail on one adapter's value.
    """
    if depth > 32:
        raise ValueError("overview facts are nested too deeply")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("overview facts contain a non-finite number")
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("overview facts contain a non-string key")
            if key in _REFERENCE_KEYS and type(item) is not str:
                raise ValueError("overview reference is not a string")
            if key == "read_ids" and (not isinstance(item, (list, tuple))
                                      or any(type(entry) is not str for entry in item)):
                raise ValueError("overview read references are not strings")
            result[key] = _plain(item, depth + 1)
        return result
    raise ValueError("overview facts contain a value that cannot be encoded")


def _validated(facts, reads):
    """Validate the adapter contract shape before any of it enters the row."""
    if not isinstance(facts, model.DeviceFacts):
        raise ValueError("adapter returned invalid overview facts")
    if not isinstance(facts.fields, dict) or set(facts.fields) - set(model.FACT_FIELDS):
        raise ValueError("adapter returned invalid overview facts")
    fields = _plain(facts.fields)
    managed = fields.get("managed")
    if managed is not None and (not isinstance(managed, list)
                                or not all(isinstance(child, dict) for child in managed)):
        raise ValueError("adapter returned invalid managed facts")
    entries = []
    for name, value in (("missing", facts.missing), ("findings", facts.findings)):
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"adapter returned invalid {name}")
        value = _plain(value)
        if not all(isinstance(entry, dict) and "field" in entry for entry in value):
            raise ValueError(f"adapter returned invalid {name}")
        entries.append(value)
    if not all(entry.get("reason") in model.REASONS for entry in entries[0]):
        raise ValueError("adapter returned an unknown missing reason")
    if not all(type(entry.get("code")) is str and type(entry.get("severity")) is str for entry in entries[1]):
        raise ValueError("adapter returned invalid findings")
    incomplete = facts.incomplete_reads
    if (not isinstance(incomplete, (list, tuple))
            or not all(type(key) is str and key in reads for key in incomplete)):
        raise ValueError("adapter returned invalid incomplete reads")
    answered = facts.answered_reads
    if (not isinstance(answered, Mapping)
            or not all(type(key) is str and key in reads and value in _ANSWERS for key, value in answered.items())):
        raise ValueError("adapter returned invalid answered reads")
    return fields, entries[0], entries[1], tuple(incomplete), dict(answered)


_ANSWERS = frozenset({"empty", "not_applicable"})


def _answered(reads, answered, incomplete):
    """Apply adapter-recognized device answers to reads the frame left unparsed."""
    for key, answer in answered.items():
        read = reads[key]
        # Only a captured answer that the frame could not classify; never a refusal, timeout or scope reason.
        if read.reason == "unparsed" and read.text is not None and key not in incomplete:
            reads[key] = replace(read, status="empty", reason=None if answer == "empty" else "not_applicable")
    for key, read in reads.items():
        # A step skipped because its prerequisite was unparsed inherits the recognized answer.
        if (read.status == "not_run" and read.reason == "unparsed" and read.spec.requires
                and all(reads[required].reason == "not_applicable" for required in read.spec.requires)):
            reads[key] = replace(read, reason="not_applicable")


def _assemble(auth, scope, module, steps, budget):
    row = model.blank_device(auth.alias, scope.platform)
    attempt_start = time.monotonic()
    reads = _run_reads(auth, steps, budget)
    attempted = [item for item in reads.values() if item.observed_at is not None]
    if attempted:
        row["duration_ms"] = max(0, int(1000 * (time.monotonic() - attempt_start)))
        reach = {item.reachability for item in attempted}
        row["reachability"] = ("reachable" if "reachable" in reach else
                               "unreachable" if "unreachable" in reach else "unknown")
    try:
        facts = module.assemble(scope, MappingProxyType(reads))
    except Exception:
        facts = None
        row["missing"].append(model.missing("device", "internal_error"))
    if facts is not None:
        try:
            fields, facts_missing, facts_findings, incomplete, answered = _validated(facts, reads)
        except Exception:
            # Malformed adapter output stays in this row; the rest of the page is still built.
            row["missing"].append(model.missing("device", "unparsed"))
        else:
            try:
                candidate = {**row, **fields, "missing": facts_missing}
                derived = _findings(candidate, reads)
                candidate["findings"] = [*facts_findings, *(item for item in derived if item not in facts_findings)]
            except Exception:
                row["missing"].append(model.missing("device", "internal_error"))
            else:
                row = candidate
                for key in incomplete:
                    if reads[key].status in {"ok", "empty"}:
                        reads[key] = replace(reads[key], status="incomplete", reason="unparsed")
                _answered(reads, answered, incomplete)
    row["reads"] = [answer.public(scope.platform) for answer in reads.values()]
    for answer in reads.values():
        if answer.reason:
            details = {"read_id": answer.spec.id}
            if answer.retry_after_seconds is not None:
                details["retry_after_seconds"] = answer.retry_after_seconds
            for field in answer.spec.fields:
                entry = model.missing(field, answer.reason, **details)
                if entry not in row["missing"]:
                    row["missing"].append(entry)
    if not (any(entry["reason"] != "not_applicable" for entry in row["missing"])
            or any(child.get("status") != "complete" for child in row["managed"] or [])):
        row["status"] = "complete"
    return row


_LANES = {}
_LANES_LOCK = Lock()


@contextmanager
def _alias_lane(alias, deadline, cancelled):
    with _LANES_LOCK:
        lock, count = _LANES.get(alias, (Lock(), 0))
        _LANES[alias] = lock, count + 1
    acquired = False
    try:
        while not cancelled.is_set() and (remaining := deadline - time.monotonic()) > 0:
            if lock.acquire(timeout=min(0.05, remaining)):
                acquired = True
                break
        yield acquired
    finally:
        if acquired:
            lock.release()
        with _LANES_LOCK:
            _, count = _LANES[alias]
            if count == 1:
                del _LANES[alias]
            else:
                _LANES[alias] = lock, count - 1


def _target(row, auth, deadline, cancelled, secrets):
    target, platform = row["target"], row["platform"]
    result = model.blank_device(target, platform)
    try:
        if row["reason"]:
            result["missing"] = [model.missing("device", row["reason"])]
            engine._overview_audit_skipped(engine._overview_redact(target, secrets=secrets), row["reason"])
            return result
        if auth is None or auth.ssh_platform != platform:
            raise ValueError("overview plan has no matching authorization")
        scope = model.Scope(platform, auth.enabled_queries, auth.read_inventory,
                            auth.device_types, auth.fortios_rest_token is not None)
        module = adapter(platform)
        if module is None:
            raise ValueError("overview adapter unavailable")
        steps = tuple(_selected_steps(row, model.with_identity(scope, module.plan(scope))))
        with _alias_lane(target, deadline, cancelled) as acquired:
            target_end = min(deadline, time.monotonic() + model.TARGET_SECONDS)
            budget = Budget(target_end if acquired else time.monotonic(), cancelled)
            result = engine.network_overview(auth, lambda: _assemble(auth, scope, module, steps, budget))
            result.pop("ok")
            return result
    except Exception:
        result["missing"] = [model.missing("device", "internal_error")]
        return result


def _cut_marker(row, count):
    if not count:
        return
    row["status"] = "partial"
    for entry in row["missing"]:
        if entry["reason"] == "output_limit" and entry["field"] == "device":
            entry["omitted_count"] = entry.get("omitted_count", 0) + count
            return
    row["missing"].append(model.missing("device", "output_limit", omitted_count=count))


def _clean_details(row, maximum=model.MAX_DETAILS):
    reads = {item["id"]: item["status"] for item in row["reads"][:maximum]}
    removed = len(row["reads"]) - len(reads)
    row["reads"] = row["reads"][:maximum]
    managed_count = min(len(row["managed"] or []), maximum)

    def clean(value, key=""):
        nonlocal removed
        if isinstance(value, dict):
            return {field: clean(item, field) for field, item in value.items()}
        if not isinstance(value, list):
            return value
        kept = []
        for item in value:
            if len(kept) == maximum:
                break
            if isinstance(item, dict):
                ids = item.get("read_ids")
                source = item.get("read_id")
                field = item.get("field", "")
                if field.startswith("managed[") and field.partition("]")[0][8:].isdigit():
                    if int(field.partition("]")[0][8:]) >= managed_count:
                        continue
                if source is not None and source not in reads:
                    continue
                if isinstance(ids, (tuple, list)):
                    ids = [key for key in ids if key in reads and reads[key] != "not_run"]
                    if not ids:
                        continue
                    item = {**item, "read_ids": ids}
            kept.append(clean(item))
        removed += len(value) - len(kept)
        return kept

    for key in model.FACT_FIELDS + ("findings", "missing"):
        if key in row:
            row[key] = clean(row[key], key)
    # Keep one of the bounded missing entries available for the limit marker.
    if removed and len(row["missing"]) == maximum:
        row["missing"].pop()
        removed += 1
    _cut_marker(row, removed)


def _size_bound(result):
    rows = result["devices"]
    for row in rows:
        _clean_details(row)
    available = model.MAX_OUTPUT - 2048
    sizes = [model.encoded_size(row) for row in rows]
    if sum(sizes) <= available:
        return
    # Preserve the target row, reachability, duration, and a count if its
    # details cannot fit. Trimming a row as one unit preserves its references.
    for index in sorted(range(len(rows)), key=sizes.__getitem__, reverse=True):
        row = rows[index]
        replacement = model.blank_device(row["target"], row["platform"])
        replacement.update(reachability=row["reachability"], duration_ms=row["duration_ms"])
        omitted = sum(len(row[key]) if isinstance(row.get(key), list) else int(row.get(key) is not None)
                      for key in model.FACT_FIELDS + ("reads", "missing", "findings"))
        _cut_marker(replacement, max(1, omitted))
        available += sizes[index] - model.encoded_size(replacement)
        rows[index] = replacement
        if sum(sizes) <= available:
            break


def _summary(rows):
    summary = dict.fromkeys(("complete", "partial", "reachable", "unreachable", "reachability_unknown"), 0)
    counts = summary["findings_by_severity"] = dict.fromkeys(("info", "warning", "critical"), 0)
    for row in rows:
        summary[row["status"]] += 1
        state = row["reachability"]
        summary["reachability_unknown" if state == "unknown" else state] += 1
        for finding in row["findings"]:
            severity = finding.get("severity")
            if severity in counts:
                counts[severity] += 1
    return summary


def run(plan, cancelled, deadline):
    rows = plan["rows"]
    selection = plan["selection"]
    if (not isinstance(rows, list) or len(rows) > model.MAX_TARGETS
            or selection["returned"] != len(rows)
            or list(row["target"] for row in rows) != sorted({row["target"] for row in rows})):
        raise ValueError("invalid internal overview page")
    secrets = list(plan["secrets"])
    auths = []
    for row in rows:
        context = row["context"]
        try:
            auth = TargetAuth.decode(row["target"], context) if context is not None else None
        except ValueError:
            row["reason"] = "auth_failed"
            auth = None
        auths.append(auth)
        if context is not None:
            secrets.append(context)
        if auth is not None:
            secrets.extend(auth.secrets)
    secrets = tuple(dict.fromkeys(secrets))
    completed = {}
    queue = iter(zip(rows, auths, strict=True))

    def execute(row, auth):
        return _target(row, replace(auth, output_secrets=secrets) if auth else None,
                       deadline, cancelled, secrets)

    def finish(row, result):
        completed[row["target"]] = result
        if not cancelled.is_set():
            progress.report(len(completed), len(rows), "Network overview target processed")

    if rows:
        with ThreadPoolExecutor(max_workers=model.MAX_PARALLEL, thread_name_prefix="overview") as executor:
            active = {}
            while True:
                while (len(active) < model.MAX_PARALLEL and not cancelled.is_set()
                       and time.monotonic() < deadline):
                    item = next(queue, None)
                    if item is None:
                        break
                    row, auth = item
                    active[executor.submit(execute, row, auth)] = row
                if not active:
                    break
                done, _ = wait(active, return_when=FIRST_COMPLETED)
                for future in done:
                    finish(active.pop(future), future.result())
        for row, auth in queue:
            # Record planned coverage and audit without opening a transport.
            finish(row, execute(row, auth))
    output = {"status": "complete", "started_at": plan["started_at"], "finished_at": model.utc_now(),
              "device_output_trust": "untrusted", "selection": selection,
              "devices": [completed[row["target"]] for row in rows]}
    # Sanitize device-derived facts before measuring size and pruning references.
    for row in output["devices"]:
        for field in (*model.FACT_FIELDS, "findings"):
            if field in row:
                row[field] = engine._overview_redact(row[field], secrets=secrets)
    _size_bound(output)
    output["summary"] = _summary(output["devices"])
    if selection["remaining"] or selection["unverified"] or output["summary"]["partial"]:
        output["status"] = "partial"
    return output
