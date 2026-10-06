from __future__ import annotations

import datetime
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from netops_admin.errors import Rejected
from netops_admin.jsontext import parse
from netops_core.inputs import InputError, read_regular

MAX_EVENT_BYTES = 8192
EXPORT_STATUS_MAX_BYTES = 64 * 1024
AUDIT_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK | os.O_CLOEXEC
AUDIT_FILE_MODE = 0o640
SAFE_TEXT = re.compile(r"^[\x20-\x7e]{0,200}$")
EVENT_FIELDS = {
    "start": frozenset((
        "change_id", "request_id", "device", "platform", "firmware", "table", "op", "key", "request_sha256",
        "plan_sha256", "snapshot_sha256", "reason_characters", "user_request_characters", "changes",
        "commands", "inverse_commands", "safeguard",
    )),
    "step": frozenset(("change_id", "device", "step", "detail")),
    "result": frozenset((
        "change_id", "request_id", "device", "status", "result", "reason", "differences", "notification",
        "audit_delivery", "safeguard",
    )),
    "administrative": frozenset(("device", "action", "reason_characters", "change_id")),
    "delivery": frozenset(("change_id", "device", "notification", "audit_delivery")),
}


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _checked(value):
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, str):
        if not SAFE_TEXT.fullmatch(value):
            raise ValueError("audit text must be short printable ASCII")
        return value
    if isinstance(value, list):
        return [_checked(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _checked(item) for key, item in value.items()}
    raise ValueError("audit value of unsupported type %s" % type(value).__name__)


def summarized_changes(profile, changes: dict) -> dict:
    summary = {}
    for name, value in sorted(changes.items()):
        attribute = profile.attributes[name]
        if value is None:
            summary[name] = "removed"
        elif attribute.type == "text":
            summary[name] = "text of %d characters" % len(value)
        elif attribute.type == "name-list":
            summary[name] = "%d object names" % len(value.split())
        elif attribute.type in ("ipv4-network", "ipv4-address", "mac-address"):
            summary[name] = attribute.type + " changed"
        else:
            summary[name] = value
    return summary


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)

    def _open(self) -> int:
        descriptor = os.open(self.path, AUDIT_FLAGS, AUDIT_FILE_MODE)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise OSError("the audit log is not a regular file")
        return descriptor

    def check_writable(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = self._open()
            try:
                os.fchmod(descriptor, AUDIT_FILE_MODE)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise Rejected(["the audit log cannot be written durably: %s" % (exc.strerror or exc)]) from None

    def event(self, kind: str, **fields) -> dict:
        allowed = EVENT_FIELDS[kind]
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError("audit event %s does not carry %s" % (kind, sorted(unknown)))
        document = {"event": kind, "at": now_utc()}
        document.update({name: _checked(value) for name, value in fields.items()})
        line = (json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        if len(line) > MAX_EVENT_BYTES:
            raise ValueError("audit event is larger than %d bytes" % MAX_EVENT_BYTES)
        descriptor = self._open()
        try:
            os.fchmod(descriptor, AUDIT_FILE_MODE)
            written = os.write(descriptor, line)
            if written != len(line):
                raise OSError("short write to the audit log")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return document


def _export_status(status_file):
    return parse(read_regular(status_file, EXPORT_STATUS_MAX_BYTES))


def export_updated_at(status_file):
    if status_file is None:
        return None
    try:
        updated = float(_export_status(status_file)["updated_at"])
    except (OSError, InputError, ValueError, KeyError, TypeError, OverflowError):
        return None
    return updated if math.isfinite(updated) else None


def export_state(status_file, limits: dict, clock=time.time, audit_file=None) -> tuple:
    if status_file is None:
        return "not-configured", None
    try:
        status = _export_status(status_file)
        updated = float(status["updated_at"])
        pending = status["pending"]
        oldest = float(status.get("oldest_pending_age_seconds", 0))
        covered = status.get("audit_file")
        if (not isinstance(pending, int) or isinstance(pending, bool) or pending < 0
                or not math.isfinite(updated) or not math.isfinite(oldest) or oldest < 0
                or updated > clock() + 5
                or (covered is not None and not (isinstance(covered, str) and os.path.isabs(covered)))):
            raise ValueError("invalid export status")
    except (OSError, InputError, ValueError, KeyError, TypeError, OverflowError, AttributeError):
        return "blocked", "export status cannot be read"
    if audit_file is not None and covered is not None and os.path.normpath(covered) != os.path.normpath(audit_file):
        return "blocked", "the export status covers another audit file"
    if clock() - updated > limits["export_status_max_age_seconds"]:
        return "blocked", "export status is stale"
    if pending > limits["export_max_pending"]:
        return "blocked", "export queue holds %d events, over the limit" % pending
    if pending and oldest > limits["export_max_age_seconds"]:
        return "blocked", "the oldest unsent audit event is older than the limit"
    unnamed = None if covered is not None else "the export status does not name the audit file"
    if pending:
        return "pending", unnamed
    return "acknowledged", unnamed
