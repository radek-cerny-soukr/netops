from __future__ import annotations

import datetime
import json
import math
import os
import re
import time
from pathlib import Path

from netops_admin.errors import Rejected

MAX_EVENT_BYTES = 8192
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

    def check_writable(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, AUDIT_FILE_MODE)
            try:
                os.fchmod(descriptor, AUDIT_FILE_MODE)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise Rejected(["the audit log cannot be written durably: %s" % exc.strerror]) from None

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
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, AUDIT_FILE_MODE)
        try:
            os.fchmod(descriptor, AUDIT_FILE_MODE)
            written = os.write(descriptor, line)
            if written != len(line):
                raise OSError("short write to the audit log")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return document


def export_updated_at(status_file):
    if status_file is None:
        return None
    try:
        return float(json.loads(Path(status_file).read_text(encoding="utf-8"))["updated_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def export_state(status_file, limits: dict, clock=time.time) -> tuple:
    if status_file is None:
        return "not-configured", None
    try:
        status = json.loads(Path(status_file).read_text(encoding="utf-8"))
        updated = float(status["updated_at"])
        pending = status["pending"]
        oldest = float(status.get("oldest_pending_age_seconds", 0))
        if (not isinstance(pending, int) or isinstance(pending, bool) or pending < 0
                or not math.isfinite(updated) or not math.isfinite(oldest) or oldest < 0
                or updated > clock() + 5):
            raise ValueError("invalid export status")
    except (OSError, ValueError, KeyError, TypeError, OverflowError, AttributeError):
        return "blocked", "export status cannot be read"
    if clock() - updated > limits["export_status_max_age_seconds"]:
        return "blocked", "export status is stale"
    if pending > limits["export_max_pending"]:
        return "blocked", "export queue holds %d events, over the limit" % pending
    if pending and oldest > limits["export_max_age_seconds"]:
        return "blocked", "the oldest unsent audit event is older than the limit"
    if pending:
        return "pending", None
    return "acknowledged", None
