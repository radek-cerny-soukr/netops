"""Secret-free JSONL audit records kept by the shared access layer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netops_core.audit import Recorder


AUDIT_PATH = Path("/var/lib/netops-helper/audit.jsonl")
_RECORDER = Recorder(AUDIT_PATH, "helper")


class AuditPersistenceError(RuntimeError):
    """Base class for typed failures of the mandatory audit boundary."""

    error_code = "audit_persistence"


class AuditPreflightError(AuditPersistenceError):
    """The audit attempt could not be persisted, so the operation did not start."""

    error_code = "audit_preflight_failed"
    operation_started = False


class AuditPostOperationError(AuditPersistenceError):
    """The operation ran, but its completion record could not be persisted."""

    error_code = "audit_post_operation_failed"
    operation_started = True


def record(event: str, **fields: Any) -> None:
    _RECORDER.record(event, **fields)
