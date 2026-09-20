from __future__ import annotations

import fcntl
import json
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

COMPONENTS = ("helper", "auditor", "admin")
STATUSES = ("started", "ok", "failed")
SEGMENT_BYTES = 2_000_000
RETAINED_SEGMENTS = 5
LOCK_SUFFIX = ".lock"
OPERATION_ID = re.compile(r"op_[0-9a-f]{32}")
FIELDS = frozenset(
    {
        "operation_id",
        "device",
        "status",
        "channel",
        "request",
        "response_sha256",
        "response_bytes",
        "started_at",
        "finished_at",
        "legacy_ssh",
        "detail",
        "query",
        "platform",
        "port",
        "count",
        "item_count",
        "offset",
        "max_bytes",
        "total_bytes",
        "returned_bytes",
        "path_sha256",
        "result_sha256",
        "use_tls",
        "plaintext_acknowledged",
        "pagination_source",
        "transport",
        "rc",
    }
)


class AuditFieldError(ValueError):
    pass


class AuditPersistenceError(RuntimeError):
    pass


def _checked_count(name, value, smallest) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < smallest:
        raise AuditFieldError(
            "%s must be a whole number of at least %d, got %r" % (name, smallest, value)
        )
    return value


class Recorder:
    def __init__(
        self, path, component, segment_bytes=SEGMENT_BYTES, retained_segments=RETAINED_SEGMENTS
    ) -> None:
        if component not in COMPONENTS:
            raise AuditFieldError(
                "component must be one of %s, got %r" % (", ".join(COMPONENTS), component)
            )
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise AuditFieldError("path must be a file system path, got %r" % (path,))
        self._path = Path(path)
        self._component = component
        self._segment_bytes = _checked_count("segment_bytes", segment_bytes, 1)
        self._retained_segments = _checked_count("retained_segments", retained_segments, 1)
        self._lock = threading.Lock()
        self._lock_path = self._path.with_name(".%s%s" % (self._path.name, LOCK_SUFFIX))

    def path(self) -> Path:
        return self._path

    def lock_path(self) -> Path:
        return self._lock_path

    @contextmanager
    def _exclusive(self):
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def component(self) -> str:
        return self._component

    def _segment(self, index) -> Path:
        return self._path if index == 0 else self._path.with_name(
            "%s.%d" % (self._path.name, index)
        )

    def _rotate(self, incoming_bytes) -> None:
        try:
            current = self._path.stat().st_size
        except FileNotFoundError:
            return
        if current + incoming_bytes <= self._segment_bytes:
            return
        self._segment(self._retained_segments - 1).unlink(missing_ok=True)
        for index in range(self._retained_segments - 2, 0, -1):
            source = self._segment(index)
            if source.exists():
                os.replace(source, self._segment(index + 1))
        if self._retained_segments > 1:
            os.replace(self._path, self._segment(1))
            os.chmod(self._segment(1), 0o600)
        else:
            self._path.unlink(missing_ok=True)

    def _checked_fields(self, event, fields) -> dict:
        if not isinstance(event, str) or not event.strip():
            raise AuditFieldError("event must be a non-empty string, got %r" % (event,))
        unknown = sorted(name for name in fields if name not in FIELDS)
        if unknown:
            raise AuditFieldError(
                "audit record of %r carries unknown field(s) %s; the fields of a record are"
                " written down in this module, one of %s"
                % (event, ", ".join(unknown), ", ".join(sorted(FIELDS)))
            )
        status = fields.get("status")
        if "status" in fields and status not in STATUSES:
            raise AuditFieldError(
                "status must be one of %s, got %r" % (", ".join(STATUSES), status)
            )
        operation_id = fields.get("operation_id")
        if "operation_id" in fields and (
            not isinstance(operation_id, str)
            or OPERATION_ID.fullmatch(operation_id) is None
        ):
            raise AuditFieldError(
                "operation_id must look like op_ followed by 32 hexadecimal characters, got %r"
                % (operation_id,)
            )
        return dict(fields)

    def record(self, event, **fields) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": self._component,
            "event": event,
            **self._checked_fields(event, fields),
        }
        try:
            encoded = (
                json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise AuditFieldError(
                "audit record of %r is not serializable as json: %s" % (event, error)
            ) from None
        if len(encoded) > self._segment_bytes:
            raise AuditPersistenceError(
                "audit record of %r is %d bytes and exceeds the segment limit of %d bytes"
                % (event, len(encoded), self._segment_bytes)
            )
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._exclusive():
                    self._rotate(len(encoded))
                    self._path.touch(mode=0o600, exist_ok=True)
                    os.chmod(self._path, 0o600)
                    with self._path.open("ab") as handle:
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
        except OSError as error:
            raise AuditPersistenceError(
                "cannot write the audit record of %r to %s: %s" % (event, self._path, error)
            ) from None
