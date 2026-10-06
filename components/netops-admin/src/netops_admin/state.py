from __future__ import annotations

import fcntl
import json
import math
import os
import re
import secrets
import stat
from pathlib import Path

from netops_admin.errors import Rejected, StateUnreadable
from netops_admin.jsontext import parse
from netops_core.inputs import InputError, read_regular

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
REJECTIONS_FILE = "rejections.json"
REJECTIONS_LOCK = ".rejections.lock"
CHANGE_NAME = re.compile(r"^[0-9a-f]{32}$")
REQUEST_NAME = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
REJECTION_WINDOW = 3600
MAX_REJECTION_ENTRIES = 10000
REQUEST_FIELDS = ("request_id", "change_id", "request_sha256", "device")
OPERATION_FIELDS = ("change_id", "request_id", "device", "status")
OPERATION_STATUSES = ("running", "finished")
OPERATION_TEXTS = ("result", "reason", "notification", "audit_delivery", "hostname", "kind", "accounts",
                   "created_at", "request_sha256")
OPERATION_NUMBERS = ("created_at_epoch", "finished_at_epoch")
OPERATION_LISTS = ("differences", "postcheck_differences", "final_check_differences")
SAFE_TEXT = re.compile(r"^[\x20-\x7e]{0,200}$")
MAX_STATE_BYTES = 16 * 1024 * 1024
LOCK_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


def _text(value) -> bool:
    return isinstance(value, str) and SAFE_TEXT.fullmatch(value) is not None


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _optional(document, names, valid) -> bool:
    return all(document.get(name) is None or valid(document[name]) for name in names)


def _operation_valid(document, name: str) -> bool:
    steps = document.get("steps", [])
    safeguard = document.get("safeguard", {})
    sessions = document.get("foreign_sessions")
    return (
        all(_text(document.get(field)) for field in OPERATION_FIELDS)
        and document["change_id"] == name and document["status"] in OPERATION_STATUSES
        and _optional(document, OPERATION_TEXTS, _text)
        and _optional(document, OPERATION_NUMBERS, _number)
        and ("budget_changes" not in document or type(document["budget_changes"]) is int and 1 <= document["budget_changes"] <= 32)
        and _optional(document, OPERATION_LISTS, lambda value: isinstance(value, list))
        and _optional(document, ("plan", "audit_policy"), lambda value: isinstance(value, dict))
        and isinstance(steps, list) and all(isinstance(step, dict) and _text(step.get("step")) for step in steps)
        and isinstance(safeguard, dict) and ("safeguard" not in document or _text(safeguard.get("fire_at")))
        and _optional(safeguard, ("name",), _text)
        and (sessions is None or isinstance(sessions, int) and not isinstance(sessions, bool) and sessions >= 0)
    )


def _block_valid(document) -> bool:
    change = document.get("change_id")
    return (_text(document.get("device")) and _text(document.get("reason"))
            and (change is None or isinstance(change, str) and CHANGE_NAME.fullmatch(change) is not None))


def _directory(path: Path) -> Path:
    path.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_atomic(path: Path, document) -> None:
    data = (json.dumps(document, sort_keys=True, ensure_ascii=True, indent=1) + "\n").encode("ascii")
    temporary = path.with_name(".%s.%s.tmp" % (path.name, secrets.token_hex(8)))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    try:
        try:
            written = os.write(descriptor, data)
            if written != len(data):
                raise OSError("short write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def read_json(path: Path):
    try:
        raw = read_regular(path, MAX_STATE_BYTES, follow=False)
    except FileNotFoundError:
        return None
    except InputError as error:
        raise ValueError(str(error)) from None
    return parse(raw)


def _lock_descriptor(path: Path) -> int:
    try:
        descriptor = os.open(path, LOCK_FLAGS, FILE_MODE)
    except OSError as exc:
        raise Rejected(["the lock file %s cannot be used: %s" % (path.name, exc.strerror)]) from None
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise Rejected(["the lock file %s is not a regular file" % path.name])
    return descriptor


class Store:
    def __init__(self, root):
        self.root = Path(root)
        try:
            self.operations = _directory(self.root / "operations")
            self.requests = _directory(self.root / "requests")
            self.locks = _directory(self.root / "locks")
            self.blocks = _directory(self.root / "blocked")
            self.baselines = _directory(self.root / "baselines")
            self.enrollments = _directory(self.root / "enrollments")
        except (OSError, ValueError) as exc:
            raise StateUnreadable(["the state directory cannot be used: %s"
                                   % (getattr(exc, "strerror", None) or type(exc).__name__)]) from None

    def check_writable(self) -> None:
        probe = self.root / (".write-probe-%s" % secrets.token_hex(8))
        try:
            write_atomic(probe, {"probe": True})
            probe.unlink()
        except OSError as exc:
            raise Rejected(["the journal cannot be written durably: %s" % exc.strerror]) from None

    def lock(self, device: str):
        return DeviceLock(self.locks / ("%s.lock" % device))

    def unreadable(self, path: Path) -> StateUnreadable:
        return StateUnreadable(["the state file %s cannot be read; a person must check it"
                                % path.relative_to(self.root)])

    def _document(self, path: Path, fields=(), valid=None):
        try:
            document = read_json(path)
            readable = document is None or isinstance(document, dict) and all(
                isinstance(document.get(name), str) for name in fields) and (valid is None or valid(document))
        except (OSError, ValueError):
            readable = False
        if not readable:
            raise self.unreadable(path)
        return document

    def request(self, request_id: str):
        if not isinstance(request_id, str) or not REQUEST_NAME.match(request_id):
            return None
        path = self.requests / ("%s.json" % request_id)
        document = self._document(path, REQUEST_FIELDS)
        if document is not None and (not CHANGE_NAME.fullmatch(document["change_id"])
                                     or document["request_id"] != request_id or not _text(document["device"])):
            raise self.unreadable(path)
        return document

    def remember_request(self, request_id: str, change_id: str, fingerprint: str, device: str) -> None:
        write_atomic(self.requests / ("%s.json" % request_id),
                     {"request_id": request_id, "change_id": change_id, "request_sha256": fingerprint, "device": device})

    def _operation(self, path: Path):
        return self._document(path, OPERATION_FIELDS, lambda document: _operation_valid(document, path.stem))

    def operation(self, change_id: str):
        if not isinstance(change_id, str) or not CHANGE_NAME.fullmatch(change_id):
            return None
        return self._operation(self.operations / ("%s.json" % change_id))

    def save(self, record: dict) -> None:
        write_atomic(self.operations / ("%s.json" % record["change_id"]), record)

    def running(self, device: str) -> list:
        found = []
        for path in sorted(self.operations.glob("*.json")):
            record = self._operation(path)
            if record and record.get("device") == device and record.get("status") == "running":
                found.append(record)
        return found

    def records(self) -> list:
        return [record for record in (self._operation(path)
                                      for path in sorted(self.operations.glob("*.json"))) if record]

    def _rejections(self) -> list:
        try:
            moments = read_json(self.root / REJECTIONS_FILE)
            readable = moments is None or isinstance(moments, list) and all(
                isinstance(moment, (int, float)) and not isinstance(moment, bool) for moment in moments)
        except (OSError, ValueError):
            readable = False
        if not readable:
            raise Rejected(["the count of refused requests (%s) cannot be read; a person must check it"
                            % REJECTIONS_FILE])
        return moments or []

    def rejections_since(self, since: float) -> int:
        return sum(1 for moment in self._rejections() if moment >= since)

    def note_rejection(self, now: float) -> None:
        descriptor = _lock_descriptor(self.root / REJECTIONS_LOCK)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            kept = [moment for moment in self._rejections() if moment >= now - REJECTION_WINDOW]
            write_atomic(self.root / REJECTIONS_FILE, (kept + [now])[-MAX_REJECTION_ENTRIES:])
        finally:
            os.close(descriptor)

    def baseline(self, device: str):
        document = self._document(self.baselines / ("%s.json" % device),
                                  valid=lambda document: isinstance(document.get("accounts"), str))
        return None if document is None else document.get("accounts")

    def _removed(self, path: Path) -> bool:
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        except OSError:
            raise self.unreadable(path) from None
        _fsync_directory(path.parent)
        return True

    def save_baseline(self, device: str, fingerprint: str) -> None:
        write_atomic(self.baselines / ("%s.json" % device), {"device": device, "accounts": fingerprint})

    def clear_baseline(self, device: str) -> None:
        self._removed(self.baselines / ("%s.json" % device))

    def enrollment(self, device: str):
        return self._document(self.enrollments / ("%s.json" % device))

    def save_enrollment(self, device: str, certificate):
        write_atomic(self.enrollments / ("%s.json" % device), certificate)

    def clear_enrollment(self, device: str):
        self._removed(self.enrollments / ("%s.json" % device))

    def blocked(self, device: str):
        return self._document(self.blocks / ("%s.json" % device), valid=_block_valid)

    def block(self, device: str, change_id: str, reason: str) -> None:
        write_atomic(self.blocks / ("%s.json" % device), {"device": device, "change_id": change_id, "reason": reason})

    def unblock(self, device: str) -> bool:
        return self._removed(self.blocks / ("%s.json" % device))


class DeviceLock:
    def __init__(self, path: Path):
        self.path = path
        self.descriptor = None

    def __enter__(self):
        self.descriptor = _lock_descriptor(self.path)
        try:
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.descriptor)
            self.descriptor = None
            raise Rejected(["another operation holds the device lock"]) from None
        return self

    def __exit__(self, *exc_info):
        if self.descriptor is not None:
            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            os.close(self.descriptor)
            self.descriptor = None
        return False
