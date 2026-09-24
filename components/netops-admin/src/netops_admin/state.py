from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path

from netops_admin.errors import Rejected

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
REJECTIONS_FILE = "rejections.json"
CHANGE_NAME = re.compile(r"^[0-9a-f]{32}$")
REQUEST_NAME = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
REJECTION_WINDOW = 3600
MAX_REJECTION_ENTRIES = 10000


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
    temporary = path.with_name(".%s.tmp" % path.name)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        written = os.write(descriptor, data)
        if written != len(data):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.operations = _directory(self.root / "operations")
        self.requests = _directory(self.root / "requests")
        self.locks = _directory(self.root / "locks")
        self.blocks = _directory(self.root / "blocked")
        self.baselines = _directory(self.root / "baselines")
        self.enrollments = _directory(self.root / "enrollments")

    def check_writable(self) -> None:
        probe = self.root / ".write-probe"
        try:
            write_atomic(probe, {"probe": True})
            probe.unlink()
        except OSError as exc:
            raise Rejected(["the journal cannot be written durably: %s" % exc.strerror]) from None

    def lock(self, device: str):
        return DeviceLock(self.locks / ("%s.lock" % device))

    def request(self, request_id: str):
        if not isinstance(request_id, str) or not REQUEST_NAME.match(request_id):
            return None
        return read_json(self.requests / ("%s.json" % request_id))

    def remember_request(self, request_id: str, change_id: str, fingerprint: str, device: str) -> None:
        write_atomic(self.requests / ("%s.json" % request_id),
                     {"request_id": request_id, "change_id": change_id, "request_sha256": fingerprint, "device": device})

    def operation(self, change_id: str):
        if not isinstance(change_id, str) or not CHANGE_NAME.match(change_id):
            return None
        return read_json(self.operations / ("%s.json" % change_id))

    def save(self, record: dict) -> None:
        write_atomic(self.operations / ("%s.json" % record["change_id"]), record)

    def running(self, device: str) -> list:
        found = []
        for path in sorted(self.operations.glob("*.json")):
            record = read_json(path)
            if record and record.get("device") == device and record.get("status") == "running":
                found.append(record)
        return found

    def records(self) -> list:
        return [record for record in (read_json(path) for path in sorted(self.operations.glob("*.json"))) if record]

    def rejections_since(self, since: float) -> int:
        return sum(1 for moment in read_json(self.root / REJECTIONS_FILE) or [] if moment >= since)

    def note_rejection(self, now: float) -> None:
        kept = [moment for moment in read_json(self.root / REJECTIONS_FILE) or [] if moment >= now - REJECTION_WINDOW]
        write_atomic(self.root / REJECTIONS_FILE, (kept + [now])[-MAX_REJECTION_ENTRIES:])

    def baseline(self, device: str):
        document = read_json(self.baselines / ("%s.json" % device))
        return None if document is None else document.get("accounts")

    def save_baseline(self, device: str, fingerprint: str) -> None:
        write_atomic(self.baselines / ("%s.json" % device), {"device": device, "accounts": fingerprint})

    def clear_baseline(self, device: str) -> None:
        path = self.baselines / ("%s.json" % device)
        if path.exists():
            path.unlink()
            _fsync_directory(path.parent)

    def enrollment(self, device: str):
        return read_json(self.enrollments / ("%s.json" % device))

    def save_enrollment(self, device: str, certificate):
        write_atomic(self.enrollments / ("%s.json" % device), certificate)

    def clear_enrollment(self, device: str):
        path = self.enrollments / ("%s.json" % device)
        if path.exists():
            path.unlink()
            _fsync_directory(path.parent)

    def blocked(self, device: str):
        return read_json(self.blocks / ("%s.json" % device))

    def block(self, device: str, change_id: str, reason: str) -> None:
        write_atomic(self.blocks / ("%s.json" % device), {"device": device, "change_id": change_id, "reason": reason})

    def unblock(self, device: str) -> bool:
        path = self.blocks / ("%s.json" % device)
        if not path.exists():
            return False
        path.unlink()
        _fsync_directory(path.parent)
        return True


class DeviceLock:
    def __init__(self, path: Path):
        self.path = path
        self.descriptor = None

    def __enter__(self):
        self.descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT, FILE_MODE)
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
