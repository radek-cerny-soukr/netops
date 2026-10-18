import asyncio
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import socket
import ssl
import time
import uuid
from .files import MAX_MESSAGE, check_regular, read_private, sync_directory, write_private
from .redaction import redact

def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object keys are unsupported")
        result[key] = value
    return result

def invalid_constant(value):
    raise ValueError("Nonfinite JSON constants are unsupported")

class AuditUnavailable(Exception):
    pass

RECOVER_HINT = "stop the instance and run `docker compose run --rm netops audit recover`"
SEGMENT_READ_LIMIT = 33554432
SYSLOG_BATCH_RECORDS = 512
SYSLOG_BATCH_BYTES = 16777216
SYSLOG_STALE_SECONDS = 300
SYSLOG_MIN_RATE = 65536
SMALL_AUDIT_MESSAGE = 65536

def oldest_queued_age(directory, now=None):
    names = [path.name for path in Path(directory).glob("*.queue")]
    if not names:
        return 0.0
    oldest = min(int(name.split("-", 1)[0]) for name in names)
    return max(0.0, (now if now is not None else time.time()) - oldest / 1e9)

def file_order(path):
    name = path.name
    if name == "current.jsonl":
        return (2, 0, name)
    stem, _, suffix = name.rpartition(".")
    prefix, dash, _ = stem.partition("-")
    if prefix.isascii() and prefix.isdigit():
        if suffix == "jsonl" and not dash:
            return (1, int(prefix), name)
        if suffix == "queue" and dash:
            return (3, int(prefix), name)
    return (0, 0, name)

def incomplete_tail(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        check_regular(fd)
        size = os.fstat(fd).st_size
        return size > 0 and os.pread(fd, 1, size - 1) != b"\n"
    finally:
        os.close(fd)

def live_incomplete_tail(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        check_regular(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        size = os.fstat(fd).st_size
        return size > 0 and os.pread(fd, 1, size - 1) != b"\n"
    finally:
        os.close(fd)

def queued_bytes(directory):
    total = 0
    for path in Path(directory).glob("*.queue"):
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise
    return total

def split_records(raw):
    cut = raw.rfind(b"\n") + 1
    return raw[:cut].splitlines(), raw[cut:]

def recover(directory):
    import hashlib
    directory = Path(directory)
    plan = []
    for path in sorted(directory.glob("*.jsonl")):
        raw = read_private(path, SEGMENT_READ_LIMIT, os.geteuid())
        lines, fragment = split_records(raw)
        for line in lines:
            try:
                json.loads(line)
            except ValueError:
                raise ValueError("A complete audit record in " + path.name + " is not valid JSON; nothing was changed; inspect the segment manually") from None
        if fragment:
            plan.append((path, len(raw), len(raw) - len(fragment), fragment))
    results = []
    for path, size, cut, fragment in plan:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            check_regular(fd, os.geteuid())
            if os.fstat(fd).st_size != size:
                raise ValueError("Audit segment " + path.name + " changed during recovery; it was not modified")
            quarantine = directory / ("incomplete-" + path.stem + "-" + str(time.time_ns()) + ".partial")
            write_private(quarantine, fragment, os.geteuid())
            os.ftruncate(fd, cut)
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_directory(directory)
        results.append({"segment": path.name, "bytes": len(fragment), "sha256": hashlib.sha256(fragment).hexdigest(), "quarantine": quarantine.name})
    return results

class Audit:
    def __init__(self, directory, settings, secrets=()):
        self.directory = Path(directory)
        self.settings = settings
        self.secrets = secrets
        self.lock = asyncio.Lock()
        self.heavy = asyncio.Semaphore(1)
        self.budget = int(settings.get("budget_bytes", 268435456))
        self.segment_size = int(settings.get("segment_bytes", 16777216))
        self.retention_seconds = int(settings.get("retention_seconds", 604800))
        if self.budget < MAX_MESSAGE * 4 or not MAX_MESSAGE <= self.segment_size <= self.budget or self.retention_seconds <= 0:
            raise ValueError("Invalid audit disk budget or retention")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.current = self.directory / "current.jsonl"
        self.stop = asyncio.Event()
        self.rejections_path = self.directory / "rejections.json"
        self.rejections = {"authentication_required": 0, "https_required": 0}
        self.rejections_first = None
        self.rejections_last = None
        self.rejections_due = 0.0
        self.rejections_task = None
        if self.rejections_path.exists():
            prior = json.loads(read_private(self.rejections_path, 4096, os.geteuid()))
            for key in self.rejections:
                value = prior["counts"][key]
                if type(value) is not int or not 0 <= value <= 9223372036854775807:
                    raise ValueError("Invalid rejection summary")
                self.rejections[key] = value
            self.rejections_first = prior.get("first")
            self.rejections_last = prior.get("last")

    def _rejection_snapshot(self):
        return {"representation": "aggregated-rejections", "counts": dict(self.rejections), "first": self.rejections_first, "last": self.rejections_last, "body_read": False, "body_retained": False, "headers_retained": False, "flush_interval_seconds": 60, "crash_may_lose_latest_seconds": 60}

    async def _persist_rejections(self, snapshot):
        try:
            await asyncio.to_thread(write_private, self.rejections_path, json.dumps(snapshot, separators=(",", ":"), allow_nan=False).encode() + b"\n", os.geteuid(), True)
        except (OSError, ValueError):
            import sys
            sys.stderr.write("netops: rejection summary unavailable; denied requests cannot execute\n")

    async def reject(self, reason):
        self.rejections[reason] = min(self.rejections[reason] + 1, 9223372036854775807)
        now = datetime.now(timezone.utc).isoformat()
        self.rejections_first = self.rejections_first or now
        self.rejections_last = now
        if time.monotonic() >= self.rejections_due and (self.rejections_task is None or self.rejections_task.done()):
            self.rejections_due = time.monotonic() + 60
            self.rejections_task = asyncio.create_task(self._persist_rejections(self._rejection_snapshot()))
            await asyncio.shield(self.rejections_task)

    async def flush_rejections(self):
        if self.rejections_task is not None:
            await self.rejections_task
        if self.rejections_last is not None:
            await self._persist_rejections(self._rejection_snapshot())

    def _files(self):
        suffix = ".queue" if self.settings["mode"] == "syslog" else ".jsonl"
        return sorted(self.directory.glob("*" + suffix))

    def _append(self, event):
        encoded = json.dumps(event, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode() + b"\n"
        if len(encoded) > MAX_MESSAGE * 2:
            raise AuditUnavailable("Audit record exceeds the supported message size")
        files = self._files()
        if self.settings["mode"] == "local":
            now = time.time()
            for path in files:
                if path != self.current and now - path.stat().st_mtime > self.retention_seconds:
                    path.unlink()
            if self.current.exists() and incomplete_tail(self.current):
                raise AuditUnavailable("Incomplete prior audit write requires operator recovery")
            if self.current.exists() and self.current.stat().st_size + len(encoded) > self.segment_size:
                os.rename(self.current, self.directory / (str(time.time_ns()) + ".jsonl"))
                sync_directory(self.directory)
            files = self._files()
            while sum(path.stat().st_size for path in files) + len(encoded) > self.budget:
                candidates = [path for path in files if path != self.current]
                if not candidates:
                    raise AuditUnavailable("Audit budget exhausted")
                min(candidates, key=lambda path: (path.stat().st_mtime_ns, file_order(path))).unlink()
                sync_directory(self.directory)
                files = self._files()
            fd = os.open(self.current, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                check_regular(fd, os.geteuid())
                fcntl.flock(fd, fcntl.LOCK_EX)
                length = os.fstat(fd).st_size
                if length:
                    tail = os.open(self.current, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        if os.pread(tail, 1, length - 1) != b"\n":
                            raise AuditUnavailable("Incomplete prior audit write requires operator recovery")
                    finally:
                        os.close(tail)
                view = memoryview(encoded)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("No audit write progress")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            sync_directory(self.directory)
        else:
            if sum(path.stat().st_size for path in files) + len(encoded) > self.budget:
                raise AuditUnavailable("Syslog queue budget exhausted")
            write_private(self.directory / (str(time.time_ns()) + "-" + uuid.uuid4().hex + ".queue"), encoded)

    async def record(self, direction, payload, correlation, secret_values=(), pre_redacted_paths=(), decode=None, heavy=True, **metadata):
        secrets = (*self.secrets, *secret_values)
        if decode is not None:
            heavy = len(payload) > SMALL_AUDIT_MESSAGE
        def prepare():
            content = payload
            invalid_json = False
            if decode == "request":
                try:
                    content = json.loads(payload, object_pairs_hook=strict_pairs, parse_constant=invalid_constant) if payload else None
                except (ValueError, RecursionError):
                    invalid_json = True
                    content = {"redacted_invalid_json": True, "bytes": len(payload), "reason": "Unparseable input may contain credentials"}
            elif decode == "response":
                try:
                    content = json.loads(payload) if payload else None
                except ValueError:
                    content = {"body": payload.decode("utf-8", errors="strict")}
            sanitized, paths = redact({"payload": content, "metadata": metadata}, secrets)
            if invalid_json:
                paths.append(["payload"])
            return sanitized, paths, invalid_json
        async def prepare_and_append():
            try:
                sanitized, paths, invalid_json = await asyncio.to_thread(prepare)
            except RecursionError as error:
                raise AuditUnavailable("audit_unavailable: unsupported nesting depth") from error
            paths.extend(list(path) for path in pre_redacted_paths)
            event = {"time": datetime.now(timezone.utc).isoformat(), "direction": direction, "correlation": correlation, "payload": sanitized["payload"], "redaction": {"paths": paths, "complete_content": not paths, "representation": "parsed-json", "byte_transcript": False}, **sanitized["metadata"]}
            async with self.lock:
                try:
                    await asyncio.to_thread(self._append, event)
                except (OSError, ValueError, RecursionError, AuditUnavailable) as error:
                    raise AuditUnavailable("audit_unavailable") from error
            return invalid_json if decode == "request" else None
        async def commit():
            if heavy:
                async with self.heavy:
                    return await prepare_and_append()
            return await prepare_and_append()
        task = asyncio.create_task(commit())
        cancelled = False
        while not task.done():
            try:
                await asyncio.wait((task,))
            except asyncio.CancelledError:
                cancelled = True
        result = task.result()
        if cancelled:
            raise asyncio.CancelledError
        return result

    def _frame(self, path):
        data = read_private(path, MAX_MESSAGE * 2, os.geteuid()).rstrip(b"\n")
        message = b"<134>1 " + datetime.now(timezone.utc).isoformat().encode() + b" - netops - - - " + data
        return str(len(message)).encode() + b" " + message

    def _deliver(self, paths):
        frames = [self._frame(path) for path in paths]
        timeout = 10 + sum(len(frame) for frame in frames) / SYSLOG_MIN_RATE
        host = self.settings["host"]
        port = int(self.settings.get("port", 6514))
        ca = self.settings.get("ca_file")
        context = ssl.create_default_context(cafile=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                connection.settimeout(timeout)
                for frame in frames:
                    connection.sendall(frame)
                try:
                    connection.unwrap()
                except ssl.SSLEOFError:
                    pass

    def _remove(self, paths):
        for path in paths:
            path.unlink()
        sync_directory(self.directory)

    def _send(self, path):
        self._deliver([path])
        self._remove([path])

    def _batch(self):
        batch, size = [], 0
        for path in self._files()[:SYSLOG_BATCH_RECORDS]:
            length = path.stat().st_size
            if batch and size + length > SYSLOG_BATCH_BYTES:
                break
            batch.append(path)
            size += length
        return batch

    async def forward(self):
        if self.settings["mode"] != "syslog":
            return
        import sys
        delay = 1.0
        failing = False
        while not self.stop.is_set():
            batch = []
            try:
                async with self.lock:
                    batch = await asyncio.to_thread(self._batch)
                if batch:
                    await asyncio.to_thread(self._deliver, batch)
                    async with self.lock:
                        await asyncio.to_thread(self._remove, batch)
                    if failing:
                        sys.stderr.write("netops: syslog delivery recovered\n")
                    failing = False
                    delay = 1.0
                    continue
            except (OSError, ValueError) as error:
                if not failing:
                    sys.stderr.write("netops: syslog delivery failed (" + type(error).__name__ + "); " + str(len(batch)) + " records stay queued and are retried\n")
                failing = True
                delay = min(delay * 2, 30.0)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=delay if failing else 1)
            except TimeoutError:
                pass
