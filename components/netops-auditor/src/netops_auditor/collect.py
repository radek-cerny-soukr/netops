from __future__ import annotations

import hashlib
import http.client
import io
import ssl
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from netops_core import hostkey, prompt, ssh
from netops_core import legacy_ssh as legacy

MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
CHANNEL_FILE = "file"
CHANNEL_REST = "fortios-rest"
CHANNEL_SSH = "ssh"
PLATFORM_FORTIOS = "fortios"
PLATFORM_EXOS = "exos"
OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
COMPLETENESS_SECTION = "snapshot"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
REST_SCHEME = "https://"
REST_METHOD = "POST"
REST_TARGET = "/api/v2/monitor/system/config/backup?scope=global"
REST_PORT = 443
REST_TIMEOUT_SECONDS = 30.0
REST_ACCEPT = "text/plain"
READ_CHUNK_BYTES = 65536
REST_MAX_BODY_BYTES = 8 * 1024 * 1024
REST_ERROR_HEAD_BYTES = 4096
REST_TIMEOUT_REASON = "the device did not finish the answer within the timeout"
TLS_FINGERPRINT_LENGTH = 64
TLS_FINGERPRINT_CHARS = frozenset("0123456789abcdef")
SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 120.0


class CollectError(Exception):
    def __init__(self, message: str, event=None):
        super().__init__(message)
        self.event = event


class ResponseTooLarge(Exception):
    pass


@dataclass(frozen=True)
class Snapshot:
    device: str
    platform: str
    channel: str
    source: str
    sha256: str
    size_bytes: int
    collected_at: str
    profile: str
    text: str = field(repr=False)


@dataclass(frozen=True)
class ChannelEvent:
    device: str
    channel: str
    request: str
    response_sha256: str
    response_bytes: int
    started_at: str
    finished_at: str
    outcome: str


def _checked_text(name: str, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CollectError("%s must be a non-empty string, got %r" % (name, value))
    return value


def _clock(now):
    if now is None:
        return lambda: datetime.now(timezone.utc)
    if callable(now):
        return now
    raise CollectError("now must be a callable returning an aware datetime, got %r" % (now,))


def _moment(clock) -> str:
    value = clock()
    if not isinstance(value, datetime):
        raise CollectError("clock must return a datetime, got %r" % (value,))
    if value.tzinfo is None or value.utcoffset() is None:
        raise CollectError("clock must return a timezone aware datetime, got %r" % (value,))
    return value.astimezone(timezone.utc).strftime(MOMENT_FORMAT)


def _finished(
    device: str,
    request: str,
    started_at: str,
    clock,
    digest: str,
    size: int,
    outcome: str,
    channel: str = CHANNEL_FILE,
) -> ChannelEvent:
    finished_at = _moment(clock)
    if finished_at < started_at:
        finished_at = started_at
    return ChannelEvent(
        device=device,
        channel=channel,
        request=request,
        response_sha256=digest,
        response_bytes=size,
        started_at=started_at,
        finished_at=finished_at,
        outcome=outcome,
    )


def collect_file(device, platform, source, profile, now=None) -> tuple:
    _checked_text("device", device)
    _checked_text("platform", platform)
    _checked_text("source", source)
    _checked_text("profile", profile)
    clock = _clock(now)
    started_at = _moment(clock)
    try:
        data = Path(source).read_bytes()
    except OSError as error:
        raise CollectError(
            "cannot read snapshot: %s" % error,
            _finished(device, source, started_at, clock, EMPTY_SHA256, 0, OUTCOME_FAILED),
        )
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CollectError(
            "snapshot is not valid UTF-8 (%s): %s" % (source, error.reason),
            _finished(device, source, started_at, clock, digest, len(data), OUTCOME_FAILED),
        )
    event = _finished(device, source, started_at, clock, digest, len(data), OUTCOME_OK)
    snapshot = Snapshot(
        device=device,
        platform=platform,
        channel=CHANNEL_FILE,
        source=source,
        sha256=digest,
        size_bytes=len(data),
        collected_at=event.finished_at,
        profile=profile,
        text=text,
    )
    return snapshot, event


def _checked_timeout(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CollectError("timeout must be a positive number of seconds, got %r" % (value,))
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise CollectError("timeout must be a positive number of seconds, got %r" % (value,))
    return seconds


def _checked_budget(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CollectError(
            "max_response_bytes must be a positive whole number of bytes, got %r" % (value,)
        )
    return value


def _checked_credential(value):
    if isinstance(value, (str, bytes, bytearray)) or not callable(getattr(value, "use", None)):
        raise CollectError(
            "credential must be a credential store handle with use(), got %s"
            % type(value).__name__
        )
    return value


def _checked_tls_fingerprint(value):
    if value is None:
        return None
    if (
        isinstance(value, str)
        and len(value) == TLS_FINGERPRINT_LENGTH
        and set(value.lower()) <= TLS_FINGERPRINT_CHARS
    ):
        return value.lower()
    raise CollectError(
        "tls_fingerprint must be the sha256 certificate fingerprint of the device,"
        " %d hexadecimal characters, or None, got %r" % (TLS_FINGERPRINT_LENGTH, value)
    )


def _rest_target(host) -> tuple:
    text = _checked_text("host", host).strip()
    if "@" in text:
        raise CollectError("host must not carry credentials, name a credential store record")
    if text.lower().startswith(REST_SCHEME):
        text = text[len(REST_SCHEME):]
    elif "://" in text:
        raise CollectError("host must be reached over https, got %r" % (host,))
    text = text.rstrip("/")
    if not text or any(mark in text for mark in ("/", "?", "#", " ", "\t")):
        raise CollectError("host must be a bare host or host:port, got %r" % (host,))
    name, port = text, REST_PORT
    if ":" in text:
        name, _, digits = text.partition(":")
        if not digits.isdigit() or not 0 < int(digits) < 65536:
            raise CollectError("host port must be a number between 1 and 65535, got %r" % (host,))
        port = int(digits)
    if not name:
        raise CollectError("host must be a bare host or host:port, got %r" % (host,))
    return name, port, "%s%s" % (REST_SCHEME, text)


class _BoundedReceive(io.RawIOBase):
    def __init__(self, peer, deadline):
        self._peer = peer
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(REST_TIMEOUT_REASON)
        self._peer.settimeout(left)
        try:
            return self._peer.recv_into(buffer)
        except TimeoutError:
            raise TimeoutError(REST_TIMEOUT_REASON) from None


class _BoundedSocket:
    def __init__(self, peer, deadline):
        self._peer = peer
        self._deadline = deadline

    def __getattr__(self, name):
        return getattr(self._peer, name)

    def makefile(self, mode="rb", buffering=None, **named):
        if "b" not in mode or "w" in mode or "+" in mode:
            return self._peer.makefile(mode, buffering, **named)
        size = buffering if isinstance(buffering, int) and buffering > 0 else io.DEFAULT_BUFFER_SIZE
        return io.BufferedReader(_BoundedReceive(self._peer, self._deadline), size)


class _RestConnection:
    def __init__(self, connection, timeout):
        self._connection = connection
        self._timeout = timeout

    def fingerprint(self):
        peer = getattr(self._connection, "sock", None)
        certificate = peer.getpeercert(True) if peer is not None else None
        if not certificate:
            return None
        return hashlib.sha256(certificate).hexdigest()

    def request(self, method, target, headers, max_bytes=REST_MAX_BODY_BYTES):
        deadline = time.monotonic() + self._timeout
        self._bounded(deadline, self._connection.request, method, target, headers=headers)
        self._bound_receive(deadline)
        response = self._bounded(deadline, self._connection.getresponse)
        if response.status != 200:
            self._bounded(deadline, response.read, REST_ERROR_HEAD_BYTES)
            return response.status, b""
        chunks, size = [], 0
        while True:
            chunk = self._bounded(deadline, response.read, READ_CHUNK_BYTES)
            if not chunk:
                break
            if size + len(chunk) > max_bytes:
                raise ResponseTooLarge(max_bytes)
            chunks.append(chunk)
            size += len(chunk)
        return response.status, b"".join(chunks)

    def _bound_receive(self, deadline) -> None:
        peer = getattr(self._connection, "sock", None)
        if peer is None or isinstance(peer, _BoundedSocket):
            return
        self._connection.sock = _BoundedSocket(peer, deadline)

    def _bounded(self, deadline, call, *arguments, **named):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(REST_TIMEOUT_REASON)
        peer = getattr(self._connection, "sock", None)
        if peer is not None:
            peer.settimeout(left)
        try:
            answer = call(*arguments, **named)
        except TimeoutError:
            raise TimeoutError(REST_TIMEOUT_REASON) from None
        self._within(deadline)
        return answer

    @staticmethod
    def _within(deadline) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError(REST_TIMEOUT_REASON)

    def close(self):
        self._connection.close()


def _open(host, port, timeout, pinned):
    context = ssl.create_default_context()
    if pinned:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    connection.connect()
    return _RestConnection(connection, timeout)


def _closed(connection) -> None:
    close = getattr(connection, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:
        pass


def _verified(connection, pin, source, failed) -> None:
    if pin is None:
        return
    seen = connection.fingerprint()
    if not isinstance(seen, str) or seen.lower() != pin:
        raise CollectError(
            "certificate of %s does not match the pinned fingerprint (expected %s, got %s)"
            % (source, pin, seen),
            failed(),
        )


def _call(connection, credential, max_bytes):
    return connection.request(
        REST_METHOD,
        REST_TARGET,
        {"Authorization": "Bearer %s" % credential.use(), "Accept": REST_ACCEPT},
        max_bytes,
    )


def collect_fortios_rest(
    device,
    host,
    credential,
    profile,
    tls_fingerprint=None,
    timeout=REST_TIMEOUT_SECONDS,
    max_response_bytes=REST_MAX_BODY_BYTES,
    opener=None,
    now=None,
) -> tuple:
    _checked_text("device", device)
    _checked_text("profile", profile)
    name, port, source = _rest_target(host)
    pin = _checked_tls_fingerprint(tls_fingerprint)
    seconds = _checked_timeout(timeout)
    budget = _checked_budget(max_response_bytes)
    _checked_credential(credential)
    connect = _open if opener is None else opener
    request = "%s %s%s" % (REST_METHOD, source, REST_TARGET)
    clock = _clock(now)
    started_at = _moment(clock)

    def failed(digest=EMPTY_SHA256, size=0):
        return _finished(
            device, request, started_at, clock, digest, size, OUTCOME_FAILED, CHANNEL_REST
        )

    try:
        connection = connect(name, port, seconds, pin is not None)
    except Exception as error:
        raise CollectError("cannot open %s: %s" % (source, error), failed()) from None
    try:
        _verified(connection, pin, source, failed)
    except CollectError:
        _closed(connection)
        raise
    except Exception as error:
        _closed(connection)
        raise CollectError(
            "cannot read the certificate of %s (%s)" % (source, type(error).__name__), failed()
        ) from None
    try:
        answer = _call(connection, credential, budget)
    except ResponseTooLarge:
        raise CollectError(
            "%s %s answered with more than %d bytes, the collector read no further"
            % (REST_METHOD, source, budget),
            failed(),
        ) from None
    except Exception as error:
        raise CollectError(
            "%s %s failed (%s)" % (REST_METHOD, source, type(error).__name__), failed()
        ) from None
    finally:
        _closed(connection)
    try:
        status, body = answer
    except (TypeError, ValueError):
        raise CollectError(
            "the rest channel must answer with status and body, got %s" % type(answer).__name__,
            failed(),
        ) from None
    if not isinstance(body, (bytes, bytearray)):
        raise CollectError(
            "the rest channel must answer with bytes, got %s" % type(body).__name__, failed()
        )
    data = bytes(body)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > budget:
        raise CollectError(
            "%s %s answered with more than %d bytes, the collector read no further"
            % (REST_METHOD, source, budget),
            failed(digest, len(data)),
        )
    if status != 200:
        raise CollectError(
            "%s %s returned http status %s" % (REST_METHOD, source, status),
            failed(digest, len(data)),
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CollectError(
            "snapshot is not valid UTF-8 (%s): %s" % (source, error.reason),
            failed(digest, len(data)),
        )
    event = _finished(
        device, request, started_at, clock, digest, len(data), OUTCOME_OK, CHANNEL_REST
    )
    snapshot = Snapshot(
        device=device,
        platform=PLATFORM_FORTIOS,
        channel=CHANNEL_REST,
        source=source,
        sha256=digest,
        size_bytes=len(data),
        collected_at=event.finished_at,
        profile=profile,
        text=text,
    )
    return snapshot, event


@dataclass(frozen=True)
class _Step:
    command: str
    field: str = ""
    expect: str = ""
    remedy: str = ""
    snapshot: bool = False
    prompt: bool = False


SSH_STEPS = {
    PLATFORM_FORTIOS: (
        _Step(
            command="get system console",
            field="output",
            expect="standard",
            remedy="set console output to standard first",
            prompt=True,
        ),
        _Step(command="show", snapshot=True, prompt=True),
    ),
    PLATFORM_EXOS: (
        _Step(command="show configuration", snapshot=True, prompt=True),
    ),
}
SSH_PLATFORMS = tuple(SSH_STEPS)


def _checked_command(value) -> str:
    command = _checked_text("command", value)
    if any(mark in command for mark in ("\n", "\r", "\x00")):
        raise CollectError("command must be a single line, got %r" % (value,))
    return command


def _checked_platform(value) -> tuple:
    steps = SSH_STEPS.get(value) if isinstance(value, str) else None
    if steps is None:
        raise CollectError(
            "platform must be one of %s, got %r" % (", ".join(SSH_PLATFORMS), value)
        )
    return steps


def _field(text, name):
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == name:
            return value.strip()
    return None


def _ssh_source(login, address, port) -> str:
    if port == SSH_PORT:
        return "%s@%s" % (login, address)
    return "%s@%s:%s" % (login, address, port)


def _ssh_step(
    device, request, command, address, port, login, credential, host_key_line, profile, seconds,
    clock, required, run,
) -> tuple:
    started_at = _moment(clock)

    def failed(digest=EMPTY_SHA256, size=0):
        return _finished(
            device, request, started_at, clock, digest, size, OUTCOME_FAILED, CHANNEL_SSH
        )

    try:
        result = ssh.run_command(
            address,
            port,
            login,
            credential,
            host_key_line,
            command,
            legacy_ssh=profile,
            timeout_seconds=seconds,
            run=run,
        )
    except ssh.SshError as error:
        raise CollectError("%s: %s" % (request, error), failed()) from None
    if result.rc != 0:
        raise CollectError(
            "%s ended with exit status %s; the auditor reads a snapshot only from a command"
            " that reported success" % (request, result.rc),
            failed(),
        )
    data = bytes(result.stdout)
    digest = hashlib.sha256(data).hexdigest()
    if required and not data:
        raise CollectError("%s returned an empty answer" % request, failed(digest, len(data)))
    return data, _finished(
        device, request, started_at, clock, digest, len(data), OUTCOME_OK, CHANNEL_SSH
    )


def collect_ssh(
    device,
    platform,
    address,
    port,
    credential,
    host_key_fingerprint,
    legacy_ssh=None,
    timeout=SSH_TIMEOUT_SECONDS,
    run=None,
    keyscan=None,
    now=None,
) -> tuple:
    _checked_text("device", device)
    steps = _checked_platform(platform)
    seconds = _checked_timeout(timeout)
    _checked_credential(credential)
    try:
        profile = legacy.checked(legacy_ssh)
    except legacy.LegacySshError as error:
        raise CollectError(str(error)) from None
    login = getattr(credential, "login", None)
    source = _ssh_source(login, address, port)
    clock = _clock(now)
    started_at = _moment(clock)

    def failed():
        return _finished(
            device,
            "%s %s" % (source, steps[0].command),
            started_at,
            clock,
            EMPTY_SHA256,
            0,
            OUTCOME_FAILED,
            CHANNEL_SSH,
        )

    try:
        host_key_line = hostkey.scan(address, port, host_key_fingerprint, seconds, run=keyscan)
    except hostkey.HostKeyError as error:
        raise CollectError(str(error), failed()) from None
    events, payload, taken, marked = [], b"", None, False
    for step in steps:
        request = "%s %s" % (source, _checked_command(step.command))
        data, event = _ssh_step(
            device,
            request,
            step.command,
            address,
            port,
            login,
            credential,
            host_key_line,
            profile,
            seconds,
            clock,
            step.snapshot,
            run,
        )
        events.append(event)
        if step.field:
            answer = data.decode("utf-8", "replace")
            if step.prompt:
                answer = prompt.cleaned(answer, platform)
            seen = _field(answer, step.field)
            if seen is None:
                raise CollectError(
                    "cannot read %s of %s from %r" % (step.field, source, step.command),
                    replace(event, outcome=OUTCOME_FAILED),
                )
            if seen != step.expect:
                raise CollectError(
                    "%s reports %s %r instead of %r; the auditor does not change device"
                    " configuration - %s" % (source, step.field, seen, step.expect, step.remedy),
                    replace(event, outcome=OUTCOME_FAILED),
                )
        if step.snapshot:
            payload, taken, marked = data, event, step.prompt
    if taken is None:
        raise CollectError("platform %r has no step that takes a snapshot" % (platform,), failed())
    try:
        text = payload.decode("utf-8")
        if marked:
            text = prompt.cleaned(text, platform)
    except UnicodeDecodeError as error:
        raise CollectError(
            "snapshot is not valid UTF-8 (%s): %s" % (source, error.reason),
            replace(taken, outcome=OUTCOME_FAILED),
        )
    body = text.encode("utf-8")
    snapshot = Snapshot(
        device=device,
        platform=platform,
        channel=CHANNEL_SSH,
        source=source,
        sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        collected_at=taken.finished_at,
        profile=login,
        text=text,
    )
    return snapshot, tuple(events)


SECTION_HEADERS = {
    PLATFORM_FORTIOS: ("config ", ""),
    PLATFORM_EXOS: ("# Module ", " configuration."),
}
SECTION_PLATFORMS = tuple(SECTION_HEADERS)


def _normalized(value: str) -> str:
    return " ".join(value.split())


def _checked_header(value) -> tuple:
    header = SECTION_HEADERS.get(value) if isinstance(value, str) else None
    if header is None:
        raise CollectError(
            "the completeness check knows a section header for %s, got platform %r"
            % (", ".join(SECTION_PLATFORMS), value)
        )
    return header


def _section_name(line, prefix, suffix) -> str:
    if not line.startswith(prefix):
        return ""
    name = line[len(prefix):]
    if suffix and name.endswith(suffix):
        name = name[: -len(suffix)]
    return name.strip()


def missing_sections(text, required_sections, platform) -> tuple:
    if not isinstance(text, str):
        raise CollectError("text must be a string, got %r" % (text,))
    prefix, suffix = _checked_header(platform)
    present = set()
    for line in text.splitlines():
        normalized = _normalized(line)
        if not normalized.endswith(suffix):
            continue
        name = _section_name(normalized, prefix, suffix)
        if name:
            present.add(name)
    missing, seen = [], set()
    for section in required_sections:
        key = _normalized(_checked_text("required section", section))
        written = _section_name(key, prefix, suffix)
        if written:
            raise CollectError(
                "required section %r is written the way platform %s opens a section in the dump"
                " (%s<section>%s); the check needs the section alone, so write %r instead"
                % (section, platform, prefix, suffix, written)
            )
        if key in seen or key in present:
            continue
        seen.add(key)
        missing.append(section)
    return tuple(missing)


def completeness_finding(device, missing):
    _checked_text("device", device)
    names = tuple(missing)
    if not names:
        return None
    return {
        "object_key": "%s/%s" % (COMPLETENESS_SECTION, device),
        "section": COMPLETENESS_SECTION,
        "line": 0,
        "evidence": {"missing_count": len(names), "missing_sections": ", ".join(names)},
    }
