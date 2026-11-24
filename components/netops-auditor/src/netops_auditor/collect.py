from __future__ import annotations

import hashlib
import http.client
import io
import json
import re
import ssl
import time
import types
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from functools import partial

from netops_core import hostkey, prompt, ssh
from netops_core import legacy_ssh as legacy
from netops_core.session import FORTINET_LOGIN_SECONDS, SessionError, fortinet_session

from . import l1_cli, l1_exos, l1_fortios, l1_junos, platforms
from .platforms import (
    HIDDEN, INCOMPLETE, NOT_SUPPORTED, UNPROVEN, VISIBLE,
    SectionVisibility, SnapshotMetadata, SSHStep,
)
from .inputs import InputError, read_regular

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
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
REST_ERROR_HEAD_BYTES = 4096
REST_TIMEOUT_REASON = "the device did not finish the answer within the timeout"
TLS_FINGERPRINT_LENGTH = 64
TLS_FINGERPRINT_CHARS = frozenset("0123456789abcdef")
SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 120.0


class CollectError(Exception):
    def __init__(self, message: str, event=None, events=None):
        super().__init__(message)
        self.event = event
        if events is None:
            events = () if event is None else (event,)
        self.events = tuple(events)


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
    metadata: SnapshotMetadata | None = field(default=None, repr=False)


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
        data = read_regular(source, MAX_SNAPSHOT_BYTES)
    except OSError as error:
        raise CollectError(
            "cannot read snapshot: %s" % error,
            _finished(device, source, started_at, clock, EMPTY_SHA256, 0, OUTCOME_FAILED),
        )
    except InputError as error:
        raise CollectError(
            "cannot read snapshot %s: %s" % (source, error),
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
        if not (digits.isascii() and digits.isdigit()) or not 0 < int(digits) < 65536:
            raise CollectError("host port must be a number between 1 and 65535, got %r" % (host,))
        port = int(digits)
    if not name:
        raise CollectError("host must be a bare host or host:port, got %r" % (host,))
    return name, port, "%s%s" % (REST_SCHEME, text)


class _BoundedReceive(io.RawIOBase):
    def __init__(self, peer, deadline):
        self._peer = peer
        self._deadline = deadline
        self._reader = peer.makefile("rb", buffering=0)

    def close(self) -> None:
        try:
            self._reader.close()
        finally:
            super().close()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(REST_TIMEOUT_REASON)
        self._peer.settimeout(left)
        try:
            return self._reader.readinto(buffer)
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
        try:
            if isinstance(response, http.client.HTTPResponse) and response.chunked:
                response._read_next_chunk_size = types.MethodType(_read_chunk_size, response)
            if response.status != 200:
                self._bounded(deadline, response.read, REST_ERROR_HEAD_BYTES)
                return response.status, b""
            _checked_framing(response)
            chunks, size = [], 0
            while True:
                chunk = self._bounded(deadline, response.read, READ_CHUNK_BYTES)
                if not chunk:
                    remaining = getattr(response, "length", None)
                    if remaining:
                        raise http.client.IncompleteRead(b"", remaining)
                    break
                if size + len(chunk) > max_bytes:
                    raise ResponseTooLarge(max_bytes)
                chunks.append(chunk)
                size += len(chunk)
            return response.status, b"".join(chunks)
        finally:
            _closed(response)

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


def _read_chunk_size(response):
    line = response.fp.readline(http.client._MAXLINE + 1)
    if len(line) > http.client._MAXLINE:
        raise http.client.LineTooLong("chunk size")
    size = line.removesuffix(b"\r\n").split(b";", 1)[0]
    if not line.endswith(b"\r\n") or not re.fullmatch(b"[0-9A-Fa-f]+", size):
        response._close_conn()
        raise ValueError("invalid chunk size")
    return int(size, 16)


def _checked_framing(response) -> None:
    lengths = response.msg.get_all("Content-Length") or []
    if lengths and response.msg.get_all("Transfer-Encoding"):
        raise http.client.HTTPException("Content-Length together with Transfer-Encoding")
    values = set()
    for line in lengths:
        for value in line.split(","):
            value = value.strip()
            if not (value.isascii() and value.isdigit()):
                raise http.client.HTTPException("Content-Length is not a whole number")
            values.add(int(value))
    if len(values) > 1:
        raise http.client.HTTPException("conflicting Content-Length values")
    if values:
        # http.client leaves the length unset for merged values such as "34, 34" and would
        # then wait for the peer to close; read exactly the verified length instead.
        response.length = values.pop()


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
    implementation = platforms.optional_collector(PLATFORM_FORTIOS)
    if implementation is not None:
        snapshot = replace(snapshot, metadata=implementation.snapshot_metadata(snapshot, {}, {}))
    return snapshot, event


RUNNING = "show running-config"
SNMP_USERS = SSHStep("show snmp user", section="snmp users")
JUNOS_CONFIG = "show configuration | display set | no-more"
JUNOS_INHERITANCE = "show configuration | display inheritance | display set | no-more"

SSH_STEPS = {
    PLATFORM_FORTIOS: (
        SSHStep(
            command="get system console",
            field="output",
            expect="standard",
            known=("more",),
            remedy="set console output to standard first",
            prompt=True,
        ),
        SSHStep(command="show", snapshot=True, prompt=True),
    ),
    PLATFORM_EXOS: (
        SSHStep(command="show configuration", snapshot=True, prompt=True),
        SSHStep("show version", section="version"),
        SSHStep("show switch", section="model"),
    ),
    "cisco-ios": (
        SSHStep(RUNNING, snapshot=True), SSHStep("show privilege", section="privilege"),
        SSHStep("show parser view", section="cli view"), SNMP_USERS,
        SSHStep("show ip ssh", section="ip ssh"),
    ),
    "cisco-nxos": (
        SSHStep(RUNNING, snapshot=True), SNMP_USERS, SSHStep("show nxapi", section="nxapi listener"),
        SSHStep("show user-account", section="session role"),
    ),
    "arista-eos": (SSHStep(RUNNING, snapshot=True), SNMP_USERS,
                   SSHStep("show users detail | json", section="session role")),
    "juniper-junos": (
        SSHStep(JUNOS_CONFIG, snapshot=True), SSHStep(JUNOS_INHERITANCE, section="inheritance"),
        SSHStep("show cli authorization", section="session role"),
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


def _described(value, known) -> str:
    if value in known:
        return repr(value)
    raw = value.encode("utf-8", "replace")
    return "an unrecognized value (%d bytes, sha256 %s)" % (len(raw), hashlib.sha256(raw).hexdigest()[:16])


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


def _ssh_step(device, request, command, clock, required, execute) -> tuple:
    started_at = _moment(clock)

    def failed(digest=EMPTY_SHA256, size=0):
        return _finished(
            device, request, started_at, clock, digest, size, OUTCOME_FAILED, CHANNEL_SSH
        )

    try:
        result = execute(command)
    except (ssh.SshError, SessionError) as error:
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
    *,
    host_key=None,
    session=None,
    inventory_platform=None,
    max_response_bytes=REST_MAX_BODY_BYTES,
) -> tuple:
    """Collect over SSH, optionally borrowing the caller's pinned FortiOS session.

    The caller retains ownership of an open session and supplies the matching
    target and credential metadata. Otherwise Core verifies the enrolled key
    before opening a FortiOS session for the two reads.
    """
    _checked_text("device", device)
    steps = _checked_platform(platform)
    if platform == PLATFORM_FORTIOS:
        implementation = platforms.optional_collector(platform)
        if implementation is not None:
            steps = implementation.SSH_STEPS
    modern = platform in EXEC_PLATFORMS
    budget = _checked_budget(max_response_bytes)
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

    deadline = time.monotonic() + seconds
    with ExitStack() as stack:
        try:
            if platform == PLATFORM_FORTIOS:
                if session is None:
                    target = types.SimpleNamespace(
                        platform=platform, address=address, port=port, legacy_ssh=profile,
                        host_key_fingerprint=host_key_fingerprint, host_key=host_key,
                    )
                    session = stack.enter_context(fortinet_session(
                        target, credential, connect_timeout_seconds=min(seconds, FORTINET_LOGIN_SECONDS),
                        timeout_seconds=seconds, idle_timeout_seconds=min(seconds, 15.0),
                        capture_max_bytes=budget,
                    ))
                execute = partial(session.run, timeout_seconds=seconds)
            else:
                host_key_line = hostkey.scan(
                    address, port, host_key_fingerprint, seconds, run=keyscan, legacy=profile
                )
                if modern:
                    def execute(command, remaining):
                        available = deadline - time.monotonic()
                        if available <= 0:
                            raise ssh.SshError("SSH collection timeout")
                        return ssh.run_command(
                            address, port, login, credential, host_key_line, command,
                            legacy_ssh=profile, timeout_seconds=available,
                            idle_timeout_seconds=min(available, 15.0), capture_max_bytes=remaining,
                            suppress_login_banner=True, run=run,
                        )
                else:
                    execute = partial(
                        ssh.run_command, address, port, login, credential, host_key_line,
                        legacy_ssh=profile, timeout_seconds=seconds, run=run,
                    )
        except hostkey.HostKeyError as error:
            raise CollectError(str(error), failed()) from None
        except SessionError as error:
            raise CollectError("%s %s: %s" % (source, steps[0].command, error), failed()) from None
        if modern:
            return _collect_exec(device, platform, inventory_platform or platform, steps,
                                 source, login, clock, execute, budget)
        builder = implementation.snapshot_metadata if platform == PLATFORM_FORTIOS and implementation else None
        return _collect_ssh_steps(device, platform, steps, source, login, clock, failed, execute, builder, budget)


def _collect_ssh_steps(device, platform, steps, source, login, clock, failed, execute, builder, budget) -> tuple:
    events, payload, taken, marked = [], b"", None, False
    answers, visibility = {}, {}
    for step in steps:
        if platform == PLATFORM_EXOS and step.section == "model":
            version = answers.get("version", "")
            if len(set(EXOS_VERSION.findall(version))) != 1 or EXOS_MODEL.search(version):
                continue
        request = "%s %s" % (source, _checked_command(step.command))
        if step.section and not step.snapshot:
            started = _moment(clock)
            data, answer, reason = _read_exec(lambda command, _: execute(command), step.command, budget)
            budget -= len(data)
            events.append(_finished(device, request, started, clock, hashlib.sha256(data).hexdigest(), len(data),
                                    OUTCOME_FAILED if reason else OUTCOME_OK, CHANNEL_SSH))
            if not reason:
                answers[step.section] = answer
            visibility[step.section] = _auxiliary_visibility(reason)
            continue
        try:
            data, event = _ssh_step(device, request, step.command, clock, step.snapshot, execute)
        except CollectError as error:
            raise CollectError(str(error), error.event, tuple(events) + (error.event,)) from None
        if step.field:
            answer = data.decode("utf-8", "replace")
            if step.prompt:
                answer = prompt.cleaned(answer, platform)
            seen = _field(answer, step.field)
            refused = replace(event, outcome=OUTCOME_FAILED)
            if seen is None:
                raise CollectError(
                    "cannot read %s of %s from %r" % (step.field, source, step.command),
                    refused,
                    tuple(events) + (refused,),
                )
            if seen != step.expect:
                raise CollectError(
                    "%s reports %s %s instead of %r; the auditor does not change device"
                    " configuration - %s"
                    % (source, step.field, _described(seen, step.known), step.expect, step.remedy),
                    refused,
                    tuple(events) + (refused,),
                )
        events.append(event)
        if step.snapshot:
            payload, taken, marked = data, event, step.prompt
            budget -= len(data)
    if taken is None:
        marker = failed()
        raise CollectError(
            "platform %r has no step that takes a snapshot" % (platform,), marker, tuple(events) + (marker,)
        )
    try:
        text = payload.decode("utf-8")
        if marked:
            text = prompt.cleaned(text, platform)
    except UnicodeDecodeError as error:
        refused = replace(taken, outcome=OUTCOME_FAILED)
        raise CollectError(
            "snapshot is not valid UTF-8 (%s): %s" % (source, error.reason),
            refused,
            tuple(refused if item is taken else item for item in events),
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
    if builder is not None:
        snapshot = replace(snapshot, metadata=builder(snapshot, answers, visibility))
    elif platform == PLATFORM_EXOS:
        snapshot = replace(snapshot, metadata=_exos_metadata(text, answers))
    return snapshot, tuple(events)


def _exos_metadata(text, answers):
    """A terminal module header proves that the preceding modules were printed to their ends."""
    if PAGER.search(text):
        return SnapshotMetadata(PLATFORM_EXOS, integrity_reason="pager")
    incomplete = SnapshotMetadata(PLATFORM_EXOS, integrity_reason="truncated")
    if not text.endswith("\n") or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", text):
        return incomplete
    try:
        tree = l1_exos.parse(text)
    except l1_exos.ParseError:
        return incomplete
    if (tree.unterminated_upm or tree.modules[:1] != ("devmgr",)
            or any(command.module == l1_exos.NO_MODULE for command in tree.commands)
            or any(EXOS_ERROR.match(command.text) or DENIED.match(command.text) for command in tree.active)):
        return incomplete
    version = answers.get("version", "")
    unknown_end = SnapshotMetadata(PLATFORM_EXOS, integrity_reason="unknown-end-format")
    if len(set(EXOS_VERSION.findall(version))) != 1:
        return unknown_end
    models = {model.upper() for model in EXOS_MODEL.findall(version)}
    if not models:
        models = {model.upper() for model in EXOS_MODEL.findall(answers.get("model", ""))}
    if len(models) != 1:
        return unknown_end
    model = models.pop()
    if model.startswith("X435-"):
        last_module = "upm"
    elif model == "EXOS-VM" or model.startswith("X440G2-"):
        last_module = "vpex"
    else:
        return unknown_end
    if tree.last_module != last_module:
        return incomplete
    finished = (module for module in tree.modules if module != last_module)
    sections = dict.fromkeys(finished, SectionVisibility(VISIBLE, "verified-profile"))
    return SnapshotMetadata(PLATFORM_EXOS, sections, complete=True, tree=tree)


EXEC_PLATFORMS = frozenset({"cisco-ios", "cisco-nxos", "arista-eos", "juniper-junos"})
ANSI = re.compile(r"\[[0-9;]*[A-Za-z]")
PAGER = re.compile(r"(?:^|[\r\n]) *--[ \t]*More[ \t]*--(?=[ \t]*(?:[\r\n\x08]|$))", re.I | re.M)
UNAVAILABLE = re.compile(r"^(?:% (?:Invalid input|Incomplete command|Ambiguous command|Invalid command)"
                         r"|(?:syntax error|unknown command|invalid command)\b)", re.I)
DENIED = re.compile(r"^(?:(?:% )?(?:permission denied|access denied|authorization failed"
                    r"|command authorization failed|not authorized)|Cmd exec error\.|"
                    r"Line has invalid autocommand|error: (?:permission|access) denied)", re.I)
SSH_AUTH_REJECTED = re.compile(r"(?:\S+@\S+: )?Permission denied \([\w,-]+\)\.?", re.I)
JUNOS_PROMPT = re.compile(r"[\w.-]+@[\w.:-]+>")
IOS_HEADER = re.compile(r"Building configuration\.\.\.\s*\n\s*Current configuration\s*:\s*[1-9][0-9]* bytes[ \t]*\n")
EOS_HEADER = re.compile(r"! Command: show running-config(?: at line 1)?")


def _frame(platform, text, tree):
    data = text.lstrip("\n \t")
    if not text.endswith("\n"):
        return False
    if platform == "juniper-junos":
        return tree.malformed is None and bool(tree.statements or tree.hidden)
    if tree.unterminated is not None:
        return False
    if platform == "cisco-ios":
        header = IOS_HEADER.match(data)
        return (header is not None and data[header.end():].startswith("!\n")
                and data.rstrip().endswith("\nend") and _has(tree, "version") and _has(tree, "hostname"))
    if platform == "cisco-nxos":
        return (bool(data) and data.splitlines()[0].rstrip() == "!Command: show running-config"
                and all(_has(tree, word) for word in ("version", "hostname", "interface")))
    data = data.removeprefix("> show running-config\n")
    return bool(data and EOS_HEADER.fullmatch(data.splitlines()[0].rstrip()) and data.rstrip().endswith("\nend"))


def _has(tree, *words):
    return any(item.mode == "set" for item in tree.matching(*words))


def _run_auxiliary(step, platform, tree, answers):
    if step.section in ("privilege", "session role"):
        return True
    if step.section == "ip ssh":
        return not tree.matching("ip", "ssh", "version")
    if step.section == "cli view":
        return "privilege" in answers
    if step.section == "nxapi listener":
        return _has(tree, "feature", "nxapi") and not any(
            item.tokens[1:3] == ("http", "port") or item.tokens == ("nxapi", "http") and item.mode == "no"
            for item in tree.matching("nxapi")
        )
    if platform == "arista-eos":
        return any(item.mode == "set" and item.tokens[1:2] in (("user",), ("group",))
                   for item in tree.matching("snmp-server"))
    if step.section == "inheritance":
        return bool(tree.inheritance)
    return True


def _read_exec(execute, command, remaining, *, configuration=False):
    try:
        if remaining <= 0:
            return b"", "", "output-limit"
        result = execute(command, remaining)
    except ssh.OutputLimitError:
        return b"", "", "output-limit"
    except SessionError as error:
        reason = {"output_limit": "output-limit", "page_limit": "pager", "idle_timeout": "timeout",
                  "command_timeout": "timeout"}.get(error.code, "transport-error")
        return b"", "", reason
    except ssh.SshError as error:
        if error.rc == ssh.CLIENT_FAILURE_CODE and SSH_AUTH_REJECTED.fullmatch(error.final):
            return b"", "", "authentication-failed"
        return b"", "", "timeout" if re.search(r"timeout|within|idle", str(error), re.I) else "transport-error"
    data = result.stdout
    if len(data) > remaining:
        return data, "", "output-limit"
    try:
        answer = data.decode("utf-8").replace("\r\r\n", "\n").replace("\r\n", "\n")
    except UnicodeDecodeError:
        return data, "", "invalid-utf8"
    stdout = [line.strip() for line in answer.split("\n") if line.strip()]
    # Device diagnostics may echo arbitrary secrets. Only classify their shape.
    error_lines = result.stderr.decode("utf-8", "replace").splitlines()
    first = next((line for line in stdout if line != "> " + command), "")
    if not configuration or not first.startswith(("Building configuration", "!", "set ", "## ", "inactive:")):
        error_lines.extend(stdout)
    if PAGER.search(ANSI.sub("", answer)) or "\x08" in answer:
        return data, "", "pager"
    if any(DENIED.match(line.strip()) for line in error_lines):
        return data, "", "permission-denied"
    if any(UNAVAILABLE.match(line.strip()) for line in error_lines):
        return data, "", "command-unavailable"
    if result.rc:
        return data, "", "transport-error"
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r", answer):
        return data, "", "truncated"
    if command.startswith("show configuration |") and stdout and JUNOS_PROMPT.fullmatch(stdout[-1]):
        answer = answer.rstrip().rpartition("\n")[0] + "\n"
    return data, answer, ""


def _auxiliary_visibility(reason):
    if not reason:
        return SectionVisibility(VISIBLE, "auxiliary-output")
    state = {"permission-denied": HIDDEN, "command-unavailable": NOT_SUPPORTED}.get(reason, INCOMPLETE)
    return SectionVisibility(state, reason)


# A complete snapshot read in a session whose full role the device reports, with a readable
# software version and the documented end of the output, proves the defaults the device does not print.
NXOS_FULL_ROLES = frozenset({"network-admin", "vdc-admin"})
NXOS_VERSION = re.compile(r"[0-9]+\.[0-9]+\([0-9A-Za-z.]+\)\S*")
EOS_DEVICE = re.compile(r"! device: \S+ \(.*\bEOS-[0-9]+\.[0-9]+\.[0-9]+.*\)")
JUNOS_VERSION = re.compile(r"[0-9]+\.[0-9]+[A-Z][0-9][0-9A-Za-z.-]*")
JUNOS_AUTHORIZATION = re.compile(r"Current user: '([^']*)' class '([^']*)'")
# The last hierarchy of a Junos switch configuration; its own last lines are not proven.
JUNOS_LAST_SECTION = "vlans"
# NX-OS ends show running-config with at least two empty lines after the sections behind line vty.
NXOS_END = re.compile(r"\n(?:[ \t]*\n){2,}\Z")
EXOS_ERROR = re.compile(r"^(?:Error:|%|\^)")
EXOS_VERSION = re.compile(r"^Image\s*:\s*ExtremeXOS version ([0-9]+(?:\.[0-9]+){3})(?![0-9.])", re.M)
EXOS_MODEL = re.compile(r"^(?:System Type|Model|Switch)[ \t]*:[ \t]*(EXOS-VM|X[0-9][A-Z0-9]*-[A-Z0-9-]+)(?=[ \t]|$)",
                        re.M | re.I)


def _session_full(platform, answers, login):
    """Whether the device reports a full role for the session that read the snapshot."""
    answer = answers.get("session role", "")
    if platform == "arista-eos":
        try:
            sessions = json.loads(answer)
        except (ValueError, RecursionError):
            return False
        vtys = sessions.get("vtys") if isinstance(sessions, dict) else None
        if not isinstance(vtys, dict) or not all(isinstance(row, dict) for row in vtys.values()):
            return False
        matching = [row for row in vtys.values() if row.get("username") == login]
        if len(matching) != 1:
            return False
        row = matching[0]
        return (row.get("service") == "sshd" and row.get("state") == "established"
                and row.get("role") == "network-admin")
    if platform == "juniper-junos":
        found = JUNOS_AUTHORIZATION.match(answer.lstrip())
        return found is not None and found.group(1).strip() == login and found.group(2) == "super-user"
    user, roles = None, set()
    for line in answer.splitlines():
        line = line.strip()
        if line.startswith("user:"):
            user = line[len("user:"):].strip()
        elif line.startswith("roles:") and user == login:
            roles.update(line[len("roles:"):].split())
    return bool(roles & NXOS_FULL_ROLES)


def _documented_end(platform, tree, text):
    if platform == "cisco-nxos":
        return NXOS_END.search(text) is not None and _has(tree, "line", "vty")
    if platform == "juniper-junos":
        lines = [line.strip() for line in text.split("\n")]
        last = next((line for line in reversed(lines)
                     if line and not line.startswith("##") and not l1_junos.SCOPE.fullmatch(line)), "")
        return last.split()[:2] in (["set", JUNOS_LAST_SECTION], ["deactivate", JUNOS_LAST_SECTION])
    return True  # EOS: _frame already requires the closing "end".


def _verified_exec(platform, tree, text, login, answers):
    if not isinstance(login, str) or not login:
        return False
    if platform == "juniper-junos":
        version = [item.tokens[1:] for item in tree.matching("version")]
        known = (not tree.hidden and not tree.denied and tree.malformed is None
                 and len(version) == 1 and len(version[0]) == 1 and JUNOS_VERSION.fullmatch(version[0][0]))
    elif platform == "cisco-nxos":
        version = [item for item in tree.matching("version") if item.mode == "set" and not item.parents]
        known = len(version) == 1 and len(version[0].tokens) > 1 and NXOS_VERSION.fullmatch(version[0].tokens[1])
    elif platform == "arista-eos":
        head = text.lstrip("\n \t").removeprefix("> show running-config\n").splitlines()[1:2]
        known = bool(head) and EOS_DEVICE.fullmatch(head[0].rstrip()) is not None
    else:
        return False
    return bool(known) and _documented_end(platform, tree, text) and _session_full(platform, answers, login)


def _section_visibility(platform, tree, auxiliary, answers, text="", login=None):
    present = SectionVisibility(VISIBLE, "content")
    verified = SectionVisibility(VISIBLE, "verified-profile")
    sections = dict.fromkeys(tree.sections, present)
    if platform == "cisco-ios":
        privilege = answers.get("privilege", "")
        view = answers.get("cli view", "")
        if (re.search(r"(?m)^Current privilege level is 15\s*$", privilege)
                and re.search(r"(?mi)^Current view is [\"']?root[\"']?\s*$", view)):
            sections.update(dict.fromkeys(l1_cli.SECTIONS - sections.keys(), verified))
    elif _verified_exec(platform, tree, text, login, answers):
        families = l1_junos.SECTIONS if platform == "juniper-junos" else l1_cli.SECTIONS
        sections = dict.fromkeys(families | tree.sections, verified)
        if platform == "juniper-junos":
            sections[JUNOS_LAST_SECTION] = present
    if platform == "juniper-junos":
        sections.update(dict.fromkeys(tree.inheritance, SectionVisibility(UNPROVEN, "inheritance-unresolved")))
        sections.update(dict.fromkeys(tree.hidden, SectionVisibility(HIDDEN, "access-denied")))
    sections.update(auxiliary)
    return sections


def _collect_exec(device, platform, inventory_platform, steps, source, login, clock, execute, budget):
    parser = platforms.PLATFORMS[platform].parser
    events, auxiliary, answers = [], {}, {}
    tree = None
    for step in steps:
        if not step.snapshot and not _run_auxiliary(step, platform, tree, answers):
            continue
        started = _moment(clock)
        data, answer, reason = _read_exec(execute, step.command, budget,
                                          configuration=step.snapshot or step.section == "inheritance")
        budget -= len(data)
        if not reason and step.snapshot:
            parsed = parser.parse(answer)
            if not _frame(platform, answer, parsed):
                reason = "truncated"
            else:
                tree, text = parsed, answer
        if not reason and step.section == "inheritance":
            inherited = parser.parse(answer)
            if not _frame(platform, answer, inherited):
                reason = "truncated"
            else:
                tree = l1_junos.with_inheritance(tree, inherited)
        event = _finished(device, "%s %s" % (source, step.command), started, clock,
                          hashlib.sha256(data).hexdigest(), len(data),
                          OUTCOME_FAILED if reason else OUTCOME_OK, CHANNEL_SSH)
        events.append(event)
        if step.snapshot:
            if reason in ("pager", "truncated"):
                metadata = SnapshotMetadata(inventory_platform, integrity_reason=reason)
                return Snapshot(device, platform, CHANNEL_SSH, source, event.response_sha256,
                                len(data), event.finished_at, login, "", metadata), tuple(events)
            if reason:
                raise CollectError("%s: %s" % (step.command, reason), event, events)
            collected_at = event.finished_at
        else:
            if not reason:
                answers[step.section] = answer
            auxiliary[step.section] = _auxiliary_visibility(reason)
    sections = _section_visibility(platform, tree, auxiliary, answers, text, login)
    metadata = SnapshotMetadata(inventory_platform, sections, answers, complete=True, tree=tree)
    body = text.encode("utf-8")
    return Snapshot(device, platform, CHANNEL_SSH, source, hashlib.sha256(body).hexdigest(),
                    len(body), collected_at, login, text, metadata), tuple(events)


SECTION_HEADERS = {
    "cisco-ios": l1_cli.parse,
    "cisco-nxos": l1_cli.parse,
    "arista-eos": l1_cli.parse,
    "juniper-junos": l1_junos.parse,
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


def _fortios_statements(text) -> list:
    statements = []
    try:
        for _start, statement in l1_fortios.logical_lines(text):
            statements.append(statement)
    except l1_fortios.TruncatedError:
        pass
    return statements


def _statements(text, platform) -> list:
    if platform == PLATFORM_FORTIOS:
        return _fortios_statements(text)
    try:
        configuration = l1_exos.parse(text)
    except l1_exos.ParseError as error:
        raise CollectError("the snapshot cannot be split into statements: %s" % error) from None
    inside = {number for first, last in configuration.upm_bodies for number in range(first, last + 1)}
    return [line for number, line in enumerate(l1_exos.split_lines(text), 1) if number not in inside]


def unterminated_line(text, platform):
    if platform in EXEC_PLATFORMS:
        tree = SECTION_HEADERS[platform](text)
        return tree.malformed if platform == "juniper-junos" else tree.unterminated
    if platform != PLATFORM_FORTIOS:
        return None
    try:
        l1_fortios.parse(text)
    except l1_fortios.TruncatedError as error:
        return error.line
    except l1_fortios.ParseError:
        head, newline, _ = text.rpartition("\n")
        if not newline or text.endswith("\n"):
            return None
        return unterminated_line(head + newline, platform)
    return None


def missing_sections(text, required_sections, platform) -> tuple:
    if not isinstance(text, str):
        raise CollectError("text must be a string, got %r" % (text,))
    header = _checked_header(platform)
    if callable(header):
        return tuple(dict.fromkeys(name for name in required_sections if name not in header(text).sections))
    prefix, suffix = header
    present = set()
    for line in _statements(text, platform):
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


def completeness_finding(device, missing, unterminated=None):
    _checked_text("device", device)
    names = tuple(missing)
    if not names and unterminated is None:
        return None
    evidence = {"missing_count": len(names), "missing_sections": ", ".join(names)}
    if unterminated is not None:
        evidence["unterminated_line"] = unterminated
    return {
        "object_key": "%s/%s" % (COMPLETENESS_SECTION, device),
        "section": COMPLETENESS_SECTION,
        "line": 0,
        "evidence": evidence,
    }
