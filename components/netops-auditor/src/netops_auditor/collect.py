from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

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
TLS_FINGERPRINT_LENGTH = 64
TLS_FINGERPRINT_CHARS = frozenset("0123456789abcdef")
SSH_BINARY = "ssh"
KEYSCAN_BINARY = "ssh-keyscan"
SSH_CONFIG_FILE = "/dev/null"
SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 120.0
SSH_OPTIONS = (
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "IdentitiesOnly=yes",
    "ClearAllForwardings=yes",
    "ProxyCommand=none",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
)
LEGACY_SSH_OPTIONS = {
    "rsa-sha1": ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa"),
}
SSH_ERROR_DETAIL_CHARS = 200
NEGOTIATION_MARKER = "no matching"
LEGACY_REMEDY = (
    "; %s offers only algorithms this client refuses - if that is intended for this one device,"
    " name the exception in its inventory entry as legacy_ssh, one of the profiles %s;"
    " there is no global switch and no other entry is weakened by it"
)
HOST_KEY_PREFIX = "SHA256:"
HOST_KEY_DIGEST_LENGTH = 43
HOST_KEY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


class CollectError(Exception):
    def __init__(self, message: str, event=None):
        super().__init__(message)
        self.event = event


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

    def request(self, method, target, headers):
        deadline = time.monotonic() + self._timeout
        self._connection.request(method, target, headers=headers)
        response = self._connection.getresponse()
        chunks = []
        while True:
            chunk = response.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            if time.monotonic() > deadline:
                raise TimeoutError("the device did not finish the answer within the timeout")
        return response.status, b"".join(chunks)

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


def _call(connection, credential):
    return connection.request(
        REST_METHOD,
        REST_TARGET,
        {"Authorization": "Bearer %s" % credential.use(), "Accept": REST_ACCEPT},
    )


def collect_fortios_rest(
    device,
    host,
    credential,
    profile,
    tls_fingerprint=None,
    timeout=REST_TIMEOUT_SECONDS,
    opener=None,
    now=None,
) -> tuple:
    _checked_text("device", device)
    _checked_text("profile", profile)
    name, port, source = _rest_target(host)
    pin = _checked_tls_fingerprint(tls_fingerprint)
    seconds = _checked_timeout(timeout)
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
        answer = _call(connection, credential)
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


def _checked_host_key(value) -> str:
    if isinstance(value, str) and value.startswith(HOST_KEY_PREFIX):
        digest = value[len(HOST_KEY_PREFIX):]
        if len(digest) == HOST_KEY_DIGEST_LENGTH and set(digest) <= HOST_KEY_CHARS:
            return value
    raise CollectError(
        "host_key_fingerprint must be the sha256 host key fingerprint as ssh-keygen -lf prints it"
        " (%s followed by %d base64 characters), got %r"
        % (HOST_KEY_PREFIX, HOST_KEY_DIGEST_LENGTH, value)
    )


def _checked_legacy_ssh(value) -> tuple:
    if value is None:
        return ()
    options = LEGACY_SSH_OPTIONS.get(value) if isinstance(value, str) else None
    if options is None:
        raise CollectError(
            "legacy_ssh must be None for a device that speaks current algorithms or name one of"
            " the profiles %s, the options of a profile are written down in this module and never"
            " taken from the inventory, got %r"
            % (", ".join(sorted(LEGACY_SSH_OPTIONS)), value)
        )
    return options


def _checked_login(value) -> str:
    login = _checked_text("login", value).strip()
    if login.startswith("-") or any(mark in login for mark in ("@", ":", "/", " ", "\t")):
        raise CollectError(
            "login must be a plain user name without @, : or whitespace, got %r" % (value,)
        )
    return login


def _checked_command(value) -> str:
    command = _checked_text("command", value)
    if any(mark in command for mark in ("\n", "\r", "\x00")):
        raise CollectError("command must be a single line, got %r" % (value,))
    return command


def _ssh_target(host) -> tuple:
    text = _checked_text("host", host).strip()
    if "@" in text:
        raise CollectError("host must not carry credentials, the login is a separate argument")
    if "://" in text or text.startswith("-") or any(
        mark in text for mark in ("/", "?", "#", " ", "\t")
    ):
        raise CollectError("host must be a bare host or host:port, got %r" % (host,))
    name, port = text, SSH_PORT
    if ":" in text:
        name, _, digits = text.partition(":")
        if not digits.isdigit() or not 0 < int(digits) < 65536:
            raise CollectError("host port must be a number between 1 and 65535, got %r" % (host,))
        port = int(digits)
    if not name:
        raise CollectError("host must be a bare host or host:port, got %r" % (host,))
    return name, port


def _fingerprint_of(blob: str) -> str:
    material = base64.b64decode(blob, validate=True)
    digest = base64.b64encode(hashlib.sha256(material).digest()).decode("ascii").rstrip("=")
    return "%s%s" % (HOST_KEY_PREFIX, digest)


def _host_key_line(run, host, port, pin, seconds, failed) -> str:
    argv = [KEYSCAN_BINARY, "-T", str(max(1, int(seconds))), "-p", str(port), host]
    try:
        result = run(argv, seconds, None)
    except Exception as error:
        raise CollectError(
            "cannot read the host key of %s (%s)" % (host, type(error).__name__), failed()
        ) from None
    output = getattr(result, "stdout", None)
    if not isinstance(output, (bytes, bytearray)):
        raise CollectError(
            "the host key scan must answer with bytes on stdout, got %s" % type(output).__name__,
            failed(),
        )
    offered = []
    for line in bytes(output).decode("utf-8", "replace").splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) < 3:
            continue
        try:
            seen = _fingerprint_of(parts[2])
        except Exception:
            continue
        if seen == pin:
            return line
        offered.append(seen)
    if not offered:
        raise CollectError(
            "%s offered no host key, exit code %s" % (host, getattr(result, "returncode", None)),
            failed(),
        )
    raise CollectError(
        "host key of %s does not match the pinned fingerprint (expected %s, offered %s)"
        % (host, pin, ", ".join(offered)),
        failed(),
    )


def _identity(path, secret, failed) -> str:
    if isinstance(secret, str):
        data = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        data = bytes(secret)
    else:
        raise CollectError(
            "credential must hand over the private key as text, got %s" % type(secret).__name__,
            failed(),
        )
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "wb") as target:
        target.write(data if data.endswith(b"\n") else data + b"\n")
    return path


def _env(workspace) -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": workspace,
        "LC_ALL": "C",
    }


def _argv(host, port, login, known_hosts, identity, command, legacy) -> list:
    argv = [SSH_BINARY, "-F", SSH_CONFIG_FILE]
    for option in SSH_OPTIONS + legacy:
        argv.extend(["-o", option])
    argv.extend(["-o", "UserKnownHostsFile=%s" % known_hosts])
    argv.extend(["-i", identity, "-p", str(port), "%s@%s" % (login, host), command])
    return argv


def _run(argv, timeout, env):
    return subprocess.run(argv, capture_output=True, timeout=timeout, env=env, check=False)


def _shredded(workspace) -> None:
    shutil.rmtree(workspace, ignore_errors=True)


PROMPT_PREFIX = re.compile(r"^([^#\n]+# )")


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
        _Step(command="disable cli paging", prompt=True),
        _Step(command="show configuration", snapshot=True, prompt=True),
    ),
}
SSH_PLATFORMS = tuple(SSH_STEPS)


def _checked_platform(value) -> tuple:
    steps = SSH_STEPS.get(value) if isinstance(value, str) else None
    if steps is None:
        raise CollectError(
            "platform must be one of %s, got %r" % (", ".join(SSH_PLATFORMS), value)
        )
    return steps


def _cleaned(text, prompt) -> str:
    if not prompt or not text:
        return text
    found = PROMPT_PREFIX.match(text.split("\n", 1)[0])
    if found is None:
        return text
    marker = found.group(1)
    lines = text.splitlines()
    lines[0] = lines[0][len(marker):]
    ending = "\n" if text.endswith("\n") else ""
    bare = marker.rstrip()
    while lines and lines[-1].rstrip() == bare:
        lines.pop()
        ending = "\n"
    return "\n".join(lines) + (ending if lines else "")


def _field(text, name):
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == name:
            return value.strip()
    return None


def _said(result) -> str:
    data = getattr(result, "stderr", None)
    if not isinstance(data, (bytes, bytearray)):
        return ""
    readable = "".join(
        character if character.isprintable() else " "
        for character in bytes(data).decode("utf-8", "replace")
    )
    text = " ".join(readable.split())
    if not text:
        return ""
    if len(text) > SSH_ERROR_DETAIL_CHARS:
        text = text[:SSH_ERROR_DETAIL_CHARS] + "..."
    return ", the client said: %s" % text


def _ssh_step(run, argv, request, device, clock, seconds, env, required, target, legacy) -> tuple:
    started_at = _moment(clock)

    def failed(digest=EMPTY_SHA256, size=0):
        return _finished(
            device, request, started_at, clock, digest, size, OUTCOME_FAILED, CHANNEL_SSH
        )

    try:
        result = run(argv, seconds, env)
    except Exception as error:
        raise CollectError("%s failed (%s)" % (request, type(error).__name__), failed()) from None
    data = getattr(result, "stdout", None)
    if not isinstance(data, (bytes, bytearray)):
        raise CollectError(
            "the ssh runner must answer with bytes on stdout, got %s" % type(data).__name__,
            failed(),
        )
    data = bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    code = getattr(result, "returncode", None)
    if code != 0:
        said = _said(result)
        remedy = ""
        if not legacy and NEGOTIATION_MARKER in said:
            remedy = LEGACY_REMEDY % (target, ", ".join(sorted(LEGACY_SSH_OPTIONS)))
        raise CollectError(
            "%s failed with exit code %s%s%s" % (request, code, said, remedy),
            failed(digest, len(data)),
        )
    if required and not data:
        raise CollectError("%s returned an empty answer" % request, failed(digest, len(data)))
    return data, _finished(
        device, request, started_at, clock, digest, len(data), OUTCOME_OK, CHANNEL_SSH
    )


def collect_ssh(
    device,
    platform,
    host,
    login,
    credential,
    profile,
    host_key_fingerprint,
    legacy_ssh=None,
    timeout=SSH_TIMEOUT_SECONDS,
    runner=None,
    now=None,
) -> tuple:
    _checked_text("device", device)
    _checked_text("profile", profile)
    steps = _checked_platform(platform)
    user = _checked_login(login)
    name, port = _ssh_target(host)
    pin = _checked_host_key(host_key_fingerprint)
    legacy = _checked_legacy_ssh(legacy_ssh)
    seconds = _checked_timeout(timeout)
    _checked_credential(credential)
    run = _run if runner is None else runner
    source = "%s@%s" % (user, name) if port == SSH_PORT else "%s@%s:%d" % (user, name, port)
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

    known_host = _host_key_line(run, name, port, pin, seconds, failed)
    workspace = tempfile.mkdtemp(prefix="netops-auditor-")
    events, payload, taken, prompt = [], b"", None, False
    try:
        os.chmod(workspace, 0o700)
        known_hosts = os.path.join(workspace, "known_hosts")
        Path(known_hosts).write_text("%s\n" % known_host, encoding="utf-8")
        identity = os.path.join(workspace, "identity")
        _identity(identity, credential.use(), failed)
        environment = _env(workspace)
        for step in steps:
            request = "%s %s" % (source, step.command)
            data, event = _ssh_step(
                run,
                _argv(name, port, user, known_hosts, identity, step.command, legacy),
                request,
                device,
                clock,
                seconds,
                environment,
                step.snapshot,
                name,
                legacy,
            )
            events.append(event)
            if step.field:
                answer = _cleaned(data.decode("utf-8", "replace"), step.prompt)
                seen = _field(answer, step.field)
                if seen is None:
                    raise CollectError(
                        "cannot read %s of %s from %r" % (step.field, source, step.command),
                        replace(event, outcome=OUTCOME_FAILED),
                    )
                if seen != step.expect:
                    raise CollectError(
                        "%s reports %s %r instead of %r; the auditor does not change device"
                        " configuration - %s"
                        % (source, step.field, seen, step.expect, step.remedy),
                        replace(event, outcome=OUTCOME_FAILED),
                    )
            if step.snapshot:
                payload, taken, prompt = data, event, step.prompt
    except CollectError:
        raise
    except Exception as error:
        raise CollectError(
            "cannot prepare the ssh call to %s (%s)" % (source, type(error).__name__), failed()
        ) from None
    finally:
        _shredded(workspace)
    if taken is None:
        raise CollectError("platform %r has no step that takes a snapshot" % (platform,), failed())
    try:
        text = _cleaned(payload.decode("utf-8"), prompt)
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
        profile=profile,
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
