"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from contextlib import contextmanager
from contextvars import ContextVar
from functools import cache, wraps
import inspect
import ftplib
import fcntl
import ipaddress
import errno
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import subprocess
import stat
import struct
import tempfile
import threading
import ssl
import time
from collections.abc import Iterable
from typing import Any

from icmplib import ping
from netops_core import hostkey as core_hostkey
from netops_core import legacy_ssh as core_legacy_ssh
from netops_core import platforms as core_platforms
from netops_core import prompt as core_prompt
from netops_core import session as core_session
from netops_core import sftp as core_sftp
from netops_core import ssh as core_ssh
from netops_core.inputs import InputError, read_regular

from . import progress
from .audit import AuditPostOperationError, AuditPreflightError, record
from .auth import (
    LEGACY_SSH_PROFILES, AuthenticationContextError, EgressScopeError,
    LegacySshProfileRequired, PolicyScopeError, TargetAuth,
)
from .inventory import unique_object
from .read_policy import (
    READ_QUERIES, is_read_sequence, normalize_platform, render_read_query, render_read_sequence,
    require_fortinet_sequence,
)
from . import normalization
from .sanitize import digest_text, redact
from . import wifi_parse
from .switch_dhcp import DHCP_BINDINGS_QUERY, summarize as dhcp_bindings_summarize
from .switch_mclag import MCLAG_QUERIES, not_supported as mclag_not_supported, summarize as mclag_summarize


_LEGACY_SSH_HOST_KEY_ALGS = ("ssh-rsa",)
_LEGACY_SSH_KEX_ALGS = ("diffie-hellman-group14-sha1",)
_SSH_LEGACY_PROFILES: dict[str | None, tuple[str, ...]] = {
    None: (),
    "rsa-sha1": _LEGACY_SSH_HOST_KEY_ALGS,
    "rsa-sha1-dh14": _LEGACY_SSH_HOST_KEY_ALGS,
}
_SSH_LEGACY_KEX: dict[str | None, tuple[str, ...]] = {
    None: (),
    "rsa-sha1": (),
    "rsa-sha1-dh14": _LEGACY_SSH_KEX_ALGS,
}
_OPENSSH_LEGACY_OPTIONS = ("HostKeyAlgorithms", "PubkeyAcceptedAlgorithms")
if (
    set(_SSH_LEGACY_PROFILES) != {None, *LEGACY_SSH_PROFILES}
    or set(_SSH_LEGACY_KEX) != set(_SSH_LEGACY_PROFILES)
    or _SSH_LEGACY_PROFILES[None]
    or _SSH_LEGACY_KEX[None]
    or any(
        set(enabled) - set(_LEGACY_SSH_HOST_KEY_ALGS)
        for enabled in _SSH_LEGACY_PROFILES.values()
    )
    or any(set(kex) - set(_LEGACY_SSH_KEX_ALGS) for kex in _SSH_LEGACY_KEX.values())
    or tuple(core_legacy_ssh.PROFILES) != LEGACY_SSH_PROFILES
    or any(
        core_legacy_ssh.openssh_options(profile)
        != tuple(f"{option}=+{name}" for option in _OPENSSH_LEGACY_OPTIONS for name in enabled)
        + tuple(f"KexAlgorithms=+{name}" for name in _SSH_LEGACY_KEX[profile])
        for profile, enabled in _SSH_LEGACY_PROFILES.items()
        if profile is not None
    )
    or core_legacy_ssh.openssh_options(None) != ()
):
    raise RuntimeError("SSH legacy profile mapping is incomplete or invalid")
_TRANSPORT_EXEC = "exec"
_TRANSPORT_PTY = "pty"
_SSH_TRANSPORTS = {
    "linux": _TRANSPORT_EXEC,
    "fortinet": _TRANSPORT_EXEC,
    "extreme_exos": _TRANSPORT_EXEC,
    "cisco_ios": _TRANSPORT_EXEC,
    "cisco_xe": _TRANSPORT_EXEC,
    "cisco_nxos": _TRANSPORT_EXEC,
    "arista_eos": _TRANSPORT_EXEC,
    "juniper_junos": _TRANSPORT_EXEC,
    "juniper_junos_els": _TRANSPORT_EXEC,
    "ruckus_unleashed": _TRANSPORT_PTY,
    "fortiadc": _TRANSPORT_EXEC,
}
_PLATFORM_PREAMBLE: dict[str, tuple[str, ...]] = {}
_RUCKUS_LOGIN_PROMPT = b"Please login:"
_RUCKUS_PASSWORD_PROMPT = b"assword"
_RUCKUS_USER_PROMPT = b"ruckus>"
_RUCKUS_ENABLE_PROMPT = b"ruckus#"
_RUCKUS_ENABLE_COMMAND = "enable"
_CONNECTION_SPACING_SECONDS: dict[str, float] = {"fortinet": 5.0, "fortiadc": 5.0}
if (
    set(_SSH_TRANSPORTS) != set(READ_QUERIES)
    or set(_SSH_TRANSPORTS.values()) - {_TRANSPORT_EXEC, _TRANSPORT_PTY}
    or set(_PLATFORM_PREAMBLE) - set(_SSH_TRANSPORTS)
    or any(
        _SSH_TRANSPORTS[platform] != _TRANSPORT_EXEC for platform in _PLATFORM_PREAMBLE
    )
    or _RUCKUS_ENABLE_COMMAND != "enable"
    or set(_CONNECTION_SPACING_SECONDS) - set(_SSH_TRANSPORTS)
    or any(
        isinstance(spacing, bool) or not isinstance(spacing, (int, float)) or spacing < 0
        for spacing in _CONNECTION_SPACING_SECONDS.values()
    )
):
    raise RuntimeError("SSH transport mapping is incomplete or invalid")
_SSH_READ_TIMEOUT_SECONDS = 60.0
_SSH_LOGIN_TIMEOUT_SECONDS = 20.0
_HOST_KEY_SCAN_TIMEOUT_SECONDS = 10.0
_HOST_KEY_PROBE_TIMEOUT_SECONDS = 5.0
_SSH_CACHE_TTL_SECONDS = 120.0
_SSH_CACHE_MAX_ENTRIES = 8
_SSH_CAPTURE_MAX_BYTES = 2_000_000
# Log message queries: fixed line limit applied to the redacted output before it is stored or paged.
# EXOS lists the newest message first; IOS, IOS XE, NX-OS, EOS and Junos print the oldest first, so the limit keeps the trailing lines.
_EXOS_LOG_QUERIES = frozenset({"log_messages", "log_warnings"})
_OLDEST_FIRST_LOG_PROFILES = frozenset({"cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "juniper_junos", "juniper_junos_els"})
_OLDEST_FIRST_LOG_QUERIES = frozenset({"log_messages", "log_interactive_commands"})
# Junos `| last 200 | no-more` prints the pager mark of the `last` stage in front of the final line, e.g. "---(more 100%)---  <line>".
_JUNOS_LAST_PAGER_MARK = re.compile(r"(?m)^[ \t]*---\(more 100%\)---[ \t]*\r?\n(?:[ \t]*\r?\n)?|---\(more 100%\)---[ \t]*")
_LOG_MAX_LINES = 200
_LOG_MESSAGE_START = re.compile(r"\d\d/\d\d/\d{4} \d\d:\d\d:\d\d")
# Entry: expiry, rc, redacted text, the secret set it was redacted with, identity response, log line limit.
_SSH_PAGE_CACHE: dict[
    tuple[Any, ...], tuple[float, int | None, str, frozenset[str], dict | None, dict | None]
] = {}
_SSH_CACHE_LOCK = threading.Lock()

_now = time.monotonic
_sleep = time.sleep


class _ConnectionLane:
    """One device's SSH-family connection queue: a lock plus the last start time."""

    __slots__ = ("lock", "last_started")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_started: float | None = None


_CONNECTION_LANES: dict[tuple[str, int], _ConnectionLane] = {}
_CONNECTION_LANES_LOCK = threading.Lock()


def _lane_for(address: str, port: int) -> _ConnectionLane:
    key = (address, port)
    with _CONNECTION_LANES_LOCK:
        lane = _CONNECTION_LANES.get(key)
        if lane is None:
            lane = _ConnectionLane()
            _CONNECTION_LANES[key] = lane
        return lane


@cache
def _lane_directory() -> Path:
    """Resolve the shared lane path only when an SSH connection needs it."""
    return Path(tempfile.gettempdir()) / ("netops-helper-ssh-lanes-%d" % os.geteuid())


@contextmanager
def _process_connection_lane(address: str, port: int):
    """Private, persistent lock inode shared by Helper and its locate workers."""
    lane_directory = _lane_directory()
    try:
        lane_directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory = os.open(lane_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("SSH lane directory is unsafe")
        name = hashlib.sha256(json.dumps([address, port]).encode()).hexdigest() + ".lane"
        descriptor = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             0o600, dir_fd=directory)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("SSH lane file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)  # closing also releases flock after cancellation
        os.close(directory)


@contextmanager
def _paced_connection(address: str, port: int, platform: str | None):
    """Serialize connections per (address, port), including independent locate workers.

    The lock is held for the whole connection. The private file retains the last
    monotonic start, so FortiOS/FortiADC starts remain at least five seconds apart
    even when consecutive reads happen in different processes.
    """
    spacing = _CONNECTION_SPACING_SECONDS.get(platform, 0.0)
    lane = _lane_for(address, port)
    with lane.lock, _process_connection_lane(address, port) as descriptor:
        saved = os.pread(descriptor, 9, 0)
        if saved:
            if len(saved) != 8:
                raise ValueError("SSH lane timestamp is invalid")
            previous, = struct.unpack("!d", saved)
            if not math.isfinite(previous) or previous < 0:
                raise ValueError("SSH lane timestamp is invalid")
            wait = previous + spacing - _now()
            if wait > 0:
                _sleep(_read_timeout(wait))
        _read_timeout(_SSH_READ_TIMEOUT_SECONDS)
        lane.last_started = _now()
        if os.pwrite(descriptor, struct.pack("!d", lane.last_started), 0) != 8:
            raise OSError("SSH lane timestamp write failed")
        yield


_HOST_KEY_CACHE_TTL_SECONDS = 600.0
_HOST_KEY_CACHE_MAX_ENTRIES = 64
_HOST_KEY_LINE_CACHE: dict[tuple[str, int, str], tuple[float, str]] = {}
_HOST_KEY_CACHE_LOCK = threading.Lock()


def _cached_host_key_line(key: tuple[str, int, str]) -> str | None:
    with _HOST_KEY_CACHE_LOCK:
        entry = _HOST_KEY_LINE_CACHE.get(key)
        if entry is None:
            return None
        expires, line = entry
        if expires <= _now():
            _HOST_KEY_LINE_CACHE.pop(key, None)
            return None
        return line


def _cache_host_key_line(key: tuple[str, int, str], line: str) -> None:
    with _HOST_KEY_CACHE_LOCK:
        if (
            key not in _HOST_KEY_LINE_CACHE
            and len(_HOST_KEY_LINE_CACHE) >= _HOST_KEY_CACHE_MAX_ENTRIES
        ):
            oldest = min(_HOST_KEY_LINE_CACHE, key=lambda item: _HOST_KEY_LINE_CACHE[item][0])
            _HOST_KEY_LINE_CACHE.pop(oldest, None)
        _HOST_KEY_LINE_CACHE[key] = (_now() + _HOST_KEY_CACHE_TTL_SECONDS, line)


def _forget_host_key_line(address: str, port: int) -> None:
    with _HOST_KEY_CACHE_LOCK:
        stale = [
            key for key in _HOST_KEY_LINE_CACHE if key[0] == address and key[1] == port
        ]
        for key in stale:
            _HOST_KEY_LINE_CACHE.pop(key, None)


class DeviceCredential:
    """The credential-store handle `netops_core` expects, built from the envelope secret."""

    __slots__ = ("kind", "login", "_secret")

    def __init__(self, auth: "TargetAuth") -> None:
        self.kind = auth.credential_kind
        self.login = auth.login
        self._secret = auth.secret

    def use(self) -> str:
        return self._secret

    def __repr__(self) -> str:
        return f"<DeviceCredential {self.kind}>"

    __str__ = __repr__


def host_key_line(
    auth: TargetAuth, address: str | None = None, platform: str | None = None,
) -> str:
    """Read the offered host keys through netops_core.hostkey.scan and keep the one matching the pin.

    A cache hit answers without a keyscan at all; a miss queues the keyscan
    itself through the same per-device lane as every other SSH-family
    connection, so it too respects the platform's connection spacing.
    """
    target = _resolve_target_ipv4(auth)[0] if address is None else address
    effective_platform = auth.ssh_platform if platform is None else platform
    cache_key = (target, auth.port, auth.host_key_fingerprint)
    cached = _cached_host_key_line(cache_key)
    if cached is not None:
        return cached
    try:
        with _paced_connection(target, auth.port, effective_platform):
            try:
                line = core_hostkey.scan(
                    target, auth.port, auth.host_key_fingerprint, _read_timeout(_HOST_KEY_SCAN_TIMEOUT_SECONDS),
                    legacy=auth.legacy_ssh,
                )
            except core_hostkey.HostKeyUnavailable as exc:
                # ssh-keyscan is silent about why no key came; one credential-free probe tells an
                # unreachable, refusing or silent host from one that answered without a usable key.
                said = core_hostkey.unavailable_said(
                    target, auth.port, _read_timeout(_HOST_KEY_PROBE_TIMEOUT_SECONDS), legacy=auth.legacy_ssh,
                )
                cause = _marked_cause(said)
                code = (cause if cause in _UNANSWERED_CAUSES
                        else "host_key_unavailable" if said else "transport_failure")
                raise _classified(AuthenticationContextError(
                    f'SSH host-key verification unavailable for target "{auth.alias}": {_TRANSPORT_ADVICE[code]}'
                ), code) from exc
    except core_hostkey.HostKeyError as exc:
        raise _classified(AuthenticationContextError(
            f'target "{auth.alias}" did not offer the pinned SSH host key'
        ), "host_key_mismatch") from exc
    _cache_host_key_line(cache_key, line)
    return line


def _resolve_target_ipv4(auth: TargetAuth) -> tuple[str, ...]:
    try:
        parsed = ipaddress.ip_address(auth.host)
    except ValueError:
        auth.require_dns()
        rows = socket.getaddrinfo(
            auth.host, None, family=socket.AF_INET, type=socket.SOCK_STREAM,
        )
        addresses = tuple(sorted({str(ipaddress.ip_address(row[4][0])) for row in rows}))
    else:
        if parsed.version != 4:
            raise EgressScopeError("only IPv4 target addresses are supported")
        addresses = (str(parsed),)
    if not addresses:
        raise EgressScopeError("target did not resolve to an IPv4 address")
    if any(not auth.egress.allows_address(address) for address in addresses):
        raise EgressScopeError("resolved target address is outside the egress allowlist")
    return addresses


def _refused_host_key_algorithms(auth: TargetAuth) -> list[str]:
    enabled = _SSH_LEGACY_PROFILES[auth.legacy_ssh]
    return [name for name in _LEGACY_SSH_HOST_KEY_ALGS if name not in enabled]


def _legacy_ssh_required(auth: TargetAuth) -> LegacySshProfileRequired:
    names = ", ".join(_refused_host_key_algorithms(auth))
    return LegacySshProfileRequired(
        f'target "{auth.alias}" offers no SSH host key or key exchange algorithm '
        f"enabled by default; for a target which offers only {names} host keys set "
        f'"legacy_ssh": "rsa-sha1" in its inventory.json entry, which allows them '
        f"for that device alone; a target which also offers only SHA-1 key exchange "
        f'needs "legacy_ssh": "rsa-sha1-dh14", which adds diffie-hellman-group14-sha1 '
        f"and nothing else for that device alone."
    )


def _exec_failure(auth: TargetAuth, exc: core_ssh.SshError) -> BaseException:
    # Only the client's own verdict tells a refused negotiation; a banner naming "no matching" is device text.
    if auth.legacy_ssh is None and _client_verdict(exc) == "negotiation":
        return _legacy_ssh_required(auth)
    return exc


def _exec_command(
    auth: TargetAuth,
    address: str,
    known_hosts_line: str,
    credential: DeviceCredential,
    command: str,
    platform: str,
    stdout_consumer=None,
) -> core_ssh.Result:
    limits = auth.configuration_limits
    stream_options = ({"stdout_consumer": stdout_consumer, "idle_timeout_seconds": limits.idle_seconds, "capture_max_bytes": limits.all_bytes}
                      if stdout_consumer is not None else {})
    try:
        with _paced_connection(address, auth.port, platform):
            return core_ssh.run_command(
                address,
                auth.port,
                auth.login,
                credential,
                known_hosts_line,
                command,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_read_timeout(limits.total_seconds if stdout_consumer is not None else _SSH_READ_TIMEOUT_SECONDS),
                **stream_options,
            )
    except (core_ssh.OutputLimitError, core_ssh.OutputConsumerError):
        raise
    except core_ssh.SshError as exc:
        _forget_host_key_line(address, auth.port)
        raise _exec_failure(auth, exc) from exc


# FortiOS and the normalized switch/router profiles: known secret literals are replaced
# before and after CRLF-to-LF normalization (switch_read and locate_endpoint read here too).
_IDENTITY_PROBE = ContextVar("helper_identity_probe", default=False)

_LINE_END_PLATFORMS = frozenset({"fortinet"}) | normalization.IDENTITY_PROFILES


def _exec_read(auth: TargetAuth, platform: str, command: str, stdout_consumer=None) -> tuple[int | None, str]:
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    credential = DeviceCredential(auth)
    for preamble in _PLATFORM_PREAMBLE.get(platform, ()):
        _exec_command(auth, address, known_hosts_line, credential, preamble, platform)
    options = {'stdout_consumer': stdout_consumer} if stdout_consumer is not None else {}
    result = _exec_command(auth, address, known_hosts_line, credential, command, platform, **options)
    if stdout_consumer is not None:
        if result.stdout:
            raise ValueError('streaming transport returned unexpected accumulated output')
        return result.rc, ''
    text = result.stdout.decode("utf-8", "replace")
    if platform in _LINE_END_PLATFORMS:
        # schema_read and the table parsers read this text: pattern rules could destroy CLI syntax.
        secrets = () if _IDENTITY_PROBE.get() else _redaction_secret_forms(auth)
        for value in secrets:
            text = text.replace(value, "<REDACTED>")
        text = text.replace("\r\n", "\n")
        for value in secrets:
            text = text.replace(value, "<REDACTED>")
    return result.rc, core_prompt.cleaned(text, platform)


def _erase_backspaces(text: str) -> str:
    kept: list[str] = []
    for char in text:
        if char != "\b":
            kept.append(char)
        elif kept and kept[-1] != "\n":
            kept.pop()
    return "".join(kept)


def _pty_body(data: bytes, command: str, prompt: bytes) -> str:
    text = _erase_backspaces(data.decode("utf-8", "replace").replace("\r", ""))
    marker = prompt.decode("ascii")
    if text.endswith(marker):
        text = text[: -len(marker)]
    lines = text.split("\n")
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    if start < end and lines[start].strip() == command:
        start += 1
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return "\n".join(lines[start:end])


def _pty_read(auth: TargetAuth, platform: str, command: str) -> tuple[int | None, str]:
    """Answer a device without an exec channel, discarding every byte of the login."""
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            session = core_session.Session(
                address,
                auth.port,
                auth.login,
                DeviceCredential(auth),
                known_hosts_line,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
            )
            try:
                for prompt, answer in (
                    (_RUCKUS_LOGIN_PROMPT, auth.login),
                    (_RUCKUS_PASSWORD_PROMPT, auth.secret),
                    (_RUCKUS_USER_PROMPT, _RUCKUS_ENABLE_COMMAND),
                ):
                    _, seen = session.expect([prompt], _SSH_LOGIN_TIMEOUT_SECONDS)
                    session.discard(seen)
                    session.send(answer)
                _, seen = session.expect([_RUCKUS_ENABLE_PROMPT], _SSH_LOGIN_TIMEOUT_SECONDS)
                session.discard(seen)
                session.send(command)
                _, answered = session.expect([_RUCKUS_ENABLE_PROMPT], _SSH_READ_TIMEOUT_SECONDS)
            finally:
                session.close()
    except core_session.SessionError:
        _forget_host_key_line(address, auth.port)
        raise
    return None, _pty_body(answered, command, _RUCKUS_ENABLE_PROMPT)


def _prompt_read(auth: TargetAuth, platform: str, command: str) -> tuple[int | None, str]:
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            session = core_session.Session(
                address,
                auth.port,
                auth.login,
                DeviceCredential(auth),
                known_hosts_line,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
                capture_max_bytes=_SSH_CAPTURE_MAX_BYTES,
            )
            try:
                prompt = _FortiosDiagnosticShell(session, platform).prompt
                session.send(command)
                _, answered = session.expect([prompt], _SSH_READ_TIMEOUT_SECONDS)
            finally:
                session.close()
    except core_session.SessionError:
        _forget_host_key_line(address, auth.port)
        raise
    return None, _pty_body(answered, command, prompt)


_LOCATE_BUDGET = ContextVar("helper_locate_budget", default=None)


def _read_timeout(seconds):
    budget = _LOCATE_BUDGET.get()
    return min(seconds, budget.remaining()) if budget is not None else seconds


_TRIAGE_READ_ATTEMPT = ContextVar("helper_triage_read_attempt", default=None)


def read_from_device(
    auth: TargetAuth, platform: str, command: str, *, stdout_consumer=None, prompt=False,
) -> tuple[int | None, str]:
    normalized = normalize_platform(platform)
    if stdout_consumer is not None and (normalized not in ('fortinet', 'fortiadc') or not callable(stdout_consumer)):
        raise ValueError('streaming is supported only for FortiOS and FortiADC exec reads')
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    attempt = _TRIAGE_READ_ATTEMPT.get()
    if attempt is not None:
        attempt[0] = True
    if prompt:
        if normalized not in ("fortiadc", "fortinet") or stdout_consumer is not None:
            raise ValueError("prompt reads are supported only for FortiADC and FortiOS catalogue queries")
        return _prompt_read(auth, normalized, command)
    if _SSH_TRANSPORTS[normalized] == _TRANSPORT_PTY:
        return _pty_read(auth, normalized, command)
    options = {"stdout_consumer": stdout_consumer} if stdout_consumer is not None else {}
    return _exec_read(auth, normalized, command, **options)


_CISCO_AUTOCOMMAND_REFUSAL = re.compile(
    r'(?m)^[ \t]*Line has invalid autocommand "[^"\r\n]*"[ \t]*\r?$'
)
_JUNOS_REFUSAL = re.compile(
    r"(?m)^[ \t]*error: (?:syntax error, expecting <command>: [^\r\n]*+"
    r"|unknown command: [^\r\n]*+|permission denied: [^\r\n]*+"
    r"|the [a-z0-9-]+ subsystem is not running)[ \t]*\r?$"
)
_CLI_REFUSALS = {
    "fortinet": re.compile(
        r"(?mi)^[ \t]*(?:Command fail\.(?:[ \t]+Return code[ \t]+-?[0-9]+)?"
        r"|command parse error before[^\r\n]*+|Unknown action[ \t]+[0-9]+"
        r"|(?:%[ \t]+)?Inbound soft reconfiguration not enabled)[ \t]*\r?$"
    ),
    "fortiadc": re.compile(
        r"(?m)^[ \t]*Command fail\. Return code is [+-]?[0-9]+ \((?:[^()\r\n]+|\(null\))\)[ \t]*\r?$"
    ),
    "extreme_exos": re.compile(
        r"(?mi)^[ \t]*(?:This user does not have permissions for this command\."
        r"|Method is not implemented on this platform\."
        r"|%%[ \t]+(?:Invalid input detected|Unrecognized command|Incomplete command|Ambiguous command)[^\r\n]*+)[ \t]*\r?$"
    ),
    "cisco_ios": _CISCO_AUTOCOMMAND_REFUSAL,
    "cisco_xe": _CISCO_AUTOCOMMAND_REFUSAL,
    "arista_eos": re.compile(
        r"(?m)^[ \t]*% Invalid input(?: \([^)\r\n]*\))? at line [0-9]+[ \t]*\r?$"
    ),
    "juniper_junos": _JUNOS_REFUSAL,
    "juniper_junos_els": _JUNOS_REFUSAL,
    "cisco_nxos": re.compile(
        r"(?m)^[ \t]*(?:Syntax error while parsing '[^'\r\n]*'"
        r"|% Permission denied for the role)[ \t]*\r?$"
    ),
}


def _cli_refused(platform: str, output: str, *, command: str | None = None) -> bool:
    """Detect device refusal lines anywhere; command is compatibility metadata only."""
    pattern = _CLI_REFUSALS.get(platform)
    return ((pattern is not None and pattern.search(output) is not None)
            or normalization.permission_refused(platform, output)
            or normalization.template_refused(platform, output))


def _control_refused(platform: str, output: str) -> bool:
    """Control reads use exactly the same refusal rules as other reads."""
    return _cli_refused(platform, output)


_IDENTITY_COMMAND = "get system status"
_IDENTITY_PLATFORMS = frozenset({"fortinet", "fortiadc"})


class _ProductIdentityError(Exception):
    def __init__(self, platform: str, rc: int | None, reason: str = "identity_os_mismatch") -> None:
        super().__init__(
            "The live device did not identify itself as the selected product "
            f"({core_platforms.normalize(platform)}); no query output was returned"
        )
        self.rc = rc
        self.reason = reason


def _require_product(platform: str, rc: int | None, status: str) -> None:
    try:
        if rc not in (0, None) or _cli_refused(platform, status):
            raise core_platforms.PlatformError("the identity command was refused")
        core_platforms.require_identity(platform, status)
    except core_platforms.PlatformError:
        raise _ProductIdentityError(platform, rc) from None


def _check_identity(auth: TargetAuth, platform: str, read) -> tuple[str, int | None, str]:
    """One identity read through `read`, checked as the selected product; returns (command, rc, output).

    The single place that decides "this is the OS the alias says": normalized reads and
    endpoint location share it, so both classify refusals and report reasons alike.
    `read` is read_from_device or a wrapper that counts the read against a budget.
    The live product is checked before each fresh read; a confirmed identity is never cached.
    """
    token = _IDENTITY_PROBE.set(True)
    try:
        if platform in normalization.IDENTITY_PROFILES:
            command = READ_QUERIES[platform]["version"].command
            rc, status = read(auth, platform, command)
            try:
                state = normalization.output_status(status, rc=rc, truncated=len(status.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES, profile=platform, command=command)
                if state != "ok" or _cli_refused(platform, status, command=command):
                    raise normalization.IdentityError("identity_" + (state if state != "ok" else "refused"))
                normalization.parse_identity(platform, status)
            except normalization.IdentityError as exc:
                raise _ProductIdentityError(platform, rc, exc.reason) from None
            return command, rc, _redact_output(status, auth)
        rc, status = read(auth, platform, _IDENTITY_COMMAND)
        _require_product(platform, rc, status)
        return _IDENTITY_COMMAND, rc, _redact_output(status, auth)
    finally:
        _IDENTITY_PROBE.reset(token)


def _verified_read(auth: TargetAuth, platform: str, command: str, prompt: bool = False) -> tuple[int | None, str]:
    if platform in normalization.IDENTITY_PROFILES:
        identity_command, rc, status = _check_identity(auth, platform, read_from_device)
        return (rc, status) if command == identity_command else read_from_device(auth, platform, command)
    if platform not in _IDENTITY_PLATFORMS:
        return read_from_device(auth, platform, command)
    # A requested status is itself the live identity check.
    identity_command, rc, status = _check_identity(auth, platform, read_from_device)
    if command == identity_command:
        return rc, status
    return read_from_device(auth, platform, command, **({"prompt": True} if prompt else {}))


_SEQUENCE_STEP_TIMEOUT_SECONDS = 30


def _sequence_read(auth: TargetAuth, platform: str, commands: tuple[str, ...]) -> tuple[int | None, str]:
    """Run a reviewed FortiOS `execute log` sequence in one SSH session and answer the last command's text.

    The log filter lives only in this session. A filter command that prints anything was refused by
    the device, so its text is answered at once for the CLI refusal check.
    """
    commands = require_fortinet_sequence(tuple(commands))
    if platform != "fortinet":
        raise ValueError("command sequences are supported only for FortiOS")
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            with core_session.Session(
                address, auth.port, auth.login, DeviceCredential(auth), known_hosts_line,
                legacy_ssh=auth.legacy_ssh, timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
                capture_max_bytes=_SSH_CAPTURE_MAX_BYTES,
            ) as session:
                shell = _FortiosDiagnosticShell(session, platform, answer_refusal_raises=False)
                text = ""
                for index, command in enumerate(commands):
                    text = shell.command(command, _SEQUENCE_STEP_TIMEOUT_SECONDS)
                    if index < len(commands) - 1 and text.strip():
                        break
    except core_session.SessionError:
        _forget_host_key_line(address, auth.port)
        raise
    return None, text


def _verified_sequence(auth: TargetAuth, platform: str, commands: tuple[str, ...]) -> tuple[int | None, str]:
    if platform not in _IDENTITY_PLATFORMS:
        raise ValueError("command sequences are supported only for FortiOS")
    _check_identity(auth, platform, read_from_device)
    return _sequence_read(auth, platform, commands)


_WTP_SEEN: dict[tuple[Any, ...], dict[str, float]] = {}
_WTP_SEEN_LOCK = threading.Lock()
_WTP_SEEN_TTL_SECONDS = 3600.0
_WTP_SEEN_MAX_TARGETS = 64
_WTP_SEEN_MAX_IDS = 256
_WTP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,34}")


def _wtp_key(auth: TargetAuth) -> tuple[Any, ...]:
    return (auth.alias, auth.host, auth.port, auth.login)


def _observed_wtp_ids(auth: TargetAuth) -> frozenset[str]:
    now = time.monotonic()
    with _WTP_SEEN_LOCK:
        for key, entries in list(_WTP_SEEN.items()):
            _WTP_SEEN[key] = {serial: expiry for serial, expiry in entries.items() if expiry > now}
            if not _WTP_SEEN[key]:
                _WTP_SEEN.pop(key, None)
        entry = _WTP_SEEN.get(_wtp_key(auth))
        return frozenset(entry) if entry else frozenset()


def _remember_wtp_ids(auth: TargetAuth, serials: list[str]) -> None:
    """Remember the access point ids this target itself listed in `wtp-status`; nothing else is remembered."""
    clean = frozenset(item for item in serials if _WTP_ID.fullmatch(item))
    if not clean:
        return
    with _WTP_SEEN_LOCK:
        now = time.monotonic()
        for old_key, entries in list(_WTP_SEEN.items()):
            _WTP_SEEN[old_key] = {serial: expiry for serial, expiry in entries.items() if expiry > now}
            if not _WTP_SEEN[old_key]:
                del _WTP_SEEN[old_key]
        key = _wtp_key(auth)
        if key not in _WTP_SEEN and len(_WTP_SEEN) >= _WTP_SEEN_MAX_TARGETS:
            _WTP_SEEN.pop(min(_WTP_SEEN, key=lambda item: max(_WTP_SEEN[item].values())), None)
        entries = _WTP_SEEN.setdefault(key, {})
        entries.update({serial: now + _WTP_SEEN_TTL_SECONDS for serial in clean})
        for serial in sorted(entries, key=lambda item: (entries[item], item))[:max(0, len(entries) - _WTP_SEEN_MAX_IDS)]:
            del entries[serial]


def _read_inventory(auth: TargetAuth) -> dict[str, tuple[str, ...]]:
    """Enrolled inventory plus the access point ids this target listed earlier (wtp_ids only)."""
    inventory = dict(auth.read_inventory)
    if auth.ssh_platform == "fortinet":
        inventory["wtp_ids"] = tuple(sorted(set(inventory.get("wtp_ids", ())) | _observed_wtp_ids(auth)))
    return inventory


def _safe_error(exc: Exception, auth: TargetAuth) -> str:
    return redact(f"{type(exc).__name__}: {exc}", auth.secrets)


def _bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool) or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _bounded_timeout(
    value: object, name: str, minimum: float, maximum: float,
) -> float | int:
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(value) or not minimum <= value <= maximum
    ):
        raise ValueError(f"{name} must be a finite number between {minimum} and {maximum}")
    return value


def _validate_pagination(offset: object, max_bytes: object) -> tuple[int, int]:
    return (
        _bounded_int(offset, "offset", 0, 8_000_000),
        _bounded_int(max_bytes, "max_bytes", 1_000, 48_000),
    )


def _page_text(text: str, offset: int, max_bytes: int, whole_lines: bool = False) -> dict[str, Any]:
    """One page of text; with whole_lines a page that is not the last ends after its last newline, if it has one."""
    raw = text.encode("utf-8")
    offset, max_bytes = _validate_pagination(offset, max_bytes)
    if offset < 0 or offset > len(raw):
        raise ValueError("offset is outside the output")
    try:
        raw[:offset].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("offset is not a UTF-8 boundary; use next_offset") from exc
    end = min(offset + max_bytes, len(raw))
    while end > offset and end < len(raw) and raw[end] & 0xC0 == 0x80:
        end -= 1
    if whole_lines and end < len(raw):
        newline = raw.rfind(b"\n", offset, end)
        if newline >= 0:
            end = newline + 1
    page = raw[offset:end].decode("utf-8")
    return {
        "total_bytes": len(raw),
        "offset": offset,
        "returned_bytes": end - offset,
        "next_offset": end if end < len(raw) else None,
        "complete": end == len(raw),
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "untrusted_device_output": page,
    }


def _redaction_secret_forms(auth: TargetAuth) -> tuple[str, ...]:
    forms = {
        form
        for value in auth.redaction_secrets
        for form in (value, value.replace("\r\n", "\n"), value.replace("\r", ""))
        if len(form.encode("utf-8")) >= 3  # same floor as sanitize.redact
    }
    return tuple(sorted(forms, key=lambda value: (-len(value), value)))


def _redact_output(output: str, auth: TargetAuth) -> str:
    """Canonical SSH text: the bytes the client receives, hashed and paged by the caller.

    The proxy and worker redact the response again with their own rules. Applying every
    layer here, until none changes the text, keeps hash, offsets and sizes true for the
    final response; the worker withholds a page that a later layer still alters.
    """
    from .sanitize import redact_response

    return redact_response(output, _redaction_secret_forms(auth))


_SCHEMA_REDACTION_UNVERIFIED = "schema redaction could not be verified; report withheld"
# Rounds of the response redaction until it changes nothing more; it settles in one or two.
_RESPONSE_ROUNDS = 8


def _redact_schema_report(report: Any, auth: TargetAuth) -> str:
    """Redact JSON values before serialization; text rules never edit JSON punctuation.

    Probe both the structured and textual rules so suffix labels (e.g. fortitoken),
    containers under secret keys, numeric credentials and nested JSON strings get
    at least the protection of every response layer. A changed leaf is withheld
    as a whole, rather than retaining a fragment of a secret.

    The known secrets are prepared once. A string that holds no form of any of them
    and cannot hide one behind a JSON escape or a nested document is judged by the
    secret-free rules alone, which is the same verdict because those rules apply a
    known secret only by replacing it as a substring; the verdict is remembered per
    distinct string. Anything else takes the complete check with every secret.
    """
    from netops.redaction import redact as product_redact
    from .page_metadata import json_object
    from .proxy_sanitize import sanitize_object, sanitize_text

    secrets = auth.redaction_secrets
    known = tuple(secret for secret in secrets if secret)
    forms = tuple(dict.fromkeys(form for secret in known for form in (
        secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1])))
    marker = "[REDACTED]"

    def exact(value: Any, secrets_=secrets) -> bool:
        if value is None or isinstance(value, (bool, int, float)):
            encoded = json.dumps(value, ensure_ascii=False)
            if any(secret and secret in encoded for secret in secrets_):
                return True
        return (sanitize_object(value, secrets_) != value
                or product_redact(value, secrets_)[0] != value
                or isinstance(value, str) and redact(value, secrets_) != value)

    plain_verdicts: dict[str, bool] = {}
    text_verdicts: dict[str, bool] = {}
    key_verdicts: dict[str, bool] = {}
    risky = False  # a string that may hold a secret behind an escape or in a nested document

    def plain(value: str) -> bool:
        verdict = plain_verdicts.get(value)
        if verdict is None:
            verdict = plain_verdicts[value] = exact(value, ())
        return verdict

    def hidden(value: Any) -> bool:
        nonlocal risky
        if type(value) is str:
            verdict = text_verdicts.get(value)
            if verdict is None:
                nested = "\\" in value or value.lstrip()[:1] in ("{", "[")
                risky = risky or nested
                if nested or any(form in value for form in forms):
                    verdict = exact(value)
                else:
                    verdict = plain(value)
                text_verdicts[value] = verdict
            return verdict
        if value is None or isinstance(value, (bool, int, float)):
            encoded = json.dumps(value, ensure_ascii=False)
            return any(secret in encoded for secret in known)
        return exact(value)

    def sensitive_key(key: Any) -> bool:
        if type(key) is str and key in key_verdicts:
            return key_verdicts[key]
        probe = {key: "netops-probe-value"}
        encoded = json.dumps(probe, ensure_ascii=False, separators=(",", ":"))
        verdict = exact(probe, ()) or exact(encoded, ()) or sanitize_text(encoded) != encoded
        if type(key) is str:
            key_verdicts[key] = verdict
        return verdict

    def show_text(attributes: Any) -> str:
        """The `show` lines of schema_read.snapshot, built from the redacted attributes.

        A line the rules still change, such as `set password "[REDACTED]"`, becomes a marker line
        as in 1.0.6; anything unexpected hides the whole text.
        """
        if not isinstance(attributes, dict) or any(type(name) is not str for name in attributes):
            return marker
        lines = []
        for name, values in sorted(attributes.items()):
            parts = values if isinstance(values, list) else [values]
            if not all(type(part) is str for part in parts):
                return marker
            line = "set " + name + " " + " ".join(json.dumps(part, ensure_ascii=False) for part in parts)
            lines.append(marker if hidden(line) else line)
        text = "\n".join(lines)
        return marker if hidden(text) else text

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for index, (key, child) in enumerate(value.items()):
                # A secret in a key must not survive either. Avoid merging redacted keys.
                key_hidden = hidden(key)
                name = f"[REDACTED_FIELD_{index}]" if key_hidden else key
                if name in result:
                    raise ValueError("schema redaction produced ambiguous field names")
                result[name] = marker if key_hidden or sensitive_key(key) else walk(child)
            if "show" in value and "attributes" in value and result.get("attributes") != value["attributes"]:
                # Do not retain a second, textual copy of a structurally hidden attribute.
                result["show"] = show_text(result.get("attributes"))
            return result
        if isinstance(value, (list, tuple)):
            return [walk(child) for child in value]
        return marker if hidden(value) else value

    encoded = json.dumps(walk(report), ensure_ascii=False, separators=(",", ":"))
    # A known string can span JSON punctuation between leaves. Never let paging
    # turn that otherwise detectable occurrence into two invisible fragments.
    if any(form in encoded for form in forms):
        raise _pagination_refused(_SCHEMA_REDACTION_UNVERIFIED)
    # No form of a secret occurs in the document, so the response rules, which apply a
    # known secret only by substring, can only differ through an escape or a nested
    # document; without such a string the secret-free pass gives the same verdict.
    # The document is what the client receives: proxy and worker, in their order, until
    # they change nothing (a value under a sensitive key becomes their marker). They see
    # the whole document as JSON and a page of it as text; a printable trailing marker
    # keeps the whole document from parsing without being removed by terminal sanitization.
    final = secrets if risky else ()

    def as_text(document: str) -> str | None:
        cleaned = product_redact(sanitize_object(document + "#", final), final)[0]
        return cleaned[:-1] if cleaned.endswith("#") else None

    for _ in range(_RESPONSE_ROUNDS):
        cleaned = as_text(product_redact(sanitize_object(encoded, final), final)[0])
        if cleaned is None:
            break
        if cleaned == encoded:
            if json_object(encoded) is None:
                break
            return encoded
        encoded = cleaned
    raise _pagination_refused(_SCHEMA_REDACTION_UNVERIFIED)


# A page of the schema document that is not the last ends after a comma between JSON members or
# elements, so the next page starts at a key or a value. Try at most this many such ends.
SCHEMA_PAGE_CUT_TRIES = 16
_JSON_STRING_OR_COMMA = re.compile(r'"(?:[^"\\]|\\.)*"|"|,')


def _schema_page(text: str, offset: int, max_bytes: int, auth: TargetAuth) -> dict[str, Any]:
    """A page of the schema document that the response layers of proxy and worker leave unchanged.

    They judge a page as text and a whole document as JSON; the document is stable as text, so a
    whole document that they would change as JSON goes in more than one page. A page that is not
    the last ends after the last comma outside a string before the first byte the layers would
    change, so neither this page ends nor the next one starts inside a key, a value or a marker.
    The document and its hash stay independent of max_bytes. The worker remains the final guard
    if no stable page fits (including an arbitrary caller offset).
    """
    from netops.redaction import redact as product_redact
    from .proxy_sanitize import sanitize_object

    secrets = auth.redaction_secrets

    def cleaned(fragment: str) -> str:
        return product_redact(sanitize_object(fragment, secrets), secrets)[0]

    page = _page_text(text, offset, max_bytes)
    fragment = page["untrusted_device_output"]
    whole = offset == 0 and page["complete"]
    if page["complete"] and not whole:
        return page
    result = cleaned(fragment)
    if whole and result == fragment:
        return page
    limit = len(os.path.commonprefix((result, fragment)))
    commas = []
    for match in _JSON_STRING_OR_COMMA.finditer(fragment):
        if match.end() > limit or match.group() == '"':
            break  # past the first change, or a string that continues on the next page
        if match.group() == ",":
            commas.append(match.end())
    for end in reversed(commas[-SCHEMA_PAGE_CUT_TRIES:]):
        shorter = fragment[:end]
        if cleaned(shorter) == shorter:
            stop = offset + len(shorter.encode("utf-8"))
            return {**page, "returned_bytes": stop - offset, "next_offset": stop,
                    "complete": False, "untrusted_device_output": shorter}
    return page


INVALID_AUDIT_VALUE = "<invalid>"


def _audit_fields(arguments: dict[str, Any], result: dict[str, Any],
                  ssh_platform: str | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    endpoint = arguments.get("endpoint")
    if isinstance(endpoint, str):
        from .wifi_rest import PATHS, WIRELESS_LOG, _log_mac
        if endpoint in PATHS:
            fields.update(channel="https", request="GET " + endpoint)
        elif _log_mac(endpoint) is not None:
            fields.update(channel="https", request="GET " + WIRELESS_LOG)
    for name in ("port", "count", "offset", "max_bytes", "timeout"):
        value = arguments.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            fields[name] = value
    for name in ("use_tls", "acknowledge_unencrypted"):
        value = arguments.get(name)
        if isinstance(value, bool):
            fields[name if name != "acknowledge_unencrypted" else "plaintext_acknowledged"] = value
    if isinstance(arguments.get("oids"), list):
        fields["item_count"] = len(arguments["oids"])
    platform: str | None = None
    if "platform" in arguments:
        try:
            platform = normalize_platform(arguments["platform"])
        except ValueError:
            fields["platform"] = INVALID_AUDIT_VALUE
        else:
            fields["platform"] = platform
    if "query" in arguments:
        query = arguments["query"]
        valid = platform is not None and isinstance(query, str) and query in READ_QUERIES[platform]
        fields["query"] = query if valid else INVALID_AUDIT_VALUE
    if "recipe" in arguments:
        value = arguments["recipe"]
        valid = isinstance(value, str) and (
            value in {"ping","traceroute","sniffer","sessions","flow","nslookup","http_probe","health_check_verify","logs"}
            or (ssh_platform == "fortiadc" and value in {"system_event_logs", "waf_attack_logs",
                                                         "session_list", "persistence_list"})
        )
        fields["recipe"] = value if valid else INVALID_AUDIT_VALUE
    for name in ("address", "source_address"):
        value = arguments.get(name)
        if isinstance(value, str):
            try:
                parsed = ipaddress.IPv4Network(value) if "/" in value else ipaddress.IPv4Address(value)
            except ValueError:
                continue
            ends = (parsed.network_address, parsed.broadcast_address) if "/" in value else (parsed,)
            if str(parsed) == value and not any(
                    end.is_multicast or end.is_unspecified or int(end) == 4294967295 for end in ends):
                fields["destination_address" if name == "address" else "source_address"] = value
    for name in ("source_port", "destination_port"):
        value = arguments.get(name)
        if type(value) is int and 0 <= value <= 65535:
            fields[name] = value
    value = arguments.get("protocol")
    if type(value) is int and value in (6,17):
        fields["protocol"] = value
    for name in ("src", "dst"):
        value = arguments.get(name)
        if isinstance(value, str):
            try:
                parsed = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if str(parsed) == value:
                fields["source_address" if name == "src" else "destination_address"] = value
    if arguments.get("proto") in ("tcp", "udp", "icmp"):
        fields["protocol"] = {"tcp": 6, "udp": 17, "icmp": 1}[arguments["proto"]]
    for name in ("since", "until"):
        if name in arguments:
            value = arguments[name]
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S") if isinstance(value, str) else None
            except ValueError:
                parsed = None
            fields[name] = (value if parsed is not None and
                            parsed.strftime("%Y-%m-%d %H:%M:%S") == value else INVALID_AUDIT_VALUE)
    if isinstance(result.get("error_code"), str) and result["error_code"] in _TRANSPORT_ERROR_CODES:
        fields["detail"] = result["error_code"]
    if result.get("deadline_reached") is True:
        fields["detail"] = "deadline_reached"
    path = arguments.get("remote_path",arguments.get("path"))
    if isinstance(path, str):
        fields["path_sha256"] = digest_text(path)
    for name in (
        "query", "platform", "total_bytes", "returned_bytes", "pagination_source",
        "transport", "rc", "virtual_server",
    ):
        value = result.get(name)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            fields[name] = value
    for name in ("content_sha256",):
        value = result.get(name)
        if isinstance(value, str):
            fields["result_sha256"] = value
            break
    return fields


def _named_snapshot(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _missing_continuation(
    event: str, auth: TargetAuth, arguments: dict[str, Any],
) -> str | None:
    continuation = _CONTINUATIONS.get(event)
    offset = arguments.get("offset")
    if continuation is None or type(offset) is not int or offset <= 0:
        return None
    key_of, message, unnamed = continuation
    snapshot = arguments.get("content_sha256")
    if not _named_snapshot(snapshot):
        return unnamed
    try:
        _validate_pagination(offset, arguments.get("max_bytes"))
        key = (*key_of(auth, arguments), snapshot)
    except Exception:
        return None
    return message if _load_continuation(key, auth) is None else None


def _audit_device_call(function: Any) -> Any:
    signature = inspect.signature(function)
    event = function.__name__

    def preflight(auth: TargetAuth, arguments: dict[str, Any]) -> str:
        try:
            operation_id = f"op_{secrets.token_hex(16)}"
            fields = _audit_fields(arguments, {}, auth.ssh_platform)
            if auth.legacy_ssh is not None:
                fields["legacy_ssh"] = auth.legacy_ssh
            record(
                event, operation_id=operation_id, device=auth.alias, status="started",
                **fields,
            )
        except Exception as exc:
            raise AuditPreflightError(
                "mandatory audit preflight failed; device operation was not started"
            ) from exc
        return operation_id

    def complete(
        auth: TargetAuth,
        arguments: dict[str, Any],
        status: str,
        operation_id: str,
        result: dict[str, Any] | None = None,
        detail: str | None = None,
    ) -> None:
        fields = _audit_fields(arguments, result or {}, auth.ssh_platform)
        if auth.legacy_ssh is not None:
            fields["legacy_ssh"] = auth.legacy_ssh
        if detail is not None:
            fields["detail"] = detail
        try:
            record(
                event, operation_id=operation_id, device=auth.alias,
                status=status, **fields,
            )
        except Exception as exc:
            raise AuditPostOperationError(
                "mandatory audit completion failed after the operation started"
            ) from exc

    if inspect.iscoroutinefunction(function):
        @wraps(function)
        async def async_wrapper(auth: TargetAuth, *args: Any, **kwargs: Any) -> dict[str, Any]:
            bound = signature.bind(auth, *args, **kwargs)
            arguments = dict(bound.arguments)
            missing = _missing_continuation(event, auth, arguments)
            if missing is not None:
                raise _pagination_refused(missing)
            operation_id = preflight(auth, arguments)
            try:
                result = await function(auth, *args, **kwargs)
            except Exception as exc:
                complete(
                    auth, arguments, "failed", operation_id,
                    detail=_transport_cause(exc) or type(exc).__name__,
                )
                raise
            complete(
                auth, arguments, "ok" if result.get("ok") is True else "failed",
                operation_id, result,
            )
            return result
        return async_wrapper

    @wraps(function)
    def wrapper(auth: TargetAuth, *args: Any, **kwargs: Any) -> dict[str, Any]:
        bound = signature.bind(auth, *args, **kwargs)
        arguments = dict(bound.arguments)
        missing = _missing_continuation(event, auth, arguments)
        if missing is not None:
            raise _pagination_refused(missing)
        operation_id = preflight(auth, arguments)
        try:
            result = function(auth, *args, **kwargs)
        except Exception as exc:
            complete(
                auth, arguments, "failed", operation_id,
                detail=_transport_cause(exc) or type(exc).__name__,
            )
            raise
        complete(
            auth, arguments, "ok" if result.get("ok") is True else "failed",
            operation_id, result,
        )
        return result
    return wrapper


def _ssh_cache_key(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
) -> tuple[Any, ...]:
    return (
        auth.alias, auth.host, auth.port, auth.login,
        hashlib.sha256(auth.secret.encode("utf-8", "replace")).hexdigest(),
        platform, query, tuple(sorted((parameters or {}).items())),
    )


def _load_cached_ssh_record(key: tuple[Any, ...]) -> tuple[int | None, str, frozenset[str]] | None:
    now = time.monotonic()
    with _SSH_CACHE_LOCK:
        for candidate, entry in list(_SSH_PAGE_CACHE.items()):
            if entry[0] <= now:
                _SSH_PAGE_CACHE.pop(candidate, None)
        cached = _SSH_PAGE_CACHE.get(key)
        return cached[1:4] if cached else None


def _load_cached_ssh_output(key: tuple[Any, ...]) -> tuple[int | None, str] | None:
    record = _load_cached_ssh_record(key)
    return None if record is None else record[:2]


def _store_cached_ssh_output(
    key: tuple[Any, ...], rc: int | None, output: str, redacted_with: Iterable[str] = (),
    normalized: dict | None = None, line_limit: dict | None = None,
) -> None:
    """Store a redacted result with the secret set it was redacted with."""
    with _SSH_CACHE_LOCK:
        if len(_SSH_PAGE_CACHE) >= _SSH_CACHE_MAX_ENTRIES:
            oldest = min(_SSH_PAGE_CACHE, key=lambda item: _SSH_PAGE_CACHE[item][0])
            _SSH_PAGE_CACHE.pop(oldest, None)
        _SSH_PAGE_CACHE[key] = (
            time.monotonic() + _SSH_CACHE_TTL_SECONDS, rc, output, frozenset(redacted_with), normalized, line_limit,
        )


def _load_continuation(key: tuple[Any, ...], auth: TargetAuth) -> tuple[int | None, str] | None:
    """The stored result of a paged read, if the current secrets leave its text as it is.

    The stored text was redacted with the secrets known at the first page; later calls of the
    session can know more (another target was used). The text is still served, with its hash,
    when the added secrets neither occur in it nor are changed by the response rules, which
    apply a known secret only as a substring. Otherwise the result counts as expired.
    """
    record = _load_cached_ssh_record(key)
    if record is None:
        return None
    rc, text, stored = record
    added = tuple(secret for secret in auth.redaction_secrets if secret not in stored)
    if added:
        from netops.redaction import redact as product_redact
        from .proxy_sanitize import sanitize_object

        if product_redact(sanitize_object(text, added), added)[0] != text:
            return None
        with _SSH_CACHE_LOCK:
            entry = _SSH_PAGE_CACHE.get(key)
            if entry is not None and entry[1:3] == (rc, text):
                _SSH_PAGE_CACHE[key] = (*entry[:3], entry[3] | frozenset(added), *entry[4:])
    return rc, text


def _ssh_read_state(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
    inventory: Any = None,
) -> tuple[str, str, tuple[Any, ...]]:
    normalized = auth.require_ssh_query(platform, query)
    inventory = _read_inventory(auth) if inventory is None else inventory
    if is_read_sequence(normalized, query):
        normalized, commands, _ = render_read_sequence(normalized, query, parameters, inventory)
        return normalized, "\n".join(commands), _ssh_cache_key(auth, normalized, query, parameters)
    normalized, command = render_read_query(normalized, query, parameters, inventory)
    return normalized, command, _ssh_cache_key(auth, normalized, query, parameters)


def _wifi_payload(auth: TargetAuth, query: str, text: str, mac_filter: dict[str, Any] | None,
                  mac_literal: str | None) -> dict[str, Any]:
    parsed = wifi_parse.summarize(query, text)
    if query == "wifi_ap_status":
        _remember_wtp_ids(auth, [item["serial"] for item in parsed["records"]])
    if mac_literal:
        parsed["mac_filter"] = mac_filter or {"mac_literal": mac_literal, "scanned_lines": None, "matched": None,
                                              "note": "continuation page of an already filtered snapshot"}
    return {"wifi": parsed}


def _limit_log_lines(text: str, oldest_first: bool = False) -> tuple[str, dict[str, Any]]:
    """At most `_LOG_MAX_LINES` newest lines of a log listing: the leading ones when the newest message comes first
    (cut at a message boundary), the trailing ones when the oldest comes first (one line per message)."""
    lines = text.splitlines()
    limit = {"max_lines": _LOG_MAX_LINES, "total_lines": len(lines), "returned_lines": len(lines), "truncated": False}
    if len(lines) <= _LOG_MAX_LINES:
        return text, limit
    if oldest_first:
        limit.update(returned_lines=_LOG_MAX_LINES, truncated=True)
        note = f"[netops-helper: log output limited to the last {_LOG_MAX_LINES} of {len(lines)} lines]"
        return note + "\n" + "\n".join(lines[-_LOG_MAX_LINES:]) + "\n", limit
    keep = _LOG_MAX_LINES
    while keep > 0 and not _LOG_MESSAGE_START.match(lines[keep]):
        keep -= 1
    keep = keep or _LOG_MAX_LINES
    limit.update(returned_lines=keep, truncated=True)
    note = f"[netops-helper: log output limited to the first {keep} of {len(lines)} lines]"
    return "\n".join(lines[:keep]) + "\n" + note + "\n", limit


def _ssh_read(
    auth: TargetAuth,
    platform: str,
    query: str,
    parameters: dict[str, str] | None,
    offset: int,
    max_bytes: int,
    content_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(platform, str) or not isinstance(query, str):
        raise ValueError("platform and query must be strings")
    offset, max_bytes = _validate_pagination(offset, max_bytes)
    normalized, command, cache_key = _ssh_read_state(auth, platform, query, parameters)
    entry = READ_QUERIES[normalized].get(query)
    sequence = is_read_sequence(normalized, query)
    prompt = entry is not None and entry.pty
    transport = _TRANSPORT_PTY if prompt or sequence else _SSH_TRANSPORTS[normalized]
    output_filter: dict[str, str] = {}
    if sequence:
        _, commands, output_filter = render_read_sequence(normalized, query, parameters, _read_inventory(auth))
    pagination_source = "fresh"
    identity_response = None
    line_limit = None
    if offset:
        if not _named_snapshot(content_sha256):
            raise _pagination_refused(_SSH_SNAPSHOT_UNNAMED)
        cached = _load_continuation((*cache_key, content_sha256), auth)
        if cached is None:
            raise _pagination_refused(_SSH_SNAPSHOT_EXPIRED)
        rc, cleaned = cached
        with _SSH_CACHE_LOCK:
            capture = _SSH_PAGE_CACHE.get((*cache_key, content_sha256))
            identity_response = capture[4] if capture and len(capture) > 4 else None
            line_limit = capture[5] if capture and len(capture) > 5 else None
        pagination_source = "cached"
    else:
        try:
            rc, output = (_verified_sequence(auth, normalized, commands) if sequence
                          else _verified_read(auth, normalized, command, prompt))
        except _ProductIdentityError as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": exc.rc,
                "error_code": "product_identity", "error": str(exc),
                **({"reason": exc.reason} if normalized in normalization.IDENTITY_PROFILES else {}),
            }
        except Exception as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, **_read_failure(exc, auth),
                **({"status": _transport_status(exc)} if normalized in normalization.IDENTITY_PROFILES else {}),
            }
        cleaned = _redact_output(output, auth)
        if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc,
                "error": "SSH output exceeds the 2000000-byte safety cap",
            }
        cleaned = _fortiswitch_configuration_output(normalized, query, parameters, cleaned)
        if normalized == "extreme_exos" and query in _EXOS_LOG_QUERIES:
            cleaned, line_limit = _limit_log_lines(cleaned)
        elif normalized in _OLDEST_FIRST_LOG_PROFILES and query in _OLDEST_FIRST_LOG_QUERIES:
            if normalized.startswith("juniper_junos"):
                cleaned = _JUNOS_LAST_PAGER_MARK.sub("", cleaned)
            cleaned, line_limit = _limit_log_lines(cleaned, oldest_first=True)
    empty_output = not cleaned.strip()
    mac_filter = None
    refused = (_cli_refused(normalized, cleaned) if sequence
               else _cli_refused(normalized, cleaned, command=command))
    if output_filter.get("mac_literal") and not offset and not empty_output and not refused:
        cleaned, mac_filter = wifi_parse.filter_events_by_mac(cleaned, output_filter["mac_literal"])
    cache_key = (*cache_key, hashlib.sha256(cleaned.encode("utf-8")).hexdigest())
    lookup_route_failed = (
        normalized == "fortinet" and query in {"policy_lookup_ipv4", "policy_lookup_ipv6"}
        and re.search(r"(?m)^[ \t]*Error code: err_route[ \t]*\r?$", cleaned) is not None
    )
    mclag = normalized == "fortinet" and query in MCLAG_QUERIES
    wifi_permission_denied = (
        normalized == "fortinet" and entry is not None
        and entry.requires_device_permission == "wifi read-write"
        and re.search(r"(?m)^[ \t]*command parse error before 'wireless-controller'[ \t]*\r?$", cleaned, re.I) is not None
        and re.search(r"(?m)^[ \t]*Command fail\. Return code -61[ \t]*\r?$", cleaned, re.I) is not None
    )
    exos_250_error = normalized == "extreme_exos" and rc == 250 and bool(cleaned.strip()) and not normalization.exos_exit_250(normalized, rc, cleaned, command=command)
    if exos_250_error or (refused and not (mclag and mclag_not_supported(query, cleaned))) or lookup_route_failed:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "permission_denied" if wifi_permission_denied else "device_cli_error",
            "error": ("Wi-Fi diagnostics need an admin-bounded account with wifi read-write and cli-diagnose; or remove wifi_* from the target's enabled_queries" if wifi_permission_denied else
                      "Policy lookup could not resolve a route for the supplied flow" if lookup_route_failed else
                      "The device CLI refused the command; check its supported features and account permissions"),
            "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
        }
    if empty_output and not (entry is not None and entry.empty_allowed):
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "empty",
            "error": "The device returned no output for this query; no result was read",
        }
    if not offset and normalized in normalization.IDENTITY_PROFILES and query == "version":
        identity_response = _normalized_identity(auth, normalized, rc, cleaned)
    page = _page_text(cleaned, offset, max_bytes, whole_lines=True)
    if page["next_offset"] is not None:
        if offset == 0:
            _store_cached_ssh_output(cache_key, rc, cleaned, auth.redaction_secrets, identity_response, line_limit)
    else:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
    return {
        "ok": True, "target": auth.alias, "platform": normalized, "query": query,
        "transport": transport, "rc": rc,
        "pagination_source": pagination_source, **page,
        **({"line_limit": line_limit} if line_limit else {}),
        **({"normalized": identity_response} if identity_response is not None else {}),
        **({"_warnings": (["exit_status_250"] if normalization.exos_exit_250(normalized, rc, cleaned, command=command) else [])
                          + (["log_line_limit"] if line_limit and line_limit["truncated"] else [])}
           if normalization.exos_exit_250(normalized, rc, cleaned, command=command) or (line_limit and line_limit["truncated"]) else {}),
        **({"_capture_state": normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)}
           if normalized in normalization.IDENTITY_PROFILES else {}),
        **({"mclag": mclag_summarize(query, cleaned, parameters)} if mclag else {}),
        **({"dhcp_bindings": dhcp_bindings_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == DHCP_BINDINGS_QUERY else {}),
        **(_wifi_payload(auth, query, cleaned, mac_filter, output_filter.get("mac_literal"))
           if normalized == "fortinet" and query in wifi_parse.PARSERS else {}),
    }


def _normalized_identity(auth, profile, rc, output):
    command = READ_QUERIES[profile]["version"].command
    warnings = ["exit_status_250"] if normalization.exos_exit_250(profile, rc, output, command=command) else []
    sources = [normalization.source_record("version", output, normalization.output_status(output, rc=rc, profile=profile, command=command))]
    try:
        record = normalization.parse_identity(profile, output, warnings)
    except normalization.IdentityError as exc:
        return normalization.response_envelope(profile, "unparsed", sources, warnings=[exc.reason])
    for query in normalization.identity_supplements(profile):
        if query not in auth.enabled_queries:
            # Only queries the operator enabled for this target are ever run.
            warnings.append("identity_source_" + query + "_not_enabled")
            continue
        try:
            code, raw = read_from_device(auth, profile, READ_QUERIES[profile][query].command)
            clean = _redact_output(raw, auth)
            source_state = normalization.output_status(clean, rc=code, truncated=len(clean.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES, profile=profile, command=READ_QUERIES[profile][query].command)
            sources.append(normalization.source_record(query, clean, source_state))
            if source_state == "ok":
                normalization.supplement_identity(record, query, clean)
            else:
                warnings.append("identity_source_" + query + "_" + source_state)
        except normalization.IdentityError:
            warnings.append("identity_source_" + query + "_ambiguous")
        except Exception as exc:
            source_state = _transport_status(exc)
            sources.append(normalization.source_record(query, "", source_state))
            warnings.append("identity_source_" + query + "_" + source_state)
    missing = [field for field in normalization.IDENTITY_FIELDS if record[field] is None]
    warnings.extend("identity_missing_" + field for field in missing)
    # A failed supplement is reported in sources[].status and warnings; it never
    # overwrites the state of the successful version read.
    return normalization.response_envelope(profile, "unparsed" if missing else "ok", sources, identity=record, warnings=warnings)


# Only these constants and their fixed advice may leave the transport diagnostic boundary.
_TRANSPORT_ADVICE = {
    "timeout": "The target did not answer in time (no connection, or no complete answer before the deadline); "
               "check that it is up and reachable from the Helper (routing, firewall, SSH port) before changing "
               "the account or the pinned host key",
    "unreachable": "The target is not reachable from the Helper (no route, or the host is down); check its power, "
                   "address and routing before changing the account or the pinned host key",
    "dns": "The enrolled target name did not resolve; check the host name and the Helper DNS",
    "connection_refused": "The target is reachable but refused the SSH connection; check that SSH is enabled on the "
                          "enrolled port and that administrative access from the Helper is allowed (trusted hosts)",
    "host_key_unavailable": "The target answered but no SSH host key could be read; check its SSH service and key "
                            "negotiation (legacy_ssh) before changing the pinned host key",
    "host_key_mismatch": "The target offered an SSH host key that does not match the enrolled pin; verify the "
                         "device key out of band and re-enroll the pin only for an expected key change",
    "negotiation": "The Helper and the target share no SSH algorithm; set legacy_ssh for this device only if its "
                   "algorithms are intended",
    "auth": "The target refused the login (the host key was verified); check the enrolled account, its password "
            "and a possible lockout",
    "auth_method_unsupported": "The target asked for a second factor or another login prompt that the Helper does "
                               "not answer (the host key was verified); enroll an account that logs in with its "
                               "password alone",
    "disconnected": "The target closed the SSH connection; check its session limits and administrative access, "
                    "then retry",
    "output_limit": "The output exceeded the transport limit; narrow the request",
    "exit_status": "The SSH command ended with a failure exit status; no output was used",
    "transport_failure": "The SSH transport failed for an unclassified reason; check reachability and SSH access "
                         "to the target",
}
_TRANSPORT_ERROR_CODES = frozenset(_TRANSPORT_ADVICE)
# First match wins: an SSH client message or a fixed transport message, never returned itself.
_TRANSPORT_MARKERS = (
    ("host_key_mismatch", ("remote host identification has changed", "host key verification failed",
                           "host key is not the pinned", "did not offer the pinned")),
    ("output_limit", ("produced more than", "output limit exceeded")),
    ("auth_method_unsupported", ("unsupported non-password authentication", "ssh_auth_method_unsupported")),
    ("auth", ("permission denied", "authentication failed", "refused the credential", "too many authentication failures")),
    ("connection_refused", ("connection refused", "refused the connection")),
    # glibc and musl word these differently ("Network is unreachable", "Network unreachable").
    ("unreachable", ("no route to host", "network is unreachable", "network unreachable", "host is unreachable",
                     "host unreachable", "not reachable")),
    ("dns", ("could not resolve hostname", "name did not resolve", "name or service not known",
             "temporary failure in name resolution")),
    ("timeout", ("timed out", "timeout", "did not finish within", "did not answer")),
    ("negotiation", ("no matching", "share no algorithm", "unable to negotiate")),
    ("disconnected", ("connection reset", "connection closed", "closed by remote host", "closed the connection",
                      "broken pipe", "ended before", "end of file", "eof")),
)
# A host that answered the probe but gave no key is host_key_unavailable; these causes come first.
_UNANSWERED_CAUSES = frozenset({"timeout", "unreachable", "dns", "connection_refused", "negotiation", "disconnected"})
_TRANSPORT_EXCEPTIONS = (core_ssh.SshError, core_session.SessionError, core_hostkey.HostKeyError, ConnectionError,
                         TimeoutError, socket.gaierror, socket.herror, EOFError, subprocess.TimeoutExpired,
                         LegacySshProfileRequired)
_UNREACHABLE_ERRNOS = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN})


def _marked_cause(text, latest=False):
    """The class of a fixed message by marker order, or with latest the class named last in client text.

    A device's pre-login banner precedes the client's own failure message, so in client text the last
    marker decides and banner words cannot steer the class.
    """
    text = str(text).lower()
    found = None
    for code, markers in _TRANSPORT_MARKERS:
        position = max(text.rfind(marker) for marker in markers)
        if position >= 0 and not latest:
            return code
        if position >= 0 and (found is None or position > found[0]):
            found = (position, code)
    return found[1] if found else None


def _exception_chain(exc):
    chain, seen = [], set()
    while exc is not None and id(exc) not in seen and len(chain) < 8:
        chain.append(exc)
        seen.add(id(exc))
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
    return chain


def _classified(error, code):
    error.transport_error_code = code
    return error


def _client_verdict(error):
    """The class named by the client's closing message (final), else by the last marker of its text (said).

    A device's pre-login banner is printed before the client's own failure message, so no banner word
    can decide the class; a message built from said would repeat it, so callers never classify that.
    """
    final = getattr(error, "final", "") or ""
    if final:
        return _marked_cause(final)
    return _marked_cause(getattr(error, "said", "") or "", latest=True)


def _typed_cause(error):
    """The class an exception's type or errno proves; None when only its text could tell."""
    if isinstance(error, core_ssh.OutputLimitError):
        return "output_limit"
    if isinstance(error, core_hostkey.HostKeyUnavailable):
        return "host_key_unavailable"
    if isinstance(error, core_hostkey.HostKeyError):
        return "host_key_mismatch"
    # Every resolver failure (EAI_NONAME, EAI_NODATA, EAI_FAIL, EAI_AGAIN, ...); its EAI number is no errno.
    if isinstance(error, (socket.gaierror, socket.herror)):
        return "dns"
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError)):
        return "disconnected"
    if isinstance(error, OSError) and error.errno in _UNREACHABLE_ERRNOS:
        return "unreachable"
    return None


def _transport_error_code(exc):
    """Classify local transport exceptions by their real cause; never return exception/device text.

    A class set by the engine or proven by type wins over any text; then the client's verdict; message
    text last, and never one that repeats what the client printed.
    """
    chain = _exception_chain(exc)
    for index, error in enumerate(chain):
        code = getattr(error, "transport_error_code", None)
        if code in _TRANSPORT_ERROR_CODES:
            return code
        if isinstance(error, LegacySshProfileRequired):
            # The wrapper only restates a refused negotiation; a verified cause beneath it decides.
            return next(filter(None, map(_client_verdict, chain[index + 1:])), "negotiation")
        code = _typed_cause(error)
        if code is not None:
            return code
    for error in chain:
        code = _client_verdict(error)
        if code is not None:
            return code
    for error in chain:
        if not getattr(error, "said", ""):
            code = _marked_cause(type(error).__name__ + " " + str(error))
            if code is not None:
                return code
    return "transport_failure"


def _transport_cause(exc):
    """The transport class of a failure that came from the SSH transport, else None (a local refusal)."""
    for error in _exception_chain(exc):
        if (getattr(error, "transport_error_code", None) in _TRANSPORT_ERROR_CODES
                or isinstance(error, _TRANSPORT_EXCEPTIONS)
                or (isinstance(error, OSError) and error.errno in _UNREACHABLE_ERRNOS)):
            return _transport_error_code(exc)
    return None


def _transport_failure(code):
    return {"error_code": code, "error": _TRANSPORT_ADVICE[code]}


def _read_failure(exc, auth):
    """A transport failure as its class and advice; a local refusal keeps ssh_unavailable and its own text."""
    code = _transport_cause(exc)
    if code is None:
        return {"error_code": "ssh_unavailable", "error": _safe_error(exc, auth)}
    return _transport_failure(code)


def _transport_status(exc):
    code = _transport_error_code(exc)
    return "truncated" if code == "output_limit" else "timeout" if code == "timeout" else "transport_error"


def _transport_result(profile, table, query, exc):
    from . import tables
    code = _transport_error_code(exc)
    status = 'truncated' if code == 'output_limit' else 'timeout' if code == 'timeout' else 'transport_error'
    result = tables.parse(profile, table, query, '', status=status)
    result.update(_transport_failure(code))
    return result


@_audit_device_call
def ssh_read(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
    offset: int, max_bytes: int, content_sha256: str | None = None,
) -> dict[str, Any]:
    result = _ssh_read(auth, platform, query, parameters, offset, max_bytes, content_sha256)
    capture_state = result.pop("_capture_state", None)
    exit_warnings = result.pop("_warnings", [])
    if result["platform"] not in normalization.IDENTITY_PROFILES:
        return result
    if "normalized" not in result:
        body = result.get("untrusted_device_output", "")
        if result.get("status") in normalization.RESULT_STATES:
            state = result["status"]
        elif result.get("reason", "").startswith("identity_"):
            reason = result["reason"].removeprefix("identity_")
            state = reason if reason in normalization.RESULT_STATES else "unparsed"
        elif "error_code" not in result and not result["ok"]:
            state = "timeout" if "timed out" in result.get("error", "").lower() or "timeout" in result.get("error", "").lower() else "truncated" if "safety cap" in result.get("error", "") else "transport_error"
        else:
            # The state describes the whole capture, not the returned page.
            state = capture_state or normalization.output_status(body, rc=result.get("rc"), profile=result["platform"],
                                                                  command=READ_QUERIES[result["platform"]][query].command.format_map(parameters or {}))
            if result.get("error_code") == "empty":
                state = "empty"
            elif not result["ok"] and state == "ok":
                state = "unparsed"
            elif result["ok"] and state == "ok":
                state = "unparsed"  # Raw catalogue output has no structured adapter yet.
        result["normalized"] = normalization.response_envelope(
            result["platform"], state,
            [normalization.source_record(query, body, state)] if body else [],
            warnings=([result["reason"]] if result.get("reason") else []) + exit_warnings,
            identity_coverage=query == "version",
        )
    elif exit_warnings:
        result["normalized"]["warnings"].extend(exit_warnings)
    if result.get("content_sha256") and result["normalized"]["identity"] is None and result["normalized"]["sources"]:
        result["normalized"]["sources"][0]["content_sha256"] = result["content_sha256"]
    result["status"] = result["normalized"]["status"]
    return result


class _FortiosDiagnosticShell:
    def __init__(self, session, platform="fortinet", answer_refusal_raises=True):
        self.session = session
        self.platform = platform
        self.answer_refusal_raises = answer_refusal_raises
        _, login = session.expect([b"# ", b"$ "], 15)
        marker = login.splitlines()[-1]
        if not re.fullmatch(self._role() + rb"[A-Za-z0-9_.+-]+(?: \([A-Za-z0-9_.+-]+\)|\((?:Primary|Secondary)\))? [#$] ", marker):
            raise ValueError("the diagnostic session prompt cannot be verified")
        self.prompt = marker
        self.ready = True
        session.discard(login)

    def _role(self):
        return rb"(?:\((?:P|S|M|I)\) )?" if self.platform == "fortiadc" else b""

    def _answer(self, command, timeout):
        _, raw = self.session.expect([self.prompt], timeout)
        self.ready = True
        text = _pty_body(raw, command, self.prompt)
        if self.answer_refusal_raises and _cli_refused(self.platform, text):
            from .fortios_diagnostics import StepRefused
            raise StepRefused(text)
        return text

    def command(self, command, timeout=10):
        self.ready = False
        self.session.send(command)
        return self._answer(command, timeout)

    def navigate(self, command):
        self.session.send(command)
        _, raw = self.session.expect([b"# ", b"$ "], 10)
        marker = raw.splitlines()[-1]
        if not re.fullmatch(self._role() + rb"[A-Za-z0-9_.+-]+(?: \([A-Za-z0-9_.+-]+\))? [#$] ", marker):
            raise ValueError("the diagnostic context prompt cannot be verified")
        text = _pty_body(raw, command, marker)
        if _cli_refused(self.platform, text):
            raise ValueError("the device refused the diagnostic context")
        self.prompt = marker
        return text

    def listen(self, timeout):
        return self._answer("", timeout)

    def interrupt(self):
        self.ready = False
        self.session.interrupt()


def _diagnostic_transport_failure(auth, recipe, code, platform=None):
    """A diagnostic that could not reach or keep its SSH session: the class and fixed advice, no device text."""
    return {"ok": False, "target": auth.alias, **({"platform": platform} if platform else {}), "recipe": recipe,
            **_transport_failure(code)}


def _session_target(auth):
    """The resolved address of a diagnostic session, or the transport class when the name does not resolve."""
    try:
        return _resolve_target_ipv4(auth)[0], None
    except OSError as error:
        return None, _transport_error_code(error)


def _fortiadc_logs(auth, recipe, address, interface, count, timeout, max_bytes, vdom, since, until):
    from . import fortiadc_diagnostics as diagnostics
    if vdom is not None or since is not None or until is not None:
        raise ValueError(f"{recipe} does not accept VDOM or time-window parameters")
    diagnostics.validate(recipe, address, interface, count, timeout, max_bytes)
    diagnostics.authorize(auth, recipe, address)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        target_address, unresolved = _session_target(auth)
        if unresolved:
            return _diagnostic_transport_failure(auth, recipe, unresolved, platform="fortiadc")
        try:
            known_hosts = host_key_line(auth, target_address, "fortiadc")
            with _paced_connection(target_address, auth.port, "fortiadc"):
                with core_session.Session(
                    target_address, auth.port, auth.login, DeviceCredential(auth),
                    known_hosts, legacy_ssh=auth.legacy_ssh, timeout_seconds=30 + timeout,
                    capture_max_bytes=16384,
                ) as session:
                    @contextmanager
                    def reconnect():
                        session.close()
                        with core_session.Session(
                            target_address, auth.port, auth.login, DeviceCredential(auth),
                            known_hosts, legacy_ssh=auth.legacy_ssh, timeout_seconds=30 + timeout,
                            capture_max_bytes=16384,
                        ) as repair_session:
                            yield _FortiosDiagnosticShell(repair_session, "fortiadc", answer_refusal_raises=False)

                    shell = _FortiosDiagnosticShell(session, "fortiadc", answer_refusal_raises=False)
                    if recipe in diagnostics.STATE_RECIPES:
                        result = diagnostics.run_state_list(
                            shell, recipe, address, count, timeout, reconnect=reconnect,
                        )
                    else:
                        result = diagnostics.run(shell, count, timeout, recipe=recipe, reconnect=reconnect)
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError(f"bounded FortiADC {recipe} read failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")

    raw_text = result["raw_output"]
    text = redact(raw_text, auth.secrets)
    selected = redact(result["output"], auth.secrets)
    total = text.encode("utf-8")
    selected_bytes = selected.encode("utf-8")
    returned = selected_bytes[:max_bytes].decode("utf-8", "ignore")
    byte_truncated = returned != selected
    state = result["state"]
    if byte_truncated:
        state = "incomplete"
    cleanup = result["cleanup"]
    timed_out = result["timed_out"]
    complete = state == "data" and cleanup == "verified" and not timed_out and not byte_truncated
    if recipe in diagnostics.STATE_RECIPES:
        scope = "current {} table for this virtual server only; no global completeness".format(
            diagnostics.STATE_RECIPES[recipe])
    else:
        scope = "current {}/{} display batch only; no historical completeness".format(*diagnostics.RECIPES[recipe])
    answer = {
        "ok": complete,
        "target": auth.alias,
        "platform": "fortiadc",
        "recipe": recipe,
        "start_line": 0,
        "scope": scope,
        "identity": list(result["identity"]),
        "state": state,
        "cleanup": cleanup,
        "deadline_reached": timed_out,
        "complete": complete,
        "loaded_records": result["loaded_records"],
        "returned_records": result["returned_records"],
        "count_truncated": result["count_truncated"],
        "truncated": result["count_truncated"] or byte_truncated,
        "total_bytes": len(total),
        "returned_bytes": len(returned.encode("utf-8")),
        "line_count": len(text.splitlines()),
        "content_sha256": digest_text(text),
        "selected_sha256": digest_text(selected),
        "unrecognized_body": result["unrecognized_body"],
        "untrusted_device_output": returned,
    }
    if recipe in diagnostics.STATE_RECIPES:
        answer["virtual_server"] = result["virtual_server"]
        answer["header_only"] = result["header_only"]
    return answer


@_audit_device_call
def fortios_diagnostics(auth: TargetAuth, recipe: str, address: str, interface: str,
                        count: int = 3, timeout: int = 10, max_bytes: int = 16000, vdom: str | None = None,
                        health_check: str | None = None,
                        source_address: str | None = None, source_port: int | None = None,
                        destination_port: int | None = None, protocol: int | None = None,
                        since: str | None = None, until: str | None = None) -> dict[str, Any]:
    from . import fortios_diagnostics as diagnostics
    if auth.ssh_platform == "fortiadc":
        if any(value is not None for value in (source_address, source_port, destination_port, protocol)):
            raise ValueError("a TCP or UDP tuple applies only to a FortiOS target")
        if recipe in {"system_event_logs", "waf_attack_logs", "session_list", "persistence_list"}:
            if health_check is not None:
                raise ValueError("health_check applies only to the FortiADC health_check_verify diagnostic")
            return _fortiadc_logs(
                auth, recipe, address, interface, count, timeout, max_bytes, vdom, since, until,
            )
        diagnostics.log_window(recipe, since, until)
        return _fortiadc_diagnostics(auth, recipe, address, interface, count, timeout, max_bytes, vdom, health_check)
    if health_check is not None:
        raise ValueError("health_check applies only to a FortiADC target")
    diagnostics.validate(recipe, address, interface, count, timeout, max_bytes, vdom,
                         source_address=source_address, source_port=source_port,
                         destination_port=destination_port, protocol=protocol)
    window = diagnostics.log_window(recipe, since, until)
    diagnostics.authorize(auth, recipe, address, interface, vdom, source_address=source_address)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        target_address, unresolved = _session_target(auth)
        if unresolved:
            return _diagnostic_transport_failure(auth, recipe, unresolved)
        try:
            known_hosts = host_key_line(auth, target_address, "fortinet")
            with _paced_connection(target_address, auth.port, "fortinet"):
                with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                          known_hosts, legacy_ssh=auth.legacy_ssh,
                                          timeout_seconds=30, capture_max_bytes=131072) as session:
                    @contextmanager
                    def reconnect():
                        session.close()
                        with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                                  known_hosts, legacy_ssh=auth.legacy_ssh,
                                                  timeout_seconds=30, capture_max_bytes=131072) as repair:
                            yield _FortiosDiagnosticShell(repair)

                    shell = _FortiosDiagnosticShell(session)
                    raw, timed_out, identity, domain = diagnostics.run(
                        shell, recipe, address, interface, count, timeout, vdom, reconnect=reconnect,
                        source_address=source_address, source_port=source_port,
                        destination_port=destination_port, protocol=protocol, window=window)
        except Exception as error:
            if isinstance(error, (diagnostics.UnsupportedPlatform, diagnostics.ScopeRefused,
                                  diagnostics.OptionRefused)):
                raise
            if isinstance(error, diagnostics.RestoreUnverified):
                check = {"flow": "'diagnose debug info' and 'diagnose debug flow filter' on the device; if debug "
                                 "output is enabled or a filter is set, run 'diagnose debug disable', 'diagnose "
                                 "debug flow trace stop' and 'diagnose debug flow filter clear'",
                         "sessions": "'diagnose sys session filter' on the device; if a filter is set, run "
                                     "'diagnose sys session filter clear'",
                         "logs": "'execute log filter dump' on the device",
                         }.get(recipe, "'execute " + recipe + "-options view-settings' on the device")
                raise ValueError("bounded FortiOS diagnostic failed; the session was closed and the diagnostic "
                                 "state restoration could not be verified: check " + check) from None
            # A transport failure that escapes the recipe left no diagnostic state behind, or its
            # restoration was verified; otherwise RestoreUnverified above names the check.
            code = _transport_cause(error)
            if code is None:
                raise ValueError("bounded FortiOS diagnostic failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code)
    if recipe == "logs":
        text = redact(raw["output"], auth.secrets)
        page = text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
        return {"ok": raw["state"] in {"ok", "empty"}, "target": auth.alias, "recipe": recipe, "vdom": domain,
                "identity": identity, "deadline_reached": timed_out, "cleanup": "verified",
                "log_state": raw["state"],
                "filter_applied": {key: redact(value, auth.secrets) for key, value in raw["filter"].items()},
                "filter_source": "device current filter as read; not set by type, target or time",
                "coverage": "loaded batch only, current category only",
                "window": window, "found": raw["found"], "loaded": raw["loaded"], "matched": raw["matched"],
                "returned": raw["returned"], "time_range": raw["time_range"],
                "content_sha256": digest_text(text), "returned_bytes": len(page.encode("utf-8")),
                "truncated": raw["truncated"] or page != text,
                "untrusted_device_output": page}
    cleaned = redact(raw, auth.secrets)
    extra = {}
    omitted = False
    if recipe == "sessions":
        cleaned, complete, dropped = diagnostics.session_projection(cleaned, count)
        extra = {"complete": complete, "sessions_omitted": dropped}
        omitted = dropped > 0
    if recipe == "flow":
        selector = diagnostics.flow_filter(address, source_address, source_port, destination_port, protocol)
        packets, lines = diagnostics.flow_trace(cleaned)
        if packets:
            extra = {"trace_state": "captured",
                     "trace_summary": "the device traced " + str(packets) + " packet" + "s" * (packets > 1) +
                                      " (" + str(lines) + " trace line" + "s" * (lines > 1) + ") for the flow filter "
                                      + selector + " within the " + str(timeout) + " s window"}
        else:
            other = len(cleaned.encode("utf-8")) if cleaned.strip() else 0
            if source_address is None:
                start = "that ICMP to or from this address is sent while the call runs."
            else:
                start = ("that a new connection with exactly this tuple starts during the call: flow debug shows "
                         "only packets that the CPU processes, not those of a session offloaded to the network "
                         "processor, and a client usually opens a new connection from a new source port, so send "
                         "it from the filtered source port. ICMP is not offloaded, so a flow call without a tuple "
                         "for ICMP to this address can check the path.")
            extra = {"trace_state": "empty",
                     "trace_summary": "no packet was traced for the flow filter " + selector + " during the "
                                      + str(timeout) + " s window"
                                      + ("; the device returned " + str(other) + " bytes without a packet trace "
                                         "line" if other else "") + ". "
                                      "An empty trace shows neither that the traffic passes nor that it is blocked. "
                                      "Check that the filter matches the real connection (addresses, ports, "
                                      "protocol), that this traffic passes through this FortiGate while the call "
                                      "runs, and " + start}
    data = cleaned.encode("utf-8")
    returned = cleaned.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
    return {"ok": True, "target": auth.alias, "recipe": recipe, "vdom": domain,
            "content_sha256": digest_text(cleaned),
            "identity": identity, "deadline_reached": timed_out,
            "cleanup": "verified", "total_bytes": len(data), "returned_bytes": len(returned.encode("utf-8")),
            "truncated": omitted or returned != cleaned, **extra,
            "untrusted_device_output": returned}


def _fortiadc_diagnostics(auth, recipe, address, interface, count, timeout, max_bytes, vdom, health_check):
    from . import configuration, fortios_diagnostics as diagnostics
    diagnostics.adc_validate(recipe, address, interface, count, timeout, max_bytes, vdom, health_check)
    diagnostics.adc_authorize(auth, recipe, address, health_check)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        target_address, unresolved = _session_target(auth)
        if unresolved:
            return _diagnostic_transport_failure(auth, recipe, unresolved, platform="fortiadc")
        try:
            known_hosts = host_key_line(auth, target_address, "fortiadc")
            with _paced_connection(target_address, auth.port, "fortiadc"):
                with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                          known_hosts, legacy_ssh=auth.legacy_ssh,
                                          timeout_seconds=30 + timeout, capture_max_bytes=131072) as session:
                    shell = _FortiosDiagnosticShell(session, "fortiadc")
                    raw, timed_out, identity = diagnostics.adc_run(shell, recipe, address, timeout, count, health_check)
        except configuration.UnsupportedConfigurationFirmware as error:
            raise diagnostics.UnsupportedPlatform("config_platform_not_supported: FortiADC " +
                                                  " build ".join(error.detected) + " is not measured") from None
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError("bounded FortiADC diagnostic failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")
    cleaned = redact(raw, auth.secrets)
    returned = cleaned.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
    truncated = returned != cleaned
    return {"ok": True, "target": auth.alias, "platform": "fortiadc", "recipe": recipe,
            **({"count_applied": False, "fixed_ping_packets": diagnostics.ADC_PING_PACKETS} if recipe == "ping" else {}),
            **({"health_check": health_check, "count_applied": True} if recipe == "health_check_verify" else {}),
            **({"count_applied": False, "http_requests": 1} if recipe == "http_probe" else {}),
            "content_sha256": digest_text(cleaned), "identity": identity,
            "deadline_reached": timed_out, "complete": not timed_out and not truncated,
            "cleanup": "not_required", "total_bytes": len(cleaned.encode("utf-8")),
            "returned_bytes": len(returned.encode("utf-8")), "truncated": truncated,
            "untrusted_device_output": returned}


@_audit_device_call
def triage_health_read(auth: TargetAuth, platform: str, query: str,
                       parameters: dict[str, str] | None = None) -> dict[str, Any]:
    return _triage_read(auth, platform, query, parameters)


@_audit_device_call
def triage_flow_read(auth: TargetAuth, platform: str, query: str,
                     parameters: dict[str, str] | None = None) -> dict[str, Any]:
    # triage_flow checks its own flow values; the slot kinds are still validated by render_read_query, and the
    # values are added to the inventory for this one read only
    inventory = {name: tuple(values) for name, values in auth.read_inventory.items()}
    for name, slot in READ_QUERIES[platform][query].slots.items():
        inventory[slot.inventory] = (*inventory.get(slot.inventory, ()), (parameters or {}).get(name, ""))
    return _triage_read(auth, platform, query, parameters, inventory)


@_audit_device_call
def triage_vpn_read(auth: TargetAuth, platform: str, query: str) -> dict[str, Any]:
    return _triage_read(auth, platform, query)


@_audit_device_call
def triage_wifi_read(auth: TargetAuth, platform: str, query: str,
                     parameters: dict[str, str] | None = None) -> dict[str, Any]:
    return _triage_read(auth, platform, query, parameters)


def _triage_read(auth: TargetAuth, platform: str, query: str,
                 parameters: dict[str, str] | None = None, inventory: Any = None) -> dict[str, Any]:
    normalized, command, _ = _ssh_read_state(auth, platform, query, parameters, inventory)
    try:
        if is_read_sequence(normalized, query):
            rc, output = _sequence_read(auth, normalized, render_read_sequence(
                normalized, query, parameters, _read_inventory(auth))[1])
        else:
            rc, output = read_from_device(auth, normalized, command)
    except Exception as exc:
        code = _transport_cause(exc)
        if code is None:
            return {"ok": False, "platform": normalized, "query": query, "reason": "device_cli_error",
                    "error_code": "ssh_unavailable"}
        return {"ok": False, "platform": normalized, "query": query,
                "reason": "timeout" if code == "timeout" else "transport_error", **_transport_failure(code)}
    cleaned = _redact_output(output, auth)
    if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "truncated"}
    if rc not in (0, None) or (
            _cli_refused(normalized, cleaned) if is_read_sequence(normalized, query)
            else _cli_refused(normalized, cleaned, command=command)):
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "device_cli_error"}
    if normalized == "fortinet" and query in wifi_parse.PARSERS:
        sequence_filter = render_read_sequence(normalized, query, parameters, _read_inventory(auth))[2] \
            if is_read_sequence(normalized, query) else {}
        if sequence_filter.get("mac_literal") and cleaned.strip():
            cleaned = wifi_parse.filter_events_by_mac(cleaned, sequence_filter["mac_literal"])[0]
        if query == "wifi_ap_status":
            _remember_wtp_ids(auth, [item["serial"] for item in wifi_parse.summarize(query, cleaned)["records"]])
    return {"ok": True, "platform": normalized, "query": query, "rc": rc,
            "content_sha256": digest_text(cleaned), "total_bytes": len(cleaned.encode("utf-8")), "text": cleaned}


# Where a triage observes from: the CLI of the target itself. It sends no probe packet, so its facts are what
# the device reports; a client-side test (traffic through a virtual server, a tunnel or a route) is separate.
_TRIAGE_VANTAGE = {
    "triage_health": ("device_cli_read", "the status, resources, sessions, HA and routing summaries the FortiGate reports",
                      "traffic of a client and the path beyond the firewall"),
    "triage_routing": ("device_cli_read", "the route lookup, routing table and neighbour state of the FortiGate",
                       "packets on the path; ping and traceroute are separate fortios_diagnostics calls"),
    "triage_vpn": ("device_cli_read", "the IPsec tunnel state, its routes and IKE error counters of the FortiGate",
                   "data flow through the tunnel; an established SA is not proof of traffic"),
    "triage_flow": ("device_cli_lookup", "the routes, the policy lookup and the sessions of the FortiGate",
                    "the packet itself; the lookup sends none"),
    "wifi_triage": ("device_cli_read", "wireless events, access point and radio state reported by the FortiGate",
                    "the switch port behind the access point"),
    "triage_slb": ("device_cli_read", "the configuration and runtime state the FortiADC reports for the virtual server, "
                   "its pool, members, health checks and profiles",
                   "whether new client connections pass through the virtual server; test that from a client"),
}


def _triage_vantage(auth: TargetAuth, tool: str) -> dict[str, Any]:
    kind, sees, does_not_see = _TRIAGE_VANTAGE[tool]
    return {"kind": kind, "device": auth.alias, "packets_sent": False, "sees": sees, "does_not_see": does_not_see}


def _run_triage(auth, run, read, tool):
    """Keep transport failures distinct from unsupported firmware, without losing partial facts."""
    from .triage_health import UnsupportedPlatform
    failures = []

    def checked(query, *args):
        answer = read(query, *args)
        transport = answer.get("error_code") in _TRANSPORT_ERROR_CODES
        if not answer.get("ok") and (query == "system_status" or transport or answer.get("error_code") == "ssh_unavailable"):
            failures.append({"step": query, "reason": answer.get("reason", "device_cli_error"),
                             "error_code": answer.get("error_code", answer.get("reason", "device_cli_error")),
                             **({"error": answer["error"]} if transport else {})})
        return answer

    try:
        result = run(checked)
    except UnsupportedPlatform:
        if not failures:
            return {"ok": False, "target": auth.alias, "error_code": "config_platform_not_supported",
                    "failed_step": "system_status", "error": "The reported model and build are not qualified for this triage",
                    "missing": [{"step": "system_status", "reason": "unsupported"}], "verdict": "incomplete",
                    "vantage": _triage_vantage(auth, tool)}
        result = {"missing": failures, "verdict": "incomplete"}
    if failures:
        result.update(error_code=failures[0]["error_code"], failed_step=failures[0]["step"])
        if failures[0]["step"] == "system_status":
            result.update(ok=False, error=failures[0].get(
                "error", "Triage read failed; inspect missing steps and check SSH access, account permissions and target scope"))
    result.setdefault("vantage", _triage_vantage(auth, tool))
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_health(auth: TargetAuth) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_health as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_health supports FortiOS targets only")

    steps = progress.Steps("triage_health")

    def read(query: str) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    result = _run_triage(auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc)), read,
                         "triage_health")
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_routing(auth: TargetAuth, address: str) -> dict[str, Any]:
    import ipaddress
    from datetime import datetime, timezone
    from . import triage_routing as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_routing supports FortiOS targets only")
    try:
        enrolled = (isinstance(address, str) and str(ipaddress.IPv4Address(address)) == address
                    and address in auth.read_inventory.get("addresses", ()))
    except ValueError:
        enrolled = False
    if not enrolled:
        raise ValueError("address must be one enrolled IPv4 address")

    steps = progress.Steps("triage_routing")

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    result = _run_triage(auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc), address, auth.alias), read,
                         "triage_routing")
    return {"target": auth.alias, **result}


def _flow_session_text(auth: TargetAuth, flow: dict[str, Any], interface: str) -> dict[str, Any]:
    """Read the sessions of one flow, source port open, through the measured `sessions` recipe machinery."""
    from . import fortios_diagnostics as diagnostics
    from netops_core.target_lock import target_lock
    protocol = {"tcp": 6, "udp": 17}[flow["proto"]]
    try:
        diagnostics.validate("sessions", flow["dst"], interface, 8, 5, 16000, source_address=flow["src"],
                             destination_port=flow["port"], protocol=protocol, any_source_port=True)
        auth.require_ssh_query("fortinet", "system_status")
        if not auth.fortios_output_standard_verified:
            raise ValueError("FortiOS output standard must be independently verified")
        if ("sessions" not in auth.read_inventory.get("diagnostic_recipes", ())
                or interface not in auth.read_inventory.get("interfaces", ())):
            return {"ok": False, "reason": "not_enrolled"}
    except (ValueError, PolicyScopeError):
        return {"ok": False, "reason": "permission_denied"}
    with target_lock(auth.host_key_fingerprint):
        target_address, unresolved = _session_target(auth)
        if unresolved:
            return {"ok": False, "reason": "transport_error", **_transport_failure(unresolved)}
        try:
            known_hosts = host_key_line(auth, target_address, "fortinet")
            with _paced_connection(target_address, auth.port, "fortinet"):
                with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                          known_hosts, legacy_ssh=auth.legacy_ssh,
                                          timeout_seconds=30, capture_max_bytes=131072) as session:
                    @contextmanager
                    def reconnect():
                        session.close()
                        with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                                  known_hosts, legacy_ssh=auth.legacy_ssh,
                                                  timeout_seconds=30, capture_max_bytes=131072) as repair:
                            yield _FortiosDiagnosticShell(repair)

                    raw, timed_out, _, _ = diagnostics.run(
                        _FortiosDiagnosticShell(session), "sessions", flow["dst"], interface, 8, 5, None,
                        reconnect=reconnect, source_address=flow["src"], destination_port=flow["port"],
                        protocol=protocol, any_source_port=True)
        except diagnostics.RestoreUnverified:
            return {"ok": False, "reason": "restore_unverified", "failed_step": "session",
                    "detail": "Diagnostic state restoration could not be verified: check 'diagnose sys session filter' "
                              "on the device; if a filter is set, run 'diagnose sys session filter clear'"}
        except diagnostics.ScopeRefused:
            return {"ok": False, "reason": "scope_refused", "failed_step": "session",
                    "detail": "The enrolled interface belongs to another VDOM"}
        except diagnostics.UnsupportedPlatform:
            return {"ok": False, "reason": "unsupported"}
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                return {"ok": False, "reason": "device_cli_error"}
            return {"ok": False, "reason": "timeout" if code == "timeout" else "transport_error",
                    **_transport_failure(code)}
    if timed_out:
        return {"ok": False, "reason": "timeout"}
    cleaned = _redact_output(raw, auth)
    if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return {"ok": False, "reason": "truncated"}
    return {"ok": True, "content_sha256": digest_text(cleaned), "text": cleaned}


@_audit_device_call
def triage_flow(auth: TargetAuth, src: str, dst: str, port: int, proto: str) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_flow as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_flow supports FortiOS targets only")
    flow = triage.validate(src, dst, port, proto)
    if "unsupported" in flow:
        return {"ok": False, "target": auth.alias, "verdict": "unsupported", "reason": flow["unsupported"],
                "detail": "triage_flow reads IPv4 flows only; no device was contacted"}

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_flow_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    def read_sessions(interface: str) -> dict[str, Any] | None:
        return _flow_session_text(auth, flow, interface)

    result = _run_triage(auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc),
                                                       flow, auth.alias, read_sessions), read, "triage_flow")
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_vpn(auth: TargetAuth, tunnel: str) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_vpn as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_vpn supports FortiOS targets only")
    if not triage.valid_tunnel(tunnel):
        raise ValueError("invalid_argument: tunnel must match [A-Za-z0-9][A-Za-z0-9_.-]{0,34}")

    steps = progress.Steps("triage_vpn")

    def read(query: str) -> dict[str, Any]:
        try:
            return triage_vpn_read(auth, "fortinet", query)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    result = _run_triage(auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc), tunnel), read,
                         "triage_vpn")
    return {"target": auth.alias, **result}


@_audit_device_call
def fortios_wifi_get(auth: TargetAuth, endpoint: str) -> dict[str, Any]:
    from . import wifi_rest
    document = wifi_rest.get(auth, endpoint)
    records, unparsed = wifi_rest.parse_counted(endpoint, document)
    return {"ok": True, "records": records, "endpoint": endpoint, "unparsed_rows": unparsed,
            "content_sha256": digest_text(json.dumps(records, sort_keys=True, allow_nan=False))}


def _wifi_rest_result(auth, reads):
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: Wi-Fi REST supports FortiOS only")
    if not auth.fortios_rest_token:
        return {"ok": False, "error_code": "unsupported", "target": auth.alias,
                "error": "Enroll helper.fortios_rest_credential (api-token) and certificate pin or CA; see docs/fortios-wifi-rest.md"}
    result = {"ok": True, "target": auth.alias, "vantage": "FortiOS REST monitor, root VDOM",
              "device_output_trust": "untrusted", "sources": []}
    for name, endpoint in reads:
        try:
            answer = fortios_wifi_get(auth, endpoint)
        except (ValueError, OSError, TypeError, AttributeError) as exc:
            from .wifi_rest import RestError
            subcode = (exc.code if isinstance(exc, RestError) else
                       "egress_denied" if isinstance(exc, EgressScopeError) else
                       "timeout" if isinstance(exc, TimeoutError) else "transport_error")
            # Keep the original coarse subcodes for existing triage clients;
            # error_code carries the precise diagnosis.
            legacy = (subcode if subcode in {"tls_pin_mismatch", "tls_verification_failed", "http_status",
                                             "timeout", "rate_limited", "egress_denied", "invalid_response"} else
                      "http_status" if subcode in {"authentication_failed", "authorization_failed", "http_server_error"}
                      else "transport_or_response_error")
            result.update(ok=False, error_code=subcode, error_subcode=legacy,
                          failed_step=endpoint,
                          error="Wi-Fi REST read failed; check error_code for TLS, authentication, timeout, HTTP, JSON, configuration or egress")
            if isinstance(exc, RestError) and exc.http_status is not None:
                result["http_status"] = exc.http_status
            break
        result[name] = answer["records"]
        fetched_at = _triage_now()
        if endpoint.endswith("/managed_ap"):
            for ap_record in result[name]:
                ap_record["fetched_at"] = fetched_at
                for radio_record in ap_record.get("radio", []):
                    radio_record["fetched_at"] = fetched_at
        if answer["unparsed_rows"]:
            result["unparsed_rows"] = result.get("unparsed_rows", 0) + answer["unparsed_rows"]
        result["sources"].append({"endpoint": endpoint, "content_sha256": answer["content_sha256"],
                                  "captured_at": fetched_at, "fetched_at": fetched_at})
    from .proxy_sanitize import sanitize_object
    return sanitize_object(result, (auth.fortios_rest_token, auth.secret))


def _wifi_clients_result(auth, ssid=None, ap=None, mac=None, ip=None, name=None):
    from .wifi_rest import MONITOR, checked_filters
    checked_filters(ssid, ap, mac, name)
    result = _wifi_rest_result(auth, (("records", MONITOR + "client"), ("access_points", MONITOR + "managed_ap")))
    if name is not None:
        result["identity_trust"] = "client_supplied"
    if not result.get("ok"):
        # AP aliases and hostname filters cannot be resolved reliably from a
        # partial read. Fail closed rather than exposing unrelated stations.
        result["records"] = []
        result.pop("access_points", None)
        result["filters"] = {k: v for k, v in {"ssid": ssid, "ap": ap, "mac": mac,
                                              "ip": ip, "name": name}.items() if v is not None}
        return result
    from .wifi_rest import DEVICES, enrich_identity
    identities = _wifi_rest_result(auth, (("devices", DEVICES),))
    result["sources"].extend(identities.get("sources", []))
    if not identities.get("ok"):
        result["identity_missing"] = {"step": "device_identity", "reason": "rest_unavailable",
                                      **{key: identities[key] for key in ("error_code", "http_status", "failed_step") if key in identities}}
    for row in result["records"]:
        enrich_identity(row, identities.get("devices", []))
        row["captured_at"] = result["sources"][0]["captured_at"]
        matches = [a for a in result["access_points"] if row["ap_id"] is not None
                   and row["ap_id"] in (a.get("serial"), a.get("wtp_id"), a.get("name"))]
        if len(matches) == 1:
            row["ap_serial"] = matches[0].get("serial")
            row["ap_name"] = matches[0].get("name", row["ap_name"])
            row["ap_detail"] = matches[0]
        row["ap"] = row.get("ap_name") or row.get("ap_serial") or row.get("ap_id")
        row["fetched_at"] = row["captured_at"]
        row["measurement_age_seconds"] = None
        row["measurement_age_note"] = "Source gives no RSSI/SNR measurement timestamp; fetched_at is retrieval time."
        row["rate_note"] = "Link RX/TX are negotiated PHY rates, not measured throughput; bandwidth units/interval are not specified by this source."
    result["records"] = [r for r in result["records"] if (ssid is None or r["ssid"] == ssid)
                         and (ap is None or ap in (r["ap_id"], r["ap_name"], r["ap_serial"]))
                         and (mac is None or r["mac"] == mac) and (ip is None or r["ip"] == ip)
                         and (name is None or r["hostname"].casefold() == name.casefold() and r["hostname"] != "unknown")]
    del result["access_points"]
    result["filters"] = {k: v for k,v in {"ssid":ssid, "ap":ap, "mac":mac, "name":name}.items() if v is not None}
    from .proxy_sanitize import sanitize_object
    return sanitize_object(result, (auth.fortios_rest_token, auth.secret))


def _wifi_station_sample(auth):
    """Additional triage snapshots use only the station endpoint."""
    from .wifi_rest import MONITOR
    result = _wifi_rest_result(auth, (("records", MONITOR + "client"),))
    for row in result.get("records", []):
        row["captured_at"] = row["fetched_at"] = result["sources"][0]["fetched_at"]
    return result


@_audit_device_call
def wifi_clients(auth: TargetAuth, ssid: str | None = None, ap: str | None = None,
                 mac: str | None = None, limit: int = 100, offset: int = 0,
                 max_bytes: int = 16_000, name: str | None = None) -> dict[str, Any]:
    from . import switch_pages
    switch_pages.validate(limit, offset, max_bytes)
    result = _wifi_clients_result(auth, ssid, ap, mac, name=name)
    for row in result.get("records", []):
        row.pop("ap_detail", None)
        row.pop("ap_name", None)
        serial = row.get("ap_serial")
        if serial is not None:
            row.pop("ap_id", None)
        if serial == row.get("ap") or serial is None:
            row.pop("ap_serial", None)
        if row.get("ap_id") == row.get("ap"):
            row.pop("ap_id", None)
    return switch_pages.page(result, limit=limit, offset=offset, max_bytes=max_bytes)


@_audit_device_call
def wifi_aps_live(auth: TargetAuth, summary: bool = False, limit: int = 100,
                  offset: int = 0, max_bytes: int = 16_000) -> dict[str, Any]:
    from .wifi_rest import MONITOR, ap_overview
    from . import switch_pages
    switch_pages.validate(limit, offset, max_bytes)
    result = _wifi_rest_result(auth, (("records", MONITOR + "managed_ap"), ("summary", MONITOR + "ap_status")))
    if result.get("ok"):
        from datetime import datetime, timezone
        from .wifi_rest import real_radio
        now = datetime.now(timezone.utc)
        for access in result["records"]:
            access["radio"] = [r for r in access.get("radio", []) if real_radio(r)]
            for radio in access["radio"]:
                stamp = radio.get("channel_utilization_timestamp")
                radio["measurement_age_seconds"] = None
                radio["channel_utilization_age_seconds"] = max(0, int((now - datetime.fromisoformat(stamp)).total_seconds())) if stamp else None
    if summary is True and result.get("ok"):
        result["records"] = [ap_overview(row) for row in result["records"]]
        result["view"] = "summary"
    return switch_pages.page(result, limit=limit, offset=offset, max_bytes=max_bytes)


@_audit_device_call
def wifi_rogue(auth: TargetAuth, limit: int = 100, min_signal: int | None = None,
               offset: int = 0, max_bytes: int = 16_000, mac: str | None = None, ap: str | None = None, full: bool = False) -> dict[str, Any]:
    from .wifi_rest import MONITOR, checked_rogue_filters
    checked_rogue_filters(limit, min_signal)
    from .wifi_rest import checked_filters
    checked_filters(ap=ap, mac=mac)
    if type(full) is not bool:
        raise ValueError("full must be boolean")
    from . import switch_pages
    switch_pages.validate(limit, offset, max_bytes)
    result = _wifi_rest_result(auth, (("rogue", MONITOR + "rogue_ap"), ("interfering", MONITOR + "interfering_ap")))
    if not result.get("ok"):
        return switch_pages.page(result, ("rogue", "interfering"), limit=limit, offset=offset, max_bytes=max_bytes)

    from .wifi_relevance import relevant_contexts, group_bssid, context_status, observation_signal, scoped_observation
    def signal(row, name):
        return observation_signal(row, name, contexts, full)

    contexts = []
    if not full:
        context = _wifi_rest_result(auth, (("clients", MONITOR + "client"), ("aps", MONITOR + "managed_ap")))
        result["sources"].extend(context.get("sources", []))
        if context.get("ok"):
            for access in context["aps"]:
                ids = (access.get("serial"), access.get("name"), access.get("wtp_id"))
                if ap is not None and ap not in ids:
                    continue
                for radio in access.get("radio", []):
                    if mac is not None and not any(c["mac"] == mac and c["ap_id"] in ids and c["radio"] == radio.get("radio_id") for c in context["clients"]):
                        continue
                    if ap is None and mac is None and not any(c["ap_id"] in ids and c["radio"] == radio.get("radio_id") for c in context["clients"]):
                        continue
                    if radio.get("oper_chan"):
                        contexts.append({"ap_id": access.get("serial"), "ap_ids": [value for value in ids if value], "band": radio.get("band"),
                                         "radio": radio.get("radio_id"), "channel": radio.get("oper_chan"), "channel_width_mhz": radio.get("channel_width_mhz")})
        result["relevance"] = {"contexts": contexts, "status": context_status(contexts),
                               "overlap": "width_unknown" if any(c.get("channel_width_mhz") is None for c in contexts) else "possible spectral overlap; neighbor width unknown means primary channel only; no DFS inference",
                               "observer_scope": "AP/radio observers with spectral overlap; otherwise controller-wide observation"}
        if not context.get("ok"):
            result["relevance"].update(status="context_read_failed", **{
                key: context[key] for key in ("error_code", "error_subcode", "failed_step", "http_status") if key in context})
    effective_signal = min_signal if min_signal is not None else None if full else -75
    result["counts"] = {}
    result["filters"] = {"limit": limit, "min_signal": effective_signal, "mac": mac, "ap": ap, "full": full}
    rogue_by_mac = {}
    for row in result["rogue"]:
        rogue_by_mac.setdefault(row.get("mac"), []).append(row)
    for name in ("rogue", "interfering"):
        rows = result[name]
        matched = []
        for row in rows:
            if not full:
                selected = [c for spectral in ([row] if name == "rogue" else rogue_by_mac.get(row.get("mac"), []))
                            for c in relevant_contexts(spectral, contexts)]
                if not selected:
                    continue
                row = scoped_observation(row, name, selected)
            strength = signal(row, name) if full else row.get("signal_strength")
            if effective_signal is None or (strength is not None and strength >= effective_signal):
                matched.append(row)
        matched.sort(key=lambda row: (-(signal(row, name) if full else row.get("signal_strength")
                                       if row.get("signal_strength") is not None else -151), str(row.get("mac", ""))))
        result[name] = group_bssid(matched, full)
        result["counts"][name] = {"total": len(rows), "matched": len(matched), "unique_bssid": len(result[name]), "returned": 0}
    result = switch_pages.page(result, ("rogue", "interfering"), limit=limit, offset=offset, max_bytes=max_bytes)
    return result


@_audit_device_call
def triage_wifi(auth: TargetAuth, mac: str | None = None, ip: str | None = None, summary: bool = False, name: str | None = None,
                history_limit: int = 100, history_offset: int = 0) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_wifi as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: wifi_triage supports FortiOS targets only")
    from .wifi_rest import checked_filters, wireless_log_path, MONITOR
    triage.validate_history(history_limit, history_offset)
    checked_filters(name=name)
    if sum(v is not None for v in (mac, ip, name)) != 1 or (mac is not None and not triage.valid_mac(mac)) \
            or (ip is not None and not triage.valid_ip(ip)):
        raise ValueError("invalid_argument: exactly one of mac (lower-case aa:bb:cc:dd:ee:ff), ip (IPv4) or name (hostname) is required")

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_wifi_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    live = (lambda: _wifi_clients_result(auth, mac=mac, ip=ip, name=name)) if auth.fortios_rest_token else None
    events = (lambda client_mac: _wifi_rest_result(auth, (("events", wireless_log_path(client_mac)),))) if auth.fortios_rest_token else None
    result = _run_triage(auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc), mac, ip, auth.alias, live=live,
                                                       name=name, event_read=events, thresholds=auth.wifi_thresholds,
                                                       neighbor_read=(lambda: _wifi_rest_result(auth, (("rogue", MONITOR + "rogue_ap"),
                                                                                                      ("interfering", MONITOR + "interfering_ap")))) if live else None,
                                                       sample_live=(lambda: _wifi_station_sample(auth)) if live else None,
                                                       enabled_queries=auth.enabled_queries), read,
                         "wifi_triage")
    if not result.get("ok"):
        return result
    return triage.overview(result) if summary is True else triage.full_page(result, history_limit, history_offset)


def _schema_cache_key(
    auth: TargetAuth, library: Any, path: str, view: str, vdom: str | None, keys: list[str],
) -> tuple[Any, ...]:
    return _ssh_cache_key(auth,"fortinet","schema_read",{
        "path":path,"view":view,"vdom":json.dumps(vdom),"owners":json.dumps(keys),
        "schema":library.sha256})


@_audit_device_call
def schema_read(
    auth: TargetAuth, path: str, view: str, vdom: str | None,
    owners: list[str] | None, offset: int, max_bytes: int, content_sha256: str | None = None,
) -> dict[str, Any]:
    from . import schema_read as reader
    offset,max_bytes=_validate_pagination(offset,max_bytes)
    if not os.environ.get("NETOPS_SCHEMA_REGISTRY"):
        return {"ok": False, "target": auth.alias, "error_code": "unsupported",
                "reason": "schema_registry_missing",
                "error": "A server-side schema registry is not installed; see docs/tools.md (schema_read)"}
    library=reader.binding(auth)
    keys=[] if owners is None else owners
    reader.selectors(auth,library,path,view,vdom,keys)
    cache_key=_schema_cache_key(auth,library,path,view,vdom,keys)
    if offset:
        if not _named_snapshot(content_sha256):
            raise _pagination_refused(_SCHEMA_SNAPSHOT_UNNAMED)
        cached=_load_continuation((*cache_key,content_sha256),auth)
        if cached is None:
            raise _pagination_refused(_SCHEMA_SNAPSHOT_EXPIRED)
        rc,cleaned=cached
        source="cached"
    else:
        try:
            rc,status=read_from_device(auth,"fortinet","get system status")
        except Exception as exc:
            if (code:=_transport_cause(exc)) is not None:
                return {"ok":False,"target":auth.alias,"platform":"fortinet","query":"schema_read",**_transport_failure(code)}
            raise ValueError("SSH schema identity read failed") from None
        if rc not in (0,None) or _cli_refused("fortinet",status):
            raise ValueError("the device refused the identity check")
        current_vdom=reader.verify_status(library,status)
        try:
            rc,raw=read_from_device(auth,"fortinet","show full-configuration")
        except Exception as exc:
            if (code:=_transport_cause(exc)) is not None:
                return {"ok":False,"target":auth.alias,"platform":"fortinet","query":"schema_read",**_transport_failure(code)}
            raise ValueError("SSH schema snapshot read failed") from None
        if rc not in (0,None) or _cli_refused("fortinet",raw):
            raise ValueError("the device refused the schema snapshot")
        report=reader.snapshot(library,raw,path,view,vdom,keys,auth.redaction_secrets,current_vdom=current_vdom)
        cleaned=_redact_schema_report(report,auth)
        if len(cleaned.encode("utf-8"))>_SSH_CAPTURE_MAX_BYTES:
            raise ValueError("schema result exceeds its safety cap")
        source="fresh"
    page=_schema_page(cleaned,offset,max_bytes,auth)
    cache_key=(*cache_key,page["content_sha256"])
    if page["next_offset"] is not None:
        if offset==0:_store_cached_ssh_output(cache_key,rc,cleaned,auth.redaction_secrets)
    else:
        with _SSH_CACHE_LOCK:_SSH_PAGE_CACHE.pop(cache_key,None)
    return {"ok":True,"target":auth.alias,"platform":"fortinet","query":"schema_read",
            "schema_sha256":library.sha256,"pagination_source":source,**page}


def _schema_continuation_key(auth: TargetAuth, arguments: dict[str, Any]) -> tuple[Any, ...]:
    from . import schema_read as reader
    path, view, vdom = arguments["path"], arguments["view"], arguments["vdom"]
    keys=[] if arguments["owners"] is None else arguments["owners"]
    library=reader.binding(auth)
    reader.selectors(auth,library,path,view,vdom,keys)
    return _schema_cache_key(auth,library,path,view,vdom,keys)


_SSH_SNAPSHOT_UNNAMED = (
    "SSH pagination needs the content_sha256 of its first page; restart at offset 0"
)
_SCHEMA_SNAPSHOT_UNNAMED = (
    "schema pagination needs the content_sha256 of its first page; restart at offset 0"
)
_SSH_SNAPSHOT_EXPIRED = "SSH pagination state expired; restart at offset 0"
_SCHEMA_SNAPSHOT_EXPIRED = "schema pagination state expired; restart at offset 0"
_PAGINATION_CODES = {
    _SSH_SNAPSHOT_UNNAMED: "ssh_pagination_snapshot_required",
    _SSH_SNAPSHOT_EXPIRED: "ssh_pagination_expired",
    _SCHEMA_SNAPSHOT_UNNAMED: "schema_pagination_snapshot_required",
    _SCHEMA_SNAPSHOT_EXPIRED: "schema_pagination_expired",
    _SCHEMA_REDACTION_UNVERIFIED: "schema_redaction_unverified",
}


class PaginationRefused(ValueError):
    """Expected refusal of a paged read; the fixed code and text are safe to show.

    A restart at offset 0 repairs a refused continuation, so the result names it.
    """

    restartable = True

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RedactionUnverified(PaginationRefused):
    """The report was withheld on purpose; reading it again produces the same refusal."""

    restartable = False


def _pagination_refused(message: str) -> PaginationRefused:
    kind = RedactionUnverified if message == _SCHEMA_REDACTION_UNVERIFIED else PaginationRefused
    return kind(_PAGINATION_CODES[message], message)


_CONTINUATIONS = {
    "ssh_read": (
        lambda auth, arguments: _ssh_read_state(
            auth, arguments["platform"], arguments["query"], arguments["parameters"],
        )[2],
        _SSH_SNAPSHOT_EXPIRED,
        _SSH_SNAPSHOT_UNNAMED,
    ),
    "schema_read": (
        _schema_continuation_key,
        _SCHEMA_SNAPSHOT_EXPIRED,
        _SCHEMA_SNAPSHOT_UNNAMED,
    ),
}


@_audit_device_call
def dns_probe(auth: TargetAuth) -> dict[str, Any]:
    auth.require_dns()
    started = time.monotonic()
    try:
        addresses = _resolve_target_ipv4(auth)
    except OSError as exc:
        return {"vantage": "helper_host", "ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
        "vantage": "helper_host",
        "ok": True,
        "target": auth.alias,
        "answers": len(addresses),
        "families": {"IPv4": len(addresses)},
        "untrusted_device_addresses": list(addresses),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
def tcp_probe(auth: TargetAuth, port: int, timeout: float) -> dict[str, Any]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    auth.require_tcp_port(port)
    timeout = _bounded_timeout(timeout, "timeout", 0.2, 15.0)
    started = time.monotonic()
    try:
        address = _resolve_target_ipv4(auth)[0]
        with socket.create_connection((address, port), timeout=timeout):
            pass
    except OSError as exc:
        return {
            "vantage": "helper_host",
            "ok": False, "target": auth.alias, "port": port,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": _safe_error(exc, auth),
        }
    return {
        "vantage": "helper_host",
        "ok": True, "target": auth.alias, "port": port,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
def icmp_probe(auth: TargetAuth, count: int) -> dict[str, Any]:
    count = _bounded_int(count, "count", 1, 8)
    auth.require_icmp()
    try:
        address = _resolve_target_ipv4(auth)[0]
        result = ping(address, count=count, interval=0.2, timeout=2, privileged=False)
    except Exception as exc:
        return {"vantage": "helper_host", "ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
        "vantage": "helper_host",
        "ok": bool(result.is_alive),
        "target": auth.alias,
        "packets_sent": result.packets_sent,
        "packets_received": result.packets_received,
        "packet_loss_percent": result.packet_loss * 100,
        "min_rtt_ms": result.min_rtt,
        "avg_rtt_ms": result.avg_rtt,
        "max_rtt_ms": result.max_rtt,
        "jitter_ms": result.jitter,
    }


def _name_tuple(entries: tuple[tuple[tuple[str, str], ...], ...]) -> list[dict[str, str]]:
    return [{key: value for key, value in group} for group in entries]


def _pin_match(auth, fingerprint, port, server_name):
    """The REST pin belongs to the enrolled REST port and target name."""
    if not auth.fortios_rest_certificate_sha256 or port != auth.fortios_rest_port or server_name != auth.host:
        return None
    return hmac.compare_digest(fingerprint, auth.fortios_rest_certificate_sha256)


def _certificate_details(der, auth, port, server_name):
    from cryptography import x509
    certificate = x509.load_der_x509_certificate(der)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(item.value) for item in san]
    except x509.ExtensionNotFound:
        names = []
    fingerprint = hashlib.sha256(der).hexdigest()
    return {"certificate_sha256": fingerprint,
            "subject": redact(certificate.subject.rfc4514_string(), auth.secrets),
            "issuer": redact(certificate.issuer.rfc4514_string(), auth.secrets),
            "san": [redact(name, auth.secrets) for name in names],
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "pin_match": _pin_match(auth, fingerprint, port, server_name)}


@_audit_device_call
def tls_probe(auth: TargetAuth, port: int, server_name: str | None) -> dict[str, Any]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if server_name is not None and (
        not isinstance(server_name, str) or not server_name
    ):
        raise ValueError("server_name must be a non-empty string or null")
    auth.require_tcp_port(port)
    selected_server_name = auth.require_tls_server_name(server_name)
    if auth.tls_ca_certificate is None:
        trust = "system"
        context = ssl.create_default_context()
    else:
        trust = "inventory_ca"
        authority = Path(auth.tls_ca_certificate).resolve()
        if TLS_CERT_DIR.resolve() not in authority.parents or not authority.is_file():
            raise ValueError("tls_ca_certificate is outside the helper trust directory")
        context = ssl.create_default_context(cafile=str(authority))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = max(context.minimum_version, ssl.TLSVersion.TLSv1_2)
    started = time.monotonic()
    try:
        address = _resolve_target_ipv4(auth)[0]
        with socket.create_connection((address, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=selected_server_name) as wrapped:
                cert = wrapped.getpeercert()
                der = wrapped.getpeercert(binary_form=True)
                cipher = wrapped.cipher()
                version = wrapped.version()
    except Exception as exc:
        result = {"vantage": "helper_host", "ok": False, "target": auth.alias,
                  "port": port, "trust": trust, "certificate_verified": False,
                  "error": _safe_error(exc, auth)}
        if isinstance(exc, ssl.SSLCertVerificationError):
            # A separate bounded handshake retrieves diagnostic data only; no HTTP or credentials.
            unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified.check_hostname = False
            unverified.verify_mode = ssl.CERT_NONE
            unverified.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                with socket.create_connection((address, port), timeout=10) as raw:
                    with unverified.wrap_socket(raw, server_hostname=selected_server_name) as wrapped:
                        result["unverified_certificate"] = {
                            "source": "unverified diagnostic handshake",
                            **_certificate_details(wrapped.getpeercert(binary_form=True), auth, port, selected_server_name)}
            except Exception:
                result["certificate_details_error"] = "unverified_certificate_unavailable"
        return result
    not_after = cert.get("notAfter")
    days_remaining = None
    if isinstance(not_after, str):
        days_remaining = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    return {
        "vantage": "helper_host",
        "ok": True,
        "target": auth.alias,
        "port": port,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "subject": redact(_name_tuple(cert.get("subject", ())), auth.secrets),
        "issuer": redact(_name_tuple(cert.get("issuer", ())), auth.secrets),
        "days_remaining": days_remaining,
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "trust": trust,
        "verified_by_system_trust": trust == "system",
        "certificate_verified": True,
        "pin_match": _pin_match(auth, hashlib.sha256(der).hexdigest(), port, selected_server_name),
        "san": [redact(value, auth.secrets) for _, value in cert.get("subjectAltName", ())],
        "not_before": datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc).isoformat()
                      if cert.get("notBefore") else None,
        "not_after": datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc).isoformat()
                     if not_after else None,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
async def snmp_get(auth: TargetAuth, oids: list[str], port: int) -> dict[str, Any]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if (
        not isinstance(oids, list) or not 1 <= len(oids) <= 20
        or any(not isinstance(oid, str) or not oid or len(oid) > 200 for oid in oids)
    ):
        raise ValueError("provide between 1 and 20 bounded string OIDs")
    usm = auth.require_snmp_usm()
    auth.require_udp_port(port)
    try:
        address = _resolve_target_ipv4(auth)[0]
    except OSError as exc:
        return {"vantage": "helper_host", "ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}

    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData, ObjectIdentity, ObjectType, SnmpEngine, UsmUserData,
        USM_AUTH_HMAC192_SHA256, USM_PRIV_CFB128_AES,
        UdpTransportTarget, get_cmd,
    )

    engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((address, port), timeout=2, retries=1)
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            UsmUserData(
                usm["user"], authKey=usm["auth_key"], privKey=usm["priv_key"],
                authProtocol=USM_AUTH_HMAC192_SHA256, privProtocol=USM_PRIV_CFB128_AES,
            ),
            transport,
            ContextData(),
            *(ObjectType(ObjectIdentity(oid)) for oid in oids),
        )
    except Exception as exc:
        return {"vantage": "helper_host", "ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    finally:
        engine.close_dispatcher()
    if error_indication or error_status:
        failure = error_indication or error_status.prettyPrint()
        return {"vantage": "helper_host", "ok": False, "target": auth.alias, "error": redact(failure, auth.secrets)}
    return {
        "vantage": "helper_host",
        "ok": True,
        "target": auth.alias,
        "values": [
            {"oid": name.get_oid().prettyPrint(), "value": redact(value.prettyPrint(), auth.secrets)}
            for name, value in var_binds
        ],
    }


def _sftp_entry(auth: TargetAuth, path: str) -> core_sftp.Entry:
    address = _resolve_target_ipv4(auth)[0]
    platform = auth.ssh_platform
    known_hosts_line = host_key_line(auth, address, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            return core_sftp.stat(
                address,
                auth.port,
                auth.login,
                DeviceCredential(auth),
                known_hosts_line,
                path,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
                roots=auth.sftp_roots,
            )
    except core_ssh.SshError as exc:
        _forget_host_key_line(address, auth.port)
        raise _exec_failure(auth, exc) from exc


@_audit_device_call
async def sftp_stat(auth: TargetAuth, remote_path: str) -> dict[str, Any]:
    path = _safe_remote_path(auth, remote_path)
    try:
        entry = await asyncio.to_thread(_sftp_entry, auth, path)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    answer: dict[str, Any] = {
        "ok": True, "target": auth.alias, "path_sha256": digest_text(path),
        "kind": entry.kind,
    }
    if entry.kind == core_sftp.KIND_DIRECTORY:
        answer["entry_count"] = entry.entry_count
        return answer
    answer["size"] = entry.size
    answer["mode"] = None if entry.mode is None else oct(entry.mode & 0o7777)
    answer["modified_ls"] = (
        None if entry.modified_ls is None else redact(entry.modified_ls, auth.secrets)
    )
    return answer


def _safe_remote_path(auth: TargetAuth, remote_path: str) -> str:
    if not isinstance(remote_path, str):
        raise ValueError("remote path must be a string")
    requested = PurePosixPath(remote_path)
    if (
        not requested.is_absolute() or str(requested) != remote_path
        or remote_path.startswith("//") or len(remote_path) > 2_000
        or ".." in requested.parts
        or any(ord(char) < 32 or ord(char) == 127 for char in remote_path)
    ):
        raise ValueError("remote path must be an absolute POSIX path")
    path = str(requested)
    if not any(
        path == root or path.startswith(root.rstrip("/") + "/")
        for root in auth.sftp_roots
    ):
        raise ValueError("remote path is outside the target SFTP allowlist")
    return path


TLS_PINS_PATH = Path("/etc/netops-helper/tls-pins.json")
TLS_CERT_DIR = Path("/etc/netops-helper/certs")
TLS_PINS_MAX_BYTES = 1024 * 1024
PLAIN_FTP_WARNING = (
    "WARNING: Plain FTP is unencrypted. Credentials and directory listing data "
    "are transmitted in plaintext."
)


class FtpsPinError(RuntimeError):
    pass


def _ftps_context(alias: str) -> tuple[ssl.SSLContext, str | None]:
    try:
        configured = json.loads(read_regular(TLS_PINS_PATH, TLS_PINS_MAX_BYTES).decode("utf-8"),
                                object_pairs_hook=unique_object)
    except FileNotFoundError:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    except (OSError, InputError, ValueError, RecursionError) as exc:
        raise FtpsPinError("FTPS pin configuration is invalid") from exc
    if not isinstance(configured, dict):
        raise FtpsPinError("FTPS pin configuration is invalid")
    entry = configured.get(alias)
    if entry is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    if not isinstance(entry, dict):
        raise FtpsPinError("FTPS pin entry is invalid")
    digest = str(entry.get("sha256", "")).lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise FtpsPinError("FTPS pin digest is invalid")
    try:
        certificate = Path(str(entry.get("certificate", ""))).resolve()
        certificate_root = TLS_CERT_DIR.resolve()
        usable = certificate_root in certificate.parents and certificate.is_file()
    except (OSError, ValueError, RuntimeError):
        usable = False
    if not usable:
        raise FtpsPinError("FTPS pin certificate is unavailable")
    try:
        context = ssl.create_default_context(cafile=str(certificate))
    except (OSError, ValueError) as exc:
        raise FtpsPinError("FTPS pin certificate is unreadable") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context, digest


def _install_ftp_passive_guard(
    client: ftplib.FTP,
    auth: TargetAuth,
    control_address: str,
) -> None:
    """Pin passive data connections to the control peer and enrolled TCP ranges."""
    original_makepasv = client.makepasv

    def guarded_makepasv() -> tuple[str, int]:
        passive_host, passive_port = original_makepasv()
        auth.require_passive_tcp_port(passive_port)
        try:
            candidate = str(ipaddress.ip_address(passive_host))
        except ValueError:
            if passive_host.rstrip(".").lower() != auth.host.rstrip(".").lower():
                raise EgressScopeError(
                    "FTP passive host differs from the enrolled control target"
                )
            candidate = control_address
        if candidate != control_address or not auth.egress.allows_address(candidate):
            raise EgressScopeError(
                "FTP passive host differs from the enrolled control target"
            )
        return control_address, passive_port

    client.makepasv = guarded_makepasv  # type: ignore[method-assign]


_FTP_LIST_MAX_BYTES = 2_000_000
_FTP_LIST_MAX_NAMES = 500
_FTP_TOTAL_TIMEOUT_SECONDS = 30.0
_FTP_CONTROL_MAX_BYTES = 262_144


def _install_ftp_control_budget(client: ftplib.FTP) -> None:
    original_getline = client.getline
    received = 0

    def bounded_getline() -> str:
        nonlocal received
        line = original_getline()
        received += len(line.encode(client.encoding, errors="replace")) + 2
        if received > _FTP_CONTROL_MAX_BYTES:
            raise ValueError("FTP control replies exceed the receive byte budget")
        return line

    client.getline = bounded_getline  # type: ignore[method-assign]


def _require_pinned_peer(peer: ssl.SSLSocket, pin_digest: str, channel: str) -> None:
    certificate = peer.getpeercert(binary_form=True)
    actual = hashlib.sha256(certificate or b"").hexdigest()
    if not certificate or not hmac.compare_digest(actual, pin_digest):
        raise ssl.SSLCertVerificationError(f"pinned FTPS certificate mismatch{channel}")


def _install_ftps_data_pin(client: ftplib.FTP_TLS, pin_digest: str) -> None:
    original_ntransfercmd = client.ntransfercmd

    def pinned_ntransfercmd(command: str, rest: Any = None) -> tuple[Any, int | None]:
        connection, size = original_ntransfercmd(command, rest)
        try:
            if not isinstance(connection, ssl.SSLSocket):
                raise ssl.SSLCertVerificationError(
                    "pinned FTPS certificate mismatch on the data connection"
                )
            _require_pinned_peer(connection, pin_digest, " on the data connection")
        except BaseException:
            connection.close()
            raise
        return connection, size

    client.ntransfercmd = pinned_ntransfercmd  # type: ignore[method-assign]


class _FTPBudget:
    def __init__(self, client):
        self.client = client
        self.data = None
        self.deadline = time.monotonic() + _FTP_TOTAL_TIMEOUT_SECONDS
        self.expired = False
        self.timer = threading.Timer(_FTP_TOTAL_TIMEOUT_SECONDS, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def _expire(self):
        self.expired = True
        for peer in (getattr(self.client, "sock", None), self.data):
            if peer is not None:
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except (OSError, AttributeError):
                    pass

    def remaining(self):
        left = self.deadline - time.monotonic()
        if self.expired or left <= 0:
            raise TimeoutError("FTP operation exceeded its total time budget")
        self.client.timeout = left
        for peer in (getattr(self.client, "sock", None), self.data):
            if peer is not None:
                peer.settimeout(left)
        return left

    def call(self, function, *args):
        self.remaining()
        answer = function(*args)
        self.remaining()
        return answer

    def close(self):
        self.timer.cancel()
        self.timer.join()


def _bounded_ftp_names(client, remote_path, budget):
    budget.call(client.voidcmd, "TYPE A")
    budget.remaining()
    peer = client.transfercmd("NLST " + remote_path)
    budget.data = peer
    names, pending, received = [], bytearray(), 0
    try:
        while True:
            budget.remaining()
            chunk = peer.recv(min(65536, _FTP_LIST_MAX_BYTES - received + 1))
            budget.remaining()
            if not chunk:
                if pending:
                    if len(names) == _FTP_LIST_MAX_NAMES:
                        return names, True
                    names.append(bytes(pending).removesuffix(b"\r").decode(client.encoding))
                break
            received += len(chunk)
            if received > _FTP_LIST_MAX_BYTES:
                raise ValueError("FTP listing exceeds the receive byte budget")
            pending.extend(chunk)
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                if len(names) == _FTP_LIST_MAX_NAMES:
                    return names, True
                names.append(bytes(line).removesuffix(b"\r").decode(client.encoding))
        if isinstance(peer, ssl.SSLSocket):
            budget.remaining()
            plain_peer = peer.unwrap()
            try:
                budget.remaining()
            finally:
                plain_peer.close()
    finally:
        peer.close()
        budget.data = None
    budget.call(client.voidresp)
    return names, False


@_audit_device_call
def ftp_list(
    auth: TargetAuth,
    remote_path: str,
    use_tls: bool,
    port: int,
    acknowledge_unencrypted: bool = False,
) -> dict[str, Any]:
    if not isinstance(use_tls, bool) or not isinstance(acknowledge_unencrypted, bool):
        raise ValueError("FTP transport flags must be boolean")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    remote_path = _safe_remote_path(auth, remote_path)
    if not use_tls and not acknowledge_unencrypted:
        raise ValueError(
            PLAIN_FTP_WARNING
            + " Set acknowledge_unencrypted=true only after explicit user approval."
        )
    auth.require_tcp_port(port)
    auth.require_passive_tcp_range()
    try:
        control_address = _resolve_target_ipv4(auth)[0]
    except OSError as exc:
        return {
            "ok": False,
            "target": auth.alias,
            "tls": use_tls,
            "transport_encrypted": use_tls,
            "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
            "security_warning": None if use_tls else PLAIN_FTP_WARNING,
            "certificate_pinned": False,
            "failure_stage": "resolve",
            "error_type": type(exc).__name__,
            "error": _safe_error(exc, auth),
        }
    pin_digest: str | None = None
    security_warning: str | None = None
    if use_tls:
        context, pin_digest = _ftps_context(auth.alias)
        client: ftplib.FTP = ftplib.FTP_TLS(timeout=30, context=context)
        if pin_digest is not None:
            _install_ftps_data_pin(client, pin_digest)
    else:
        security_warning = PLAIN_FTP_WARNING
        client = ftplib.FTP(timeout=30)
    _install_ftp_passive_guard(client, auth, control_address)
    _install_ftp_control_budget(client)
    budget = _FTPBudget(client)
    stage = "connect"
    try:
        budget.call(client.connect, control_address, port)
        if isinstance(client, ftplib.FTP_TLS):
            client.host = auth.host
            stage = "tls_handshake"
            budget.call(client.auth)
            if pin_digest is not None:
                stage = "certificate_pin"
                _require_pinned_peer(client.sock, pin_digest, "")
            stage = "login_over_tls"
            budget.call(client.login, auth.login, auth.secret)
            stage = "protect_data_channel"
            budget.call(client.prot_p)
        else:
            stage = "plain_login"
            budget.call(client.login, auth.login, auth.secret)
        stage = "directory_list"
        names, truncated = _bounded_ftp_names(client, remote_path, budget)
        stage = "quit"
        if truncated:
            client.close()
        else:
            budget.call(client.quit)
    except EgressScopeError:
        try:
            client.close()
        except Exception:
            pass
        raise
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return {
            "ok": False,
            "target": auth.alias,
            "tls": use_tls,
            "transport_encrypted": use_tls,
            "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
            "security_warning": security_warning,
            "certificate_pinned": pin_digest is not None,
            "failure_stage": stage,
            "error_type": type(exc).__name__,
            "error": _safe_error(exc, auth),
        }
    finally:
        budget.close()
    return {
        "ok": True, "target": auth.alias, "tls": use_tls,
        "transport_encrypted": use_tls,
        "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
        "security_warning": security_warning,
        "certificate_pinned": pin_digest is not None,
        "entries": [redact(PurePosixPath(name).name, auth.secrets) for name in names],
        "truncated": truncated,
    }


@_audit_device_call
def config_read(auth: TargetAuth, platform: str, section: str, include_all: bool = False,
                snapshot_id: str = '', offset: int = 0, limit: int = 48000,
                redaction: str = 'minimal', include_defaults: bool = False, *,
                contains: str | None = None, context: int = 0,
                content_sha256: str | None = None, filter_sha256: str | None = None) -> dict[str, Any]:
    from . import configuration
    configuration.require(auth, platform, 'read')
    if redaction not in ('minimal', 'full') or type(include_defaults) is not bool:
        raise ValueError('invalid configuration capture options')
    configuration.filter_arguments(contains, context, content_sha256, filter_sha256)
    if offset and (contains is not None or filter_sha256 is not None) and (
            content_sha256 is None or filter_sha256 is None):
        raise ValueError('configuration filter continuation requires both fingerprints')
    if not snapshot_id and (content_sha256 is not None or filter_sha256 is not None):
        raise ValueError('configuration fingerprints require an existing snapshot')
    view = (contains, context, content_sha256, filter_sha256)
    try:
        if redaction == 'full':
            return _full_config_read(auth, platform, section, include_all, snapshot_id, offset, limit,
                                     include_defaults, view)
        if platform == 'fortiadc' or include_defaults:
            raise ValueError('config_platform_not_supported: full redaction mode required')
        return _minimal_config_read(auth, section, include_all, snapshot_id, offset, limit, view)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': 'fortiadc' if platform == 'fortiadc' else 'fortios',
                'section': section, **_transport_failure(failure.code)}


class _ConfigurationTransportFailed(ValueError):
    """A configuration read whose device transport failed; only its class leaves the engine."""

    def __init__(self, code: str) -> None:
        super().__init__('configuration transport-failed; output withheld')
        self.code = code


def _raise_transport(exc: BaseException) -> None:
    code = _transport_cause(exc)
    if code is not None:
        raise _ConfigurationTransportFailed(code) from None


def _minimal_config_read(auth, section, include_all, snapshot_id, offset, limit, view):
    from . import configuration
    command = configuration.read_command(section, include_all)
    configuration.page_arguments(offset, limit)
    with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, 'fortios')):
        if snapshot_id:
            capture = configuration.get_snapshot(auth, snapshot_id, section)
            text, count, firmware, identity = capture.text, capture.redacted_count, capture.firmware, snapshot_id
        else:
            if snapshot_id != '' or offset != 0:
                raise ValueError('a nonzero page offset requires an existing snapshot')
            try:
                identity_rc, status = read_from_device(auth, 'fortinet', 'get system status')
            except Exception as exc:
                _raise_transport(exc)
                raise ValueError('configuration identity read failed; output withheld') from None
            if identity_rc != 0:
                raise ValueError('configuration identity read refused; output withheld')
            firmware = configuration.require_single_vdom(status)
            if _cli_refused('fortinet', status):
                raise ValueError('configuration identity read refused; output withheld')
            capture = configuration.StreamRedactor(auth.secrets, section, limits=auth.configuration_limits)
            try:
                rc, raw = read_from_device(auth, 'fortinet', command, stdout_consumer=configuration.bounded_consumer(capture.feed))
                if rc != 0 or raw:
                    raise ValueError('configuration read refused; output withheld')
                text, hidden, count = capture.finish()
                text = configuration.response_content(text, auth.secrets)
            except core_ssh.OutputLimitError:
                raise ValueError('configuration capture-limit-exceeded; output withheld') from None
            except core_ssh.OutputConsumerError:
                if capture.budget_refusal is not None:
                    raise configuration.ConfigurationBudgetError(capture.budget_refusal) from None
                raise ValueError('configuration redaction-unverifiable; output withheld') from None
            except configuration.ConfigurationBudgetError:
                raise
            except configuration.ConfigurationRedactionError as exc:
                category = 'capture-limit-exceeded' if exc.reason == 'capture-limit-exceeded' else 'redaction-unverifiable'
                raise ValueError('configuration ' + category + '; output withheld') from None
            except Exception as exc:
                _raise_transport(exc)
                raise ValueError('configuration read failed; output withheld') from None
            finally:
                capture.close()
            identity = configuration.store(auth, text, hidden, count, section, firmware)
        capture = hidden = None
        try:
            view_fields = _filtered_view(configuration, identity, view, offset, limit,
                                         lambda: configuration.get_snapshot(auth, identity, section), auth.secrets)
            response = {'ok': True, 'target': auth.alias, 'platform': 'fortios', 'view': 'running',
                    'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                    'redaction_profile': configuration.PROFILE, 'redacted_count': count,
                    'section': section, 'command': command,
                    'firmware': dict(zip(('model', 'version', 'build'), firmware)), **view_fields}
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


def _filtered_view(configuration, identity, view, offset, limit, lookup, secrets=()):
    contains, context, content_sha256, filter_sha256 = view
    fingerprint = configuration.filter_digest(identity, contains, context)
    if filter_sha256 is not None and not hmac.compare_digest(filter_sha256, fingerprint):
        raise ValueError('configuration filter changed; restart at offset 0')
    filtered, total_lines, matched_lines = configuration.filtered_snapshot(lookup, identity, contains, context, offset,
                                                                           secrets)
    if content_sha256 is not None and not hmac.compare_digest(
            content_sha256, configuration.content_digest(filtered)):
        raise ValueError('configuration content changed; restart at offset 0')
    fields = configuration.payload(filtered, offset, limit)
    if contains is not None:
        fields.update(total_lines=total_lines, matched_lines=matched_lines, filter_sha256=fingerprint)
    return fields


def _full_config_read(auth, platform, section, include_all, snapshot_id, offset, limit, include_defaults, view):
    from . import configuration, config_fortios, config_fortiadc
    platform = 'fortiadc' if platform == 'fortiadc' else 'fortios'
    wire_platform = 'fortiadc' if platform == 'fortiadc' else 'fortinet'
    adapter = config_fortiadc if platform == 'fortiadc' else config_fortios
    command = adapter.read_command(section, include_all, include_defaults)
    configuration.page_arguments(offset, limit)
    with configuration.capture(auth.configuration_limits,
                               target=configuration.scope(auth, 'fortiadc' if platform == 'fortiadc' else 'fortios')):
        if snapshot_id:
            cached = configuration.get_full_snapshot(auth, snapshot_id, section, platform=platform,
                                                       include_defaults=include_defaults)
            firmware, text, count, identity = cached.firmware, cached.text, cached.redacted_count, snapshot_id
            policy = adapter.policy_for(firmware)
            if cached.profile != policy.identifier:
                raise ValueError('configuration snapshot policy mismatch')
            metadata = configuration.snapshot_metadata(cached)
        else:
            if snapshot_id != '' or offset != 0:
                raise ValueError('a nonzero page offset requires an existing snapshot')
            try:
                rc, status = read_from_device(auth, wire_platform, 'get system status')
            except Exception as exc:
                _raise_transport(exc)
                raise ValueError('configuration transport-failed during identity read; output withheld') from None
            if rc != 0 or _cli_refused(wire_platform, status):
                raise ValueError('configuration device-refused during identity read; output withheld')
            try:
                firmware, metadata = adapter.verify_identity(status)
            except configuration.UnsupportedConfigurationFirmware as exc:
                message = 'configuration firmware-not-supported'
                if exc.detected:
                    message += (' for ' + platform + '; detected ' + exc.detected[0] + ' build ' + exc.detected[1] +
                                '; supported ' + ', '.join(version + ' build ' + build for version, build in exc.supported))
                raise ValueError(message + '; output withheld') from None
            except ValueError:
                raise ValueError('configuration identity-unverifiable; output withheld') from None
            policy = adapter.policy_for(firmware)
            forbidden = auth.secrets
            capture_section = (adapter.object_section(section)[0]
                               if platform == 'fortiadc' and section != 'all' else section)
            capture = configuration.StreamRedactor(forbidden, capture_section, policy=policy, limits=auth.configuration_limits)
            tls_fields = (config_fortiadc.TLSGetFields(capture, section, command)
                          if platform == 'fortiadc' and capture_section == config_fortiadc.TLS_GET_FAMILY else None)
            normalizer = (config_fortiadc.Normalizer(tls_fields.feed if tls_fields else capture.feed, capture.maximum)
                          if platform == 'fortiadc' else None)
            try:
                try:
                    rc, raw = read_from_device(auth, wire_platform, command,
                                               stdout_consumer=configuration.bounded_consumer(normalizer.feed if normalizer else capture.feed))
                except core_ssh.OutputLimitError:
                    raise ValueError('configuration capture-limit-exceeded; output withheld') from None
                except core_ssh.OutputConsumerError as exc:
                    if capture.budget_refusal is not None:
                        raise configuration.ConfigurationBudgetError(capture.budget_refusal) from None
                    failure = exc.__context__
                    if isinstance(failure, configuration.ConfigurationRedactionError):
                        raise configuration.ConfigurationRedactionError(
                            failure.reason, line=failure.line, context=failure.context) from None
                    raise ValueError('configuration redaction-unverifiable; output withheld') from None
                except (configuration.ConfigurationRedactionError, configuration.ConfigurationBudgetError):
                    raise
                except ValueError as exc:
                    _raise_transport(exc)
                    raise configuration.ConfigurationRedactionError('redaction-unverifiable') from None
                except Exception as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration transport-failed during capture; output withheld') from None
                if rc != 0:
                    raise ValueError('configuration device-refused during capture; output withheld')
                if raw:
                    raise ValueError('configuration transport-contract-failed; output withheld')
                if normalizer:
                    try:
                        normalizer.finish()
                        if tls_fields:
                            tls_fields.finish()
                    except ValueError:
                        raise configuration.ConfigurationRedactionError('stream-incomplete') from None
                text, hidden, count = capture.finish()
                if platform == 'fortiadc':
                    metadata = adapter.assess(text, auth.login, section)
                else:
                    metadata = adapter.assess(text, auth.login, metadata)
                # The stored, hashed and paged text is what the client receives after proxy and worker.
                text = configuration.response_content(text, forbidden)
                if section != 'all':
                    metadata['configuration_complete'] = False
                    metadata['visibility_limitations'].append('requested-section-only')
                metadata.update(capture.summary())
                if metadata['unverified_count']:
                    metadata['configuration_complete'] = False
                    if metadata['unverified_count'] > metadata['unsupported_format_count']:
                        metadata['visibility_limitations'].append('schema-fields-unverified')
                    if metadata['unsupported_format_count']:
                        metadata['visibility_limitations'].append('formats-not-verified')
                identity = configuration.store(auth, text, hidden, count, section, firmware,
                                               platform=platform, profile=policy.identifier,
                                               include_defaults=include_defaults, metadata=metadata)
            except configuration.ConfigurationRedactionError as exc:
                raise ValueError('configuration ' + exc.reason + exc.location + '; output withheld') from None
            except ValueError:
                raise
            except Exception:
                raise ValueError('configuration capture-failed; output withheld') from None
            finally:
                capture.close()
        capture = hidden = cached = None
        try:
            view_fields = _filtered_view(
                configuration, identity, view, offset, limit,
                lambda: configuration.get_full_snapshot(auth, identity, section, platform=platform,
                                                        include_defaults=include_defaults), auth.secrets)
            response = {'ok': True, 'target': auth.alias, 'platform': platform, 'view': 'running',
                    'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                    'redaction_profile': policy.identifier, 'redacted_count': count,
                    'redaction': 'full', 'include_defaults': include_defaults, 'capture_complete': True,
                    'section': section, 'command': command, **metadata,
                    'firmware': dict(zip(('model', 'version', 'build'), firmware)), **view_fields}
            if (platform == 'fortiadc' and section != 'all' and
                    adapter.object_section(section)[0] == config_fortiadc.TLS_GET_FAMILY):
                response['normalized_from_get'] = True
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


@_audit_device_call
def config_diff(auth: TargetAuth, platform: str, base_snapshot: str,
                other_snapshot: str, offset: int = 0, limit: int = 48000, secret_offset: int = 0) -> dict[str, Any]:
    from . import configuration
    configuration.require(auth, platform, 'compare')
    configuration.page_arguments(offset, limit)
    if type(secret_offset) is not int or not 0 <= secret_offset <= 1073741824:
        raise ValueError('invalid secret change page')
    with configuration.capture(auth.configuration_limits,
                               target=configuration.scope(auth, 'fortiadc' if platform == 'fortiadc' else 'fortios')):
        text, changed, identical, metadata = configuration.compare(
            auth, base_snapshot, other_snapshot,
            platform='fortiadc' if platform == 'fortiadc' else 'fortios', with_metadata=True)
        changes, next_secret = changed.page(secret_offset)
        response = {'ok': True, 'target': auth.alias, 'platform': 'fortiadc' if platform == 'fortiadc' else 'fortios',
                'base_snapshot': base_snapshot, 'other_snapshot': other_snapshot,
                'identical': identical, 'secrets_changed': changes,
                'secret_offset': secret_offset, 'next_secret_offset': next_secret,
                'secrets_changed_count': len(changed), **metadata, **configuration.payload(text, offset, limit)}
        text = changed = None
        return response


def _triage_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _triage_failure(error: object) -> str:
    text = str(error).casefold()
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "refused" in text or "device_cli_error" in text:
        return "device_cli_error"
    if "not enabled" in text or "outside target policy" in text or "not_supported" in text:
        return "unsupported"
    return "device_cli_error"


def _adc_step_permitted(auth: TargetAuth, arguments: dict[str, Any]) -> bool:
    inventory = auth.read_inventory
    if arguments["recipe"] not in inventory.get("diagnostic_recipes", ()):
        return False
    if arguments.get("address") not in inventory.get("addresses", ()):
        return False
    if "health_check" in arguments and arguments["health_check"] not in inventory.get("adc_health_checks", ()):
        return False
    return arguments["recipe"] != "ping" or auth.egress.allow_icmp


@_audit_device_call
def triage_slb(auth: TargetAuth, virtual_server: str, vdom: str = "root") -> dict[str, Any]:
    from . import config_fortiadc, configuration, triage_slb as rules
    from .read_policy import SAFE_FORTIADC_OBJECT
    if auth.ssh_platform != "fortiadc":
        raise ValueError("unsupported_platform: triage_slb requires a FortiADC target")
    inventory = auth.read_inventory
    if (not isinstance(virtual_server, str) or virtual_server not in inventory.get("adc_virtual_servers", ())
            or not isinstance(vdom, str) or vdom not in inventory.get("adc_vdoms", ())):
        raise ValueError("virtual server or vdom is outside target inventory")
    configuration.require(auth, "fortiadc", "read")
    started = _triage_now()
    steps = progress.Steps("triage_slb")

    def identity_failure(code: str, reason: str, error: str) -> dict[str, Any]:
        # Like the FortiOS triages: a structured result names the code and the failed step; nothing else was read.
        return {"ok": False, "target": auth.alias, "platform": "fortiadc", "vantage": _triage_vantage(auth, "triage_slb"),
                "started_at": started, "finished_at": _triage_now(), "virtual_server": virtual_server, "vdom": vdom,
                "error_code": code, "failed_step": "system_status", "error": error,
                "missing": [{"step": "system_status", "reason": reason, "error_code": code,
                             **({"error": error} if code in _TRANSPORT_ERROR_CODES else {})}],
                "checked": [], "findings": [], "verdict": "incomplete"}

    try:
        try:
            rc, status = read_from_device(auth, "fortiadc", _IDENTITY_COMMAND)
        except Exception as exc:
            code = _transport_cause(exc)
            if code is None:
                return identity_failure("ssh_unavailable", "ssh_unavailable",
                                        "Triage read failed; check SSH access to the target and its host key")
            return identity_failure(code, "timeout" if code == "timeout" else "transport_error",
                                    _TRANSPORT_ADVICE[code])
        if rc not in (0, None) or _cli_refused("fortiadc", status):
            return identity_failure("device_cli_error", "device_cli_error",
                                    "The identity read was refused; check the account permissions")
        try:
            _, identity = config_fortiadc.verify_identity(status)
        except configuration.UnsupportedConfigurationFirmware:
            return identity_failure("config_platform_not_supported", "unsupported",
                                    "triage_slb requires FortiADC 7.6.7 build 0676")
        except Exception:
            return identity_failure("product_identity", "unparsed",
                                    "The identity of the target could not be verified; nothing else was read")
    finally:
        steps.read("system_status")
    status = None
    missing: list[dict[str, Any]] = []
    sources: dict[str, dict[str, Any]] = {}
    executed: set[str] = set()
    chain: dict[str, Any] = {"virtual_server": virtual_server, "vdom": vdom}

    def miss(step: str, reason: str, detail: str | None = None) -> None:
        missing.append({"step": step, "reason": reason, **({"detail": detail} if detail else {})})

    def transport_miss(step: str, result: dict[str, Any]) -> bool:
        code = result.get("error_code")
        if code not in _TRANSPORT_ERROR_CODES:
            return False
        missing.append({"step": step, "reason": "timeout" if code == "timeout" else "transport_error",
                        **_transport_failure(code)})
        return True

    def config_step(step: str, section: str, parser, defaults: bool = True):
        attempt = [False]
        token = _TRIAGE_READ_ATTEMPT.set(attempt)
        try:
            result = config_read(auth, "fortiadc", section, redaction="full", include_defaults=defaults)
            attempt[0] = True
        except Exception as exc:
            miss(step, _triage_failure(exc) if attempt[0] else "local_refusal", str(exc).split(";")[0][:120])
            return None
        finally:
            _TRIAGE_READ_ATTEMPT.reset(token)
            if attempt[0]:
                steps.read(step)
        if result.get("ok") is False:
            if not transport_miss(step, result):
                miss(step, "device_cli_error")
            return None
        sources[step] = {"call": "config_read", "section": section,
                         "content_sha256": result["content_sha256"], "captured_at": _triage_now()}
        if result.get("next_offset") is not None:
            miss(step, "truncated")
            return None
        try:
            value = parser(result["untrusted_device_output"])
        except rules.TriageParseError:
            miss(step, "unparsed")
            return None
        executed.add(step)
        return value

    def query_step(step: str, query: str, parameters: dict[str, str] | None, parser):
        attempt = [False]
        token = _TRIAGE_READ_ATTEMPT.set(attempt)
        try:
            result = ssh_read(auth, "fortiadc", query, parameters, 0, 48_000)
            attempt[0] = True
        except Exception as exc:
            miss(step, _triage_failure(exc) if attempt[0] else "local_refusal")
            return None
        finally:
            _TRIAGE_READ_ATTEMPT.reset(token)
            if attempt[0]:
                steps.read(step)
        if result.get("ok") is not True:
            if transport_miss(step, result):
                return None
            code = result.get("error_code")
            miss(step, code if code in rules.MISSING_REASONS else _triage_failure(result.get("error", "")),
                 code if isinstance(code, str) else None)
            return None
        sources[step] = {"call": "ssh_read", "query": query, "content_sha256": result["content_sha256"],
                         "captured_at": _triage_now()}
        if result.get("next_offset") is not None:
            miss(step, "truncated")
            return None
        if not result["untrusted_device_output"].strip():
            miss(step, "empty")
            return None
        try:
            value = parser(result["untrusted_device_output"])
        except rules.TriageParseError:
            miss(step, "unparsed")
            return None
        executed.add(step)
        return value

    vs = config_step("vs_config", "load-balance virtual-server " + virtual_server,
                     lambda text: rules.virtual_server_config(text, virtual_server))
    chain["vs"] = {"config": vs, "runtime": None}
    pool_name = vs["pool"] if vs else None
    chain["pool"] = {"name": pool_name, "config": None}
    if vs and (pool_name is None or not SAFE_FORTIADC_OBJECT.fullmatch(pool_name)):
        miss("pool_config", "unparsed" if pool_name else "not_applicable")
    elif vs:
        chain["pool"]["config"] = config_step("pool_config", "load-balance pool " + pool_name,
                                              lambda text: rules.pool_config(text, pool_name))
    else:
        miss("pool_config", "not_applicable")
    pool = chain["pool"]["config"]
    checks: list[str] = []
    if pool:
        for name in [*pool["health_check"], *(c for m in pool["members"] for c in (m["health_check"] or ()))]:
            if name not in checks:
                checks.append(name)
    chain["health_checks"] = []
    for index, name in enumerate(checks):
        step = "health_check_config:" + name
        if index >= rules.MAX_HEALTH_CHECKS:
            miss(step, "truncated")
            continue
        if not SAFE_FORTIADC_OBJECT.fullmatch(name) or name not in inventory.get("adc_health_checks", ()):
            miss(step, "unsupported", "health check is not enrolled in adc_health_checks")
            continue
        value = config_step(step, "system health-check " + name, lambda text, n=name: rules.health_check_config(text, n))
        chain["health_checks"].append({"name": name, "config": value})
    tls_profile = vs["client_ssl_profile"] if vs else None
    waf_profile = vs["waf_profile"] if vs else None
    dos_profile = vs["dos_profile"] if vs else None
    chain["tls"] = {"config": None, "runtime": None}
    chain["waf"] = {"config": None, "runtime": None}
    chain["dos"] = {"config": {"profile": dos_profile} if dos_profile else None, "runtime": None}
    if tls_profile:
        if SAFE_FORTIADC_OBJECT.fullmatch(tls_profile):
            chain["tls"]["config"] = config_step("tls_config", "load-balance client-ssl-profile " + tls_profile,
                                                 lambda text: {"profile": tls_profile}, defaults=False)
        else:
            miss("tls_config", "unparsed")
    if waf_profile:
        if SAFE_FORTIADC_OBJECT.fullmatch(waf_profile):
            chain["waf"]["config"] = config_step("waf_config", "security waf profile " + waf_profile,
                                                 lambda text: {"profile": waf_profile})
        else:
            miss("waf_config", "unparsed")
    runtime = query_step("slb_vs_stat", "slb_vs_stat", {"vdom": vdom, "virtual_server": virtual_server},
                         lambda text: rules.parse_vs_stat(text, virtual_server, vdom))
    chain["vs"]["runtime"] = runtime
    chain["load"] = query_step("slb_load", "slb_load", None, lambda text: rules.parse_slb_load(text, virtual_server))
    chain["members"] = []
    if pool:
        states = {m["id"]: m for p in (runtime or {}).get("pools", ()) for m in p["members"]}
        for member in pool["members"]:
            state = states.get(member["id"])
            chain["members"].append({
                "id": member["id"], "real_server": member["real_server"], "config_status": member["status"],
                "runtime": {"hc_state": state["hc_state"], "last_state_change": state["last_state_change"]}
                if state else None})
    if tls_profile:
        chain["tls"]["runtime"] = query_step("tls_handshake_stats", "tls_handshake_stats",
                                             {"virtual_server": virtual_server}, rules.parse_tls_stats)
    if dos_profile:
        chain["dos"]["runtime"] = {}
        for query in ("dos_access_limit", "dos_conn_limit", "dos_req_limit"):
            value = query_step(query, query, {"virtual_server": virtual_server},
                               lambda text: rules.parse_dos(text, virtual_server))
            if value is not None:
                chain["dos"]["runtime"][query] = value
    if waf_profile:
        chain["waf"]["runtime"] = query_step("waf_signature_status", "waf_signature_status", None,
                                             rules.parse_key_values)
    chain["resources"] = {"runtime": query_step("system_performance", "system_performance", None,
                                                rules.parse_key_values)}
    # Resolve only DOWN members, once per real server, within the reserved read plan.
    chain["real_servers"] = {}
    if pool and runtime:
        states = {m["id"]: m for p in runtime["pools"] if p["name"] == pool_name for m in p["members"]}
        names = list(dict.fromkeys(m["real_server"] for m in pool["members"]
                                  if m["status"] == "enable" and m["real_server"]
                                  and states.get(m["id"], {}).get("hc_state") not in (None, "UP")))
        for index, name in enumerate(names):
            step = "real_server_config:" + name
            if index >= rules.MAX_REAL_SERVERS:
                miss(step, "truncated")
                continue
            if not SAFE_FORTIADC_OBJECT.fullmatch(name):
                miss(step, "unparsed")
                continue
            address = config_step(step, "load-balance real-server " + name,
                                  lambda text, n=name: rules.real_server_address(text, n))
            if address is not None:
                chain["real_servers"][name] = address
    findings, hypotheses, next_steps = rules.evaluate(chain, sources, auth.alias)
    next_steps = [step for step in next_steps if _adc_step_permitted(auth, step["arguments"])]
    checked = sorted(executed)
    return {
        "ok": True, "target": auth.alias, "platform": "fortiadc", "identity": identity,
        "vantage": _triage_vantage(auth, "triage_slb"), "started_at": started, "finished_at": _triage_now(),
        "virtual_server": virtual_server, "vdom": vdom, "chain": chain,
        "findings": findings, "hypotheses": hypotheses, "next_steps": next_steps,
        "missing": missing, "checked": checked,
        "verdict": rules.verdict(findings, missing, executed),
    }


def _fortiswitch_configuration_output(profile, query, parameters, text):
    if profile != 'fortinet':
        return text
    from . import fortiswitch_ports
    if query not in (fortiswitch_ports.CONFIG, fortiswitch_ports.VLAN_IDS):
        return text
    # Preserve a refusal/empty/pager classification without returning unrelated configuration.
    state = normalization.output_status(text)
    if _cli_refused(profile, text) or state == 'permission_denied':
        return 'Command fail. Return code -61\n'
    if state == 'empty':
        return ''
    if state == 'truncated':
        return '--More--\n'
    if state in ('unsupported', 'not_applicable'):
        return 'error: unknown command\n'
    if query == fortiswitch_ports.VLAN_IDS:
        from . import fortigate_tables
        return fortigate_tables.configuration_view(text)
    return fortiswitch_ports.configuration_view(query, text, parameters or {})


@_audit_device_call
def normalized_query(auth: TargetAuth, platform: str, query: str, table: str, parameters=None) -> dict[str, Any]:
    """One authorized, identity-checked catalogue read, redacted before parsing."""
    from . import tables
    profile, command, _ = _ssh_read_state(auth, platform, query, parameters)
    try:
        rc, output = _verified_read(auth, profile, command)
        cleaned = _redact_output(output, auth)
        if len(cleaned.encode('utf-8')) > _SSH_CAPTURE_MAX_BYTES:
            return tables.parse(profile, table, query, '', status='truncated')
        cleaned = _fortiswitch_configuration_output(profile, query, parameters, cleaned)
        state = normalization.output_status(cleaned, rc=rc, profile=profile, command=command)
        refused = _cli_refused(profile, cleaned)
        if refused and state == 'ok':
            state = 'permission_denied'
        result = tables.parse(profile, table, query, cleaned, rc=rc, status=state, command=command, refused=refused)
        if state == 'transport_error':
            result.update(_transport_failure('exit_status'))
        if normalization.exos_exit_250(profile, rc, cleaned, command=command):
            result['warnings'].append('exit_status_250')
        return result
    except _ProductIdentityError as exc:
        result = tables.parse(profile, table, query, '', status='unparsed')
        result['warnings'].append(exc.reason)
        return result
    except Exception as exc:
        return _transport_result(profile, table, query, exc)


@_audit_device_call
def switch_read(auth: TargetAuth, table: str, vlan_id: str | None = None,
                mac: str | None = None, ip: str | None = None, limit: int = 100,
                offset: int = 0, max_bytes: int = 16_000, interface: str | None = None,
                managed_switch: str | None = None) -> dict[str, Any]:
    from . import ip_interfaces, tables, switch_pages, port_vlan
    switch_pages.validate(limit, offset, max_bytes)
    profile = auth.ssh_platform
    if table == "interface_errors" and profile != "fortinet":
        from . import port_errors
        tables.request(profile, table, vlan_id, mac, ip, auth.device_types, interface, managed_switch)
        result = port_errors.read(auth, interface, normalized_query)
        return switch_pages.page({"target": auth.alias, **result}, ("records", "unparsed"),
                                 limit=limit, offset=offset, max_bytes=max_bytes)
    query, parameters, filters = tables.request(profile, table, vlan_id, mac, ip, auth.device_types, interface, managed_switch)
    if profile == 'fortinet' and table == 'mac_entry' and managed_switch is None:
        from . import fortigate_tables
        result = fortigate_tables.read_mac(auth,
            lambda q, t, p: normalized_query(auth, profile, q, t, p))
    elif query is None:
        result = tables.parse(profile, table, None, '', status='unsupported')
        if profile == 'fortinet':
            from . import switch_managed
            result.update(reason='table_not_supported_for_profile', data={
                'field': 'table', 'supported_tables': switch_managed.supported_tables()})
    elif table == 'port_vlan' and profile == 'fortinet':
        from . import fortiswitch_ports
        result = fortiswitch_ports.read_vlan(auth, parameters,
            lambda q, t, p: normalized_query(auth, profile, q, t, p))
    elif table == 'port_vlan':
        result = port_vlan.read(auth, lambda q, t: normalized_query(auth, profile, q, t))
    else:
        result = normalized_query(auth, profile, query, table, parameters)
    if table == 'vlan':
        result = port_vlan.join_vlans(auth, result, lambda q, t: normalized_query(auth, profile, q, t))
    if managed_switch is not None:
        result['managed_switch'] = managed_switch
    if profile in ('cisco_ios', 'cisco_xe') and table == 'route' and query == 'route_lookup' and result['status'] == 'empty':
        from . import route_fallback

        def read_route_table():
            if 'route_table' not in auth.enabled_queries:
                return tables.parse(profile, table, 'route_table', '', status='permission_denied')
            return normalized_query(auth, profile, 'route_table', table)

        result = route_fallback.lookup(result, tables.literal(ip)[1], read_route_table)
    if table == 'ip_interface':
        result = ip_interfaces.join(profile, result, auth.enabled_queries,
                                    lambda name, other: normalized_query(auth, profile, name, other))
    if profile == 'juniper_junos_els' and table == 'mac_entry' and result['records']:
        if 'vlans' in auth.enabled_queries:
            vlans = normalized_query(auth, profile, 'vlans', 'vlan')
            result['sources'].extend(vlans['sources'])
            for row in result['records']:
                ids = {v['vlan_id'] for v in vlans['records'] if v['name'] == row.get('vlan_name')}
                if len(ids) == 1:
                    row['vlan_id'] = ids.pop()
            if vlans['status'] not in ('ok', 'empty'):
                result['status'] = vlans['status']
            result['unparsed'].extend({**line, 'query': 'vlans'} for line in vlans['unparsed'])
            result['coverage']['unparsed_lines'] = len(result['unparsed'])
            result['warnings'] = list(dict.fromkeys(result['warnings'] + vlans['warnings']))
            coverage_warnings = list(dict.fromkeys(result['coverage'].get('warnings', []) + vlans['coverage'].get('warnings', [])))
            if coverage_warnings:
                result['coverage']['warnings'] = coverage_warnings
            result['coverage']['missing_fields'] = sorted({k for row in result['records'] for k, v in row.items() if v is None})
            if not result['coverage']['missing_fields']:
                result['warnings'] = [warning for warning in result['warnings'] if warning != 'fields_absent_in_catalogue_output']
            result['coverage']['complete'] = vlans['coverage']['complete'] and result['status'] in ('ok', 'empty') and not result['coverage']['missing_fields'] and not result['unparsed'] and not result['coverage'].get('warnings')
        else:
            result['warnings'].append('vlan_tag_join_not_enabled')
    # The filter is applied after the full capture has been classified. A bad
    # line outside the matching rows must still make coverage incomplete.
    result['records'] = [row for row in result['records'] if all(row.get(k) == v for k, v in filters.items())]
    if table == 'route' and ip is not None and query is not None and not parameters:
        result['records'] = tables.longest_prefix(result['records'], tables.literal(ip)[1])
    return switch_pages.page({'target': auth.alias, **result, 'ok': result['status'] in ('ok', 'empty', 'not_applicable')},
                             ('records', 'unparsed'), limit=limit, offset=offset, max_bytes=max_bytes)


# The identity supplement that prints the host name where `show version` does not (EXOS sysName).
_HOSTNAME_SUPPLEMENTS = {"extreme_exos": "switch", "arista_eos": "hostname"}


def _locate_endpoint_run(auths, endpoint, progress=lambda result: None, *, deadline=None):
    from . import locate, tables, port_vlan
    budget = locate.Budget()
    if deadline is not None:
        budget.deadline = min(budget.deadline, deadline)
    verified = {}
    identified = {}
    target_reads = dict.fromkeys((a.alias for a in auths), 0)
    import threading
    lanes = {(a.host, a.port): threading.RLock() for a in auths}

    def serialized(function):
        @wraps(function)
        def wrapped(auth, *args, **kwargs):
            with lanes[(auth.host, auth.port)]:
                token = _LOCATE_BUDGET.set(budget)
                try:
                    budget.remaining()
                    return function(auth, *args, **kwargs)
                finally:
                    _LOCATE_BUDGET.reset(token)
        return wrapped

    def device(auth, profile, command):
        with budget.lanes:
            with budget.lock:
                if target_reads[auth.alias] >= auth.locate_read_limit:
                    raise locate.LimitReached("target_read_limit")
                budget.take()
                target_reads[auth.alias] += 1
            return read_from_device(auth, profile, command)

    def read(auth, table, query, parameters, ip):
        profile = auth.ssh_platform
        if table == 'port_vlan' and profile == 'fortinet':
            from . import fortiswitch_ports
            return fortiswitch_ports.read_vlan(auth, parameters,
                lambda q, t, p: locate_endpoint_read(auth, profile, q, t, p))
        if table == 'port_vlan':
            return port_vlan.read(auth, lambda q, t: locate_endpoint_read(auth, profile, q, t, None))
        if query is None:
            query, parameters, _ = tables.request(profile, table, ip=ip, device_types=auth.device_types)
        if query is None:
            return tables.parse(profile, table, None, '', status='unsupported')
        return locate_endpoint_read(auth, profile, query, table, parameters)

    @serialized
    @_audit_device_call
    def locate_endpoint_read(auth, platform, query, table, parameters):
        profile = platform
        # Both target policy and fixed catalogue rendering apply to every read,
        # including managed-switch serials. Learned data is never a command slot.
        try:
            profile, command, _ = _ssh_read_state(auth, profile, query, parameters)
        except PolicyScopeError:
            return tables.parse(profile, table, query, '', status='permission_denied')
        try:
            if auth.alias not in verified:
                verified[auth.alias] = (profile, _check_identity(auth, profile, device)[2])
            rc, output = device(auth, profile, command)
            cleaned = _redact_output(output, auth)
            if len(cleaned.encode()) > _SSH_CAPTURE_MAX_BYTES:
                return tables.parse(profile, table, query, '', status='truncated')
            cleaned = _fortiswitch_configuration_output(profile, query, parameters, cleaned)
            state = normalization.output_status(cleaned, rc=rc, profile=profile, command=command)
            if table == 'identity':
                # An identity supplement: its text only yields the host name an LLDP neighbour is compared with.
                return {'status': 'ok' if state == 'ok' and not _cli_refused(profile, cleaned) else state, 'text': cleaned}
            refused = _cli_refused(profile, cleaned)
            if refused and state == 'ok':
                state = 'permission_denied'
            result = tables.parse(profile, table, query, cleaned, rc=rc, status=state, command=command, refused=refused)
            if state == 'transport_error':
                result.update(_transport_failure('exit_status'))
            if normalization.exos_exit_250(profile, rc, cleaned, command=command):
                result['warnings'].append('exit_status_250')
            return result
        except locate.LimitReached:
            raise
        except _ProductIdentityError as exc:
            result = tables.parse(profile, table, query, '', status='unparsed')
            result['warnings'].append(exc.reason)
            return result
        except Exception as exc:
            return _transport_result(profile, table, query, exc)

    @serialized
    def identify(auth):
        """Host names of a target this run has already verified: from its identity output, else from the
        catalogue supplement that prints it, when enabled (one more counted, audited read)."""
        if auth.alias not in verified:
            return ()
        if auth.alias in identified:
            return identified[auth.alias]
        profile, status = verified[auth.alias]
        query = _HOSTNAME_SUPPLEMENTS.get(profile)
        try:
            hostname = normalization.parse_identity(profile, status)["hostname"] if profile in normalization.IDENTITY_PROFILES else None
            if hostname is None and query in auth.enabled_queries:
                found = locate_endpoint_read(auth, profile, query, 'identity', None)
                record = dict.fromkeys(normalization.IDENTITY_FIELDS)
                if found['status'] == 'ok':
                    normalization.supplement_identity(record, query, found['text'])
                hostname = record['hostname']
        except normalization.IdentityError:
            # An identity that names no single host identifies no LLDP neighbour.
            hostname = None
        identified[auth.alias] = (hostname,) if hostname else ()
        return identified[auth.alias]

    return locate.run(auths, endpoint, read, budget, progress, identify)


def locate_endpoint(targets: list[str], endpoint: str, auth_context: str) -> dict[str, Any]:
    """Credentials travel over a private pipe to a separately bounded worker."""
    from . import endpoint_worker, tables
    tables.literal(endpoint)
    # Decode before spawning: an invalid or incomplete injected scope cannot
    # trigger a worker, and the worker repeats this check before device access.
    endpoint_worker.decode(targets, auth_context)
    return endpoint_worker.call(targets, endpoint, auth_context)
