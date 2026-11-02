"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

import asyncio
from datetime import datetime
from contextlib import contextmanager
from functools import wraps
import inspect
import ftplib
import ipaddress
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import threading
import ssl
import time
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

from .audit import AuditPostOperationError, AuditPreflightError, record
from .auth import (
    LEGACY_SSH_PROFILES, AuthenticationContextError, EgressScopeError,
    LegacySshProfileRequired, PolicyScopeError, TargetAuth,
)
from .inventory import unique_object
from .read_policy import READ_QUERIES, normalize_platform, render_read_query
from .sanitize import digest_text, redact
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
_SSH_CACHE_TTL_SECONDS = 120.0
_SSH_CACHE_MAX_ENTRIES = 8
_SSH_CAPTURE_MAX_BYTES = 2_000_000
_SSH_PAGE_CACHE: dict[tuple[Any, ...], tuple[float, int | None, str]] = {}
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


@contextmanager
def _paced_connection(address: str, port: int, platform: str | None):
    """Queue one SSH-family connection to a device behind the platform's spacing.

    Every device has exactly one lane: connections to it never run in parallel,
    and each one waits until `spacing(platform)` seconds have passed since the
    previous connection to that same (address, port) started. Different devices
    never wait on each other. The lane's lock is held for the whole connection,
    not only for the wait, so a slow connection also delays the next one.
    """
    spacing = _CONNECTION_SPACING_SECONDS.get(platform, 0.0)
    lane = _lane_for(address, port)
    with lane.lock:
        if lane.last_started is not None:
            wait = lane.last_started + spacing - _now()
            if wait > 0:
                _sleep(wait)
        lane.last_started = _now()
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
            line = core_hostkey.scan(
                target, auth.port, auth.host_key_fingerprint, _HOST_KEY_SCAN_TIMEOUT_SECONDS,
                legacy=auth.legacy_ssh,
            )
    except core_hostkey.HostKeyUnavailable as exc:
        raise AuthenticationContextError(
            f'SSH host-key verification unavailable for target "{auth.alias}"; '
            'check reachability, SSH port and key negotiation before changing the pinned key'
        ) from exc
    except core_hostkey.HostKeyError as exc:
        raise AuthenticationContextError(
            f'target "{auth.alias}" did not offer the pinned SSH host key'
        ) from exc
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
    if auth.legacy_ssh is None and core_ssh.NEGOTIATION_MARKER in getattr(exc, "said", ""):
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
                timeout_seconds=limits.total_seconds if stdout_consumer is not None else _SSH_READ_TIMEOUT_SECONDS,
                **stream_options,
            )
    except (core_ssh.OutputLimitError, core_ssh.OutputConsumerError):
        raise
    except core_ssh.SshError as exc:
        _forget_host_key_line(address, auth.port)
        raise _exec_failure(auth, exc) from exc


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
    return result.rc, core_prompt.cleaned(
        result.stdout.decode("utf-8", "replace"), platform,
    )


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


def read_from_device(
    auth: TargetAuth, platform: str, command: str, *, stdout_consumer=None, prompt=False,
) -> tuple[int | None, str]:
    normalized = normalize_platform(platform)
    if stdout_consumer is not None and (normalized not in ('fortinet', 'fortiadc') or not callable(stdout_consumer)):
        raise ValueError('streaming is supported only for FortiOS and FortiADC exec reads')
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
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


def _cli_refused(platform: str, output: str) -> bool:
    pattern = _CLI_REFUSALS.get(platform)
    return pattern is not None and pattern.search(output) is not None


_IDENTITY_COMMAND = "get system status"
_IDENTITY_PLATFORMS = frozenset({"fortinet", "fortiadc"})


class _ProductIdentityError(Exception):
    def __init__(self, platform: str, rc: int | None) -> None:
        super().__init__(
            "The live device did not identify itself as the selected product "
            f"({core_platforms.normalize(platform)}); no query output was returned"
        )
        self.rc = rc


def _require_product(platform: str, rc: int | None, status: str) -> None:
    try:
        if rc not in (0, None) or _cli_refused(platform, status):
            raise core_platforms.PlatformError("the identity command was refused")
        core_platforms.require_identity(platform, status)
    except core_platforms.PlatformError:
        raise _ProductIdentityError(platform, rc) from None


def _verified_read(auth: TargetAuth, platform: str, command: str, prompt: bool = False) -> tuple[int | None, str]:
    if platform not in _IDENTITY_PLATFORMS:
        return read_from_device(auth, platform, command)
    rc, status = read_from_device(auth, platform, _IDENTITY_COMMAND)
    _require_product(platform, rc, status)
    if command == _IDENTITY_COMMAND:
        return rc, status
    return read_from_device(auth, platform, command, **({"prompt": True} if prompt else {}))


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


def _page_text(text: str, offset: int, max_bytes: int) -> dict[str, Any]:
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


INVALID_AUDIT_VALUE = "<invalid>"


def _audit_fields(arguments: dict[str, Any], result: dict[str, Any],
                  ssh_platform: str | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {}
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
                parsed = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if str(parsed) == value and not parsed.is_multicast and not parsed.is_unspecified and int(parsed) != 4294967295:
                fields["destination_address" if name == "address" else "source_address"] = value
    for name in ("source_port", "destination_port"):
        value = arguments.get(name)
        if type(value) is int and 0 <= value <= 65535:
            fields[name] = value
    value = arguments.get("protocol")
    if type(value) is int and value in (6,17):
        fields["protocol"] = value
    for name in ("since", "until"):
        if name in arguments:
            value = arguments[name]
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S") if isinstance(value, str) else None
            except ValueError:
                parsed = None
            fields[name] = (value if parsed is not None and
                            parsed.strftime("%Y-%m-%d %H:%M:%S") == value else INVALID_AUDIT_VALUE)
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
    return message if _load_cached_ssh_output(key) is None else None


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
                raise ValueError(missing)
            operation_id = preflight(auth, arguments)
            try:
                result = await function(auth, *args, **kwargs)
            except Exception as exc:
                complete(
                    auth, arguments, "failed", operation_id,
                    detail=type(exc).__name__,
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
            raise ValueError(missing)
        operation_id = preflight(auth, arguments)
        try:
            result = function(auth, *args, **kwargs)
        except Exception as exc:
            complete(
                auth, arguments, "failed", operation_id,
                detail=type(exc).__name__,
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


def _load_cached_ssh_output(key: tuple[Any, ...]) -> tuple[int | None, str] | None:
    now = time.monotonic()
    with _SSH_CACHE_LOCK:
        for candidate, (expires, _, _) in list(_SSH_PAGE_CACHE.items()):
            if expires <= now:
                _SSH_PAGE_CACHE.pop(candidate, None)
        cached = _SSH_PAGE_CACHE.get(key)
        return (cached[1], cached[2]) if cached else None


def _store_cached_ssh_output(key: tuple[Any, ...], rc: int | None, output: str) -> None:
    with _SSH_CACHE_LOCK:
        if len(_SSH_PAGE_CACHE) >= _SSH_CACHE_MAX_ENTRIES:
            oldest = min(_SSH_PAGE_CACHE, key=lambda item: _SSH_PAGE_CACHE[item][0])
            _SSH_PAGE_CACHE.pop(oldest, None)
        _SSH_PAGE_CACHE[key] = (time.monotonic() + _SSH_CACHE_TTL_SECONDS, rc, output)


def _ssh_read_state(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
) -> tuple[str, str, tuple[Any, ...]]:
    normalized = auth.require_ssh_query(platform, query)
    normalized, command = render_read_query(normalized, query, parameters, auth.read_inventory)
    return normalized, command, _ssh_cache_key(auth, normalized, query, parameters)


@_audit_device_call
def ssh_read(
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
    prompt = entry is not None and entry.pty
    transport = _TRANSPORT_PTY if prompt else _SSH_TRANSPORTS[normalized]
    pagination_source = "fresh"
    if offset:
        if not _named_snapshot(content_sha256):
            raise ValueError(_SSH_SNAPSHOT_UNNAMED)
        cached = _load_cached_ssh_output((*cache_key, content_sha256))
        if cached is None:
            raise ValueError("SSH pagination state expired; restart at offset 0")
        rc, cleaned = cached
        pagination_source = "cached"
    else:
        try:
            rc, output = _verified_read(auth, normalized, command, prompt)
        except _ProductIdentityError as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": exc.rc,
                "error_code": "product_identity", "error": str(exc),
            }
        except Exception as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport,
                "error": _safe_error(exc, auth),
            }
        cleaned = redact(output, auth.secrets)
        if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc,
                "error": "SSH output exceeds the 2000000-byte safety cap",
            }
    cache_key = (*cache_key, hashlib.sha256(cleaned.encode("utf-8")).hexdigest())
    lookup_route_failed = (
        normalized == "fortinet" and query in {"policy_lookup_ipv4", "policy_lookup_ipv6"}
        and re.search(r"(?m)^[ \t]*Error code: err_route[ \t]*\r?$", cleaned) is not None
    )
    mclag = normalized == "fortinet" and query in MCLAG_QUERIES
    if (_cli_refused(normalized, cleaned) and not (mclag and mclag_not_supported(query, cleaned))) or lookup_route_failed:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "device_cli_error",
            "error": ("Policy lookup could not resolve a route for the supplied flow" if lookup_route_failed else
                      "The device CLI refused the command; check its supported features and account permissions"),
            "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
        }
    if not cleaned.strip() and not (entry is not None and entry.empty_allowed):
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "empty",
            "error": "The device returned no output for this query; no result was read",
        }
    page = _page_text(cleaned, offset, max_bytes)
    if page["next_offset"] is not None:
        if offset == 0:
            _store_cached_ssh_output(cache_key, rc, cleaned)
    else:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
    return {
        "ok": True, "target": auth.alias, "platform": normalized, "query": query,
        "transport": transport, "rc": rc,
        "pagination_source": pagination_source, **page,
        **({"mclag": mclag_summarize(query, cleaned, parameters)} if mclag else {}),
        **({"dhcp_bindings": dhcp_bindings_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == DHCP_BINDINGS_QUERY else {}),
    }


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


def _fortiadc_logs(auth, recipe, address, interface, count, timeout, max_bytes, vdom, since, until):
    from . import fortiadc_diagnostics as diagnostics
    if vdom is not None or since is not None or until is not None:
        raise ValueError(f"{recipe} does not accept VDOM or time-window parameters")
    diagnostics.validate(recipe, address, interface, count, timeout, max_bytes)
    diagnostics.authorize(auth, recipe, address)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        target_address = _resolve_target_ipv4(auth)[0]
        known_hosts = host_key_line(auth, target_address, "fortiadc")
        try:
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
        except Exception:
            raise ValueError(f"bounded FortiADC {recipe} read failed; the session was closed") from None

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
                        count: int = 3, timeout: int = 5, max_bytes: int = 16000, vdom: str | None = None,
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
        target_address = _resolve_target_ipv4(auth)[0]
        known_hosts = host_key_line(auth, target_address, "fortinet")
        try:
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
            raise ValueError("bounded FortiOS diagnostic failed; the session was closed") from None
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
        target_address = _resolve_target_ipv4(auth)[0]
        known_hosts = host_key_line(auth, target_address, "fortiadc")
        try:
            with _paced_connection(target_address, auth.port, "fortiadc"):
                with core_session.Session(target_address, auth.port, auth.login, DeviceCredential(auth),
                                          known_hosts, legacy_ssh=auth.legacy_ssh,
                                          timeout_seconds=30 + timeout, capture_max_bytes=131072) as session:
                    shell = _FortiosDiagnosticShell(session, "fortiadc")
                    raw, timed_out, identity = diagnostics.adc_run(shell, recipe, address, timeout, count, health_check)
        except configuration.UnsupportedConfigurationFirmware as error:
            raise diagnostics.UnsupportedPlatform("config_platform_not_supported: FortiADC " +
                                                  " build ".join(error.detected) + " is not measured") from None
        except Exception:
            raise ValueError("bounded FortiADC diagnostic failed; the session was closed") from None
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
def triage_vpn_read(auth: TargetAuth, platform: str, query: str) -> dict[str, Any]:
    return _triage_read(auth, platform, query)


def _triage_read(auth: TargetAuth, platform: str, query: str,
                 parameters: dict[str, str] | None = None) -> dict[str, Any]:
    normalized, command, _ = _ssh_read_state(auth, platform, query, parameters)
    try:
        rc, output = read_from_device(auth, normalized, command)
    except Exception as exc:
        timed_out = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower() or "timeout" in str(exc).lower()
        return {"ok": False, "platform": normalized, "query": query,
                "reason": "timeout" if timed_out else "device_cli_error"}
    cleaned = redact(output, auth.secrets)
    if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "truncated"}
    if rc not in (0, None) or _cli_refused(normalized, cleaned):
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "device_cli_error"}
    return {"ok": True, "platform": normalized, "query": query, "rc": rc,
            "content_sha256": digest_text(cleaned), "total_bytes": len(cleaned.encode("utf-8")), "text": cleaned}


@_audit_device_call
def triage_health(auth: TargetAuth) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_health as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_health supports FortiOS targets only")

    def read(query: str) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    result = triage.run(read, lambda: datetime.now(timezone.utc))
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

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    result = triage.run(read, lambda: datetime.now(timezone.utc), address)
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_vpn(auth: TargetAuth, tunnel: str) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_vpn as triage
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_vpn supports FortiOS targets only")
    if not triage.valid_tunnel(tunnel):
        raise ValueError("invalid_argument: tunnel must match [A-Za-z0-9][A-Za-z0-9_.-]{0,34}")

    def read(query: str) -> dict[str, Any]:
        try:
            return triage_vpn_read(auth, "fortinet", query)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    result = triage.run(read, lambda: datetime.now(timezone.utc), tunnel)
    return {"target": auth.alias, **result}


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
    library=reader.binding(auth)
    keys=[] if owners is None else owners
    reader.selectors(auth,library,path,view,vdom,keys)
    cache_key=_schema_cache_key(auth,library,path,view,vdom,keys)
    if offset:
        if not _named_snapshot(content_sha256):
            raise ValueError(_SCHEMA_SNAPSHOT_UNNAMED)
        cached=_load_cached_ssh_output((*cache_key,content_sha256))
        if cached is None:
            raise ValueError("schema pagination state expired; restart at offset 0")
        rc,cleaned=cached
        source="cached"
    else:
        try:
            rc,status=read_from_device(auth,"fortinet","get system status")
        except Exception:
            raise ValueError("SSH schema identity read failed") from None
        if rc not in (0,None) or _cli_refused("fortinet",status):
            raise ValueError("the device refused the identity check")
        current_vdom=reader.verify_status(library,status)
        try:
            rc,raw=read_from_device(auth,"fortinet","show full-configuration")
        except Exception:
            raise ValueError("SSH schema snapshot read failed") from None
        if rc not in (0,None) or _cli_refused("fortinet",raw):
            raise ValueError("the device refused the schema snapshot")
        report=reader.snapshot(library,raw,path,view,vdom,keys,auth.secrets,current_vdom=current_vdom)
        cleaned=json.dumps(report,ensure_ascii=False,separators=(",",":"))
        if len(cleaned.encode("utf-8"))>_SSH_CAPTURE_MAX_BYTES:
            raise ValueError("schema result exceeds its safety cap")
        source="fresh"
    page=_page_text(cleaned,offset,max_bytes)
    cache_key=(*cache_key,page["content_sha256"])
    if page["next_offset"] is not None:
        if offset==0:_store_cached_ssh_output(cache_key,rc,cleaned)
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
_CONTINUATIONS = {
    "ssh_read": (
        lambda auth, arguments: _ssh_read_state(
            auth, arguments["platform"], arguments["query"], arguments["parameters"],
        )[2],
        "SSH pagination state expired; restart at offset 0",
        _SSH_SNAPSHOT_UNNAMED,
    ),
    "schema_read": (
        _schema_continuation_key,
        "schema pagination state expired; restart at offset 0",
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
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
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
            "ok": False, "target": auth.alias, "port": port,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": _safe_error(exc, auth),
        }
    return {
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
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
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
        return {
            "ok": False, "target": auth.alias, "port": port, "trust": trust,
            "error": _safe_error(exc, auth),
        }
    not_after = cert.get("notAfter")
    days_remaining = None
    if isinstance(not_after, str):
        days_remaining = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    return {
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
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}

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
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    finally:
        engine.close_dispatcher()
    if error_indication or error_status:
        failure = error_indication or error_status.prettyPrint()
        return {"ok": False, "target": auth.alias, "error": redact(failure, auth.secrets)}
    return {
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
    if redaction == 'full':
        return _full_config_read(auth, platform, section, include_all, snapshot_id, offset, limit, include_defaults,
                                 view)
    if platform == 'fortiadc' or include_defaults:
        raise ValueError('config_platform_not_supported: full redaction mode required')
    command = configuration.read_command(section, include_all)
    configuration.page_arguments(offset, limit)
    with configuration.capture(auth.configuration_limits,
                               target=configuration.scope(auth, 'fortiadc' if platform == 'fortiadc' else 'fortios')):
        if snapshot_id:
            capture = configuration.get_snapshot(auth, snapshot_id, section)
            text, count, firmware, identity = capture.text, capture.redacted_count, capture.firmware, snapshot_id
        else:
            if snapshot_id != '' or offset != 0:
                raise ValueError('a nonzero page offset requires an existing snapshot')
            try:
                identity_rc, status = read_from_device(auth, 'fortinet', 'get system status')
            except Exception:
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
            except core_ssh.OutputLimitError:
                raise ValueError('configuration capture-limit-exceeded; output withheld') from None
            except core_ssh.OutputConsumerError:
                if capture.budget_refusal is not None:
                    raise configuration.ConfigurationBudgetError(capture.budget_refusal) from None
                raise ValueError('configuration redaction-unverifiable; output withheld') from None
            except configuration.ConfigurationBudgetError:
                raise
            except configuration.ConfigurationRedactionError as exc:
                category = 'capture-limit-exceeded' if exc.reason == 'capture-limit-exceeded' else 'read failed'
                raise ValueError('configuration ' + category + '; output withheld') from None
            except Exception:
                raise ValueError('configuration read failed; output withheld') from None
            finally:
                capture.close()
            identity = configuration.store(auth, text, hidden, count, section, firmware)
        capture = hidden = None
        try:
            view_fields = _filtered_view(configuration, identity, view, offset, limit,
                                         lambda: configuration.get_snapshot(auth, identity, section))
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


def _filtered_view(configuration, identity, view, offset, limit, lookup):
    contains, context, content_sha256, filter_sha256 = view
    fingerprint = configuration.filter_digest(identity, contains, context)
    if filter_sha256 is not None and not hmac.compare_digest(filter_sha256, fingerprint):
        raise ValueError('configuration filter changed; restart at offset 0')
    filtered, total_lines, matched_lines = configuration.filtered_snapshot(lookup, identity, contains, context, offset)
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
            except Exception:
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
                except ValueError:
                    raise configuration.ConfigurationRedactionError('redaction-unverifiable') from None
                except Exception:
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
                                                        include_defaults=include_defaults))
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
    try:
        rc, status = read_from_device(auth, "fortiadc", _IDENTITY_COMMAND)
        if rc not in (0, None) or _cli_refused("fortiadc", status):
            raise ValueError("identity read refused")
        _, identity = config_fortiadc.verify_identity(status)
    except configuration.UnsupportedConfigurationFirmware:
        raise ValueError("config_platform_not_supported: triage_slb requires FortiADC 7.6.7 build 0676") from None
    except Exception:
        raise ValueError("triage identity-unverifiable; nothing else was read") from None
    status = None
    missing: list[dict[str, Any]] = []
    sources: dict[str, dict[str, Any]] = {}
    executed: set[str] = set()
    chain: dict[str, Any] = {"virtual_server": virtual_server, "vdom": vdom}

    def miss(step: str, reason: str, detail: str | None = None) -> None:
        missing.append({"step": step, "reason": reason, **({"detail": detail} if detail else {})})

    def config_step(step: str, section: str, parser, defaults: bool = True):
        try:
            result = config_read(auth, "fortiadc", section, redaction="full", include_defaults=defaults)
        except Exception as exc:
            miss(step, _triage_failure(exc), str(exc).split(";")[0][:120])
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
        try:
            result = ssh_read(auth, "fortiadc", query, parameters, 0, 48_000)
        except Exception as exc:
            miss(step, _triage_failure(exc))
            return None
        if result.get("ok") is not True:
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
    findings, hypotheses, next_steps = rules.evaluate(chain, sources, auth.alias)
    next_steps = [step for step in next_steps if _adc_step_permitted(auth, step["arguments"])]
    checked = sorted(executed)
    return {
        "ok": True, "target": auth.alias, "platform": "fortiadc", "identity": identity,
        "started_at": started, "finished_at": _triage_now(),
        "virtual_server": virtual_server, "vdom": vdom, "chain": chain,
        "findings": findings, "hypotheses": hypotheses, "next_steps": next_steps,
        "missing": missing, "checked": checked,
        "verdict": rules.verdict(findings, missing, executed),
    }
