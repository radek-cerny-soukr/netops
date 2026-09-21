"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

import asyncio
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
from netops_core import prompt as core_prompt
from netops_core import session as core_session
from netops_core import sftp as core_sftp
from netops_core import ssh as core_ssh

from .audit import AuditPostOperationError, AuditPreflightError, record
from .auth import (
    LEGACY_SSH_PROFILES, AuthenticationContextError, EgressScopeError,
    LegacySshProfileRequired, TargetAuth,
)
from .read_policy import READ_QUERIES, normalize_platform, render_read_query
from .sanitize import digest_text, redact


_LEGACY_SSH_HOST_KEY_ALGS = ("ssh-rsa",)
_SSH_LEGACY_PROFILES: dict[str | None, tuple[str, ...]] = {
    None: (),
    "rsa-sha1": _LEGACY_SSH_HOST_KEY_ALGS,
}
_OPENSSH_LEGACY_OPTIONS = ("HostKeyAlgorithms", "PubkeyAcceptedAlgorithms")
if (
    set(_SSH_LEGACY_PROFILES) != {None, *LEGACY_SSH_PROFILES}
    or _SSH_LEGACY_PROFILES[None]
    or any(
        set(enabled) - set(_LEGACY_SSH_HOST_KEY_ALGS)
        for enabled in _SSH_LEGACY_PROFILES.values()
    )
    or tuple(core_legacy_ssh.PROFILES) != LEGACY_SSH_PROFILES
    or any(
        core_legacy_ssh.openssh_options(profile)
        != tuple(f"{option}=+{name}" for option in _OPENSSH_LEGACY_OPTIONS for name in enabled)
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
}
_PLATFORM_PREAMBLE: dict[str, tuple[str, ...]] = {}
_RUCKUS_LOGIN_PROMPT = b"Please login:"
_RUCKUS_PASSWORD_PROMPT = b"assword"
_RUCKUS_USER_PROMPT = b"ruckus>"
_RUCKUS_ENABLE_PROMPT = b"ruckus#"
_RUCKUS_ENABLE_COMMAND = "enable"
_CONNECTION_SPACING_SECONDS: dict[str, float] = {"fortinet": 5.0}
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
    """Read the offered host keys with ssh-keyscan and keep the one matching the pin.

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
            )
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
        f"for that device alone. SHA-1 key exchange has no profile and stays disabled."
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
) -> core_ssh.Result:
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
                timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
            )
    except core_ssh.SshError as exc:
        _forget_host_key_line(address, auth.port)
        raise _exec_failure(auth, exc) from exc


def _exec_read(auth: TargetAuth, platform: str, command: str) -> tuple[int | None, str]:
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    credential = DeviceCredential(auth)
    for preamble in _PLATFORM_PREAMBLE.get(platform, ()):
        _exec_command(auth, address, known_hosts_line, credential, preamble, platform)
    result = _exec_command(auth, address, known_hosts_line, credential, command, platform)
    return result.rc, core_prompt.cleaned(
        result.stdout.decode("utf-8", "replace"), platform,
    )


def _pty_body(data: bytes, command: str, prompt: bytes) -> str:
    text = data.decode("utf-8", "replace").replace("\r", "")
    marker = prompt.decode("ascii")
    if text.endswith(marker):
        text = text[: -len(marker)]
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command:
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


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


def read_from_device(
    auth: TargetAuth, platform: str, command: str,
) -> tuple[int | None, str]:
    normalized = normalize_platform(platform)
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    if _SSH_TRANSPORTS[normalized] == _TRANSPORT_PTY:
        return _pty_read(auth, normalized, command)
    return _exec_read(auth, normalized, command)


_CLI_REFUSALS = {
    "fortinet": re.compile(
        r"(?mi)^[ \t]*(?:Command fail\.(?:[ \t]+Return code[ \t]+-?[0-9]+)?"
        r"|command parse error before[^\r\n]*|Unknown action[ \t]+[0-9]+)[ \t]*\r?$"
    ),
    "extreme_exos": re.compile(
        r"(?mi)^[ \t]*(?:This user does not have permissions for this command\."
        r"|%%[ \t]+(?:Invalid input detected|Unrecognized command|Incomplete command|Ambiguous command)[^\r\n]*)[ \t]*\r?$"
    ),
}


def _cli_refused(platform: str, output: str) -> bool:
    pattern = _CLI_REFUSALS.get(platform)
    return pattern is not None and pattern.search(output) is not None


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


def _audit_fields(arguments: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for name in ("port", "count", "offset", "max_bytes"):
        value = arguments.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            fields[name] = value
    for name in ("use_tls", "acknowledge_unencrypted"):
        value = arguments.get(name)
        if isinstance(value, bool):
            fields[name if name != "acknowledge_unencrypted" else "plaintext_acknowledged"] = value
    if isinstance(arguments.get("oids"), list):
        fields["item_count"] = len(arguments["oids"])
    for name in ("query", "platform"):
        value = arguments.get(name)
        if isinstance(value, str):
            fields[name] = value
    if isinstance(fields.get("platform"), str):
        try:
            fields["platform"] = normalize_platform(fields["platform"])
        except ValueError:
            pass
    path = arguments.get("remote_path")
    if isinstance(path, str):
        fields["path_sha256"] = digest_text(path)
    for name in (
        "query", "platform", "total_bytes", "returned_bytes", "pagination_source",
        "transport", "rc",
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


def _audit_device_call(function: Any) -> Any:
    signature = inspect.signature(function)
    event = function.__name__

    def preflight(auth: TargetAuth, arguments: dict[str, Any]) -> str:
        try:
            operation_id = f"op_{secrets.token_hex(16)}"
            fields = _audit_fields(arguments, {})
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
        fields = _audit_fields(arguments, result or {})
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


@_audit_device_call
def ssh_read(
    auth: TargetAuth,
    platform: str,
    query: str,
    parameters: dict[str, str] | None,
    offset: int,
    max_bytes: int,
) -> dict[str, Any]:
    if not isinstance(platform, str) or not isinstance(query, str):
        raise ValueError("platform and query must be strings")
    offset, max_bytes = _validate_pagination(offset, max_bytes)
    normalized = auth.require_ssh_query(platform, query)
    normalized, command = render_read_query(normalized, query, parameters, auth.read_inventory)
    transport = _SSH_TRANSPORTS[normalized]
    cache_key = _ssh_cache_key(auth, normalized, query, parameters)
    pagination_source = "fresh"
    if offset:
        cached = _load_cached_ssh_output(cache_key)
        if cached is None:
            raise ValueError("SSH pagination state expired; restart at offset 0")
        rc, cleaned = cached
        pagination_source = "cached"
    else:
        try:
            rc, output = read_from_device(auth, normalized, command)
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
    if _cli_refused(normalized, cleaned):
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "device_cli_error",
            "error": "The device CLI refused the command; check its supported features and account permissions",
            "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
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
    context = ssl.create_default_context()
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
        return {"ok": False, "target": auth.alias, "port": port, "error": _safe_error(exc, auth)}
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
        "verified_by_system_trust": True,
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
    community = auth.require_snmp_community()
    auth.require_udp_port(port)
    address = _resolve_target_ipv4(auth)[0]

    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, get_cmd,
    )

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((address, port), timeout=2, retries=1)
    try:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            CommunityData(community, mpModel=1),
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
            {"oid": name.prettyPrint(), "value": redact(value.prettyPrint(), auth.secrets)}
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
    answer["modified_ls"] = entry.modified_ls
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
PLAIN_FTP_WARNING = (
    "WARNING: Plain FTP is unencrypted. Credentials and directory listing data "
    "are transmitted in plaintext."
)


def _ftps_context(alias: str) -> tuple[ssl.SSLContext, str | None]:
    try:
        configured = json.loads(TLS_PINS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("FTPS pin configuration is invalid") from exc
    entry = configured.get(alias)
    if entry is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    if not isinstance(entry, dict):
        raise RuntimeError("FTPS pin entry is invalid")
    digest = str(entry.get("sha256", "")).lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeError("FTPS pin digest is invalid")
    certificate = Path(str(entry.get("certificate", ""))).resolve()
    certificate_root = TLS_CERT_DIR.resolve()
    if certificate_root not in certificate.parents or not certificate.is_file():
        raise RuntimeError("FTPS pin certificate is unavailable")
    context = ssl.create_default_context(cafile=str(certificate))
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
    control_address = _resolve_target_ipv4(auth)[0]
    pin_digest: str | None = None
    security_warning: str | None = None
    if use_tls:
        context, pin_digest = _ftps_context(auth.alias)
        client: ftplib.FTP = ftplib.FTP_TLS(timeout=30, context=context)
    else:
        security_warning = PLAIN_FTP_WARNING
        client = ftplib.FTP(timeout=30)
    _install_ftp_passive_guard(client, auth, control_address)
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
                peer = client.sock.getpeercert(binary_form=True)
                actual = hashlib.sha256(peer or b"").hexdigest()
                if not peer or not hmac.compare_digest(actual, pin_digest):
                    raise ssl.SSLCertVerificationError("pinned FTPS certificate mismatch")
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
