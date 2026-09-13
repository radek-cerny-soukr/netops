"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from functools import wraps
import inspect
from datetime import datetime, timezone
import ftplib
import ipaddress
import hashlib
import hmac
import json
import math
import os
import tempfile
from pathlib import Path, PurePosixPath
import secrets
import socket
import threading
import ssl
import time
from typing import Any, Iterator

from icmplib import ping
from netmiko import ConnectHandler
from netmiko.fortinet.fortinet_ssh import FortinetSSH
from paramiko.ssh_exception import IncompatiblePeer

from .audit import AuditPostOperationError, AuditPreflightError, record
from .auth import (
    LEGACY_SSH_PROFILES, EgressScopeError, LegacySshProfileRequired, TargetAuth,
)
from .read_policy import READ_QUERIES, normalize_platform, render_read_query
from .sanitize import digest_text, redact


_WEAK_SSH_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
]
_LEGACY_SSH_HOST_KEY_ALGS = ("ssh-rsa",)
_SSH_LEGACY_PROFILES: dict[str | None, tuple[str, ...]] = {
    None: (),
    "rsa-sha1": _LEGACY_SSH_HOST_KEY_ALGS,
}
_ASYNCSSH_KEX_ALGS = "-diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
_ASYNCSSH_HOST_KEY_ALGS: dict[str | None, str] = {
    None: "-ssh-rsa",
    "rsa-sha1": "+ssh-rsa",
}
if (
    set(_SSH_LEGACY_PROFILES) != {None, *LEGACY_SSH_PROFILES}
    or set(_ASYNCSSH_HOST_KEY_ALGS) != set(_SSH_LEGACY_PROFILES)
    or _SSH_LEGACY_PROFILES[None]
    or any(
        set(enabled) - set(_LEGACY_SSH_HOST_KEY_ALGS)
        for enabled in _SSH_LEGACY_PROFILES.values()
    )
    or any(
        _ASYNCSSH_HOST_KEY_ALGS[profile]
        != ("+" if enabled else "-") + ",".join(_LEGACY_SSH_HOST_KEY_ALGS)
        for profile, enabled in _SSH_LEGACY_PROFILES.items()
    )
    or _ASYNCSSH_KEX_ALGS != "-" + ",".join(_WEAK_SSH_KEX)
):
    raise RuntimeError("SSH legacy profile mapping is incomplete or invalid")
_NETMIKO_DEVICE_TYPES = {
    "linux": "linux",
    "fortinet": "fortinet",
    "extreme_exos": "extreme_exos",
    "cisco_ios": "cisco_ios",
    "cisco_xe": "cisco_xe",
    "cisco_nxos": "cisco_nxos",
    "arista_eos": "arista_eos",
    "juniper_junos": "juniper_junos",
    "juniper_junos_els": "juniper_junos",
}
if (
    set(_NETMIKO_DEVICE_TYPES) != set(READ_QUERIES)
    or _NETMIKO_DEVICE_TYPES.get("fortinet") != "fortinet"
    or _NETMIKO_DEVICE_TYPES.get("juniper_junos_els") != "juniper_junos"
    or any(
        not isinstance(device_type, str) or not device_type
        for device_type in _NETMIKO_DEVICE_TYPES.values()
    )
):
    raise RuntimeError("Netmiko device-type mapping is incomplete or invalid")
_SSH_CACHE_TTL_SECONDS = 120.0
_SSH_CACHE_MAX_ENTRIES = 8
_SSH_CAPTURE_MAX_BYTES = 2_000_000
_SSH_PAGE_CACHE: dict[tuple[Any, ...], tuple[float, str]] = {}
_SSH_CACHE_LOCK = threading.Lock()

class ReadOnlyFortinetSSH(FortinetSSH):
    """FortiOS session setup which never enters configuration or changes paging."""

    def session_preparation(self) -> None:
        data = self._test_channel_read(pattern=f"to accept|{self.prompt_pattern}")
        if "to accept" in data:
            self.write_channel("a\r")
            self._test_channel_read(pattern=self.prompt_pattern)
        self.set_base_prompt()

    def cleanup(self, command: str = "exit") -> None:
        # Closing Paramiko directly avoids FortinetSSH's persistent paging restore.
        return None


@contextmanager
def _known_hosts_file(auth: TargetAuth) -> Iterator[str]:
    auth.require_known_hosts()
    fd, path = tempfile.mkstemp(prefix="netops-known-hosts-", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(auth.known_hosts)
        os.chmod(path, 0o600)
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


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


def _open_verified_socket(auth: TargetAuth, timeout: float = 10.0) -> socket.socket:
    address = _resolve_target_ipv4(auth)[0]
    return socket.create_connection((address, auth.port), timeout=timeout)


def _disabled_ssh_algorithms(auth: TargetAuth) -> dict[str, list[str]]:
    enabled = _SSH_LEGACY_PROFILES[auth.legacy_ssh]
    return {
        "keys": [name for name in _LEGACY_SSH_HOST_KEY_ALGS if name not in enabled],
        "kex": list(_WEAK_SSH_KEX),
    }


def _legacy_ssh_required(auth: TargetAuth) -> LegacySshProfileRequired:
    names = ", ".join(_disabled_ssh_algorithms(auth)["keys"])
    return LegacySshProfileRequired(
        f'target "{auth.alias}" offers no SSH host key or key exchange algorithm '
        f"enabled by default; for a target which offers only {names} host keys set "
        f'"legacy_ssh": "rsa-sha1" in its target-policy.json entry, which allows them '
        f"for that target alone. SHA-1 key exchange has no profile and stays disabled."
    )


def _caused_by(exc: BaseException, expected: type[BaseException]) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, expected):
            return True
        current = current.__cause__ or current.__context__
    return False


@contextmanager
def netmiko_connection(auth: TargetAuth, platform: str) -> Iterator[Any]:
    normalized = normalize_platform(platform)
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    sock = _open_verified_socket(auth)
    with _known_hosts_file(auth) as known_hosts_path:
        connection_factory = (
            ReadOnlyFortinetSSH if normalized == "fortinet" else ConnectHandler
        )
        try:
            connection = connection_factory(
                device_type=_NETMIKO_DEVICE_TYPES[normalized],
                host=auth.host,
                port=auth.port,
                username=auth.login,
                password=auth.password,
                sock=sock,
                conn_timeout=10,
                auth_timeout=12,
                banner_timeout=15,
                fast_cli=False,
                ssh_strict=True,
                system_host_keys=False,
                alt_host_keys=True,
                alt_key_file=known_hosts_path,
                disabled_algorithms=_disabled_ssh_algorithms(auth),
            )
        except BaseException as exc:
            sock.close()
            if auth.legacy_ssh is None and _caused_by(exc, IncompatiblePeer):
                raise _legacy_ssh_required(auth) from exc
            raise
        try:
            yield connection
        finally:
            connection.disconnect()
            sock.close()


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
    for name in ("port", "count", "max_hops", "offset", "max_bytes"):
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
    for name in ("query", "platform", "total_bytes", "returned_bytes", "pagination_source"):
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
                event, operation_id=operation_id, target=auth.alias, status="started",
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
                event, operation_id=operation_id, target=auth.alias,
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
                    auth, arguments, "rejected", operation_id,
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
                auth, arguments, "rejected", operation_id,
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
        hashlib.sha256(auth.password.encode("utf-8", "replace")).hexdigest(),
        platform, query, tuple(sorted((parameters or {}).items())),
    )


def _load_cached_ssh_output(key: tuple[Any, ...]) -> str | None:
    now = time.monotonic()
    with _SSH_CACHE_LOCK:
        for candidate, (expires, _) in list(_SSH_PAGE_CACHE.items()):
            if expires <= now:
                _SSH_PAGE_CACHE.pop(candidate, None)
        cached = _SSH_PAGE_CACHE.get(key)
        return cached[1] if cached else None


def _store_cached_ssh_output(key: tuple[Any, ...], output: str) -> None:
    with _SSH_CACHE_LOCK:
        if len(_SSH_PAGE_CACHE) >= _SSH_CACHE_MAX_ENTRIES:
            oldest = min(_SSH_PAGE_CACHE, key=lambda item: _SSH_PAGE_CACHE[item][0])
            _SSH_PAGE_CACHE.pop(oldest, None)
        _SSH_PAGE_CACHE[key] = (time.monotonic() + _SSH_CACHE_TTL_SECONDS, output)


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
    cache_key = _ssh_cache_key(auth, normalized, query, parameters)
    pagination_source = "fresh"
    if offset:
        cleaned = _load_cached_ssh_output(cache_key)
        if cleaned is None:
            raise ValueError("SSH pagination state expired; restart at offset 0")
        pagination_source = "cached"
    else:
        try:
            with netmiko_connection(auth, normalized) as connection:
                output = str(connection.send_command(command, read_timeout=60))
        except Exception as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "error": _safe_error(exc, auth),
            }
        cleaned = redact(output, auth.secrets)
        if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "error": "SSH output exceeds the 2000000-byte safety cap",
            }
    page = _page_text(cleaned, offset, max_bytes)
    if page["next_offset"] is not None:
        if offset == 0:
            _store_cached_ssh_output(cache_key, cleaned)
    else:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
    return {
        "ok": True, "target": auth.alias, "platform": normalized, "query": query,
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


@asynccontextmanager
async def _sftp_client(auth: TargetAuth):
    import asyncssh

    sock = await asyncio.to_thread(_open_verified_socket, auth)
    with _known_hosts_file(auth) as known_hosts_path:
        try:
            async with asyncssh.connect(
                auth.host,
                port=auth.port,
                sock=sock,
                username=auth.login,
                password=auth.password,
                client_keys=[],
                known_hosts=known_hosts_path,
                server_host_key_algs=_ASYNCSSH_HOST_KEY_ALGS[auth.legacy_ssh],
                kex_algs=_ASYNCSSH_KEX_ALGS,
                config=None,
                connect_timeout=10,
                login_timeout=15,
                keepalive_interval=15,
                keepalive_count_max=2,
            ) as connection:
                async with connection.start_sftp_client(sftp_version=3) as sftp:
                    yield sftp
        except asyncssh.KeyExchangeFailed as exc:
            if auth.legacy_ssh is None:
                raise _legacy_ssh_required(auth) from exc
            raise


@_audit_device_call
async def sftp_stat(auth: TargetAuth, remote_path: str) -> dict[str, Any]:
    path = _safe_remote_path(auth, remote_path)
    try:
        async with _sftp_client(auth) as sftp:
            attributes = await sftp.stat(path)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    size = int(attributes.size or 0)
    permissions = int(attributes.permissions or 0)
    modified = attributes.mtime
    return {
        "ok": True, "target": auth.alias, "path_sha256": digest_text(path),
        "size": size, "mode": oct(permissions & 0o7777),
        "modified_utc": datetime.fromtimestamp(modified, timezone.utc).isoformat() if modified is not None else None,
    }


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
    stage = "connect"
    try:
        client.connect(control_address, port)
        if isinstance(client, ftplib.FTP_TLS):
            client.host = auth.host
            stage = "tls_handshake"
            client.auth()
            if pin_digest is not None:
                stage = "certificate_pin"
                peer = client.sock.getpeercert(binary_form=True)
                actual = hashlib.sha256(peer or b"").hexdigest()
                if not peer or not hmac.compare_digest(actual, pin_digest):
                    raise ssl.SSLCertVerificationError("pinned FTPS certificate mismatch")
            stage = "login_over_tls"
            client.login(auth.login, auth.password)
            stage = "protect_data_channel"
            client.prot_p()
        else:
            stage = "plain_login"
            client.login(auth.login, auth.password)
        stage = "directory_list"
        names = client.nlst(remote_path)
        stage = "quit"
        client.quit()
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
    return {
        "ok": True, "target": auth.alias, "tls": use_tls,
        "transport_encrypted": use_tls,
        "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
        "security_warning": security_warning,
        "certificate_pinned": pin_digest is not None,
        "entries": [redact(PurePosixPath(name).name, auth.secrets) for name in names[:500]],
        "truncated": len(names) > 500,
    }
