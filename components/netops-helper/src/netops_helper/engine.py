"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import replace
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
import sys
import tempfile
import threading
import ssl
import time
from collections.abc import Iterable
from types import SimpleNamespace
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

from . import junos_poe
from . import fortiadc_diagnostics, progress
from .audit import AuditPostOperationError, AuditPreflightError, record
from .auth import (
    LEGACY_SSH_PROFILES, AuthenticationContextError, EgressScopeError,
    LegacySshProfileRequired, PolicyScopeError, TargetAuth,
)
from .inventory import unique_object
from .query_catalog.arista import LOG_WINDOW_QUERIES as EOS_LOG_WINDOW_QUERIES
from .query_catalog.cisco import IOS_G55_QUERIES, IOS_G57_QUERIES, IOS_MANAGEMENT_QUERIES, IOS_XE_G73_QUERIES, IOS_XE_PORT_QUERIES, IOS_XE_PROBE_QUERIES, XE_LOG_HISTORY
from .query_catalog.cisco import NXOS_G93_QUERIES, NXOS_G95_QUERIES, NXOS_G97_QUERIES, NXOS_LOG_HISTORY
from .query_catalog.extreme import LOG_HISTORY as EXOS_LOG_HISTORY
from .query_catalog.junos import (
    CONFIG_COMMANDS as JUNOS_CONFIG_COMMANDS, CONFIG_READ_QUERIES as JUNOS_CONFIG_READS,
    FILTER_BINDING_QUERY, G134_QUERIES, G135_QUERIES, LOG_HISTORY_COMMAND, LOG_HISTORY_QUERY,
    PROFILES as JUNOS_PROFILES, TESTED_G134, TRACEROUTE_MAX_HOPS,
)
from .read_policy import (
    READ_QUERIES, is_read_sequence, normalize_platform, render_read_query, render_read_sequence,
    require_fortinet_sequence,
)
from . import fortios_vdom
from . import normalization
from .sanitize import (
    FORTIOS_IPSEC_KEY_QUERIES, digest_text, eos_management_status, nxos_management_output, redact,
    redact_cisco_sa_keys, redact_exos_log_commands, redact_fortios_ipsec_keys, redact_ios_log_commands, redact_ios_management,
    redact_nxos_snmp_communities, strip_terminal_controls,
)
from . import wifi_parse
from .switch_dhcp import (DHCP_BINDINGS_QUERY, FORTIOS_LEASES_QUERY, eos_relay_counters, fortios_leases as fortios_leases_summarize,
                          summarize as dhcp_bindings_summarize)
from .fortigate_tables import USER_DEVICES_QUERY, user_devices as user_devices_summarize, \
    INTERFACE_LIST_QUERY, interface_list as interface_list_summarize
from .triage_routing import BGP_NEIGHBOR_QUERIES, ROUTE_DATABASE_QUERIES, \
    bgp_neighbors as bgp_neighbors_summarize, route_database as route_database_summarize
from . import triage_health as health_rules
from .triage_health import CRASH_LOG_QUERY, SENSORS_QUERY, crash_log as crash_log_summarize, \
    hardware_sensors as hardware_sensors_summarize
from .switch_mclag import MCLAG_QUERIES, not_supported as mclag_not_supported, summarize as mclag_summarize
from .switch_mlag_eos import payload as mlag_eos_payload
from .switch_mlag_exos import payload as mlag_exos_payload
from .switch_vpc import summarize as vpc_summarize


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
# Three 1 s probes per hop, plus time for SSH and command startup.
_JUNOS_TRACEROUTE_TIMEOUT_SECONDS = 150.0
_SSH_LOGIN_TIMEOUT_SECONDS = 20.0
_HOST_KEY_SCAN_TIMEOUT_SECONDS = 10.0
_HOST_KEY_PROBE_TIMEOUT_SECONDS = 5.0
_SSH_CACHE_TTL_SECONDS = 120.0
_SSH_CACHE_MAX_ENTRIES = 8
_SSH_CAPTURE_MAX_BYTES = 2_000_000
_EXOS_BLANK_STATUS_250_QUERIES = frozenset({"bfd_sessions", "ospf_lsdb", "ospf_neighbors"})
# Log message queries: fixed line limit applied to the redacted output before it is stored or paged.
# EXOS lists the newest message first; IOS, IOS XE, NX-OS, EOS and Junos print the oldest first, so the limit keeps the trailing lines.
_EXOS_LOG_QUERIES = frozenset({"log_messages", "log_warnings"})
_OLDEST_FIRST_LOG_PROFILES = frozenset({"cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "juniper_junos", "juniper_junos_els"})
# eos health: the EOS time-window and time-range reads are capped the same way (oldest first).
_OLDEST_FIRST_LOG_QUERIES = frozenset({"log_messages", "log_interactive_commands"}) | EOS_LOG_WINDOW_QUERIES
# Junos `| last 200 | no-more` prints the pager mark of the `last` stage in front of the final line, e.g. "---(more 100%)---  <line>".
_JUNOS_LAST_PAGER_MARK = re.compile(r"(?m)^[ \t]*---\(more 100%\)---[ \t]*\r?\n(?:[ \t]*\r?\n)?|---\(more 100%\)---[ \t]*")
_LOG_MAX_LINES = 200
_LOG_MESSAGE_START = re.compile(r"\d\d/\d\d/\d{4} \d\d:\d\d:\d\d")
# Entry: expiry, rc, redacted text, the secret set it was redacted with, identity response, log line limit,
# response labels (VDOM or Junos snapshot labels), EOS log metadata (capture status before filtering/capping and
# unreadable lines removed by filtering).
_SSH_PAGE_CACHE: dict[
    tuple[Any, ...], tuple[float, int | None, str, frozenset[str], dict | None, dict | None,
                           dict | None, tuple[str, int] | None]
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
        if _OVERVIEW_BUDGET.get() is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            while True:
                _read_timeout(1)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    _sleep(_read_timeout(0.05))
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)  # closing also releases flock after cancellation
        os.close(directory)


@contextmanager
def _connection_lock(lock):
    if _OVERVIEW_BUDGET.get() is None:
        with lock:
            yield
        return
    while not lock.acquire(timeout=_read_timeout(0.05)):
        pass
    try:
        yield
    finally:
        lock.release()


@contextmanager
def _paced_connection(address: str, port: int, platform: str | None):
    """Serialize connections per (address, port), including independent locate workers.

    The lock is held for the whole connection. The private file retains the last
    monotonic start, so FortiOS/FortiADC starts remain at least five seconds apart
    even when consecutive reads happen in different processes.
    """
    spacing = _CONNECTION_SPACING_SECONDS.get(platform, 0.0)
    lane = _lane_for(address, port)
    with _connection_lock(lane.lock), _process_connection_lane(address, port) as descriptor:
        saved = os.pread(descriptor, 9, 0)
        if saved:
            if len(saved) != 8:
                raise ValueError("SSH lane timestamp is invalid")
            previous, = struct.unpack("!d", saved)
            if not math.isfinite(previous) or previous < 0:
                raise ValueError("SSH lane timestamp is invalid")
            wait = previous + spacing - _now()
            if wait > 0:
                allowed = _read_timeout(wait)
                if _OVERVIEW_BUDGET.get() is not None and allowed < wait:
                    raise TimeoutError("connection spacing exceeds the remaining read time")
                _sleep(allowed)
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
    """Build a Fortinet pin locally, or use the cached scan for other platforms."""
    target = _resolve_target_ipv4(auth)[0] if address is None else address
    effective_platform = auth.ssh_platform if platform is None else platform
    if effective_platform in _IDENTITY_PLATFORMS or effective_platform == "fortios":
        return core_hostkey.pinned_line(target, auth.port, auth.host_key_fingerprint, getattr(auth, "host_key", None))
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


def _overview_getaddrinfo(host):
    # Killing the subprocess on timeout also stops its blocking system resolver.
    program = ("import json,socket,sys; "
               "print(json.dumps(socket.getaddrinfo(sys.argv[1], None, "
               "family=socket.AF_INET, type=socket.SOCK_STREAM)))")
    result = subprocess.run(
        [sys.executable, "-I", "-c", program, host], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=_read_timeout(_SSH_READ_TIMEOUT_SECONDS),
    )
    if result.returncode:
        raise socket.gaierror("system resolver failed")
    return json.loads(result.stdout)


def _resolve_target_ipv4(auth: TargetAuth) -> tuple[str, ...]:
    try:
        parsed = ipaddress.ip_address(auth.host)
    except ValueError:
        auth.require_dns()
        if _OVERVIEW_BUDGET.get() is not None:
            rows = _overview_getaddrinfo(auth.host)
        else:
            rows = socket.getaddrinfo(auth.host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
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


def _read_endpoint(auth, platform):
    cached = _OVERVIEW_ENDPOINT.get()
    if cached is not None and "pin" in cached:
        return cached["pin"]
    address = _resolve_target_ipv4(auth)[0]
    endpoint = address, host_key_line(auth, address, platform)
    if cached is not None:
        cached["pin"] = endpoint
    return endpoint


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


def _is_junos_traceroute(platform: str, command: str) -> bool:
    return platform in {"juniper_junos", "juniper_junos_els"} and command.startswith("traceroute ")


class _NxosTraceTimeout(TimeoutError):
    def __init__(self, output: bytes):
        super().__init__("NX-OS traceroute timed out")
        self.output = output


def _exec_command(
    auth: TargetAuth,
    address: str,
    known_hosts_line: str,
    credential: DeviceCredential,
    command: str,
    platform: str,
    stdout_consumer=None,
) -> core_ssh.Result:
    if platform in _IDENTITY_PLATFORMS:
        return _fortinet_exec(auth, platform, command, stdout_consumer)
    limits = auth.configuration_limits
    stream_options = ({"stdout_consumer": stdout_consumer, "idle_timeout_seconds": limits.idle_seconds, "capture_max_bytes": limits.all_bytes}
                      if stdout_consumer is not None else {})
    timeout = _SSH_READ_TIMEOUT_SECONDS
    trace_output = None
    if stdout_consumer is not None:
        timeout = limits.total_seconds
    elif platform == "cisco_nxos" and command.startswith(("traceroute ", "traceroute6 ")):
        # The SSH runner feeds bounded output before it stops a timed-out process.
        trace_output = bytearray()
        stream_options["stdout_consumer"] = trace_output.extend
    elif _is_junos_traceroute(platform, command):
        timeout = _JUNOS_TRACEROUTE_TIMEOUT_SECONDS
        stream_options["separate_client_log"] = True
    scope = _READ_SCOPE.get() or {}
    if (scope.get("ios_security_read") or scope.get("ios_management") or scope.get("ios_empty_allowed")
            or platform == "cisco_ios" and (scope.get("xe_detail") or scope.get("xe_log_history"))):
        # Keep device-channel stderr so a failed read cannot become an empty success.
        stream_options["suppress_login_banner"] = True
        if platform == "cisco_xe" and scope.get("ios_security_read"):
            # IOL XE can acknowledge a successful read and then close the SSH connection.
            stream_options["separate_client_log"] = True
    try:
        with _paced_connection(address, auth.port, platform):
            result = core_ssh.run_command(
                address,
                auth.port,
                auth.login,
                credential,
                known_hosts_line,
                command,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_read_timeout(timeout),
                **stream_options,
            )
            return replace(result, stdout=bytes(trace_output)) if trace_output is not None else result
    except (core_ssh.OutputLimitError, core_ssh.OutputConsumerError):
        raise
    except core_ssh.SshError as exc:
        _forget_host_key_line(address, auth.port)
        if trace_output and _transport_status(exc) == "timeout":
            raise _NxosTraceTimeout(bytes(trace_output)) from exc
        raise _exec_failure(auth, exc) from exc


# FortiOS and the normalized switch/router profiles: known secret literals are replaced
# before and after CRLF-to-LF normalization (switch_read and locate_endpoint read here too).
_IDENTITY_PROBE = ContextVar("helper_identity_probe", default=False)

_LINE_END_PLATFORMS = frozenset({"fortinet"}) | normalization.IDENTITY_PROFILES

_OPENSSH_STDERR_NOTICES = frozenset({
    "** WARNING: connection is not using a post-quantum key exchange algorithm.",
    '** This session may be vulnerable to "store now, decrypt later" attacks.',
    "** This session may be vulnerable to store-now decrypt-later attacks.",
    "** The server may need to be upgraded. See https://openssh.com/pq.html",
})
_OPENSSH_KNOWN_HOST_ADDED = re.compile(
    r"Warning: Permanently added '[^'\r\n]+' \([A-Z0-9-]+\) to the list of known hosts\."
)
_IOSV_SSH_LICENSE = re.compile(
    r"(?m)^\*{20,}[ \t]*\n\* IOSv is strictly limited to use for evaluation,[^\r\n]*\*[ \t]*\n"
    r"(?:\* [^*\r\n]+\*[ \t]*\n){4}\* Cisco in writing\.[ \t]+\*[ \t]*\n"
    r"\*{20,}[ \t]*(?:\n|$)"
)
_EMPTY_READ_STDERR_ERROR = "The device read returned unexpected SSH diagnostics without data"


class _FortinetReader:
    """Hold the connection lane and the pinned terminal from the first read to the end of an operation."""

    def __init__(self, auth: TargetAuth, stack: ExitStack):
        self.auth = auth
        self.stack = stack
        self.endpoint = None
        self.cli = None
        self.failure = None

    def target(self, platform):
        if self.failure is not None:
            raise self.failure
        if self.endpoint is None:
            auth = self.auth
            try:
                address = _resolve_target_ipv4(auth)[0]
                self.endpoint = address, host_key_line(auth, address, platform)
            except Exception as exc:
                self.failure = exc
                raise
        return self.endpoint

    def session(self, platform, *, capture_max_bytes=None):
        if self.failure is not None:
            raise self.failure
        if self.cli is None:
            auth = self.auth
            try:
                address, _ = self.target(platform)
                device = SimpleNamespace(platform=platform, port=auth.port, address=address,
                                         legacy_ssh=auth.legacy_ssh, host_key=getattr(auth, "host_key", None),
                                         host_key_fingerprint=auth.host_key_fingerprint)
                with ExitStack() as connection:
                    connection.enter_context(_paced_connection(address, auth.port, platform))
                    self.cli = connection.enter_context(core_session.fortinet_session(
                        device, DeviceCredential(auth), connect_timeout_seconds=_read_timeout(_SSH_LOGIN_TIMEOUT_SECONDS),
                        capture_max_bytes=_SSH_CAPTURE_MAX_BYTES if capture_max_bytes is None else capture_max_bytes,
                    ))
                    self.stack.enter_context(connection.pop_all())
            except Exception as exc:
                self.failure = exc
                raise
        return self.cli

    @contextmanager
    def cleanup_shell(self, platform):
        """Give the recipe one fresh, pinned session after the original transport is lost."""
        if not getattr(self.cli, "_closed", False):
            raise ValueError("the diagnostic session is still open")
        self.stack.close()  # Release the original connection lane before reacquiring it.
        with ExitStack() as stack:
            repair = _FortinetReader(self.auth, stack)
            repair.endpoint = self.endpoint
            cli = repair.session(platform, capture_max_bytes=self.cli.max_transcript_bytes)
            yield _FortiosDiagnosticShell(cli, platform, answer_refusal_raises=platform != "fortiadc")


_FORTINET_READER = ContextVar("helper_fortinet_reader", default=None)


@contextmanager
def _fortinet_operation(auth, *, finish=False):
    """Bind a lazy reader for this caller, including its audited subcalls."""
    current = _FORTINET_READER.get()
    if current is not None and current.auth is auth:
        try:
            yield current
        finally:
            if finish:
                current.stack.close()
        return
    with ExitStack() as stack:
        reader = _FortinetReader(auth, stack)
        token = _FORTINET_READER.set(reader)
        try:
            yield reader
        finally:
            _FORTINET_READER.reset(token)


def _fortinet_needs_refusal_text(platform, command):
    # These catalogue families interpret specific CLI refusals. Core's run()
    # marks such a command as refused and discards its body.
    if platform == "fortiadc":
        return command in fortiadc_diagnostics.INTERFACE_EXEC_WORDS
    # A managed switch without PSE ports answers its PoE summary with `switch:<serial> is not PoE capable`
    # before the refusal line (FortiOS 7.6.8); the overview reports that as not applicable.
    return command.startswith(("diagnose wireless-controller ", "diagnose switch-controller switch-info mclag ",
                               "diagnose switch-controller switch-info poe summary ",
                               "get router info bgp neighbors ", "get router info6 bgp neighbors "))


def _fortinet_exec(auth, platform, command, stdout_consumer=None):
    with _fortinet_operation(auth) as reader:
        cli = reader.session(platform)
        timeout = _read_timeout(_SSH_READ_TIMEOUT_SECONDS)
        if stdout_consumer is None and _fortinet_needs_refusal_text(platform, command):
            shell = _FortiosDiagnosticShell(cli, platform, answer_refusal_raises=False)
            text = shell.exec_text(command, timeout)
            rc = int(platform == "fortiadc" and _cli_refused(platform, text))
            return core_session.FortinetResult(rc, text.encode(), "", "", "")
        options = {"timeout_seconds": timeout, "capture_max_bytes": core_ssh.CAPTURE_MAX_BYTES}
        if stdout_consumer is not None:
            limits = auth.configuration_limits
            options = dict(timeout_seconds=_read_timeout(limits.total_seconds),
                           idle_timeout_seconds=limits.idle_seconds, capture_max_bytes=limits.all_bytes)
        framed = stdout_consumer is not None and platform == "fortiadc"
        if framed:
            # Core strips terminal framing. Feed the observed start/end prompts into the
            # existing ADC normalizer after Core has established each one.
            initial = cli._last_prompt
            first = True

            def framed_consumer(data):
                nonlocal first
                if first:
                    data = initial + data
                    first = False
                stdout_consumer(data)
        else:
            framed_consumer = stdout_consumer
        try:
            result = cli.run(command, stdout_consumer=framed_consumer, **options)
        except core_session.SessionError as exc:
            if stdout_consumer is not None and exc.code == "output_limit":
                raise core_ssh.OutputLimitError() from None
            raise
        if result.continuation:
            cli.close()
            raise core_session.SessionError("unexpected Fortinet continuation", code="terminal")
        if framed and result.rc == 0 and not first:
            try:
                stdout_consumer(cli._last_prompt + b"\n")
            except core_ssh.OutputLimitError:
                raise
            except Exception:
                raise core_ssh.OutputConsumerError() from None
        return result


def _exec_read(auth: TargetAuth, platform: str, command: str, stdout_consumer=None) -> tuple[int | None, str]:
    options = {'stdout_consumer': stdout_consumer} if stdout_consumer is not None else {}
    if platform in _IDENTITY_PLATFORMS:
        with _fortinet_operation(auth) as reader:
            address, pinned_line = reader.target(platform)
            result = _exec_command(auth, address, pinned_line, DeviceCredential(auth), command, platform, **options)
    else:
        address, known_hosts_line = _read_endpoint(auth, platform)
        credential = DeviceCredential(auth)
        for preamble in _PLATFORM_PREAMBLE.get(platform, ()):
            _exec_command(auth, address, known_hosts_line, credential, preamble, platform)
        result = _exec_command(auth, address, known_hosts_line, credential, command, platform, **options)
    if stdout_consumer is not None:
        if result.stdout:
            raise ValueError('streaming transport returned unexpected accumulated output')
        return result.rc, ''
    text = result.stdout.decode("utf-8", "replace")
    if _is_junos_traceroute(platform, command) and result.stderr:
        # Junos writes the trace header and diagnostics to stderr.
        stderr = result.stderr.decode("utf-8", "replace")
        text = stderr.rstrip("\r\n") + "\n" + text if text else stderr
    if platform in {"cisco_ios", "cisco_xe", "cisco_nxos", "extreme_exos"} and result.stderr:
        # Keep recognized refusals for redaction and classification. Other stderr stays private.
        stderr = result.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
        device_stderr = core_prompt.cleaned(stderr, platform)
        holder = _READ_SCOPE.get()
        management_read = holder is not None and holder.get("ios_management") and not _IDENTITY_PROBE.get()
        refusals = "\n".join(
            line for line in device_stderr.split("\n")
            if _cli_refused(platform, line, command=command)
            or management_read and normalization.output_status(
                strip_terminal_controls(line), profile=platform, command=command
            ) in {"permission_denied", "unsupported"}
        )
        if holder is not None and not _IDENTITY_PROBE.get():
            if platform == "cisco_nxos":
                # A successful NX-OS exec can carry any configured login banner on stderr.
                holder["unexpected_stderr"] = bool(refusals)
            else:
                notices = _OPENSSH_STDERR_NOTICES
                blank_only = not stderr.strip()
                if (holder.get("ios_g57") or holder.get("ios_management") or holder.get("xe_detail")) and result.rc == 0:
                    # IOSv writes its license greeting to stderr. IOL XE can emit a
                    # client disconnect notice after sending a successful exit status.
                    identity = holder.get("product_identity", {})
                    if platform == "cisco_ios" and identity.get("model") == "IOSv":
                        stderr = _IOSV_SSH_LICENSE.sub("", stderr, count=1)
                    if platform == "cisco_xe":
                        notices = notices | {f"Connection to {address} closed by remote host."}
                # IOL-L2 closes a successful empty EtherChannel/LACP exec after two CRLFs.
                # Require successful execution with the measured empty framing.
                xe_empty_channel = (
                    platform == "cisco_xe" and result.rc == 0 and result.stdout == b"\r\n\r\n"
                    and (command == "show lacp internal" or re.fullmatch(r"show etherchannel [0-9]{1,3} detail", command))
                )
                if result.rc == 0 and platform == "cisco_xe" and (
                    xe_empty_channel or (holder.get("xe_detail") and not text.strip())
                    or command in {"show aaa servers", "show tacacs"}
                ):
                    notices = notices | {f"Connection to {address} closed by remote host."}
                xe_empty_table = command in {
                    "show lacp neighbor", "show standby brief", "show spanning-tree root", "show ntp associations",
                } and not text.strip()
                if platform == "cisco_xe" and result.rc == 0 and (holder.get("ios_security_read") or xe_empty_table):
                    # IOL XE can also deliver the close notice on the command channel after
                    # sending exit status 0. Accept only a notice naming this SSH endpoint.
                    notices = notices | {
                        f"Connection to {address} closed by remote host.",
                        f"Connection to {address} port {auth.port} closed by remote host.",
                    }
                holder["unexpected_stderr"] = blank_only or any(
                    line and line not in notices and not _OPENSSH_KNOWN_HOST_ADDED.fullmatch(line)
                    for line in map(str.strip, stderr.split("\n"))
                )
        if refusals:
            text = refusals + "\n" + text
    if platform in _LINE_END_PLATFORMS:
        # schema_read and the table parsers read this text: pattern rules could destroy CLI syntax.
        secrets = () if _IDENTITY_PROBE.get() else _redaction_secret_forms(auth)
        for value in secrets:
            text = text.replace(value, "<REDACTED>")
        text = text.replace("\r\n", "\n")
        for value in secrets:
            text = text.replace(value, "<REDACTED>")
    cleaned = core_prompt.cleaned(text, platform)
    if platform == "fortiadc" and command in fortiadc_diagnostics.INTERFACE_EXEC_WORDS and result.stderr:
        refusal = fortiadc_diagnostics.interface_exec_refusal(command, cleaned, result.stderr.decode("utf-8", "replace"))
        if refusal:
            cleaned = cleaned.rstrip("\r\n") + "\n" + refusal
    return result.rc, cleaned


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
    address, known_hosts_line = _read_endpoint(auth, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            session = core_session.Session(
                address,
                auth.port,
                auth.login,
                DeviceCredential(auth),
                known_hosts_line,
                legacy_ssh=auth.legacy_ssh,
                timeout_seconds=_read_timeout(_SSH_READ_TIMEOUT_SECONDS),
            )
            try:
                for prompt, answer in (
                    (_RUCKUS_LOGIN_PROMPT, auth.login),
                    (_RUCKUS_PASSWORD_PROMPT, auth.secret),
                    (_RUCKUS_USER_PROMPT, _RUCKUS_ENABLE_COMMAND),
                ):
                    _, seen = session.expect([prompt], _read_timeout(_SSH_LOGIN_TIMEOUT_SECONDS))
                    session.discard(seen)
                    _read_timeout(_SSH_LOGIN_TIMEOUT_SECONDS)
                    session.send(answer)
                _, seen = session.expect([_RUCKUS_ENABLE_PROMPT], _read_timeout(_SSH_LOGIN_TIMEOUT_SECONDS))
                session.discard(seen)
                _read_timeout(_SSH_READ_TIMEOUT_SECONDS)
                session.send(command)
                _, answered = session.expect([_RUCKUS_ENABLE_PROMPT], _read_timeout(_SSH_READ_TIMEOUT_SECONDS))
            finally:
                session.close()
    except core_session.SessionError:
        _forget_host_key_line(address, auth.port)
        raise
    return None, _pty_body(answered, command, _RUCKUS_ENABLE_PROMPT)


_IOS_EXEC_PROMPT = re.compile(rb"(?:\A|\n)([A-Za-z0-9_.-]{1,63}[>#])[ \t]*\Z")
_IOS_LOGIN_PROMPT_QUIET_SECONDS = 0.25
_IOS_XE_INVALID_PROBE = re.compile(r"(?m)^[ \t]*% Invalid input detected at '\^' marker\.[ \t]*\Z")


def _ios_probe_prompt(auth: TargetAuth, command: str, *, platform: str = "cisco_ios") -> tuple[int | None, str]:
    """Capture a bounded IOS probe through its final prompt, without terminal settings."""
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    try:
        with _paced_connection(address, auth.port, platform):
            session = core_session.Session(
                address, auth.port, auth.login, DeviceCredential(auth), known_hosts_line,
                legacy_ssh=auth.legacy_ssh, timeout_seconds=_SSH_READ_TIMEOUT_SECONDS,
                capture_max_bytes=_SSH_CAPTURE_MAX_BYTES,
            )
            try:
                # A banner line can look like the prompt at the end of a PTY read.
                _, login = session.expect(
                    [_IOS_EXEC_PROMPT], _SSH_LOGIN_TIMEOUT_SECONDS, quiet_seconds=_IOS_LOGIN_PROMPT_QUIET_SECONDS,
                )
                prompt = _IOS_EXEC_PROMPT.search(login)[1]
                session.discard(login)
                session.send(command)
                if platform == "cisco_xe":
                    final_prompt = re.compile(rb"(?:\A|\n)" + re.escape(prompt) + rb"[ \t]*\Z")
                    index, answered = session.expect([final_prompt, b"--More--"], _SSH_READ_TIMEOUT_SECONDS)
                    if index == 1:
                        return None, _erase_backspaces(answered.decode("utf-8", "replace").replace("\r", ""))
                else:
                    _, answered = session.expect([prompt], _SSH_READ_TIMEOUT_SECONDS)
                # IOS can horizontally scroll a long command echo. Discard that first line.
                text = _erase_backspaces(answered.decode("utf-8", "replace").replace("\r", "")).rstrip(" \t")
                marker = prompt.decode("ascii")
                if not text.endswith(marker):
                    raise ValueError("the IOS probe did not reach its final prompt")
                body = "\n".join(text[:-len(marker)].split("\n")[1:]).strip()
                holder = _READ_SCOPE.get()
                if (platform == "cisco_xe" and " source " in command and prompt.endswith(b"#")
                        and holder is not None and holder.get("product_identity") is not None
                        and _IOS_XE_INVALID_PROBE.search(body)):
                    # A '#' prompt can also belong to a lower privilege level.
                    try:
                        session.send("show privilege")
                        _, privilege = session.expect([final_prompt], _SSH_READ_TIMEOUT_SECONDS)
                        holder["xe_source_privileged"] = (
                            _pty_body(privilege.rstrip(b" \t"), "show privilege", prompt) == "Current privilege level is 15"
                        )
                    except core_session.SessionError:
                        pass  # Preserve the original refusal when privilege cannot be verified.
            finally:
                session.close()
    except core_session.SessionError:
        _forget_host_key_line(address, auth.port)
        raise
    return None, body


def _prompt_read(auth: TargetAuth, platform: str, command: str) -> tuple[int | None, str]:
    with _fortinet_operation(auth) as reader:
        shell = _FortiosDiagnosticShell(reader.session(platform), platform, answer_refusal_raises=False)
        return None, shell.command(command, _read_timeout(_SSH_READ_TIMEOUT_SECONDS))


def _ios_family_adapter(platform):
    """The adapter module of the Cisco IOS, IOS XE, NX-OS, Arista EOS and Junos (junos config) configuration reads."""
    if platform in ('juniper_junos', 'juniper_junos_els'):
        from . import config_junos_adapter as adapter
        return adapter
    if platform == 'cisco_nxos':
        from . import config_cisco_nxos_adapter as adapter
        return adapter
    if platform == 'arista_eos':
        from . import config_arista_eos_adapter as adapter
        return adapter
    if platform == 'cisco_xe':
        from . import config_cisco_xe_adapter as adapter
        return adapter
    if platform == 'cisco_ios':
        from . import config_cisco_ios_adapter as adapter
        return adapter
    raise ValueError('config_platform_not_supported')


def _ios_family_redactor(platform):
    """The running-config stream consumer class of the adapter's redaction profile (POLICY_DESCRIPTOR[1])."""
    if platform == 'cisco_nxos':
        from .config_indented import NxosStreamRedactor
        return NxosStreamRedactor
    if platform == 'arista_eos':
        from .config_indented import EosStreamRedactor
        return EosStreamRedactor
    if platform in ('juniper_junos', 'juniper_junos_els'):
        from .config_junos_adapter import JunosSetRedactor
        return JunosSetRedactor
    from .config_cisco_ios import StreamRedactor
    return StreamRedactor


def _adapter_platform(adapter, platform):
    """The platform an adapter reads for: its single PLATFORM, or the requested one of its PLATFORMS (Junos)."""
    platforms = getattr(adapter, 'PLATFORMS', None)
    return platform if platforms is not None and platform in platforms else adapter.PLATFORM


def _ios_capture_consumer(command, stdout_consumer, platform='cisco_ios') -> bool:
    """Allow only fixed adapter capture commands and a bounded configuration consumer."""
    from . import configuration
    adapter = _ios_family_adapter(platform)
    return (command in (adapter.COMMAND, getattr(adapter, 'STARTUP_COMMAND', adapter.COMMAND))
            and getattr(stdout_consumer, '__module__', None) == configuration.__name__
            and getattr(stdout_consumer, '__qualname__', None) == 'bounded_consumer.<locals>.feed')


_LOCATE_BUDGET = ContextVar("helper_locate_budget", default=None)
_OVERVIEW_BUDGET = ContextVar("helper_overview_budget", default=None)
_OVERVIEW_ENDPOINT = ContextVar("helper_overview_endpoint", default=None)


def _read_timeout(seconds):
    budget = _OVERVIEW_BUDGET.get() or _LOCATE_BUDGET.get()
    return min(seconds, budget.remaining()) if budget is not None else seconds


_TRIAGE_READ_ATTEMPT = ContextVar("helper_triage_read_attempt", default=None)


def read_from_device(
    auth: TargetAuth, platform: str, command: str, *, stdout_consumer=None, prompt=False,
) -> tuple[int | None, str]:
    normalized = normalize_platform(platform)
    if stdout_consumer is not None and (normalized not in ('fortinet', 'fortiadc', 'extreme_exos', 'cisco_ios', 'cisco_xe',
                                                           'cisco_nxos', 'arista_eos', 'juniper_junos',
                                                           'juniper_junos_els')
                                        or not callable(stdout_consumer)
                                        or (normalized in ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos',
                                                           'juniper_junos', 'juniper_junos_els')
                                            and not _ios_capture_consumer(command, stdout_consumer, normalized))):
        raise ValueError('streaming is supported only for FortiOS, FortiADC and ExtremeXOS exec reads '
                         'and the fixed Cisco IOS configuration capture')
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    attempt = _TRIAGE_READ_ATTEMPT.get()
    if attempt is not None:
        attempt[0] = True
    if prompt:
        if normalized == "cisco_ios" and stdout_consumer is None:
            return _ios_probe_prompt(auth, command)
        if normalized == "cisco_xe" and stdout_consumer is None:
            return _ios_probe_prompt(auth, command, platform=normalized)
        if normalized not in ("fortiadc", "fortinet") or stdout_consumer is not None:
            raise ValueError("prompt reads require a supported CLI catalogue query")
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
    r"|the [a-z0-9-]+ subsystem is not running"
    r"|device [a-z0-9./:-]+ not found"
    # junos routing: an unknown routing instance in `show route table <ri>.inet.0` / `show arp vpn <ri>`.
    r"|No routing tables matching specification\.|Named Route table not found\.)[ \t]*\r?$"
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
        r"|Error:[ \t]+Permission denied\.?"
        r"|Method is not implemented on this platform\."
        r"|%%[ \t]+(?:Invalid input detected|Unrecognized command|Incomplete command|Ambiguous command)[^\r\n]*+)[ \t]*\r?$"
    ),
    "cisco_ios": _CISCO_AUTOCOMMAND_REFUSAL,
    "cisco_xe": _CISCO_AUTOCOMMAND_REFUSAL,
    "arista_eos": re.compile(
        r"(?mi)^[ \t]*(?:% Invalid input(?: \([^)\r\n]*\))? at line [0-9]+|"
        + normalization.EOS_UNAVAILABLE_LINE + r")[ \t]*\r?$"
    ),
    "juniper_junos": _JUNOS_REFUSAL,
    "juniper_junos_els": _JUNOS_REFUSAL,
    "cisco_nxos": re.compile(
        r"(?m)^[ \t]*(?:Syntax error while parsing '[^'\r\n]*'"
        r"|% Permission denied for the role)[ \t]*\r?$"
    ),
    # Unleashed 200.15: an object read (ap/wlan/performance by MAC or name) of an absent object.
    "ruckus_unleashed": wifi_parse.RUCKUS_NOT_FOUND,
}


_RUCKUS_CLI_UNRECOGNIZED = re.compile(r"(?mi)^[ \t]*The command is either unrecognized or incomplete\.[^\r\n]*$")


def _cli_refused(platform: str, output: str, *, command: str | None = None) -> bool:
    """Detect device refusal lines anywhere; command is compatibility metadata only."""
    if (platform == "cisco_nxos" and command is not None
            and command.startswith("show radius-server statistics ")
            and output.strip() == "RADIUS server not found"):
        return True
    if platform == "ruckus_unleashed" and _RUCKUS_CLI_UNRECOGNIZED.search(output):
        return True
    pattern = _CLI_REFUSALS.get(platform)
    return ((pattern is not None and pattern.search(output) is not None)
            or normalization.permission_refused(platform, output)
            or normalization.template_refused(platform, output))


def _fortiadc_diagnose_refused(command: str | None, output: str) -> bool:
    from .fortiadc_diagnostics import diagnose_refused
    return command is not None and diagnose_refused(command, output)


def _fortiadc_diagnose_advice() -> str:
    from .fortiadc_diagnostics import DIAGNOSE_NOT_PERMITTED_ADVICE
    return DIAGNOSE_NOT_PERMITTED_ADVICE


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
                identity = normalization.parse_identity(platform, status)
                holder = _READ_SCOPE.get()
                if platform in {"cisco_nxos", "cisco_ios", "cisco_xe"} and holder is not None:
                    holder["product_identity"] = identity
                if platform == "extreme_exos" and holder is not None and holder.get("exos_log_history"):
                    holder["exos_log_firmware"] = health_rules.exos_firmware(identity, status, EXOS_LOG_HISTORY)
            except normalization.IdentityError as exc:
                raise _ProductIdentityError(platform, rc, exc.reason) from None
            return command, rc, _redact_output(status, auth)
        rc, status = read(auth, platform, _IDENTITY_COMMAND)
        _require_product(platform, rc, status)
        holder = _READ_SCOPE.get()
        if platform == "fortinet" and holder is not None and holder.get("fortios_firmware"):
            holder["fortios_identity"] = core_platforms.version_record(status)
        return _IDENTITY_COMMAND, rc, _redact_output(status, auth)
    finally:
        _IDENTITY_PROBE.reset(token)


# The VDOM scope of the last FortiOS read in this context: callers that label results open a holder with
# _scope_capture(); _verified_read and _verified_sequence fill it (scope, VDOM index, extra answers).
_READ_SCOPE = ContextVar("helper_read_scope", default=None)


@contextmanager
def _scope_capture(extra: tuple[str, ...] = ()):
    holder: dict[str, Any] = {"extra": tuple(extra)}
    token = _READ_SCOPE.set(holder)
    try:
        yield holder
    finally:
        _READ_SCOPE.reset(token)


def _session_scope(auth: TargetAuth, status: str, identity: bool) -> dict | None:
    """The FortiOS VDOM scope a read may use, recorded in the open holder; refuses per-VDOM reads out of scope.

    The status read itself names the VDOM and is never refused for its scope (only a malformed scope refuses).
    """
    holder = _READ_SCOPE.get()
    try:
        found = fortios_vdom.scope(status)
        if not identity:
            found = fortios_vdom.require(found, auth.read_inventory, status)
    except fortios_vdom.VdomRefused as refused:
        if holder is not None:
            holder["scope"] = refused.scope
        if identity:
            return None  # the status itself is answered unlabelled; per-VDOM reads stay refused
        raise
    if holder is not None:
        holder["scope"] = found
    return found


def _context_read(auth: TargetAuth, platform: str, found: dict, commands: tuple[str, ...],
                  sequence: bool = False) -> tuple[int | None, str]:
    holder = _READ_SCOPE.get()
    rc, output, index, extras = _vdom_context_read(
        auth, platform, found["vdom"], commands, sequence=sequence,
        extra=holder.get("extra", ()) if holder is not None else ())
    if holder is not None:
        holder.update(index=index, extras=extras)
    return rc, output


def _exos_log_evidence(auth: TargetAuth, command: str, parse):
    # Isolate optional reads from the primary capture's stderr and keep only parsed timestamps.
    with _scope_capture() as holder:
        try:
            rc, output = read_from_device(auth, "extreme_exos", command)
        except Exception:
            return None
        state = normalization.output_status(output, rc=rc, profile="extreme_exos", command=command,
                                            truncated=len(output.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES)
        if rc != 0 or state != "ok" or holder.get("unexpected_stderr"):
            return None
    return parse(output)


def _verified_read(auth: TargetAuth, platform: str, command: str, prompt: bool = False) -> tuple[int | None, str]:
    if platform in normalization.IDENTITY_PROFILES:
        identity_command, rc, status = _check_identity(auth, platform, read_from_device)
        holder = _READ_SCOPE.get()
        if holder is not None and holder.get("junos_firmware"):
            holder["junos_identity"] = normalization.parse_identity(platform, status)
            if command == LOG_HISTORY_COMMAND:
                holder["junos_log_clock"] = _triage_read(auth, platform, "uptime")
        if holder is not None and holder.get("xe_log_history"):
            holder["xe_log_clock"] = _triage_read(auth, platform, "clock")
        if holder is not None and (source := holder.get("exos_log_history")):
            holder["exos_log_clock"] = _exos_log_evidence(
                auth, READ_QUERIES["extreme_exos"]["switch"].command, health_rules.exos_log_clock)
            rc, output = read_from_device(auth, platform, command)
            if rc == 0 and not _cli_refused(platform, output, command=command):
                # Read retention after the selected window, so an older row still retained is evidence
                # for the earlier capture. The validated source selects one of two fixed reads.
                retained_command = {
                    "memory-buffer": READ_QUERIES["extreme_exos"]["log_messages"].command,
                    "nvram": "show log messages nvram",
                }[source]
                holder["exos_log_oldest"] = _exos_log_evidence(auth, retained_command, health_rules.exos_log_oldest)
            return rc, output
        return ((rc, status) if command == identity_command else
                read_from_device(auth, platform, command, **({"prompt": True} if prompt else {})))
    if platform not in _IDENTITY_PLATFORMS:
        return read_from_device(auth, platform, command)
    with _fortinet_operation(auth):
        # A requested status is itself the live identity check.
        identity_command, rc, status = _check_identity(auth, platform, read_from_device)
        if platform == "fortinet":
            found = _session_scope(auth, status, command == identity_command)
            if command != identity_command and fortios_vdom.contextual(found):
                return _context_read(auth, platform, found, (command,))
        if command == identity_command:
            return rc, status
        return read_from_device(auth, platform, command, **({"prompt": True} if prompt else {}))


_SEQUENCE_STEP_TIMEOUT_SECONDS = 30
# The catalogue commands a per-VDOM administrator is refused (fortios_vdom.VDOM_ADMIN_REFUSED_QUERIES): their data
# is not limited to its VDOM. Decided by the command, because the context read runs catalogue commands.
_VDOM_ADMIN_REFUSED_COMMANDS = frozenset(READ_QUERIES["fortinet"][query].command
                                         for query in fortios_vdom.VDOM_ADMIN_REFUSED_QUERIES
                                         if query in READ_QUERIES["fortinet"])


def _login_vdom_context(shell: Any, vdom: str) -> bool:
    """After a refused `config vdom` / `config global`: is this session a per-VDOM administrator's login of `vdom`?

    Positive device signals only, read in the same session (measured, verification; see fortios_vdom): the status
    names multi-VDOM mode and exactly `vdom`, and the per-VDOM probe `get system arp` answers its table where a
    global session answers `-61`. The prompt must not show a context (`<host> (<context>) `). The texts are never
    answered.
    """
    if b" (" in shell.prompt:
        return False
    status = shell.command(_IDENTITY_COMMAND, _SEQUENCE_STEP_TIMEOUT_SECONDS)
    if _cli_refused("fortinet", status) or not fortios_vdom.login_status(status, vdom):
        return False  # another VDOM (or none verified): nothing more is sent
    probe = shell.command(fortios_vdom.LOGIN_CONTEXT_PROBE, _SEQUENCE_STEP_TIMEOUT_SECONDS)
    return not _cli_refused("fortinet", probe) and fortios_vdom.login_context(status, probe, vdom)


def _vdom_context_read(auth: TargetAuth, platform: str, vdom: str, commands: tuple[str, ...], *,
                       sequence: bool = False, extra: tuple[str, ...] = ()) -> tuple[int | None, str, int | None, tuple[str, ...]]:
    """Run reviewed FortiOS reads in one SSH session inside `config vdom` / `edit <vdom>` /... / `end`.

    Measured on the 60F 7.6.8 in multi-VDOM mode: a per-VDOM read outside a VDOM context is refused, and
    `edit <vdom>` prints `current vf=<vdom>:<index>`. Nothing is answered unless that marker names this VDOM
    and the prompt shows it. One command, or with `sequence` a reviewed `execute log` sequence (a filter
    command that prints anything ends it, as in _sequence_read); `extra` commands (the VDOM membership join)
    run afterwards in the same context and are answered separately. Returns (rc, text, VDOM index, extras).

    A per-VDOM administrator cannot enter `config vdom` (`Unknown action 0`, measured, verification) and reads its
    VDOM in its login context. Only when `config vdom` was refused and _login_vdom_context proves that context
    for this VDOM, the commands run directly; the index is then None (no marker). If any command of the read,
    `extra` included (the membership join `show system interface` lists every VDOM), has data not limited to the
    VDOM, the whole read raises VdomRefused("vdom_admin_global_scope_unavailable") before any of them is sent.
    """
    if platform != "fortinet":
        raise ValueError("VDOM context reads are supported only for FortiOS")
    if not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    if not fortios_vdom.VDOM_NAME.fullmatch(vdom):
        raise fortios_vdom.VdomRefused("vdom_unverified")
    if sequence:
        commands = require_fortinet_sequence(tuple(commands))
    elif len(commands) != 1:
        raise ValueError("a VDOM context read runs exactly one catalogue command")
    attempt = _TRIAGE_READ_ATTEMPT.get()
    if attempt is not None:
        attempt[0] = True
    with _fortinet_operation(auth) as reader:
        session = reader.session(platform)
        shell = _FortiosDiagnosticShell(session, platform, answer_refusal_raises=False)
        initial = shell.prompt
        index: int | None
        entered = False
        try:
            try:
                shell.navigate("config vdom")
            except ValueError as refused:
                if "refused" not in str(refused) or not _login_vdom_context(shell, vdom):
                    raise fortios_vdom.VdomRefused("vdom_context_unverified") from None
                if any(command in _VDOM_ADMIN_REFUSED_COMMANDS for command in (*commands, *extra)):
                    raise fortios_vdom.VdomRefused(
                        fortios_vdom.VDOM_ADMIN_GLOBAL, {"vdom_mode": "multiple", "vdom": vdom}) from None
                index = None
            else:
                entered = True
                try:
                    index = fortios_vdom.context_index(shell.navigate("edit " + vdom), vdom)
                except ValueError:
                    raise fortios_vdom.VdomRefused("vdom_context_unverified") from None
                if not shell.prompt.endswith((b" (" + vdom.encode("ascii") + b") # ",
                                              b" (" + vdom.encode("ascii") + b") $ ")):
                    raise fortios_vdom.VdomRefused("vdom_context_unverified")
            text = ""
            for position, command in enumerate(commands):
                text = shell.command(command, _SEQUENCE_STEP_TIMEOUT_SECONDS)
                if sequence and position < len(commands) - 1 and text.strip():
                    break
            extras = tuple(shell.command(command, _SEQUENCE_STEP_TIMEOUT_SECONDS) for command in extra)
        finally:
            if entered:
                shell.leave(initial)
    return None, text, index, extras


def _global_context_read(auth: TargetAuth, platform: str, command: str,
                         vdom: str | None = None) -> tuple[int | None, str]:
    """Run one reviewed global FortiOS read in one SSH session inside `config global` / command / `end`.

    Multi-VDOM only (verification): the global system state commands are refused inside `config vdom` / `edit <vdom>`
    (`-61`, measured on the 60F 7.6.8). `config global` prints no marker (measured): nothing is answered unless
    the device accepted it with an empty answer (measured) and the prompt is `<host> (global) # ` or `$ `.
    A refusal raises VdomRefused("global_context_not_permitted"), any other prompt "global_context_unverified";
    a refusal in a session that _login_vdom_context proves to be a per-VDOM administrator's login of `vdom`
    raises VdomRefused("vdom_admin_global_scope_unavailable") (verification).
    """
    if platform != "fortinet":
        raise ValueError("global context reads are supported only for FortiOS")
    if not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    attempt = _TRIAGE_READ_ATTEMPT.get()
    if attempt is not None:
        attempt[0] = True
    with _fortinet_operation(auth) as reader:
        shell = _FortiosDiagnosticShell(reader.session(platform), platform, answer_refusal_raises=False)
        initial = shell.prompt
        try:
            entered = shell.navigate("config " + fortios_vdom.GLOBAL_CONTEXT)
        except ValueError as refused:
            code = "global_context_not_permitted" if "refused" in str(refused) else "global_context_unverified"
            if code == "global_context_not_permitted" and vdom is not None and _login_vdom_context(shell, vdom):
                code = fortios_vdom.VDOM_ADMIN_GLOBAL
            raise fortios_vdom.VdomRefused(code) from None
        try:
            if entered.strip() or not fortios_vdom.global_prompt(shell.prompt):
                raise fortios_vdom.VdomRefused("global_context_unverified")
            text = shell.command(command, _SEQUENCE_STEP_TIMEOUT_SECONDS)
        finally:
            shell.leave(initial)
    return None, text


def _sequence_read(auth: TargetAuth, platform: str, commands: tuple[str, ...]) -> tuple[int | None, str]:
    """Run a reviewed FortiOS `execute log` sequence in one SSH session and answer the last command's text.

    The log filter lives only in this session. A filter command that prints anything was refused by
    the device, so its text is answered at once for the CLI refusal check.
    """
    commands = require_fortinet_sequence(tuple(commands))
    if platform != "fortinet":
        raise ValueError("command sequences are supported only for FortiOS")
    with _fortinet_operation(auth) as reader:
        shell = _FortiosDiagnosticShell(reader.session(platform), platform, answer_refusal_raises=False)
        text = ""
        for index, command in enumerate(commands):
            text = shell.command(command, _SEQUENCE_STEP_TIMEOUT_SECONDS)
            if index < len(commands) - 1 and text.strip():
                break
    return None, text


def _verified_sequence(auth: TargetAuth, platform: str, commands: tuple[str, ...]) -> tuple[int | None, str]:
    if platform not in _IDENTITY_PLATFORMS:
        raise ValueError("command sequences are supported only for FortiOS")
    with _fortinet_operation(auth):
        _, _, status = _check_identity(auth, platform, read_from_device)
        if platform == "fortinet":
            found = _session_scope(auth, status, False)
            if fortios_vdom.contextual(found):
                return _context_read(auth, platform, found, tuple(commands), sequence=True)
        return _sequence_read(auth, platform, commands)


def _verified_fortiadc_interface_summary(auth: TargetAuth, commands: tuple[str, str]):
    """Use the reviewed exec reads and stop on the first unsuccessful source."""
    with _fortinet_operation(auth):
        platform = "fortiadc"
        _check_identity(auth, platform, read_from_device)
        sources = []
        for command in commands:
            rc, output = read_from_device(auth, platform, command)
            if rc not in (0, None) or _cli_refused(platform, output, command=command):
                return rc, output, command
            if len(output.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
                raise core_ssh.OutputLimitError()
            sources.append(output)
        rows = fortiadc_diagnostics.interface_summary(*sources)
        return rc, "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows), None


_WTP_SEEN: dict[tuple[Any, ...], dict[str, float]] = {}
_WTP_SEEN_LOCK = threading.Lock()
_WTP_SEEN_TTL_SECONDS = 3600.0
_WTP_SEEN_MAX_TARGETS = 64
_WTP_SEEN_MAX_IDS = 256
_WTP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,34}")


_RUCKUS_WLAN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
_OBSERVED_PATTERNS = {"wtp_ids": _WTP_ID, "wlan_names": _RUCKUS_WLAN_NAME}


def _wtp_key(auth: TargetAuth, category: str = "wtp_ids") -> tuple[Any, ...]:
    key = (auth.alias, auth.host, auth.port, auth.login)
    return key if category == "wtp_ids" else (*key, category)


def _observed_wtp_ids(auth: TargetAuth, category: str = "wtp_ids") -> frozenset[str]:
    now = time.monotonic()
    with _WTP_SEEN_LOCK:
        for key, entries in list(_WTP_SEEN.items()):
            _WTP_SEEN[key] = {serial: expiry for serial, expiry in entries.items() if expiry > now}
            if not _WTP_SEEN[key]:
                _WTP_SEEN.pop(key, None)
        entry = _WTP_SEEN.get(_wtp_key(auth, category))
        return frozenset(entry) if entry else frozenset()


def _remember_wtp_ids(auth: TargetAuth, serials: list[str], category: str = "wtp_ids") -> None:
    """Remember the access point ids (FortiOS `wtp-status`, Ruckus AP device names) or the Ruckus WLAN names this
    target itself listed; nothing else is remembered."""
    clean = frozenset(item for item in serials
                      if isinstance(item, str) and _OBSERVED_PATTERNS[category].fullmatch(item)
                      and not (category == "wlan_names" and item.casefold() == "all"))
    if not clean:
        return
    with _WTP_SEEN_LOCK:
        now = time.monotonic()
        for old_key, entries in list(_WTP_SEEN.items()):
            _WTP_SEEN[old_key] = {serial: expiry for serial, expiry in entries.items() if expiry > now}
            if not _WTP_SEEN[old_key]:
                del _WTP_SEEN[old_key]
        key = _wtp_key(auth, category)
        if key not in _WTP_SEEN and len(_WTP_SEEN) >= _WTP_SEEN_MAX_TARGETS:
            _WTP_SEEN.pop(min(_WTP_SEEN, key=lambda item: max(_WTP_SEEN[item].values())), None)
        entries = _WTP_SEEN.setdefault(key, {})
        entries.update({serial: now + _WTP_SEEN_TTL_SECONDS for serial in clean})
        for serial in sorted(entries, key=lambda item: (entries[item], item))[:max(0, len(entries) - _WTP_SEEN_MAX_IDS)]:
            del entries[serial]


def _read_inventory(auth: TargetAuth) -> dict[str, tuple[str, ...]]:
    """Enrolled inventory plus the access point ids (and Ruckus WLAN names) this target listed earlier."""
    inventory = dict(auth.read_inventory)
    categories = {"fortinet": ("wtp_ids",), "ruckus_unleashed": ("wtp_ids", "wlan_names")}
    for category in categories.get(auth.ssh_platform, ()):
        inventory[category] = tuple(sorted(set(inventory.get(category, ())) | _observed_wtp_ids(auth, category)))
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


def _redaction_secret_forms(auth: TargetAuth, extra: Iterable[str] = ()) -> tuple[str, ...]:
    forms = {
        form
        for value in (*auth.redaction_secrets, *extra)
        for form in (value, value.replace("\r\n", "\n"), value.replace("\r", ""))
        if len(form.encode("utf-8")) >= 3  # same floor as sanitize.redact
    }
    return tuple(sorted(forms, key=lambda value: (-len(value), value)))


def _redact_output(output: str, auth: TargetAuth, *, extra_secrets: Iterable[str] = ()) -> str:
    """Canonical SSH text: the bytes the client receives, hashed and paged by the caller.

    The proxy and worker redact the response again with their own rules. Applying every
    layer here, until none changes the text, keeps hash, offsets and sizes true for the
    final response; the worker withholds a page that a later layer still alters.
    """
    from .sanitize import redact_response

    return redact_response(output, _redaction_secret_forms(auth, extra_secrets))


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
                  ssh_platform: str | None = None,
                  diagnostic_names: tuple[str, ...] = ()) -> dict[str, Any]:
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
            or (ssh_platform == "fortiadc" and (value in fortiadc_diagnostics.RECIPES
                                                or value in fortiadc_diagnostics.STATE_RECIPES
                                                or value in {"disk_usage", "ntp_status",
                                                             fortiadc_diagnostics.PACKET_CAPTURE}))
        )
        fields["recipe"] = value if valid else INVALID_AUDIT_VALUE
    destination = arguments.get("address")
    if (ssh_platform == "fortinet" and fields.get("recipe") in ("ping", "traceroute")
            and isinstance(destination, str) and "%" not in destination):
        from .fortios_diagnostics import probe_target
        try:
            kind = probe_target(destination)
        except ValueError:
            pass
        else:
            if kind == 6 or (kind == "name" and destination in diagnostic_names):
                fields["destination_address"] = destination
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
            fields = _audit_fields(arguments, {}, auth.ssh_platform, auth.read_inventory.get("diagnostic_names", ()))
            if auth.legacy_ssh is not None:
                fields["legacy_ssh"] = auth.legacy_ssh
            record(
                event, operation_id=operation_id, device=(
                    _overview_redact(auth.alias, auth) if event == "network_overview" else auth.alias
                ), status="started",
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
        fields = _audit_fields(arguments, result or {}, auth.ssh_platform,
                               auth.read_inventory.get("diagnostic_names", ()))
        if auth.legacy_ssh is not None:
            fields["legacy_ssh"] = auth.legacy_ssh
        if detail is not None:
            fields["detail"] = detail
        try:
            record(
                event, operation_id=operation_id, device=(
                    _overview_redact(auth.alias, auth) if event == "network_overview" else auth.alias
                ), status=status, **fields,
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
            with _fortinet_operation(auth):
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
    normalized: dict | None = None, line_limit: dict | None = None, labels: dict | None = None,
    eos_log_metadata: tuple[str, int] | None = None,
) -> None:
    """Store redacted text and the metadata that belongs to this snapshot."""
    with _SSH_CACHE_LOCK:
        if len(_SSH_PAGE_CACHE) >= _SSH_CACHE_MAX_ENTRIES:
            oldest = min(_SSH_PAGE_CACHE, key=lambda item: _SSH_PAGE_CACHE[item][0])
            _SSH_PAGE_CACHE.pop(oldest, None)
        _SSH_PAGE_CACHE[key] = (
            time.monotonic() + _SSH_CACHE_TTL_SECONDS, rc, output, frozenset(redacted_with), normalized, line_limit,
            dict(labels) if labels else None, eos_log_metadata,
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
    if normalized in JUNOS_PROFILES and query in JUNOS_CONFIG_READS:
        if "read" not in auth.read_inventory.get("config_access", ()):
            raise PolicyScopeError("Junos configuration reads require config_access read")
    if normalized in JUNOS_PROFILES and query == LOG_HISTORY_QUERY:
        auth.require_ssh_query(normalized, "uptime")
    if normalized in {"cisco_ios", "cisco_xe"} and query == XE_LOG_HISTORY:
        auth.require_ssh_query(normalized, "clock")
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


def _ruckus_wifi_payload(auth: TargetAuth, query: str, text: str) -> dict[str, Any]:
    """Normalised records of a Ruckus Unleashed read; AP device names and WLAN names it lists become selectable.

    The parser always reads the whole captured snapshot (every page carries the same `wifi`), so `complete` says
    whether that snapshot was read completely: no counters missing (`incomplete`) and no unparsed line. It never
    depends on the text page and is never true together with `incomplete`.
    """
    parsed = wifi_parse.summarize_ruckus(query, text)
    parsed["complete"] = not parsed.get("incomplete", False) and parsed["unparsed_count"] == 0
    if query == "access_points":
        _remember_wtp_ids(auth, [item["name"] for item in parsed["records"] if item["name"]])
    elif query == "wlans":
        _remember_wtp_ids(auth, [item["name"] for item in parsed["records"] if item["name"]], "wlan_names")
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


_NXOS_PROBES = frozenset({"ping", "ping_source", "ping6", "ping6_source",
                          "traceroute", "traceroute_source", "traceroute6", "traceroute6_source"})


def _nxos_probe_complete(query, text, parameters):
    """Recognize completion, not connectivity success; a lost ping is still a measurement."""
    if query.startswith("ping"):
        counts = re.search(r"(?m)^5 packets transmitted, ([0-5]) packets received, [0-9.]+% packet loss\s*$", text)
        return counts is not None
    # NX-OS SSH exec omits the traceroute banner. A hop ends with all three
    # probe answers. Earlier hops alone must never look like a completed trace.
    for line in text.splitlines():
        hop = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not hop:
            continue
        answers = re.findall(r"\b[0-9.]+ ms\b|\*", hop[2])
        reached = re.search(r"(?<![0-9A-Fa-f:.])" + re.escape(parameters["address"]) + r"(?![0-9A-Fa-f:.])", hop[2])
        if len(answers) >= 3 and (reached or int(hop[1]) == 30 or re.search(r"![A-Z]", hop[2])):
            return True
    return False


_JUNOS_TRACEROUTE_HOP = re.compile(r"(?m)^[ \t]*(\d{1,2})[ \t]+([^\r\n]+)")
_JUNOS_TRACE_ADDRESS = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
_JUNOS_TRACE_RTT = r"[0-9]+(?:\.[0-9]+)?[ \t]+ms"
_JUNOS_TRACEROUTE_PROBE = re.compile(
    rf"\b(?P<address>{_JUNOS_TRACE_ADDRESS})\b|\b{_JUNOS_TRACE_RTT}\b(?P<marker>[ \t]*!\S*)?"
)
_JUNOS_TRACEROUTE_BANNER = re.compile(
    rf"traceroute to {_JUNOS_TRACE_ADDRESS} \({_JUNOS_TRACE_ADDRESS}\), [0-9]+ hops max, [0-9]+ byte packets"
)
_JUNOS_TRACEROUTE_FULL_HOP = re.compile(
    rf"([0-9]{{1,2}})(?:[ \t]+(?:\*|(?:{_JUNOS_TRACE_ADDRESS}[ \t]+)?"
    rf"{_JUNOS_TRACE_RTT}(?:[ \t]*!(?:[A-Z]|[0-9]+)?)?)){{3}}"
)


def _junos_traceroute_summary(command: str, output: str) -> dict[str, Any] | None:
    hops = _JUNOS_TRACEROUTE_HOP.findall(output)
    if not hops:
        return None
    last_hop, probes = hops[-1]
    target = command.split()[1]
    responder = None
    reached = False
    for probe in _JUNOS_TRACEROUTE_PROBE.finditer(probes):
        if probe["address"] is not None:
            responder = probe["address"]
        elif responder == target and (probe["marker"] or "").strip() in {"", "!"}:
            # A standalone ! is a low reply TTL. !H, !N, etc. are ICMP failure codes.
            reached = True
    return {
        "destination_reached": reached,
        "hop_limit_reached": not reached and int(last_hop) == TRACEROUTE_MAX_HOPS,
        "last_hop": int(last_hop),
        "max_hops": TRACEROUTE_MAX_HOPS,
    }


def _junos_traceroute_rows_complete(output: str) -> bool:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines and _JUNOS_TRACEROUTE_BANNER.fullmatch(lines[0]):
        lines = lines[1:]
    return output.endswith("\n") and bool(lines) and all(
        (hop := _JUNOS_TRACEROUTE_FULL_HOP.fullmatch(line)) is not None and int(hop[1]) == index
        for index, line in enumerate(lines, 1)
    )


def _fortigate_interface_samples(auth):
    from . import fortigate_tables

    session_unavailable = False

    def read(command):
        nonlocal session_unavailable
        start = time.monotonic()
        if session_unavailable:
            return start, ''
        try:
            rc, text = _verified_read(auth, 'fortinet', command)
        except Exception as exc:
            code = _transport_cause(exc)
            if code is None:
                raise
            reader = _FORTINET_READER.get()
            session_unavailable = code == 'disconnected' or (
                reader is not None and getattr(reader.cli, '_closed', False))
            # Keep the verified link state and the remaining telemetry samples.
            rc, text = None, ''
        midpoint = (start + time.monotonic()) / 2
        if normalization.output_status(text, rc=rc, profile='fortinet', command=command) != 'ok':
            text = ''
        return midpoint, text

    start, before = read(fortigate_tables.INTERFACE_COUNTERS_COMMAND)
    _, speed = read(fortigate_tables.INTERFACE_SPEED_COMMAND)
    end, after = read(fortigate_tables.INTERFACE_COUNTERS_COMMAND)
    return fortigate_tables.interface_samples(end - start, before, speed, after)


def _junos_count_matches(auth, profile, query, expected, *, pattern="[[:graph:]]"):
    command = READ_QUERIES[profile][query].command.removesuffix(" | no-more")
    try:
        rc, count = read_from_device(auth, profile, command + f' | match "{pattern}" | count | no-more')
    except Exception:
        return False
    return rc == 0 and count.strip() == f"Count: {expected} lines"


def _junos_counter_count_matches(auth, profile, query, output):
    # Ignore blank lines so CLI formatting and transport whitespace agree.
    return _junos_count_matches(auth, profile, query, sum(bool(line.strip()) for line in output.splitlines()))


def _junos_g134_output(auth, profile, query, output, rc, parameters, clock_read):
    """Return safe query text and snapshot labels, or a fixed error classification."""
    from . import junos_management
    from .switch_dhcp import junos_dhcp_status

    if len(output.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return "", {}, "truncated"
    if query == LOG_HISTORY_QUERY:
        output = _JUNOS_LAST_PAGER_MARK.sub("", output)
    state = normalization.output_status(output, rc=rc, profile=profile)
    if normalization.permission_refused(profile, output):
        return "", {}, "permission_denied"
    if _cli_refused(profile, output):
        return "", {}, junos_dhcp_status(query, output) or (state if state == "unsupported" else "device_cli_error")
    if state not in {"ok", "empty"}:
        return "", {}, "device_cli_error" if state == "transport_error" else state
    if state == "empty" and query != LOG_HISTORY_QUERY and not query.endswith("_statistics"):
        return output, {}, None
    if query in JUNOS_CONFIG_COMMANDS:
        try:
            projected = junos_management.json_lines(junos_management.config_projection(query, output))
        except ValueError:
            return "", {}, "unparsed"
        return _redact_output(projected, auth), {}, None
    if query == LOG_HISTORY_QUERY:
        try:
            if not clock_read or not clock_read.get("ok"):
                raise ValueError("missing Junos clock")
            clock, zone = junos_management.device_clock(clock_read["text"])
        except ValueError:
            # Keep the fixed error and withhold the unfiltered log.
            return "", {}, "unparsed"
        date_reference = clock
        clock_verified = True
        if clock.hour == 23 and clock.minute >= 58:
            # A capture near midnight may contain classic log entries from the next day or year.
            # Keep the earlier clock for completeness: the later sample is only for dating entries.
            after = _triage_read(auth, profile, "uptime")
            try:
                later, later_zone = junos_management.device_clock(after["text"] if after.get("ok") else "")
                clock_verified = later_zone == zone and timedelta(0) <= later - clock <= timedelta(minutes=5)
                if clock_verified:
                    date_reference = later
            except ValueError:
                clock_verified = False
        projected, coverage = junos_management.log_history(
            output, parameters, clock, zone, truncated=False,
            date_reference=date_reference, clock_verified=clock_verified)
        return _redact_output(projected, auth), {"log_history": coverage}, None
    if query == "snmp_statistics":
        try:
            counters, extended = junos_management.snmp_counters(output)
        except ValueError:
            return "", {}, "unparsed"
        if not extended and not _junos_counter_count_matches(auth, profile, query, output):
            return "", {}, "unparsed"
        return _redact_output(junos_management.json_lines(counters), auth), {}, None
    if query == "system_users":
        try:
            sessions = junos_management.session_projection(output)
        except ValueError:
            return "", {}, "unparsed"
        return _redact_output(junos_management.json_lines(sessions), auth), {"session_count": len(sessions)}, None
    if query == "dns_lookup":
        if output.strip() == ";; connection timed out; no servers could be reached":
            return "", {}, "dns_timeout"
        if not junos_management.dns_output_complete(output):
            return "", {}, "unparsed"
    state = junos_dhcp_status(query, output)
    if state == "needs_count":
        state = None if _junos_counter_count_matches(auth, profile, query, output) else "unparsed"
    return _redact_output(output, auth), {}, state


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
    extender_modem = normalized == "fortinet" and query == health_rules.EXTENDER_MODEM_QUERY
    empty_allowed = entry is not None and entry.empty_allowed
    nxos_overlay = normalized == "cisco_nxos" and query in NXOS_G97_QUERIES
    nxos_management = normalized == "cisco_nxos" and query in NXOS_G95_QUERIES
    nxos_log = normalized == "cisco_nxos" and query in {NXOS_LOG_HISTORY, "log_messages"}
    nxos_gateway = normalized == "cisco_nxos" and query in health_rules.NXOS_GATEWAY_QUERIES
    nxos_g93 = nxos_log or normalized == "cisco_nxos" and query in NXOS_G93_QUERIES
    sequence = is_read_sequence(normalized, query)
    ios_security = query in _IOS_SECURITY_QUERIES.get(normalized, {})
    adc_interface_read = normalized == "fortiadc" and query in fortiadc_diagnostics.INTERFACE_EXEC_QUERIES
    adc_summary = normalized == "fortiadc" and query == "interface_summary"
    prompt = entry is not None and entry.pty
    transport = _TRANSPORT_PTY if prompt or (sequence and not adc_summary) else _SSH_TRANSPORTS[normalized]
    output_filter: dict[str, str] = {}
    if sequence:
        _, commands, output_filter = render_read_sequence(normalized, query, parameters, _read_inventory(auth))
    c9800_read = normalized == "cisco_xe" and query.startswith("c9800_")
    pagination_source = "fresh"
    identity_response = None
    g135 = normalized in JUNOS_PROFILES and query in G135_QUERIES
    g134 = normalized in JUNOS_PROFILES and query in G134_QUERIES
    ios_g57 = normalized in {"cisco_ios", "cisco_xe"} and query in IOS_G57_QUERIES
    qfp_read = normalized == "cisco_xe" and query in {"qfp_drops", "qfp_utilization"}
    # The QFP parser classifies a blank capture as incomplete.
    empty_allowed = empty_allowed or qfp_read
    xe_probe = normalized == "cisco_xe" and query in IOS_XE_PROBE_QUERIES
    xe_log = normalized in {"cisco_ios", "cisco_xe"} and query == XE_LOG_HISTORY
    exos_log = normalized == "extreme_exos" and query == EXOS_LOG_HISTORY
    exos_buffer_log = normalized == "extreme_exos" and query in _EXOS_LOG_QUERIES
    xe_detail = normalized in {"cisco_ios", "cisco_xe"} and query in health_rules.XE_DETAIL_KEYS
    xe_g72 = xe_log or xe_detail
    ios_management = normalized in {"cisco_ios", "cisco_xe"} and query in IOS_MANAGEMENT_QUERIES
    management_complete = False
    ios_management_refusal = None
    xe_source_privileged = False
    line_limit = None
    labels: dict[str, Any] = {}
    junos_labels: dict[str, Any] = {}
    eos_log_metadata = None
    stderr_failure = None
    ruckus_config_refused = False
    exos_log_refused = False
    if offset:
        if not _named_snapshot(content_sha256):
            raise _pagination_refused(_SSH_SNAPSHOT_UNNAMED)
        cached = _load_continuation((*cache_key, content_sha256), auth)
        if cached is None:
            raise _pagination_refused(_SSH_SNAPSHOT_EXPIRED)
        rc, cleaned = cached
        with _SSH_CACHE_LOCK:
            capture = _SSH_PAGE_CACHE.get((*cache_key, content_sha256))
            if capture is not None:
                identity_response, line_limit, cached_labels, eos_log_metadata = capture[4:]
                labels = dict(cached_labels or {})
                management_complete = labels.pop("_ios_management_complete", False)
                if g134:
                    junos_labels, labels = labels, {}
        pagination_source = "cached"
    else:
        try:
            with _scope_capture() as holder:
                if normalized == "cisco_ios" and empty_allowed:
                    holder["ios_empty_allowed"] = True
                if g135 or g134:
                    holder["junos_firmware"] = True
                if ios_g57:
                    holder["ios_g57"] = True
                if ios_management:
                    holder["ios_management"] = True
                if xe_log:
                    holder["xe_log_history"] = True
                if exos_log:
                    holder["exos_log_history"] = parameters["source"]
                if xe_detail:
                    holder["xe_detail"] = True
                if extender_modem or normalized == "fortinet" and query in FORTIOS_IPSEC_KEY_QUERIES:
                    holder["fortios_firmware"] = True
                if ios_security:
                    holder["ios_security_read"] = True
                try:
                    if adc_summary:
                        rc, output, failed_command = _verified_fortiadc_interface_summary(auth, commands)
                        if failed_command is not None:
                            command = failed_command
                    else:
                        rc, output = (_verified_sequence(auth, normalized, commands) if sequence
                                      else _verified_read(auth, normalized, command, prompt))
                    if normalized == 'fortinet' and query == INTERFACE_LIST_QUERY and output.strip() and (
                            normalization.output_status(output, rc=rc, profile=normalized, command=command) == 'ok'):
                        with _scope_capture():
                            output += _fortigate_interface_samples(auth)
                finally:
                    labels = fortios_vdom.label(holder.get("scope"), query, holder.get("index"))
                    if normalized == "cisco_nxos":
                        labels.update(_nxos_firmware(holder, query))
                    elif ios_security:
                        labels.update(_ios_security_firmware(holder, normalized, query))
                    elif normalized == "cisco_xe":
                        labels.update(_ios_xe_port_firmware(holder, query))
                    if c9800_read and (identity := holder.get("product_identity")) is not None:
                        from netops_core import c9800, tested

                        labels.update(_firmware_fields(tested.support(
                            "IOS XE", identity["os_version"], c9800.DOCUMENTED_RELEASES,
                            model=identity["model"], function=query,
                        )))
                    if qfp_read and (identity := holder.get("product_identity")) is not None:
                        from netops_core import tested

                        # Cisco's QFP examples identify the platform family but omit its running release.
                        labels.update(_firmware_fields({
                            "status": tested.UNTESTED, "platform": "IOS XE", "device_version": identity["os_version"],
                            "model": identity["model"], "tested_versions": [],
                            "message": "Cisco's published hardware QFP samples do not identify a tested IOS XE release.",
                        }))
                    if extender_modem and (identity := holder.get("fortios_identity")) is not None:
                        from netops_core import tested

                        model, version, build = identity
                        labels.update(_firmware_fields(tested.support(
                            "FortiOS", f"{version} build{build}", ("5.4 (Fortinet CLI fixture, build unspecified)",),
                            model=model, function=query)))
                    elif "fortios_identity" in holder:
                        from .fortios_diagnostics import fortios_support
                        from .triage_vpn import DETAIL_IDENTITIES

                        labels.update(_firmware_fields(fortios_support(
                            holder["fortios_identity"], DETAIL_IDENTITIES, query)))
                    if (xe_probe or ios_management) and (identity := holder.get("product_identity")) is not None:
                        from netops_core import tested
                        os_name, versions = (
                            ("IOS", ("15.9(3)M12", "15.2(20200924:215240)")) if normalized == "cisco_ios"
                            else ("IOS XE", ("17.18.2",))
                        )
                        labels.update(_firmware_fields(tested.support(
                            os_name, identity["os_version"], versions, model=identity["model"], function=query,
                        )))
                    if xe_probe:
                        xe_source_privileged = holder.get("xe_source_privileged", False)
                    if ios_g57 and (identity := holder.get("product_identity")) is not None:
                        from netops_core import tested

                        os_name, versions = (("IOS", ("15.9(3)M12",)) if normalized == "cisco_ios"
                                        else ("IOS XE", ("17.18.2",)))
                        if query == "qos_queues":
                            # Vendor captures supply the populated hardware queue results.
                            versions = ((("Catalyst 2960-X", "15.2(6)E"),) if normalized == "cisco_ios"
                                        else (("Catalyst 9300", "16.12.3"),))
                        labels.update(_firmware_fields(tested.support(
                            os_name, identity["os_version"], versions, model=identity["model"], function=query,
                        )))
                    if xe_g72 and (identity := holder.get("product_identity")) is not None:
                        from netops_core import tested
                        labels.update(_firmware_fields(tested.support(
                            "IOS" if normalized == "cisco_ios" else "IOS XE", identity["os_version"],
                            health_rules.IOS_HEALTH_TESTED if normalized == "cisco_ios" else health_rules.XE_HEALTH_TESTED,
                            model=identity["model"], function=query,
                        )))
                    if exos_log:
                        labels.update(holder.get("exos_log_firmware", {}))
                    read_scope = {"scope": holder.get("scope")}
                    if g135 or g134:
                        identity_response = holder.get("junos_identity")
                    elif normalized == "cisco_ios" and query == "etherchannel_load_balance":
                        identity_response = holder.get("product_identity")
        except fortios_vdom.VdomRefused as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport,
                "error_code": exc.code, "error": str(exc), **labels,
            }
        except _ProductIdentityError as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": exc.rc,
                "error_code": "product_identity", "error": str(exc),
                **({"complete": False} if adc_interface_read or xe_probe or xe_g72 or nxos_g93 or exos_log else {}),
                **({"reason": exc.reason} if normalized in normalization.IDENTITY_PROFILES else {}),
            }
        except _NxosTraceTimeout as exc:
            hops = "".join(line for line in exc.output.decode("utf-8", "replace").splitlines(keepends=True)
                           if line.endswith("\n") and re.match(r"[ \t]*(?:[1-9]|[12][0-9]|30)[ \t]+", line))
            cleaned = _redact_output(hops, auth)
            return {
                "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                "transport": transport, "status": "timeout", "complete": False, **labels,
                **_transport_failure("timeout", auth),
                "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
            }
        except Exception as exc:
            status = _transport_status(exc) if normalized in normalization.IDENTITY_PROFILES else None
            if exos_log and status == "truncated":
                status = "incomplete"
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, **_read_failure(exc, auth),
                **({"complete": False} if adc_interface_read or xe_probe or xe_g72 or nxos_g93 or exos_log else {}),
                **(labels if xe_probe or xe_g72 else {}),
                **({"status": status} if status else {}),
                **({"status": "incomplete", "complete": False} if extender_modem else {}),
            }
        if extender_modem:
            # This command can contain subscriber identifiers anywhere in the reply, including refusal text.
            # Only the typed projection is exposed. Do not cache or page the original bytes.
            body = strip_terminal_controls(output)
            refused = rc not in (0, None) or _cli_refused(normalized, body, command=command)
            summary = health_rules.fortiextender_modem_status("" if refused else body)
            return {
                "ok": not refused, "target": auth.alias, "platform": normalized, "query": query,
                "transport": transport, "rc": rc, "pagination_source": "fresh", **labels, **_page_text("", 0, max_bytes),
                "status": summary["status"], "complete": summary["complete"],
                "fortiextender_modem": {"modems": summary["modems"],
                                       "identifiers_redacted": summary["identifiers_redacted"]},
                **({"error_code": "device_cli_error", "error": "The FortiExtender modem query was refused"}
                   if refused else {}),
            }
        if empty_allowed and holder.get("unexpected_stderr") and (not xe_log or not output.strip()):
            stderr_failure = {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc, "status": "unparsed",
                "error_code": "device_cli_error", "error": _EMPTY_READ_STDERR_ERROR,
                **(labels if ios_g57 else {}),
                **({"complete": False} if xe_g72 or nxos_g93 or exos_log else {}),
            }
        if normalized == "extreme_exos" and query in {"radius", "tacacs", "accounts", "netlogin", "netlogin_port", "management", "snmp_targets"}:
            from .exos_services import redact_credentials
            output = redact_credentials(output)
        if normalized == "ruckus_unleashed":
            from .sanitize import redact_ruckus_secrets, ruckus_config_allowlist
            secrets = _redaction_secret_forms(auth)
            output = redact_ruckus_secrets(output, secrets)
            if query == "config_settings":
                # Test the CLI reply before the section filter replaces top-level refusal text.
                ruckus_config_refused = _cli_refused(normalized, output, command=command)
                output = "" if ruckus_config_refused else ruckus_config_allowlist(output, secrets)
        if normalized == "arista_eos":
            projected = eos_management_status(query, output)
            if output.strip() and not projected.strip():
                return {
                    "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                    "transport": transport, "rc": rc, "status": "unparsed",
                    "error_code": "incomplete_output",
                    "error": "The device response did not contain recognized operational fields",
                }
            output = projected
        if ios_g57 and query in {"ikev1_sa", "ikev2_sa", "ipsec_sa"}:
            output = redact_cisco_sa_keys(output)
        if normalized == "cisco_ios" and query == "qos_policy":
            output = re.sub(r"[ \t]+(--More--)[ \t\r\n]*\Z", r"\n\1\n", output, flags=re.I)
        if normalized == "juniper_junos" and query in {"ike_security_associations", "ipsec_security_associations"}:
            from .sanitize import redact_junos_sa_keys
            output = redact_junos_sa_keys(output)
        if normalized == "fortinet" and query in FORTIOS_IPSEC_KEY_QUERIES:
            # ipsec status: IKE/ESP key material before hashing, paging and the response.
            output = redact_fortios_ipsec_keys(output)
        if normalized == "cisco_xe" and query == "authentication_sessions_interface":
            # Cisco redirect URLs can include per-session tokens of any length.
            output = _ACCESS_SESSION_REDIRECT.sub(r"\1 <REDACTED>", strip_terminal_controls(output))
        if ios_management:
            state = normalization.output_status(strip_terminal_controls(output), rc=rc, profile=normalized, command=command)
            if state in {"permission_denied", "unsupported"}:
                ios_management_refusal = state
            output, management_complete = redact_ios_management(query, output, classic_ios=normalized == "cisco_ios")
        if normalized == "cisco_xe" and query == "c9800_client_deletes":
            output = wifi_parse.c9800_preserve_numeric_counters(output)
        community_secrets: set[str] = set()
        if nxos_management:
            if query == "snmp_statistics":
                _, labels["_snmp_table_masked"] = redact_nxos_snmp_communities(
                    output, community_secrets=community_secrets)
            state = normalization.output_status(output, rc=rc, profile=normalized, command=command)
            output, recognized = nxos_management_output(query, output)
            if query == "radius_statistics" and output.strip() == "RADIUS server not found":
                state = "not_applicable"
            elif state == "ok" and not recognized:
                state = "unparsed"
            labels["_nxos_management_state"] = state
        if normalized in {"cisco_ios", "cisco_xe"} and (xe_log or query in {"log_messages", "log_warnings"}):
            output = redact_ios_log_commands(output)
        if exos_log or exos_buffer_log:
            exos_log_refused = _cli_refused(normalized, output, command=command)
            exos_state = normalization.output_status(output, rc=rc, profile=normalized, command=command)
            output, exos_withheld = redact_exos_log_commands(output)
            if exos_buffer_log and (exos_withheld or exos_state == "truncated"):
                labels["status"] = "incomplete"
        if (xe_detail or nxos_gateway) and query in {"hsrp_detail", "vrrp_detail", "vrrpv3_detail"}:
            ios_paged = normalized == "cisco_ios" and normalization.output_status(
                strip_terminal_controls(output), rc=rc, profile=normalized, command=command,
            ) == "truncated"
            output = health_rules.xe_redact_fhrp(output)
            if ios_paged and not output.rstrip().endswith("--More--"):
                output = output.rstrip() + "\n--More--\n"
        if g134:
            cleaned, junos_labels, state = _junos_g134_output(
                auth, normalized, query, output, rc, parameters or {}, holder.get("junos_log_clock"))
            if state == "not_applicable":
                junos_labels["status"] = state
            elif state:
                known_status = ("timeout" if state == "dns_timeout" else
                                state if state in normalization.RESULT_STATES else "unparsed")
                return {
                    "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                    "transport": transport, "rc": rc, "status": known_status, "complete": False,
                    "error_code": ("incomplete_output" if state in {"unparsed", "truncated"} else state),
                    "error": ("The device's DNS lookup timed out without reaching a resolver"
                              if state == "dns_timeout" else
                              "The device did not provide a complete, recognized output"
                              if state in {"unparsed", "truncated"} else
                              "The device command failed or was refused; check command support and account permissions"),
                    **({"archive_correlation": "external_archive_unavailable"}
                       if query == LOG_HISTORY_QUERY and state == "permission_denied" else {}),
                }
        else:
            cleaned = _redact_output(output, auth, extra_secrets=community_secrets)
        if query == FILTER_BINDING_QUERY:
            from .tables import junos_firewall_bindings
            if not (re.fullmatch(r"\s*error: (?:permission denied(?:: [\w-]+)?|unknown command)[^\S\n]*\s*", cleaned)
                    or junos_firewall_bindings(cleaned)["complete"]):
                return {
                    "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                    "transport": transport, "rc": rc, "status": "unparsed",
                    "error_code": "incomplete_output", "error": "Unrecognized IPv4 firewall filter binding output",
                }
        if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc,
                "error": "SSH output exceeds the 2000000-byte safety cap",
                **({"complete": False} if adc_interface_read or xe_g72 or nxos_g93 or exos_log else {}),
                **({"status": "incomplete"} if exos_log else {}),
            }
        try:
            cleaned = _fortiswitch_configuration_output(normalized, query, parameters, cleaned, read_scope)
        except fortios_vdom.VdomRefused as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc,
                "error_code": exc.code, "error": str(exc), **labels,
            }
        if "other_vdom_records" in read_scope:
            # Multi-VDOM VLAN projection: only the VLAN interfaces whose own `set vdom` names this VDOM.
            labels.update(data_scope="vdom", other_vdom_records=read_scope["other_vdom_records"])
        if nxos_g93 and (rc not in (0, None) or _cli_refused(normalized, cleaned, command=command)):
            state = normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)
            return {
                "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                "transport": transport, "rc": rc, "complete": False,
                "status": state if state in {"permission_denied", "unsupported"} else "unparsed",
                "error_code": "device_cli_error", "error": "The device command failed or was refused", **labels,
            }
        if xe_g72 and rc not in (0, None):
            return {
                "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                "transport": transport, "rc": rc, "status": "unparsed", "complete": False,
                "error_code": "device_cli_error", "error": "The device command exited unsuccessfully", **labels,
            }
        if xe_log and not _cli_refused(normalized, cleaned, command=command):
            state = normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)
            cleaned, coverage = health_rules.xe_log_history(
                cleaned, parameters or {}, holder.get("xe_log_clock", {}), state, _LOG_MAX_LINES, profile=normalized)
            labels["log_history"] = coverage
        if nxos_log and not _cli_refused(normalized, cleaned, command=command):
            if stderr_failure is not None and not cleaned.strip():
                return stderr_failure
            state = normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)
            cleaned, labels["log_history"] = health_rules.nxos_log_history(
                cleaned, parameters if query == NXOS_LOG_HISTORY else {"count": "200"}, state)
        if exos_log:
            if rc not in (0, None) or exos_log_refused:
                denied = exos_state == "permission_denied"
                return {
                    "ok": False, "target": auth.alias, "platform": normalized, "query": query,
                    "transport": transport, "rc": rc, "complete": False,
                    "status": "permission_denied" if denied else "incomplete",
                    "error_code": "permission_denied" if denied else "device_cli_error",
                    "error": "The EXOS log read was refused or failed",
                }
            cleaned, coverage = health_rules.exos_log_history(
                cleaned, parameters, exos_state, _LOG_MAX_LINES, withheld=exos_withheld,
                clock=holder.get("exos_log_clock"), oldest=holder.get("exos_log_oldest"))
            labels.update(log_history=coverage, status=coverage["status"])
        if normalized == "arista_eos" and query in EOS_LOG_WINDOW_QUERIES:
            state = normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)
            unreadable = 0
            interface = (parameters or {}).get("interface")
            if interface and rc in (None, 0) and state in {"ok", "empty", "truncated"} and not _cli_refused(
                    normalized, cleaned, command=command):
                from .triage_health import eos_filter_log_interface
                cleaned, unreadable = eos_filter_log_interface(cleaned, interface)
            eos_log_metadata = (state, unreadable)
        if exos_buffer_log:
            cleaned, line_limit = _limit_log_lines(cleaned)
            if line_limit["truncated"]:
                labels["status"] = "incomplete"
        elif normalized in _OLDEST_FIRST_LOG_PROFILES and query in _OLDEST_FIRST_LOG_QUERIES:
            if normalized.startswith("juniper_junos"):
                cleaned = _JUNOS_LAST_PAGER_MARK.sub("", cleaned)
            cleaned, line_limit = _limit_log_lines(cleaned, oldest_first=True)
    management_state = labels.pop("_nxos_management_state", None)
    snmp_table_masked = labels.pop("_snmp_table_masked", False)
    empty_output = not cleaned.strip()
    empty_allowed = (empty_allowed or junos_labels.get("status") == "not_applicable"
                     or junos_labels.get("session_count") == 0)
    mac_filter = None
    refused = (ruckus_config_refused or ios_management_refusal is not None or exos_log_refused
               or _cli_refused(normalized, cleaned, command=None if sequence else command))
    traceroute = _is_junos_traceroute(normalized, command)
    trace_summary = _junos_traceroute_summary(command, cleaned) if traceroute else None
    traceroute_failed = traceroute and not empty_output and trace_summary is None
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
    # These EXOS protocol reads return exactly one newline with status 250 when there is no state.
    exos_empty_250 = (
        normalized == "extreme_exos" and rc == 250 and cleaned == "\n"
        and query in _EXOS_BLANK_STATUS_250_QUERIES and empty_allowed
    )
    exos_success_250 = exos_empty_250 or normalization.exos_exit_250(normalized, rc, cleaned, command=command)
    exos_250_error = normalized == "extreme_exos" and rc == 250 and not empty_output and not exos_success_250
    # Measured in a verified VDOM context: a profile without diagnose answers only `Unknown action 0`.
    diagnose_denied = (labels.get("vdom_mode") == "multiple" and not sequence
                       and fortios_vdom.diagnose_refused(command, cleaned))
    forwarding_failed = (normalized == "cisco_nxos" and query == "forwarding_ipv4_route"
                         and (rc not in (0, None) or re.search(r"(?m)^\s*Cmd exec error\.[ \t]*$", cleaned)))
    partial_forwarding = forwarding_failed and not refused and re.search(r"(?m)^IPv4 routes for table ", cleaned)
    # FortiADC (adc statistics ADC-C13, measured 7.6.7 build0676): a profile without diagnose rejects the first diagnose word.
    adc_diagnose_denied = normalized == "fortiadc" and not sequence and _fortiadc_diagnose_refused(command, cleaned)
    adc_interface_failed = adc_interface_read and rc not in (0, None)
    adc_interface_denied = (adc_interface_read and auth.account_role == "read-only"
                            and fortiadc_diagnostics.interface_exec_refusal(command, cleaned) is not None)
    xe_missing_vrf = (xe_probe and (parameters or {}).get("vrf") and re.search(
        r"(?m)^vrf " + re.escape(parameters["vrf"]) + r" does not exist(?:[ \t]+\^)?[ \t]*$", cleaned,
    ))
    xe_invalid_source = xe_source_privileged and not xe_missing_vrf
    management_failed = (
        nxos_management and (rc not in (0, None) or management_state in {"permission_denied", "unsupported"})
    ) or (ios_management and not empty_output and rc not in (0, None))
    if (management_failed or forwarding_failed or exos_250_error
            or (refused and not (mclag and mclag_not_supported(query, cleaned)))
            or lookup_route_failed or traceroute_failed or adc_interface_failed):
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": ("permission_denied" if (wifi_permission_denied or diagnose_denied or adc_diagnose_denied
                                                   or adc_interface_denied)
                           else "incomplete_output" if adc_interface_failed and not refused
                           else "invalid_argument" if xe_invalid_source else "device_cli_error"),
            "error": ("Wi-Fi diagnostics need an admin-bounded account with wifi read-write and cli-diagnose; or remove wifi_* from the target's enabled_queries" if wifi_permission_denied else
                      fortios_vdom.ADVICE["diagnose_not_permitted"] if diagnose_denied else
                      "The FortiADC read-only profile was denied access to this interface command" if adc_interface_denied else
                      _fortiadc_diagnose_advice() if adc_diagnose_denied else
                      "The FortiADC interface command exited unsuccessfully; its output may be incomplete" if adc_interface_failed and not refused else
                      "Policy lookup could not resolve a route for the supplied flow" if lookup_route_failed else
                      "The enrolled VRF does not exist on the device" if xe_missing_vrf else
                      "The device rejected a probe parameter; check that the source interface exists and can be used"
                      if xe_invalid_source else
                      "Traceroute returned a diagnostic without any hop results" if traceroute_failed and not refused else
                      "The device returned a partial forwarding table before the command failed" if partial_forwarding else
                      "The requested RADIUS server is not configured on the device"
                      if nxos_management and query == "radius_statistics" and management_state == "not_applicable" else
                      "The device has no access point, WLAN or client with that MAC address or name"
                      if normalized == "ruckus_unleashed" and wifi_parse.RUCKUS_NOT_FOUND.search(cleaned) else
                      "The device command exited unsuccessfully" if management_failed and not refused else
                      "The device CLI refused the command; check its supported features and account permissions"),
            **({"reason": "diagnose_not_permitted"} if diagnose_denied or adc_diagnose_denied else {}),
            **({"status": management_state, "complete": False} if nxos_management else {}),
            **({"complete": False} if forwarding_failed else {}),
            **({"status": ios_management_refusal} if ios_management_refusal else {}),
            **({"status": "not_applicable"} if xe_missing_vrf else {}),
            **({"status": "unparsed"} if xe_invalid_source else {}),
            **({"status": normalization.output_status(cleaned, rc=rc, profile=normalized, command=command),
                "complete": False} if normalized == "arista_eos" and refused else {}),
            **({"complete": False} if adc_interface_read or xe_probe or ios_g57 or xe_g72 or nxos_overlay or ios_management or nxos_g93 else {}),
            **labels,
            "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
        }
    if normalized == "cisco_nxos" and query in _NXOS_PROBES and not empty_output:
        failed = rc not in (0, None, 1) or re.search(r"(?mi)^traceroute:|^ping6?:.*(?:invalid|not local|cannot|error)", cleaned)
        if failed or not _nxos_probe_complete(query, cleaned, parameters or {}):
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "transport": transport, "rc": rc,
                "error_code": "device_cli_error" if failed else "incomplete_output",
                "error": "The device probe failed" if failed else "The bounded probe returned no complete statistics or final hop",
                "untrusted_device_output": _page_text(cleaned, 0, max_bytes)["untrusted_device_output"],
            }
    if empty_output and stderr_failure is not None:
        return stderr_failure
    fortinet_refused = normalized in _IDENTITY_PLATFORMS and rc == 1
    # Let the overlay adapter report incomplete coverage for blank captures.
    if empty_output and not empty_allowed and not fortinet_refused and not (nxos_overlay or c9800_read):
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "empty",
            "error": "The device returned no output for this query; no result was read", **labels,
            **({"complete": False} if adc_interface_read or xe_probe or xe_g72 or nxos_overlay or nxos_g93 else {}),
        }
    if empty_output and rc not in (0, None) and not exos_empty_250 and junos_labels.get("status") != "not_applicable":
        # empty_allowed means an empty successful read; a failed command without output is not an empty log.
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
        return {
            "ok": False, "target": auth.alias, "platform": normalized,
            "query": query, "transport": transport, "rc": rc,
            "error_code": "device_cli_error",
            "error": "The device command failed without output; no result was read", **labels,
            **({"complete": False} if nxos_overlay else {}),
        }
    if normalized == "ruckus_unleashed" and not offset:
        model, version = (wifi_parse.ruckus_identity(cleaned) if query == "system_info"
                          else _read_ruckus_identity(auth))
        labels.update(_ruckus_firmware_fields(auth, model, version))
    if not offset and normalized in normalization.IDENTITY_PROFILES and query == "version":
        identity_response = _normalized_identity(auth, normalized, rc, cleaned)
    page = _page_text(cleaned, offset, max_bytes, whole_lines=True)
    if g134:
        coverage = junos_labels.get("log_history")
        if coverage is not None and not coverage["complete"]:
            page["complete"] = False
            junos_labels["status"] = "unparsed"
        junos_labels.setdefault("status", "empty" if empty_output else "ok")
    interface_payload = {}
    if adc_summary:
        if offset and cleaned.encode("utf-8")[offset - 1:offset] != b"\n":
            raise ValueError("offset is not an interface row boundary; use next_offset")
        try:
            rows_complete = all(row.get("complete") is True for row in map(json.loads, cleaned.splitlines()))
            interface_payload["interfaces"] = [json.loads(line) for line in page["untrusted_device_output"].splitlines()]
        except (AttributeError, ValueError):
            return {"ok": False, "target": auth.alias, "platform": normalized, "query": query,
                    "transport": transport, "rc": rc, "complete": False, "error_code": "incomplete_output",
                    "error": "The FortiADC interface summary could not be represented safely"}
        if not rows_complete:
            interface_payload.update(complete=False, interface_summary_note="Interface source data is missing for one "
                                     "or more rows. See missing_sources and missing_fields in the affected rows.")
    capture_state = (normalization.output_status(cleaned, rc=0 if exos_empty_250 else rc,
                                                 profile=normalized, command=command)
                     if normalized in normalization.IDENTITY_PROFILES else None)
    if trace_summary is not None:
        if (capture_state == "ok" and (trace_summary["destination_reached"] or trace_summary["hop_limit_reached"])
                and _junos_traceroute_rows_complete(cleaned)):
            labels["status"] = "ok"
        else:
            page["complete"] = False
    if eos_log_metadata and eos_log_metadata[0] not in {"ok", "empty"}:
        capture_state = eos_log_metadata[0]
    if nxos_management:
        capture_state = management_state
        if capture_state != "ok":
            page["complete"] = False
    if ios_management and capture_state == "ok" and not management_complete:
        capture_state = "unparsed"
    if capture_state == "truncated" or (ios_management and capture_state == "unparsed"):
        page["complete"] = False
    if nxos_overlay and offset:
        # A continuation page cannot supply a complete set of normalized records.
        page["complete"] = False
    if xe_log and "log_history" in labels:
        capture_state = labels["log_history"]["status"]
        if not labels["log_history"]["complete"]:
            page["complete"] = False
        labels["status"] = capture_state
    if nxos_log and (coverage := labels.get("log_history")) is not None:
        labels["status"] = coverage["status"]
        capture_state = coverage["status"] if coverage["complete"] else "unparsed"
        if not coverage["complete"]:
            page["complete"] = False
    nxos_health_details = {}
    if normalized == "cisco_nxos" and (nxos_gateway or query == "logging_info"):
        if nxos_gateway:
            summary = health_rules.nxos_gateway_detail(query, cleaned, capture_state)
            nxos_health_details["gateway"] = summary
        else:
            summary = health_rules.nxos_logging_info(cleaned, capture_state)
            nxos_health_details["logging"] = summary
        nxos_health_details["status"] = summary["status"]
        if not summary["complete"]:
            page["complete"] = False
    if exos_log and not labels["log_history"]["complete"]:
        page["complete"] = False
    if exos_buffer_log and labels.get("status") == "incomplete":
        page["complete"] = False
        capture_state = "incomplete"
    xe_summary = (health_rules.xe_detail(query, cleaned, capture_state)
                  if xe_detail and not offset and page["next_offset"] is None else {})
    if normalized == "cisco_ios" and xe_detail and not xe_summary:
        page["complete"] = False
    diagnostics = {}
    firmware = {}
    if (g135 or g134) and identity_response is not None:
        from netops_core import tested
        firmware = _firmware_fields(tested.support(
            "Junos", identity_response["os_version"], TESTED_G134,
            model=identity_response["model"], function="Junos platform diagnostics" if g134 else "Junos security diagnostics",
        ))
    if g135 and not offset and page["next_offset"] is None:
        from .tables import junos_firewall_diagnostics
        count_verified = True
        if query == "security_policies" and capture_state == "ok":
            headers = len(re.findall(r"(?m)^[ \t]*Policy:", cleaned))
            count_verified = _junos_count_matches(auth, normalized, query, headers, pattern="^[[:space:]]*Policy:")
        diagnostics = junos_firewall_diagnostics(
            normalized, query, cleaned, capture_state, parameters, count_verified=count_verified)
    nxos_diagnostics = {}
    if normalized == "cisco_nxos" and not offset and page["next_offset"] is None:
        from . import tables
        from .query_catalog.cisco import NXOS_G94_QUERIES, NXOS_G96_QUERIES

        if nxos_overlay:
            normalized_table = tables.nxos_overlay_diagnostics(query, cleaned, capture_state)
        elif query in tables.NXOS_SCOPED_TABLES:
            table = ("neighbor_l3" if query in tables.NXOS_LOOKUPS else
                     "dhcp_binding" if query == "dhcp_snooping_binding" else "mac_entry")
            normalized_table = tables.parse(normalized, table, query, cleaned, rc=rc, status=capture_state,
                                            command=command)
        elif query in NXOS_G94_QUERIES or query == "access_lists":
            normalized_table = tables.nxos_g94_diagnostics(query, cleaned, parameters or {}, capture_state)
        elif query in NXOS_G96_QUERIES:
            normalized_table = tables.nxos_g96_diagnostics(query, cleaned, parameters or {}, capture_state, rc)
        else:
            normalized_table = None
        if normalized_table is not None:
            nxos_diagnostics = {"normalized": normalized_table}
            if not normalized_table["coverage"]["complete"]:
                nxos_diagnostics["complete"] = False
    ios_diagnostics = {}
    if ios_security and not offset and page["next_offset"] is None:
        from . import tables
        table = tables.IOS_FORWARDING_TABLES.get(query)
        if table:
            ios_diagnostics["normalized"] = tables.parse(normalized, table, query, cleaned, rc=rc,
                                                 status=capture_state, command=command)
        else:
            diagnostic = tables.ios_security_diagnostic(normalized, query, cleaned, capture_state, parameters or {})
            if diagnostic is not None:
                ios_diagnostics["normalized"] = diagnostic
        if ios_diagnostics and not ios_diagnostics["normalized"]["coverage"]["complete"]:
            ios_diagnostics["complete"] = False
    if ios_g57:
        from .tables import ios_g57_diagnostics

        if not offset and page["next_offset"] is None:
            summary = ios_g57_diagnostics(normalized, query, cleaned, parameters or {}, capture_state)
            ios_diagnostics["normalized"] = summary
            page["complete"] = summary["coverage"]["complete"]
        else:
            page["complete"] = False
    c9800_payload = {}
    if c9800_read:
        parsed = wifi_parse.summarize_c9800(query, cleaned, status=capture_state)
        if query == "c9800_client_detail":
            from .normalization import normalize_mac
            expected_mac = normalize_mac((parameters or {})["mac"])
            if not parsed["records"] or parsed["records"][0]["mac"] != expected_mac:
                parsed.update(records=[], complete=False, status="incomplete")
        if query == "c9800_ap_tag_detail":
            if not parsed["records"] or parsed["records"][0]["name"] != (parameters or {})["ap_name"]:
                parsed.update(records=[], complete=False, status="incomplete")
        if offset or page["next_offset"] is not None:
            parsed.update(records=[], complete=False, status="incomplete")
        c9800_payload = {"wifi": parsed, "status": parsed["status"],
                         "complete": page["complete"] and parsed["complete"]}
    qfp_payload = {}
    if qfp_read:
        from .tables import ios_xe_qfp_diagnostic

        diagnostic = ios_xe_qfp_diagnostic(query, cleaned, capture_state,
                                          full_page=not offset and page["next_offset"] is None)
        qfp_payload = {"normalized": diagnostic, "complete": diagnostic["coverage"]["complete"]}
    overlay_failed = nxos_overlay and rc not in (0, None)
    result = {
        "ok": not overlay_failed, "target": auth.alias, "platform": normalized, "query": query,
        "transport": transport, "rc": rc, **labels, **junos_labels,
        "pagination_source": pagination_source, **page, **interface_payload, **c9800_payload,
        **qfp_payload,
        **({"status": capture_state} if ios_management else {}),
        **({"error_code": "device_cli_error", "error": "The device command exited unsuccessfully",
            "complete": False} if overlay_failed else {}),
        **({"line_limit": line_limit} if line_limit else {}),
        **({"normalized": identity_response}
           if identity_response is not None and query == "version" and not (g135 or g134) else {}),
        **({"_warnings": (["exit_status_250"] if exos_success_250 else [])
                          + (["log_line_limit"] if line_limit and line_limit["truncated"] else [])
                          + (["snmp_community_table_unrecognized"] if snmp_table_masked else [])}
           if exos_success_250 or (line_limit and line_limit["truncated"]) or snmp_table_masked else {}),
        **({"status": management_state} if nxos_management else {}),
        **({"_capture_state": capture_state} if normalized in normalization.IDENTITY_PROFILES else {}),
        **({"mclag": mclag_summarize(query, cleaned, parameters)} if mclag else {}),
        **({"vpc": vpc_summarize(cleaned, capture_state)} if normalized == "cisco_nxos" and query == "vpc_status" else {}),
        **({"traceroute": trace_summary} if trace_summary is not None else {}),
        **mlag_eos_payload(normalized, query, cleaned, capture_state),
        **(_eos_management_payload(query, cleaned, parameters) if normalized == "arista_eos" else {}),
        **(_eos_health_routing_payload(query, cleaned, parameters, capture_state, page, line_limit,
                                       eos_log_metadata[1] if eos_log_metadata else 0)
           if normalized == "arista_eos" else {}),
        **mlag_exos_payload(normalized, query, cleaned, capture_state),
        **({"dhcp_bindings": dhcp_bindings_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == DHCP_BINDINGS_QUERY else {}),
        **({"dhcp_leases": fortios_leases_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == FORTIOS_LEASES_QUERY else {}),
        **({"devices": user_devices_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == USER_DEVICES_QUERY else {}),
        **({"sensors": hardware_sensors_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == SENSORS_QUERY else {}),
        **({"crash_log": crash_log_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == CRASH_LOG_QUERY else {}),
        **({"route_database": route_database_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query in ROUTE_DATABASE_QUERIES else {}),
        **({"bgp_neighbors": bgp_neighbors_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query in BGP_NEIGHBOR_QUERIES else {}),
        **({"interfaces": interface_list_summarize(cleaned, page["offset"], page["offset"] + page["returned_bytes"])}
           if normalized == "fortinet" and query == INTERFACE_LIST_QUERY else {}),
        **(_wifi_payload(auth, query, cleaned, mac_filter, output_filter.get("mac_literal"))
           if normalized == "fortinet" and query in wifi_parse.PARSERS else {}),
        **(_ruckus_wifi_payload(auth, query, cleaned)
           if normalized == "ruckus_unleashed" and query in wifi_parse.RUCKUS_PARSERS else {}),
        **({"ha_standby": fortiadc_diagnostics.standby_status(
            cleaned, complete=page["complete"] and not offset)}
           if normalized == "fortiadc" and query == "ha_standby_status" else {}),
        **_nxos_ports_read(normalized, query, cleaned, parameters, capture_state, rc),
        **_optics_payload(normalized, query, cleaned, parameters, capture_state),
        **junos_poe.payload(normalized, query, cleaned, capture_state),
        **(_ios_routing_read(query, cleaned, parameters, capture_state, normalized)
           if normalized in {"cisco_ios", "cisco_xe"} and not xe_probe else {}),
        **(_ios_xe_probe_result(query, cleaned, parameters, capture_state) if xe_probe else {}),
        **(_ios_ports_read(normalized, query, cleaned, parameters, capture_state, (identity_response or {}).get("os_version"))
           if normalized in ("cisco_ios", "cisco_xe") else {}),
        **diagnostics,
        **nxos_diagnostics,
        **nxos_health_details,
        **ios_diagnostics,
        **xe_summary,
        **firmware,
    }
    if stderr_failure is not None and result.get("normalized", {}).get("status", capture_state) == "empty":
        return stderr_failure
    if page["next_offset"] is not None:
        if offset == 0:
            cache_labels = {**labels, **junos_labels}
            if nxos_management:
                cache_labels.update(_nxos_management_state=management_state, _snmp_table_masked=snmp_table_masked)
            if ios_management:
                cache_labels["_ios_management_complete"] = management_complete
            _store_cached_ssh_output(cache_key, rc, cleaned, auth.redaction_secrets, identity_response, line_limit,
                                     cache_labels, eos_log_metadata)
    else:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
    return result


def _eos_health_routing_payload(query, output, parameters, capture_state, page, line_limit, unreadable_logs):
    """eos health (EP09/EP10): EOS log window, health and routing summaries."""
    from .triage_health import eos_health_payload
    from .triage_routing import eos_routing_payload
    return (eos_health_payload(query, output, capture_state, page["offset"], page["offset"] + page["returned_bytes"],
                               parameters, line_limit, unreadable_logs)
            or eos_routing_payload(query, output, parameters, capture_state))


def _eos_management_payload(query, output, parameters):
    if query == "dhcp_relay_counters":
        return {"dhcp_relay_counters": eos_relay_counters(output)}
    if query != "dns_lookup":
        return {}
    name = parameters["name"]
    if output.strip() in {f"{program}: {name}: {error}" for program in ("ping", "ping6")
                          for error in ("Name or service not known", "Temporary failure in name resolution")}:
        return {"dns_lookup": {"name": name, "resolved": False, "address": None}}
    match = re.search(r"(?m)^PING [^\s(]+[ \t]*\(([0-9a-fA-F:.]+)\)", output)
    try:
        address = str(ipaddress.ip_address(match[1])) if match else None
    except ValueError:
        address = None
    return {"dns_lookup": {"name": name, "resolved": True if address else None, "address": address}}


_NXOS_G92_READS = frozenset({
    "interface_details", "interface_transceiver", "stp_detail", "stp_interface_detail", "stp_mst",
    "port_channel_database", "lacp_interface", "port_channel_load_balance", "vpc_status",
    "vpc_member_consistency", "vpc_interface_consistency", "lldp_neighbor_interface", "cdp_neighbor_interface",
})


def _nxos_firmware(holder, query):
    identity = holder.get("product_identity")
    from .query_catalog.cisco import NXOS_G94_QUERIES, NXOS_G96_QUERIES

    if not identity or query not in (_NXOS_G92_READS | NXOS_G94_QUERIES.keys() | NXOS_G96_QUERIES.keys()
                                     | NXOS_G93_QUERIES.keys() | NXOS_G95_QUERIES | NXOS_G97_QUERIES.keys()
                                     | {"access_lists", "dhcp_snooping_binding"}):
        return {}
    from netops_core import tested

    # DOM uses manufacturer's output. The GNS3 image does not measure a physical module.
    versions = ("10.6(x)",) if query == "interface_transceiver" else ("9.3(12)",)
    return _firmware_fields(tested.support("NX-OS", identity["os_version"], versions,
                                           model=identity.get("model"), function=query))


_IOS_SECURITY_QUERIES = {"cisco_ios": IOS_G55_QUERIES, "cisco_xe": IOS_XE_G73_QUERIES}
_ACCESS_SESSION_REDIRECT = re.compile(r"(?mi)^([ \t]*URL[ \t]+Redirect[ \t]*:)[^\n]*?(?=--More--[ \t]*$|$)")


def _ios_security_firmware(holder, profile, query):
    identity = holder.get("product_identity")
    if not identity:
        return {}
    from netops_core import tested

    family, versions = (("IOS XE", ("17.18.2",)) if profile == "cisco_xe"
                        else ("IOS", ("15.2(20200924:215240)", "15.9(3)M12")))
    return _firmware_fields(tested.support(family, identity["os_version"], versions,
                                          model=identity.get("model"), function=query))


def _ios_xe_port_firmware(holder, query):
    identity = holder.get("product_identity")
    if not identity or query not in IOS_XE_PORT_QUERIES.keys() | {"interface_transceiver", "interface_details", "interface_errors"}:
        return {}
    from netops_core import tested

    versions = {"power_inline_detail": ("17.14.x",), "interface_transceiver": ("17.13.x",)}.get(query, ("17.18.2",))
    return _firmware_fields(tested.support(
        "IOS XE", identity["os_version"], versions, model=identity.get("model"), function=query,
    ))


def _nxos_ports_read(platform, query, text, parameters, state, rc):
    if platform != 'cisco_nxos':
        return {}
    from . import switch_vpc, tables
    if query in ('vpc_interface_consistency', 'vpc_member_consistency'):
        return {'vpc_consistency': switch_vpc.consistency(text, state)}
    table = {
        'stp_interface_detail': 'stp_port_counters',
        'lacp_interface': 'lag_member', 'lldp_neighbor_interface': 'lldp_neighbor',
        'cdp_neighbor_interface': 'cdp_neighbor',
    }.get(query)
    if table is None:
        return {}
    interface = (parameters or {}).get('interface')
    field = 'local_port' if table.endswith('_neighbor') else 'port'
    filters = {field: tables.port(interface)} if interface else None
    return {'normalized': tables.parse(platform, table, query, text, rc=rc, status=state, filters=filters)}


def _ios_ports_read(platform, query, text, parameters, state, version):
    """Cisco port, STP, LACP, PoE and neighbor summaries over the redacted capture."""
    from . import ios_ports
    return ios_ports.read(query, text, parameters, state, version=version, profile=platform)


_IOS_PROBES = frozenset({
    "ping", "ping_source", "ping_vrf", "ping_vrf_source", "ping_ipv6", "ping_ipv6_source",
    "traceroute", "traceroute_source", "traceroute_vrf", "traceroute_vrf_source",
})
_IOS_XE_TRACE_HOP = re.compile(
    r"([1-5])[ \t]+(\*|([0-9a-fA-F:.]+)(?: \[AS \d+\])?"
    r"(?: \[MPLS: Labels? ([0-9]+(?:/[0-9]+)*) Exp [0-9]+\])?"
    r"(?: \([^()]+\))?[ \t]+\d+ msec)"
)
_IOS_XE_PING_SENT = re.compile(r"Sending (\d+), \d+-byte ICMP Echos to (\S+), timeout is (\d+) seconds:")
_IOS_XE_PING_TOTAL = re.compile(
    r"Success rate is (\d+) percent \((\d+)/(\d+)\)(?:, round-trip min/avg/max = \d+/\d+/\d+ ms)?"
)


def _ios_probe_result(query, text, parameters, state):
    """Expose measured loss/hops; a missing ping footer is never a completed probe."""
    status = state or "unparsed"
    summary = {"destination": parameters["address"],
               "source_interface": parameters.get("source"), "vrf": parameters.get("vrf")}
    if re.search(r"(?mi)^% (?:Unrecognized host or address, or protocol not running|VRF .*does not exist)", text):
        status = "not_configured"
    if status == "ok":
        if query.startswith("ping"):
            found = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text)
            sent = re.search(r"Sending (\d+),", text)
            if not found or not sent or int(found[3]) != 5 or int(sent[1]) != 5 or not 0 <= int(found[2]) <= 5 or int(found[1]) != int(found[2]) * 20:
                status = "unparsed"
            else:
                summary.update(sent=5, received=int(found[2]), loss_percent=100-int(found[1]),
                               reachable=int(found[2]) > 0, timeout_seconds=1)
        else:
            hops = re.findall(r"(?m)^ *([1-5]) +([^\n]+)$", text)
            if "Tracing the route to " not in text or not hops:
                status = "unparsed"
            else:
                summary.update(max_hops=5, probes_per_hop=1, timeout_seconds=1,
                               hops=[{"hop": int(number), "result": body.strip()} for number, body in hops])
                summary["reached_destination"] = any(
                    parameters["address"] in row["result"].split() for row in summary["hops"])
    envelope = normalization.response_envelope(
        "cisco_ios", status, [normalization.source_record(query, text, status)], identity_coverage=False)
    envelope["coverage"]["complete"] = status == "ok"
    return {"probe": summary, "normalized": envelope}


def _ios_xe_ping(lines, destination, source_interface, vrf):
    if len(lines) < 3:
        return None
    sent = _IOS_XE_PING_SENT.fullmatch(lines[0])
    total = _IOS_XE_PING_TOTAL.fullmatch(lines[-1])
    if not sent or not total or sent[1] != "5" or sent[3] != "1" or ipaddress.ip_address(sent[2]) != destination:
        return None
    replies = lines[1:-1]
    source = None
    prefix = "Packet sent with a source address of "
    if replies[0].startswith(prefix):
        address, _, zone = replies[0].removeprefix(prefix).partition("%")
        source = ipaddress.ip_address(address)
        if source.version != destination.version or (zone and zone != vrf):
            return None
        replies = replies[1:]
    if source_interface and source is None:
        return None
    progress = "".join(replies)
    received = progress.count("!")
    if (not re.fullmatch(r"[!.UQM?&]{5}", progress)
            or (int(total[1]), int(total[2]), int(total[3])) != (received * 20, received, 5)):
        return None
    return {"sent": 5, "received": received, "loss_percent": 100 - received * 20,
            "reachable": received > 0, "timeout_seconds": 1,
            **({"source_address": str(source)} if source is not None else {})}


def _ios_xe_trace(lines, destination):
    header = "Tracing the route to "
    if not lines or not lines[0].startswith(header) or ipaddress.ip_address(lines[0][len(header):]) != destination:
        return None
    rows = lines[1:]
    if rows and rows[0] == "VRF info: (vrf in name/id, vrf out name/id)":
        rows = rows[1:]
    exhausted = bool(rows and rows[-1] == "Destination not found inside max hopcount diameter.")
    if exhausted:
        rows = rows[:-1]
    hops = []
    destination_replied = False
    for number, row in enumerate(rows, 1):
        hop = _IOS_XE_TRACE_HOP.fullmatch(row)
        if not hop or int(hop[1]) != number or destination_replied:
            return None
        if hop[3]:
            address = ipaddress.ip_address(hop[3])
            if address.version != destination.version:
                return None
            destination_replied = address == destination
        measured = {"hop": number, "result": hop[2]}
        if hop[4]:
            measured["mpls_labels"] = [int(label) for label in hop[4].split("/")]
        hops.append(measured)
    if not hops or (exhausted and (destination_replied or len(hops) != 5)):
        return None
    # The verified EXEC prompt also ends traces to a target that replies from another address.
    ended_early = len(hops) < 5 and hops[-1]["result"] != "*"
    if len(hops) < 5 and not ended_early:
        return None
    return {"max_hops": 5, "probes_per_hop": 1, "timeout_seconds": 1,
            "hops": hops, "reached_destination": destination_replied or ended_early,
            "destination_replied": destination_replied}


def _ios_xe_probe_result(query, text, parameters, state):
    destination = ipaddress.ip_address(parameters["address"])
    source = parameters.get("source")
    vrf = parameters.get("vrf")
    measurement = None
    if state == "ok":
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines and lines[0] == "Type escape sequence to abort.":
            lines.pop(0)
            try:
                measurement = (_ios_xe_ping(lines, destination, source, vrf) if query.startswith("ping")
                               else _ios_xe_trace(lines, destination))
            except ValueError:  # The device printed a malformed address.
                pass
        if measurement is None:
            state = "unparsed"
    envelope = normalization.response_envelope(
        "cisco_xe", state, [normalization.source_record(query, text, state)], identity_coverage=False,
    )
    envelope["coverage"]["complete"] = measurement is not None
    if measurement is None:
        return {"ok": False, "complete": False, "normalized": envelope, "error_code": "incomplete_output",
                "error": "The device did not return a complete, recognized probe result"}
    return {"probe": {"destination": str(destination), "source_interface": source, "vrf": vrf, **measurement},
            "normalized": envelope}


def _ios_routing_read(query, text, parameters, state, platform="cisco_ios"):
    if platform == "cisco_ios" and query in _IOS_PROBES:
        return _ios_probe_result(query, text, parameters, state)
    from .triage_routing import ios_read
    return ios_read(query, text, parameters, state, platform)


def _optics_payload(platform, query, text, parameters, capture_state):
    from . import optics
    derived = optics.payload(platform, query, text, parameters)
    if capture_state != "ok":  # the whole capture is not a complete healthy read: nothing is measured
        for summary in derived.values():
            if summary["state"] == "measured":
                summary["state"] = "partial"
            summary["missing_fields"].append("capture")
    return derived


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
    if isinstance(error, core_session.SessionError):
        if error.code in {"timeout", "idle_timeout"}:
            return "timeout"
        if error.code in {"output_limit", "page_limit"}:
            return "output_limit"
        if error.code == "auth":
            return _client_verdict(error) or "auth"
        if error.code == "host_key":
            return "host_key_mismatch"
        if error.code == "negotiation":
            return "negotiation"
        if error.code == "disconnected":
            # Before the first prompt, Core can retain a fixed verdict from the separate client log.
            return _client_verdict(error) or "disconnected"
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


# FortiOS 8.0.2 Administration Guide, "General configurations" (Create per-VDOM administrators): a per-VDOM
# administrator must log in through an interface that belongs to its VDOM; elsewhere FortiOS refuses the login
# (measured verification: `name_invalid` in VDOM root). Added only for a FortiOS target with diagnostic_vdoms.
_FORTIOS_VDOM_AUTH_ADVICE = ("; a per-VDOM administrator of a multi-VDOM FortiGate must log in through an interface "
                             "that belongs to its own VDOM, so check that the enrolled address is in that VDOM")


def _transport_failure(code, auth):
    """The transport class and its fixed advice; `auth` is the target, required so that no path drops its advice."""
    advice = _TRANSPORT_ADVICE[code]
    if (code == "host_key_mismatch" and auth is not None and
            auth.ssh_platform in _IDENTITY_PLATFORMS and getattr(auth, "host_key", None) in (None, "")):
        advice = "missing Fortinet public host key; add host_key at enrollment"
    if (code == "auth" and auth is not None and auth.ssh_platform == "fortinet"
            and auth.read_inventory.get("diagnostic_vdoms")):
        advice += _FORTIOS_VDOM_AUTH_ADVICE
    return {"error_code": code, "error": advice}


def _read_failure(exc, auth):
    """A transport failure as its class and advice; a local refusal keeps ssh_unavailable and its own text."""
    code = _transport_cause(exc)
    if code is None:
        return {"error_code": "ssh_unavailable", "error": _safe_error(exc, auth)}
    return _transport_failure(code, auth)


def _transport_status(exc):
    code = _transport_error_code(exc)
    return "truncated" if code == "output_limit" else "timeout" if code == "timeout" else "transport_error"


def _transport_result(profile, table, query, exc, auth):
    from . import tables
    code = _transport_error_code(exc)
    status = 'truncated' if code == 'output_limit' else 'timeout' if code == 'timeout' else 'transport_error'
    result = tables.parse(profile, table, query, '', status=status)
    result.update(_transport_failure(code, auth))
    return result


def _adc_certificate_inventory(auth, platform, query, parameters, offset, max_bytes, content_sha256):
    from netops_core.fortiadc_https import Management, RequestError
    from . import config_fortiadc
    from .proxy_sanitize import sanitize_object

    offset, max_bytes = _validate_pagination(offset, max_bytes)
    if offset or content_sha256 is not None:
        raise ValueError("certificate_inventory returns a fresh structured result")
    _, command, _ = _ssh_read_state(auth, platform, query, parameters)
    port = auth.require_tcp_port(auth.fortios_rest_port)
    result = {"target": auth.alias, "platform": platform, "query": query,
              "scope": "account-visible global VDOM", "ok": False, "complete": False}
    if auth.credential_kind != "password":
        return {**result, "error_code": "password_credential_required"}
    missing = []
    try:
        acme = None
        with _fortinet_operation(auth) as reader:
            try:
                address, _ = reader.target(platform)
            except (OSError, ValueError, core_hostkey.HostKeyError) as exc:
                return {**result, **_read_failure(exc, auth)}
            client = Management(address, port, auth.fortios_rest_certificate_sha256)
            try:
                rc, output = _verified_read(auth, platform, command)
                if rc in (0, None) and not _cli_refused(platform, output, command=command):
                    acme = config_fortiadc.certificate_acme(output)
            except (OSError, ValueError, core_ssh.SshError, core_session.SessionError, _ProductIdentityError):
                # ACME is an optional extra read (1.0.12 summary): a refused SSH identity read leaves the
                # ACME state unknown (reported in `missing`) but must not discard the HTTPS inventory, which verifies
                # the product identity on its own through platform/info.
                pass
        with client.login(auth.login, auth.secret) as session:
            info = session.read("platform/info", vdom="global")
            if not isinstance(info, dict) or not isinstance(info.get("firmwareVersion"), str):
                raise RequestError("product_identity")
            try:
                identity, _ = config_fortiadc.verify_identity("Version: " + info["firmwareVersion"])
            except (ValueError, config_fortiadc.UnsupportedConfigurationFirmware):
                raise RequestError("product_identity") from None
            entries, missing = config_fortiadc.certificate_inventory(session, acme, datetime.now(timezone.utc))
            entries = sanitize_object(entries, (*auth.secrets, session.token, *session.cookies.values()))
        result.update(_config_firmware_fields(config_fortiadc, identity))
    except RequestError as exc:
        return {**result, "error_code": exc.code}

    entries.sort(key=lambda row: (row["not_after"], row["kind"], row["name"]))
    kept, used = [], 2
    for entry in entries:
        size = len(json.dumps(entry, ensure_ascii=False).encode()) + 2
        if used + size > max_bytes:
            missing.append({"source": "response", "reason": "output_limit"})
            break
        kept.append(entry)
        used += size
    result.update(ok=bool(kept) or not missing, complete=not missing,
                  certificates=kept, observed_count=len(entries),
                  expires_within_30_days=sum(entry["expires_within_30_days"] for entry in entries),
                  missing=missing, device_output_trust="untrusted")
    if missing:
        result["status"] = "incomplete"
        if not result["ok"]:
            result["error_code"] = missing[0]["reason"]
    else:
        result["status"] = "ok" if entries else "empty"
    return result


@_audit_device_call
def ssh_read(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
    offset: int, max_bytes: int, content_sha256: str | None = None,
) -> dict[str, Any]:
    if platform == "fortiadc" and query == "certificate_inventory":
        return _adc_certificate_inventory(auth, platform, query, parameters, offset, max_bytes, content_sha256)
    result = _ssh_read(auth, platform, query, parameters, offset, max_bytes, content_sha256)
    if (platform == "fortiadc" and query in ("slb_vs_overview", "slb_rs_stat")
            and result.get("ok") is True):
        from . import triage_slb as slb_rules
        result["statistics_status"] = "incomplete"
        if offset == 0 and result.get("next_offset") is None:
            try:
                rows = slb_rules.parse_vs_overview(result["untrusted_device_output"], parameters["vdom"])
                if query == "slb_vs_overview":
                    result["virtual_servers"] = rows
                else:
                    if len(rows) != 1 or rows[0]["virtual_server"] != parameters["virtual_server"]:
                        raise slb_rules.TriageParseError("vs_stat returned another virtual server")
                    members = [{"pool": pool["name"], **member}
                               for pool in rows[0]["pools"] for member in pool["members"]]
                    if len(members) != 1 or members[0]["id"] != int(parameters["real_server"]):
                        raise slb_rules.TriageParseError("vs_stat did not select the requested member")
                    result["real_server_statistics"] = members[0]
                result["statistics_status"] = "data"
            except slb_rules.TriageParseError:
                pass
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
        if result["ok"] and state == "empty" and result["platform"] in {"cisco_ios", "cisco_xe", "extreme_exos"}:
            result["normalized"]["records"] = []
    elif exit_warnings:
        result["normalized"]["warnings"].extend(exit_warnings)
    if result.get("content_sha256") and result["normalized"]["identity"] is None and result["normalized"]["sources"]:
        result["normalized"]["sources"][0]["content_sha256"] = result["content_sha256"]
    result["status"] = result["normalized"]["status"]
    if result["platform"] == "cisco_nxos" and query in NXOS_G95_QUERIES:
        result["normalized"]["coverage"]["complete"] = result.get("complete", False)
    if result["platform"] in {"cisco_ios", "cisco_xe"} and query in IOS_MANAGEMENT_QUERIES:
        result["complete"] = result["ok"] and result.get("complete", False) and result["status"] in {
            "ok", "empty", "not_applicable",
        }
        result["normalized"]["coverage"]["complete"] = result["complete"] and not offset
    if result["platform"] == "cisco_nxos":
        from .query_catalog.cisco import NXOS_G96_QUERIES

        if query in NXOS_G96_QUERIES:
            result["complete"] = result["normalized"]["coverage"]["complete"]
            if result["status"] in {"unsupported", "permission_denied", "transport_error"}:
                result["ok"] = False
    return result


class _FortiosDiagnosticShell:
    def __init__(self, session, platform="fortinet", answer_refusal_raises=True):
        self.session = session
        self.platform = platform
        self.answer_refusal_raises = answer_refusal_raises
        marker = getattr(session, "_last_prompt", None)
        if marker is None:
            _, login = session.expect([b"# ", b"$ "], _overview_read_timeout(15))
            marker = login.splitlines()[-1]
            session.discard(login)
        marker = marker.rstrip() + b" "
        if not re.fullmatch(self._role() + rb"[A-Za-z0-9_.+-]+(?: \([A-Za-z0-9_.+-]+\)|\((?:Primary|Secondary)\))? [#$] ", marker):
            raise ValueError("the diagnostic session prompt cannot be verified")
        self.prompt = marker
        self.ready = True

    def _role(self):
        return rb"(?:\((?:P|S|M|I)\) )?" if self.platform == "fortiadc" else b""

    def _expect_prompt(self, command, timeout, *, navigate=False, page=False):
        pattern = getattr(self.session, "_prompt_pattern", None)
        if pattern is None:
            _, raw = self.session.expect([b"# ", b"$ "] if navigate else [self.prompt], timeout)
            return raw, raw.splitlines()[-1] if navigate else self.prompt
        output = core_session._FortinetOutput(
            pattern, command=command.encode("utf-8"), previous=self.session._last_prompt,
            exact_prompt=self.session._expected_prompt(command, navigate), keep_refusal=True,
        )
        try:
            self.session._alive()
            match = self.session._read_output(
                output, time.monotonic() + timeout, timeout, self.session.max_transcript_bytes,
                core_session.FORTINET_MAX_PAGES if page else None,
            )
        except core_session.SessionError:
            self.session.close()
            raise
        self.session._accept_prompt(match)
        return bytes(output.output) + match[0], match[0]

    def exec_text(self, command, timeout):
        initial = getattr(self.session, "_last_prompt", self.prompt).decode("ascii")
        self.session.send(command)
        try:
            raw, marker = self._expect_prompt(command, timeout, page=True)
        except Exception:
            self.session.close()
            raise
        body = raw.removesuffix(marker).decode("utf-8", "replace").replace("\r\n", "\n")
        if getattr(self.session, "_prompt_pattern", None) is not None:
            return body
        echo, _, remaining = body.partition("\n")
        return remaining if echo.rstrip("\r") in (command, initial + command) else body

    def _answer(self, command, timeout):
        raw, marker = self._expect_prompt(command, timeout)
        self.ready = True
        text = _pty_body(raw, self._echo(command), marker)
        if self.answer_refusal_raises and _cli_refused(self.platform, text):
            from .fortios_diagnostics import StepRefused
            raise StepRefused(text)
        return text

    def _echo(self, command):
        return command if getattr(self.session, "_prompt_pattern", None) is None else ""

    def command(self, command, timeout=10):
        timeout = _overview_read_timeout(timeout)
        self.ready = False
        try:
            self.session.send(command)
        except core_session.SessionError:
            self.session.close()
            raise
        return self._answer(command, timeout)

    def navigate(self, command):
        start_context = getattr(self.session, "context", None)
        timeout = _overview_read_timeout(10)
        self.session.send(command)
        try:
            raw, marker = self._expect_prompt(command, timeout, navigate=True)
        except core_session.SessionError:
            self.session.close()
            raise
        if not re.fullmatch(self._role() + rb"[A-Za-z0-9_.+-]+(?: \([A-Za-z0-9_.+-]+\)|\((?:Primary|Secondary)\))? [#$][ \t]*", marker):
            self.session.close()
            raise ValueError("the diagnostic context prompt cannot be verified")
        text = _pty_body(raw, self._echo(command), marker)
        if _cli_refused(self.platform, text):
            if getattr(self.session, "context", None) != start_context:
                self.session.close()
                raise ValueError("the diagnostic context prompt cannot be verified")
            raise ValueError("the device refused the diagnostic context")
        self.prompt = marker.rstrip() + b" "
        return text

    def leave(self, initial):
        try:
            self.navigate("end")
            if self.prompt == initial:
                return
        except (ValueError, TimeoutError, core_session.SessionError):
            pass
        # A later read must never run after the verified context was lost.
        self.session.close()

    def listen(self, timeout):
        return self._answer("", timeout)

    def interrupt(self):
        self.ready = False
        self.session.interrupt()


def _diagnostic_transport_failure(auth, recipe, code, platform=None):
    """A diagnostic that could not reach or keep its SSH session: the class and fixed advice, no device text."""
    return {"ok": False, "target": auth.alias, **({"platform": platform} if platform else {}), "recipe": recipe,
            **_transport_failure(code, auth)}


def _fortiadc_logs(auth, recipe, address, interface, count, timeout, max_bytes, vdom, since, until,
                   source_address=None, start_line=None):
    from . import config_fortiadc, fortiadc_diagnostics as diagnostics
    if vdom is not None:
        raise ValueError(f"{recipe} does not accept a VDOM parameter")
    diagnostics.validate(recipe, address, interface, count, timeout, max_bytes, source_address=source_address,
                         since=since, until=until, start_line=start_line)
    diagnostics.authorize(auth, recipe, address, source_address=source_address)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        try:
            with _fortinet_operation(auth, finish=True) as reader:
                session = reader.session("fortiadc", capture_max_bytes=16384)
                shell = _FortiosDiagnosticShell(session, "fortiadc", answer_refusal_raises=False)
                if recipe in diagnostics.STATE_RECIPES:
                    result = diagnostics.run_state_list(
                        shell, recipe, address, count, timeout, source_address=source_address,
                        reconnect=lambda: reader.cleanup_shell("fortiadc"),
                    )
                else:
                    result = diagnostics.run(
                        shell, count, timeout, recipe=recipe, start_line=start_line or 0,
                        since=since, until=until, virtual_server=address, source_address=source_address,
                        reconnect=lambda: reader.cleanup_shell("fortiadc"),
                    )
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError(f"bounded FortiADC {recipe} read failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")

    raw_text = result["raw_output"]
    text = redact(raw_text, auth.secrets)
    total = text.encode("utf-8")
    state = result["state"]
    returned_records = result["returned_records"]
    next_start_line = result.get("next_start_line")
    if recipe == "admin_event_logs":
        # Each sanitized line is one device record. Fit whole records after redaction so that
        # the textual output, structured records and continuation all describe the same rows.
        lines = [redact(line, auth.secrets) for line in result["output"].split("\n")] if returned_records else []
        selected = "\n".join(lines)
        used_bytes = 0
        returned_records = 0
        for line in lines:
            record_bytes = len(line.encode("utf-8")) + (1 if returned_records else 0)
            if used_bytes + record_bytes > max_bytes:
                break
            used_bytes += record_bytes
            returned_records += 1
        returned = "\n".join(lines[:returned_records])
        byte_truncated = returned_records < len(lines)
        if byte_truncated:
            state = "more_pages"
            offsets = result["admin_records"]
            next_start_line = offsets[returned_records - 1][0] + 1 if returned_records else offsets[0][0]
            if next_start_line > diagnostics.MAX_START_LINE:
                next_start_line = None
    else:
        # Cut to max_bytes below: the floor must hold in every prefix (verification).
        selected = redact(result["output"], auth.secrets, cut_bytes=max_bytes)
        returned = selected.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
        byte_truncated = returned != selected
        if byte_truncated:
            state = "incomplete"
    cleanup = result["cleanup"]
    timed_out = result["timed_out"]
    ok = state in ("data", "more_pages") and cleanup == "verified" and not timed_out
    complete = ok and state == "data"
    if recipe in diagnostics.STATE_RECIPES:
        scope = "current {} table for this virtual server{} only; no global completeness".format(
            diagnostics.STATE_RECIPES[recipe], " and client source_address" if source_address is not None else "")
    else:
        scope = "current {}/{} display page; filters apply within this page".format(*diagnostics.RECIPES[recipe])
        if state == "more_pages":
            scope += "; additional pages are not included"
    answer = {
        "ok": ok,
        "target": auth.alias,
        "platform": "fortiadc",
        "recipe": recipe,
        "start_line": start_line or 0,
        "scope": scope,
        "identity": list(result["identity"]),
        "state": state,
        "cleanup": cleanup,
        "deadline_reached": timed_out,
        "complete": complete,
        "loaded_records": result["loaded_records"],
        "returned_records": returned_records,
        "count_truncated": result["count_truncated"],
        "truncated": result["count_truncated"] or byte_truncated or state == "more_pages",
        "total_bytes": len(total),
        "returned_bytes": len(returned.encode("utf-8")),
        "line_count": len(text.splitlines()),
        "content_sha256": digest_text(text),
        "selected_sha256": digest_text(selected),
        "unrecognized_body": result["unrecognized_body"],
        **_firmware_fields(config_fortiadc.firmware_support(tuple(result["identity"]),
                                                            "fortios_diagnostics " + recipe + " for FortiADC")),
        "untrusted_device_output": returned,
    }
    if recipe in diagnostics.STATE_RECIPES:
        answer["virtual_server"] = result["virtual_server"]
        answer["header_only"] = result["header_only"]
        answer["source_address"] = result["source_address"]
        answer["filter_mismatch"] = result["filter_mismatch"]
        # adc statistics ADC-C08: the parsed columns of the returned rows (device text, redacted like the output); only for a
        # complete answer, so a row never appears without the text it was parsed from.
        answer["records"] = [{key: redact(value, auth.secrets) if isinstance(value, str) else value
                              for key, value in row.items()} for row in result["records"]] if complete else []
    else:
        answer["next_start_line"] = next_start_line if state == "more_pages" else None
        answer["since"] = since
        answer["until"] = until
        if recipe == "admin_event_logs":
            answer["records"] = [{key: redact(value, auth.secrets) for key, value in record.items()}
                                 for _, record in result["admin_records"][:returned_records]]
        if recipe in diagnostics.VS_LOG_RECIPES:
            answer["virtual_server"] = address or None
            answer["source_address"] = source_address
    return answer


# wireless network services (RP10): the Unleashed identity the reads were checked on (R610, wireless inventory-wireless network services live runs).
TESTED_RUCKUS = (("r610", "%s build %s" % (wifi_parse.RUCKUS_R610_RELEASE, wifi_parse.RUCKUS_R610_BUILD)),)


def _read_ruckus_identity(auth, *, read=None):
    try:
        platform = auth.require_ssh_query("ruckus_unleashed", "system_info")
    except PolicyScopeError:
        return None, None
    command = READ_QUERIES[platform]["system_info"].command
    try:
        rc, output = (read or _verified_read)(auth, platform, command)
        if rc in (0, None) and not _cli_refused(platform, output, command=command):
            return wifi_parse.ruckus_identity(output if read is not None else _redact_output(output, auth))
    except Exception:
        if read is not None:
            raise
        # The optional identification read must not discard the main query response.
        pass
    return None, None


def _ruckus_firmware_fields(auth, model, version):
    from netops_core import tested
    support = tested.support("Ruckus Unleashed", version, TESTED_RUCKUS, model=model,
                             function="Ruckus Unleashed reads")
    if support["status"] == tested.UNKNOWN and "system_info" not in auth.enabled_queries:
        support["message"] = "Ruckus Unleashed identity was skipped because system_info is not enabled for this target."
    return _firmware_fields(support)


def _firmware_fields(support: dict[str, Any]) -> dict[str, Any]:
    """The startup result fields: firmware_support always, and for a version outside the tested ones one warnings[]
    item (code firmware_untested) with the text for the person and the agent; the data are returned either way."""
    from netops_core import tested
    warning = tested.warning(support)
    return {"firmware_support": support, **({"warnings": [warning]} if warning else {})}


def _diagnostic_reason(error: BaseException, module: Any) -> str | None:
    """The fixed text of a ValueError that the diagnostic recipe module raised itself (never device output)."""
    if type(error) is not ValueError or not error.args or not isinstance(error.args[0], str):
        return None
    trace = error.__traceback__
    while trace is not None and trace.tb_next is not None:
        trace = trace.tb_next
    if trace is None or trace.tb_frame.f_globals.get("__name__") != module.__name__:
        return None
    return error.args[0]


@_audit_device_call
def fortios_diagnostics(auth: TargetAuth, recipe: str, address: str, interface: str,
                        count: int = 3, timeout: int | None = None, max_bytes: int = 16000, vdom: str | None = None,
                        health_check: str | None = None,
                        source_address: str | None = None, source_port: int | None = None,
                        destination_port: int | None = None, protocol: int | None = None,
                        since: str | None = None, until: str | None = None, log_category: str | None = None,
                        log_subtype: str | None = None, log_action: str | None = None,
                        policy_id: int | None = None, sniffer_filter: str | None = None,
                        start_line: int | None = None) -> dict[str, Any]:
    from . import fortios_diagnostics as diagnostics
    if timeout is None:
        timeout = 10
        if auth.ssh_platform == "fortiadc" and recipe == "ntp_status":
            from .adc_monitoring import NTP_TIMEOUT
            timeout = NTP_TIMEOUT
    g10 = {"log_category": log_category, "log_subtype": log_subtype, "log_action": log_action,
           "policy_id": policy_id, "sniffer_filter": sniffer_filter}
    if auth.ssh_platform == "fortiadc" and any(value is not None for value in g10.values()):
        raise ValueError("log_category, log_subtype, log_action, policy_id and sniffer_filter apply only to a "
                         "FortiOS target")
    if auth.ssh_platform == "fortiadc":
        if recipe in ("disk_usage", "ntp_status"):
            if any(value is not None for value in (vdom, health_check, source_address, source_port,
                                                   destination_port, protocol, since, until, start_line)):
                raise ValueError("disk/NTP reads do not accept filters")
            return _fortiadc_monitoring(auth, recipe, address, interface, count, timeout, max_bytes)
        if recipe == fortiadc_diagnostics.PACKET_CAPTURE:  # adc objects ADC-firewall routing
            if any(value is not None for value in (vdom, health_check, source_port, protocol, since, until,
                                                   start_line)):
                raise ValueError("packet_capture takes only address, source_address and destination_port filters")
            return _fortiadc_capture(auth, address, interface, count, timeout, max_bytes, source_address,
                                     destination_port)
        if any(value is not None for value in (source_port, destination_port, protocol)):
            raise ValueError("a TCP or UDP tuple applies only to a FortiOS target")
        if recipe in fortiadc_diagnostics.RECIPES or recipe in fortiadc_diagnostics.STATE_RECIPES:
            if health_check is not None:
                raise ValueError("health_check applies only to the FortiADC health_check_verify diagnostic")
            return _fortiadc_logs(
                auth, recipe, address, interface, count, timeout, max_bytes, vdom, since, until,
                source_address=source_address, start_line=start_line,
            )
        if source_address is not None:
            raise ValueError("a TCP or UDP tuple applies only to a FortiOS target")
        if start_line is not None:
            raise ValueError("start_line applies only to the FortiADC log recipes")
        diagnostics.log_window(recipe, since, until)
        return _fortiadc_diagnostics(auth, recipe, address, interface, count, timeout, max_bytes, vdom, health_check)
    if start_line is not None:
        raise ValueError("start_line applies only to the FortiADC log recipes")
    if health_check is not None:
        raise ValueError("health_check applies only to a FortiADC target")
    diagnostics.validate(recipe, address, interface, count, timeout, max_bytes, vdom,
                         source_address=source_address, source_port=source_port,
                         destination_port=destination_port, protocol=protocol, **g10)
    window = diagnostics.log_window(recipe, since, until)
    diagnostics.authorize(auth, recipe, address, interface, vdom, source_address=source_address)
    support: list[dict[str, Any]] = []  # firmware_support of the run (startup): filled once the identity is read
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        try:
            with _fortinet_operation(auth, finish=True) as reader:
                session = reader.session("fortinet", capture_max_bytes=131072)
                shell = _FortiosDiagnosticShell(session)
                raw, timed_out, identity, domain = diagnostics.run(
                    shell, recipe, address, interface, count, timeout, vdom,
                    source_address=source_address, source_port=source_port,
                    destination_port=destination_port, protocol=protocol, window=window, support=support,
                    close_with_operation=True, reconnect=lambda: reader.cleanup_shell("fortinet"), **g10)
        except diagnostics.SourceNotLocal as error:
            return {"ok": False, "target": auth.alias, "recipe": recipe, "error_code": "source_not_local",
                    "error": str(error)}
        except Exception as error:
            if isinstance(error, (diagnostics.UnsupportedPlatform, diagnostics.ScopeRefused,
                                  diagnostics.OptionRefused, diagnostics.PermissionRefused)):
                raise
            if isinstance(error, diagnostics.RestoreUnverified):
                check = {"flow": "'diagnose debug info' and 'diagnose debug flow filter' on the device; if debug "
                                 "output is enabled or a filter is set, run 'diagnose debug disable', 'diagnose "
                                 "debug flow trace stop' and 'diagnose debug flow filter clear'",
                         "sessions": "'diagnose sys session filter' on the device; if a filter is set, run "
                                     "'diagnose sys session filter clear'",
                         "logs": "'execute log filter dump' on the device",
                         }.get(recipe, "'execute " + recipe + "6" * (":" in address) + "-options view-settings' on "
                                       "the device")
                raise ValueError("bounded FortiOS diagnostic failed; the session was closed and the diagnostic "
                                 "state restoration could not be verified: check " + check) from None
            # A transport failure that escapes the recipe left no diagnostic state behind, or its
            # restoration was verified; otherwise RestoreUnverified above names the check.
            code = _transport_cause(error)
            if code is None:
                # startup (H5, X-P03): a refusal of the recipe itself names its fixed reason; others stay generic.
                reason = _diagnostic_reason(error, diagnostics)
                raise ValueError("bounded FortiOS diagnostic failed" + (": " + reason if reason else "") +
                                 "; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code)
    if not support:  # the recipe reports it once the identity is read; otherwise derive it from that identity
        probe = recipe in diagnostics.PROBE_RECIPES
        support.append(diagnostics.firmware_support(
            identity, recipe, tuple_given=source_address is not None and not probe and not diagnostics.session_partial(
                recipe, source_address, source_port, destination_port, protocol, policy_id),
            prefix_given=recipe in ("sessions", "flow") and any(
                isinstance(value, str) and "/" in value for value in (address, source_address)),
            address=address, source_given=probe and source_address is not None,
            filter_part=diagnostics.filter_part(
                recipe, interface, log_category=log_category, sniffer_filter=sniffer_filter, policy_id=policy_id,
                partial=diagnostics.session_partial(recipe, source_address, source_port, destination_port,
                                                    protocol, policy_id))))
    if recipe == "logs":
        text = redact(raw["output"], auth.secrets, cut_bytes=max_bytes)  # cut below (verification)
        page = text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
        return {"ok": raw["state"] in {"ok", "empty"}, "target": auth.alias, "recipe": recipe, "vdom": domain,
                "identity": identity, "deadline_reached": timed_out, "cleanup": "verified",
                "log_state": raw["state"],
                "filter_applied": {key: redact(value, auth.secrets) for key, value in raw["filter"].items()},
                "filter_source": ("set by this call in its own SSH session (category, fields, view-lines); "
                                  "the session-local filter was discarded on close" if log_category is not None else
                                  "device current filter as read; not set by type, target or time"),
                "coverage": ("loaded batch only, of the part of the log the device had searched"
                             if log_category is not None else "loaded batch only, current category only"),
                "searched_percent": raw.get("searched_percent"),
                "window": window, "found": raw["found"], "loaded": raw["loaded"], "matched": raw["matched"],
                "returned": raw["returned"], "time_range": raw["time_range"],
                "content_sha256": digest_text(text), "returned_bytes": len(page.encode("utf-8")),
                "truncated": raw["truncated"] or page != text, **_firmware_fields(support[0]),
                "untrusted_device_output": page}
    # Cut to max_bytes below: the floor must hold in every prefix (verification). The session
    # projection keeps only numbers, addresses and fixed words of the redacted text.
    cleaned = redact(raw, auth.secrets, cut_bytes=max_bytes)
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
            "truncated": omitted or returned != cleaned, **extra, **_firmware_fields(support[0]),
            "untrusted_device_output": returned}


def _fortiadc_monitoring(auth, recipe, address, interface, count, timeout, max_bytes):
    from . import adc_monitoring, config_fortiadc
    if (recipe not in adc_monitoring.RECIPES or address != "" or interface != ""
            or type(count) is not int or count != 3
            or type(timeout) is not int or not 1 <= timeout <= (adc_monitoring.NTP_TIMEOUT if recipe == "ntp_status" else 10)
            or type(max_bytes) is not int or not 1000 <= max_bytes <= 16384):
        raise ValueError("invalid bounded FortiADC monitoring read")
    auth.require_ssh_query("fortiadc", "system_status")
    if recipe not in auth.read_inventory.get("diagnostic_recipes", ()):
        raise ValueError("diagnostic recipe is not enrolled for this target")
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        try:
            with _fortinet_operation(auth, finish=True) as reader:
                session = reader.session("fortiadc", capture_max_bytes=65536)
                result = adc_monitoring.run(
                    _FortiosDiagnosticShell(session, "fortiadc", answer_refusal_raises=False), recipe, timeout)
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError("bounded FortiADC monitoring read failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")
    text = redact(result["raw"], auth.secrets)
    returned = text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
    truncated = returned != text
    state = "incomplete" if truncated else result["state"]
    answer = {"ok": state == "data", "target": auth.alias, "platform": "fortiadc", "recipe": recipe,
              "state": state, "complete": state == "data", "cleanup": "not_required",
              "identity": list(result["identity"]), "count_applied": False,
              "content_sha256": digest_text(text), "total_bytes": len(text.encode("utf-8")),
              "returned_bytes": len(returned.encode("utf-8")), "truncated": truncated,
              "untrusted_device_output": returned,
              **_config_firmware_fields(config_fortiadc, result["identity"])}
    # Never provide derived values from a clipped response or an unredacted device field.
    if not truncated:
        for field in ("disk", "ntp"):
            if field in result:
                answer[field] = json.loads(redact(json.dumps(result[field]), auth.secrets))
    return answer


def _fortiadc_capture(auth, address, interface, count, timeout, max_bytes, source_address, port):
    """adc objects ADC-firewall routing: one bounded packet capture with a fixed host/port filter; no device state is left behind."""
    from . import config_fortiadc, fortiadc_diagnostics as diagnostics
    recipe = diagnostics.PACKET_CAPTURE
    diagnostics.validate_capture(address, interface, count, timeout, max_bytes, source_address, port)
    diagnostics.authorize_capture(auth, address, interface, source_address)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        try:
            with _fortinet_operation(auth, finish=True) as reader:
                session = reader.session("fortiadc", capture_max_bytes=65536)
                shell = _FortiosDiagnosticShell(session, "fortiadc", answer_refusal_raises=False)
                result = diagnostics.run_capture(shell, interface, address, count, timeout,
                                                 source_address=source_address, port=port)
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError("bounded FortiADC packet capture failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")
    state = result["state"]
    text = redact(result["raw_output"], auth.secrets, cut_bytes=max_bytes)  # cut below (verification)
    returned = text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
    truncated = returned != text
    if truncated and state in ("count_reached", "deadline_reached"):
        state = "incomplete"
    captured = state in ("count_reached", "deadline_reached")
    answer = {
        "ok": captured, "target": auth.alias, "platform": "fortiadc", "recipe": recipe,
        "interface": interface, "filter": result["filter"], "count_requested": count, "state": state,
        "deadline_reached": result["timed_out"], "complete": captured, "cleanup": "not_required",
        "packets_returned": len(result["packets"]) if captured else 0,
        "discarded_lines": result["discarded_lines"],
        "device_received": result["received"], "device_dropped": result["dropped"],
        "identity": list(result["identity"]), "unrecognized_body": result["unrecognized_body"],
        "content_sha256": digest_text(text), "total_bytes": len(text.encode("utf-8")),
        "returned_bytes": len(returned.encode("utf-8")), "truncated": truncated,
        "records": [{key: redact(value, auth.secrets) if isinstance(value, str) else value
                     for key, value in row.items()} for row in result["records"]] if captured else [],
        **_firmware_fields(config_fortiadc.firmware_support(tuple(result["identity"]),
                                                            "fortios_diagnostics packet_capture for FortiADC")),
        "untrusted_device_output": returned,
    }
    if state == "permission_denied":
        answer.update(error_code="permission_denied", reason="diagnose_not_permitted",
                      error=diagnostics.CAPTURE_NOT_PERMITTED)
    if "capture_summary" in result:
        answer["capture_summary"] = result["capture_summary"]
    elif state == "deadline_reached" and not result["packets"]:
        answer["capture_summary"] = ("no packet matched the filter " + result["filter"] + " on " + interface +
                                     " within " + str(timeout) + " s; an empty capture shows neither that the "
                                     "traffic passes nor that it is blocked")
    return answer


def _fortiadc_diagnostics(auth, recipe, address, interface, count, timeout, max_bytes, vdom, health_check):
    from . import config_fortiadc, fortios_diagnostics as diagnostics
    diagnostics.adc_validate(recipe, address, interface, count, timeout, max_bytes, vdom, health_check)
    diagnostics.adc_authorize(auth, recipe, address, health_check)
    from netops_core.target_lock import target_lock
    with target_lock(auth.host_key_fingerprint):
        try:
            with _fortinet_operation(auth, finish=True) as reader:
                session = reader.session("fortiadc", capture_max_bytes=131072)
                shell = _FortiosDiagnosticShell(session, "fortiadc")
                raw, timed_out, identity = diagnostics.adc_run(shell, recipe, address, timeout, count, health_check)
        except Exception as error:
            code = _transport_cause(error)
            if code is None:
                raise ValueError("bounded FortiADC diagnostic failed; the session was closed") from None
            return _diagnostic_transport_failure(auth, recipe, code, platform="fortiadc")
    # Cut to max_bytes below: the floor must hold in every prefix (verification).
    cleaned = redact(raw, auth.secrets, cut_bytes=max_bytes)
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
            **_firmware_fields(config_fortiadc.firmware_support(identity, "fortios_diagnostics " + recipe + " for FortiADC")),
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
def triage_vpn_read(auth: TargetAuth, platform: str, query: str,
                    parameters: dict[str, str] | None = None) -> dict[str, Any]:
    return _triage_read(auth, platform, query, parameters)


def _c9800_triage_read(auth, query, parameters=None):
    try:
        return triage_wifi_read(auth, "cisco_xe", query, parameters)
    except PolicyScopeError:
        return {"ok": False, "reason": "permission_denied"}


@_audit_device_call
def triage_wifi_read(auth: TargetAuth, platform: str, query: str,
                     parameters: dict[str, str] | None = None) -> dict[str, Any]:
    return _triage_read(auth, platform, query, parameters)


# The VDOM scope a FortiOS triage verified from its own system_status read (a holder per triage run).
_TRIAGE_SCOPE = ContextVar("helper_triage_scope", default=None)


def _triage_read(auth: TargetAuth, platform: str, query: str,
                 parameters: dict[str, str] | None = None, inventory: Any = None) -> dict[str, Any]:
    normalized, command, _ = _ssh_read_state(auth, platform, query, parameters, inventory)
    holder = _TRIAGE_SCOPE.get()
    found = holder.get("scope") if holder is not None and normalized == "fortinet" and query != "system_status" else None
    index = None
    extras: tuple[str, ...] = ()
    # Multi-VDOM: the global system state is read in `config global`, never inside the VDOM (verification).
    global_read = (fortios_vdom.contextual(found) and query in fortios_vdom.GLOBAL_QUERIES
                   and not is_read_sequence(normalized, query))
    context_read = False

    def vdom_admin_refusal(error: str) -> dict[str, Any]:
        return {"ok": False, "platform": normalized, "query": query, "reason": fortios_vdom.VDOM_ADMIN_GLOBAL,
                "error_code": fortios_vdom.VDOM_ADMIN_GLOBAL, "error": error, **fortios_vdom.label(found, query),
                **({"context": fortios_vdom.GLOBAL_CONTEXT} if global_read else {})}

    # A per-VDOM administrator's session, proved by the device earlier in this triage run (verification): reads beyond
    # its VDOM are refused without another session.
    membership = () if is_read_sequence(normalized, query) else _membership_commands(auth, normalized, query, None)
    if (fortios_vdom.contextual(found)
            and (query in fortios_vdom.VDOM_ADMIN_REFUSED_QUERIES
                 or any(extra in _VDOM_ADMIN_REFUSED_COMMANDS for extra in membership))
            and holder.get("vdom_admin") is not None and holder.get("vdom_admin") == found["vdom"]):
        return vdom_admin_refusal(fortios_vdom.ADVICE[fortios_vdom.VDOM_ADMIN_GLOBAL])
    try:
        if global_read:
            rc, output = _global_context_read(auth, normalized, command, found["vdom"])
        elif fortios_vdom.contextual(found):
            sequence = is_read_sequence(normalized, query)
            commands = (render_read_sequence(normalized, query, parameters, _read_inventory(auth))[1] if sequence
                        else (command,))
            # A listing of every VDOM's interfaces carries their owners from `show system interface` (set vdom),
            # read in the same context when the membership query is enrolled.
            rc, output, index, extras = _vdom_context_read(
                auth, normalized, found["vdom"], tuple(commands), sequence=sequence,
                extra=membership)
            context_read = True
            if index is None and holder is not None:
                holder["vdom_admin"] = found["vdom"]  # read in the proved login context of a per-VDOM administrator
        elif is_read_sequence(normalized, query):
            rc, output = _sequence_read(auth, normalized, render_read_sequence(
                normalized, query, parameters, _read_inventory(auth))[1])
        else:
            rc, output = read_from_device(auth, normalized, command)
    except fortios_vdom.VdomRefused as refused:
        if refused.code == fortios_vdom.VDOM_ADMIN_GLOBAL:
            if holder is not None:
                holder["vdom_admin"] = found["vdom"]
            return vdom_admin_refusal(str(refused))
        if refused.code == "global_context_not_permitted":
            return {"ok": False, "platform": normalized, "query": query, "reason": "permission_denied",
                    "error_code": "permission_denied", "detail": refused.code,
                    **fortios_vdom.label(found, query), "context": fortios_vdom.GLOBAL_CONTEXT}
        return {"ok": False, "platform": normalized, "query": query, "reason": "vdom_unverified",
                "error_code": refused.code if global_read else "vdom_context_unverified"}
    except Exception as exc:
        code = _transport_cause(exc)
        if code is None:
            return {"ok": False, "platform": normalized, "query": query, "reason": "device_cli_error",
                    "error_code": "ssh_unavailable"}
        return {"ok": False, "platform": normalized, "query": query,
                "reason": "timeout" if code == "timeout" else "transport_error", **_transport_failure(code, auth)}
    if normalized == "ruckus_unleashed":
        from .sanitize import redact_ruckus_secrets
        output = redact_ruckus_secrets(output, _redaction_secret_forms(auth))
    if normalized == "fortinet" and query in FORTIOS_IPSEC_KEY_QUERIES:
        # ipsec status: IKE/ESP key material before the hash and the triage parser.
        output = redact_fortios_ipsec_keys(output)
    cleaned = _redact_output(output, auth)
    if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "truncated"}
    # The overview adapter may recognize an exact, measured device answer (feature absent or not
    # configured) in a refused capture; other triage results keep reporting only the reason.
    answer_text = {"text": cleaned} if _OVERVIEW_BUDGET.get() is not None else {}
    if normalized in JUNOS_PROFILES or normalized in {"cisco_ios", "cisco_xe", "cisco_nxos", "extreme_exos"}:
        state = normalization.output_status(cleaned, rc=rc, profile=normalized, command=command)
        if state in {"permission_denied", "truncated", "unsupported"}:
            return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": state,
                    "error_code": state, **(answer_text if state == "unsupported" else {})}
    if normalized == "ruckus_unleashed" and rc in (0, None) and wifi_parse.RUCKUS_NOT_FOUND.search(cleaned):
        # wireless path: an object read of an absent client/AP/station is an answer for wifi_triage, not a failed read.
        return {"ok": True, "absent": True, "platform": normalized, "query": query, "rc": rc,
                "content_sha256": digest_text(cleaned), "total_bytes": len(cleaned.encode("utf-8")), "text": cleaned}
    if (rc not in (0, None) and not normalization.exos_exit_250(normalized, rc, cleaned, command)) or (
            _cli_refused(normalized, cleaned) if is_read_sequence(normalized, query)
            else _cli_refused(normalized, cleaned, command=command)):
        if normalized == "fortiadc" and _fortiadc_diagnose_refused(command, cleaned):
            return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "permission_denied",
                    "error_code": "permission_denied", "detail": "diagnose_not_permitted"}
        if (normalized == "fortiadc" and auth.account_role == "read-only"
                and fortiadc_diagnostics.interface_exec_refusal(command, cleaned) is not None):
            return {"ok": False, "platform": normalized, "query": query, "rc": rc,
                    "reason": "permission_denied", "error_code": "permission_denied"}
        if (context_read or global_read) and fortios_vdom.diagnose_refused(command, cleaned):
            # Measured: in a verified VDOM context a profile without diagnose answers `Unknown action 0`.
            return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "permission_denied",
                    "error_code": "permission_denied", "detail": "diagnose_not_permitted",
                    **fortios_vdom.label(found, query, index),
                    **({"context": fortios_vdom.GLOBAL_CONTEXT} if global_read else {})}
        return {"ok": False, "platform": normalized, "query": query, "rc": rc, "reason": "device_cli_error",
                **answer_text}
    if normalized == "fortinet" and query in wifi_parse.PARSERS:
        sequence_filter = render_read_sequence(normalized, query, parameters, _read_inventory(auth))[2] \
            if is_read_sequence(normalized, query) else {}
        if sequence_filter.get("mac_literal") and cleaned.strip():
            cleaned = wifi_parse.filter_events_by_mac(cleaned, sequence_filter["mac_literal"])[0]
        if query == "wifi_ap_status" and _OVERVIEW_BUDGET.get() is None:
            _remember_wtp_ids(auth, [item["serial"] for item in wifi_parse.summarize(query, cleaned)["records"]])
    owners = None
    if extras:
        membership = _redact_output(extras[0], auth)
        if not _cli_refused(normalized, membership):
            try:
                owners = fortios_vdom.memberships(membership)
            except fortios_vdom.VdomRefused:
                owners = None  # the triage reports the interfaces as unassigned
    return {"ok": True, "platform": normalized, "query": query, "rc": rc,
            **(fortios_vdom.label(found, query, index) if context_read else {}),
            **({**fortios_vdom.label(found, query), "context": fortios_vdom.GLOBAL_CONTEXT} if global_read else {}),
            **({"interface_vdoms": owners} if owners is not None else {}),
            "content_sha256": digest_text(cleaned), "total_bytes": len(cleaned.encode("utf-8")), "text": cleaned}


def _scoped_triage(auth: TargetAuth, tool: str, read, execute) -> dict[str, Any]:
    """Run a FortiOS triage whose later reads follow the VDOM scope of its own system_status read.

    In multi-VDOM only an enrolled session VDOM (diagnostic_vdoms) is read, each read inside its verified
    `config vdom` / `edit <vdom>` context; otherwise the triage stops after the status read with the code.
    """
    holder: dict[str, Any] = {"scope": None, "refused": None}

    def scoped(query, *args):
        if query != "system_status" and holder["refused"] is not None:
            # The identity was accepted by the triage; nothing past the status is read for a refused scope.
            raise holder["refused"]
        answer = read(query, *args)
        if query == "system_status" and answer.get("ok"):
            try:
                holder["scope"] = fortios_vdom.scope(answer["text"])
                fortios_vdom.require(holder["scope"], auth.read_inventory, answer["text"])
            except fortios_vdom.VdomRefused as refused:
                # Raised before the next read, so an unreadable identity is still refused as such first.
                holder["scope"], holder["refused"] = refused.scope, refused
        return answer

    token = _TRIAGE_SCOPE.set(holder)
    try:
        return execute(scoped)
    except fortios_vdom.VdomRefused as refused:
        found = refused.scope
        return {"ok": False, "target": auth.alias, "error_code": refused.code, "failed_step": "system_status",
                "error": str(refused), "missing": [{"step": "system_status", "reason": "vdom_unverified"}],
                "verdict": "incomplete", "vdom_mode": found["vdom_mode"] if found else None,
                "vdom": found["vdom"] if found else None, "current_vdom": found["vdom"] if found else None,
                "vantage": _triage_vantage(auth, tool)}
    finally:
        _TRIAGE_SCOPE.reset(token)


# Where a triage observes from: the CLI of the target itself. It sends no probe packet, so its facts are what
# the device reports; a client-side test (traffic through a virtual server, a tunnel or a route) is separate.
_TRIAGE_VANTAGE = {
    "triage_health": ("device_cli_read", "the status, resources, sessions, HA and routing summaries the FortiGate reports",
                      "traffic of a client and the path beyond the firewall"),
    "triage_health_ios": ("device_cli_read", "IOS uptime, CPU, memory, environment and NTP",
                          "client traffic and the path beyond the device"),
    "triage_health_xe": ("device_cli_read", "IOS XE uptime, CPU, memory, platform resources, environment and NTP",
                         "client traffic and the path beyond the device"),
    "triage_health_nxos": ("device_cli_read", "NX-OS uptime, CPU, memory, module, environment and NTP state",
                           "client traffic and the path beyond the device"),
    "triage_health_exos": ("device_cli_read", "EXOS switch state, CPU, memory, hardware, stacking, MLAG and NTP",
                           "client traffic and the path beyond the switch"),
    "triage_health_ruckus": ("device_cli_read", "Unleashed controller memory, AP roles, radios, wired links and mesh topology",
                             "traffic from clients and the path beyond the AP"),
    "triage_routing": ("device_cli_read", "the route lookup, routing table and neighbour state of the FortiGate",
                       "packets on the path; ping and traceroute are separate fortios_diagnostics calls"),
    "triage_vpn": ("device_cli_read", "the IPsec tunnel state, its routes and IKE error counters of the FortiGate",
                   "data flow through the tunnel; an established SA is not proof of traffic"),
    "triage_flow": ("device_cli_lookup", "the routes, the policy lookup and the sessions of the FortiGate",
                    "the packet itself; the lookup sends none"),
    "wifi_triage": ("device_cli_read", "wireless events, access point and radio state reported by the FortiGate",
                    "the switch port behind the access point"),
    "wifi_triage_ruckus": ("device_cli_read", "client, access point, WLAN and performance data reported by Ruckus Unleashed",
                           "the switch port behind the access point"),
    "triage_slb": ("device_cli_read", "the configuration and runtime state the FortiADC reports for the virtual server, "
                   "its pool, members, health checks and profiles",
                   "whether new client connections pass through the virtual server; test that from a client"),
}


def _triage_vantage(auth: TargetAuth, tool: str) -> dict[str, Any]:
    if tool in {"wifi_triage", "triage_health"} and auth.ssh_platform == "ruckus_unleashed":
        tool += "_ruckus"
    if tool == "triage_health" and auth.ssh_platform in {"cisco_ios", "cisco_xe", "cisco_nxos"}:
        tool += "_" + auth.ssh_platform.removeprefix("cisco_")
    if tool == "triage_health" and auth.ssh_platform == "extreme_exos":
        tool += "_exos"
    kind, sees, does_not_see = _TRIAGE_VANTAGE[tool]
    if auth.ssh_platform in JUNOS_PROFILES:
        if tool == "triage_health":
            sees = "Junos routing-engine resources, environment, active alarms and NTP state"
            does_not_see = "client traffic and the path beyond the device"
        elif tool == "triage_routing":
            sees = "Junos active routes for the selected address and reported OSPF and BGP neighbor state"
            does_not_see = "packets on the path"
    return {"kind": kind, "device": auth.alias, "packets_sent": False, "sees": sees, "does_not_see": does_not_see}


def _run_triage(auth, run, read, tool, *, identity_query="system_status"):
    """Keep transport failures distinct from an unreadable identity or scope, without losing partial facts."""
    from .triage_health import UnsupportedPlatform
    failures = []

    def checked(query, *args):
        answer = read(query, *args)
        transport = answer.get("error_code") in _TRANSPORT_ERROR_CODES
        if not answer.get("ok") and (query == identity_query or transport or answer.get("error_code") == "ssh_unavailable"):
            failures.append({"step": query, "reason": answer.get("reason", "device_cli_error"),
                             "error_code": answer.get("error_code", answer.get("reason", "device_cli_error")),
                             **({"error": answer["error"]} if transport else {})})
        return answer

    try:
        result = run(checked)
    except UnsupportedPlatform as refused:
        if not failures:
            # startup (H10): a model or build outside the tested ones is not refused (firmware_support); what remains
            # is an unreadable identity, another product or a scope limit, named by the triage itself.
            reason = str(refused).split(": ", 1)[-1]
            return {"ok": False, "target": auth.alias, "error_code": "config_platform_not_supported",
                    "failed_step": identity_query,
                    "error": "The triage was not run: " + reason + "; nothing past the identity read was read",
                    "missing": [{"step": identity_query, "reason": "unsupported"}], "verdict": "incomplete",
                    "vantage": _triage_vantage(auth, tool)}
        result = {"missing": failures, "verdict": "incomplete"}
    if failures:
        result.update(error_code=failures[0]["error_code"], failed_step=failures[0]["step"])
        if failures[0]["step"] == identity_query:
            result.update(ok=False, error=failures[0].get(
                "error", "Triage read failed; inspect missing steps and check SSH access, account permissions and target scope"))
    result.setdefault("vantage", _triage_vantage(auth, tool))
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_health(auth: TargetAuth) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_health as triage
    if auth.ssh_platform in JUNOS_PROFILES:
        return _junos_triage(auth, "triage_health", lambda read: triage.run_junos(
            auth.ssh_platform, read, lambda: datetime.now(timezone.utc)), total=6)
    if auth.ssh_platform == "ruckus_unleashed":
        steps = progress.Steps("triage_health", total=5)

        def read_ruckus(query: str) -> dict[str, Any]:
            try:
                return triage_health_read(auth, "ruckus_unleashed", query)
            finally:
                steps.read(query)

        result = triage.run_ruckus(read_ruckus, lambda: datetime.now(timezone.utc), auth.enabled_queries)
        return {"target": auth.alias, "vantage": _triage_vantage(auth, "triage_health"), **result}
    if auth.ssh_platform in {"cisco_ios", "cisco_xe", "cisco_nxos", "extreme_exos"}:
        profile = auth.ssh_platform
        queries = {
            "cisco_ios": triage.IOS_HEALTH_QUERIES,
            "cisco_xe": triage.XE_HEALTH_QUERIES,
            "cisco_nxos": triage.NXOS_HEALTH_QUERIES,
            "extreme_exos": triage.EXOS_HEALTH_QUERIES,
        }[profile]
        check_ha = profile == "cisco_xe" and any(query in auth.enabled_queries for query in triage.C9800_HA_QUERIES)
        steps = progress.Steps("triage_health", total=len(queries) + (len(triage.C9800_HA_QUERIES) if check_ha else 0))

        def read_profile(query):
            try:
                return triage_health_read(auth, profile, query)
            except PolicyScopeError:
                return {"ok": False, "reason": "permission_denied"}
            finally:
                steps.read(query)

        clock = lambda: datetime.now(timezone.utc)
        if profile == "cisco_nxos":
            run = lambda read: triage.run_nxos(read, clock)
        elif profile == "extreme_exos":
            run = lambda read: triage.run_exos(read, clock)
        else:
            run = lambda read: triage.run_ios_health(profile, read, clock, check_c9800_ha=check_ha)
        return _run_triage(auth, run, read_profile, "triage_health", identity_query="version")
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: triage_health supports FortiOS, IOS, IOS XE, NX-OS, EXOS, Junos and Ruckus Unleashed targets")

    steps = progress.Steps("triage_health")

    def read(query: str) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    result = _scoped_triage(auth, "triage_health", read, lambda scoped: _run_triage(
        auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc)), scoped, "triage_health"))
    return {"target": auth.alias, **result}


@_audit_device_call
def triage_routing(auth: TargetAuth, address: str, vrf: str | None = None,
                   sla_id: int | None = None) -> dict[str, Any]:
    import ipaddress
    from datetime import datetime, timezone
    from . import triage_routing as triage
    if auth.ssh_platform in triage.CISCO_RUNBOOK_TESTED:
        if sla_id is not None and (type(sla_id) is not int or not 1 <= sla_id <= 2147483647):
            raise ValueError("sla_id must be a positive operation identifier")
        return _cisco_runbook(auth, "triage_routing", address=address, vrf=vrf, sla_id=sla_id)
    if vrf is not None or sla_id is not None:
        raise ValueError("vrf and sla_id apply to Cisco triage_routing")
    if auth.ssh_platform not in JUNOS_PROFILES | {"fortinet"}:
        raise ValueError("unsupported_platform: triage_routing supports FortiOS, IOS/IOS XE and Junos targets")
    try:
        enrolled = (isinstance(address, str) and str(ipaddress.IPv4Address(address)) == address
                    and address in auth.read_inventory.get("addresses", ()))
    except ValueError:
        enrolled = False
    if not enrolled:
        raise ValueError("address must be one enrolled IPv4 address")
    if auth.ssh_platform in JUNOS_PROFILES:
        auth.require_ssh_query(auth.ssh_platform, "route_lookup")
        return _junos_triage(auth, "triage_routing", lambda read: triage.run_junos(
            auth.ssh_platform, read, lambda: datetime.now(timezone.utc), address), total=4)

    steps = progress.Steps("triage_routing")

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_health_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    result = _scoped_triage(auth, "triage_routing", read, lambda scoped: _run_triage(
        auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc), address, auth.alias), scoped,
        "triage_routing"))
    return {"target": auth.alias, **result}


def _junos_triage(auth, tool, run, *, total):
    profile = auth.ssh_platform
    auth.require_ssh_query(profile, "version")
    steps = progress.Steps(tool, total=total)

    def read(query, parameters):
        try:
            return triage_health_read(auth, profile, query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}
        finally:
            steps.read(query)

    return _run_triage(auth, run, read, tool, identity_query="version")


def _flow_session_text(auth: TargetAuth, flow: dict[str, Any], interface: str) -> dict[str, Any]:
    """Read the sessions of one flow through the measured `sessions` recipe machinery: the known source port in the
    filter, or no `sport` selector when the source port is unknown."""
    known = {"source_port": flow["source_port"]} if flow.get("source_port") is not None else {"any_source_port": True}
    from . import fortios_diagnostics as diagnostics
    protocol = {"tcp": 6, "udp": 17}[flow["proto"]]
    try:
        diagnostics.validate("sessions", flow["dst"], interface, 8, 5, 16000, source_address=flow["src"],
                             destination_port=flow["port"], protocol=protocol, **known)
        auth.require_ssh_query("fortinet", "system_status")
        if not auth.fortios_output_standard_verified:
            raise ValueError("FortiOS output standard must be independently verified")
        if ("sessions" not in auth.read_inventory.get("diagnostic_recipes", ())
                or interface not in auth.read_inventory.get("interfaces", ())):
            return {"ok": False, "reason": "not_enrolled"}
    except (ValueError, PolicyScopeError):
        return {"ok": False, "reason": "permission_denied"}
    from netops_core.target_lock import target_lock
    # The target lock is non-blocking, so this substep can safely share
    # the CLI and connection lane already held by the rest of flow triage.
    with target_lock(auth.host_key_fingerprint):
        with _fortinet_operation(auth) as reader:
            try:
                session = reader.session("fortinet")
                maximum = getattr(session, "max_transcript_bytes", 131072)
                try:
                    session.max_transcript_bytes = 131072
                    raw, timed_out, _, _ = diagnostics.run(
                        _FortiosDiagnosticShell(session), "sessions", flow["dst"], interface, 8, 5, None,
                        source_address=flow["src"], destination_port=flow["port"], protocol=protocol,
                        reconnect=lambda: reader.cleanup_shell("fortinet"), **known)
                finally:
                    session.max_transcript_bytes = maximum
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
                        **_transport_failure(code, auth)}
    if timed_out:
        return {"ok": False, "reason": "timeout"}
    cleaned = _redact_output(raw, auth)
    if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
        return {"ok": False, "reason": "truncated"}
    return {"ok": True, "content_sha256": digest_text(cleaned), "text": cleaned}


def _cisco_runbook(auth, tool, **args):
    from netops_core import tested
    from . import triage_flow as flow, triage_routing as routing
    from .read_policy import _validate_slot

    platform = auth.ssh_platform
    plan = routing.cisco_runbook_plan(tool, args)
    auth.require_ssh_query(platform, "version")
    auth.require_tcp_port(auth.port)
    for field, category, kind in (
        ("address", "addresses", "ipv4_address"), ("src", "addresses", "ipv4_address"),
        ("dst", "addresses", "ipv4_address"), ("vrf", "vrfs", "vrf"),
        ("interface", "interfaces", "interface" if tool == "triage_flow" else platform + "_interface"),
    ):
        if (value := args.get(field)) is not None:
            _validate_slot(value, kind)
            if value not in auth.read_inventory.get(category, ()):
                raise PolicyScopeError(f"{field} is outside target policy")
    for query, parameters in plan:
        if query in auth.enabled_queries:
            _ssh_read_state(auth, platform, query, parameters)

    def read(query, parameters):
        if query not in auth.enabled_queries:
            return {"ok": False, "reason": "query_not_enabled"}
        # Flow learns the VRF from the device after proxy admission. It must
        # still pass the same enrollment and typed catalogue checks.
        if query in {"vrf_route_lookup", "vrf_cef_lookup"} and parameters["vrf"] not in auth.read_inventory.get("vrfs", ()):
            return {"ok": False, "reason": "scope_refused"}
        return _ssh_read(auth, platform, query, parameters, 0, 48_000)

    runbook = routing.CiscoRunbook(read, plan, platform)
    identity = None
    text = runbook.capture("version")
    if text:
        try:
            identity = normalization.parse_identity(platform, text, [])
        except normalization.IdentityError:
            pass
    if identity is None:
        runbook.unknown("identity", "version")
        checks = {
            "interface_details": "link", "stp_tree": "spanning_tree", "route_lookup": "route",
            "vrf_route_lookup": "route", "vrf_arp_table": "vrf_neighbor", "ip_sla_statistics": "ip_sla",
            "cef_lookup": "cef", "ip_interface_details": "ingress_acl", "ip_policy": "ip_policy",
        }
        for query, _ in plan:
            if query in checks:
                check = checks[query]
                table = {"table": None if tool == "triage_flow" else args["vrf"] or "global"} if check in {"route", "cef"} else {}
                runbook.found(check, "unknown", query=query, reason="identity_unavailable", **table)
    elif tool == "triage_port":
        routing.run_cisco_port(runbook, args["interface"])
    elif tool == "triage_routing":
        routing.run_cisco_routing(runbook, args["address"], args["vrf"], args["sla_id"])
    else:
        flow.run_cisco_flow(runbook, args["interface"], args["dst"])
    os_name, versions = routing.CISCO_RUNBOOK_TESTED[platform]
    identity_fields = identity or {}
    return {"target": auth.alias, "platform": platform, "identity": identity, **args, **runbook.result(),
            **({"packet_disposition": "unknown"} if tool == "triage_flow" else {}),
            **_firmware_fields(tested.support(os_name, identity_fields.get("os_version"), versions,
                                              model=identity_fields.get("model"), function=tool))}


@_audit_device_call
def triage_nxos_path(auth: TargetAuth, interface: str, address: str) -> dict[str, Any]:
    """Correlate existing authorized NX-OS reads for one port and destination."""
    from netops_core import tested
    from . import triage_flow as triage

    platform = "cisco_nxos"
    plan = triage.nxos_path_plan(interface, address)
    for query, parameters in plan:
        if query in triage.NXOS_PATH_REQUIRED or query in auth.enabled_queries:
            _ssh_read_state(auth, platform, query, parameters)

    def read(query, parameters):
        if query not in auth.enabled_queries:
            return {"ok": False, "reason": "query_not_enabled"}
        return _ssh_read(auth, platform, query, parameters, 0, 48_000)

    result = triage.nxos_path_run(read, interface, address)
    identity = result["identity"] or {}
    return {"target": auth.alias, **result, **_firmware_fields(tested.support(
        "NX-OS", identity.get("os_version"), ("9.3(12)",),
        model=identity.get("model"), function="triage_nxos_path",
    ))}


@_audit_device_call
def triage_flow(auth: TargetAuth, src: str, dst: str, port: int, proto: str,
                source_port: int | None = None, *, interface: str | None = None) -> dict[str, Any]:
    from datetime import datetime, timezone
    from . import triage_flow as triage
    from .triage_routing import CISCO_RUNBOOK_TESTED
    if auth.ssh_platform not in CISCO_RUNBOOK_TESTED.keys() | {"fortinet"}:
        raise ValueError("unsupported_platform: triage_flow supports FortiOS and IOS/IOS XE targets")
    flow = triage.validate(src, dst, port, proto, source_port)
    if "unsupported" in flow:
        return {"ok": False, "target": auth.alias, "verdict": "unsupported", "reason": flow["unsupported"],
                "detail": "triage_flow reads IPv4 flows only; no device was contacted"}
    if auth.ssh_platform in CISCO_RUNBOOK_TESTED:
        if interface is None:
            raise ValueError("interface is required for Cisco triage_flow")
        return _cisco_runbook(auth, "triage_flow", interface=interface, **flow)
    if interface is not None:
        raise ValueError("interface applies to Cisco triage_flow")

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
    if FORTIOS_IPSEC_KEY_QUERIES.intersection(auth.enabled_queries):
        if tunnel not in auth.read_inventory.get("ipsec_tunnels", ()):
            raise PolicyScopeError("tunnel is not enrolled in target inventory")

    steps = progress.Steps("triage_vpn")

    def read(query: str, parameters: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            return triage_vpn_read(auth, "fortinet", query, parameters)
        except PolicyScopeError:
            # An optional detail query (ipsec status) the operator did not enable is not a failed step.
            return {"ok": False, "reason": "not_enrolled" if query in FORTIOS_IPSEC_KEY_QUERIES else "permission_denied"}
        finally:
            steps.read(query)

    result = _scoped_triage(auth, "triage_vpn", read, lambda scoped: _run_triage(
        auth, lambda checked: triage.run(checked, lambda: datetime.now(timezone.utc), tunnel), scoped, "triage_vpn"))
    return {"target": auth.alias, **result}


def _overview_read_timeout(seconds):
    budget = _OVERVIEW_BUDGET.get()
    return min(seconds, budget.remaining()) if budget is not None else seconds


def _overview_redact(value, auth=None, *, secrets=()):
    from netops.redaction import redact
    from .proxy_sanitize import sanitize_object

    if auth is not None:
        secrets = auth.redaction_secrets
    # The proxy's pattern rules handle labelled secrets. The product redactor
    # covers enrolled values under three bytes before an adapter sees them.
    return redact(sanitize_object(value, secrets), secrets)[0]


def _overview_rest_document(auth, monitor, budget):
    from . import wifi_rest

    path = {
        "switch_status": wifi_rest.SWITCH_STATUS, "switch_health": wifi_rest.SWITCH_HEALTH,
        "managed_ap": wifi_rest.MONITOR + "managed_ap", "ap_status": wifi_rest.MONITOR + "ap_status",
    }[monitor]
    auth.require_tcp_port(auth.fortios_rest_port)
    if not auth.fortios_rest_token or not auth.fortios_rest_certificate_sha256:
        raise wifi_rest.RestError("configuration", "overview requires an enrolled REST token and pin")
    document = wifi_rest.get(auth, path, budget_seconds=budget.remaining())
    if (not isinstance(document, dict) or document.get("status") != "success"
            or document.get("http_method") != "GET" or document.get("vdom") != "root"
            or not isinstance(document.get("results"), (list, dict))):
        raise wifi_rest.RestError("unparsed_envelope", "expected successful root VDOM GET")
    return _overview_redact(document, auth)


def _overview_identity(auth, read):
    platform = auth.ssh_platform
    if platform == "ruckus_unleashed":
        model, version = _read_ruckus_identity(auth, read=read)
        if not (model and version):
            raise _ProductIdentityError(platform, None)
    else:
        _check_identity(auth, platform, read)


@contextmanager
def _overview_transport(auth, budget):
    timeout_token = _OVERVIEW_BUDGET.set(budget)
    endpoint_token = _OVERVIEW_ENDPOINT.set({})
    try:
        with _fortinet_operation(auth) as reader:
            yield reader
    finally:
        _OVERVIEW_ENDPOINT.reset(endpoint_token)
        _OVERVIEW_BUDGET.reset(timeout_token)


def _overview_ssh(auth, spec, scope):
    """Return classified CLI output using the same catalogue and verified VDOM reader as triage."""
    platform = auth.ssh_platform
    parameters = dict(spec.parameters)
    auth.require_tcp_port(auth.port)
    _, command, _ = _ssh_read_state(auth, platform, spec.query, parameters, auth.read_inventory)
    query = READ_QUERIES[platform][spec.query]
    if platform == "fortiadc" and is_read_sequence(platform, spec.query):
        commands = render_read_sequence(platform, spec.query, parameters, auth.read_inventory)[1]
        output = []
        for part in commands:
            rc, text = read_from_device(auth, platform, part)
            state = normalization.output_status(text, rc=rc, profile=platform, command=part,
                                                truncated=len(text.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES)
            if state != "ok" or _cli_refused(platform, text, command=part):
                reason = "permission_denied" if _fortiadc_diagnose_refused(part, text) else state
                return {"ok": False, "reason": reason, "rc": rc}
            output.append(_redact_output(text, auth))
        answer = {"ok": True, "text": "\n".join(output), "rc": rc}
    else:
        token = _TRIAGE_SCOPE.set(scope)
        try:
            answer = _triage_read(auth, platform, spec.query, parameters, auth.read_inventory)
        finally:
            _TRIAGE_SCOPE.reset(token)
    if not answer.get("ok"):
        return answer
    text = answer["text"]
    state = normalization.output_status(text, rc=answer["rc"], profile=platform, command=command,
                                        truncated=len(text.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES)
    if state == "empty" and query.empty_allowed:
        return {**answer, "status": "empty"}
    if state != "ok":
        return {**answer, "ok": False, "reason": state}
    return {**answer, "status": "ok"}


def _overview_audit_skipped(target, reason):
    # Even an alias without usable auth has one operation in the audit ledger.
    operation_id = f"op_{secrets.token_hex(16)}"
    record("network_overview", operation_id=operation_id, device=target, status="started")
    record("network_overview", operation_id=operation_id, device=target, status="failed", detail=reason)


@_audit_device_call
def network_overview(auth: TargetAuth, execute) -> dict[str, Any]:
    result = execute()
    return {**result, "ok": result["status"] == "complete"}


@_audit_device_call
def fortios_wifi_get(auth: TargetAuth, endpoint: str, budget_seconds: float | None = None) -> dict[str, Any]:
    from . import wifi_rest
    # Without a shared deadline the call is unchanged (TIMEOUT applies).
    document = (wifi_rest.get(auth, endpoint) if budget_seconds is None
                else wifi_rest.get(auth, endpoint, budget_seconds=budget_seconds))
    records, unparsed = wifi_rest.parse_counted(endpoint, document)
    firmware = {}
    if endpoint == wifi_rest.POLICY_HITS:
        from netops_core import tested
        version = document.get('version')
        version = version.removeprefix('v') if isinstance(version, str) else None
        support = tested.support('FortiOS', version, ('8.0.2',), function='firewall_policy_hits')
        firmware = {'firmware_support': support, 'warnings': [tested.warning(support)] if not tested.is_tested(support) else []}
    return {"ok": True, "records": records, "endpoint": endpoint, "unparsed_rows": unparsed, **firmware,
            "content_sha256": digest_text(json.dumps(records, sort_keys=True, allow_nan=False))}


def _wifi_rest_result(auth, reads, before_read=None):
    """`before_read(auth, endpoint)` (optional) charges each GET actually sent to a caller's
    shared budget and returns the seconds left of its deadline; it may raise to stop."""
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: Wi-Fi REST supports FortiOS only")
    if not auth.fortios_rest_token:
        return {"ok": False, "error_code": "unsupported", "target": auth.alias,
                "error": "Enroll helper.fortios_rest_credential (api-token) and certificate pin or CA; see docs/fortios-wifi-rest.md"}
    result = {"ok": True, "target": auth.alias, "vantage": "FortiOS REST monitor, root VDOM",
              "device_output_trust": "untrusted", "sources": []}
    for name, endpoint in reads:
        seconds = before_read(auth, endpoint) if before_read is not None else None
        try:
            answer = (fortios_wifi_get(auth, endpoint) if seconds is None
                      else fortios_wifi_get(auth, endpoint, budget_seconds=seconds))
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
        if 'firmware_support' in answer:
            result.update(firmware_support=answer['firmware_support'], warnings=answer['warnings'])
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


def _wifi_clients_result(auth, ssid=None, ap=None, mac=None, ip=None, name=None, before_read=None):
    from .wifi_rest import MONITOR, checked_filters
    checked_filters(ssid, ap, mac, name)
    result = _wifi_rest_result(auth, (("records", MONITOR + "client"), ("access_points", MONITOR + "managed_ap")),
                               before_read)
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
    identities = _wifi_rest_result(auth, (("devices", DEVICES),), before_read)
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
        elif len(matches) > 1 and before_read is not None:
            # locate_endpoint only (the one before_read caller): the same join's several
            # matching APs, so that ambiguity is not mistaken for an unjoined AP.
            row["ap_matches"] = [{key: a.get(key) for key in ("serial", "wtp_id", "name", "local_addr")}
                                 for a in matches]
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
def firewall_policy_hits(auth: TargetAuth, unused_only: bool = False, limit: int = 100,
                         offset: int = 0, max_bytes: int = 16_000) -> dict[str, Any]:
    """RO policy counters in root VDOM; zero hits are candidates within the counter lifetime only."""
    from .wifi_rest import POLICY_HITS
    from . import switch_pages
    if type(unused_only) is not bool:
        raise ValueError('unused_only must be boolean')
    switch_pages.validate(limit, offset, max_bytes)
    result = _wifi_rest_result(auth, (('records', POLICY_HITS),))
    if result.get('ok'):
        rows = sorted(result['records'], key=lambda row: row['policy_id'])
        incomplete = sum(row['state'] == 'incomplete' for row in rows)
        result.update(state='incomplete' if incomplete else 'ok' if rows else 'empty',
                      counts={'policies': len(rows), 'unused_candidates': sum(row['unused_candidate'] is True for row in rows),
                              'incomplete': incomplete}, unused_only=unused_only,
                      counter_note='Counters cover the device counter lifetime; reset, reboot and HA changes can affect them. '
                                   'Zero hits are candidates for investigation, not proof a policy is safe to remove. '
                                   'Only policies returned by the root VDOM monitor are included; policy 0 is implicit. '
                                   'Each page reads current counters and sorts by policy ID.')
        result['records'] = [row for row in rows if row['unused_candidate'] is True] if unused_only else rows
    return switch_pages.page(result, limit=limit, offset=offset, max_bytes=max_bytes)


@_audit_device_call
def fortiswitch_overview(auth: TargetAuth) -> dict[str, Any]:
    """Every FortiLink-managed switch of the root VDOM from two RO REST reads; no serial is needed."""
    from .wifi_rest import SWITCH_HEALTH, SWITCH_STATUS, switch_overview
    result = _wifi_rest_result(auth, (("records", SWITCH_STATUS),))
    if not result.get("ok"):
        result["records"] = []
        return result
    health = _wifi_rest_result(auth, (("health", SWITCH_HEALTH),))
    result["sources"].extend(health.get("sources", []))
    if not health.get("ok"):
        # The connection view stands on its own; only uptime and health stay unknown.
        result["health_missing"] = {"reason": "rest_unavailable", **{
            key: health[key] for key in ("error_code", "http_status", "failed_step") if key in health}}
    result["records"] = switch_overview(result["records"], health.get("health"))
    result["counts"] = {"switches": len(result["records"]),
                        "up": sum(1 for row in result["records"] if row["status"] == "Connected"),
                        "not_connected": sum(1 for row in result["records"] if row["status"] != "Connected")}
    result["join_time_note"] = "join_time_local is the FortiGate wall clock without a time zone, as the device prints it."
    return result


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
    if auth.ssh_platform == "cisco_xe":
        triage.validate_history(history_limit, history_offset)
        if not triage.valid_mac(mac) or ip is not None or name is not None:
            raise ValueError("invalid_argument: Catalyst 9800 wifi_triage requires one client MAC")
        return triage.run_c9800(lambda query, parameters: _c9800_triage_read(auth, query, parameters),
                               mac, auth.alias, summary=summary)
    if auth.ssh_platform == "ruckus_unleashed":
        return _triage_wifi_ruckus(auth, mac, ip, summary, name, history_limit, history_offset)
    if auth.ssh_platform != "fortinet":
        raise ValueError("unsupported_platform: wifi_triage supports FortiOS, Ruckus Unleashed and Catalyst 9800 targets")
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


def _triage_wifi_ruckus(auth: TargetAuth, mac: str | None, ip: str | None, summary: bool, name: str | None,
                        history_limit: int, history_offset: int) -> dict[str, Any]:
    """wireless path (RP02): Ruckus Unleashed client triage over catalogue reads of this target (inside the audited call)."""
    from datetime import datetime, timezone
    from . import triage_wifi as triage
    triage.validate_history(history_limit, history_offset)
    if name is not None:
        raise ValueError("invalid_argument: a Ruckus Unleashed target selects the client by mac or ip, not by name")

    def read(query: str, parameters: dict[str, str] | None) -> dict[str, Any]:
        try:
            return triage_wifi_read(auth, "ruckus_unleashed", query, parameters)
        except PolicyScopeError:
            return {"ok": False, "reason": "permission_denied"}

    result = _run_triage(auth, lambda checked: triage.run_ruckus(checked, lambda: datetime.now(timezone.utc), mac, ip,
                                                                  auth.alias, enabled_queries=auth.enabled_queries),
                         read, "wifi_triage", identity_query="system_info")
    if not result.get("ok"):
        return {"ok": False, **result}
    return triage.ruckus_overview(result) if summary is True else triage.full_page(result, history_limit, history_offset)


def _schema_cache_key(
    auth: TargetAuth, library: Any, path: str, view: str, vdom: str | None, keys: list[str],
) -> tuple[Any, ...]:
    return _ssh_cache_key(auth,"fortinet","schema_read",{
        "path":path,"view":view,"vdom":json.dumps(vdom),"owners":json.dumps(keys),
        "schema":library.sha256})


def _schema_capture_text(captured, auth):
    text = captured.decode("utf-8", "replace")
    for value in _redaction_secret_forms(auth):
        text = text.replace(value, "<REDACTED>")
    return core_prompt.cleaned(text, "fortinet")


@_audit_device_call
def schema_read(
    auth: TargetAuth, path: str, view: str, vdom: str | None,
    owners: list[str] | None, offset: int, max_bytes: int, content_sha256: str | None = None,
) -> dict[str, Any]:
    from . import configuration, schema_read as reader
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
                return {"ok":False,"target":auth.alias,"platform":"fortinet","query":"schema_read",**_transport_failure(code,auth)}
            raise ValueError("SSH schema identity read failed") from None
        if rc not in (0,None) or _cli_refused("fortinet",status):
            raise ValueError("the device refused the identity check")
        current_vdom=reader.verify_status(library,status)
        try:
            captured = bytearray()

            def capture(chunk):
                if len(captured) + len(chunk) > reader.MAX_SNAPSHOT:
                    raise core_ssh.OutputLimitError()
                captured.extend(chunk)

            rc,raw=read_from_device(auth,"fortinet","show full-configuration",
                                    stdout_consumer=configuration.bounded_consumer(capture))
            if captured:
                raw = _schema_capture_text(captured, auth)
        except Exception as exc:
            if (code:=_transport_cause(exc)) is not None:
                return {"ok":False,"target":auth.alias,"platform":"fortinet","query":"schema_read",**_transport_failure(code,auth)}
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
_CONFIG_REDACTION_CHANGED = (
    "configuration snapshot predates a session secret; take a new config_read capture at offset 0 without "
    "snapshot_id, and for config_diff compare two new captures"
)
_PAGINATION_CODES = {
    _CONFIG_REDACTION_CHANGED: "config_snapshot_redaction_changed",
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


class SnapshotIncomparable(PaginationRefused):
    """config_diff of two snapshots taken with other section, firmware, profile or options (verification).

    Also snapshots of another scope (target, platform or credential; verification) or different
    FortiADC account visibility. A restart at offset 0 cannot repair the mismatch.
    """

    restartable = False


class ConfigurationRefusal(PaginationRefused):
    """A config_read/config_diff refusal with a fixed machine code and fixed safe text (verification).

    ``config_platform_not_supported``: the identity of an ExtremeXOS, Cisco IOS, IOS XE, NX-OS or Arista EOS
    target cannot be read conclusively (identity-unverifiable); the text stays the engine text, only the
    machine code is new.  An identity that is read but is not the tested one is no refusal (startup): the read
    runs and the reply carries ``firmware_support`` with a ``firmware_untested`` warning.
    ``config_diff_limit_exceeded``: the line diff of two snapshots exceeds its fixed bound.  A restart at
    offset 0 repairs neither.
    """

    restartable = False


_CONFIG_SCOPE_MISMATCH = 'configuration snapshot scope mismatch'


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
        if platform not in _IDENTITY_PLATFORMS and platform != "fortios":
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
                content_sha256: str | None = None, filter_sha256: str | None = None,
                approve_baseline: bool = False) -> dict[str, Any]:
    from . import configuration
    configuration.require(auth, platform, 'read')
    if type(approve_baseline) is not bool:
        raise ValueError('invalid baseline approval')
    if approve_baseline:
        if platform == 'ruckus_unleashed':
            raise ValueError('Unleashed snapshots support in-memory comparison')
        configuration.require(auth, platform, 'compare')
        if (not snapshot_id or content_sha256 is None or offset != 0 or contains is not None or
                filter_sha256 is not None or context != 0):
            raise ValueError('baseline approval requires an existing unfiltered snapshot and content_sha256')
        response = config_read(auth, platform, section, include_all, snapshot_id, offset, limit,
                               redaction, include_defaults, content_sha256=content_sha256)
        if response.get('ok'):
            stored = 'fortios' if platform == 'fortinet' else platform
            with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, stored)):
                try:
                    response.update(configuration.approve_baseline(auth, snapshot_id, section,
                                                                   content_sha256, platform=stored))
                except configuration.ConfigurationBaselineError as exc:
                    raise ConfigurationRefusal('config_baseline_unavailable', str(exc)) from None
        return response
    if redaction not in ('minimal', 'full') or type(include_defaults) is not bool:
        raise ValueError('invalid configuration capture options')
    configuration.filter_arguments(contains, context, content_sha256, filter_sha256)
    if offset and (contains is not None or filter_sha256 is not None) and (
            content_sha256 is None or filter_sha256 is None):
        raise ValueError('configuration filter continuation requires both fingerprints')
    if not snapshot_id and (content_sha256 is not None or filter_sha256 is not None):
        raise ValueError('configuration fingerprints require an existing snapshot')
    view = (contains, context, content_sha256, filter_sha256)
    if platform == 'ruckus_unleashed':
        if section != 'all' or include_all is not True or redaction != 'full' or include_defaults:
            raise ValueError('Unleashed requires section all, include_all true, redaction full and include_defaults false')
        return _ruckus_config_read(auth, snapshot_id, offset, limit, view)
    if platform == 'extreme_exos':
        return _exos_config_read(auth, section, include_all, snapshot_id, offset, limit, redaction,
                                 include_defaults, view)
    if platform in ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'juniper_junos', 'juniper_junos_els'):
        return _ios_config_read(auth, section, include_all, snapshot_id, offset, limit, redaction,
                                include_defaults, view, platform)
    try:
        if redaction == 'full':
            return _full_config_read(auth, platform, section, include_all, snapshot_id, offset, limit,
                                     include_defaults, view)
        if platform == 'fortiadc' or include_defaults:
            raise ValueError('config_platform_not_supported: full redaction mode required')
        return _minimal_config_read(auth, section, include_all, snapshot_id, offset, limit, view)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': 'fortiadc' if platform == 'fortiadc' else 'fortios',
                'section': section, **_transport_failure(failure.code, auth)}


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
    from . import configuration, config_fortios
    command = configuration.read_command(section, include_all)
    configuration.page_arguments(offset, limit)
    with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, 'fortios')):
        forbidden = auth.redaction_secrets
        if snapshot_id:
            capture = configuration.get_snapshot(auth, snapshot_id, section)
            text, count, firmware, identity = capture.text, capture.redacted_count, capture.firmware, snapshot_id
            if not configuration.snapshot_redaction_current(capture, forbidden):
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
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
            capture = configuration.StreamRedactor(forbidden, section, limits=auth.configuration_limits)
            try:
                rc, raw = read_from_device(auth, 'fortinet', command, stdout_consumer=configuration.bounded_consumer(capture.feed))
                if rc != 0 or raw:
                    raise ValueError('configuration read refused; output withheld')
                text, hidden, count = capture.finish()
                text = configuration.response_content(text, forbidden)
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
            identity = configuration.store(auth, text, hidden, count, section, firmware, response_secrets=forbidden)
        capture = hidden = None
        try:
            view_fields = _filtered_view(configuration, identity, view, offset, limit,
                                         lambda: configuration.get_snapshot(auth, identity, section), forbidden, current=True)
            response = {'ok': True, 'target': auth.alias, 'platform': 'fortios', 'view': 'running',
                    'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                    'redaction_profile': configuration.PROFILE, 'redacted_count': count,
                    'section': section, 'command': command,
                    'firmware': dict(zip(('model', 'version', 'build'), firmware)), **view_fields}
            if not snapshot_id:
                response.update(configuration.retain_history(auth, identity, section))
            response.update(_firmware_fields(config_fortios.firmware_support(firmware)))
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


def _filtered_view(configuration, identity, view, offset, limit, lookup, secrets=(), *, current=False):
    contains, context, content_sha256, filter_sha256 = view
    fingerprint = configuration.filter_digest(identity, contains, context)
    if filter_sha256 is not None and not hmac.compare_digest(filter_sha256, fingerprint):
        raise ValueError('configuration filter changed; restart at offset 0')
    filtered, total_lines, matched_lines = configuration.filtered_snapshot(lookup, identity, contains, context, offset,
                                                                           secrets)
    if current and contains is not None and configuration.response_content(filtered, secrets) is not filtered:
        # A cached filtered view predates a session secret; never page it with its old hash.
        raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
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
    forbidden = auth.redaction_secrets
    retain_adc = (platform == 'fortiadc' and section == 'all' and include_defaults and
                  configuration.fortiadc_history_enabled(auth))
    command = adapter.read_command(section, include_all, include_defaults)
    configuration.page_arguments(offset, limit)
    with configuration.capture(auth.configuration_limits,
                               target=configuration.scope(auth, 'fortiadc' if platform == 'fortiadc' else 'fortios')):
        if snapshot_id:
            cached = configuration.get_full_snapshot(auth, snapshot_id, section, platform=platform,
                                                       include_defaults=include_defaults)
            firmware, text, count, identity = cached.firmware, cached.text, cached.redacted_count, snapshot_id
            if not configuration.snapshot_redaction_current(cached, forbidden):
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
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
                # startup (H11, H12, H18): a version or build outside the tested ones is read with the nearest field
                # policy and reported in firmware_support; only an unreadable identity or product is refused.
                firmware, metadata = adapter.verify_identity(status)
            except ValueError:
                raise ValueError('configuration identity-unverifiable; output withheld') from None
            policy = adapter.policy_for(firmware)
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
                except core_session.SessionError as exc:
                    if (exc.code in {"timeout", "idle_timeout", "disconnected", "page_limit"}
                            and (normalizer.raw_bytes if normalizer else capture.raw_bytes)):
                        raise configuration.ConfigurationRedactionError('stream-incomplete') from None
                    _raise_transport(exc)
                    raise ValueError('configuration transport-failed during capture; output withheld') from None
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
                framed = capture.frame_prompt is not None
                text, hidden, count = capture.finish()
                if platform == 'fortiadc':
                    full_adc = section == 'all' and include_defaults
                    if ((framed or full_adc) and not capture.frame_ended or
                            full_adc and not adapter.full_capture_complete(text)):
                        raise configuration.ConfigurationRedactionError('stream-incomplete')
                    metadata = adapter.assess(text, auth.login, section, include_defaults=include_defaults)
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
                                               include_defaults=include_defaults, metadata=metadata,
                                               response_secrets=forbidden)
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
                                                        include_defaults=include_defaults), forbidden,
                current=True)
            response = {'ok': True, 'target': auth.alias, 'platform': platform, 'view': 'running',
                    'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                    'redaction_profile': policy.identifier, 'redacted_count': count,
                    'redaction': 'full', 'include_defaults': include_defaults, 'capture_complete': True,
                    'section': section, 'command': command, **metadata,
                    'firmware': dict(zip(('model', 'version', 'build'), firmware)), **view_fields}
            support = adapter.firmware_support(firmware)
            if support['status'] != 'tested':
                # The field policy of the nearest tested version redacted this snapshot (fail-closed).
                response['policy_firmware'] = adapter.policy_firmware(firmware)
            response.update(_firmware_fields(support))
            if (platform == 'fortiadc' and section != 'all' and
                    adapter.object_section(section)[0] == config_fortiadc.TLS_GET_FAMILY):
                response['normalized_from_get'] = True
            if not snapshot_id and (platform == 'fortios' or retain_adc):
                response.update(configuration.retain_history(auth, identity, section, platform=platform))
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


def _ruckus_config_read(auth, snapshot_id, offset, limit, view):
    from . import configuration
    from .config_buffers import ContentBuilder, ContentLimitError
    from .sanitize import ruckus_config_allowlist

    platform, section = 'ruckus_unleashed', 'all'
    profile = configuration.RUCKUS_PROFILE
    command = READ_QUERIES[platform]["config_settings"].command
    configuration.page_arguments(offset, limit)
    if offset and not snapshot_id:
        raise ValueError('configuration continuation requires snapshot_id')
    response = {'target': auth.alias, 'platform': platform, 'section': section, 'command': command}
    limits = auth.configuration_limits
    forbidden = _redaction_secret_forms(auth)
    with configuration.capture(limits, target=configuration.scope(auth, platform)):
        fresh = not snapshot_id
        if snapshot_id:
            snapshot = configuration.get_snapshot(auth, snapshot_id, section, platform=platform, profile=profile)
            if not configuration.snapshot_redaction_current(snapshot, forbidden):
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
            model, version = snapshot.firmware
            text = snapshot.text
        else:
            try:
                rc, output = _verified_read(auth, platform, command)
            except Exception as exc:
                return {**response, 'ok': False, 'complete': False, **_read_failure(exc, auth)}
            if rc not in (0, None) or _cli_refused(platform, output, command=command):
                return {**response, 'ok': False, 'complete': False, 'error_code': 'device_cli_error',
                        'error': 'The device CLI refused the configuration read'}
            byte_limit = min(_SSH_CAPTURE_MAX_BYTES, limits.all_bytes)
            if len(output.encode('utf-8')) > byte_limit:
                return {**response, 'ok': False, 'complete': False, 'error_code': 'incomplete_output',
                        'error': 'The configuration output exceeds its capture limit'}
            cleaned = _redact_output(ruckus_config_allowlist(output, forbidden), auth)
            parsed = wifi_parse.parse_ruckus_config(cleaned)
            model, version = _read_ruckus_identity(auth)
            if parsed["incomplete"] or parsed["unparsed_count"]:
                return {**response, 'ok': False, 'complete': False, 'error_code': 'incomplete_output',
                        'error': 'The device did not return all recognized configuration sections',
                        'missing_sections': parsed["missing_sections"], 'unparsed_count': parsed["unparsed_count"],
                        **_ruckus_firmware_fields(auth, model, version)}
            builder = ContentBuilder(byte_limit, forbidden, serialized_markers=False)
            try:
                builder.add(cleaned.encode('ascii', 'backslashreplace'))
                text = configuration.response_content(builder.finish(), forbidden)
            except ContentLimitError:
                return {**response, 'ok': False, 'complete': False, 'error_code': 'incomplete_output',
                        'error': 'The redacted configuration exceeds its capture limit'}
            finally:
                builder.close()
            metadata = {'config_scope': 'device-account-visible', 'configuration_complete': False,
                        'visibility_limitations': ['requested-section-only', 'account-rights-not-verified']}
            snapshot_id = configuration.store(
                auth, text, configuration.HiddenRecords(), 0, section, (model, version),
                platform=platform, profile=profile, metadata=metadata, response_secrets=forbidden)
            snapshot = configuration.get_snapshot(auth, snapshot_id, section, platform=platform, profile=profile)
        try:
            page = _filtered_view(configuration, snapshot_id, view, offset, limit, lambda: snapshot, forbidden,
                                  current=not fresh)
            return {**response, 'ok': True, 'complete': True, 'capture_complete': True, 'view': 'running',
                    'snapshot_id': snapshot_id, 'snapshot_sha256': configuration.content_digest(text),
                    'redaction': 'full', 'redaction_profile': profile, 'include_defaults': False,
                    **configuration.snapshot_metadata(snapshot), **_ruckus_firmware_fields(auth, model, version), **page}
        except BaseException:
            if fresh:
                configuration.discard_snapshot(snapshot_id)
            raise


def _exos_config_read(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view):
    """ExtremeXOS configuration read with the adapter's fixed read command, through the accepted config_exos consumer (one admitted option set)."""
    from . import config_exos_adapter as adapter
    try:
        return _exos_capture(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': adapter.PLATFORM,
                'section': section, **_transport_failure(failure.code, auth)}


_CONFIG_PLATFORM_NOT_SUPPORTED = 'config_platform_not_supported'
_IDENTITY_UNVERIFIABLE = 'configuration identity-unverifiable; output withheld'


def _config_firmware_fields(adapter, firmware):
    """startup (decision of 2026-11-17): the reply fields of the identity against the adapter's tested identity.

    A tested identity adds nothing, so its reply stays as before.  Another model, version or build is no
    refusal: the reply carries ``firmware_support`` (netops_core.tested, machine-readable) and a
    ``warnings`` item with the code ``firmware_untested`` and a short text for a person or an agent.
    """
    from netops_core import tested
    support = adapter.firmware_support(firmware)
    if tested.is_tested(support):
        return {}
    return {'firmware_support': support, 'warnings': [tested.warning(support)]}


def _identity_refused():
    """A device refusal of an EXOS/IOS family identity read: the same device-refused class as a refused capture.

    The text stays 'during identity read'; the chained fixed capture refusal lets the worker answer with the
    device-refused category (-32602 and guidance), as for a refused capture, instead of an internal error.
    """
    from . import configuration
    raise ValueError('configuration device-refused during identity read; output withheld') from (
        configuration.ConfigurationRefusedError())


def _exos_identity(auth, *, include_switch=False):
    """Exactly two protected exec identity reads; anything inconclusive withholds before the capture."""
    from . import config_exos_adapter as adapter
    outputs = []
    for command in adapter.IDENTITY_COMMANDS:
        try:
            rc, status = read_from_device(auth, adapter.PLATFORM, command)
        except Exception as exc:
            _raise_transport(exc)
            raise ValueError('configuration transport-failed during identity read; output withheld') from None
        if rc != 0 or type(status) is not str or _cli_refused(adapter.PLATFORM, status):
            _identity_refused()
        try:
            if command == 'show version':
                adapter.version_identity(status)
        except ValueError:
            raise ConfigurationRefusal(_CONFIG_PLATFORM_NOT_SUPPORTED, _IDENTITY_UNVERIFIABLE) from None
        outputs.append(status)
    try:
        identity = adapter.verify_identity(*outputs)
        return (*identity, outputs[1]) if include_switch else identity
    except ValueError:
        raise ConfigurationRefusal(_CONFIG_PLATFORM_NOT_SUPPORTED, _IDENTITY_UNVERIFIABLE) from None


def _exos_dirty(auth, hostname):
    platform = 'extreme_exos'
    address = _resolve_target_ipv4(auth)[0]
    known_hosts_line = host_key_line(auth, address, platform)
    anchor = (hostname + '.').encode('ascii')
    with _paced_connection(address, auth.port, platform):
        with core_session.Session(address, auth.port, auth.login, DeviceCredential(auth),
                                  known_hosts_line, legacy_ssh=auth.legacy_ssh,
                                  timeout_seconds=_SSH_LOGIN_TIMEOUT_SECONDS) as session:
            kind, _ = session.expect([b'\n' + anchor, b'\n* ' + anchor, b'\nSlot-', b'\n* Slot-'],
                                     _SSH_LOGIN_TIMEOUT_SECONDS)
            if kind >= 2:
                _, slot = session.expect(anchor, _SSH_LOGIN_TIMEOUT_SECONDS)
                if re.fullmatch(rb'[0-9]+ ' + re.escape(anchor), slot) is None:
                    raise ValueError('unverified ExtremeXOS stack prompt')
            _, tail = session.expect([b'# ', b'> '], _SSH_LOGIN_TIMEOUT_SECONDS)
    if re.fullmatch(rb'[0-9]+ [#>] ', tail) is None:
        raise ValueError('unverified ExtremeXOS prompt')
    return kind in (1, 3)


def _exos_live_diff(auth, base, offset, secret_offset):
    from . import config_exos_adapter as adapter

    if offset or secret_offset:
        raise ValueError('a live configuration comparison does not have continuation pages')
    try:
        firmware, _, switch = _exos_identity(auth, include_switch=True)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': adapter.PLATFORM,
                **_transport_failure(failure.code, auth)}
    try:
        hostname, selected, booted, saved = adapter.comparison_source(switch, base)
    except ValueError:
        return {'ok': False, 'target': auth.alias, 'platform': adapter.PLATFORM,
                'comparison_complete': False, 'reason': 'saved_configuration_unverified'}
    command = adapter.comparison_command(saved)
    response = {'ok': True, 'target': auth.alias, 'platform': adapter.PLATFORM, 'view': 'running',
                'origin': 'device', 'saved_configuration': saved, 'selected_configuration': selected,
                'booted_configuration': booted, 'firmware': dict(zip(('model', 'version', 'build'), firmware)),
                **_config_firmware_fields(adapter, firmware)}
    missing = []
    try:
        if saved not in (selected, booted):
            rc, files = read_from_device(auth, adapter.PLATFORM, 'ls')
            if rc or saved not in files.split():
                raise ValueError('saved configuration file was not found')
        rc, output = read_from_device(auth, adapter.PLATFORM, command)
        if rc != 0 or _cli_refused(adapter.PLATFORM, output):
            missing.append('difference_refused')
        else:
            removed, added = adapter.diff_counts(output, saved)
            response.update(content_changed=bool(removed or added), added_lines=added, removed_lines=removed,
                            hidden_changed_lines=removed + added)
    except core_ssh.OutputLimitError:
        missing.append('difference_unverified')
    except (core_ssh.SshError, _ConfigurationTransportFailed):
        missing.append('difference_transport_failed')
    except ValueError:
        missing.append('difference_unverified')
    try:
        response['dirty'] = _exos_dirty(auth, hostname)
    except (ValueError, OSError, core_ssh.SshError, core_session.SessionError):
        response['dirty'] = None
        missing.append('prompt_unverified')
    return {**response, 'comparison_complete': not missing, 'missing': missing}


_JUNOS_LOGIN_PROMPT = re.compile(rb'(?:\A|\n)([A-Za-z0-9_.-]{1,128}@[A-Za-z0-9_.-]{1,64})> [ \t]*\Z')
_JUNOS_EDIT_FOOTER = re.compile(r'(?:\A|\n)(?:# commit confirmed will be rolled back in [0-9]+ minutes?\n)?\[edit\]\Z')


def _junos_candidate_compare(auth, platform):
    """Read the shared candidate in a separate session without editing or discarding configuration."""
    from .config_junos_adapter import CANDIDATE_COMPARE

    address = _resolve_target_ipv4(auth)[0]
    known = host_key_line(auth, address, platform)
    with _paced_connection(address, auth.port, platform):
        with core_session.Session(address, auth.port, auth.login, DeviceCredential(auth), known,
                                  legacy_ssh=auth.legacy_ssh, timeout_seconds=_SSH_LOGIN_TIMEOUT_SECONDS) as session:
            _, login = session.expect([_JUNOS_LOGIN_PROMPT], _SSH_LOGIN_TIMEOUT_SECONDS)
            identity = _JUNOS_LOGIN_PROMPT.search(login).group(1)
            prompts = [re.compile(rb'(?:\A|\n)' + re.escape(identity + mode) + rb' [ \t]*\Z')
                       for mode in (b'>', b'#')]
            session.send('configure')
            mode, entered = session.expect(prompts, _SSH_READ_TIMEOUT_SECONDS)
            if mode != 1 or b'Entering configuration mode' not in entered:
                return 1, ''
            session.send(CANDIDATE_COMPARE)
            mode, answer = session.expect(prompts, _SSH_READ_TIMEOUT_SECONDS)
            if mode != 1:
                return 1, ''
            # A read-only shared editor can exit while another editor's changes are still pending.
            # Never answer a discard prompt: closing this otherwise untouched session is sufficient.
            session.send('exit configuration-mode')
            session.expect(prompts[:1], _SSH_READ_TIMEOUT_SECONDS)
    output = _pty_body(answer, CANDIDATE_COMPARE, identity + b'# ')
    footer = _JUNOS_EDIT_FOOTER.search(output)
    if footer is None:
        raise ValueError('Junos comparison has no configuration prompt context')
    return 0, output[:footer.start()]


def _junos_live_diff(auth, platform, base, other, offset, limit, secret_offset):
    """Compare a rollback or the shared candidate with running and redact the hierarchical output."""
    from . import config_junos_adapter as adapter

    if offset or secret_offset:
        raise ValueError('a live configuration comparison does not have continuation pages')
    try:
        firmware, _ = _ios_identity(auth, platform)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': platform, **_transport_failure(failure.code, auth)}
    candidate = 'candidate' in (base, other)
    command = adapter.comparison_command('candidate' if candidate else base)
    response = {'ok': True, 'target': auth.alias, 'platform': platform, 'view': 'running', 'origin': 'device',
                'base_snapshot': base, 'other_snapshot': other, 'command': command,
                'redaction_profile': adapter.PROFILE, 'hidden_lines_compared': False,
                'firmware': dict(zip(('model', 'version', 'build'), firmware)),
                **_config_firmware_fields(adapter, firmware)}
    missing = []
    try:
        rc, probe = read_from_device(auth, platform, adapter.VISIBILITY_COMMAND)
        if rc != 0 or type(probe) is not str or _cli_refused(platform, probe) or not adapter.visible(probe):
            missing.append('configuration_not_visible')
        else:
            rc, output = (_junos_candidate_compare(auth, platform) if candidate
                          else read_from_device(auth, platform, command))
            if rc != 0 or type(output) is not str or _cli_refused(platform, output):
                missing.append('difference_refused')
            else:
                # Junos show | compare treats the candidate as the destination.
                lines, counts = adapter.compare_lines(output, auth.redaction_secrets, reverse=base == 'candidate')
                text = ''.join(line + '\n' for line in lines)
                if len(text.encode('utf-8')) > min(limit, adapter.DIFF_MAX_BYTES):
                    missing.append('difference_too_large')
                else:
                    if counts['unparsed_lines']:
                        missing.append('difference_unparsed')
                    changed = bool(counts['added_lines'] or counts['removed_lines'])
                    response.update(identical=not changed and not counts['unparsed_lines'],
                                    content_changed=changed or bool(counts['unparsed_lines']), **counts,
                                    untrusted_device_output=text)
    except core_ssh.OutputLimitError:
        missing.append('difference_too_large')
    except (core_ssh.SshError, core_session.SessionError, _ConfigurationTransportFailed):
        missing.append('difference_transport_failed')
    except ValueError as exc:
        from .configuration import ConfigurationRefusedError
        missing.append('difference_refused' if isinstance(exc, ConfigurationRefusedError) else 'difference_unverified')
    if missing:
        for key in ('identical', 'content_changed', 'untrusted_device_output'):
            response.pop(key, None)
    return {**response, 'comparison_complete': not missing, 'missing': missing}


def _exos_capture(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view):
    from . import configuration, config_exos, config_exos_adapter as adapter
    platform = adapter.PLATFORM
    command = adapter.read_command(section, include_all, include_defaults, redaction)
    configuration.page_arguments(offset, limit)
    # The credentials plus the private session handoff: what the proxy and worker redact from the reply.
    # Only redaction input; the snapshot scope stays the target/credential HMAC.
    forbidden = auth.redaction_secrets
    with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, platform)):
        if snapshot_id:
            cached = configuration.get_full_snapshot(auth, snapshot_id, section, platform=platform,
                                                       include_defaults=include_defaults)
            if cached.profile != adapter.PROFILE or not adapter.firmware_record(cached.firmware):
                raise ValueError('configuration snapshot policy mismatch')
            if configuration.response_content(cached.text, forbidden) is not cached.text:
                # The session gained a secret after this capture: refuse, a fresh capture redacts it.
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
            text, count, firmware, identity = cached.text, cached.redacted_count, cached.firmware, snapshot_id
            metadata = configuration.snapshot_metadata(cached)
        else:
            if snapshot_id != '' or offset != 0:
                raise ValueError('a nonzero page offset requires an existing snapshot')
            firmware, metadata = _exos_identity(auth)
            capture = config_exos.StreamRedactor(forbidden, section, limits=auth.configuration_limits)
            try:
                try:
                    rc, raw = read_from_device(auth, platform, command,
                                               stdout_consumer=configuration.bounded_consumer(capture.feed))
                except core_ssh.OutputLimitError:
                    raise ValueError('configuration capture-limit-exceeded; output withheld') from None
                except core_ssh.OutputConsumerError as exc:
                    failure = exc.__context__
                    if isinstance(failure, configuration.ConfigurationBudgetError):
                        raise configuration.ConfigurationBudgetError(
                            'configuration memory budget exhausted for target; output withheld') from None
                    if isinstance(failure, configuration.ConfigurationRefusedError):
                        raise configuration.ConfigurationRefusedError() from None
                    if isinstance(failure, configuration.ConfigurationRedactionError):
                        raise configuration.ConfigurationRedactionError(failure.reason, line=failure.line) from None
                    raise configuration.ConfigurationRedactionError('redaction-unverifiable') from None
                except (configuration.ConfigurationRedactionError, configuration.ConfigurationBudgetError,
                        configuration.ConfigurationRefusedError):
                    raise
                except ValueError as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration transport-contract-failed; output withheld') from None
                except Exception as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration transport-failed during capture; output withheld') from None
                if rc != 0:
                    raise ValueError('configuration device-refused during capture; output withheld')
                if raw:
                    raise ValueError('configuration transport-contract-failed; output withheld')
                text, hidden, count = capture.finish()
                metadata = adapter.assess(metadata, capture.summary())
                # The stored, hashed and paged text is what the client receives after proxy and worker.
                text = configuration.response_content(text, forbidden)
                identity = configuration.store(auth, text, hidden, count, section, firmware,
                                               platform=platform, profile=adapter.PROFILE,
                                               include_defaults=include_defaults, metadata=metadata)
            except configuration.ConfigurationRedactionError as exc:
                raise ValueError('configuration ' + exc.reason + exc.location + '; output withheld') from None
            except configuration.ConfigurationRefusedError:
                raise ValueError('configuration device-refused during capture; output withheld') from None
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
                                                        include_defaults=include_defaults), forbidden,
                current=bool(snapshot_id))
            response = {'ok': True, 'target': auth.alias, 'platform': platform, 'view': 'running',
                        'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                        'redaction_profile': adapter.PROFILE, 'redacted_count': count,
                        'redaction': 'full', 'include_defaults': include_defaults, 'capture_complete': True,
                        'section': section, 'command': command, **metadata,
                        'firmware': dict(zip(('model', 'version', 'build'), firmware)),
                        **_config_firmware_fields(adapter, firmware), **view_fields}
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


def _ios_config_read(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view,
                     platform='cisco_ios'):
    """Cisco IOS, IOS XE, NX-OS or Arista EOS configuration read with the adapter's fixed read command, through the adapter's stream consumer (one admitted option set)."""
    adapter = _ios_family_adapter(platform)
    try:
        return _ios_capture(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view,
                            platform)
    except _ConfigurationTransportFailed as failure:
        return {'ok': False, 'target': auth.alias, 'platform': _adapter_platform(adapter, platform),
                'section': section, **_transport_failure(failure.code, auth)}


def _ios_identity(auth, platform='cisco_ios'):
    """One protected exec ``show version`` read, bounded by the adapter; anything else withholds before the capture."""
    adapter = _ios_family_adapter(platform)
    platform = _adapter_platform(adapter, platform)
    (command,) = adapter.IDENTITY_COMMANDS
    try:
        rc, status = read_from_device(auth, platform, command)
    except Exception as exc:
        _raise_transport(exc)
        raise ValueError('configuration transport-failed during identity read; output withheld') from None
    if rc != 0 or type(status) is not str or _cli_refused(platform, status):
        _identity_refused()
    try:
        return adapter.verify_identity(status)
    except ValueError:
        raise ConfigurationRefusal(_CONFIG_PLATFORM_NOT_SUPPORTED, _IDENTITY_UNVERIFIABLE) from None


def _ios_capture(auth, section, include_all, snapshot_id, offset, limit, redaction, include_defaults, view,
                 platform='cisco_ios', *, comparison_view=None):
    from . import configuration
    adapter = _ios_family_adapter(platform)
    platform = _adapter_platform(adapter, platform)
    redactor = _ios_family_redactor(platform)
    # The only admitted option set (section all, include_all true, no defaults, redaction full);
    # everything else, including a request with the ``all`` option, is refused before any SSH.
    command = adapter.read_command(section, include_all, include_defaults, redaction)
    if comparison_view == 'startup':
        command = adapter.STARTUP_COMMAND
    configuration.page_arguments(offset, limit)
    # Credentials plus the private session handoff, as for EXOS: redaction input only; the snapshot
    # scope stays the target/credential HMAC.
    forbidden = auth.redaction_secrets
    with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, platform)):
        if snapshot_id:
            cached = configuration.get_full_snapshot(auth, snapshot_id, section, platform=platform,
                                                       include_defaults=include_defaults)
            if cached.profile != adapter.PROFILE or not adapter.firmware_record(cached.firmware):
                raise ValueError('configuration snapshot policy mismatch')
            if configuration.response_content(cached.text, forbidden) is not cached.text:
                # The session gained a secret after this capture: refuse, a fresh capture redacts it.
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
            text, count, firmware, identity = cached.text, cached.redacted_count, cached.firmware, snapshot_id
            metadata = configuration.snapshot_metadata(cached)
            if metadata.get('comparison_view') == 'startup':
                command = adapter.STARTUP_COMMAND
        else:
            if snapshot_id != '' or offset != 0:
                raise ValueError('a nonzero page offset requires an existing snapshot')
            firmware, metadata = _ios_identity(auth, platform)
            if comparison_view is not None and platform == 'cisco_nxos':
                try:
                    rc, output = read_from_device(auth, platform, command + ' | count')
                except (*_TRANSPORT_EXCEPTIONS, ValueError) as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration stream-incomplete; output withheld') from None
                if rc != 0:
                    raise ValueError('configuration device-refused during count; output withheld')
                expected_lines = adapter.line_count(output)
                if expected_lines is None:
                    raise ValueError('configuration stream-incomplete; output withheld')
                capture = adapter.ComparisonRedactor(forbidden, section, limits=auth.configuration_limits,
                                                     command=command, expected_lines=expected_lines)
            elif comparison_view is not None and platform == 'cisco_ios':
                capture = redactor(forbidden, section, limits=auth.configuration_limits, comparison=True)
            elif comparison_view is not None and platform == 'arista_eos':
                from .config_indented import EosComparisonRedactor
                capture = EosComparisonRedactor(forbidden, section, limits=auth.configuration_limits, command=command)
            elif platform == 'cisco_xe':
                capture = redactor(forbidden, section, limits=auth.configuration_limits, comparison_view=comparison_view)
            else:
                capture = redactor(forbidden, section, limits=auth.configuration_limits)
            if comparison_view is not None:
                metadata['comparison_view'] = comparison_view
            try:
                try:
                    rc, raw = read_from_device(auth, platform, command,
                                               stdout_consumer=configuration.bounded_consumer(capture.feed))
                except core_ssh.OutputLimitError:
                    raise ValueError('configuration capture-limit-exceeded; output withheld') from None
                except core_ssh.OutputConsumerError as exc:
                    failure = exc.__context__
                    if isinstance(failure, configuration.ConfigurationBudgetError):
                        raise configuration.ConfigurationBudgetError(
                            'configuration memory budget exhausted for target; output withheld') from None
                    if isinstance(failure, configuration.ConfigurationRefusedError):
                        raise configuration.ConfigurationRefusedError() from None
                    if isinstance(failure, configuration.ConfigurationRedactionError):
                        raise configuration.ConfigurationRedactionError(failure.reason, line=failure.line) from None
                    raise configuration.ConfigurationRedactionError('redaction-unverifiable') from None
                except (configuration.ConfigurationRedactionError, configuration.ConfigurationBudgetError,
                        configuration.ConfigurationRefusedError):
                    raise
                except ValueError as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration transport-contract-failed; output withheld') from None
                except Exception as exc:
                    _raise_transport(exc)
                    raise ValueError('configuration transport-failed during capture; output withheld') from None
                if rc != 0:
                    raise ValueError('configuration device-refused during capture; output withheld')
                if raw:
                    raise ValueError('configuration transport-contract-failed; output withheld')
                text, hidden, count = capture.finish()
                if count != len(hidden):
                    raise ValueError('configuration capture-failed; output withheld')
                # The IOS/NX-OS/EOS consumers' generic hidden records (ordinal + label digest) only back its
                # count; like EXOS, a full-profile snapshot keeps none (config_diff compares only the visible text).
                hidden = configuration.HiddenRecords()
                metadata = adapter.assess(metadata, capture.summary())
                # The stored, hashed and paged text is what the client receives after proxy and worker.
                text = configuration.response_content(text, forbidden)
                identity = configuration.store(auth, text, hidden, count, section, firmware,
                                               platform=platform, profile=adapter.PROFILE,
                                               include_defaults=include_defaults, metadata=metadata)
            except configuration.ConfigurationRedactionError as exc:
                raise ValueError('configuration ' + exc.reason + exc.location + '; output withheld') from None
            except configuration.ConfigurationRefusedError:
                raise ValueError('configuration device-refused during capture; output withheld') from None
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
                                                        include_defaults=include_defaults), forbidden,
                current=bool(snapshot_id))
            response = {'ok': True, 'target': auth.alias, 'platform': platform,
                        'view': metadata.get('comparison_view', 'running'),
                        'snapshot_id': identity, 'snapshot_sha256': configuration.content_digest(text),
                        'redaction_profile': adapter.PROFILE, 'redacted_count': count,
                        'redaction': 'full', 'include_defaults': include_defaults, 'capture_complete': True,
                        'section': section, 'command': command, **metadata,
                        'firmware': dict(zip(('model', 'version', 'build'), firmware)),
                        **_config_firmware_fields(adapter, firmware), **view_fields}
            text = None
            return response
        except BaseException:
            if not snapshot_id:
                configuration.discard_snapshot(identity)
            raise


# config_diff platforms (verification): the requested name -> the snapshot platform. FortiOS/FortiADC as before;
# EXOS and the IOS family compare only snapshots of their exact config_read profile.
_DIFF_PLATFORMS = {'fortios': 'fortios', 'fortinet': 'fortios', 'fortiadc': 'fortiadc',
                   'extreme_exos': 'extreme_exos', 'cisco_ios': 'cisco_ios', 'cisco_xe': 'cisco_xe',
                   'cisco_nxos': 'cisco_nxos', 'arista_eos': 'arista_eos',
                   'ruckus_unleashed': 'ruckus_unleashed',
                   'juniper_junos': 'juniper_junos', 'juniper_junos_els': 'juniper_junos_els'}
_MARKER_DIFF_PLATFORMS = frozenset(('extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'ruckus_unleashed',
                                     'juniper_junos', 'juniper_junos_els'))


def _startup_live_diff(auth, adapter):
    from . import configuration
    captures = []
    try:
        for source in adapter.LIVE_DIFF:
            captured = _ios_capture(auth, 'all', True, '', 0, 1, 'full', False,
                                    (None, 0, None, None), adapter.PLATFORM, comparison_view=source)
            captures.append(captured['snapshot_id'])
    except BaseException:
        for identity in captures:
            configuration.discard_snapshot(identity)
        raise
    status = None
    try:
        rc, output = read_from_device(auth, adapter.PLATFORM, adapter.DIFF_COMMAND)
        if rc == 0 and not _cli_refused(adapter.PLATFORM, output):
            status = adapter.native_diff_status(output)
    except (*_TRANSPORT_EXCEPTIONS, ValueError):
        # The two redacted captures are still usable when the auxiliary native check fails.
        pass
    firmware_fields = {key: captured[key] for key in ('firmware_support', 'warnings') if key in captured}
    return captures[0], captures[1], status, firmware_fields


@_audit_device_call
def config_diff(auth: TargetAuth, platform: str, base_snapshot: str,
                other_snapshot: str, offset: int = 0, limit: int = 48000, secret_offset: int = 0) -> dict[str, Any]:
    from . import configuration
    configuration.require(auth, platform, 'compare')
    configuration.page_arguments(offset, limit)
    if type(secret_offset) is not int or not 0 <= secret_offset <= 1073741824:
        raise ValueError('invalid secret change page')
    live = (platform in ('arista_eos', 'cisco_nxos', 'cisco_ios', 'cisco_xe')
            and (base_snapshot, other_snapshot) == ('startup', 'running'))
    if live:
        adapter = _ios_family_adapter(platform)
        if offset or secret_offset:
            raise ValueError('active startup comparison starts at offset zero; use its snapshot IDs for later pages')
        try:
            base_snapshot, other_snapshot, native_status, firmware_fields = _startup_live_diff(auth, adapter)
        except _ConfigurationTransportFailed as failure:
            return {'ok': False, 'target': auth.alias, 'platform': platform, **_transport_failure(failure.code, auth)}
        except ValueError as failure:
            match = re.match(r'configuration (device-refused|stream-incomplete|capture-limit-exceeded|'
                             r'redaction-unverifiable)\b', str(failure))
            return {'ok': False, 'target': auth.alias, 'platform': platform,
                    'error_code': match[1] if match else 'configuration-capture-failed',
                    'error': {'arista_eos': 'EOS', 'cisco_nxos': 'NX-OS',
                              'cisco_ios': 'IOS', 'cisco_xe': 'IOS XE'}[platform] +
                             ' running/startup comparison could not capture both configurations'}
    stored = _DIFF_PLATFORMS[platform]
    if stored == 'ruckus_unleashed' and base_snapshot == 'baseline':
        raise ValueError('Unleashed comparison requires two in-memory snapshot IDs')
    if stored == 'extreme_exos':
        from . import config_exos_adapter as adapter
        if adapter.live_comparison(base_snapshot, other_snapshot):
            return _exos_live_diff(auth, base_snapshot, offset, secret_offset)
    if stored in ('juniper_junos', 'juniper_junos_els'):
        from . import config_junos_adapter as adapter
        if adapter.live_comparison(base_snapshot, other_snapshot):
            return _junos_live_diff(auth, stored, base_snapshot, other_snapshot, offset, limit, secret_offset)
    marked = stored in _MARKER_DIFF_PLATFORMS
    guarded = marked or stored in ('fortios', 'fortiadc')
    admit = None
    if guarded:
        forbidden = auth.redaction_secrets

        def admit(snapshot):
            # The same guard as a config_read page from a snapshot: a session secret added after the
            # capture would change the stored text, so neither snapshot is compared; a fresh pair redacts it.
            if configuration.response_content(snapshot.text, forbidden) is not snapshot.text:
                raise _pagination_refused(_CONFIG_REDACTION_CHANGED)
    with configuration.capture(auth.configuration_limits, target=configuration.scope(auth, stored)):
        try:
            text, changed, identical, metadata = configuration.compare(
                auth, base_snapshot, other_snapshot, platform=stored, with_metadata=True, admit=admit)
        except PaginationRefused:
            raise
        except configuration.ConfigurationBaselineError as exc:
            raise ConfigurationRefusal('config_baseline_unavailable', str(exc)) from None
        except configuration.DiffLimitExceeded as exc:
            # The line diff of the EXOS/IOS family exceeds its fixed bound (verification) or the memory budget
            # (verification): a fixed code and one of two fixed texts.
            message = str(exc)
            if message not in (configuration.DIFF_LIMIT_EXCEEDED, configuration.DIFF_BUDGET_EXCEEDED):
                message = configuration.DIFF_LIMIT_EXCEEDED
            raise ConfigurationRefusal('config_diff_limit_exceeded', message) from None
        except ValueError as exc:
            if ((marked and str(exc) in (configuration.INCOMPARABLE, _CONFIG_SCOPE_MISMATCH)) or
                    (stored == 'fortiadc' and str(exc) == configuration.FORTIADC_VISIBILITY_MISMATCH)):
                raise SnapshotIncomparable('config_snapshot_incomparable', str(exc)) from None
            raise
        if guarded:
            # The paged diff text is redacted with the same session secrets as the final reply.
            try:
                text = configuration.response_content(text, forbidden)
            except configuration.ConfigurationBudgetError:
                raise ConfigurationRefusal('config_diff_limit_exceeded',
                                           configuration.DIFF_BUDGET_EXCEEDED) from None
        changes, next_secret = changed.page(secret_offset)
        response = {'ok': True, 'target': auth.alias, 'platform': stored,
                'base_snapshot': base_snapshot, 'other_snapshot': other_snapshot,
                'identical': identical, 'secrets_changed': changes,
                'secret_offset': secret_offset, 'next_secret_offset': next_secret,
                'secrets_changed_count': len(changed), **metadata, **configuration.payload(text, offset, limit)}
        if stored == 'ruckus_unleashed':
            identity = metadata['base_capture']['firmware']
            response.update(_ruckus_firmware_fields(auth, identity['model'], identity['version']))
        if marked:
            # Hidden (MARKER) lines are constants in both snapshots: identical means only that the visible
            # redacted text is equal; a change confined to hidden lines is not visible (no hidden-line hashes).
            response['hidden_lines_compared'] = False
        if live:
            response.update(firmware_fields)
        elif stored == 'cisco_nxos':
            adapter = _ios_family_adapter(stored)
            firmware = metadata['other_capture']['firmware']
            record = tuple(firmware[key] for key in ('model', 'version', 'build') if key in firmware)
            response.update(_config_firmware_fields(adapter, record))
        if live:
            if native_status is False and not identical:
                native_status = None
            response['unsaved_changes'] = native_status
            response['comparison_status'] = 'incomplete' if native_status is None else 'verified'
            if native_status is None:
                response['comparison_reason'] = 'native-diff-unavailable-or-inconsistent'
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
            found, identity = config_fortiadc.verify_identity(status)
            # startup (H12): another model or build is triaged with firmware_support "untested" and a warning.
            support = config_fortiadc.firmware_support(found, "triage_slb")
        except configuration.UnsupportedConfigurationFirmware:
            # Only another product kind is refused here (startup §2.4), never a model or build.
            return identity_failure("config_platform_not_supported", "unsupported",
                                    "triage_slb requires a FortiADC target; the device reports another product")
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
                        **_transport_failure(code, auth)})
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
    required = rules.REQUIRED_STEPS
    content_routing = bool(vs) and vs["content_routing"] == "enable"
    if content_routing:
        # adc statistics ADC-C04: the pool is chosen per request by the content-routing entries; read each entry (at most
        # MAX_CONTENT_ROUTES) and name its pool as a configured candidate. With exactly one candidate pool and every
        # entry read, that pool is the pool of every routed request and is evaluated like a static pool.
        chain["pool"]["selection"] = "content_routing"
        chain["content_routing"] = []
        required = ["vs_config", "slb_vs_stat", "system_performance"]
        complete = bool(vs["content_routing_list"])
        if not complete:
            miss("content_routing", "empty", "content-routing enable without content-routing-list")
        for index, entry in enumerate(dict.fromkeys(vs["content_routing_list"])):
            safe = SAFE_FORTIADC_OBJECT.fullmatch(entry) is not None
            step = "content_routing:" + entry if safe else "content_routing"
            if index >= rules.MAX_CONTENT_ROUTES or not safe:
                complete = False
                miss(step, "truncated" if index >= rules.MAX_CONTENT_ROUTES else "unparsed")
                continue
            value = config_step(step, "load-balance content-routing " + entry,
                                lambda text, n=entry: rules.content_routing_config(text, n))
            required.append(step)
            if value is None:
                complete = False
            elif value["schedule_list"] == "enable":
                complete = False
                miss(step, "unsupported", "content-routing entry selects its pool by schedule-list")
            chain["content_routing"].append({
                "entry": entry, "type": value["type"] if value else None,
                "pool": value["pool"] if value and value["schedule_list"] != "enable" else None,
                "conditions": value["conditions"] if value else None,
                "sources": [sources["vs_config"], *([sources[step]] if value else [])]})
        references: dict[str, dict[str, Any]] = {}
        for item in chain["content_routing"]:
            if item["pool"] is not None:
                reference = references.setdefault(item["pool"], {"name": item["pool"], "relation": "configured_candidate",
                                                                 "entries": [], "sources": [sources["vs_config"]]})
                reference["entries"].append(item["entry"])
                reference["sources"].append(item["sources"][1])
        chain["pool"]["references"] = list(references.values())
        chain["pool"]["candidates_complete"] = complete
        single = list(references) if complete and len(references) == 1 else []
        pool_name = single[0] if single else None
        chain["pool"]["name"] = pool_name
        if pool_name is not None and SAFE_FORTIADC_OBJECT.fullmatch(pool_name):
            required.append("pool_config")
            chain["pool"]["config"] = config_step("pool_config", "load-balance pool " + pool_name,
                                                  lambda text: rules.pool_config(text, pool_name))
        required = tuple(required)
    elif vs and vs["schedule_list"] == "enable":
        # The pool is chosen by schedule: read the schedule-pool entries and their schedule groups; the
        # candidate pools are configured references only, the device output names no active pool.
        chain["pool"]["selection"] = "schedule"
        chain["schedule"], chain["schedule_groups"] = [], []
        required = ["vs_config", "slb_vs_stat", "system_performance"]
        complete = bool(vs["schedule_pool_list"])
        if not complete:
            miss("schedule_pool", "empty", "schedule-list enable without schedule-pool-list")
        for index, entry in enumerate(dict.fromkeys(vs["schedule_pool_list"])):
            safe = SAFE_FORTIADC_OBJECT.fullmatch(entry) is not None
            step = "schedule_pool:" + entry if safe else "schedule_pool"
            complete = False if index >= rules.MAX_SCHEDULE_ENTRIES or not safe else complete
            if index >= rules.MAX_SCHEDULE_ENTRIES:
                miss(step, "truncated")
                continue
            if not safe:
                miss(step, "unparsed")
                continue
            value = config_step(step, "load-balance schedule-pool " + entry,
                                lambda text, n=entry: rules.schedule_pool_config(text, n))
            complete = complete and value is not None
            required.append(step)
            chain["schedule"].append({"entry": entry, "schedule": value["schedule"] if value else None,
                                      "pool": value["pool"] if value else None,
                                      "sources": [sources["vs_config"], *([sources[step]] if value else [])]})
        for name in dict.fromkeys(item["schedule"] for item in chain["schedule"] if item["schedule"]):
            if not SAFE_FORTIADC_OBJECT.fullmatch(name):
                miss("schedule_group", "unparsed")
                continue
            step = "schedule_group:" + name
            value = config_step(step, "system schedule-group " + name,
                                lambda text, n=name: rules.schedule_group_config(text, n))
            required.append(step)
            chain["schedule_groups"].append({"name": name, "members": value["members"] if value else None,
                                             "sources": [sources[step]] if value else []})
        references: dict[str, dict[str, Any]] = {}
        for item in chain["schedule"]:
            if item["pool"] is not None:
                reference = references.setdefault(item["pool"], {"name": item["pool"], "relation": "configured_candidate",
                                                                 "entries": [], "sources": [sources["vs_config"]]})
                reference["entries"].append(item["entry"])
                reference["sources"].append(item["sources"][1])
        chain["pool"]["references"] = list(references.values())
        chain["pool"]["candidates_complete"] = complete
        required = tuple(required)
    elif vs and (pool_name is None or not SAFE_FORTIADC_OBJECT.fullmatch(pool_name)):
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
    if runtime and chain["pool"].get("selection") == "schedule":
        # What vs_stat prints, with its source; on 7.6.7 build 0676 not the pool the schedule selects.
        chain["pool"]["references"] += [{"name": item["name"], "relation": "reported_by_vs_stat",
                                         "sources": [sources["slb_vs_stat"]]} for item in runtime["pools"]]
    chain["load"] = query_step("slb_load", "slb_load", None, lambda text: rules.parse_slb_load(text, virtual_server))
    chain["members"] = []
    if pool:
        # Joined by pool name and member id; a candidate missing from vs_stat keeps an unknown (None) runtime.
        states = rules.pool_runtime_members((runtime or {}).get("pools"), pool_name) or {}
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
    # Resolve only DOWN members, once per real server, within the reserved read plan (not with content routing,
    # whose entry reads use that part of the plan).
    chain["real_servers"] = {}
    if pool and runtime and not content_routing:
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
        "verdict": rules.verdict(findings, missing, executed, required),
        **_firmware_fields(support),
    }


def _fortiswitch_configuration_output(profile, query, parameters, text, scoped=None):
    """The projected configuration text of the FortiOS configuration queries (other queries unchanged).

    `scoped` is the VDOM scope holder of the read: in multi-VDOM the VLAN projection keeps only the VLAN
    interfaces whose own `set vdom` names the session VDOM, decided before the projection drops `set vdom`;
    the holder gets `other_vdom_records`. An unassignable VLAN interface raises VdomRefused.
    """
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
        found = scoped.get('scope') if scoped is not None else None
        if fortios_vdom.contextual(found):
            try:
                text, scoped['other_vdom_records'] = fortigate_tables.vdom_configuration_view(text, found['vdom'])
            except fortios_vdom.VdomRefused as refused:
                raise fortios_vdom.VdomRefused(refused.code, found) from None
            return text
        return fortigate_tables.configuration_view(text)
    return fortiswitch_ports.configuration_view(query, text, parameters or {})


def _membership_commands(auth: TargetAuth, profile: str, query: str, table: str | None) -> tuple[str, ...]:
    """The VDOM membership read joined to a read whose rows name interfaces of any VDOM, if enrolled.

    `table` None: a triage read (its interface rows are assigned by the triage itself).
    """
    if (profile == 'fortinet' and query in fortios_vdom.MEMBERSHIP_READS
            and (table is None or table in fortios_vdom.MEMBERSHIP_TABLES)
            and fortios_vdom.MEMBERSHIP_QUERY in auth.enabled_queries):
        return (fortios_vdom.MEMBERSHIP_COMMAND,)
    return ()


def _vdom_refused_table(profile: str, table: str, query: str, refused: Any) -> dict[str, Any]:
    """A normalized table read refused for its VDOM scope: no records, the code and advice, the scope it saw."""
    from . import tables
    result = tables.parse(profile, table, query, '',
                          status='permission_denied' if refused.code in (
                              'vdom_scope_required', 'vdom_not_found', fortios_vdom.VDOM_ADMIN_GLOBAL) else 'unparsed')
    result.update(error_code=refused.code, error=str(refused), **fortios_vdom.label(refused.scope, query))
    result['warnings'].append(refused.code)
    return result


def _vdom_scoped_table(auth: TargetAuth, result: dict[str, Any], holder: dict[str, Any], profile: str, table: str,
                       query: str, command: str, cleaned: str) -> dict[str, Any]:
    """Label a FortiOS table with its VDOM scope; in multi-VDOM keep only rows of the session VDOM.

    A multi-VDOM record names the session `vdom` only when its owner is verified: rows of a read whose data is
    limited to the VDOM context (data scope `vdom`); rows of a listing of every VDOM (`all_vdoms`) or of an
    unmeasured scope (`unverified`) only after their interface is assigned from `show system interface`
    (set vdom) read in the same context, or, for the VLAN table, from the `set vdom` of each VLAN entry before
    its projection. Other VDOMs' rows are dropped and counted; rows that cannot be assigned are never labelled:
    the table is refused without rows.
    """
    from . import tables
    found = holder.get('scope')
    label = fortios_vdom.label(found, query, holder.get('index'))
    if not fortios_vdom.contextual(found):
        result.update(label)
        return result
    if fortios_vdom.diagnose_refused(command, cleaned):
        result.update(status='permission_denied', ok=False, error_code='permission_denied', reason='diagnose_not_permitted',
                      error=fortios_vdom.ADVICE['diagnose_not_permitted'], records=[])
        result['coverage']['complete'] = False
    elif label['data_scope'] == 'vdom':
        result['records'] = [{**row, 'vdom': found['vdom']} for row in result['records']]
    elif 'other_vdom_records' in holder:
        # The VLAN projection kept only the VLAN interfaces whose own `set vdom` names this VDOM.
        result['records'] = [{**row, 'vdom': found['vdom']} for row in result['records']]
        result['other_vdom_records'] = holder['other_vdom_records']
        label['data_scope'] = 'vdom'
    elif table in fortios_vdom.MEMBERSHIP_TABLES and label['data_scope'] in fortios_vdom.OWNER_SCOPES \
            and result['status'] in ('ok', 'empty'):
        try:
            extras = holder.get('extras') or ()
            if not extras:
                raise fortios_vdom.VdomRefused('vdom_membership_unverified', found)
            text = _redact_output(extras[0], auth)
            if _cli_refused(profile, text):
                raise fortios_vdom.VdomRefused('vdom_membership_unverified', found)
            owners = fortios_vdom.memberships(text)
            result['records'], other = fortios_vdom.assign(
                result['records'], fortios_vdom.MEMBERSHIP_TABLES[table], owners, found['vdom'])
        except fortios_vdom.VdomRefused as refused:
            failed = _vdom_refused_table(profile, table, query, refused)
            failed.update(label, sources=result['sources'] + failed['sources'])
            if not (holder.get('extras') or ()) and fortios_vdom.MEMBERSHIP_QUERY not in auth.enabled_queries:
                failed['warnings'].append(fortios_vdom.MEMBERSHIP_QUERY + '_join_not_enabled')
            return failed
        projection = ''.join('%s %s\n' % (name, owner) for name, owner in sorted(owners.items()))
        result['sources'].append(normalization.source_record(fortios_vdom.MEMBERSHIP_QUERY, projection, 'ok'))
        result['other_vdom_records'] = other
        result['coverage']['parsed_records'] = len(result['records'])
        if not result['records'] and result['status'] == 'ok':
            result['status'] = 'empty'
        label['data_scope'] = 'vdom'
    elif result['status'] in ('ok', 'empty'):
        # Rows whose VDOM owner cannot be verified are never presented as rows of the session VDOM.
        failed = _vdom_refused_table(profile, table, query,
                                     fortios_vdom.VdomRefused('vdom_membership_unverified', found))
        failed.update(label, sources=result['sources'] + failed['sources'])
        return failed
    else:
        result['records'] = []
    result.update(label)
    return result


@_audit_device_call
def normalized_query(auth: TargetAuth, platform: str, query: str, table: str, parameters=None) -> dict[str, Any]:
    """One authorized, identity-checked catalogue read, redacted before parsing."""
    from . import fortigate_tables, tables
    profile, command, _ = _ssh_read_state(auth, platform, query, parameters)
    entry = READ_QUERIES[profile].get(query)
    try:
        with _scope_capture(_membership_commands(auth, profile, query, table)) as holder:
            if profile == 'cisco_ios' and entry is not None and entry.empty_allowed:
                holder['ios_empty_allowed'] = True
            ios_security = query in _IOS_SECURITY_QUERIES.get(profile, {})
            if ios_security:
                holder['ios_security_read'] = True
            try:
                rc, output = _verified_read(auth, profile, command)
            except fortios_vdom.VdomRefused as exc:
                return _vdom_refused_table(profile, table, query, exc)
        cleaned = _redact_output(output, auth)
        if len(cleaned.encode('utf-8')) > _SSH_CAPTURE_MAX_BYTES:
            return tables.parse(profile, table, query, '', status='truncated')
        try:
            cleaned = _fortiswitch_configuration_output(profile, query, parameters, cleaned, holder)
        except fortios_vdom.VdomRefused as exc:
            return _vdom_refused_table(profile, table, query, exc)
        state = normalization.output_status(cleaned, rc=rc, profile=profile, command=command)
        if profile == 'extreme_exos' and query == 'lag_summary' and state == 'empty':
            # A valid empty EXOS sharing table has a zero-group footer.
            state = 'unparsed'
        refused = _cli_refused(profile, cleaned)
        if profile == 'fortinet' and query == 'local_stp_ports' and state == 'not_applicable':
            state = 'empty' if rc in (0, None) else 'unsupported'
        if refused and state == 'ok':
            state = 'permission_denied'
        if profile == 'fortinet' and query == 'local_switch_vlans' and state == 'ok':
            companion = fortigate_tables.LOCAL_SWITCH_INTERFACE_COMMAND
            with _scope_capture():
                interface_rc, interface_output = _verified_read(auth, profile, companion)
            interface_output = _redact_output(interface_output, auth)
            if (len(interface_output.encode('utf-8')) + len(cleaned.encode('utf-8')) > _SSH_CAPTURE_MAX_BYTES):
                return tables.parse(profile, table, query, '', status='truncated')
            if normalization.output_status(interface_output, rc=interface_rc, profile=profile, command=companion) == 'ok':
                cleaned += fortigate_tables.LOCAL_SWITCH_INTERFACES + interface_output
        filters = None
        if (parameters and 'interface' in parameters and (
                profile == 'cisco_nxos' and query in _NXOS_G92_READS or
                profile == 'cisco_xe' and query in IOS_XE_PORT_QUERIES.keys() | {'interface_transceiver'})):
            field = 'local_port' if table.endswith('_neighbor') else 'port'
            filters = {field: tables.port(parameters['interface'])}
        result = tables.parse(profile, table, query, cleaned, rc=rc, status=state, command=command,
                              refused=refused, filters=filters)
        unexpected_stderr = holder.get('unexpected_stderr') and entry is not None and entry.empty_allowed
        if unexpected_stderr and (not cleaned.strip() or result['status'] == 'empty'):
            result = tables.parse(profile, table, query, cleaned, rc=rc, status='unparsed', command=command)
            return dict(result, error_code='device_cli_error', error=_EMPTY_READ_STDERR_ERROR)
        if unexpected_stderr and refused and not result['ok']:
            result['error_code'] = 'device_cli_error'
        firmware = {}
        if ios_security:
            firmware = _ios_security_firmware(holder, profile, query)
        elif profile == 'cisco_nxos':
            firmware = _nxos_firmware(holder, query)
        elif profile == 'cisco_xe':
            firmware = _ios_xe_port_firmware(holder, query)
        if firmware:
            result['warnings'].extend(firmware.pop('warnings', []))
            result.update(firmware)
        if state == 'transport_error':
            result.update(_transport_failure('exit_status', auth))
        if normalization.exos_exit_250(profile, rc, cleaned, command=command):
            result['warnings'].append('exit_status_250')
        return _vdom_scoped_table(auth, result, holder, profile, table, query, command, cleaned)
    except _ProductIdentityError as exc:
        result = tables.parse(profile, table, query, '', status='unparsed')
        result['warnings'].append(exc.reason)
        return result
    except Exception as exc:
        return _transport_result(profile, table, query, exc, auth)


@_audit_device_call
def switch_read(auth: TargetAuth, table: str, vlan_id: str | None = None,
                mac: str | None = None, ip: str | None = None, limit: int = 100,
                offset: int = 0, max_bytes: int = 16_000, interface: str | None = None,
                managed_switch: str | None = None, baseline: str | None = None,
                summary: str | None = None, vr: str | None = None, vrf: str | None = None,
                address_family: str | None = None) -> dict[str, Any]:
    from . import ip_interfaces, tables, switch_pages, port_vlan
    switch_pages.validate(limit, offset, max_bytes)
    profile = auth.ssh_platform
    counters_key = previous = None
    if table == "interface_errors":
        from . import port_errors
        if summary is not None and summary not in port_errors.SUMMARY_MODES:
            raise ValueError("summary is counts or changes")
        # The baseline is checked before any device read.
        counters_key = port_errors._key(auth.alias, profile, interface, managed_switch)
        previous = port_errors.decode_baseline(baseline, counters_key) if baseline is not None else None
    elif baseline is not None or summary is not None:
        raise ValueError("baseline and summary apply only to table interface_errors")
    if table == "interface_errors" and profile != "fortinet":
        tables.request(profile, table, vlan_id, mac, ip, auth.device_types, interface, managed_switch, vr=vr, vrf=vrf,
                       address_family=address_family)
        result = port_errors.shape(port_errors.read(auth, interface, normalized_query), counters_key, previous, summary)
        return switch_pages.page({"target": auth.alias, **result}, ("records", "unparsed"),
                                 limit=limit, offset=offset, max_bytes=max_bytes)
    query, parameters, filters = tables.request(profile, table, vlan_id, mac, ip, auth.device_types, interface, managed_switch,
                                                vr=vr, vrf=vrf, address_family=address_family,
                                                enabled_queries=auth.enabled_queries)
    if profile == 'arista_eos' and table == 'mac_entry' and query not in auth.enabled_queries:
        from .eos_ports import mac_queries
        raise PolicyScopeError('SSH query is not enabled for this target; the MAC read needs one of: '
                               + ', '.join(mac_queries(vlan_id, mac, interface)))
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
    elif table == 'port_vlan' and profile == 'fortinet' and managed_switch is not None:
        from . import fortiswitch_ports
        result = fortiswitch_ports.read_vlan(auth, parameters,
            lambda q, t, p: normalized_query(auth, profile, q, t, p))
    elif table == 'port_vlan' and profile != 'fortinet':
        result = port_vlan.read(auth, lambda q, t, p=None: normalized_query(auth, profile, q, t, p), interface)
    else:
        result = normalized_query(auth, profile, query, table, parameters)
    if table == 'interface' and profile == 'extreme_exos':
        result = port_vlan.join_interfaces(auth, result, lambda q, t: normalized_query(auth, profile, q, t))
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
        if profile == 'cisco_nxos' and vrf is not None:
            # A management/customer interface must never borrow a mask from the default VRF.
            enabled = ('route_table',) if 'route_table_vrf' in auth.enabled_queries else ()
            result = ip_interfaces.join(profile, result, enabled,
                lambda name, other: normalized_query(auth, profile, name + '_vrf', other, {'vrf': vrf}))
        else:
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
                # The failed join read names its cause, as a direct read would.
                result.update({key: vlans[key] for key in ('error_code', 'error') if key in vlans})
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
    if table == 'route' and ip is not None and query is not None and '{address}' not in READ_QUERIES[profile][query].command:
        result['records'] = tables.longest_prefix(result['records'], tables.literal(ip)[1])
    if table == 'interface_errors':
        result = port_errors.shape(result, counters_key, previous, summary)
    return switch_pages.page({'target': auth.alias, **result, 'ok': result['status'] in ('ok', 'empty', 'not_applicable')},
                             ('records', 'unparsed'), limit=limit, offset=offset, max_bytes=max_bytes)


def check_intent(plan_name, plans, read_switch):
    """Compare declared checks against normalized switch_read results for one invocation."""
    from . import port_vlan, switch_pages
    from .normalization import normalize_port
    from .tables import LAG_FLAGS

    def port_key(value):
        try:
            return normalize_port(value)['name']
        except ValueError:
            # FortiOS allows underscores in enrolled aggregate names.
            return value

    states = {name for _, name in LAG_FLAGS}
    reads, checks = {}, []
    steps = progress.Steps("check_intent", total=sum(len(rows) for _, _, plan in plans for rows in plan.values()))
    for target, platform, plan in plans:
        for kind, rows in plan.items():
            for expected in rows:
                selector = expected['name'] if kind == 'lag' else expected['port']
                table = {'lag': 'lag', 'vlan': 'port_vlan', 'poe': 'poe_port'}[kind]
                interface = selector if kind != 'lag' or platform == 'fortinet' else None
                serial = expected.get('managed_switch')
                key = (target, table, interface, serial)
                if key not in reads:
                    args = {'target': target, 'table': table, 'max_bytes': switch_pages.MAX_BYTES,
                            'limit': switch_pages.MAX_LIMIT}
                    if interface is not None:
                        args['interface'] = interface
                    if serial is not None:
                        args['managed_switch'] = serial
                    reads[key] = read_switch(args)
                steps.read(table)
                payload = reads[key]
                check = {'target': target, 'kind': kind, 'expected': expected}
                if 'firmware_support' in payload:
                    check['firmware_support'] = payload['firmware_support']

                coverage = payload.get('coverage', {})
                complete = coverage.get('complete') is True
                if kind == 'vlan' and payload.get('source') == 'configuration':
                    # FortiSwitch membership is configuration and has no operational link state.
                    complete = complete or coverage.get('missing_fields') == ['oper_status']
                if (payload.get('status') not in ('ok', 'empty') or not complete or payload.get('unparsed')
                        or payload.get('has_more') is not False or coverage.get('warnings')):
                    check.update(status='incomplete', reason='read_incomplete',
                                 read_status=payload.get('status', 'unavailable'))
                    checks.append(check)
                    continue

                column = 'name' if kind == 'lag' else 'port'
                matches = [record for record in payload.get('records', ())
                           if port_key(record.get(column)) == port_key(selector)]
                if kind == 'lag' and len(matches) == 1:
                    members = matches[0].get('members')
                    if members is not None and all(
                        member.get('state') in states and isinstance(member.get('port'), str) for member in members
                    ):
                        ports = [port_key(member['port']) for member in members]
                        if len(ports) == len(set(ports)):
                            active = sorted(port for port, member in zip(ports, members) if member['state'] == 'bundled')
                            check.update(actual=active, status='pass' if active == sorted(
                                {port_key(member) for member in expected['active_members']}) else 'fail')
                elif kind == 'lag' and not matches:
                    check.update(actual=None, status='fail', reason='lag_absent')
                elif kind == 'vlan' and len(matches) == 1:
                    membership = port_vlan.membership(matches[0], expected['vlan_id'])
                    if membership['carries_vlan'] is not None:
                        actual = membership['tagging'] if membership['carries_vlan'] else 'absent'
                        check.update(actual=actual, status='pass' if actual == expected['membership'] else 'fail')
                elif kind == 'poe' and len(matches) == 1:
                    actual = matches[0].get('power_w')
                    if type(actual) in (int, float) and 0 <= actual and math.isfinite(actual):
                        check.update(actual=actual, status='pass' if expected['min_w'] <= actual <= expected['max_w'] else 'fail')
                if 'status' not in check:
                    check.update(status='incomplete', reason='observation_missing_or_ambiguous')
                checks.append(check)
    statuses = {check['status'] for check in checks}
    status = 'incomplete' if not checks or 'incomplete' in statuses else 'fail' if 'fail' in statuses else 'pass'
    return {'plan': plan_name, 'status': status, 'checks': checks}


# The identity supplement that prints the host name where `show version` does not (EXOS sysName).
_HOSTNAME_SUPPLEMENTS = {"extreme_exos": "switch", "arista_eos": "hostname"}


def _locate_firmware(profile, status):
    from netops_core import tested

    if profile == 'fortinet':
        try:
            _, version, build = core_platforms.version_record(status)
            version = version + ' build' + build
        except core_platforms.VersionRecordError:
            version = None
        return tested.support('FortiOS', version, ('8.0.2 build0251',), function='endpoint location')
    if profile == 'extreme_exos':
        try:
            version = normalization.parse_identity(profile, status)['os_version']
        except normalization.IdentityError:
            version = None
        return tested.support('ExtremeXOS', version, ('33.6.1.14', '33.7.1.6'), function='endpoint location')
    return None


def _locate_endpoint_run(auths, endpoint, progress=lambda result: None, *, deadline=None):
    with ExitStack() as connections:
        return _locate_endpoint_correlate(auths, endpoint, progress, deadline, connections)


def _locate_endpoint_correlate(auths, endpoint, progress, deadline, connections):
    from . import locate, tables, port_vlan
    budget = locate.Budget()
    if deadline is not None:
        budget.deadline = min(budget.deadline, deadline)
    verified = {}
    identified, firmware = {}, {}
    target_reads = dict.fromkeys((a.alias for a in auths), 0)
    import threading
    endpoints = [(a.host, a.port) for a in auths]
    lanes = {address: threading.RLock() for address in endpoints}
    # Distinct aliases of the same socket must not reserve its connection lane concurrently.
    readers = {a.alias: _FortinetReader(a, connections) for a in auths
               if a.ssh_platform == 'fortinet' and endpoints.count((a.host, a.port)) == 1}

    def serialized(function):
        @wraps(function)
        def wrapped(auth, *args, **kwargs):
            with lanes[(auth.host, auth.port)]:
                token = _LOCATE_BUDGET.set(budget)
                connection = _FORTINET_READER.set(readers.get(auth.alias))
                try:
                    budget.remaining()
                    return function(auth, *args, **kwargs)
                finally:
                    _FORTINET_READER.reset(connection)
                    _LOCATE_BUDGET.reset(token)
        return wrapped

    def device(auth, profile, command, holder=None):
        with budget.lanes:
            with budget.lock:
                if target_reads[auth.alias] >= auth.locate_read_limit:
                    raise locate.LimitReached("target_read_limit")
                budget.take()
                target_reads[auth.alias] += 1
            if holder is not None and fortios_vdom.contextual(holder.get('scope')):
                # Multi-VDOM FortiOS: one counted read inside the verified context of the session VDOM.
                rc, output, index, extras = _vdom_context_read(auth, profile, holder['scope']['vdom'], (command,),
                                                               extra=holder.get('extra', ()))
                holder.update(index=index, extras=extras)
                return rc, output
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
                firmware[auth.alias] = _locate_firmware(*verified[auth.alias])
            holder = {'scope': None, 'extra': _membership_commands(auth, profile, query, table)}
            if profile == 'fortinet' and table != 'identity':
                holder['scope'] = fortios_vdom.require(fortios_vdom.scope(verified[auth.alias][1]),
                                                       auth.read_inventory)
            rc, output = device(auth, profile, command, holder)
            if profile == 'fortinet':
                # FortiOS redraws long FortiLink commands before echoing them.
                # Erase only a leading line that reconstructs the exact command.
                echo, _, body = output.lstrip('\r\n').partition('\n')
                if '\b' in echo and _erase_backspaces(echo).strip() == command:
                    output = body
            cleaned = _redact_output(output, auth)
            if len(cleaned.encode()) > _SSH_CAPTURE_MAX_BYTES:
                return tables.parse(profile, table, query, '', status='truncated')
            cleaned = _fortiswitch_configuration_output(profile, query, parameters, cleaned, holder)
            state = normalization.output_status(cleaned, rc=rc, profile=profile, command=command)
            if table == 'identity':
                # An identity supplement: its text only yields the host name an LLDP neighbour is compared with.
                return {'status': 'ok' if state == 'ok' and not _cli_refused(profile, cleaned) else state, 'text': cleaned}
            refused = _cli_refused(profile, cleaned)
            if refused and state == 'ok':
                state = 'permission_denied'
            if table in locate.NAME_TABLES:
                result = locate.parse_name_read(profile, table, query, cleaned, state, parameters)
            else:
                result = tables.parse(profile, table, query, cleaned, rc=rc, status=state, command=command, refused=refused)
            if state == 'transport_error':
                result.update(_transport_failure('exit_status', auth))
            if normalization.exos_exit_250(profile, rc, cleaned, command=command):
                result['warnings'].append('exit_status_250')
            support = firmware[auth.alias]
            if support:
                result['firmware_support'] = support
            return _vdom_scoped_table(auth, result, holder, profile, table, query, command, cleaned)
        except fortios_vdom.VdomRefused as exc:
            return _vdom_refused_table(profile, table, query, exc)
        except locate.LimitReached:
            raise
        except _ProductIdentityError as exc:
            result = tables.parse(profile, table, query, '', status='unparsed')
            result['warnings'].append(exc.reason)
            return result
        except Exception as exc:
            return _transport_result(profile, table, query, exc, auth)

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

    def rest_read(auth, rest_endpoint):
        # Every REST GET actually sent is charged like an SSH read: per-target limit,
        # shared cap and deadline; its own timeout is capped by what remains.
        with budget.lock:
            if target_reads[auth.alias] >= auth.locate_read_limit:
                raise locate.LimitReached("target_read_limit")
            budget.take()
            target_reads[auth.alias] += 1
        return budget.remaining()

    @serialized
    def stations(auth, mac, ip):
        return _wifi_clients_result(auth, mac=mac, ip=ip, before_read=rest_read)

    def wired(target_endpoint, report, **options):
        return locate.run(auths, target_endpoint, read, budget, report, identify, **options)

    @serialized
    @_audit_device_call
    def ruckus_read(auth, platform, query, table, parameters):
        """wireless path: one counted, audited Ruckus Unleashed catalogue read, redacted and parsed like ssh_read."""
        from datetime import datetime, timezone
        from .sanitize import redact_ruckus_secrets
        profile, command, _ = _ssh_read_state(auth, platform, query, parameters)
        captured = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        try:
            rc, output = device(auth, profile, command)
        except locate.LimitReached:
            raise
        except Exception as exc:
            return {'ok': False, 'error_code': _transport_cause(exc) or 'ssh_unavailable', 'failed_step': query}
        cleaned = _redact_output(redact_ruckus_secrets(output, _redaction_secret_forms(auth)), auth)
        source = {'query': query, 'command': command, 'content_sha256': digest_text(cleaned), 'captured_at': captured}
        if rc not in (0, None) or _cli_refused(profile, cleaned, command=command):
            return {'ok': False, 'error_code': 'device_cli_error', 'failed_step': query, 'sources': [source]}
        parsed = wifi_parse.summarize_ruckus(query, cleaned)
        if parsed['unparsed_count']:
            return {'ok': False, 'error_code': 'unparsed', 'failed_step': query, 'sources': [source]}
        if parsed.get('incomplete'):
            return {'ok': False, 'error_code': 'incomplete', 'failed_step': query, 'sources': [source]}
        return {'ok': True, 'records': parsed['records'], 'sources': [source]}

    def ruckus(auth, mac, ip):
        """Active clients of one Unleashed controller joined to the AP each is associated to (`show ap all`)."""
        clients = ruckus_read(auth, 'ruckus_unleashed', 'clients', 'wifi_client', None)
        if not clients['ok']:
            return clients
        rows = [row for row in clients['records'] if (mac is not None and row['mac'] == mac) or (ip is not None and row['ip'] == ip)]
        if not rows:
            return {**clients, 'records': []}
        aps = ruckus_read(auth, 'ruckus_unleashed', 'access_points', 'wifi_ap', None)
        if not aps['ok']:
            return {**aps, 'sources': clients['sources'] + aps.get('sources', [])}
        records = []
        for row in rows:
            ap = next((item for item in aps['records'] if item['mac'] and item['mac'] == row['ap_mac']), None)
            records.append({**{key: row[key] for key in ('mac', 'ip', 'wlan', 'vlan_id', 'channel', 'radio')},
                            'ap': None if ap is None else {
                                'mac': ap['mac'], 'name': ap['name'], 'ip': ap['ip'], 'role': ap['role'],
                                'uplink_ports': [port['interface'] for port in ap['lan_ports']
                                                 if (port['logical_link'] or '').lower() == 'up']}})
        return {'ok': True, 'records': records, 'sources': clients['sources'] + aps['sources']}

    @serialized
    @_audit_device_call
    def c9800_client(auth, mac, ip):
        from .triage_wifi import c9800_read
        from netops_core import c9800 as controller

        profile = "cisco_xe"
        if ip is not None:
            return {"ok": False, "error_code": "client_mac_required"}
        try:
            if auth.alias not in verified:
                verified[auth.alias] = (profile, _check_identity(auth, profile, device)[2])
            if not controller.CONTROLLER_IMAGE.search(verified[auth.alias][1]):
                return {"ok": False, "error_code": "unsupported_platform"}
        except _ProductIdentityError as exc:
            return {"ok": False, "error_code": exc.reason}
        except locate.LimitReached:
            raise
        except Exception as exc:
            return {"ok": False, "error_code": _transport_cause(exc) or "ssh_unavailable"}

        def read(query, parameters):
            try:
                _, command, _ = _ssh_read_state(auth, profile, query, parameters)
            except PolicyScopeError:
                return {"ok": False, "reason": "permission_denied"}
            try:
                rc, text = device(auth, profile, command)
            except locate.LimitReached:
                raise
            except Exception as exc:
                return {"ok": False, "reason": _transport_cause(exc) or "ssh_unavailable"}
            text = _redact_output(text, auth)
            state = normalization.output_status(text, rc=rc, profile=profile, command=command)
            if state != "ok" or _cli_refused(profile, text, command=command):
                return {"ok": False, "reason": state if state != "ok" else "device_cli_error"}
            if len(text.encode()) > _SSH_CAPTURE_MAX_BYTES:
                return {"ok": False, "reason": "truncated"}
            return {"ok": True, "text": text, "content_sha256": digest_text(text)}

        clients = c9800_read(read, "c9800_clients")
        sources = [clients["source"]] if "source" in clients else []
        if not clients["complete"]:
            return {"ok": False, "failed_step": "c9800_clients", "sources": sources,
                    "error_code": clients.get("reason", "incomplete")}
        station = next((row for row in clients["records"] if row["mac"] == mac), None)
        if station is None:
            return {"ok": True, "records": [], "sources": sources}
        detail = c9800_read(read, "c9800_client_detail", {"mac": mac})
        aps = c9800_read(read, "c9800_aps")
        sources.extend(item["source"] for item in (detail, aps) if "source" in item)
        client = next((row for row in detail["records"] if row["mac"] == mac), {})
        missing = [{"step": query, "reason": item.get("reason", "incomplete")}
                   for query, item in (("c9800_client_detail", detail), ("c9800_aps", aps)) if not item["complete"]]
        same_ap = client.get("ap_name", station["ap_name"]) == station["ap_name"]
        if not same_ap:
            missing.append({"step": "c9800_client_detail", "reason": "association_changed"})
        ap = wifi_parse.c9800_ap({**station, **client}, aps["records"]) if same_ap and aps["complete"] else None
        vlan = client.get("vlan", "")
        return {"ok": True, "sources": sources, "missing": missing,
                "records": [{"mac": mac, "ip": client.get("ip"), "wlan": client.get("wlan"),
                             "vlan_id": int(vlan) if vlan.isdecimal() else None,
                             "channel": client.get("channel"), "radio": client.get("slot"),
                             "locally_switched": client.get("data_switching") == "Local",
                             "ap": {"mac": ap["ethernet_mac"], "name": ap["name"], "ip": ap.get("ip"),
                                    "role": ap["state"]} if ap else None}]}

    def c9800_port(edge):
        from . import port_errors

        alias, port = edge["vantage"], edge["port"]
        target = next((auth for auth in auths if auth.alias == alias), None)
        if target is None or target.ssh_platform not in {"cisco_ios", "cisco_xe"}:
            return {"ap_port_diagnostics": {"status": "unsupported", "complete": False}}
        profile = target.ssh_platform
        diagnostics = {}
        for table in ("cdp_neighbor", "poe_port", "interface_errors"):
            try:
                if table == "interface_errors":
                    bounded = port_errors.bounded_queries(profile, port, target.enabled_queries, target.read_inventory)
                    if not bounded:
                        raise PolicyScopeError("no enabled per-port counter read")
                    observed = port_errors.read(target, port, locate_endpoint_read)
                    selected = observed["records"]
                else:
                    query, params, _ = tables.request(profile, table, interface=port, device_types=target.device_types)
                    if query is None:
                        diagnostics[table] = {"status": "unsupported", "complete": False}
                        continue
                    observed = locate_endpoint_read(target, profile, query, table, params)
                    field = "local_port" if table == "cdp_neighbor" else "port"
                    selected = [row for row in observed["records"] if row.get(field) == tables.port(port)]
                complete = observed["coverage"]["complete"] and len(selected) == len(observed["records"])
                if table != "cdp_neighbor":
                    complete = complete and bool(selected)
                status = observed["status"]
                diagnostics[table] = {"status": "incomplete" if not complete and status == "ok" else status,
                                      "complete": complete, "records": selected, "sources": observed["sources"]}
            except (PolicyScopeError, ValueError):
                diagnostics[table] = {"status": "permission_denied", "complete": False}
            except locate.LimitReached as exc:
                diagnostics[table] = {"status": str(exc), "complete": False}
        return diagnostics

    from . import locate_wifi
    kind, value = locate.selector(endpoint)
    if kind != 'hostname':
        return locate_wifi.run(auths, endpoint, budget, wired, stations, progress, ruckus=ruckus,
                               c9800=c9800_client, c9800_port=c9800_port)

    resolved = locate.resolve_name(auths, value, budget, read, progress)
    identity = resolved['resolution']
    if resolved['missing']:
        return resolved

    def with_resolution(result):
        coverage = result['coverage']
        missing = list(result['missing'])
        verdict = result['verdict']
        if verdict == 'not_found_in_checked_data':
            verdict = 'incomplete'
            missing.append({'vantage': None, 'table': 'endpoint', 'reason': 'location_not_observed'})
            coverage = {**coverage, 'complete': False}
        return {**result, 'endpoint': resolved['endpoint'], 'resolution': identity, 'verdict': verdict,
                'vantage': resolved['vantage'] + result['vantage'], 'missing': missing, 'coverage': coverage}

    return with_resolution(locate_wifi.run(auths, identity['mac'], budget, wired, stations,
                                          lambda result: progress(with_resolution(result)),
                                          ruckus=ruckus, c9800=c9800_client, c9800_port=c9800_port,
                                          expected_ip=identity['ip']))


def vpc_compare(auths: list[TargetAuth], vpc_id: str) -> dict[str, Any]:
    """Compare exactly two enrolled NX-OS targets using only their enabled reads."""
    from . import switch_vpc
    from .read_policy import _validate_slot

    number = int(_validate_slot(vpc_id, 'vpc_id'))
    profile = 'cisco_nxos'
    if (len(auths) != 2 or len({auth.alias for auth in auths}) != 2
            or len({(auth.host, auth.port) for auth in auths}) != 2
            or any(auth.ssh_platform != profile for auth in auths)):
        raise ValueError('vpc_compare requires two distinct enrolled NX-OS targets')
    queries = (('vpc_status', None), ('vpc_member_consistency', {'vpc_id': vpc_id}))
    for auth in auths:
        for query, parameters in queries:
            _ssh_read_state(auth, profile, query, parameters)

    observations = []
    for auth in auths:
        brief, parameters = (ssh_read(auth, profile, query, values, 0, 16000) for query, values in queries)
        source_states = []
        for (query, _), result, key in zip(queries, (brief, parameters), ('vpc', 'vpc_consistency')):
            state = result.get(key, {}).get('state') or result.get('status') or result.get('error_code')
            source_states.append({'query': query, 'status': state, 'content_sha256': result.get('content_sha256'),
                                  **{name: result[name] for name in ('firmware_support', 'warnings') if name in result}})
        observations.append({'target': auth.alias, 'sources': source_states,
                             'vpc': brief.get('vpc', {}), 'consistency': parameters.get('vpc_consistency', {})})
    result = switch_vpc.compare(observations, number)
    return {'ok': result['state'] != 'incomplete', **result}


def locate_endpoint(targets: list[str], endpoint: str, auth_context: str) -> dict[str, Any]:
    """Credentials travel over a private pipe to a separately bounded worker."""
    from . import endpoint_worker, locate
    locate.selector(endpoint)
    # Decode before spawning: an invalid or incomplete injected scope cannot
    # trigger a worker, and the worker repeats this check before device access.
    endpoint_worker.decode(targets, auth_context)
    return endpoint_worker.call(targets, endpoint, auth_context)


@_audit_device_call
def triage_port(auth: TargetAuth, interface: str, domain: str = 's0') -> dict[str, Any]:
    """Correlate authorized EXOS or EOS port reads; the EXOS domain is enrolled in services."""
    from . import triage_port as triage
    from .triage_routing import CISCO_RUNBOOK_TESTED
    if auth.ssh_platform in CISCO_RUNBOOK_TESTED:
        if domain != 's0':
            raise ValueError('domain applies only to EXOS triage_port')
        return _cisco_runbook(auth, "triage_port", interface=interface)
    if auth.ssh_platform == 'arista_eos':
        return _triage_port_eos(auth, interface, domain)
    if auth.ssh_platform == 'juniper_junos_els':
        platform = auth.ssh_platform
        if domain != 's0':
            raise ValueError('domain applies only to EXOS triage_port')
        from .read_policy import _validate_slot
        _validate_slot(interface, 'junos_physical_interface')
        _ssh_read_state(auth, platform, 'interface_details', {'interface': interface})

        def read_raw(query, parameters):
            if query not in auth.enabled_queries:
                return {'ok': False, 'status': 'permission_denied', 'query': query}
            max_bytes = 48000 if query == 'interface_details' else 16000
            return ssh_read(auth, platform, query, parameters, 0, max_bytes)

        return {'target': auth.alias, 'platform': platform, **triage.run_junos(interface, read_raw)}

    if auth.ssh_platform != 'extreme_exos':
        raise ValueError('unsupported_platform: triage_port supports EXOS, EOS, Junos ELS and IOS/IOS XE')
    # Validate both selectors and inventory before the first transport call.
    _ssh_read_state(auth, auth.ssh_platform, 'stp_port_detail', {'interface': interface, 'domain': domain})
    from . import tables

    def read_table(table):
        query = 'lldp_interface_details' if table == 'lldp_neighbor' else tables.BINDINGS[auth.ssh_platform].get(table)
        if query not in auth.enabled_queries:
            return tables.parse(auth.ssh_platform, table, query, '', status='permission_denied')
        if table == 'lldp_neighbor':
            return normalized_query(auth, auth.ssh_platform, query, table, {'interface': interface})
        return switch_read(auth, table, interface=interface, limit=500, max_bytes=48000)

    def read_raw(query, params):
        if query not in auth.enabled_queries:
            return {'ok': False, 'status': 'permission_denied', 'query': query}
        return ssh_read(auth, auth.ssh_platform, query, params, 0, 16000)

    result = triage.run(interface, domain, read_table, read_raw)
    return {'target': auth.alias, 'platform': auth.ssh_platform, **result}


def _triage_port_eos(auth: TargetAuth, interface: str, domain: str) -> dict[str, Any]:
    from . import tables, triage_port as triage
    if domain != 's0':
        raise ValueError('domain applies only to EXOS triage_port')
    # Validate the selector and inventory before the first transport call.
    _ssh_read_state(auth, auth.ssh_platform, 'stp_interface_detail', {'interface': interface})

    def read_table(table):
        query = tables.request(auth.ssh_platform, table, interface=interface)[0]
        if query not in auth.enabled_queries:
            return tables.parse(auth.ssh_platform, table, query, '', status='permission_denied')
        return switch_read(auth, table, interface=interface, limit=500, max_bytes=48000)

    def read_raw(query, params):
        if query not in auth.enabled_queries:
            return {'ok': False, 'status': 'permission_denied', 'query': query}
        return ssh_read(auth, auth.ssh_platform, query, params, 0, 16000)

    return {'target': auth.alias, 'platform': auth.ssh_platform, **triage.run_eos(interface, read_table, read_raw)}
