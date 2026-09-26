from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import time

from . import legacy_ssh as legacy_module
from . import ssh as ssh_module

PREFIX = "SHA256:"
DIGEST_LENGTH = 43
KEYSCAN_BINARY = "ssh-keyscan"
KEY_TYPES = ("ed25519", "ecdsa", "rsa")
PROBE_LOGIN = "netops-hostkey"
PROBE_OPTIONS = (
    "BatchMode=yes",
    "StrictHostKeyChecking=accept-new",
    "GlobalKnownHostsFile=/dev/null",
    "HashKnownHosts=no",
    "CheckHostIP=no",
    "UpdateHostKeys=no",
    "PubkeyAuthentication=no",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "HostbasedAuthentication=no",
    "GSSAPIAuthentication=no",
    "ClearAllForwardings=yes",
    "ProxyCommand=none",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
)
KNOWN_HOSTS_NAME = "known_hosts"
KEYSCAN_CAPTURE_MAX_BYTES = 256 * 1024
DIGEST_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
MIN_PORT = 1
MAX_PORT = 65535


class HostKeyError(Exception):
    pass


def checked_pin(value) -> str:
    if isinstance(value, str) and value.startswith(PREFIX):
        digest = value[len(PREFIX):]
        if len(digest) == DIGEST_LENGTH and set(digest) <= DIGEST_CHARS:
            return value
    raise HostKeyError(
        "host_key_fingerprint must hold the sha256 host key fingerprint of the device as"
        " ssh-keygen -lf prints it (%s followed by %d base64 characters), no first contact"
        " trust, got %r" % (PREFIX, DIGEST_LENGTH, value)
    )


def fingerprint_of(blob) -> str:
    if not isinstance(blob, str) or not blob.strip():
        raise HostKeyError("host key blob must be a non-empty base64 string, got %r" % (blob,))
    try:
        material = base64.b64decode(blob, validate=True)
    except Exception:
        raise HostKeyError("host key blob is not valid base64") from None
    digest = base64.b64encode(hashlib.sha256(material).digest()).decode("ascii").rstrip("=")
    return "%s%s" % (PREFIX, digest)


def _checked_host(value) -> str:
    if not isinstance(value, str):
        raise HostKeyError("host must be a bare host name or address, got %r" % (value,))
    host = value.strip()
    if (
        not host
        or host.startswith("-")
        or "@" in host
        or "://" in host
        or any(mark in host for mark in ("/", "?", "#", " ", "\t"))
    ):
        raise HostKeyError("host must be a bare host name or address, got %r" % (value,))
    return host


def _checked_port(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HostKeyError(
            "port must be a whole number between %d and %d, got %r" % (MIN_PORT, MAX_PORT, value)
        )
    if not MIN_PORT <= value <= MAX_PORT:
        raise HostKeyError(
            "port must be a whole number between %d and %d, got %r" % (MIN_PORT, MAX_PORT, value)
        )
    return value


def _checked_timeout(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HostKeyError("timeout must be a positive number of seconds, got %r" % (value,))
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise HostKeyError("timeout must be a positive number of seconds, got %r" % (value,))
    return seconds


def keyscan_argv(host, port, timeout_seconds, key_type=None) -> list:
    name = _checked_host(host)
    number = _checked_port(port)
    seconds = _checked_timeout(timeout_seconds)
    argv = [KEYSCAN_BINARY, "-T", str(max(1, int(seconds))), "-p", str(number)]
    if key_type is not None:
        if key_type not in KEY_TYPES:
            raise HostKeyError(
                "key type must be one of %s, got %r" % (", ".join(KEY_TYPES), key_type)
            )
        argv.extend(["-t", key_type])
    argv.append(name)
    return argv


def matching_line(lines, pin) -> str:
    line, offered = _match(lines, checked_pin(pin))
    if line is not None:
        return line
    raise HostKeyError(
        "no offered host key matches the pinned fingerprint %s, %d key(s) offered"
        % (pin, offered)
    )


def _key_lines(lines) -> list:
    return [line for line in lines if not line.startswith("#") and len(line.split()) >= 3]


def _match(lines, fingerprint):
    offered = 0
    for line in lines:
        if not isinstance(line, str):
            raise HostKeyError(
                "the host key scan must answer with text lines, got %s" % type(line).__name__
            )
        parts = line.split()
        if line.startswith("#") or len(parts) < 3:
            continue
        try:
            seen = fingerprint_of(parts[2])
        except HostKeyError:
            continue
        if seen == fingerprint:
            return line, offered
        offered += 1
    return None, offered


def _env() -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def probe_argv(host, port, timeout_seconds, known_hosts, legacy) -> list:
    name = _checked_host(host)
    number = _checked_port(port)
    seconds = _checked_timeout(timeout_seconds)
    options = PROBE_OPTIONS + (
        "UserKnownHostsFile=%s" % known_hosts,
        "ConnectTimeout=%d" % max(1, int(seconds)),
    ) + legacy_module.openssh_options(legacy)
    argv = [ssh_module.SSH_BINARY, "-F", ssh_module.CONFIG_FILE]
    for option in options:
        argv.extend(["-o", option])
    argv.extend(["-T", "-p", str(number), "-l", PROBE_LOGIN, name, "exit"])
    return argv


def scan(
    host, port, pin, timeout_seconds, *, capture_max_bytes=KEYSCAN_CAPTURE_MAX_BYTES, run=None,
    legacy=None,
) -> str:
    fingerprint = checked_pin(pin)
    name = keyscan_argv(host, port, timeout_seconds)[-1]
    seconds = _checked_timeout(timeout_seconds)
    try:
        profile = legacy_module.checked(legacy)
    except legacy_module.LegacySshError as error:
        raise HostKeyError("cannot read the host key of %s: %s" % (name, error)) from None
    try:
        budget = ssh_module._checked_capture(capture_max_bytes)
    except ssh_module.SshError as error:
        raise HostKeyError("cannot read the host key of %s: %s" % (name, error)) from None
    runner = run if run is not None else ssh_module._capped_runner(budget)
    if legacy_module.needs_sha1_key_exchange(profile):
        return _probe(runner, host, port, fingerprint, seconds, name, profile)
    deadline = time.monotonic() + seconds
    offered = 0
    answered = False
    code = None
    for index, key_type in enumerate(KEY_TYPES):
        remaining = seconds if index == 0 else deadline - time.monotonic()
        if remaining < 1 and index > 0:
            break
        code, data = _scan_one(runner, keyscan_argv(host, port, remaining, key_type), name, remaining)
        lines = data.decode("utf-8", "replace").splitlines()
        if not _key_lines(lines):
            continue
        if code != 0:
            raise HostKeyError("%s offered no host key, exit code %s" % (name, code))
        answered = True
        line, seen = _match(lines, fingerprint)
        if line is not None:
            return line
        offered += seen
    if not answered:
        raise HostKeyError("%s offered no host key, exit code %s" % (name, code))
    raise HostKeyError(
        "no offered host key matches the pinned fingerprint %s, %d key(s) offered"
        % (fingerprint, offered)
    )


def _probe(runner, host, port, fingerprint, seconds, name, profile) -> str:
    with tempfile.TemporaryDirectory(prefix="netops-core-hostkey-") as directory:
        known_hosts = os.path.join(directory, KNOWN_HOSTS_NAME)
        code, _ = _scan_one(
            runner, probe_argv(host, port, seconds, known_hosts, profile), name, seconds
        )
        try:
            with open(known_hosts, "rb") as handle:
                data = handle.read(KEYSCAN_CAPTURE_MAX_BYTES + 1)
        except FileNotFoundError:
            data = b""
    if len(data) > KEYSCAN_CAPTURE_MAX_BYTES:
        raise HostKeyError("%s offered more than %d bytes of host keys" % (name, KEYSCAN_CAPTURE_MAX_BYTES))
    if not data:
        raise HostKeyError("%s offered no host key, exit code %s" % (name, code))
    line, offered = _match(data.decode("utf-8", "replace").splitlines(), fingerprint)
    if line is not None:
        return line
    raise HostKeyError(
        "no offered host key matches the pinned fingerprint %s, %d key(s) offered"
        % (fingerprint, offered)
    )


def _scan_one(runner, argv, name, seconds):
    try:
        result = runner(argv, capture_output=True, timeout=seconds, check=False, env=_env())
    except ssh_module.SshError as error:
        raise HostKeyError("cannot read the host key of %s: %s" % (name, error)) from None
    except Exception as error:
        raise HostKeyError(
            "cannot read the host key of %s (%s)" % (name, type(error).__name__)
        ) from None
    output = getattr(result, "stdout", None)
    if not isinstance(output, (bytes, bytearray)):
        raise HostKeyError(
            "the host key scan must answer with bytes on stdout, got %s" % type(output).__name__
        )
    return getattr(result, "returncode", None), bytes(output)


def known_hosts_file(directory, line) -> str:
    if not isinstance(line, str) or not line.strip():
        raise HostKeyError("host key line must be a non-empty single line, got %r" % (line,))
    if any(mark in line for mark in ("\n", "\r", "\x00")):
        raise HostKeyError("host key line must be a single line, got %r" % (line,))
    path = os.path.join(directory, KNOWN_HOSTS_NAME)
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise HostKeyError("cannot write the known hosts file %s: %s" % (path, error)) from None
    with os.fdopen(handle, "wb") as target:
        target.write(("%s\n" % line).encode("utf-8"))
    return path
